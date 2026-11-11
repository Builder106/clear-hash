//! Docker rebuild orchestration + file-tree comparison.
//!
//! The rebuild pipeline:
//!   1. On the host: `git clone --no-checkout` the selected source repo, then `git fetch origin
//!      <commit>` and `git checkout --detach <commit>`. Verify `HEAD` matches the pinned SHA — defends
//!      against a tampered git server returning a different tree for the requested ref.
//!   2. Pull the adapter's pinned Docker image (cache hit common).
//!   3. Create a fresh container with the source tree bind-mounted at `/src`. Run the adapter's
//!      rebuild script with `SOURCE_DATE_EPOCH` set to the commit's author time.
//!   4. `download_from_container /out` to extract the rebuilt artifact back to the host.
//!
//! npm and PyPI dependencies are fetched and hash-verified on the host before any
//! package code executes. Their rebuilds mount the verified archives read-only at
//! `/deps` and use Docker network mode `none`. Cargo retains its packaging network policy.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

mod offline;
pub mod simulate_tamper;

use bollard::models::{ContainerCreateBody, HostConfig};
use bollard::query_parameters::{
    CreateContainerOptions, CreateImageOptions, LogsOptions, WaitContainerOptions,
};
use bollard::Docker;
use clearhash_core::{tree, FileTreeHash, PackageRef, ProvenanceClaim, VerifyOutcome};
use clearhash_ecosystems::{AdapterError, EcosystemAdapter};
use futures_util::StreamExt;
use thiserror::Error;
use tokio::process::Command;

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("tarball extraction: {0}")]
    Extract(String),
    #[error("adapter: {0}")]
    Adapter(#[from] AdapterError),
    #[error("docker: {0}")]
    Docker(#[from] bollard::errors::Error),
    #[error("dependency prefetch: {0}")]
    Prefetch(String),
    #[error("git: {0}")]
    Git(String),
    #[error("rebuild script exited with status {0}; stderr tail: {1}")]
    RebuildFailed(i64, String),
    #[error("checked-out HEAD ({actual}) does not match pinned commit ({expected})")]
    CommitDrift { expected: String, actual: String },
}

// Tarball extraction and tree-hashing (used by both registry-side and rebuild-side trees).

pub fn extract_archive(
    adapter: &dyn EcosystemAdapter,
    archive: &Path,
    pkg: &PackageRef,
    dest_root: &Path,
) -> Result<PathBuf, SandboxError> {
    let file = std::fs::File::open(archive)?;
    let gz = flate2::read::GzDecoder::new(file);
    let mut tarball = tar::Archive::new(gz);

    let extract_into = dest_root.join("extracted");
    std::fs::create_dir_all(&extract_into)?;

    tarball
        .unpack(&extract_into)
        .map_err(|e| SandboxError::Extract(e.to_string()))?;

    let final_root = match adapter.strip_archive_prefix(pkg) {
        Some(prefix) => {
            let primary = extract_into.join(&prefix);
            if primary.exists() {
                primary
            } else {
                // Python normalizes distribution names to underscores, but the
                // separator before the version remains a hyphen.
                let alt = extract_into.join(
                    prefix
                        .strip_suffix(&format!("-{}", pkg.version))
                        .map_or_else(
                            || prefix.clone(),
                            |name| format!("{}-{}", name.replace('-', "_"), pkg.version),
                        ),
                );
                if alt.exists() {
                    alt
                } else {
                    primary
                }
            }
        }
        None => extract_into,
    };
    if !final_root.exists() {
        return Err(SandboxError::Extract(format!(
            "archive did not contain expected top-level directory at {}",
            final_root.display()
        )));
    }
    Ok(final_root)
}

pub fn hash_tree(
    adapter: &dyn EcosystemAdapter,
    root: &Path,
) -> Result<(FileTreeHash, Vec<clearhash_core::FileEntry>), SandboxError> {
    let entries = adapter.build_entries(root)?;
    let hash = FileTreeHash::from_sorted_entries(&entries);
    Ok((hash, entries))
}

pub fn compare_trees(
    adapter: &dyn EcosystemAdapter,
    registry_root: &Path,
    rebuild_root: &Path,
) -> Result<VerifyOutcome, SandboxError> {
    let (reg_hash, reg_entries) = hash_tree(adapter, registry_root)?;
    let (rb_hash, rb_entries) = hash_tree(adapter, rebuild_root)?;
    if reg_hash == rb_hash {
        Ok(VerifyOutcome::Match {
            tree_hash: reg_hash,
        })
    } else {
        Ok(VerifyOutcome::TreeMismatch {
            differences: tree::diff_sorted(&reg_entries, &rb_entries),
        })
    }
}

// Rebuild orchestration.

pub struct RebuildOutcome {
    /// Path to the rebuilt archive file on the host (e.g. the `.tgz` `npm pack` produced).
    pub artifact_path: PathBuf,
}

/// Source tree selected by a verified attestation or an explicit manual pin.
/// Contains no assertion about builder identity or signature verification.
#[derive(Debug, Clone)]
pub struct RebuildSource {
    pub source_repo: String,
    pub commit_sha: String,
}

impl From<&ProvenanceClaim> for RebuildSource {
    fn from(claim: &ProvenanceClaim) -> Self {
        Self {
            source_repo: claim.source_repo.clone(),
            commit_sha: claim.commit_sha.clone(),
        }
    }
}

pub async fn rebuild(
    adapter: &dyn EcosystemAdapter,
    source: &RebuildSource,
    pkg: &PackageRef,
    workdir: &Path,
) -> Result<RebuildOutcome, SandboxError> {
    let source_dir = workdir.join("source");
    let output_dir = workdir.join("rebuilt");
    std::fs::create_dir_all(&source_dir)?;
    std::fs::create_dir_all(&output_dir)?;

    clone_and_pin(&source.source_repo, &source.commit_sha, &source_dir).await?;

    let dependencies = offline::prepare(adapter, &source_dir, workdir).await?;

    let docker = Docker::connect_with_local_defaults()?;
    pull_image(&docker, adapter.rebuild_image(), adapter.rebuild_platform()).await?;

    let container_id = create_and_run(
        &docker,
        adapter,
        source,
        pkg,
        &source_dir,
        dependencies.as_deref(),
    )
    .await?;
    let logs_tail = wait_and_collect_logs(&docker, &container_id).await?;
    let exit_code = container_exit_code(&docker, &container_id).await?;
    if exit_code != 0 {
        let _ = docker.remove_container(&container_id, None).await;
        return Err(SandboxError::RebuildFailed(exit_code, logs_tail));
    }

    download_artifacts(
        &docker,
        &container_id,
        adapter.built_artifact_dir(),
        &output_dir,
    )
    .await?;
    let _ = docker.remove_container(&container_id, None).await;

    let artifact_path = pick_artifact(&output_dir)?;
    Ok(RebuildOutcome { artifact_path })
}

fn clean_git_url(repo: &str) -> &str {
    let repo = repo.strip_prefix("git+").unwrap_or(repo);
    // A SLSA URI can end in @refs/heads/main. Preserve SSH user@host prefixes.
    let path_start = repo.find("://").map_or(0, |i| i + 3);
    let path_start = repo[path_start..].find('/').map(|i| path_start + i);
    match (path_start, repo.rfind('@')) {
        (Some(path), Some(at)) if at > path => &repo[..at],
        _ => repo,
    }
}

async fn clone_and_pin(repo: &str, commit: &str, dest: &Path) -> Result<(), SandboxError> {
    // Strip `git+` prefix and trailing ref to feed `git clone`.
    let clean_url = clean_git_url(repo);

    let status = Command::new("git")
        .args(["clone", "--quiet", "--no-checkout", "--", clean_url, "."])
        .current_dir(dest)
        .stdin(Stdio::null())
        .status()
        .await
        .map_err(|e| SandboxError::Git(format!("spawn clone: {e}")))?;
    if !status.success() {
        return Err(SandboxError::Git(format!(
            "git clone {clean_url} failed with status {status:?}"
        )));
    }

    // Fetch the exact commit (may not be on a branch / may be unreachable in a shallow clone).
    let _ = Command::new("git")
        .args(["fetch", "--quiet", "origin", commit])
        .current_dir(dest)
        .stdin(Stdio::null())
        .status()
        .await
        .map_err(|e| SandboxError::Git(format!("spawn fetch: {e}")))?;

    let checkout = Command::new("git")
        .args(["checkout", "--quiet", "--detach", commit, "--"])
        .current_dir(dest)
        .stdin(Stdio::null())
        .status()
        .await
        .map_err(|e| SandboxError::Git(format!("spawn checkout: {e}")))?;
    if !checkout.success() {
        return Err(SandboxError::Git(format!(
            "git checkout {commit} failed (status {checkout:?})"
        )));
    }

    // Verify HEAD == commit. Defense against a malicious git server / DNS hijack.
    let head_out = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(dest)
        .output()
        .await
        .map_err(|e| SandboxError::Git(format!("rev-parse: {e}")))?;
    let head = String::from_utf8_lossy(&head_out.stdout).trim().to_string();
    if !head.eq_ignore_ascii_case(commit) {
        return Err(SandboxError::CommitDrift {
            expected: commit.into(),
            actual: head,
        });
    }
    tracing::info!(commit = %commit, "git HEAD pinned");
    Ok(())
}

async fn pull_image(
    docker: &Docker,
    image: &str,
    platform: Option<&str>,
) -> Result<(), SandboxError> {
    let options = CreateImageOptions {
        from_image: Some(image.to_string()),
        platform: platform.unwrap_or_default().to_string(),
        ..Default::default()
    };
    let mut stream = docker.create_image(Some(options), None, None);
    while let Some(msg) = stream.next().await {
        match msg {
            Ok(info) => {
                if let Some(status) = info.status {
                    tracing::debug!(image, status, "pull");
                }
            }
            Err(e) => return Err(SandboxError::Docker(e)),
        }
    }
    Ok(())
}

async fn create_and_run(
    docker: &Docker,
    adapter: &dyn EcosystemAdapter,
    source: &RebuildSource,
    pkg: &PackageRef,
    source_dir: &Path,
    dependencies: Option<&Path>,
) -> Result<String, SandboxError> {
    let script = adapter
        .rebuild_script()
        .replace("{COMMIT_SHA}", &source.commit_sha)
        .replace("{REPO_URL}", &source.source_repo)
        .replace("{PKG_NAME}", &pkg.name)
        .replace("{PKG_VERSION}", &pkg.version);

    let source_abs = std::fs::canonicalize(source_dir)?;
    let mut binds = vec![format!("{}:/src", source_abs.display())];
    if let Some(dependencies) = dependencies {
        binds.push(format!(
            "{}:/deps:ro",
            std::fs::canonicalize(dependencies)?.display()
        ));
    }

    let config: ContainerCreateBody = ContainerCreateBody {
        image: Some(adapter.rebuild_image().to_string()),
        cmd: Some(vec!["/bin/sh".into(), "-c".into(), script]),
        working_dir: Some("/src".into()),
        env: Some(vec![
            format!("PKG_NAME={}", pkg.name),
            format!("PKG_VERSION={}", pkg.version),
        ]),
        host_config: Some(HostConfig {
            binds: Some(binds),
            network_mode: dependencies.map(|_| "none".to_string()),
            auto_remove: Some(false),
            ..Default::default()
        }),
        ..Default::default()
    };

    let name = format!("clearhash-rebuild-{}", &source.commit_sha[..12]);
    let opts = CreateContainerOptions {
        name: Some(name.clone()),
        platform: adapter.rebuild_platform().unwrap_or_default().to_string(),
    };
    let created = docker.create_container(Some(opts), config).await?;
    docker.start_container(&created.id, None).await?;
    Ok(created.id)
}

async fn wait_and_collect_logs(
    docker: &Docker,
    container_id: &str,
) -> Result<String, SandboxError> {
    let mut wait = docker.wait_container(container_id, None::<WaitContainerOptions>);
    // Drain wait stream so the container has exited before we collect logs.
    while wait.next().await.is_some() {}

    let mut log_stream = docker.logs(
        container_id,
        Some(LogsOptions {
            stdout: true,
            stderr: true,
            tail: "200".into(),
            ..Default::default()
        }),
    );
    let mut tail = String::new();
    while let Some(chunk) = log_stream.next().await {
        match chunk {
            Ok(c) => tail.push_str(&c.to_string()),
            Err(_) => break,
        }
    }
    Ok(tail)
}

async fn container_exit_code(docker: &Docker, container_id: &str) -> Result<i64, SandboxError> {
    let inspect = docker.inspect_container(container_id, None).await?;
    Ok(inspect.state.and_then(|s| s.exit_code).unwrap_or(0))
}

async fn download_artifacts(
    docker: &Docker,
    container_id: &str,
    container_path: &str,
    dest: &Path,
) -> Result<(), SandboxError> {
    let options = bollard::query_parameters::DownloadFromContainerOptions {
        path: container_path.to_string(),
    };
    let mut stream = docker.download_from_container(container_id, Some(options));
    let mut tar_bytes: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let bytes = chunk?;
        tar_bytes.extend_from_slice(&bytes);
    }

    // The downloaded stream is an uncompressed tar of `container_path`'s contents.
    let mut tarball = tar::Archive::new(std::io::Cursor::new(tar_bytes));
    std::fs::create_dir_all(dest)?;
    tarball
        .unpack(dest)
        .map_err(|e| SandboxError::Extract(format!("download-from-container unpack: {e}")))?;
    Ok(())
}

/// Locate the rebuilt artifact inside `dest`. We expect exactly one `.tgz` / `.tar.gz` /
/// `.crate` file produced by the rebuild script. The download_from_container call places
/// the contents of (e.g.) `/out` under `dest/out/`.
fn pick_artifact(dest: &Path) -> Result<PathBuf, SandboxError> {
    let mut candidates = Vec::new();
    for entry in walkdir::WalkDir::new(dest)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let is_archive = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.ends_with(".tgz") || n.ends_with(".tar.gz") || n.ends_with(".crate"))
            .unwrap_or(false);
        if is_archive {
            candidates.push(path.to_path_buf());
        }
    }
    match candidates.len() {
        0 => Err(SandboxError::Extract(format!(
            "no artifact (.tgz/.tar.gz/.crate) found under {}",
            dest.display()
        ))),
        1 => Ok(candidates.remove(0)),
        _ => Err(SandboxError::Extract(format!(
            "rebuild produced {} candidate artifacts; expected exactly 1: {:?}",
            candidates.len(),
            candidates
        ))),
    }
}

/// Convenience: wait briefly so docker daemon socket connection is reliable in tests
/// and verify that the daemon supports Linux containers. On Windows runners, Docker
/// may run Windows containers where Linux-based rebuild images have no matching manifest.
pub async fn docker_reachable() -> bool {
    tokio::time::timeout(Duration::from_secs(3), async {
        match Docker::connect_with_local_defaults() {
            Ok(d) => {
                if d.ping().await.is_err() {
                    return false;
                }
                match d.info().await {
                    Ok(info) => {
                        let os_type = info.os_type.as_deref().unwrap_or_default();
                        os_type.eq_ignore_ascii_case("linux")
                    }
                    Err(_) => false,
                }
            }
            Err(_) => false,
        }
    })
    .await
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clearhash_ecosystems::for_ecosystem;
    use std::io::Write;

    fn git(repo: &Path, args: &[&str]) -> String {
        let out = std::process::Command::new("git")
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env(
                "GIT_CONFIG_GLOBAL",
                if cfg!(windows) { "NUL" } else { "/dev/null" },
            )
            .current_dir(repo)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    }

    fn commit_fixture(repo: &Path) -> String {
        git(repo, &["add", "."]);
        git(
            repo,
            &[
                "-c",
                "user.name=ClearHash Test",
                "-c",
                "user.email=test@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-m",
                "fixture",
            ],
        );
        git(repo, &["rev-parse", "HEAD"])
    }

    #[test]
    fn git_url_cleaning_preserves_ssh_users() {
        for (input, expected) in [
            (
                "git+https://example.com/repo@refs/heads/main",
                "https://example.com/repo",
            ),
            (
                "git+ssh://git@example.com/owner/repo.git@refs/tags/v1",
                "ssh://git@example.com/owner/repo.git",
            ),
            (
                "ssh://git@example.com/owner/repo.git",
                "ssh://git@example.com/owner/repo.git",
            ),
            (
                "git@example.com:owner/repo.git",
                "git@example.com:owner/repo.git",
            ),
        ] {
            assert_eq!(clean_git_url(input), expected);
        }
    }

    #[tokio::test]
    async fn checkout_pins_an_older_commit_and_rejects_a_ref() {
        let repo = tempfile::tempdir().unwrap();
        git(repo.path(), &["init", "--quiet"]);
        std::fs::write(repo.path().join("source"), "original").unwrap();
        let pin = commit_fixture(repo.path());
        std::fs::write(repo.path().join("source"), "later").unwrap();
        commit_fixture(repo.path());
        let dest = tempfile::tempdir().unwrap();
        clone_and_pin(repo.path().to_str().unwrap(), &pin, dest.path())
            .await
            .unwrap();
        assert_eq!(git(dest.path(), &["rev-parse", "HEAD"]), pin);
        assert_eq!(
            std::fs::read_to_string(dest.path().join("source")).unwrap(),
            "original"
        );
        let dest = tempfile::tempdir().unwrap();
        assert!(matches!(
            clone_and_pin(repo.path().to_str().unwrap(), "HEAD", dest.path()).await,
            Err(SandboxError::CommitDrift { .. })
        ));
        let dest = tempfile::tempdir().unwrap();
        assert!(
            clone_and_pin(repo.path().to_str().unwrap(), &"0".repeat(40), dest.path())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn cargo_pinned_workspace_rebuild_matches_and_detects_tampering() {
        if !docker_reachable().await {
            eprintln!("skipping Cargo rebuild: Docker daemon unreachable");
            return;
        }
        let repo = tempfile::tempdir().unwrap();
        git(repo.path(), &["init", "--quiet"]);
        std::fs::create_dir_all(repo.path().join("member/src")).unwrap();
        std::fs::write(
            repo.path().join("Cargo.toml"),
            "[workspace]\nmembers = [\"member\"]\nresolver = \"2\"\n",
        )
        .unwrap();
        std::fs::write(
            repo.path().join("member/Cargo.toml"),
            "[package]\nname = \"clearhash-fixture\"\nversion = \"1.0.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::write(
            repo.path().join("member/src/lib.rs"),
            "pub fn answer() -> u8 { 42 }\n",
        )
        .unwrap();
        std::fs::write(
            repo.path().join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname = \"clearhash-fixture\"\nversion = \"1.0.0\"\n",
        )
        .unwrap();
        let pin = commit_fixture(repo.path());
        let pkg: PackageRef = "cargo:clearhash-fixture@1.0.0".parse().unwrap();
        let adapter = for_ecosystem(pkg.ecosystem);
        let source = RebuildSource {
            source_repo: repo.path().to_string_lossy().into(),
            commit_sha: pin,
        };
        let registry_dir = tempfile::tempdir().unwrap();
        let registry = rebuild(&*adapter, &source, &pkg, registry_dir.path())
            .await
            .unwrap();
        // The repository's default branch advances; verification must still rebuild the pin.
        std::fs::write(
            repo.path().join("member/src/lib.rs"),
            "pub fn answer() -> u8 { 0 }\n",
        )
        .unwrap();
        commit_fixture(repo.path());
        let rebuilt_dir = tempfile::tempdir().unwrap();
        let rebuilt = rebuild(&*adapter, &source, &pkg, rebuilt_dir.path())
            .await
            .unwrap();
        let reg_root = extract_archive(
            &*adapter,
            &registry.artifact_path,
            &pkg,
            &registry_dir.path().join("registry"),
        )
        .unwrap();
        let rb_root = extract_archive(
            &*adapter,
            &rebuilt.artifact_path,
            &pkg,
            &rebuilt_dir.path().join("rebuild"),
        )
        .unwrap();
        assert!(reg_root.join(".cargo_vcs_info.json").is_file());
        assert!(matches!(
            compare_trees(&*adapter, &reg_root, &rb_root).unwrap(),
            VerifyOutcome::Match { .. }
        ));
        std::fs::write(
            reg_root.join("src/lib.rs"),
            "pub fn answer() -> u8 { 99 }\n",
        )
        .unwrap();
        let outcome = compare_trees(&*adapter, &reg_root, &rb_root).unwrap();
        assert_eq!(outcome.exit_code(), 1);
        assert!(
            matches!(outcome, VerifyOutcome::TreeMismatch { differences } if differences.iter().any(|d| matches!(d, clearhash_core::TreeDifference::ContentDiffers { path } if path == "src/lib.rs")))
        );
        let wrong_version: PackageRef = "cargo:clearhash-fixture@9.0.0".parse().unwrap();
        let wrong_dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            rebuild(&*adapter, &source, &wrong_version, wrong_dir.path()).await,
            Err(SandboxError::RebuildFailed(..))
        ));
    }

    #[tokio::test]
    async fn npm_native_platform_rebuild_matches_and_detects_binary_tampering() {
        use clearhash_ecosystems::npm::{NpmAdapter, NpmPlatform};
        if !docker_reachable().await {
            eprintln!("skipping npm native rebuild: Docker daemon unreachable");
            return;
        }
        let (platform, cpu) = match std::env::consts::ARCH {
            "x86_64" => (NpmPlatform::LinuxAmd64, "x64"),
            "aarch64" => (NpmPlatform::LinuxArm64, "arm64"),
            _ => return,
        };
        let repo = tempfile::tempdir().unwrap();
        git(repo.path(), &["init", "--quiet"]);
        // Exercise selection of a platform-specific package in a workspace.
        std::fs::create_dir_all(repo.path().join("native")).unwrap();
        std::fs::write(
            repo.path().join("package.json"),
            r#"{"name":"fixture-root","private":true,"workspaces":["native"]}"#,
        )
        .unwrap();
        let mut manifest = serde_json::json!({
            "name": "@clearhash/addon-linux", "version": "1.0.0",
            "os": ["linux"], "cpu": [cpu], "libc": ["glibc"],
            "files": ["build/Release/addon.node"],
            "scripts": {
                "preinstall": "node -e 'process.exit(81)'",
                "install": "node -e 'process.exit(82)'",
                "postinstall": "node -e 'process.exit(83)'",
                "prepare": "node -e 'process.exit(84)'",
                "prepack": "node -e 'process.exit(85)'",
                "prebuild": "node -e 'process.exit(86)'",
                "postbuild": "node -e 'process.exit(87)'",
                "build": format!("node -e \"if(process.arch !== '{cpu}' || require('./build/Release/addon.node').answer() !== 42) process.exit(1)\"")
            }
        });
        let manifest_path = repo.path().join("native/package.json");
        std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        std::fs::write(
            repo.path().join("native/binding.gyp"),
            r#"{"targets":[{"target_name":"addon","sources":["addon.c"]}]}"#,
        )
        .unwrap();
        std::fs::write(
            repo.path().join("native/addon.c"),
            r#"
#include <node_api.h>
static napi_value answer(napi_env env, napi_callback_info info) {
    napi_value value;
    napi_create_int32(env, 42, &value);
    return value;
}
static napi_value init(napi_env env, napi_value exports) {
    napi_value fn;
    napi_create_function(env, "answer", NAPI_AUTO_LENGTH, answer, NULL, &fn);
    napi_set_named_property(env, exports, "answer", fn);
    return exports;
}
NAPI_MODULE(NODE_GYP_MODULE_NAME, init)
"#,
        )
        .unwrap();
        std::fs::write(
            repo.path().join("package-lock.json"),
            serde_json::json!({"name":"fixture-root", "lockfileVersion":3, "requires":true, "packages": {
                "": {"name":"fixture-root", "workspaces":["native"]},
                "native": {"name":"@clearhash/addon-linux", "version":"1.0.0"},
                "node_modules/@clearhash/addon-linux": {"resolved":"native", "link":true}
            }}).to_string(),
        ).unwrap();
        let source = RebuildSource {
            source_repo: repo.path().to_string_lossy().into(),
            commit_sha: commit_fixture(repo.path()),
        };
        let pkg: PackageRef = "npm:@clearhash/addon-linux@1.0.0".parse().unwrap();
        let adapter = NpmAdapter::for_platform(platform);
        let registry_dir = tempfile::tempdir().unwrap();
        let registry = rebuild(&adapter, &source, &pkg, registry_dir.path())
            .await
            .unwrap();
        let rebuild_dir = tempfile::tempdir().unwrap();
        let rebuilt = rebuild(&adapter, &source, &pkg, rebuild_dir.path())
            .await
            .unwrap();
        let reg_root = extract_archive(
            &adapter,
            &registry.artifact_path,
            &pkg,
            &registry_dir.path().join("tree"),
        )
        .unwrap();
        let rb_root = extract_archive(
            &adapter,
            &rebuilt.artifact_path,
            &pkg,
            &rebuild_dir.path().join("tree"),
        )
        .unwrap();
        let binary = reg_root.join("build/Release/addon.node");
        assert!(std::fs::read(&binary).unwrap().starts_with(b"\x7fELF"));
        assert!(matches!(
            compare_trees(&adapter, &reg_root, &rb_root).unwrap(),
            VerifyOutcome::Match { .. }
        ));
        std::fs::write(binary, b"tampered native binary").unwrap();
        assert!(
            matches!(compare_trees(&adapter, &reg_root, &rb_root).unwrap(),
            VerifyOutcome::TreeMismatch { differences } if differences.iter().any(|d| matches!(d,
                clearhash_core::TreeDifference::ContentDiffers { path } if path == "build/Release/addon.node")))
        );

        // A build failure must not be swallowed, packed, or reported as a match.
        manifest["scripts"]["build"] = serde_json::json!("node -e 'process.exit(19)'");
        std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        let source = RebuildSource {
            commit_sha: commit_fixture(repo.path()),
            ..source
        };
        let failed_dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            rebuild(&adapter, &source, &pkg, failed_dir.path()).await,
            Err(SandboxError::RebuildFailed(..))
        ));

        // Source constraints are checked independently of registry declarations.
        manifest["os"] = serde_json::json!(["darwin"]);
        std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        let source = RebuildSource {
            commit_sha: commit_fixture(repo.path()),
            ..source
        };
        let failed_dir = tempfile::tempdir().unwrap();
        assert!(
            matches!(rebuild(&adapter, &source, &pkg, failed_dir.path()).await,
            Err(SandboxError::RebuildFailed(_, log)) if log.contains("source os does not support linux"))
        );
    }

    #[tokio::test]
    async fn npm_offline_install_uses_verified_tarballs_without_network() {
        use clearhash_ecosystems::offline::Integrity;
        if !docker_reachable().await {
            eprintln!("skipping offline npm rebuild: Docker daemon unreachable");
            return;
        }
        let docker = Docker::connect_with_local_defaults().unwrap();
        let adapter = for_ecosystem(clearhash_core::Ecosystem::Npm);
        pull_image(&docker, adapter.rebuild_image(), None)
            .await
            .unwrap();
        for algorithm in ["sha512", "sha384", "sha256"] {
            let source = tempfile::tempdir().unwrap();
            let dependencies = tempfile::tempdir().unwrap();
            let tarball = make_npm_tarball(dependencies.path(), "0.tgz", "module.exports = 42;");
            // Compute SRI with the pinned image's Node crypto, independently of Rust verification.
            let output = std::process::Command::new("docker").args([
                "run", "--rm", "--network=none", "-v",
                &format!("{}:/deps:ro", dependencies.path().display()),
                adapter.rebuild_image(), "node", "-e",
                &format!("console.log('{algorithm}-' + require('crypto').createHash('{algorithm}').update(require('fs').readFileSync('/deps/0.tgz')).digest('base64'))")
            ]).output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let sri = String::from_utf8(output.stdout).unwrap().trim().to_string();
            assert!(Integrity::parse(&sri)
                .unwrap()
                .matches(&std::fs::read(tarball).unwrap()));
            let build = r#"node -e "if(require('x') !== 42 || Object.values(require('os').networkInterfaces()).flat().some(i => !i.internal)) process.exit(1); console.log('offline-build-ok')""#;
            std::fs::write(source.path().join("package.json"), serde_json::json!({
                "name":"offline-fixture", "version":"1.0.0", "dependencies":{"x":"1.0.0"},
                "scripts":{"build":build,"preinstall":"exit 81","prepare":"exit 82","prepack":"exit 83"}
            }).to_string()).unwrap();
            std::fs::write(source.path().join("package-lock.json"), serde_json::json!({
                "name":"offline-fixture", "version":"1.0.0", "lockfileVersion":3, "requires":true,
                "packages": {
                    "":{"name":"offline-fixture","version":"1.0.0","dependencies":{"x":"1.0.0"}},
                    "node_modules/x":{"version":"1.0.0","resolved":"https://registry.invalid/x.tgz","integrity":sri}
                }
            }).to_string()).unwrap();
            if algorithm == "sha512" {
                let path = source.path().join("package-lock.json");
                let mut lock: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                lock["packages"]["node_modules/x"]
                    .as_object_mut()
                    .unwrap()
                    .remove("resolved");
                std::fs::write(path, lock.to_string()).unwrap();
            }
            let locked = adapter
                .offline_dependencies(source.path())
                .unwrap()
                .unwrap();
            assert_eq!(locked.len(), 1);
            assert_eq!(locked[0].filename, "0.tgz");
            let committed_lock = std::fs::read(source.path().join("package-lock.json")).unwrap();
            let pin = RebuildSource {
                source_repo: "unused".into(),
                commit_sha: "0123456789abcdef0123456789abcdef01234567".into(),
            };
            let pkg = "npm:offline-fixture@1.0.0".parse().unwrap();
            let id = create_and_run(
                &docker,
                &*adapter,
                &pin,
                &pkg,
                source.path(),
                Some(dependencies.path()),
            )
            .await
            .unwrap();
            let logs = wait_and_collect_logs(&docker, &id).await.unwrap();
            let exit = container_exit_code(&docker, &id).await.unwrap();
            let config = docker.inspect_container(&id, None).await.unwrap();
            let out = tempfile::tempdir().unwrap();
            download_artifacts(&docker, &id, "/out", out.path())
                .await
                .unwrap();
            docker.remove_container(&id, None).await.unwrap();
            assert_eq!(exit, 0, "{logs}");
            assert!(logs.contains("offline-build-ok"), "{logs}");
            assert_eq!(
                std::fs::read(source.path().join("package-lock.json")).unwrap(),
                committed_lock
            );
            assert_eq!(
                config.host_config.unwrap().network_mode.as_deref(),
                Some("none")
            );
            assert!(pick_artifact(out.path()).is_ok());

            // An empty verified cache must fail rather than contact the URL in the lockfile.
            std::fs::remove_file(dependencies.path().join("0.tgz")).unwrap();
            let id = create_and_run(
                &docker,
                &*adapter,
                &pin,
                &pkg,
                source.path(),
                Some(dependencies.path()),
            )
            .await
            .unwrap();
            let logs = wait_and_collect_logs(&docker, &id).await.unwrap();
            let exit = container_exit_code(&docker, &id).await.unwrap();
            docker.remove_container(&id, None).await.unwrap();
            assert_ne!(
                exit, 0,
                "missing offline dependency unexpectedly installed: {logs}"
            );
        }
    }

    #[tokio::test]
    async fn pypi_offline_build_uses_locked_wheels_and_fails_on_missing_backend() {
        if !docker_reachable().await {
            eprintln!("skipping offline PyPI rebuild: Docker daemon unreachable");
            return;
        }
        let repo = tempfile::tempdir().unwrap();
        git(repo.path(), &["init", "--quiet"]);
        std::fs::write(
            repo.path().join("pylock.toml"),
            include_str!("../tests/fixtures/pylock.toml"),
        )
        .unwrap();
        std::fs::write(
            repo.path().join("pyproject.toml"),
            r#"
[build-system]
requires = ["setuptools==75.8.0"]
build-backend = "backend"
backend-path = ["."]
[project]
name = "offline-fixture"
version = "1.0.0"
"#,
        )
        .unwrap();
        std::fs::write(
            repo.path().join("backend.py"),
            r#"
import socket
from setuptools.build_meta import *
# Both the build-requirements probe and the sdist builder execute without a network.
try:
    socket.create_connection(("1.1.1.1", 443), timeout=1)
except OSError:
    pass
else:
    raise RuntimeError("build backend unexpectedly has network access")
"#,
        )
        .unwrap();
        let pin = RebuildSource {
            source_repo: repo.path().to_string_lossy().into(),
            commit_sha: commit_fixture(repo.path()),
        };
        let adapter = for_ecosystem(clearhash_core::Ecosystem::Pypi);
        let pkg = "pypi:offline-fixture@1.0.0".parse().unwrap();
        let work = tempfile::tempdir().unwrap();
        let rebuilt = rebuild(&*adapter, &pin, &pkg, work.path()).await.unwrap();
        let tree = extract_archive(&*adapter, &rebuilt.artifact_path, &pkg, work.path()).unwrap();
        assert!(tree.join("backend.py").exists());
        // Preserve a valid lockfile but omit the backend wheel from its closure.
        let lock = include_str!("../tests/fixtures/pylock.toml");
        let last = lock.rfind("[[packages]]").unwrap();
        std::fs::write(repo.path().join("pylock.toml"), &lock[..last]).unwrap();
        let pin = RebuildSource {
            commit_sha: commit_fixture(repo.path()),
            ..pin
        };
        let work = tempfile::tempdir().unwrap();
        assert!(matches!(
            rebuild(&*adapter, &pin, &pkg, work.path()).await,
            Err(SandboxError::RebuildFailed(..))
        ));
    }

    fn make_npm_tarball(dir: &Path, name: &str, content: &str) -> PathBuf {
        let path = dir.join(name);
        let f = std::fs::File::create(&path).unwrap();
        let gz = flate2::write::GzEncoder::new(f, flate2::Compression::default());
        let mut tar = tar::Builder::new(gz);

        let pkg_json = br#"{"name":"x","version":"1.0.0"}"#;
        let mut h = tar::Header::new_gnu();
        h.set_path("package/package.json").unwrap();
        h.set_size(pkg_json.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        tar.append(&h, &pkg_json[..]).unwrap();

        let mut h = tar::Header::new_gnu();
        h.set_path("package/index.js").unwrap();
        h.set_size(content.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        tar.append(&h, content.as_bytes()).unwrap();

        let gz = tar.into_inner().unwrap();
        gz.finish().unwrap().flush().unwrap();
        path
    }

    #[test]
    fn extract_strips_package_prefix() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg = PackageRef {
            ecosystem: clearhash_core::Ecosystem::Npm,
            name: "x".into(),
            version: "1.0.0".into(),
        };
        let archive = make_npm_tarball(tmp.path(), "x-1.0.0.tgz", "console.log('a')");
        let adapter = for_ecosystem(clearhash_core::Ecosystem::Npm);

        let root = extract_archive(&*adapter, &archive, &pkg, tmp.path()).unwrap();
        assert!(root.join("package.json").exists());
        assert!(root.join("index.js").exists());
    }

    #[test]
    fn identical_trees_compare_as_match() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg = PackageRef {
            ecosystem: clearhash_core::Ecosystem::Npm,
            name: "x".into(),
            version: "1.0.0".into(),
        };
        let reg_tgz = make_npm_tarball(tmp.path(), "reg.tgz", "console.log('a')");
        let rb_tgz = make_npm_tarball(tmp.path(), "rb.tgz", "console.log('a')");

        let reg_dir = tempfile::tempdir().unwrap();
        let rb_dir = tempfile::tempdir().unwrap();
        let adapter = for_ecosystem(clearhash_core::Ecosystem::Npm);
        let r1 = extract_archive(&*adapter, &reg_tgz, &pkg, reg_dir.path()).unwrap();
        let r2 = extract_archive(&*adapter, &rb_tgz, &pkg, rb_dir.path()).unwrap();

        let outcome = compare_trees(&*adapter, &r1, &r2).unwrap();
        assert!(matches!(outcome, VerifyOutcome::Match { .. }));
    }

    #[test]
    fn content_change_compares_as_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg = PackageRef {
            ecosystem: clearhash_core::Ecosystem::Npm,
            name: "x".into(),
            version: "1.0.0".into(),
        };
        let reg_tgz = make_npm_tarball(tmp.path(), "reg.tgz", "console.log('a')");
        let rb_tgz = make_npm_tarball(tmp.path(), "rb.tgz", "console.log('TAMPERED')");

        let reg_dir = tempfile::tempdir().unwrap();
        let rb_dir = tempfile::tempdir().unwrap();
        let adapter = for_ecosystem(clearhash_core::Ecosystem::Npm);
        let r1 = extract_archive(&*adapter, &reg_tgz, &pkg, reg_dir.path()).unwrap();
        let r2 = extract_archive(&*adapter, &rb_tgz, &pkg, rb_dir.path()).unwrap();

        let outcome = compare_trees(&*adapter, &r1, &r2).unwrap();
        match outcome {
            VerifyOutcome::TreeMismatch { differences } => {
                assert!(differences.iter().any(|d| matches!(
                    d,
                    clearhash_core::TreeDifference::ContentDiffers { path } if path == "index.js"
                )));
            }
            other => panic!("expected TreeMismatch, got {:?}", other),
        }
    }
}
