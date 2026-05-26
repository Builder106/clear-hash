//! Docker rebuild orchestration + file-tree comparison.
//!
//! The rebuild pipeline:
//!   1. On the host: `git clone --depth=1` the attested source repo, then `git fetch origin
//!      <commit>` and `git checkout <commit>`. Verify `HEAD` matches the attested SHA — defends
//!      against a tampered git server returning a different tree for the requested ref.
//!   2. Pull the adapter's pinned Docker image (cache hit common).
//!   3. Create a fresh container with the source tree bind-mounted at `/src`. Run the adapter's
//!      rebuild script with `SOURCE_DATE_EPOCH` set to the commit's author time.
//!   4. `download_from_container /out` to extract the rebuilt artifact back to the host.
//!
//! Network model: the rebuild container has default network (bridge). It needs network to run
//! `npm ci` / `pip install` / `cargo download`, which fetch lockfile-pinned dependencies. The
//! lockfile is part of the attested source tree, so the dependency closure is deterministic
//! by content even though the registry is queried. `--ignore-scripts` blocks the highest-impact
//! exfiltration path (lifecycle hooks). Fully air-gapped builds via pre-fetched offline caches
//! are a v1.1 hardening (see ROADMAP.md).

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

pub mod simulate_tamper;

use bollard::container::{Config, CreateContainerOptions, LogsOptions, WaitContainerOptions};
use bollard::image::CreateImageOptions;
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
    #[error("git: {0}")]
    Git(String),
    #[error("rebuild script exited with status {0}; stderr tail: {1}")]
    RebuildFailed(i64, String),
    #[error("checked-out HEAD ({actual}) does not match attested commit ({expected})")]
    CommitDrift { expected: String, actual: String },
}

// -----------------------------------------------------------------------------------------
// Tarball extraction & tree-hashing (used by both registry-side and rebuild-side trees).
// -----------------------------------------------------------------------------------------

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
        Some(prefix) => extract_into.join(prefix),
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

// -----------------------------------------------------------------------------------------
// Rebuild orchestration.
// -----------------------------------------------------------------------------------------

pub struct RebuildOutcome {
    /// Path to the rebuilt archive file on the host (e.g. the `.tgz` `npm pack` produced).
    pub artifact_path: PathBuf,
}

pub async fn rebuild(
    adapter: &dyn EcosystemAdapter,
    claim: &ProvenanceClaim,
    pkg: &PackageRef,
    workdir: &Path,
) -> Result<RebuildOutcome, SandboxError> {
    let source_dir = workdir.join("source");
    let output_dir = workdir.join("rebuilt");
    std::fs::create_dir_all(&source_dir)?;
    std::fs::create_dir_all(&output_dir)?;

    clone_and_pin(&claim.source_repo, &claim.commit_sha, &source_dir).await?;

    let docker = Docker::connect_with_local_defaults()?;
    pull_image(&docker, adapter.rebuild_image()).await?;

    let container_id = create_and_run(&docker, adapter, claim, pkg, &source_dir).await?;
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

async fn clone_and_pin(repo: &str, commit: &str, dest: &Path) -> Result<(), SandboxError> {
    // Strip `git+` prefix and trailing ref to feed `git clone`.
    let clean_url = repo
        .strip_prefix("git+")
        .unwrap_or(repo)
        .split('@')
        .next()
        .unwrap_or(repo);

    let status = Command::new("git")
        .args(["clone", "--quiet", "--no-checkout", clean_url, "."])
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
        .args(["checkout", "--quiet", commit])
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

async fn pull_image(docker: &Docker, image: &str) -> Result<(), SandboxError> {
    let options = CreateImageOptions {
        from_image: image,
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
    claim: &ProvenanceClaim,
    pkg: &PackageRef,
    source_dir: &Path,
) -> Result<String, SandboxError> {
    let script = adapter
        .rebuild_script()
        .replace("{COMMIT_SHA}", &claim.commit_sha)
        .replace("{REPO_URL}", &claim.source_repo)
        .replace("{PKG_NAME}", &pkg.name)
        .replace("{PKG_VERSION}", &pkg.version);

    let source_abs = std::fs::canonicalize(source_dir)?;
    let bind = format!("{}:/src", source_abs.display());

    let config: Config<String> = Config {
        image: Some(adapter.rebuild_image().to_string()),
        cmd: Some(vec!["/bin/sh".into(), "-c".into(), script]),
        working_dir: Some("/src".into()),
        host_config: Some(bollard::secret::HostConfig {
            binds: Some(vec![bind]),
            auto_remove: Some(false),
            ..Default::default()
        }),
        ..Default::default()
    };

    let name = format!("clearhash-rebuild-{}", &claim.commit_sha[..12]);
    let opts = CreateContainerOptions {
        name: name.clone(),
        platform: None,
    };
    let created = docker.create_container(Some(opts), config).await?;
    docker.start_container::<String>(&created.id, None).await?;
    Ok(created.id)
}

async fn wait_and_collect_logs(
    docker: &Docker,
    container_id: &str,
) -> Result<String, SandboxError> {
    let mut wait = docker.wait_container(container_id, None::<WaitContainerOptions<String>>);
    // Drain wait stream so the container has exited before we collect logs.
    while wait.next().await.is_some() {}

    let mut log_stream = docker.logs(
        container_id,
        Some(LogsOptions::<String> {
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
    let options = bollard::container::DownloadFromContainerOptions {
        path: container_path,
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

/// Convenience: wait briefly so docker daemon socket connection is reliable in tests.
pub async fn docker_reachable() -> bool {
    tokio::time::timeout(Duration::from_secs(3), async {
        match Docker::connect_with_local_defaults() {
            Ok(d) => d.ping().await.is_ok(),
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
