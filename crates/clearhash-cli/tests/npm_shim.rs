//! Process-boundary tests use local delegates; no registry or Docker is required.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::json;

const SHIM: &str = env!("CARGO_BIN_EXE_clearhash-npm");
const SRI: &str = "sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=";

struct Fixture {
    _temp: tempfile::TempDir,
    project: PathBuf,
    npm: PathBuf,
    verify: PathBuf,
    lock: PathBuf,
    events: PathBuf,
}

fn script(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join("project with spaces");
        fs::create_dir(&project).unwrap();
        fs::write(
            project.join("package.json"),
            b"{\"name\":\"project\",\"version\":\"1.0.0\"}\n",
        )
        .unwrap();
        fs::create_dir(project.join("node_modules")).unwrap();
        fs::write(project.join("node_modules/sentinel"), "untouched").unwrap();
        let npm = temp.path().join("real npm");
        script(
            &npm,
            r#"#!/bin/sh
set -eu
case "$1" in
  --version) echo "${NPM_VERSION:-11.0.0}"; exit 0 ;;
  install)
    printf 'resolve %s\n' "$*" >> "$EVENTS"
    cp "$LOCK" package-lock.json
    exit "${RESOLVE_EXIT:-0}" ;;
  ci)
    printf 'install %s\n' "$*" >> "$EVENTS"
    exit "${INSTALL_EXIT:-0}" ;;
  *) printf 'passthrough %s\n' "$*" >> "$EVENTS"; exit 17 ;;
esac
"#,
        );
        let verify = temp.path().join("verify package");
        script(
            &verify,
            r#"#!/bin/sh
set -eu
printf 'verify %s\n' "$*" >> "$EVENTS"
if [ -n "${MUTATE:-}" ]; then printf 'changed' > "$MUTATE"; fi
if [ "${FAIL_PACKAGE:-}" = "$2" ]; then exit "${VERIFY_EXIT:-1}"; fi
exit 0
"#,
        );
        let lock = temp.path().join("resolved.json");
        let events = temp.path().join("events");
        let fixture = Self {
            _temp: temp,
            project,
            npm,
            verify,
            lock,
            events,
        };
        fixture.write_lock(json!({
            "node_modules/a":{"version":"1.0.0","integrity":SRI},
            "node_modules/a/node_modules/b":{"version":"2.0.0","integrity":SRI,"dev":true},
            "node_modules/b":{"version":"2.0.0","integrity":SRI},
            "node_modules/alias":{"name":"@org/pkg","version":"3.0.0","integrity":SRI,"optional":true}
        }));
        fixture
    }

    fn write_lock(&self, packages: serde_json::Value) {
        let mut packages = packages.as_object().unwrap().clone();
        packages.insert("".into(), json!({"name":"project","version":"1.0.0"}));
        fs::write(
            &self.lock,
            serde_json::to_vec(&json!({"lockfileVersion":3,"packages":packages})).unwrap(),
        )
        .unwrap();
    }

    fn command(&self) -> Command {
        let mut command = Command::new(SHIM);
        command
            .current_dir(&self.project)
            .env("CLEARHASH_REAL_NPM", &self.npm)
            .env("CLEARHASH_VERIFY_BIN", &self.verify)
            .env_remove("CLEARHASH_NPM_ACTIVE")
            .env_remove("CLEARHASH_NPM_POLICY_FILE")
            .env("EVENTS", &self.events)
            .env("LOCK", &self.lock);
        command
    }

    fn events(&self) -> String {
        fs::read_to_string(&self.events).unwrap_or_default()
    }

    fn assert_untouched(&self) {
        assert_eq!(
            fs::read(self.project.join("package.json")).unwrap(),
            b"{\"name\":\"project\",\"version\":\"1.0.0\"}\n"
        );
        assert!(!self.project.join("package-lock.json").exists());
        assert_eq!(
            fs::read_to_string(self.project.join("node_modules/sentinel")).unwrap(),
            "untouched"
        );
    }
}

fn assert_code(output: &Output, code: i32) {
    assert_eq!(
        output.status.code(),
        Some(code),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn installation_follows_all_deduplicated_verifications_with_integrity_binding() {
    let f = Fixture::new();
    let output = f
        .command()
        .args(["install", "a@^1", "-D", "--legacy-peer-deps"])
        .output()
        .unwrap();
    assert_code(&output, 0);
    let events = f.events();
    let lines: Vec<_> = events.lines().collect();
    assert_eq!(lines.len(), 5, "{events}");
    assert!(lines[0].starts_with("resolve install "));
    assert!(lines[0].contains("--package-lock-only=true"));
    assert_eq!(
        lines[1],
        format!("verify verify npm:@org/pkg@3.0.0 --expected-integrity {SRI}")
    );
    assert!(lines[2].contains("npm:a@1.0.0"));
    assert!(lines[3].contains("npm:b@2.0.0"));
    assert!(lines[4].starts_with("install ci "));
    assert!(lines[4].contains("--legacy-peer-deps"));
    assert!(!lines[4].contains("a@^1"));
    for line in [lines[0], lines[4]] {
        assert!(line.contains("--ignore-scripts"));
        assert!(line.contains("--global=false"));
        assert!(line.contains("--package-lock=true"));
    }
    assert_eq!(
        fs::read(f.project.join("package-lock.json")).unwrap(),
        fs::read(&f.lock).unwrap()
    );
}

#[test]
fn block_checks_remaining_packages_and_leaves_project_untouched() {
    for exit in ["1", "2", "3"] {
        let f = Fixture::new();
        let output = f
            .command()
            .arg("i")
            .env("FAIL_PACKAGE", "npm:@org/pkg@3.0.0")
            .env("VERIFY_EXIT", exit)
            .output()
            .unwrap();
        assert_code(&output, 1);
        assert_eq!(
            f.events()
                .lines()
                .filter(|l| l.starts_with("verify "))
                .count(),
            3
        );
        assert!(!f.events().lines().any(|l| l.starts_with("install ")));
        f.assert_untouched();
    }
}

#[test]
fn scoped_warn_and_log_are_explicit_and_invalid_policies_fail_closed() {
    for action in ["warn", "log"] {
        let f = Fixture::new();
        let policy = f._temp.path().join("policy.json");
        fs::write(&policy, format!(r#"{{"scopes":{{"@org":"{action}"}}}}"#)).unwrap();
        let output = f
            .command()
            .arg("add")
            .env("CLEARHASH_NPM_POLICY_FILE", policy)
            .env("FAIL_PACKAGE", "npm:@org/pkg@3.0.0")
            .output()
            .unwrap();
        assert_code(&output, 0);
        assert!(f.events().lines().last().unwrap().starts_with("install ci"));
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains(&format!(r#""policy":"{action}""#)));
        assert_eq!(stderr.contains("warning:"), action == "warn");
    }
    let f = Fixture::new();
    let policy = f._temp.path().join("policy.json");
    fs::write(&policy, r#"{"default":"allow"}"#).unwrap();
    assert_code(
        &f.command()
            .arg("install")
            .env("CLEARHASH_NPM_POLICY_FILE", policy)
            .output()
            .unwrap(),
        3,
    );
    assert!(f.events().is_empty());
    f.assert_untouched();
}

#[test]
fn failures_and_project_edits_prevent_installation() {
    let f = Fixture::new();
    assert_code(
        &f.command()
            .arg("install")
            .env("RESOLVE_EXIT", "19")
            .output()
            .unwrap(),
        19,
    );
    assert_eq!(f.events().lines().count(), 1);
    f.assert_untouched();

    let f = Fixture::new();
    let output = f
        .command()
        .arg("install")
        .env("MUTATE", f.project.join("package.json"))
        .output()
        .unwrap();
    assert_code(&output, 3);
    assert!(!f.events().lines().any(|l| l.starts_with("install ")));
    assert_eq!(
        fs::read_to_string(f.project.join("package.json")).unwrap(),
        "changed"
    );

    let f = Fixture::new();
    assert_code(
        &f.command()
            .arg("install")
            .env("INSTALL_EXIT", "23")
            .output()
            .unwrap(),
        23,
    );
}

#[test]
fn ci_uses_existing_lock_and_shrinkwrap_precedence_without_resolution() {
    let f = Fixture::new();
    fs::copy(&f.lock, f.project.join("npm-shrinkwrap.json")).unwrap();
    fs::write(f.project.join("package-lock.json"), "invalid ignored lock").unwrap();
    assert_code(&f.command().arg("ci").output().unwrap(), 0);
    assert!(!f.events().contains("resolve "));
    assert_eq!(f.events().lines().count(), 4);
    assert_eq!(
        fs::read_to_string(f.project.join("package-lock.json")).unwrap(),
        "invalid ignored lock"
    );

    let f = Fixture::new();
    assert_code(&f.command().arg("ci").output().unwrap(), 3);
    assert!(f.events().is_empty());
    f.assert_untouched();
}

#[test]
fn unsupported_inputs_and_old_npm_never_install() {
    for args in [
        vec!["install", "--global"],
        vec!["install", "--prefix=/tmp"],
        vec!["--prefix=/tmp", "install"],
        vec!["ci", "a"],
    ] {
        let f = Fixture::new();
        assert_code(&f.command().args(args).output().unwrap(), 3);
        assert!(f.events().is_empty());
        f.assert_untouched();
    }
    let f = Fixture::new();
    assert_code(
        &f.command()
            .arg("install")
            .env("NPM_VERSION", "6.14.0")
            .output()
            .unwrap(),
        3,
    );
    assert!(f.events().is_empty());

    let f = Fixture::new();
    f.write_lock(json!({"node_modules/a":{"version":"1.0.0","integrity":"sha1-abc"}}));
    assert_code(&f.command().arg("install").output().unwrap(), 3);
    assert_eq!(f.events().lines().count(), 1);
    f.assert_untouched();
}

#[test]
fn path_shim_skips_itself_and_propagates_non_install_exit_status() {
    let f = Fixture::new();
    let shim_dir = f._temp.path().join("shim");
    let real_dir = f._temp.path().join("real");
    fs::create_dir(&shim_dir).unwrap();
    fs::create_dir(&real_dir).unwrap();
    symlink(SHIM, shim_dir.join("npm")).unwrap();
    symlink(&f.npm, real_dir.join("npm")).unwrap();
    let paths = std::env::join_paths([
        shim_dir,
        real_dir,
        PathBuf::from("/usr/bin"),
        PathBuf::from("/bin"),
    ])
    .unwrap();
    let output = f
        .command()
        .args(["view", "@org/pkg"])
        .env_remove("CLEARHASH_REAL_NPM")
        .env_remove("CLEARHASH_VERIFY_BIN")
        .env("PATH", paths)
        .output()
        .unwrap();
    assert_code(&output, 17);
    assert_eq!(f.events(), "passthrough view @org/pkg\n");

    let output = f
        .command()
        .arg("install")
        .env("CLEARHASH_REAL_NPM", SHIM)
        .output()
        .unwrap();
    assert_code(&output, 3);
    let output = f
        .command()
        .arg("install")
        .env("CLEARHASH_NPM_ACTIVE", "1")
        .output()
        .unwrap();
    assert_code(&output, 3);
}

#[test]
fn npm_aliases_and_abbreviations_cannot_bypass_verification() {
    for command in [
        "ad",
        "isntall",
        "install-cl",
        "isntall-c",
        "installClean",
        "cleanInstall",
    ] {
        let f = Fixture::new();
        fs::copy(&f.lock, f.project.join("package-lock.json")).unwrap();
        let output = f
            .command()
            .arg(command)
            .env("FAIL_PACKAGE", "npm:a@1.0.0")
            .output()
            .unwrap();
        assert_code(&output, 1);
        assert_eq!(
            f.events()
                .lines()
                .filter(|l| l.starts_with("verify "))
                .count(),
            3,
            "{command}"
        );
        assert!(
            !f.events()
                .lines()
                .any(|l| l.starts_with("install ") || l.starts_with("passthrough ")),
            "{command}"
        );
    }
    for command in [
        "install-test",
        "install-ci-t",
        "it",
        "cit",
        "sit",
        "clean-install-t",
    ] {
        let f = Fixture::new();
        assert_code(&f.command().arg(command).output().unwrap(), 3);
        assert!(f.events().is_empty());
    }
}

#[test]
fn verifier_rejects_invalid_integrity_before_fetching() {
    let output = Command::new(env!("CARGO_BIN_EXE_clearhash"))
        .args([
            "verify",
            "npm:never-fetched@1.0.0",
            "--expected-integrity",
            "sha1-bad",
        ])
        .output()
        .unwrap();
    assert_code(&output, 3);
    assert!(!String::from_utf8_lossy(&output.stderr).contains("Fetching"));
}

#[test]
fn real_npm_installs_cached_locked_bytes_offline_without_lifecycle_hooks() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use flate2::{write::GzEncoder, Compression};
    use sha2::{Digest, Sha512};

    // The process-boundary suite above runs everywhere on Unix. Exercise real
    // npm as well when it is installed, using a fresh local cache and no network.
    let npm = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|dir| dir.join("npm"))
        .find(|path| path.is_file());
    let Some(npm) = npm else {
        eprintln!("skipping real npm fixture: npm unavailable");
        return;
    };
    let version = Command::new(&npm).arg("--version").output().unwrap();
    let version = String::from_utf8_lossy(&version.stdout);
    if version
        .trim()
        .split('.')
        .next()
        .and_then(|v| v.parse::<u32>().ok())
        .is_none_or(|v| v < 11)
    {
        eprintln!("skipping real npm fixture: npm 11+ required");
        return;
    }
    let npm = npm.canonicalize().unwrap();
    for mode in ["ci", "install"] {
        let f = Fixture::new();
        let package = br#"{"name":"fixture","version":"1.0.0","scripts":{"preinstall":"exit 91","install":"exit 92","postinstall":"exit 93","prepare":"exit 94"}}"#;
        let mut archive = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
        for (path, bytes) in [
            ("package/package.json", &package[..]),
            ("package/index.js", &b"module.exports = 42;\n"[..]),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o644);
            header.set_size(bytes.len() as u64);
            header.set_cksum();
            archive.append_data(&mut header, path, bytes).unwrap();
        }
        let bytes = archive.into_inner().unwrap().finish().unwrap();
        let tarball = f._temp.path().join("fixture.tgz");
        fs::write(&tarball, &bytes).unwrap();
        let integrity = format!("sha512-{}", STANDARD.encode(Sha512::digest(&bytes)));
        let cache = f._temp.path().join("cache");
        let output = Command::new(&npm)
            .current_dir(f._temp.path())
            .args(["cache", "add"])
            .arg(&tarball)
            .arg("--cache")
            .arg(&cache)
            .args([
                "--ignore-scripts",
                "--offline",
                "--audit=false",
                "--fund=false",
            ])
            .output()
            .unwrap();
        assert_code(&output, 0);
        let manifest = br#"{"name":"project","version":"1.0.0","dependencies":{"fixture":"1.0.0"},"scripts":{"preinstall":"exit 95","install":"exit 96","postinstall":"exit 97","prepare":"exit 98"}}"#;
        fs::write(f.project.join("package.json"), manifest).unwrap();
        let lock = json!({"lockfileVersion":3,"name":"project","version":"1.0.0","packages":{
            "":{"name":"project","version":"1.0.0","dependencies":{"fixture":"1.0.0"}},
            "node_modules/fixture":{"version":"1.0.0","resolved":"https://registry.npmjs.org/fixture/-/fixture-1.0.0.tgz","integrity":integrity,"hasInstallScript":true}
        }});
        fs::write(
            f.project.join("package-lock.json"),
            serde_json::to_vec(&lock).unwrap(),
        )
        .unwrap();
        fs::write(f.project.join(".npmrc"), format!("offline=true\ncache={}\nignore-scripts=false\ndry-run=true\npackage-lock-only=true\n", cache.display())).unwrap();
        let output = f
            .command()
            .arg(mode)
            .env("CLEARHASH_REAL_NPM", &npm)
            .env("npm_config_global", "true")
            .env("npm_config_prefix", f._temp.path().join("wrong-prefix"))
            .output()
            .unwrap();
        assert_code(&output, 0);
        assert_eq!(
            fs::read(f.project.join("node_modules/fixture/index.js")).unwrap(),
            b"module.exports = 42;\n"
        );
        assert!(!f.project.join("node_modules/sentinel").exists());
        assert_eq!(f.events().lines().count(), 1);
        assert!(f
            .events()
            .contains(&format!("--expected-integrity {integrity}")));
    }
}
