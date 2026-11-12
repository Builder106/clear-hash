//! Exercise the recipe's shared helper against real Git trees and index blobs.
#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use serde_json::{json, Value};

const CI: &str = env!("CARGO_BIN_EXE_clearhash-ci");
const SRI: &str = "sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=";
const OTHER_SRI: &str = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    verifier: PathBuf,
    events: PathBuf,
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

fn entry(version: &str) -> Value {
    json!({"version":version,"integrity":SRI})
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("consumer with spaces");
        fs::create_dir(&root).unwrap();
        let verifier = temp.path().join("verify package");
        fs::write(
            &verifier,
            r#"#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$EVENTS"
if [ "${VERIFY_EXIT:-0}" = signal ]; then kill -TERM $$; fi
exit "${VERIFY_EXIT:-0}"
"#,
        )
        .unwrap();
        fs::set_permissions(&verifier, fs::Permissions::from_mode(0o755)).unwrap();
        let f = Self {
            events: temp.path().join("events"),
            verifier,
            root,
            _temp: temp,
        };
        f.git(&["init", "--initial-branch=main"]);
        f.git(&["config", "user.email", "tests@example.invalid"]);
        f.git(&["config", "user.name", "Recipe tests"]);
        f
    }

    fn git(&self, args: &[&str]) -> Vec<u8> {
        let output = Command::new("git")
            .current_dir(&self.root)
            .args(args)
            .output()
            .unwrap();
        assert_code(&output, 0);
        output.stdout
    }

    fn commit(&self) {
        self.git(&["add", "."]);
        self.git(&[
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--allow-empty",
            "-m",
            "fixture",
        ]);
    }

    fn lock(&self, path: &str, packages: Value) {
        let mut packages = packages.as_object().unwrap().clone();
        packages.insert("".into(), json!({"name":"consumer","version":"1.0.0"}));
        let path = self.root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            path,
            serde_json::to_vec(&json!({"lockfileVersion":3,"packages":packages})).unwrap(),
        )
        .unwrap();
    }

    fn command(&self) -> Command {
        let mut command = Command::new(CI);
        command
            .current_dir(&self.root)
            .env("CLEARHASH_VERIFY_BIN", &self.verifier)
            .env("EVENTS", &self.events)
            .env_remove("VERIFY_EXIT");
        command
    }

    fn events(&self) -> String {
        fs::read_to_string(&self.events).unwrap_or_default()
    }
}

#[test]
fn diff_selects_new_versions_integrities_and_actual_alias_names_once() {
    let f = Fixture::new();
    f.lock(
        "package-lock.json",
        json!({
            "node_modules/unchanged":entry("1.0.0"),
            "node_modules/moved":entry("1.0.0"),
            "node_modules/removed":entry("1.0.0"),
            "node_modules/upgrade":entry("1.0.0"),
            "node_modules/rehash":entry("1.0.0")
        }),
    );
    f.commit();
    f.lock("package-lock.json", json!({
        "node_modules/unchanged":entry("1.0.0"),
        "node_modules/unchanged/node_modules/moved":entry("1.0.0"),
        "node_modules/upgrade":entry("2.0.0"),
        "node_modules/rehash":{"version":"1.0.0","integrity":OTHER_SRI},
        "node_modules/alias":{"name":"@actual/pkg","version":"3.0.0","integrity":SRI,"optional":true},
        "node_modules/dev":{"version":"1.0.0","integrity":SRI,"dev":true},
        "node_modules/dev/node_modules/alias":{"name":"@actual/pkg","version":"3.0.0","integrity":SRI}
    }));
    let before = fs::read(f.root.join("package-lock.json")).unwrap();
    assert_code(&f.command().args(["--base", "HEAD"]).output().unwrap(), 0);
    let events = f.events();
    assert_eq!(
        events.lines().collect::<Vec<_>>(),
        vec![
            format!("verify npm:@actual/pkg@3.0.0 --expected-integrity {SRI}"),
            format!("verify npm:dev@1.0.0 --expected-integrity {SRI}"),
            format!("verify npm:rehash@1.0.0 --expected-integrity {OTHER_SRI}"),
            format!("verify npm:upgrade@2.0.0 --expected-integrity {SRI}")
        ]
    );
    assert_eq!(before, fs::read(f.root.join("package-lock.json")).unwrap());
    assert!(!f.root.join("node_modules").exists());
}

#[test]
fn unchanged_or_removal_only_diffs_do_not_invoke_a_verifier() {
    let f = Fixture::new();
    f.lock(
        "package-lock.json",
        json!({"node_modules/a":entry("1.0.0")}),
    );
    f.commit();
    for packages in [json!({"node_modules/a":entry("1.0.0")}), json!({})] {
        f.lock("package-lock.json", packages);
        assert_code(
            &f.command()
                .args(["--base", "HEAD"])
                .env("CLEARHASH_VERIFY_BIN", "/missing")
                .output()
                .unwrap(),
            0,
        );
        assert!(f.events().is_empty());
    }
}

#[test]
fn new_lockfile_is_fully_verified_but_missing_base_is_an_error() {
    let f = Fixture::new();
    f.commit();
    f.lock(
        "package-lock.json",
        json!({"node_modules/a":entry("1.0.0")}),
    );
    let output = f
        .command()
        .args(["--base", "not-a-real-base"])
        .output()
        .unwrap();
    assert_code(&output, 3);
    assert!(String::from_utf8_lossy(&output.stderr).contains("fetch the trusted base"));
    assert!(f.events().is_empty());
    assert_code(&f.command().args(["--base", "HEAD"]).output().unwrap(), 0);
    assert_eq!(f.events().lines().count(), 1);
}

#[test]
fn staged_mode_reads_index_and_never_the_unstaged_lock() {
    let f = Fixture::new();
    f.lock(
        "package-lock.json",
        json!({"node_modules/a":entry("1.0.0")}),
    );
    f.commit();
    f.lock(
        "package-lock.json",
        json!({"node_modules/a":entry("2.0.0")}),
    );
    f.git(&["add", "package-lock.json"]);
    fs::write(f.root.join("package-lock.json"), "invalid unstaged lock").unwrap();
    assert_code(&f.command().arg("--staged").output().unwrap(), 0);
    assert_eq!(
        f.events(),
        format!("verify npm:a@2.0.0 --expected-integrity {SRI}\n")
    );
    assert_eq!(
        fs::read_to_string(f.root.join("package-lock.json")).unwrap(),
        "invalid unstaged lock"
    );
}

#[test]
fn staged_initial_commit_verifies_every_entry() {
    let f = Fixture::new();
    f.lock(
        "package-lock.json",
        json!({"node_modules/a":entry("1.0.0")}),
    );
    f.git(&["add", "."]);
    assert_code(&f.command().arg("--staged").output().unwrap(), 0);
    assert_eq!(f.events().lines().count(), 1);
}

#[test]
fn shrinkwrap_precedence_applies_independently_to_both_snapshots() {
    let f = Fixture::new();
    f.lock(
        "package-lock.json",
        json!({"node_modules/ignored":entry("1.0.0")}),
    );
    f.lock(
        "npm-shrinkwrap.json",
        json!({"node_modules/a":entry("1.0.0")}),
    );
    f.commit();
    fs::write(f.root.join("package-lock.json"), "ignored malformed lock").unwrap();
    f.lock(
        "npm-shrinkwrap.json",
        json!({"node_modules/a":entry("2.0.0")}),
    );
    assert_code(&f.command().args(["--base", "HEAD"]).output().unwrap(), 0);
    assert_eq!(
        f.events(),
        format!("verify npm:a@2.0.0 --expected-integrity {SRI}\n")
    );
    fs::remove_file(&f.events).unwrap();
    // Removing shrinkwrap selects package-lock without treating its old contents
    // as the baseline; the previous effective lock was shrinkwrap.
    fs::remove_file(f.root.join("npm-shrinkwrap.json")).unwrap();
    f.lock(
        "package-lock.json",
        json!({"node_modules/ignored":entry("1.0.0")}),
    );
    assert_code(&f.command().args(["--base", "HEAD"]).output().unwrap(), 0);
    assert!(f.events().contains("npm:ignored@1.0.0"));
}

#[test]
fn adding_shrinkwrap_to_the_index_selects_it_instead_of_worktree_locks() {
    let f = Fixture::new();
    f.lock(
        "package-lock.json",
        json!({"node_modules/a":entry("1.0.0")}),
    );
    f.commit();
    f.lock(
        "npm-shrinkwrap.json",
        json!({"node_modules/a":entry("2.0.0")}),
    );
    f.git(&["add", "npm-shrinkwrap.json"]);
    f.lock(
        "npm-shrinkwrap.json",
        json!({"node_modules/a":entry("3.0.0")}),
    );
    assert_code(&f.command().arg("--staged").output().unwrap(), 0);
    assert!(f.events().contains("npm:a@2.0.0"));
    assert!(!f.events().contains("npm:a@3.0.0"));
}

#[test]
fn all_nonzero_verifier_exits_and_signals_block_and_continue_checking() {
    for exit in ["1", "2", "3", "17", "signal"] {
        let f = Fixture::new();
        f.commit();
        f.lock(
            "package-lock.json",
            json!({"node_modules/a":entry("1.0.0"),"node_modules/b":entry("1.0.0")}),
        );
        let output = f
            .command()
            .args(["--base", "HEAD"])
            .env("VERIFY_EXIT", exit)
            .output()
            .unwrap();
        assert_code(&output, 1);
        assert_eq!(f.events().lines().count(), 2);
        assert_eq!(
            String::from_utf8_lossy(&output.stderr)
                .matches("\"matched\":false")
                .count(),
            2
        );
    }
}

#[test]
fn invalid_and_unsupported_locks_fail_before_any_verification() {
    let f = Fixture::new();
    f.lock("package-lock.json", json!({}));
    f.commit();
    for invalid in [
        "not json".to_owned(),
        json!({"lockfileVersion":1,"packages":{"":{}}}).to_string(),
        json!({"lockfileVersion":3,"packages":{"":{},"node_modules/a":{"version":"1.0.0"}}}).to_string(),
        json!({"lockfileVersion":3,"packages":{"":{},"workspace":{"link":true}}}).to_string(),
        json!({"lockfileVersion":3,"packages":{"":{},"node_modules/a":{"version":"1.0.0","integrity":SRI,"resolved":"file:../x"}}}).to_string()
    ] {
        fs::write(f.root.join("package-lock.json"), invalid).unwrap();
        assert_code(&f.command().args(["--base", "HEAD"]).output().unwrap(), 3);
        assert!(f.events().is_empty());
    }
}

#[test]
fn missing_current_lock_and_deleted_index_lock_fail_closed() {
    let f = Fixture::new();
    f.lock("package-lock.json", json!({}));
    f.commit();
    fs::remove_file(f.root.join("package-lock.json")).unwrap();
    assert_code(&f.command().args(["--base", "HEAD"]).output().unwrap(), 3);
    f.git(&["add", "-u"]);
    assert_code(&f.command().arg("--staged").output().unwrap(), 3);
    assert!(f.events().is_empty());
}

#[test]
fn nested_lock_paths_and_invocation_from_subdirectories_work() {
    let f = Fixture::new();
    f.lock("service with spaces/package-lock.json", json!({}));
    f.commit();
    f.lock(
        "service with spaces/package-lock.json",
        json!({"node_modules/a":entry("1.0.0")}),
    );
    assert_code(
        &f.command()
            .current_dir(f.root.join("service with spaces"))
            .args([
                "--base",
                "HEAD",
                "--lockfile",
                "service with spaces/package-lock.json",
            ])
            .output()
            .unwrap(),
        0,
    );
    assert_eq!(f.events().lines().count(), 1);
}

#[test]
fn unsafe_paths_and_symlinks_cannot_select_an_unintended_lock() {
    let f = Fixture::new();
    f.lock("package-lock.json", json!({}));
    f.commit();
    for path in [
        "../package-lock.json",
        "/package-lock.json",
        "x/../package-lock.json",
        "Cargo.lock",
        "package-lock.json\n",
        "x\\package-lock.json",
    ] {
        assert_code(
            &f.command()
                .args(["--base", "HEAD", "--lockfile", path])
                .output()
                .unwrap(),
            3,
        );
    }
    fs::rename(f.root.join("package-lock.json"), f.root.join("target.json")).unwrap();
    symlink("target.json", f.root.join("package-lock.json")).unwrap();
    assert_code(&f.command().args(["--base", "HEAD"]).output().unwrap(), 3);
    f.git(&["add", "package-lock.json"]);
    assert_code(&f.command().arg("--staged").output().unwrap(), 3);
    assert!(f.events().is_empty());
}

#[test]
fn unresolved_index_conflicts_fail_closed() {
    let f = Fixture::new();
    f.lock("package-lock.json", json!({}));
    f.commit();
    let oid = String::from_utf8(f.git(&["rev-parse", "HEAD:package-lock.json"])).unwrap();
    f.git(&["update-index", "--force-remove", "package-lock.json"]);
    let mut child = Command::new("git")
        .current_dir(&f.root)
        .args(["update-index", "--index-info"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    for stage in [1, 2, 3] {
        writeln!(
            child.stdin.as_mut().unwrap(),
            "100644 {} {stage}\tpackage-lock.json",
            oid.trim()
        )
        .unwrap();
    }
    drop(child.stdin.take());
    assert!(child.wait().unwrap().success());
    assert_code(&f.command().arg("--staged").output().unwrap(), 3);
    assert!(f.events().is_empty());
}

#[test]
fn missing_verifier_is_an_execution_error_and_cli_requires_a_baseline() {
    let f = Fixture::new();
    f.commit();
    f.lock(
        "package-lock.json",
        json!({"node_modules/a":entry("1.0.0")}),
    );
    assert_code(
        &f.command()
            .args(["--base", "HEAD"])
            .env("CLEARHASH_VERIFY_BIN", "/no-such-verifier")
            .output()
            .unwrap(),
        3,
    );
    assert_code(&f.command().output().unwrap(), 2);
    assert_code(
        &f.command()
            .args(["--base", "HEAD", "--staged"])
            .output()
            .unwrap(),
        2,
    );
    assert!(f.events().is_empty());
}
