//! Install-time npm gate. Resolve without scripts, verify the entire lock, then use npm ci.

use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, ExitStatus, Stdio};

use anyhow::{bail, ensure, Context, Result};
use clearhash_cli::npm_lock::{locked_packages, valid_name, valid_part};
use serde::Deserialize;
use serde_json::Value;

const INPUTS: &[&str] = &[
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    ".npmrc",
];
const HELP: &str = "clearhash-npm: verify npm packages before installation

Usage: clearhash-npm install [registry-package ...] [options]
       clearhash-npm ci [options]

Install aliases are supported. Other npm commands pass through.
Requires npm 11+. Run from the project root. Global installs, workspaces and non-registry dependencies
are unsupported. Installation uses npm ci with lifecycle scripts disabled.
Options: --save-dev/-D, --save-prod/-P, --save-optional/-O, --save-peer,
         --save-exact/-E, --legacy-peer-deps, --strict-peer-deps,
         --omit=dev|optional|peer, --include=prod|dev|optional|peer,
         --ignore-scripts, --no-audit, --no-fund.
Environment:
  CLEARHASH_REAL_NPM         Absolute path to the real npm (otherwise found on PATH)
  CLEARHASH_VERIFY_BIN       Absolute path to clearhash (otherwise sibling binary)
  CLEARHASH_NPM_POLICY_FILE  JSON policy: {\"default\":\"block\",\"scopes\":{\"@org\":\"warn\"}}
Policies: block (default), warn, log. Every verification emits JSON to stderr.
";

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Action {
    #[default]
    Block,
    Warn,
    Log,
}

impl Action {
    fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Warn => "warn",
            Self::Log => "log",
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Policy {
    default: Action,
    scopes: BTreeMap<String, Action>,
}

impl Policy {
    fn load() -> Result<Self> {
        let policy: Self = match env::var_os("CLEARHASH_NPM_POLICY_FILE") {
            Some(path) => serde_json::from_slice(&fs::read(path).context("reading npm policy")?)
                .context("invalid npm policy")?,
            None => Self::default(),
        };
        for scope in policy.scopes.keys() {
            ensure!(
                scope.starts_with('@') && valid_part(&scope[1..]),
                "invalid npm policy scope: {scope}"
            );
        }
        Ok(policy)
    }

    fn action(&self, name: &str) -> Action {
        name.split_once('/')
            .and_then(|(scope, _)| self.scopes.get(scope))
            .copied()
            .unwrap_or(self.default)
    }
}

struct InstallArgs {
    ci: bool,
    resolve: Vec<OsString>,
    install: Vec<OsString>,
}

fn install_command(command: &str) -> Option<bool> {
    match command {
        "install" | "ad" | "add" | "i" | "in" | "ins" | "inst" | "insta" | "instal" | "isnt"
        | "isnta" | "isntal" | "isntall" => Some(false),
        "ci" | "clean-install" | "ic" | "install-clean" | "isntall-clean" => Some(true),
        value
            if (value.starts_with("install-cl") && "install-clean".starts_with(value))
                || (value.starts_with("isntall-") && "isntall-clean".starts_with(value)) =>
        {
            Some(true)
        }
        _ => None,
    }
}

fn parse_install(ci: bool, args: &[OsString]) -> Result<InstallArgs> {
    let mut result = InstallArgs {
        ci,
        resolve: Vec::new(),
        install: Vec::new(),
    };
    for arg in args {
        let text = arg.to_str().context("npm arguments must be UTF-8")?;
        if matches!(text, "--legacy-peer-deps" | "--strict-peer-deps")
            || text
                .strip_prefix("--omit=")
                .is_some_and(|v| matches!(v, "dev" | "optional" | "peer"))
            || text
                .strip_prefix("--include=")
                .is_some_and(|v| matches!(v, "prod" | "dev" | "optional" | "peer"))
        {
            result.install.push(arg.clone());
        } else if matches!(text, "--ignore-scripts" | "--no-audit" | "--no-fund") {
            // Always enforced by the wrapper.
        } else if !ci
            && matches!(
                text,
                "--save-dev"
                    | "-D"
                    | "--save-prod"
                    | "-P"
                    | "--save-optional"
                    | "-O"
                    | "--save-peer"
                    | "--save-exact"
                    | "-E"
            )
        {
            // Resolution-only save flags.
        } else {
            ensure!(
                !ci && valid_spec(text),
                "unsupported install argument: {text}"
            );
        }
        result.resolve.push(arg.clone());
    }
    Ok(result)
}

fn valid_range(range: &str) -> bool {
    !range.is_empty()
        && range
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b" .^~<>=|*+-".contains(&b))
}

fn valid_spec(spec: &str) -> bool {
    let (name, range) = match spec.rfind('@').filter(|&i| i > 0) {
        Some(i) if !spec[..i].contains(":") => (&spec[..i], Some(&spec[i + 1..])),
        _ => (spec, None),
    };
    // npm aliases have a second package spec after @npm:.
    if let Some((alias, target)) = spec.split_once("@npm:") {
        return valid_name(alias) && valid_spec(target);
    }
    valid_name(name) && range.is_none_or(valid_range)
}

fn validate_manifest(bytes: &[u8]) -> Result<()> {
    let manifest: Value = serde_json::from_slice(bytes).context("invalid package.json")?;
    ensure!(manifest.is_object(), "package.json must be an object");
    ensure!(
        manifest.get("workspaces").is_none(),
        "npm workspaces are unsupported by the install gate"
    );
    for field in ["patchedDependencies", "packageExtensions"] {
        ensure!(
            manifest.get(field).is_none(),
            "{field} is unsupported by the install gate"
        );
    }
    if let Some(overrides) = manifest.get("overrides") {
        validate_overrides(overrides)?;
    }
    // Git prepare and local dependency behavior must never enter host resolution.
    for field in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(deps) = manifest.get(field) {
            for (name, range) in deps.as_object().context("dependencies must be objects")? {
                let range = range.as_str().context("dependency spec must be a string")?;
                let valid = range
                    .strip_prefix("npm:")
                    .map_or_else(|| valid_range(range), valid_spec);
                ensure!(
                    valid_name(name) && valid,
                    "unsupported dependency: {name}={range}"
                );
            }
        }
    }
    Ok(())
}

fn validate_overrides(value: &Value) -> Result<()> {
    match value {
        Value::Object(entries) => {
            for value in entries.values() {
                validate_overrides(value)?;
            }
        }
        Value::String(spec) => {
            let valid = spec.strip_prefix('$').map_or_else(
                || {
                    spec.strip_prefix("npm:")
                        .map_or_else(|| valid_range(spec), valid_spec)
                },
                valid_name,
            );
            ensure!(valid, "unsupported npm override: {spec}");
        }
        _ => bail!("invalid npm override"),
    }
    Ok(())
}

fn executable(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        path.metadata()
            .is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn real_npm(current: &Path) -> Result<PathBuf> {
    if let Some(path) = env::var_os("CLEARHASH_REAL_NPM") {
        let path = PathBuf::from(path);
        ensure!(
            path.is_absolute() && executable(&path),
            "CLEARHASH_REAL_NPM must be an absolute executable path"
        );
        ensure!(
            path.canonicalize()? != current,
            "real npm points back to clearhash-npm"
        );
        return Ok(path);
    }
    for dir in env::split_paths(&env::var_os("PATH").unwrap_or_default()) {
        #[cfg(windows)]
        let names = ["npm.exe", "npm.cmd"];
        #[cfg(not(windows))]
        let names = ["npm"];
        for name in names {
            let path = dir.join(name);
            if executable(&path) && path.canonicalize()? != current {
                return Ok(path.canonicalize()?);
            }
        }
    }
    bail!("real npm not found on PATH; set CLEARHASH_REAL_NPM")
}

fn verifier(current: &Path) -> Result<PathBuf> {
    let path = env::var_os("CLEARHASH_VERIFY_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| current.with_file_name(format!("clearhash{}", env::consts::EXE_SUFFIX)));
    ensure!(
        path.is_absolute() && executable(&path),
        "clearhash verifier missing; install both CLI binaries or set CLEARHASH_VERIFY_BIN"
    );
    ensure!(
        path.canonicalize()? != current,
        "verifier points back to clearhash-npm"
    );
    Ok(path)
}

fn require_supported_npm(npm_bin: &Path) -> Result<()> {
    let output = Command::new(npm_bin)
        .arg("--version")
        .env("CLEARHASH_NPM_ACTIVE", "1")
        .output()
        .context("checking npm version")?;
    ensure!(output.status.success(), "could not determine npm version");
    let version = semver::Version::parse(std::str::from_utf8(&output.stdout)?.trim())?;
    ensure!(
        version.major >= 11,
        "clearhash-npm requires npm 11 or newer"
    );
    Ok(())
}

fn code(status: ExitStatus) -> u8 {
    status
        .code()
        .and_then(|c| u8::try_from(c).ok())
        .unwrap_or(3)
}

fn npm(npm: &Path, root: &Path, command: &str) -> Command {
    let mut cmd = Command::new(npm);
    cmd.current_dir(root)
        .arg(command)
        .arg("--prefix")
        .arg(root)
        .args([
            "--global=false",
            "--workspaces=false",
            "--ignore-scripts",
            "--audit=false",
            "--fund=false",
            "--package-lock=true",
            "--dry-run=false",
        ])
        .env("CLEARHASH_NPM_ACTIVE", "1");
    cmd
}

struct Input {
    name: &'static str,
    bytes: Option<Vec<u8>>,
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn publish(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file =
        tempfile::NamedTempFile::new_in(path.parent().context("missing parent directory")?)?;
    file.write_all(bytes)?;
    if let Ok(metadata) = fs::metadata(path) {
        file.as_file().set_permissions(metadata.permissions())?;
    }
    file.persist(path).map_err(|e| e.error)?;
    Ok(())
}

fn install(npm_bin: &Path, verify_bin: &Path, args: InstallArgs, policy: &Policy) -> Result<u8> {
    require_supported_npm(npm_bin)?;
    let root = env::current_dir()?;
    let stage = tempfile::Builder::new()
        .prefix("clearhash-npm-")
        .tempdir()?;
    let mut inputs = Vec::new();
    for &name in INPUTS {
        let bytes = read_optional(&root.join(name))?;
        if let Some(bytes) = &bytes {
            fs::write(stage.path().join(name), bytes)?;
        }
        inputs.push(Input { name, bytes });
    }
    validate_manifest(
        inputs[0]
            .bytes
            .as_deref()
            .context("run clearhash-npm from a project root with package.json")?,
    )?;
    let lock_name = if inputs[2].bytes.is_some() {
        "npm-shrinkwrap.json"
    } else {
        "package-lock.json"
    };
    if args.ci {
        ensure!(
            stage.path().join(lock_name).is_file(),
            "npm ci requires an existing lockfile"
        );
    } else {
        let status = npm(npm_bin, stage.path(), "install")
            .args(&args.resolve)
            .args(["--package-lock-only=true", "--save=true"])
            .status()
            .context("resolving npm dependencies")?;
        if !status.success() {
            return Ok(code(status));
        }
    }
    let lock_bytes =
        fs::read(stage.path().join(lock_name)).context("npm did not produce a lockfile")?;
    let manifest_bytes = fs::read(stage.path().join("package.json"))?;
    validate_manifest(&manifest_bytes)?;
    let packages = locked_packages(&lock_bytes)?;
    let mut blocked = false;
    for package in packages {
        let reference = format!("npm:{}@{}", package.name, package.version);
        let action = policy.action(&package.name);
        let status = Command::new(verify_bin)
            .args([
                "verify",
                &reference,
                "--expected-integrity",
                &package.integrity,
            ])
            // Keep npm's stdout usable and avoid retaining unbounded verifier output.
            .stdout(Stdio::from(std::io::stderr()))
            .status()
            .with_context(|| format!("verifying {reference}"))?;
        let exit = code(status);
        eprintln!(
            "{}",
            serde_json::json!({"event":"clearhash-npm.verify", "package":reference, "policy":action.as_str(), "exit_code":exit, "matched":status.success()})
        );
        if !status.success() {
            match action {
                Action::Block => blocked = true,
                Action::Warn => eprintln!(
                    "warning: {reference} did not verify; warn policy permits installation"
                ),
                Action::Log => {}
            }
        }
    }
    if blocked {
        eprintln!("clearhash-npm: installation blocked by verification policy");
        return Ok(1);
    }
    for input in &inputs {
        ensure!(
            read_optional(&root.join(input.name))? == input.bytes,
            "{} changed during verification; retry installation",
            input.name
        );
    }
    // Publish only after the gate passes. npm ci consumes exactly this lock and
    // replaces node_modules, so an existing unverified install cannot be reused.
    if !args.ci {
        publish(&root.join("package.json"), &manifest_bytes)?;
        publish(&root.join(lock_name), &lock_bytes)?;
    }
    let status = npm(npm_bin, &root, "ci")
        .args(&args.install)
        .arg("--package-lock-only=false")
        .status()
        .context("installing verified npm lock")?;
    Ok(code(status))
}

fn run() -> Result<u8> {
    let args: Vec<OsString> = env::args_os().skip(1).collect();
    if args.first().is_none_or(|v| v == "--help" || v == "-h") {
        print!("{HELP}");
        return Ok(0);
    }
    ensure!(
        env::var_os("CLEARHASH_NPM_ACTIVE").is_none(),
        "recursive npm shim invocation; check CLEARHASH_REAL_NPM"
    );
    let current = env::current_exe()?.canonicalize()?;
    let raw_command = args[0].to_str().context("npm command must be UTF-8")?;
    // npm accepts camelCase commands and unique abbreviations of aliases.
    let command: String = raw_command
        .chars()
        .flat_map(|c| {
            if c.is_ascii_uppercase() {
                vec!['-', c.to_ascii_lowercase()]
            } else {
                vec![c]
            }
        })
        .collect();
    let command = command.as_str();
    // Leading configuration flags could hide an install command from the gate.
    ensure!(
        !command.starts_with('-') || matches!(command, "--version" | "-v"),
        "place supported options after the npm command"
    );
    let install_args = install_command(command)
        .map(|ci| parse_install(ci, &args[1..]))
        .transpose()?;
    ensure!(
        install_args.is_some()
            || !(command.starts_with("install-")
                || command.starts_with("clean-install-")
                || matches!(command, "it" | "cit" | "sit")),
        "compound npm install commands are unsupported; run install/ci and test separately"
    );
    let npm_bin = real_npm(&current)?;
    match install_args {
        Some(args) => install(&npm_bin, &verifier(&current)?, args, &Policy::load()?),
        None => Ok(code(
            Command::new(npm_bin)
                .args(args)
                .env("CLEARHASH_NPM_ACTIVE", "1")
                .status()
                .context("running npm")?,
        )),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("clearhash-npm: {error:#}");
            ExitCode::from(3)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SRI: &str = "sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=";

    #[test]
    fn lock_covers_nested_scoped_alias_optional_and_multiple_versions() {
        let dep = json!({"version":"1.0.0", "integrity":SRI});
        let mut alias = dep.clone();
        alias["name"] = json!("@actual/pkg");
        let lock = json!({"lockfileVersion":3, "packages":{
            "":{}, "node_modules/a":dep, "node_modules/a/node_modules/b":dep,
            "node_modules/b":dep, "node_modules/@scope/pkg":dep,
            "node_modules/alias":alias,
            "node_modules/dev":{"version":"2.0.0","dev":true,"integrity":SRI},
            "node_modules/optional":{"version":"1.0.0","optional":true,"integrity":SRI}
        }});
        let packages = locked_packages(&serde_json::to_vec(&lock).unwrap()).unwrap();
        assert_eq!(packages.len(), 6);
        assert!(packages.iter().any(|p| p.name == "@actual/pkg"));
        assert!(packages.iter().any(|p| p.name == "optional"));
    }

    #[test]
    fn lock_rejects_unverifiable_sources_and_malformed_entries() {
        let good = json!({"version":"1.0.0","integrity":SRI});
        for patch in [
            json!({"link":true}),
            json!({"inBundle":true}),
            json!({"version":"^1.0.0"}),
            json!({"name":"../escape"}),
            json!({"resolved":"git+https://example.com/repo"}),
            json!({"resolved":"file:../x"}),
            json!({"resolved":"http://example.com/x"}),
            json!({"resolved":"https://user:password@example.com/x"}),
            json!({"integrity":"sha1-abc"}),
            json!({"integrity":null}),
        ] {
            let mut entry = good.clone();
            entry
                .as_object_mut()
                .unwrap()
                .extend(patch.as_object().unwrap().clone());
            let lock = json!({"lockfileVersion":3,"packages":{"":{},"node_modules/a":entry}});
            assert!(
                locked_packages(&serde_json::to_vec(&lock).unwrap()).is_err(),
                "{patch}"
            );
        }
        for path in [
            "workspace",
            "node_modules/../x",
            "node_modules/@scope/../x",
            "node_modules/a/other/b",
            "node_modules/a/node_modules/",
        ] {
            let lock = json!({"lockfileVersion":3,"packages":{"":{},path:good}});
            assert!(
                locked_packages(&serde_json::to_vec(&lock).unwrap()).is_err(),
                "{path}"
            );
        }
        for lock in [
            json!({}),
            json!({"lockfileVersion":1,"packages":{"":{}}}),
            json!({"lockfileVersion":3,"packages":{}}),
        ] {
            assert!(locked_packages(&serde_json::to_vec(&lock).unwrap()).is_err());
        }
    }

    #[test]
    fn install_options_cannot_escape_the_gate() {
        for option in [
            "-g",
            "--global",
            "--global=false",
            "--prefix=/tmp",
            "--workspace=x",
            "--package-lock=false",
            "--ignore-scripts=false",
            "--dry-run",
            "--no-save",
            "--",
            "--userconfig=x",
            "--dangerously-allow-all-scripts",
            "-Dg",
        ] {
            assert!(parse_install(false, &[option.into()]).is_err(), "{option}");
        }
        for spec in [
            "foo",
            "@scope/name@^1.0.0",
            "alias@npm:@scope/pkg@~1.0",
            "x@latest",
        ] {
            assert!(parse_install(false, &[spec.into()]).is_ok(), "{spec}");
            assert!(parse_install(true, &[spec.into()]).is_err());
        }
        for spec in [
            "../pkg",
            "https://example.com/x.tgz",
            "git+ssh://x",
            "owner/repo",
            "foo@file:../pkg",
            "x@npm:../pkg",
        ] {
            assert!(!valid_spec(spec), "{spec}");
        }
        let options = ["x", "-D", "--legacy-peer-deps", "--omit=dev"].map(OsString::from);
        let parsed = parse_install(false, &options).unwrap();
        assert_eq!(parsed.resolve, options);
        assert_eq!(
            parsed.install,
            ["--legacy-peer-deps", "--omit=dev"].map(OsString::from)
        );
    }

    #[test]
    fn manifest_rejects_host_sources_and_artifact_mutations() {
        for manifest in [
            json!({"workspaces":[]}),
            json!({"patchedDependencies":{}}),
            json!({"dependencies":{"x":"git+https://example.com/x"}}),
            json!({"overrides":{"x":{"y":"file:../x"}}}),
        ] {
            assert!(validate_manifest(&serde_json::to_vec(&manifest).unwrap()).is_err());
        }
        validate_manifest(
            br#"{"dependencies":{"x":"^1.0","alias":"npm:@scope/x@1"},"overrides":{"x":"$x"}}"#,
        )
        .unwrap();
    }

    #[test]
    fn policy_matches_actual_scope_and_defaults_to_block() {
        let policy: Policy =
            serde_json::from_str(r#"{"scopes":{"@org":"warn","@vendor":"log"}}"#).unwrap();
        assert_eq!(policy.action("@org/pkg"), Action::Warn);
        assert_eq!(policy.action("@vendor/pkg"), Action::Log);
        assert_eq!(policy.action("@org-other/pkg"), Action::Block);
        assert_eq!(policy.action("ordinary"), Action::Block);
        assert!(serde_json::from_str::<Policy>(r#"{"default":"allow"}"#).is_err());
        assert!(serde_json::from_str::<Policy>(r#"{"defaut":"warn"}"#).is_err());
    }
}
