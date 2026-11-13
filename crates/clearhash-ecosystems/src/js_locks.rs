//! pnpm and Yarn lockfiles for network-off npm rebuilds, and the package-manager
//! release each needs. Lock interpretation only: nothing here runs package code.
//!
//! Archives are named the way Yarn 1 names offline-mirror files
//! (`@scope-name-1.0.0.tgz`). Yarn 1 reads `/deps` as its mirror, and the recipe's
//! loopback registry maps request paths to files by the same rule for pnpm and Yarn 2+.
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD, Engine};
use url::Url;
use yaml_rust2::{Yaml, YamlLoader};

use crate::npm::allows_target;
use crate::offline::{archive, invalid, registry_tarball, Check, Dependency, Integrity};
use crate::AdapterError;

/// File name of the package-manager tarball under `/tools`.
pub const PACKAGE_MANAGER_ARCHIVE: &str = "package-manager.tgz";
/// File name of a Yarn 2+ bundle under `/tools`, for pins whose hash covers that file.
pub const YARN_BUNDLE: &str = "yarn.js";

/// Used when a pnpm project has no `packageManager` pin. pnpm 10 writes lockfile 9.0.
const DEFAULT_PNPM: (&str, &str) = (
    "10.34.9",
    "sha512-9JtajqD97bRLs8DB1ldQkqU8KVDZW3rRXfEfF5dId6LeOgHAfpNOmyjOcW5RwJqUlixzBtCb4uHksYqMh2L9Mg==",
);
/// Used when a Yarn 1 project has no `packageManager` pin.
const DEFAULT_YARN: (&str, &str) = (
    "1.22.22",
    "sha512-prL3kGtyG7o9Z9Sv8IPfBNrWTDmXB4Qbes8A9rEzt6wkJV8mUvoirjU0Mp3GGAU06Y0XQyA3/2/RQFVuK7MTfg==",
);

/// The package manager a source root uses, chosen by lockfile as the recipe chooses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Manager {
    Npm,
    Pnpm,
    Yarn,
    YarnBerry,
}

/// npm locks take precedence, then `pnpm-lock.yaml`, then `yarn.lock`.
pub fn manager(source: &Path) -> Option<Manager> {
    if source.join("npm-shrinkwrap.json").is_file() || source.join("package-lock.json").is_file() {
        return Some(Manager::Npm);
    }
    if source.join("pnpm-lock.yaml").is_file() {
        return Some(Manager::Pnpm);
    }
    let yarn = std::fs::read_to_string(source.join("yarn.lock")).ok()?;
    // The recipe tests the same marker with `grep -q '^__metadata:'`.
    Some(if yarn.lines().any(|l| l.starts_with("__metadata:")) {
        Manager::YarnBerry
    } else {
        Manager::Yarn
    })
}

fn load_yaml(path: &Path) -> Result<Yaml, AdapterError> {
    load_yaml_documents(path)?
        .into_iter()
        .next()
        .ok_or_else(|| invalid(format!("{} is empty", path.display())))
}

fn load_yaml_documents(path: &Path) -> Result<Vec<Yaml>, AdapterError> {
    let name = path
        .file_name()
        .map_or_else(Default::default, |n| n.to_string_lossy());
    let text = std::fs::read_to_string(path).map_err(|e| invalid(format!("{name}: {e}")))?;
    YamlLoader::load_from_str(&text).map_err(|e| invalid(format!("{name}: {e}")))
}

/// Split `name@reference`, where a scoped name starts with its own `@`.
fn split_spec(spec: &str) -> Option<(&str, &str)> {
    let at = spec.get(1..)?.find('@')? + 1;
    Some((&spec[..at], &spec[at + 1..]))
}

/// Yarn 1's offline-mirror file name for a tarball URL (`getTarballNameFromUrl`):
/// `<scope>-<file>` for registry layouts, otherwise the last path segment.
pub fn mirror_name(url: &Url) -> String {
    let segments: Vec<&str> = url.path().split('/').collect();
    let base = segments.last().copied().unwrap_or_default();
    let n = segments.len();
    let is_dash = |s: &str| s == "-" || s == "_attachments";
    // The registry layout is `.../<name>/-/[@scope/]<file>`.
    let dash = if n >= 3 && is_dash(segments[n - 2]) {
        n - 2
    } else if n >= 4 && segments[n - 2].starts_with('@') && is_dash(segments[n - 3]) {
        n - 3
    } else {
        return base.into();
    };
    if dash < 2 || segments[dash - 1].is_empty() {
        return base.into();
    }
    let name = segments[dash - 1];
    let scope = if dash >= 3 && segments[dash - 2].len() > 1 && segments[dash - 2].starts_with('@')
    {
        Some(segments[dash - 2])
    } else if name.starts_with('@') {
        name.rfind("%2f")
            .filter(|&i| i > 1 && i + 3 < name.len())
            .map(|i| &name[..i])
    } else {
        None
    };
    match scope {
        Some(scope) => format!("{scope}-{base}"),
        None => base.into(),
    }
}

/// Add an archive unless an identical one is present. Two different archives under one
/// mirror name cannot both be served, so that is a lock-stage error.
fn push(archives: &mut Vec<Dependency>, dependency: Dependency) -> Result<(), AdapterError> {
    match archives.iter().find(|d| d.filename == dependency.filename) {
        Some(previous) if *previous == dependency => Ok(()),
        Some(_) => Err(invalid(format!(
            "two locked archives share the file name {}",
            dependency.filename
        ))),
        None => {
            archives.push(dependency);
            Ok(())
        }
    }
}

fn registry_archive(name: &str, version: &str, check: Check) -> Result<Dependency, AdapterError> {
    let url = registry_tarball(name, version)?;
    let filename = mirror_name(&Url::parse(&url).map_err(|_| invalid("invalid tarball URL"))?);
    archive(&url, filename, check)
}

fn registry_metadata(name: &str, version: &str) -> Result<Check, AdapterError> {
    Url::parse(&format!("https://registry.npmjs.org/{name}/{version}"))
        .map(Check::Registry)
        .map_err(|_| invalid(format!("{name}@{version}: invalid registry URL")))
}

fn strings(value: &Yaml) -> Option<Vec<String>> {
    value.as_vec().map(|items| {
        items
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect()
    })
}

/// pnpm skips optional packages whose `os`, `cpu`, or `libc` excludes the platform.
fn pnpm_supports(entry: &Yaml, cpu: &str) -> bool {
    [("os", "linux"), ("cpu", cpu), ("libc", "glibc")]
        .into_iter()
        .all(|(field, target)| allows_target(strings(&entry[field]).as_deref(), target))
}

/// pnpm lockfile 9.0. Every fetched entry needs an SRI hash from the lock. pnpm 11
/// and later may write a second YAML document, with the first locking pnpm itself.
pub fn pnpm(source: &Path, cpu: &str) -> Result<Vec<Dependency>, AdapterError> {
    let documents = load_yaml_documents(&source.join("pnpm-lock.yaml"))?;
    if documents.is_empty() {
        return Err(invalid("pnpm-lock.yaml is empty"));
    }
    let mut archives = Vec::new();
    for lock in &documents {
        let version = match &lock["lockfileVersion"] {
            Yaml::String(v) | Yaml::Real(v) => v.as_str(),
            _ => "",
        };
        if version != "9.0" {
            return Err(invalid("offline pnpm requires lockfileVersion 9.0"));
        }
        if let Some(packages) = lock["packages"].as_hash() {
            pnpm_packages(packages, cpu, &mut archives)?;
        }
    }
    Ok(archives)
}

fn pnpm_packages(
    packages: &yaml_rust2::yaml::Hash,
    cpu: &str,
    archives: &mut Vec<Dependency>,
) -> Result<(), AdapterError> {
    for (key, entry) in packages {
        let key = key
            .as_str()
            .ok_or_else(|| invalid("pnpm package key is not a string"))?;
        let (name, version) =
            split_spec(key).ok_or_else(|| invalid(format!("{key}: malformed pnpm package key")))?;
        if !pnpm_supports(entry, cpu) {
            continue;
        }
        let resolution = &entry["resolution"];
        if resolution["directory"].as_str().is_some()
            || resolution["tarball"]
                .as_str()
                .is_some_and(|t| t.starts_with("file:"))
        {
            // Local source, pinned by Git.
            continue;
        }
        if let Some(kind) = resolution["type"].as_str() {
            return Err(invalid(format!("{key}: {kind} sources need the network")));
        }
        if resolution["tarball"].as_str().is_some() {
            // pnpm fetches these absolute URLs, which the loopback registry cannot serve.
            return Err(invalid(format!("{key}: tarball URLs need the network")));
        }
        let integrity = Integrity::parse(resolution["integrity"].as_str().unwrap_or(""))
            .map_err(|e| invalid(format!("{key}: {e}")))?;
        let dependency = registry_archive(name, version, Check::Pinned(integrity))
            .map_err(|e| invalid(format!("{key}: {e}")))?;
        push(archives, dependency)?;
    }
    Ok(())
}

fn unquote(value: &str) -> &str {
    let value = value.trim();
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value)
}

/// Yarn 1 (`# yarn lockfile v1`). Every fetched entry needs an SRI hash; SHA-1 is rejected.
pub fn yarn(source: &Path) -> Result<Vec<Dependency>, AdapterError> {
    let text = std::fs::read_to_string(source.join("yarn.lock"))
        .map_err(|e| invalid(format!("yarn.lock: {e}")))?;
    if !text.lines().any(|l| l.trim() == "# yarn lockfile v1") {
        return Err(invalid("yarn.lock is neither a Yarn 1 nor a Yarn 2+ lock"));
    }
    // (header, resolved, integrity) for each top-level entry.
    let mut entries: Vec<(&str, Option<&str>, Option<&str>)> = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        if !line.starts_with(' ') {
            entries.push((line.trim_end_matches(':'), None, None));
        } else if let Some(entry) = entries.last_mut() {
            if let Some(value) = line.strip_prefix("  resolved ") {
                entry.1 = Some(unquote(value));
            } else if let Some(value) = line.strip_prefix("  integrity ") {
                entry.2 = Some(unquote(value));
            }
        }
    }
    let mut archives = Vec::new();
    for (header, resolved, integrity) in entries {
        // Workspace, `file:`, and `link:` entries are local source, pinned by Git.
        let Some(resolved) =
            resolved.filter(|r| !r.starts_with("file:") && !r.starts_with("link:"))
        else {
            continue;
        };
        let url = resolved.split('#').next().unwrap_or_default();
        let integrity = Integrity::parse(integrity.unwrap_or(""))
            .map_err(|e| invalid(format!("{header}: {e}")))?;
        let filename = Url::parse(url)
            .map(|u| mirror_name(&u))
            .map_err(|_| invalid(format!("{header}: invalid resolved URL")))?;
        let dependency = archive(url, filename, Check::Pinned(integrity))
            .map_err(|e| invalid(format!("{header}: {e}")))?;
        push(&mut archives, dependency)?;
    }
    Ok(archives)
}

/// Yarn 2+ (`__metadata`). The lock checksum covers Yarn's zip, so the host checks the
/// registry tarball against the registry's published integrity, and Yarn checks the lock
/// checksum inside the network-off container. Every entry is fetched: Yarn fetches
/// some packages for other platforms, such as the base of its built-in patches.
pub fn yarn_berry(source: &Path) -> Result<Vec<Dependency>, AdapterError> {
    let lock = load_yaml(&source.join("yarn.lock"))?;
    let entries = lock
        .as_hash()
        .ok_or_else(|| invalid("yarn.lock is not a mapping"))?;
    let mut archives = Vec::new();
    for (key, entry) in entries {
        if key.as_str() == Some("__metadata") {
            continue;
        }
        let resolution = entry["resolution"]
            .as_str()
            .ok_or_else(|| invalid("Yarn lock entry has no resolution"))?;
        let (name, reference) = split_spec(resolution)
            .ok_or_else(|| invalid(format!("{resolution}: malformed resolution")))?;
        let Some(version) = reference.strip_prefix("npm:") else {
            // Workspaces, links, portals, and local files are pinned by Git. Patches name
            // their base package, which the lock lists as its own `npm:` entry.
            if ["workspace:", "link:", "portal:", "patch:", "file:"]
                .iter()
                .any(|p| reference.starts_with(p))
            {
                continue;
            }
            return Err(invalid(format!(
                "{resolution}: this source needs the network"
            )));
        };
        // Yarn leaves the checksum out for platform packages the locking machine never
        // fetched. Those rest on the registry integrity alone; others must be pinned.
        if entry["checksum"].as_str().is_none() && entry["conditions"].as_str().is_none() {
            return Err(invalid(format!("{resolution}: no checksum in the lock")));
        }
        let check = registry_metadata(name, version)?;
        let dependency = registry_archive(name, version, check)
            .map_err(|e| invalid(format!("{resolution}: {e}")))?;
        push(&mut archives, dependency)?;
    }
    Ok(archives)
}

/// A `packageManager` pin such as `pnpm@10.13.1+sha512.<hex>`.
#[derive(Debug, PartialEq, Eq)]
struct Pin {
    name: String,
    version: semver::Version,
    hash: Option<Integrity>,
}

fn package_manager_pin(source: &Path) -> Result<Option<Pin>, AdapterError> {
    let Ok(bytes) = std::fs::read(source.join("package.json")) else {
        return Ok(None);
    };
    let manifest: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| invalid(format!("package.json: {e}")))?;
    let Some(field) = manifest.get("packageManager").and_then(|v| v.as_str()) else {
        return Ok(None);
    };
    let (spec, hash) = field
        .split_once('+')
        .map_or((field, None), |(s, h)| (s, Some(h)));
    let (name, version) = spec
        .rsplit_once('@')
        .filter(|(name, _)| !name.is_empty())
        .ok_or_else(|| invalid(format!("packageManager {field}: expected name@version")))?;
    let version = semver::Version::parse(version)
        .map_err(|_| invalid(format!("packageManager {field}: expected an exact version")))?;
    let hash = hash
        .map(|hash| {
            let (algorithm, hex) = hash
                .split_once('.')
                .ok_or_else(|| invalid(format!("packageManager {field}: malformed hash")))?;
            let digest = hex::decode(hex)
                .map_err(|_| invalid(format!("packageManager {field}: malformed hash")))?;
            Integrity::parse(&format!("{algorithm}-{}", STANDARD.encode(digest)))
        })
        .transpose()?;
    Ok(Some(Pin {
        name: name.into(),
        version,
        hash,
    }))
}

/// A committed Yarn release named by `.yarnrc.yml`, inside the source tree.
pub fn yarn_path(source: &Path) -> Result<Option<PathBuf>, AdapterError> {
    let config = source.join(".yarnrc.yml");
    if !config.is_file() {
        return Ok(None);
    }
    let Some(path) = load_yaml(&config)?["yarnPath"].as_str().map(str::to_string) else {
        return Ok(None);
    };
    let root = source.canonicalize().map_err(|e| invalid(e.to_string()))?;
    let release = source
        .join(&path)
        .canonicalize()
        .map_err(|e| invalid(format!("yarnPath {path}: {e}")))?;
    if !release.starts_with(&root) || !release.is_file() {
        return Err(invalid(format!(
            "yarnPath {path} is not a file in the source tree"
        )));
    }
    Ok(Some(release))
}

fn tool(name: &str, version: &str, check: Check) -> Result<Dependency, AdapterError> {
    archive(
        &registry_tarball(name, version)?,
        PACKAGE_MANAGER_ARCHIVE.into(),
        check,
    )
}

fn default_tool(
    name: &str,
    (version, integrity): (&str, &str),
) -> Result<Dependency, AdapterError> {
    tool(name, version, Check::Pinned(Integrity::parse(integrity)?))
}

/// The pnpm or Yarn release a rebuild runs, or `None` for npm and committed `yarnPath`.
pub fn package_manager(source: &Path, cpu: &str) -> Result<Option<Dependency>, AdapterError> {
    let manager = manager(source);
    let wanted = match manager {
        Some(Manager::Pnpm) => "pnpm",
        Some(Manager::Yarn | Manager::YarnBerry) => "yarn",
        Some(Manager::Npm) | None => return Ok(None),
    };
    if manager == Some(Manager::YarnBerry) && yarn_path(source)?.is_some() {
        return Ok(None);
    }
    // A pin for a different manager does not apply to this lock.
    let pin = package_manager_pin(source)?.filter(|p| p.name == wanted);
    let pinned = |name: &str, pin: Pin| {
        let version = pin.version.to_string();
        let check = match pin.hash {
            Some(hash) => Check::Pinned(hash),
            None => registry_metadata(name, &version)?,
        };
        tool(name, &version, check)
    };
    let release = match (manager, pin) {
        (Some(Manager::Pnpm), None) => default_tool("pnpm", DEFAULT_PNPM)?,
        // pnpm 12 runs a native binary from `@pnpm/exe.<platform>`. The pin's hash covers
        // only the `pnpm` launcher tarball, so the binary is checked against the registry.
        (Some(Manager::Pnpm), Some(pin)) if pin.version.major >= 12 => {
            let name = format!("@pnpm/exe.linux-{cpu}");
            let version = pin.version.to_string();
            tool(&name, &version, registry_metadata(&name, &version)?)?
        }
        (Some(Manager::Pnpm), Some(pin)) => pinned("pnpm", pin)?,
        (Some(Manager::Yarn), None) => default_tool("yarn", DEFAULT_YARN)?,
        (Some(Manager::Yarn), Some(pin)) if pin.version.major == 1 => pinned("yarn", pin)?,
        (Some(Manager::Yarn), Some(_)) => {
            return Err(invalid(
                "packageManager pins Yarn 2+ but yarn.lock is a Yarn 1 lock",
            ))
        }
        // Corepack's hash covers the `yarn.js` file at repo.yarnpkg.com, not the
        // `@yarnpkg/cli-dist` tarball, so a hashed pin is checked against that file.
        (
            Some(Manager::YarnBerry),
            Some(Pin {
                version,
                hash: Some(hash),
                ..
            }),
        ) if version.major >= 2 => archive(
            &format!("https://repo.yarnpkg.com/{version}/packages/yarnpkg-cli/bin/yarn.js"),
            YARN_BUNDLE.into(),
            Check::Pinned(hash),
        )?,
        (Some(Manager::YarnBerry), Some(pin)) if pin.version.major >= 2 => {
            pinned("@yarnpkg/cli-dist", pin)?
        }
        _ => {
            return Err(invalid(
                "a Yarn 2+ lock needs a committed yarnPath or a packageManager pin",
            ))
        }
    };
    Ok(Some(release))
}

#[cfg(test)]
mod tests {
    //! Lockfile fixtures below are hand-written test inputs, not data from real releases.
    use super::*;
    use crate::offline::tests::{pinned, sri};

    fn write(dir: &Path, name: &str, text: &str) {
        std::fs::write(dir.join(name), text).unwrap();
    }

    #[test]
    fn manager_follows_the_recipe_precedence() {
        let source = tempfile::tempdir().unwrap();
        assert_eq!(manager(source.path()), None);
        write(source.path(), "yarn.lock", "# yarn lockfile v1\n");
        assert_eq!(manager(source.path()), Some(Manager::Yarn));
        write(source.path(), "yarn.lock", "__metadata:\n  version: 8\n");
        assert_eq!(manager(source.path()), Some(Manager::YarnBerry));
        write(source.path(), "pnpm-lock.yaml", "lockfileVersion: '9.0'\n");
        assert_eq!(manager(source.path()), Some(Manager::Pnpm));
        write(source.path(), "package-lock.json", "{}");
        assert_eq!(manager(source.path()), Some(Manager::Npm));
    }

    #[test]
    fn mirror_names_match_yarn_1() {
        for (url, name) in [
            (
                "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz",
                "left-pad-1.3.0.tgz",
            ),
            (
                "https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz",
                "@babel-core-7.24.0.tgz",
            ),
            (
                "https://registry.npmjs.org/@babel%2fcore/-/core-7.24.0.tgz",
                "@babel-core-7.24.0.tgz",
            ),
            ("https://codeload.github.com/a/b/tar.gz/0123abc", "0123abc"),
        ] {
            assert_eq!(mirror_name(&Url::parse(url).unwrap()), name, "{url}");
        }
    }

    #[test]
    fn pnpm_reads_hashed_registry_entries_and_skips_other_platforms() {
        let source = tempfile::tempdir().unwrap();
        let lock = format!(
            "lockfileVersion: '9.0'\n\npackages:\n\n  left-pad@1.3.0:\n    resolution: {{integrity: {a}}}\n\n  '@scope/pkg@2.0.0':\n    resolution: {{integrity: {b}}}\n\n  '@esbuild/darwin-arm64@0.21.0':\n    resolution: {{integrity: {c}}}\n    cpu: [arm64]\n    os: [darwin]\n\n  '@esbuild/linux-x64@0.21.0':\n    resolution: {{integrity: {c}}}\n    cpu: [x64]\n    os: [linux]\n\n  local@file:vendor/local:\n    resolution: {{directory: vendor/local, type: directory}}\n",
            a = sri(b"left-pad"),
            b = sri(b"scoped"),
            c = sri(b"native"),
        );
        write(source.path(), "pnpm-lock.yaml", &lock);
        let archives = pnpm(source.path(), "x64").unwrap();
        let names: Vec<_> = archives.iter().map(|d| d.filename.as_str()).collect();
        assert_eq!(
            names,
            [
                "left-pad-1.3.0.tgz",
                "@scope-pkg-2.0.0.tgz",
                "@esbuild-linux-x64-0.21.0.tgz"
            ]
        );
        assert_eq!(
            archives[1].url.as_str(),
            "https://registry.npmjs.org/@scope/pkg/-/pkg-2.0.0.tgz"
        );
        assert!(pinned(&archives[0]).matches(b"left-pad"));
        assert_eq!(pnpm(source.path(), "arm64").unwrap().len(), 2);
        let env_lock = format!(
            "---\nlockfileVersion: '9.0'\npackages:\n  pnpm@11.25.0:\n    resolution: {{integrity: {}}}\n---\n",
            sri(b"pnpm")
        );
        write(
            source.path(),
            "pnpm-lock.yaml",
            &format!("{env_lock}{lock}"),
        );
        assert_eq!(pnpm(source.path(), "x64").unwrap().len(), 4);
    }

    #[test]
    fn pnpm_rejects_unhashed_git_tarball_and_old_locks() {
        let source = tempfile::tempdir().unwrap();
        for entry in [
            "x@1.0.0:\n    resolution: {integrity: sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA=}".to_string(),
            "x@1.0.0:\n    resolution: {}".into(),
            "x@https://codeload.github.com/a/b/tar.gz/abc:\n    resolution: {tarball: https://codeload.github.com/a/b/tar.gz/abc}".into(),
            "x@git+https://github.com/a/b.git#abc:\n    resolution: {type: git, repo: 'https://github.com/a/b.git', commit: abc}".into(),
            format!("x@latest:\n    resolution: {{integrity: {}}}", sri(b"x")),
        ] {
            write(
                source.path(),
                "pnpm-lock.yaml",
                &format!("lockfileVersion: '9.0'\npackages:\n  {entry}\n"),
            );
            assert!(pnpm(source.path(), "x64").is_err(), "{entry}");
        }
        write(source.path(), "pnpm-lock.yaml", "lockfileVersion: '6.0'\n");
        assert!(pnpm(source.path(), "x64").is_err());
        write(source.path(), "pnpm-lock.yaml", "lockfileVersion: '9.0'\n");
        assert!(pnpm(source.path(), "x64").unwrap().is_empty());
    }

    #[test]
    fn yarn_1_reads_resolved_urls_and_rejects_sha1_only_entries() {
        let source = tempfile::tempdir().unwrap();
        let lock = format!(
            "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n# yarn lockfile v1\n\n\n\"@babel/code-frame@^7.0.0\", \"@babel/code-frame@^7.10.4\":\n  version \"7.12.13\"\n  resolved \"https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.12.13.tgz#dcfc826beef65e75c50e21d3837d7d95798dd658\"\n  integrity {a}\n  dependencies:\n    left-pad \"^1.3.0\"\n\nleft-pad@^1.3.0:\n  version \"1.3.0\"\n  resolved \"https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#5b8a3a7765dfe001261dde915589e782f8c94d1e\"\n  integrity {b}\n\nlocal@file:./vendor/local:\n  version \"0.0.0\"\n",
            a = sri(b"frame"),
            b = sri(b"left-pad"),
        );
        write(source.path(), "yarn.lock", &lock);
        let archives = yarn(source.path()).unwrap();
        let names: Vec<_> = archives.iter().map(|d| d.filename.as_str()).collect();
        assert_eq!(
            names,
            ["@babel-code-frame-7.12.13.tgz", "left-pad-1.3.0.tgz"]
        );
        assert_eq!(
            archives[1].url.as_str(),
            "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz"
        );
        assert!(pinned(&archives[0]).matches(b"frame"));
        write(
            source.path(),
            "yarn.lock",
            &lock.replace(&sri(b"left-pad"), "sha1-W4o6d2Xf4AEmHd6RVYnngvjJTR4="),
        );
        assert!(yarn(source.path()).is_err());
        write(source.path(), "yarn.lock", "left-pad@^1.3.0:\n");
        assert!(yarn(source.path()).is_err());
    }

    #[test]
    fn yarn_berry_checks_registry_integrity_and_skips_local_sources() {
        let source = tempfile::tempdir().unwrap();
        let lock = "__metadata:\n  version: 8\n  cacheKey: 10c0\n\n\"left-pad@npm:^1.3.0\":\n  version: 1.3.0\n  resolution: \"left-pad@npm:1.3.0\"\n  checksum: 10c0/abc\n  languageName: node\n  linkType: hard\n\n\"@esbuild/darwin-arm64@npm:0.21.0\":\n  version: 0.21.0\n  resolution: \"@esbuild/darwin-arm64@npm:0.21.0\"\n  conditions: os=darwin & cpu=arm64\n  checksum: 10c0/def\n  languageName: node\n  linkType: hard\n\n\"app@workspace:.\":\n  version: 0.0.0-use.local\n  resolution: \"app@workspace:.\"\n  languageName: unknown\n  linkType: soft\n\n\"typescript@patch:typescript@npm%3A5.4.5#optional!builtin<compat/typescript>\":\n  version: 5.4.5\n  resolution: \"typescript@patch:typescript@npm%3A5.4.5#optional!builtin<compat/typescript>::version=5.4.5&hash=5adc0c\"\n  checksum: 10c0/123\n  languageName: node\n  linkType: hard\n";
        write(source.path(), "yarn.lock", lock);
        let archives = yarn_berry(source.path()).unwrap();
        assert_eq!(archives.len(), 2);
        assert_eq!(archives[0].filename, "left-pad-1.3.0.tgz");
        assert_eq!(
            archives[0].check,
            Check::Registry(Url::parse("https://registry.npmjs.org/left-pad/1.3.0").unwrap())
        );
        write(
            source.path(),
            "yarn.lock",
            &lock.replace("  checksum: 10c0/def\n", ""),
        );
        assert_eq!(yarn_berry(source.path()).unwrap().len(), 2);
        write(
            source.path(),
            "yarn.lock",
            &lock.replace("  checksum: 10c0/abc\n", ""),
        );
        let error = yarn_berry(source.path()).unwrap_err().to_string();
        assert!(error.contains("no checksum in the lock"), "{error}");
        write(
            source.path(),
            "yarn.lock",
            "__metadata:\n  version: 8\n\"x@https://example.com/x.tgz\":\n  resolution: \"x@https://example.com/x.tgz\"\n  checksum: 10c0/abc\n",
        );
        assert!(yarn_berry(source.path()).is_err());
    }

    #[test]
    fn package_manager_follows_pins_defaults_and_yarn_path() {
        let source = tempfile::tempdir().unwrap();
        write(source.path(), "package-lock.json", "{}");
        assert_eq!(package_manager(source.path(), "x64").unwrap(), None);
        std::fs::remove_file(source.path().join("package-lock.json")).unwrap();

        write(source.path(), "pnpm-lock.yaml", "lockfileVersion: '9.0'\n");
        let default = package_manager(source.path(), "x64").unwrap().unwrap();
        assert_eq!(
            default.url.as_str(),
            "https://registry.npmjs.org/pnpm/-/pnpm-10.34.9.tgz"
        );
        assert_eq!(default.filename, PACKAGE_MANAGER_ARCHIVE);

        let hex = "37ebf1a5c7a30d5fabe0c5df44ee8da4c965ca0c5af3dbab28c3a1681b70a256218d05c81c9c0dcf767ef6b8551eb5b960042b9ed4300c59242336377e01cfad";
        write(
            source.path(),
            "package.json",
            &format!(r#"{{"packageManager":"pnpm@10.13.1+sha512.{hex}"}}"#),
        );
        let hashed = package_manager(source.path(), "x64").unwrap().unwrap();
        assert_eq!(
            hashed.url.as_str(),
            "https://registry.npmjs.org/pnpm/-/pnpm-10.13.1.tgz"
        );
        assert!(matches!(hashed.check, Check::Pinned(_)));

        write(
            source.path(),
            "package.json",
            r#"{"packageManager":"pnpm@12.16.1"}"#,
        );
        let native = package_manager(source.path(), "arm64").unwrap().unwrap();
        assert_eq!(
            native.url.as_str(),
            "https://registry.npmjs.org/@pnpm/exe.linux-arm64/-/exe.linux-arm64-12.16.1.tgz"
        );
        assert_eq!(
            native.check,
            Check::Registry(
                Url::parse("https://registry.npmjs.org/@pnpm/exe.linux-arm64/12.16.1").unwrap()
            )
        );
        std::fs::remove_file(source.path().join("pnpm-lock.yaml")).unwrap();

        write(source.path(), "yarn.lock", "__metadata:\n  version: 8\n");
        write(
            source.path(),
            "package.json",
            r#"{"packageManager":"yarn@4.18.1"}"#,
        );
        let berry = package_manager(source.path(), "x64").unwrap().unwrap();
        assert_eq!(
            berry.url.as_str(),
            "https://registry.npmjs.org/@yarnpkg/cli-dist/-/cli-dist-4.18.1.tgz"
        );
        // A hashed pin covers the yarn.js bundle that Corepack downloads.
        let hex = "c38cafb5c7bb273f3926d04e55e1d8c9dfa7d9c3ea1f36a4868fa028b9e5f72298f0b7f401ad5eb921749eb012eb1c3bb74bf7503df3ee43fd600d14a018266f";
        write(
            source.path(),
            "package.json",
            &format!(r#"{{"packageManager":"yarn@4.10.3+sha512.{hex}"}}"#),
        );
        let bundle = package_manager(source.path(), "x64").unwrap().unwrap();
        assert_eq!(
            bundle.url.as_str(),
            "https://repo.yarnpkg.com/4.10.3/packages/yarnpkg-cli/bin/yarn.js"
        );
        assert_eq!(bundle.filename, YARN_BUNDLE);
        assert!(matches!(bundle.check, Check::Pinned(_)));
        write(
            source.path(),
            "package.json",
            r#"{"packageManager":"yarn@4.18.1"}"#,
        );
        std::fs::create_dir_all(source.path().join(".yarn/releases")).unwrap();
        write(source.path(), ".yarn/releases/yarn-4.18.1.cjs", "");
        write(
            source.path(),
            ".yarnrc.yml",
            "yarnPath: .yarn/releases/yarn-4.18.1.cjs\n",
        );
        assert_eq!(package_manager(source.path(), "x64").unwrap(), None);
        write(source.path(), ".yarnrc.yml", "yarnPath: ../outside.cjs\n");
        assert!(package_manager(source.path(), "x64").is_err());
        std::fs::remove_file(source.path().join(".yarnrc.yml")).unwrap();
        write(source.path(), "package.json", "{}");
        assert!(package_manager(source.path(), "x64").is_err());

        write(source.path(), "yarn.lock", "# yarn lockfile v1\n");
        let classic = package_manager(source.path(), "x64").unwrap().unwrap();
        assert_eq!(
            classic.url.as_str(),
            "https://registry.npmjs.org/yarn/-/yarn-1.22.22.tgz"
        );
        write(
            source.path(),
            "package.json",
            r#"{"packageManager":"yarn@4.18.1"}"#,
        );
        assert!(package_manager(source.path(), "x64").is_err());
        write(
            source.path(),
            "package.json",
            r#"{"packageManager":"pnpm@latest"}"#,
        );
        assert!(package_manager(source.path(), "x64").is_err());
    }
}
