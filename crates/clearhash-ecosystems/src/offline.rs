//! Adapter-owned lockfile interpretation and integrity policy. No package code runs on the host.
use std::path::Path;

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use sha2::{Digest, Sha256, Sha384, Sha512};
use url::Url;

use crate::AdapterError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    pub url: Url,
    /// A single, safe filename under the cache directory.
    pub filename: String,
    pub check: Check,
}

/// How the host checks an archive before it reaches a container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Check {
    /// A hash pinned by the lock, a `packageManager` field, or ClearHash itself.
    Pinned(Integrity),
    /// The `dist.integrity` in this npm registry version document, read over HTTPS.
    /// Used only where no pin covers the tarball: Yarn 2+ locks pin Yarn's own zip,
    /// which Yarn checks inside the container, and unhashed `packageManager` pins.
    Registry(Url),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Integrity {
    algorithm: String,
    digests: Vec<Vec<u8>>,
}

pub(crate) fn invalid(message: impl Into<String>) -> AdapterError {
    AdapterError::InvalidRebuild(message.into())
}

impl Integrity {
    /// SRI accepts alternatives only within the strongest declared algorithm.
    /// SHA-1-only locks are rejected rather than silently weakening the trust root.
    pub fn parse(sri: &str) -> Result<Self, AdapterError> {
        let mut selected = Self {
            algorithm: String::new(),
            digests: Vec::new(),
        };
        let mut strength = 0;
        for token in sri.split_whitespace() {
            let (algorithm, digest) = token
                .split_once('-')
                .ok_or_else(|| invalid("malformed dependency integrity"))?;
            let rank = match algorithm {
                "sha512" => 64,
                "sha384" => 48,
                "sha256" => 32,
                _ => {
                    return Err(invalid(
                        "dependency integrity must use SHA-256, SHA-384 or SHA-512",
                    ))
                }
            };
            let decoded = STANDARD
                .decode(digest)
                .map_err(|_| invalid("invalid base64 integrity digest"))?;
            if decoded.len() != rank {
                return Err(invalid("invalid integrity digest length"));
            }
            if rank > strength {
                selected.algorithm = algorithm.into();
                selected.digests.clear();
                strength = rank;
            }
            if rank == strength {
                selected.digests.push(decoded);
            }
        }
        if strength == 0 {
            return Err(invalid("missing dependency integrity"));
        }
        Ok(selected)
    }

    pub fn matches(&self, bytes: &[u8]) -> bool {
        let actual = match self.algorithm.as_str() {
            "sha512" => Sha512::digest(bytes).to_vec(),
            "sha384" => Sha384::digest(bytes).to_vec(),
            "sha256" => Sha256::digest(bytes).to_vec(),
            _ => return false,
        };
        self.digests.contains(&actual)
    }
}

pub(crate) fn archive(
    url: &str,
    filename: String,
    check: Check,
) -> Result<Dependency, AdapterError> {
    let url = Url::parse(url).map_err(|_| invalid("invalid dependency URL"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(invalid(
            "dependency URLs must use HTTPS without credentials",
        ));
    }
    if filename.is_empty() || filename.starts_with('.') || filename.contains(['/', '\\', ':']) {
        return Err(invalid("unsafe dependency archive filename"));
    }
    Ok(Dependency {
        url,
        filename,
        check,
    })
}

/// The registry tarball URL for an exact npm version. Never re-resolves a range.
pub(crate) fn registry_tarball(name: &str, version: &str) -> Result<String, AdapterError> {
    semver::Version::parse(version).map_err(|_| {
        invalid(format!(
            "{name}@{version}: expected an exact registry version"
        ))
    })?;
    let unscoped = name.rsplit('/').next().unwrap_or("");
    let scoped_once = name.matches('/').count() == usize::from(name.starts_with('@'));
    if unscoped.is_empty()
        || !scoped_once
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"@/._-".contains(&c))
    {
        return Err(invalid(format!("{name}: invalid registry package name")));
    }
    Ok(format!(
        "https://registry.npmjs.org/{name}/-/{unscoped}-{version}.tgz"
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NpmLock {
    lockfile_version: u32,
    packages: std::collections::BTreeMap<String, NpmPackage>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NpmPackage {
    name: Option<String>,
    version: Option<String>,
    resolved: Option<String>,
    integrity: Option<String>,
    #[serde(default)]
    link: bool,
    #[serde(default)]
    in_bundle: bool,
}

pub fn npm(source: &Path) -> Result<Vec<Dependency>, AdapterError> {
    // npm gives shrinkwrap precedence over package-lock; interpret the same file it will use.
    let path = if source.join("npm-shrinkwrap.json").exists() {
        source.join("npm-shrinkwrap.json")
    } else {
        source.join("package-lock.json")
    };
    let bytes = std::fs::read(&path).map_err(|e| {
        invalid(format!(
            "offline npm requires a committed package-lock.json or npm-shrinkwrap.json: {e}"
        ))
    })?;
    let lock: NpmLock =
        serde_json::from_slice(&bytes).map_err(|e| invalid(format!("npm lockfile: {e}")))?;
    if !matches!(lock.lockfile_version, 2 | 3) {
        return Err(invalid("offline npm requires lockfileVersion 2 or 3"));
    }
    let mut archives = Vec::new();
    for (path, package) in lock.packages {
        // Root and workspace manifests describe source already pinned by Git.
        if !path.split('/').any(|part| part == "node_modules") {
            continue;
        }
        if package.link {
            let target = package
                .resolved
                .ok_or_else(|| invalid("workspace link has no target"))?;
            let root = source.canonicalize().map_err(|e| invalid(e.to_string()))?;
            let target = source
                .join(target)
                .canonicalize()
                .map_err(|e| invalid(format!("workspace link: {e}")))?;
            if !target.starts_with(&root) {
                return Err(invalid("workspace link escapes pinned source"));
            }
            continue;
        }
        if package.in_bundle {
            continue;
        }
        let url = match package.resolved {
            Some(url) => url,
            None => {
                // npm's omit-lockfile-registry-resolved removes URLs but retains
                // registry coordinates and integrity. Never re-resolve a version.
                let version = package
                    .version
                    .ok_or_else(|| invalid(format!("{path}: missing locked version")))?;
                let name = package.name.as_deref().unwrap_or_else(|| {
                    path.rsplit_once("node_modules/")
                        .map_or("", |(_, name)| name)
                });
                registry_tarball(name, &version).map_err(|e| invalid(format!("{path}: {e}")))?
            }
        };
        let integrity = Integrity::parse(package.integrity.as_deref().unwrap_or(""))?;
        let dependency = archive(
            &url,
            format!("{}.tgz", archives.len()),
            Check::Pinned(integrity),
        )?;
        if !archives
            .iter()
            .any(|d: &Dependency| d.url == dependency.url && d.check == dependency.check)
        {
            archives.push(dependency);
        }
    }
    Ok(archives)
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct PyLock {
    lock_version: String,
    packages: Vec<PyPackage>,
}

#[derive(Deserialize)]
struct PyPackage {
    name: String,
    version: String,
    #[serde(default)]
    wheels: Vec<Wheel>,
}

#[derive(Deserialize)]
struct Wheel {
    name: Option<String>,
    url: String,
    hashes: std::collections::BTreeMap<String, String>,
}

pub fn pypi(source: &Path) -> Result<Vec<Dependency>, AdapterError> {
    let text = std::fs::read_to_string(source.join("pylock.toml")).map_err(|e| invalid(format!("offline PyPI requires a committed pylock.toml containing build and backend wheels: {e}")))?;
    let lock: PyLock = toml::from_str(&text).map_err(|e| invalid(format!("pylock.toml: {e}")))?;
    if lock.lock_version != "1.0" {
        return Err(invalid("unsupported pylock.toml lock-version"));
    }
    let mut archives = Vec::new();
    for package in lock.packages {
        if package.wheels.is_empty() {
            return Err(invalid(format!(
                "{}=={}: offline build requires locked wheels",
                package.name, package.version
            )));
        }
        for wheel in package.wheels {
            let digest = wheel
                .hashes
                .get("sha256")
                .ok_or_else(|| invalid("locked wheel requires sha256"))?;
            let digest = hex::decode(digest).map_err(|_| invalid("invalid wheel sha256"))?;
            let integrity = Integrity::parse(&format!("sha256-{}", STANDARD.encode(digest)))?;
            let url = Url::parse(&wheel.url).map_err(|_| invalid("invalid wheel URL"))?;
            let name = wheel.name.unwrap_or_else(|| {
                url.path_segments()
                    .and_then(|mut s| s.next_back())
                    .unwrap_or("")
                    .into()
            });
            if !name.ends_with(".whl") {
                return Err(invalid("locked artifact is not a wheel"));
            }
            let dependency = archive(&wheel.url, name, Check::Pinned(integrity))?;
            if let Some(previous) = archives
                .iter()
                .find(|d: &&Dependency| d.filename == dependency.filename)
            {
                if *previous != dependency {
                    return Err(invalid("conflicting locked wheel filenames"));
                }
            } else {
                archives.push(dependency);
            }
        }
    }
    Ok(archives)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) fn pinned(dependency: &Dependency) -> &Integrity {
        match &dependency.check {
            Check::Pinned(integrity) => integrity,
            Check::Registry(url) => panic!("expected a pinned hash, found {url}"),
        }
    }

    pub(crate) fn sri(bytes: &[u8]) -> String {
        format!("sha512-{}", STANDARD.encode(Sha512::digest(bytes)))
    }

    #[test]
    fn integrity_rejects_tampering_and_downgrades() {
        assert!(Integrity::parse(&sri(b"archive"))
            .unwrap()
            .matches(b"archive"));
        assert!(!Integrity::parse(&sri(b"archive"))
            .unwrap()
            .matches(b"tampered"));
        let weak = format!("sha256-{}", STANDARD.encode(Sha256::digest(b"archive")));
        for input in [
            format!("{weak} {}", sri(b"other")),
            format!("{} {weak}", sri(b"other")),
        ] {
            assert!(!Integrity::parse(&input).unwrap().matches(b"archive"));
        }
        for invalid in ["", "sha1-abc", "sha512-bad", "sha256-!!!!", "oops"] {
            assert!(Integrity::parse(invalid).is_err());
        }
        let alternatives = format!("{} {}", sri(b"other"), sri(b"archive"));
        assert!(Integrity::parse(&alternatives).unwrap().matches(b"archive"));
        let sha384 = format!("sha384-{}", STANDARD.encode(Sha384::digest(b"archive")));
        assert!(Integrity::parse(&sha384).unwrap().matches(b"archive"));
    }

    #[test]
    fn npm_walks_transitive_dev_optional_and_workspace_dependencies() {
        let source = tempfile::tempdir().unwrap();
        std::fs::create_dir(source.path().join("member")).unwrap();
        let dep = json!({"resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz", "integrity": sri(b"archive")});
        let lock = json!({"lockfileVersion": 3, "packages": {
            "": {}, "member": {}, "node_modules/member": {"link": true, "resolved": "member"},
            "node_modules/x": dep, "node_modules/x/node_modules/y": {"dev": true, "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz", "integrity": sri(b"archive")},
            "node_modules/optional": {"optional": true, "resolved": "https://registry.npmjs.org/o.tgz", "integrity": sri(b"optional")},
            "node_modules/@scope/pkg": {"version":"1.2.3", "integrity":sri(b"scoped")},
            "node_modules/alias": {"name":"@scope/pkg", "version":"1.2.3", "integrity":sri(b"scoped")},
            "node_modules/x/node_modules/bundled": {"inBundle": true}
        }});
        std::fs::write(source.path().join("package-lock.json"), lock.to_string()).unwrap();
        let dependencies = npm(source.path()).unwrap();
        assert_eq!(dependencies.len(), 3);
        assert!(dependencies
            .iter()
            .any(|d| d.url.as_str() == "https://registry.npmjs.org/@scope/pkg/-/pkg-1.2.3.tgz"));
        assert!(dependencies.iter().any(|d| pinned(d).matches(b"archive")));
        assert!(dependencies.iter().any(|d| pinned(d).matches(b"optional")));
    }

    #[test]
    fn npm_rejects_unlocked_and_unsafe_sources_and_honors_shrinkwrap() {
        let source = tempfile::tempdir().unwrap();
        assert!(npm(source.path()).is_err());
        for entry in [
            json!({}),
            json!({"resolved":"git+https://example.com/repo", "integrity": sri(b"x")}),
            json!({"resolved":"http://example.com/x.tgz", "integrity": sri(b"x")}),
            json!({"resolved":"https://example.com/x.tgz"}),
            json!({"resolved":"file:../x", "integrity": sri(b"x")}),
            json!({"resolved":"..", "link": true}),
        ] {
            let lock = json!({"lockfileVersion": 3, "packages": {"node_modules/x": entry}});
            std::fs::write(source.path().join("package-lock.json"), lock.to_string()).unwrap();
            assert!(npm(source.path()).is_err());
        }
        for version in [1, 4] {
            std::fs::write(
                source.path().join("package-lock.json"),
                json!({"lockfileVersion": version, "packages": {}}).to_string(),
            )
            .unwrap();
            assert!(npm(source.path()).is_err());
        }
        std::fs::write(
            source.path().join("npm-shrinkwrap.json"),
            r#"{"lockfileVersion":2,"packages":{"":{}}}"#,
        )
        .unwrap();
        assert!(npm(source.path()).unwrap().is_empty());
    }

    fn wheel_lock(url: &str, name: &str, hash: &str) -> String {
        format!("lock-version = '1.0'\n[[packages]]\nname = 'build'\nversion = '1.2.2'\n[[packages.wheels]]\nurl = '{url}'\nname = '{name}'\n[packages.wheels.hashes]\nsha256 = '{hash}'\n")
    }

    #[test]
    fn pypi_reads_hashed_wheels_and_rejects_unpinned_or_unsafe_archives() {
        let source = tempfile::tempdir().unwrap();
        assert!(pypi(source.path()).is_err());
        let hash = hex::encode(Sha256::digest(b"wheel"));
        let valid = wheel_lock(
            "https://files.pythonhosted.org/build.whl",
            "build-1.2.2-py3-none-any.whl",
            &hash,
        );
        std::fs::write(source.path().join("pylock.toml"), &valid).unwrap();
        let wheels = pypi(source.path()).unwrap();
        assert_eq!(wheels.len(), 1);
        assert!(pinned(&wheels[0]).matches(b"wheel"));
        assert!(!pinned(&wheels[0]).matches(b"tampered"));
        for text in [
            valid.replace("https:", "http:"),
            valid.replace(&hash, "abc"),
            valid.replace("build-1.2.2-py3-none-any.whl", "../escape.whl"),
            valid.replace("build-1.2.2-py3-none-any.whl", "build.tar.gz"),
            valid.replace("sha256 =", "sha1 ="),
            valid.replace("'1.0'", "'9.0'"),
            "lock-version = '1.0'\n[[packages]]\nname = 'build'\nversion = '1.2.2'".into(),
        ] {
            std::fs::write(source.path().join("pylock.toml"), text).unwrap();
            assert!(pypi(source.path()).is_err());
        }
    }
}
