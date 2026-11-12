//! Strict registry-only npm lock parsing. Every package is bound to its integrity.

use std::collections::BTreeSet;

use anyhow::{ensure, Context, Result};
use clearhash_ecosystems::offline::Integrity;
use serde_json::Value;

pub fn valid_part(part: &str) -> bool {
    !part.is_empty()
        && !part.starts_with(['.', '-'])
        && part
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

pub fn valid_name(name: &str) -> bool {
    if let Some(scoped) = name.strip_prefix('@') {
        scoped
            .split_once('/')
            .is_some_and(|(scope, name)| valid_part(scope) && valid_part(name))
    } else {
        valid_part(name)
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct LockedPackage {
    pub name: String,
    pub version: String,
    pub integrity: String,
}

pub fn locked_packages(bytes: &[u8]) -> Result<BTreeSet<LockedPackage>> {
    let lock: Value = serde_json::from_slice(bytes).context("invalid npm lockfile")?;
    ensure!(
        matches!(lock["lockfileVersion"].as_u64(), Some(2 | 3)),
        "verification requires lockfileVersion 2 or 3"
    );
    let entries = lock["packages"]
        .as_object()
        .context("lockfile has no packages")?;
    ensure!(
        entries.get("").is_some_and(Value::is_object),
        "lockfile has no root package"
    );
    let mut packages = BTreeSet::new();
    for (path, entry) in entries {
        if path.is_empty() {
            continue;
        }
        ensure!(entry.is_object(), "invalid lock entry: {path}");
        // Validate every path component, including nested and scoped installs.
        let mut remaining = path.as_str();
        let installed_name = loop {
            let tail = remaining
                .strip_prefix("node_modules/")
                .context("workspace/local lock entries are unsupported")?;
            if let Some((name, rest)) = tail.split_once("/node_modules/") {
                ensure!(valid_name(name), "invalid lock path: {path}");
                remaining = &tail[name.len() + 1..];
                ensure!(!rest.is_empty(), "invalid lock path: {path}");
            } else {
                ensure!(valid_name(tail), "invalid lock path: {path}");
                break tail;
            }
        };
        ensure!(
            entry.get("link").is_none_or(|v| v == false)
                && entry.get("inBundle").is_none_or(|v| v == false),
            "linked and bundled dependencies are unsupported: {path}"
        );
        let name = entry
            .get("name")
            .map_or(Some(installed_name), Value::as_str)
            .context("invalid locked name")?;
        ensure!(valid_name(name), "invalid package name: {name}");
        let version = entry["version"]
            .as_str()
            .context("missing locked version")?;
        semver::Version::parse(version).context("expected exact registry version")?;
        if let Some(resolved) = entry.get("resolved") {
            let url = url::Url::parse(resolved.as_str().context("invalid resolved URL")?)?;
            ensure!(
                url.scheme() == "https"
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none(),
                "unsupported dependency URL for {path}"
            );
        }
        let integrity = entry["integrity"]
            .as_str()
            .context("missing locked integrity")?;
        Integrity::parse(integrity).with_context(|| format!("invalid integrity for {path}"))?;
        packages.insert(LockedPackage {
            name: name.into(),
            version: version.into(),
            integrity: integrity.into(),
        });
    }
    Ok(packages)
}
