//! Ecosystem adapters. Every registry-specific quirk lives behind the `EcosystemAdapter` trait;
//! engine crates (`registry`, `provenance`, `sandbox`) only know about `dyn EcosystemAdapter`.

use std::path::Path;

use async_trait::async_trait;
use clearhash_core::{Ecosystem, FileEntry, PackageRef, ProvenanceClaim};
use url::Url;

pub mod cargo;
pub mod npm;
pub mod pypi;

/// What a single ecosystem adapter must provide.
///
/// The trait is intentionally narrow. State-bearing work (HTTP clients, Docker sockets,
/// temp dirs) belongs to the engine crates. The adapter only translates between
/// "the abstract pipeline" and "this ecosystem's URLs, archive format, build script,
/// and normalization rules."
#[async_trait]
pub trait EcosystemAdapter: Send + Sync {
    fn ecosystem(&self) -> Ecosystem;
    fn name(&self) -> &'static str {
        self.ecosystem().as_str()
    }

    // --- Step 1: where to fetch ---------------------------------------------------------

    fn artifact_url(&self, pkg: &PackageRef) -> Url;

    /// Some ecosystems (cargo) publish no attestation today. Returning `None` here is the
    /// adapter's way of telling the CLI "this ecosystem requires --allow-unattested."
    fn attestation_url(&self, pkg: &PackageRef) -> Option<Url>;

    // --- Optional: latest-version resolution -------------------------------------------

    /// URL whose response body, when fed to `parse_latest_version`, yields the latest stable
    /// version string for the given package name. Used by the web frontend to accept
    /// `<ecosystem>:<name>` inputs without an `@<version>` suffix.
    ///
    /// Returning `None` means this ecosystem doesn't support latest-resolution. The web layer
    /// surfaces the underlying parse error in that case.
    fn latest_version_url(&self, name: &str) -> Option<Url> {
        let _ = name;
        None
    }

    /// Parse the latest stable version out of the response body served by `latest_version_url`.
    fn parse_latest_version(&self, body: &[u8]) -> Result<String, AdapterError> {
        let _ = body;
        Err(AdapterError::Unimplemented("parse_latest_version"))
    }

    // --- Step 2: parse the attestation envelope ----------------------------------------

    /// Pull the SLSA in-toto statement (DSSE-wrapped) out of a registry-specific envelope.
    /// The sigstore signature is verified separately by `clearhash-provenance` — the adapter
    /// only owns the envelope schema.
    fn parse_attestation(&self, bundle: &[u8]) -> Result<ProvenanceClaim, AdapterError>;

    // --- Steps 3-4: how to rebuild -----------------------------------------------------

    /// Pinned Docker image. Never tag-track; always pin a digest in production.
    fn rebuild_image(&self) -> &'static str;

    /// Build script injected into the network-isolated container. The sandbox crate
    /// substitutes `{COMMIT_SHA}` and `{REPO_URL}` placeholders before exec.
    fn rebuild_script(&self) -> &'static str;

    /// Absolute path inside the container from which built artifacts should be pulled.
    fn built_artifact_dir(&self) -> &'static str;

    // --- Step 5: tree normalization & comparison ---------------------------------------

    /// Path prefixes that should be stripped from the *extracted* registry artifact
    /// before walking. Most registries wrap the package in a single top-level directory
    /// (`package/` for npm, `<name>-<version>/` for PyPI sdists, etc.).
    fn strip_archive_prefix(&self, pkg: &PackageRef) -> Option<String>;

    /// Patterns (matched against relative posix path) that should be excluded from the
    /// comparison entirely — files that registries inject post-pack and that rebuilds
    /// cannot reproduce.
    fn ignore_paths(&self) -> &'static [&'static str];

    /// Adapter-specific tweaks applied to a single file's bytes before hashing.
    /// Default: identity. npm overrides this to scrub the registry-injected fields
    /// (`_id`, `_integrity`, `_resolved`, `dist`) from `package.json`.
    fn normalize_file(&self, path: &str, bytes: Vec<u8>) -> Vec<u8> {
        let _ = path;
        bytes
    }

    /// Walk a directory, apply normalization, return sorted `FileEntry`s ready for hashing.
    fn build_entries(&self, root: &Path) -> Result<Vec<FileEntry>, AdapterError> {
        let mut out = Vec::new();
        for entry in walkdir::WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let rel = entry
                .path()
                .strip_prefix(root)
                .map_err(|e| AdapterError::Walk(e.to_string()))?;
            let rel_str = rel.to_string_lossy().replace('\\', "/");

            if self
                .ignore_paths()
                .iter()
                .any(|pat| path_matches(pat, &rel_str))
            {
                continue;
            }

            let raw = std::fs::read(entry.path())
                .map_err(|e| AdapterError::Walk(format!("read {}: {}", rel_str, e)))?;
            let bytes = self.normalize_file(&rel_str, raw);

            #[cfg(unix)]
            let executable = {
                use std::os::unix::fs::PermissionsExt;
                let m = entry
                    .metadata()
                    .map_err(|e| AdapterError::Walk(e.to_string()))?;
                m.permissions().mode() & 0o100 != 0
            };
            #[cfg(not(unix))]
            let executable = false;

            out.push(clearhash_core::tree::entry_from_bytes(
                rel_str, &bytes, executable,
            ));
        }
        out.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(out)
    }
}

/// Crude glob: supports a trailing `*` (prefix match) or exact match. Sufficient for the
/// short, hand-curated ignore lists each adapter ships. Avoids pulling in the full
/// `globset` crate for ~10 patterns.
fn path_matches(pattern: &str, path: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        path.starts_with(prefix)
    } else {
        pattern == path
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("malformed attestation: {0}")]
    MalformedAttestation(String),
    #[error("walking the tree: {0}")]
    Walk(String),
    #[error("ecosystem not yet implemented for this step: {0}")]
    Unimplemented(&'static str),
}

/// Dispatch helper used by the CLI.
pub fn for_ecosystem(eco: Ecosystem) -> Box<dyn EcosystemAdapter> {
    match eco {
        Ecosystem::Npm => Box::new(npm::NpmAdapter),
        Ecosystem::Pypi => Box::new(pypi::PypiAdapter),
        Ecosystem::Cargo => Box::new(cargo::CargoAdapter),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_returns_named_adapter() {
        assert_eq!(for_ecosystem(Ecosystem::Npm).name(), "npm");
        assert_eq!(for_ecosystem(Ecosystem::Pypi).name(), "pypi");
        assert_eq!(for_ecosystem(Ecosystem::Cargo).name(), "cargo");
    }

    #[test]
    fn glob_prefix_match() {
        assert!(path_matches("node_modules/*", "node_modules/foo/index.js"));
        assert!(!path_matches("node_modules/*", "src/foo.js"));
        assert!(path_matches("package.json", "package.json"));
        assert!(!path_matches("package.json", "package.json.lock"));
    }
}
