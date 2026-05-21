//! PyPI adapter — skeleton. Filled in at Step 6 of the implementation plan.

use async_trait::async_trait;
use clearhash_core::{Ecosystem, PackageRef, ProvenanceClaim};
use url::Url;

use crate::{AdapterError, EcosystemAdapter};

pub struct PypiAdapter;

#[async_trait]
impl EcosystemAdapter for PypiAdapter {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Pypi
    }

    fn artifact_url(&self, _pkg: &PackageRef) -> Url {
        // Real impl: fetch https://pypi.org/pypi/{name}/{version}/json, pick the sdist entry.
        // Stubbed for Step 1; the URL is resolved lazily in the registry crate.
        Url::parse("https://pypi.org/").unwrap()
    }

    fn attestation_url(&self, _pkg: &PackageRef) -> Option<Url> {
        // PEP 740 endpoint, filled in at Step 6.
        None
    }

    fn latest_version_url(&self, name: &str) -> Option<Url> {
        let raw = format!("https://pypi.org/pypi/{name}/json");
        Some(Url::parse(&raw).expect("pypi latest-version URL"))
    }

    fn parse_latest_version(&self, body: &[u8]) -> Result<String, AdapterError> {
        let v: serde_json::Value = serde_json::from_slice(body)
            .map_err(|e| AdapterError::MalformedAttestation(format!("pypi metadata: {e}")))?;
        // `info.version` is the latest *stable* release (what `pip install <pkg>` resolves to).
        v.get("info")
            .and_then(|i| i.get("version"))
            .and_then(|s| s.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                AdapterError::MalformedAttestation("pypi response missing info.version".into())
            })
    }

    fn parse_attestation(&self, _bundle: &[u8]) -> Result<ProvenanceClaim, AdapterError> {
        Err(AdapterError::Unimplemented("pypi.parse_attestation"))
    }

    fn rebuild_image(&self) -> &'static str {
        "python:3.12.2-slim-bookworm"
    }

    fn rebuild_script(&self) -> &'static str {
        r#"set -eu
mkdir -p /out
cd /src
export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct {COMMIT_SHA} 2>/dev/null || echo 0)"
export TZ=UTC
pip install --quiet build
python -m build --sdist --outdir /out
"#
    }

    fn built_artifact_dir(&self) -> &'static str {
        "/out"
    }

    fn strip_archive_prefix(&self, pkg: &PackageRef) -> Option<String> {
        // PyPI sdists wrap contents in `<name>-<version>/`.
        Some(format!("{}-{}", pkg.name, pkg.version))
    }

    fn ignore_paths(&self) -> &'static [&'static str] {
        &["PKG-INFO", "*.egg-info/*"]
    }
}
