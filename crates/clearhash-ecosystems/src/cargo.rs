//! Cargo adapter — skeleton. Filled in at Step 7 of the implementation plan.
//!
//! Cargo has no widespread SLSA attestation as of 2026. `attestation_url` returns `None`;
//! every cargo verify requires `--allow-unattested` at the CLI layer.

use async_trait::async_trait;
use clearhash_core::{Ecosystem, PackageRef, ProvenanceClaim};
use url::Url;

use crate::{AdapterError, EcosystemAdapter};

pub struct CargoAdapter;

#[async_trait]
impl EcosystemAdapter for CargoAdapter {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Cargo
    }

    fn artifact_url(&self, pkg: &PackageRef) -> Url {
        let raw = format!(
            "https://static.crates.io/crates/{name}/{name}-{ver}.crate",
            name = pkg.name,
            ver = pkg.version,
        );
        Url::parse(&raw).expect("cargo artifact URL")
    }

    fn attestation_url(&self, _pkg: &PackageRef) -> Option<Url> {
        None
    }

    fn latest_version_url(&self, name: &str) -> Option<Url> {
        let raw = format!("https://crates.io/api/v1/crates/{name}");
        Some(Url::parse(&raw).expect("cargo latest-version URL"))
    }

    fn parse_latest_version(&self, body: &[u8]) -> Result<String, AdapterError> {
        let v: serde_json::Value = serde_json::from_slice(body)
            .map_err(|e| AdapterError::MalformedAttestation(format!("crates.io metadata: {e}")))?;
        // `crate.max_stable_version` is what `cargo add <name>` (no version pin) would resolve to.
        // Falls back to `max_version` if no stable release exists (pre-1.0 crates).
        v.get("crate")
            .and_then(|c| c.get("max_stable_version").or_else(|| c.get("max_version")))
            .and_then(|s| s.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                AdapterError::MalformedAttestation(
                    "crates.io response missing crate.max_stable_version".into(),
                )
            })
    }

    fn parse_attestation(&self, _bundle: &[u8]) -> Result<ProvenanceClaim, AdapterError> {
        Err(AdapterError::Unimplemented("cargo.parse_attestation"))
    }

    fn rebuild_image(&self) -> &'static str {
        "rust:1.78-slim-bookworm"
    }

    fn rebuild_script(&self) -> &'static str {
        r#"set -eu
mkdir -p /out
cd /src
cargo package --locked --no-verify --target-dir=/tmp/cargo-build
cp target/package/*.crate /out/ 2>/dev/null || cp /tmp/cargo-build/package/*.crate /out/
"#
    }

    fn built_artifact_dir(&self) -> &'static str {
        "/out"
    }

    fn strip_archive_prefix(&self, pkg: &PackageRef) -> Option<String> {
        // .crate files wrap contents in `<name>-<version>/`.
        Some(format!("{}-{}", pkg.name, pkg.version))
    }

    fn ignore_paths(&self) -> &'static [&'static str] {
        // .cargo_vcs_info.json encodes the source commit — keep it; it's part of the determinism story.
        &[]
    }
}
