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
