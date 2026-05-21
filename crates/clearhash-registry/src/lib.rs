//! Fetcher for package artifacts + SLSA attestation bundles.
//!
//! Lives behind one async function `fetch(adapter, pkg) -> FetchedArtifact`. The result holds
//! the on-disk archive path, the optional attestation envelope bytes, and the SHA-256 of the
//! downloaded artifact for diagnostic logging.

use std::path::PathBuf;
use std::time::Duration;

use bytes::Bytes;
use clearhash_core::{sha256, PackageRef};
use clearhash_ecosystems::EcosystemAdapter;
use thiserror::Error;

pub struct FetchedArtifact {
    /// On-disk path to the downloaded archive. Lives inside a `tempfile::TempDir`
    /// owned by the returned `FetchedArtifact` so cleanup is automatic.
    pub archive_path: PathBuf,
    /// `None` if the registry returned 404 for the attestation endpoint, or if the
    /// adapter does not publish attestations (cargo today).
    pub attestation_bundle: Option<Bytes>,
    /// SHA-256 of the downloaded artifact. Diagnostic only — the real comparison
    /// is done against the rebuilt tree in `clearhash-sandbox::compare_trees`.
    pub registry_sha256: [u8; 32],
    /// Hold the temp dir alive for the lifetime of the result.
    _tempdir: tempfile::TempDir,
}

#[derive(Debug, Error)]
pub enum FetchError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("registry returned status {0} for {1}")]
    BadStatus(reqwest::StatusCode, String),
}

pub async fn fetch(
    adapter: &dyn EcosystemAdapter,
    pkg: &PackageRef,
) -> Result<FetchedArtifact, FetchError> {
    let client = reqwest::Client::builder()
        .user_agent(concat!("clearhash/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(60))
        .build()?;

    let artifact_url = adapter.artifact_url(pkg);
    tracing::info!(url = %artifact_url, "fetching artifact");

    let resp = client.get(artifact_url.clone()).send().await?;
    if !resp.status().is_success() {
        return Err(FetchError::BadStatus(resp.status(), artifact_url.into()));
    }
    let bytes = resp.bytes().await?;
    let registry_sha256 = sha256(&bytes);

    let dir = tempfile::Builder::new().prefix("clearhash-").tempdir()?;
    let filename = artifact_url
        .path_segments()
        .and_then(|mut s| s.next_back())
        .unwrap_or("artifact")
        .to_string();
    let archive_path = dir.path().join(&filename);
    tokio::fs::write(&archive_path, &bytes).await?;

    // Attestation bundle. None is a normal outcome (legacy packages / cargo).
    let attestation_bundle = match adapter.attestation_url(pkg) {
        None => None,
        Some(url) => {
            tracing::info!(url = %url, "fetching attestation");
            let resp = client.get(url.clone()).send().await?;
            match resp.status() {
                s if s.is_success() => Some(resp.bytes().await?),
                reqwest::StatusCode::NOT_FOUND => None,
                other => return Err(FetchError::BadStatus(other, url.into())),
            }
        }
    };

    Ok(FetchedArtifact {
        archive_path,
        attestation_bundle,
        registry_sha256,
        _tempdir: dir,
    })
}
