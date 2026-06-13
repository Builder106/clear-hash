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
    #[error("adapter: {0}")]
    Adapter(#[from] clearhash_ecosystems::AdapterError),
    #[error("ecosystem does not support latest-version resolution")]
    UnsupportedResolution,
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

/// Resolve the latest stable version for a package name via the adapter's metadata endpoint.
/// Returns `UnsupportedResolution` if the ecosystem hasn't implemented `latest_version_url`.
pub async fn resolve_latest_version(
    adapter: &dyn EcosystemAdapter,
    name: &str,
) -> Result<String, FetchError> {
    let url = adapter
        .latest_version_url(name)
        .ok_or(FetchError::UnsupportedResolution)?;

    let client = reqwest::Client::builder()
        .user_agent(concat!("clearhash/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(15))
        .build()?;

    tracing::info!(url = %url, "resolving latest version");
    let resp = client.get(url.clone()).send().await?;
    if !resp.status().is_success() {
        return Err(FetchError::BadStatus(resp.status(), url.into()));
    }
    let body = resp.bytes().await?;
    let version = adapter.parse_latest_version(&body)?;
    Ok(version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clearhash_core::{Ecosystem, ProvenanceClaim};
    use clearhash_ecosystems::{AdapterError, EcosystemAdapter};
    use reqwest::Url; // re-export of url::Url — the type the trait returns.
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Minimal adapter whose URLs point at a wiremock server. Only the four
    /// methods fetch()/resolve_latest_version() actually call are real; the
    /// rebuild/normalize surface is never reached by these tests.
    struct FakeAdapter {
        base: String,
        with_attestation: bool,
        with_latest: bool,
    }

    impl FakeAdapter {
        fn new(base: &str) -> Self {
            Self { base: base.to_string(), with_attestation: true, with_latest: true }
        }
        fn no_attestation(base: &str) -> Self {
            Self { base: base.to_string(), with_attestation: false, with_latest: true }
        }
        fn no_latest(base: &str) -> Self {
            Self { base: base.to_string(), with_attestation: true, with_latest: false }
        }
    }

    impl EcosystemAdapter for FakeAdapter {
        fn ecosystem(&self) -> Ecosystem {
            Ecosystem::Npm
        }
        fn artifact_url(&self, _pkg: &PackageRef) -> Url {
            Url::parse(&format!("{}/artifact.tgz", self.base)).unwrap()
        }
        fn attestation_url(&self, _pkg: &PackageRef) -> Option<Url> {
            if self.with_attestation {
                Some(Url::parse(&format!("{}/attestation", self.base)).unwrap())
            } else {
                None
            }
        }
        fn latest_version_url(&self, _name: &str) -> Option<Url> {
            if self.with_latest {
                Some(Url::parse(&format!("{}/meta", self.base)).unwrap())
            } else {
                None
            }
        }
        fn parse_latest_version(&self, body: &[u8]) -> Result<String, AdapterError> {
            Ok(String::from_utf8_lossy(body).trim().to_string())
        }

        // --- never reached by registry tests ---
        fn parse_attestation(&self, _bundle: &[u8]) -> Result<ProvenanceClaim, AdapterError> {
            unimplemented!("not exercised by registry fetch tests")
        }
        fn rebuild_image(&self) -> &'static str {
            unimplemented!()
        }
        fn rebuild_script(&self) -> &'static str {
            unimplemented!()
        }
        fn built_artifact_dir(&self) -> &'static str {
            unimplemented!()
        }
        fn strip_archive_prefix(&self, _pkg: &PackageRef) -> Option<String> {
            None
        }
        fn ignore_paths(&self) -> &'static [&'static str] {
            &[]
        }
    }

    fn pkg() -> PackageRef {
        PackageRef { ecosystem: Ecosystem::Npm, name: "left-pad".into(), version: "1.0.0".into() }
    }

    #[tokio::test]
    async fn fetch_writes_archive_and_captures_attestation() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/artifact.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"tarball-bytes".to_vec()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/attestation"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"att-bytes".to_vec()))
            .mount(&server)
            .await;

        let adapter = FakeAdapter::new(&server.uri());
        let result = fetch(&adapter, &pkg()).await.expect("fetch should succeed");

        let on_disk = tokio::fs::read(&result.archive_path).await.unwrap();
        assert_eq!(on_disk, b"tarball-bytes");
        assert_eq!(result.registry_sha256, sha256(b"tarball-bytes"));
        assert_eq!(result.attestation_bundle.as_deref(), Some(&b"att-bytes"[..]));
    }

    #[tokio::test]
    async fn fetch_maps_attestation_404_to_none() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/artifact.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"x".to_vec()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/attestation"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let result = fetch(&FakeAdapter::new(&server.uri()), &pkg()).await.unwrap();
        assert!(result.attestation_bundle.is_none(), "404 attestation should map to None");
    }

    #[tokio::test]
    async fn fetch_skips_attestation_when_adapter_has_none() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/artifact.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"x".to_vec()))
            .mount(&server)
            .await;
        // No /attestation mock registered — if fetch requested it, wiremock
        // would return 404 and we'd still get None, so to prove it's *not*
        // requested we rely on the adapter returning no attestation URL.
        let result = fetch(&FakeAdapter::no_attestation(&server.uri()), &pkg()).await.unwrap();
        assert!(result.attestation_bundle.is_none());
    }

    #[tokio::test]
    async fn fetch_errors_on_bad_artifact_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/artifact.tgz"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let result = fetch(&FakeAdapter::new(&server.uri()), &pkg()).await;
        assert!(matches!(result, Err(FetchError::BadStatus(s, _)) if s.as_u16() == 500));
    }

    #[tokio::test]
    async fn fetch_errors_on_bad_attestation_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/artifact.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"x".to_vec()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/attestation"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let result = fetch(&FakeAdapter::new(&server.uri()), &pkg()).await;
        assert!(matches!(result, Err(FetchError::BadStatus(s, _)) if s.as_u16() == 503));
    }

    #[tokio::test]
    async fn resolve_latest_version_parses_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/meta"))
            .respond_with(ResponseTemplate::new(200).set_body_string("2.3.4\n"))
            .mount(&server)
            .await;

        let v = resolve_latest_version(&FakeAdapter::new(&server.uri()), "left-pad")
            .await
            .unwrap();
        assert_eq!(v, "2.3.4");
    }

    #[tokio::test]
    async fn resolve_latest_version_unsupported_when_adapter_has_no_url() {
        let server = MockServer::start().await;
        let err = resolve_latest_version(&FakeAdapter::no_latest(&server.uri()), "left-pad")
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::UnsupportedResolution));
    }

    #[tokio::test]
    async fn resolve_latest_version_errors_on_bad_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/meta"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let err = resolve_latest_version(&FakeAdapter::new(&server.uri()), "left-pad")
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::BadStatus(s, _) if s.as_u16() == 500));
    }
}
