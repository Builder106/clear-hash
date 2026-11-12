//! Fetch archives without executing package-manager or package code on the host.
use std::path::{Path, PathBuf};
use std::time::Duration;

use clearhash_ecosystems::{
    offline::{Check, Dependency, Integrity},
    EcosystemAdapter,
};
use futures_util::StreamExt;
use tokio::io::AsyncWriteExt;

use crate::SandboxError;

// Bound each response so a registry cannot exhaust host memory or disk with one archive.
const MAX_ARCHIVE_BYTES: usize = 256 * 1024 * 1024;

pub(super) async fn prepare(
    adapter: &dyn EcosystemAdapter,
    source: &Path,
    workdir: &Path,
) -> Result<Option<PathBuf>, SandboxError> {
    let Some(dependencies) = adapter.offline_dependencies(source)? else {
        return Ok(None);
    };
    fetch_all(&dependencies, &workdir.join("dependencies"))
        .await
        .map(Some)
}

/// Fetch the adapter's package-manager release into `workdir/tools`, if it needs one.
pub(super) async fn prepare_tools(
    adapter: &dyn EcosystemAdapter,
    source: &Path,
    workdir: &Path,
) -> Result<Option<PathBuf>, SandboxError> {
    let tools = adapter.build_tools(source)?;
    if tools.is_empty() {
        return Ok(None);
    }
    fetch_all(&tools, &workdir.join("tools")).await.map(Some)
}

async fn fetch_all(
    dependencies: &[Dependency],
    destination: &Path,
) -> Result<PathBuf, SandboxError> {
    // Always start fresh. A retained workdir must never supply unverified stale files.
    std::fs::create_dir(destination)?;
    let client = reqwest::Client::builder()
        .https_only(true)
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|e| SandboxError::Prefetch(e.to_string()))?;
    for dependency in dependencies {
        fetch(&client, dependency, destination).await?;
    }
    Ok(destination.to_path_buf())
}

async fn download(client: &reqwest::Client, url: &reqwest::Url) -> Result<Vec<u8>, SandboxError> {
    let response = client
        .get(url.clone())
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| SandboxError::Prefetch(e.to_string()))?;
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| SandboxError::Prefetch(e.to_string()))?;
        if bytes.len().saturating_add(chunk.len()) > MAX_ARCHIVE_BYTES {
            return Err(SandboxError::Prefetch(
                "archive exceeds 256 MiB limit".into(),
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

/// The integrity the npm registry publishes for one version (`dist.integrity`).
async fn registry_integrity(
    client: &reqwest::Client,
    url: &reqwest::Url,
) -> Result<Integrity, SandboxError> {
    let body = download(client, url).await?;
    let document: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| SandboxError::Prefetch(format!("registry metadata {url}: {e}")))?;
    let sri = document["dist"]["integrity"].as_str().ok_or_else(|| {
        SandboxError::Prefetch(format!("registry metadata {url}: no dist.integrity"))
    })?;
    Integrity::parse(sri).map_err(|e| SandboxError::Prefetch(format!("{url}: {e}")))
}

async fn fetch(
    client: &reqwest::Client,
    dependency: &Dependency,
    destination: &Path,
) -> Result<(), SandboxError> {
    let registry;
    let integrity = match &dependency.check {
        Check::Pinned(integrity) => integrity,
        Check::Registry(url) => {
            registry = registry_integrity(client, url).await?;
            &registry
        }
    };
    let bytes = download(client, &dependency.url).await?;
    if !integrity.matches(&bytes) {
        return Err(SandboxError::Prefetch(format!(
            "integrity mismatch for {}",
            dependency.filename
        )));
    }
    // Files become visible only after verification. create_new also rejects collisions/symlinks.
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination.join(&dependency.filename))
        .await?;
    file.write_all(&bytes).await?;
    file.flush().await?;
    tracing::debug!(archive = %dependency.filename, "dependency integrity verified");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clearhash_ecosystems::offline::Integrity;
    use wiremock::{matchers::path, Mock, MockServer, ResponseTemplate};

    fn dependency(server: &MockServer) -> Dependency {
        Dependency {
            url: format!("{}/dep.tgz", server.uri()).parse().unwrap(),
            filename: "dep.tgz".into(),
            // SHA-256 of "abc".
            check: Check::Pinned(
                Integrity::parse("sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=").unwrap(),
            ),
        }
    }

    #[tokio::test]
    async fn registry_checked_archives_must_match_the_published_integrity() {
        for (published, succeeds) in [
            ("sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=", true),
            ("sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa1=", false),
        ] {
            let server = MockServer::start().await;
            Mock::given(path("/dep/1.0.0"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(serde_json::json!({"dist": {"integrity": published}})),
                )
                .mount(&server)
                .await;
            Mock::given(path("/dep.tgz"))
                .respond_with(ResponseTemplate::new(200).set_body_string("abc"))
                .mount(&server)
                .await;
            let mut dependency = dependency(&server);
            dependency.check =
                Check::Registry(format!("{}/dep/1.0.0", server.uri()).parse().unwrap());
            let destination = tempfile::tempdir().unwrap();
            let result = fetch(&reqwest::Client::new(), &dependency, destination.path()).await;
            assert_eq!(result.is_ok(), succeeds, "{result:?}");
            assert_eq!(destination.path().join("dep.tgz").exists(), succeeds);
        }
    }

    #[tokio::test]
    async fn only_hash_verified_successful_responses_enter_cache() {
        for (status, body, succeeds) in [
            (200, "abc", true),
            (200, "tampered", false),
            (404, "abc", false),
        ] {
            let server = MockServer::start().await;
            Mock::given(path("/dep.tgz"))
                .respond_with(ResponseTemplate::new(status).set_body_string(body))
                .expect(1)
                .mount(&server)
                .await;
            let destination = tempfile::tempdir().unwrap();
            let result = fetch(
                &reqwest::Client::new(),
                &dependency(&server),
                destination.path(),
            )
            .await;
            assert_eq!(result.is_ok(), succeeds, "{result:?}");
            assert_eq!(destination.path().join("dep.tgz").exists(), succeeds);
            if succeeds {
                assert_eq!(
                    std::fs::read(destination.path().join("dep.tgz")).unwrap(),
                    b"abc"
                );
            }
        }
    }
}
