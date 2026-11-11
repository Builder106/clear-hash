//! Fetch archives without executing package-manager or package code on the host.
use std::path::{Path, PathBuf};
use std::time::Duration;

use clearhash_ecosystems::{offline::Dependency, EcosystemAdapter};
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
    let destination = workdir.join("dependencies");
    // Always start fresh. A retained workdir must never supply unverified stale files.
    std::fs::create_dir(&destination)?;
    let client = reqwest::Client::builder()
        .https_only(true)
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|e| SandboxError::Prefetch(e.to_string()))?;
    for dependency in dependencies {
        fetch(&client, &dependency, &destination).await?;
    }
    Ok(Some(destination))
}

async fn fetch(
    client: &reqwest::Client,
    dependency: &Dependency,
    destination: &Path,
) -> Result<(), SandboxError> {
    let response = client
        .get(dependency.url.clone())
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
    if !dependency.integrity.matches(&bytes) {
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
            integrity: Integrity::parse("sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=")
                .unwrap(),
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
