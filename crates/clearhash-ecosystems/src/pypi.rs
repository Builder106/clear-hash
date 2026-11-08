//! PyPI ecosystem adapter.
//!
//! Registry root: https://pypi.org
//! Release metadata: https://pypi.org/pypi/{name}/{version}/json
//! Attestation API: PEP 740 / PEP 691 integrity endpoint at
//! `https://pypi.org/integrity/{name}/{version}/{filename}/provenance`

use async_trait::async_trait;
use clearhash_core::{Ecosystem, PackageRef, ProvenanceClaim};
use serde::Deserialize;
use url::Url;
use x509_parser::prelude::*;

use crate::{AdapterError, EcosystemAdapter, ReleaseUrls};

pub struct PypiAdapter;

#[async_trait]
impl EcosystemAdapter for PypiAdapter {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Pypi
    }

    fn artifact_url(&self, pkg: &PackageRef) -> Url {
        // Fallback static URL pointing to the release metadata endpoint.
        // The real sdist URL is resolved dynamically via `release_metadata_url`.
        self.release_metadata_url(pkg)
            .unwrap_or_else(|| Url::parse("https://pypi.org/").unwrap())
    }

    fn attestation_url(&self, _pkg: &PackageRef) -> Option<Url> {
        // Resolved dynamically via `release_metadata_url` / `parse_release_urls`.
        None
    }

    fn release_metadata_url(&self, pkg: &PackageRef) -> Option<Url> {
        let raw = format!("https://pypi.org/pypi/{}/{}/json", pkg.name, pkg.version);
        Url::parse(&raw).ok()
    }

    fn parse_release_urls(
        &self,
        body: &[u8],
        pkg: &PackageRef,
    ) -> Result<ReleaseUrls, AdapterError> {
        let meta: PypiReleaseMetadata = serde_json::from_slice(body).map_err(|e| {
            AdapterError::MalformedAttestation(format!("pypi release metadata: {e}"))
        })?;

        // Find the sdist entry, preferring `.tar.gz` / `.tgz` over `.zip`.
        let sdist = meta
            .urls
            .iter()
            .find(|u| {
                u.packagetype == "sdist"
                    && (u.filename.ends_with(".tar.gz") || u.filename.ends_with(".tgz"))
            })
            .or_else(|| meta.urls.iter().find(|u| u.packagetype == "sdist"))
            .ok_or_else(|| {
                AdapterError::MalformedAttestation(format!(
                    "no sdist found for package {}@{}",
                    pkg.name, pkg.version
                ))
            })?;

        let artifact_url = Url::parse(&sdist.url).map_err(|e| {
            AdapterError::MalformedAttestation(format!("invalid artifact url {}: {e}", sdist.url))
        })?;

        let attestation_url = if let Some(ref prov) = sdist.provenance {
            Url::parse(prov).ok()
        } else {
            let raw = format!(
                "https://pypi.org/integrity/{}/{}/{}/provenance",
                pkg.name, pkg.version, sdist.filename
            );
            Url::parse(&raw).ok()
        };

        Ok(ReleaseUrls {
            artifact_url,
            attestation_url,
        })
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

    fn parse_attestation(&self, bundle: &[u8]) -> Result<ProvenanceClaim, AdapterError> {
        let env: Pep740Response = serde_json::from_slice(bundle)
            .map_err(|e| AdapterError::MalformedAttestation(format!("pep740 envelope: {e}")))?;

        let bundle_item = env.attestation_bundles.into_iter().next().ok_or_else(|| {
            AdapterError::MalformedAttestation("empty attestation_bundles in envelope".into())
        })?;

        let publisher = bundle_item.publisher;

        // Check if any attestation has an in-toto statement with SLSA provenance materials.
        for att in &bundle_item.attestations {
            if let Some(ref env) = att.envelope {
                if let Some(ref stmt_b64) = env.statement {
                    if let Ok(stmt_bytes) = base64_decode_standard(stmt_b64) {
                        if let Ok(stmt) = serde_json::from_slice::<InTotoStatement>(&stmt_bytes) {
                            if let Ok(mut claim) = extract_claim_from_statement(stmt) {
                                if let Some(time) = extract_signed_at(&bundle_item.attestations) {
                                    claim.signed_at = time;
                                }
                                return Ok(claim);
                            }
                        }
                    }
                }
            }
        }

        // If no SLSA statement is present (e.g. PyPI Publish attestation), extract claims from
        // the Sigstore Fulcio leaf certificate and publisher metadata.
        let mut source_repo = None;
        let mut commit_sha = None;
        let mut builder_id = String::new();

        if let Some(ref pub_info) = publisher {
            if let Some(ref repo) = pub_info.repository {
                if repo.starts_with("http://") || repo.starts_with("https://") {
                    source_repo = Some(repo.clone());
                } else {
                    let kind = pub_info.kind.as_deref().unwrap_or("GitHub");
                    if kind.eq_ignore_ascii_case("github") {
                        source_repo = Some(format!("https://github.com/{repo}"));
                    } else if kind.eq_ignore_ascii_case("gitlab") {
                        source_repo = Some(format!("https://gitlab.com/{repo}"));
                    } else {
                        source_repo = Some(repo.clone());
                    }
                }
            }

            if let Some(ref wf) = pub_info.workflow {
                let kind = pub_info.kind.as_deref().unwrap_or("GitHub");
                builder_id = format!("{kind}:{wf}");
            }

            if let Some(ref claims) = pub_info.claims {
                if let Some(sha) = claims
                    .get("sha")
                    .or_else(|| claims.get("commit"))
                    .and_then(|v| v.as_str())
                {
                    if is_commit_sha(sha) {
                        commit_sha = Some(sha.to_ascii_lowercase());
                    }
                }
            }
        }

        for att in &bundle_item.attestations {
            if let Some(ref vm) = att.verification_material {
                if let Some(ref cert_b64) = vm.certificate {
                    let cert_der = base64_decode_standard(cert_b64)
                        .map_err(AdapterError::MalformedAttestation)?;
                    let (_, cert) = X509Certificate::from_der(&cert_der).map_err(|e| {
                        AdapterError::MalformedAttestation(format!("parsing certificate: {e}"))
                    })?;

                    for ext in cert.extensions() {
                        let oid_str = ext.oid.to_string();
                        // 1.3.6.1.4.1.57264.1.3: Source Repository Commit SHA
                        // 1.3.6.1.4.1.57264.1.10: Source Repository SHA (v2)
                        // 1.3.6.1.4.1.57264.1.13: Source Repository Digest
                        if (oid_str == "1.3.6.1.4.1.57264.1.3"
                            || oid_str == "1.3.6.1.4.1.57264.1.10"
                            || oid_str == "1.3.6.1.4.1.57264.1.13")
                            && commit_sha.is_none()
                        {
                            commit_sha = extract_sha_from_bytes(ext.value);
                        }

                        // 1.3.6.1.4.1.57264.1.12: Source Repository URI
                        // 1.3.6.1.4.1.57264.1.5: Source Repository Owner/Repo
                        if oid_str == "1.3.6.1.4.1.57264.1.12" {
                            if source_repo.is_none() {
                                source_repo = extract_url_from_bytes(ext.value);
                            }
                        } else if oid_str == "1.3.6.1.4.1.57264.1.5" && source_repo.is_none() {
                            if let Ok(owner_repo) = std::str::from_utf8(ext.value) {
                                let clean =
                                    owner_repo.trim().trim_matches(|c: char| c.is_control());
                                if !clean.is_empty() {
                                    source_repo = Some(format!("https://github.com/{clean}"));
                                }
                            }
                        }
                    }
                }
            }
        }

        let source_repo = source_repo.ok_or_else(|| {
            AdapterError::MalformedAttestation("source repository missing from attestation".into())
        })?;

        let commit_sha = commit_sha.ok_or_else(|| {
            AdapterError::MalformedAttestation("commit SHA missing from attestation".into())
        })?;

        let signed_at =
            extract_signed_at(&bundle_item.attestations).unwrap_or_else(chrono::Utc::now);

        if builder_id.is_empty() {
            builder_id = "pypi-trusted-publisher".to_string();
        }

        Ok(ProvenanceClaim {
            source_repo,
            commit_sha,
            builder_id,
            signed_at,
        })
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
        &["PKG-INFO", "*.egg-info/*", "*.dist-info/*"]
    }
}

// --- Data types for PEP 740 envelopes ----------------------------------------------------

#[derive(Deserialize)]
struct PypiReleaseMetadata {
    urls: Vec<PypiArtifactUrl>,
}

#[derive(Deserialize)]
struct PypiArtifactUrl {
    filename: String,
    packagetype: String,
    url: String,
    provenance: Option<String>,
}

#[derive(Deserialize)]
struct Pep740Response {
    #[serde(default)]
    attestation_bundles: Vec<Pep740Bundle>,
}

#[derive(Deserialize)]
struct Pep740Bundle {
    publisher: Option<Pep740Publisher>,
    #[serde(default)]
    attestations: Vec<Pep740Attestation>,
}

#[derive(Deserialize)]
struct Pep740Publisher {
    kind: Option<String>,
    repository: Option<String>,
    workflow: Option<String>,
    claims: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct Pep740Attestation {
    envelope: Option<Pep740Envelope>,
    verification_material: Option<Pep740VerificationMaterial>,
}

#[derive(Deserialize)]
struct Pep740Envelope {
    statement: Option<String>,
}

#[derive(Deserialize)]
struct Pep740VerificationMaterial {
    certificate: Option<String>,
    #[serde(default)]
    transparency_entries: Vec<Pep740TransparencyEntry>,
}

#[derive(Deserialize)]
struct Pep740TransparencyEntry {
    #[serde(rename = "integratedTime")]
    integrated_time: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct InTotoStatement {
    predicate: serde_json::Value,
}

fn extract_signed_at(attestations: &[Pep740Attestation]) -> Option<chrono::DateTime<chrono::Utc>> {
    for att in attestations {
        if let Some(ref vm) = att.verification_material {
            for entry in &vm.transparency_entries {
                if let Some(ref t) = entry.integrated_time {
                    let secs = t
                        .as_i64()
                        .or_else(|| t.as_str().and_then(|s| s.parse::<i64>().ok()));
                    if let Some(secs) = secs {
                        return chrono::DateTime::from_timestamp(secs, 0);
                    }
                }
            }
        }
    }
    None
}

fn extract_claim_from_statement(s: InTotoStatement) -> Result<ProvenanceClaim, AdapterError> {
    let pred = s.predicate;

    // SLSA v1
    if let Some(deps) = pred
        .get("buildDefinition")
        .and_then(|b| b.get("resolvedDependencies"))
        .and_then(|d| d.as_array())
    {
        for d in deps {
            let uri = d.get("uri").and_then(|u| u.as_str()).unwrap_or("");
            let commit = d
                .get("digest")
                .and_then(|dg| dg.get("gitCommit").or_else(|| dg.get("sha1")))
                .and_then(|c| c.as_str());
            if let Some(commit) = commit {
                let builder = pred
                    .get("runDetails")
                    .and_then(|r| r.get("builder"))
                    .and_then(|b| b.get("id"))
                    .and_then(|i| i.as_str())
                    .unwrap_or("")
                    .to_string();
                return Ok(ProvenanceClaim {
                    source_repo: uri.to_string(),
                    commit_sha: commit.to_string(),
                    builder_id: builder,
                    signed_at: chrono::Utc::now(),
                });
            }
        }
    }

    // SLSA v0.2
    if let Some(mats) = pred.get("materials").and_then(|m| m.as_array()) {
        if let Some(first) = mats.first() {
            let uri = first.get("uri").and_then(|u| u.as_str()).unwrap_or("");
            let commit = first
                .get("digest")
                .and_then(|d| d.get("sha1").or_else(|| d.get("gitCommit")))
                .and_then(|c| c.as_str());
            if let Some(commit) = commit {
                let builder = pred
                    .get("builder")
                    .and_then(|b| b.get("id"))
                    .and_then(|i| i.as_str())
                    .unwrap_or("")
                    .to_string();
                return Ok(ProvenanceClaim {
                    source_repo: uri.to_string(),
                    commit_sha: commit.to_string(),
                    builder_id: builder,
                    signed_at: chrono::Utc::now(),
                });
            }
        }
    }

    Err(AdapterError::MalformedAttestation(
        "no (repo, commit) in statement materials or resolvedDependencies".into(),
    ))
}

fn is_commit_sha(s: &str) -> bool {
    s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn extract_sha_from_bytes(bytes: &[u8]) -> Option<String> {
    for window in bytes.windows(40) {
        if window.iter().all(|b| b.is_ascii_hexdigit()) {
            if let Ok(s) = std::str::from_utf8(window) {
                return Some(s.to_ascii_lowercase());
            }
        }
    }
    None
}

fn extract_url_from_bytes(bytes: &[u8]) -> Option<String> {
    if let Ok(s) = std::str::from_utf8(bytes) {
        if let Some(idx) = s.find("http://").or_else(|| s.find("https://")) {
            let part = &s[idx..];
            let end = part
                .find(|c: char| c.is_whitespace() || c == '\0' || c == '\r' || c == '\n')
                .unwrap_or(part.len());
            return Some(part[..end].to_string());
        }
    }
    None
}

fn base64_decode_standard(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| format!("base64 decode error: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(name: &str, ver: &str) -> PackageRef {
        PackageRef {
            ecosystem: Ecosystem::Pypi,
            name: name.into(),
            version: ver.into(),
        }
    }

    #[test]
    fn parse_release_urls_picks_sdist_and_integrity_endpoint() {
        let json_body = br#"{
            "info": { "name": "sampleproject", "version": "4.0.0" },
            "urls": [
                {
                    "filename": "sampleproject-4.0.0-py3-none-any.whl",
                    "packagetype": "bdist_wheel",
                    "url": "https://files.pythonhosted.org/packages/whl/sampleproject-4.0.0.whl",
                    "provenance": null
                },
                {
                    "filename": "sampleproject-4.0.0.tar.gz",
                    "packagetype": "sdist",
                    "url": "https://files.pythonhosted.org/packages/sdist/sampleproject-4.0.0.tar.gz",
                    "provenance": null
                }
            ]
        }"#;

        let p = pkg("sampleproject", "4.0.0");
        let urls = PypiAdapter.parse_release_urls(json_body, &p).unwrap();
        assert_eq!(
            urls.artifact_url.as_str(),
            "https://files.pythonhosted.org/packages/sdist/sampleproject-4.0.0.tar.gz"
        );
        assert_eq!(
            urls.attestation_url.unwrap().as_str(),
            "https://pypi.org/integrity/sampleproject/4.0.0/sampleproject-4.0.0.tar.gz/provenance"
        );
    }

    #[test]
    fn parse_release_urls_respects_explicit_provenance() {
        let json_body = br#"{
            "urls": [
                {
                    "filename": "demo-1.0.0.tar.gz",
                    "packagetype": "sdist",
                    "url": "https://files.pythonhosted.org/packages/demo-1.0.0.tar.gz",
                    "provenance": "https://custom.index/integrity/demo.provenance"
                }
            ]
        }"#;

        let p = pkg("demo", "1.0.0");
        let urls = PypiAdapter.parse_release_urls(json_body, &p).unwrap();
        assert_eq!(
            urls.attestation_url.unwrap().as_str(),
            "https://custom.index/integrity/demo.provenance"
        );
    }

    #[test]
    fn parse_release_urls_errors_when_no_sdist() {
        let json_body = br#"{
            "urls": [
                {
                    "filename": "demo-1.0.0.whl",
                    "packagetype": "bdist_wheel",
                    "url": "https://files.pythonhosted.org/packages/demo-1.0.0.whl",
                    "provenance": null
                }
            ]
        }"#;

        let p = pkg("demo", "1.0.0");
        let err = PypiAdapter.parse_release_urls(json_body, &p).unwrap_err();
        assert!(matches!(err, AdapterError::MalformedAttestation(_)));
    }

    #[test]
    fn parse_attestation_from_pep740_fixture() {
        let fixture = include_bytes!(
            "../../clearhash-provenance/tests/fixtures/pypi_sampleproject_4.0.0_attestation.json"
        );
        let claim = PypiAdapter.parse_attestation(fixture).unwrap();
        assert_eq!(claim.source_repo, "https://github.com/pypa/sampleproject");
        assert_eq!(claim.commit_sha, "621e4974ca25ce531773def586ba3ed8e736b3fc");
        assert_eq!(claim.builder_id, "GitHub:release.yml");
        assert_eq!(claim.signed_at.timestamp(), 1730932627);
    }
}
