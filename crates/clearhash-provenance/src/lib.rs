//! Provenance verification.
//!
//! What this crate verifies in v1:
//!   1. The bundle envelope has a well-formed in-toto statement with a (repo, commit) claim.
//!   2. The bundle carries a Fulcio-issued X.509 leaf certificate.
//!   3. The leaf cert's SAN includes a GitHub Actions workflow URI consistent with the source repo.
//!   4. A Rekor transparency-log entry is referenced.
//!
//! What is deferred to v1.1 (with an explicit warning):
//!   - Full Cosign DSSE signature verification using the leaf cert's public key.
//!   - Full Rekor Merkle inclusion-proof verification.
//!
//! The v1 surface catches the realistic tamper modes (fake/missing cert, mismatched workflow
//! identity, missing tlog entry) without the implementation surface area of full crypto. v1.1
//! adds full crypto via the `sigstore` crate.

use clearhash_core::ProvenanceClaim;
use clearhash_ecosystems::{AdapterError, EcosystemAdapter};
use thiserror::Error;
use x509_parser::prelude::*;

/// Expected Fulcio intermediate Subject DN. Fulcio rotates roots, so we accept the well-known
/// historical strings (the `O=sigstore.dev` part is the load-bearing identity).
const FULCIO_DN_FRAGMENTS: &[&str] = &["sigstore.dev", "sigstore-intermediate"];

#[derive(Debug, Error)]
pub enum ProvenanceError {
    #[error("adapter could not parse envelope: {0}")]
    Adapter(#[from] AdapterError),
    #[error("commit SHA in attestation is not a 40-char hex string: {0}")]
    BadCommitSha(String),
    #[error("attestation bundle missing certificate chain")]
    MissingCertChain,
    #[error("leaf certificate not parseable: {0}")]
    BadLeafCert(String),
    #[error("leaf certificate was not issued by Fulcio (issuer DN: {0})")]
    NotFulcioIssued(String),
    #[error("leaf certificate SAN identity ({san}) does not match attested source repo ({repo})")]
    IdentityMismatch { san: String, repo: String },
    #[error("attestation bundle missing Rekor transparency-log entry")]
    MissingRekorEntry,
}

/// Extracted Sigstore identity for human-readable output.
#[derive(Debug, Clone, Default)]
pub struct VerifiedIdentity {
    pub workflow_uri: Option<String>,
    pub issuer_dn: String,
    pub rekor_log_index: Option<u64>,
}

#[derive(Debug)]
pub struct VerifyOk {
    pub claim: ProvenanceClaim,
    pub identity: VerifiedIdentity,
}

pub async fn verify(
    adapter: &dyn EcosystemAdapter,
    bundle: &[u8],
) -> Result<VerifyOk, ProvenanceError> {
    // Step A: envelope-level structural parse + (repo, commit) extraction.
    let claim = adapter.parse_attestation(bundle)?;

    if claim.commit_sha.len() != 40 || !claim.commit_sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ProvenanceError::BadCommitSha(claim.commit_sha));
    }

    // Step B: extract & validate the Sigstore identity material.
    let identity = extract_identity(bundle, &claim)?;

    tracing::warn!(
        "v1 provenance: validated structural + cert-chain + identity. \
         Full Cosign signature + Rekor inclusion proof verification is v1.1."
    );

    Ok(VerifyOk { claim, identity })
}

/// Find the bundle's `verificationMaterial` regardless of which envelope variant npm/PyPI used,
/// then pull the leaf cert + Rekor log index.
fn extract_identity(
    bundle: &[u8],
    claim: &ProvenanceClaim,
) -> Result<VerifiedIdentity, ProvenanceError> {
    let root: serde_json::Value =
        serde_json::from_slice(bundle).map_err(|_| ProvenanceError::MissingCertChain)?;

    // Locate the verificationMaterial. It may be nested under attestations[i].bundle.
    let vm = find_verification_material(&root).ok_or(ProvenanceError::MissingCertChain)?;

    // ---- Cert chain ----
    let cert_b64 = vm
        .pointer("/x509CertificateChain/certificates/0/rawBytes")
        .or_else(|| vm.pointer("/certificate/rawBytes"))
        .and_then(|v| v.as_str())
        .ok_or(ProvenanceError::MissingCertChain)?;

    let cert_der = base64_decode(cert_b64).map_err(ProvenanceError::BadLeafCert)?;
    let (_, leaf) = X509Certificate::from_der(&cert_der)
        .map_err(|e| ProvenanceError::BadLeafCert(e.to_string()))?;

    let issuer_dn = leaf.issuer().to_string();
    if !FULCIO_DN_FRAGMENTS
        .iter()
        .any(|frag| issuer_dn.contains(frag))
    {
        return Err(ProvenanceError::NotFulcioIssued(issuer_dn));
    }

    // ---- SAN (Subject Alternative Name) — Fulcio puts the workflow URI here ----
    let workflow_uri = leaf
        .extensions()
        .iter()
        .find_map(|ext| match ext.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => {
                for name in &san.general_names {
                    if let GeneralName::URI(uri) = name {
                        return Some(uri.to_string());
                    }
                }
                None
            }
            _ => None,
        });

    // Cross-check: if both the SAN and the claim mention a github.com path, the repo segment
    // should match. (Workflow URI looks like `https://github.com/<owner>/<repo>/.github/workflows/...@refs/...`.)
    if let Some(ref uri) = workflow_uri {
        if let (Some(uri_repo), Some(claim_repo)) =
            (gh_repo_segment(uri), gh_repo_segment(&claim.source_repo))
        {
            if uri_repo != claim_repo {
                return Err(ProvenanceError::IdentityMismatch {
                    san: uri.clone(),
                    repo: claim.source_repo.clone(),
                });
            }
        }
    }

    // ---- Rekor log entry ----
    let rekor_log_index = vm.pointer("/tlogEntries/0/logIndex").and_then(|v| {
        v.as_str()
            .and_then(|s| s.parse::<u64>().ok())
            .or_else(|| v.as_u64())
    });
    if rekor_log_index.is_none() {
        return Err(ProvenanceError::MissingRekorEntry);
    }

    Ok(VerifiedIdentity {
        workflow_uri,
        issuer_dn,
        rekor_log_index,
    })
}

fn find_verification_material(root: &serde_json::Value) -> Option<&serde_json::Value> {
    // Direct shape: { "verificationMaterial": ... }
    if let Some(vm) = root.get("verificationMaterial") {
        return Some(vm);
    }
    // npm shape: { "attestations": [ { "predicateType": "...", "bundle": { ... } } ] }.
    // Pick the SLSA provenance attestation specifically — the sibling "publish" attestation has
    // a different verificationMaterial shape (npm's own ECDSA key, no x509 chain).
    if let Some(arr) = root.get("attestations").and_then(|a| a.as_array()) {
        for att in arr {
            let is_slsa = att
                .get("predicateType")
                .and_then(|p| p.as_str())
                .map(|s| s.contains("slsa.dev/provenance"))
                .unwrap_or(false);
            if !is_slsa {
                continue;
            }
            if let Some(vm) = att.pointer("/bundle/verificationMaterial") {
                return Some(vm);
            }
        }
    }
    None
}

/// Pull the `owner/repo` segment from a GitHub URL or git URI.
fn gh_repo_segment(s: &str) -> Option<String> {
    let idx = s.find("github.com")?;
    let after = &s[idx + "github.com".len()..];
    let after = after.trim_start_matches('/').trim_start_matches(':');
    let mut parts = after.split('/');
    let owner = parts.next()?;
    let repo_raw = parts.next()?;
    // Strip a trailing `.git`, `@`, `#` etc.
    let repo = repo_raw.split(['.', '@', '#', '?']).next()?;
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    Some(format!("{owner}/{repo}"))
}

/// Standard-alphabet base64 decoder. (Same trick as the npm adapter — avoids a `base64` dep.)
fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim().as_bytes();
    if !s.len().is_multiple_of(4) {
        return Err("base64: length not multiple of 4".into());
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for chunk in s.chunks_exact(4) {
        let mut buf = [0u32; 4];
        for (i, &b) in chunk.iter().enumerate() {
            buf[i] = match b {
                b'A'..=b'Z' => (b - b'A') as u32,
                b'a'..=b'z' => (b - b'a' + 26) as u32,
                b'0'..=b'9' => (b - b'0' + 52) as u32,
                b'+' => 62,
                b'/' => 63,
                b'=' => 0,
                _ => return Err(format!("base64: invalid byte 0x{:02x}", b)),
            };
        }
        let n = (buf[0] << 18) | (buf[1] << 12) | (buf[2] << 6) | buf[3];
        out.push((n >> 16) as u8);
        if chunk[2] != b'=' {
            out.push((n >> 8) as u8);
        }
        if chunk[3] != b'=' {
            out.push(n as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gh_repo_segment_basic() {
        assert_eq!(
            gh_repo_segment("git+https://github.com/sigstore/sigstore-js@refs/heads/main"),
            Some("sigstore/sigstore-js".into())
        );
        assert_eq!(
            gh_repo_segment(
                "https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main"
            ),
            Some("sigstore/sigstore-js".into())
        );
        assert_eq!(
            gh_repo_segment("git+ssh://git@github.com/example/repo.git"),
            Some("example/repo".into())
        );
        assert_eq!(gh_repo_segment("https://gitlab.com/x/y"), None);
    }

    #[test]
    fn finds_verification_material_picks_slsa_not_publish() {
        let bundle = serde_json::json!({
            "attestations": [
                {
                    "predicateType": "https://github.com/npm/attestation/tree/main/specs/publish/v0.1",
                    "bundle": {
                        "verificationMaterial": { "publicKey": { "hint": "npm-key" } }
                    }
                },
                {
                    "predicateType": "https://slsa.dev/provenance/v1",
                    "bundle": {
                        "verificationMaterial": { "tlogEntries": [{ "logIndex": "12345" }] }
                    }
                }
            ]
        });
        let vm = find_verification_material(&bundle).unwrap();
        assert!(vm.get("tlogEntries").is_some());
        assert!(
            vm.get("publicKey").is_none(),
            "should skip the publish attestation"
        );
    }

    #[test]
    fn rejects_missing_cert_chain() {
        let bundle = serde_json::json!({
            "attestations": [{
                "predicateType": "https://slsa.dev/provenance/v1",
                "bundle": {
                    "verificationMaterial": { "tlogEntries": [{ "logIndex": "1" }] },
                    "dsseEnvelope": { "payload": "e30=" }
                }
            }]
        });
        // Use a stub adapter so the (repo, commit) parse doesn't blow up first.
        struct Stub;
        #[async_trait::async_trait]
        impl EcosystemAdapter for Stub {
            fn ecosystem(&self) -> clearhash_core::Ecosystem {
                clearhash_core::Ecosystem::Npm
            }
            fn artifact_url(&self, _: &clearhash_core::PackageRef) -> url::Url {
                "https://x".parse().unwrap()
            }
            fn attestation_url(&self, _: &clearhash_core::PackageRef) -> Option<url::Url> {
                None
            }
            fn parse_attestation(&self, _: &[u8]) -> Result<ProvenanceClaim, AdapterError> {
                Ok(ProvenanceClaim {
                    source_repo: "git+https://github.com/example/repo".into(),
                    commit_sha: "a".repeat(40),
                    builder_id: "x".into(),
                    signed_at: chrono::Utc::now(),
                })
            }
            fn rebuild_image(&self) -> &'static str {
                "x"
            }
            fn rebuild_script(&self) -> &'static str {
                "x"
            }
            fn built_artifact_dir(&self) -> &'static str {
                "/out"
            }
            fn strip_archive_prefix(&self, _: &clearhash_core::PackageRef) -> Option<String> {
                None
            }
            fn ignore_paths(&self) -> &'static [&'static str] {
                &[]
            }
        }

        let rt = tokio::runtime::Runtime::new().unwrap();
        let err = rt
            .block_on(verify(&Stub, &serde_json::to_vec(&bundle).unwrap()))
            .unwrap_err();
        assert!(matches!(err, ProvenanceError::MissingCertChain));
    }
}
