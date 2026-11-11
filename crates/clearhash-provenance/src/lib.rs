//! Provenance verification.
//!
//! What this crate verifies in v1.1:
//!   1. The bundle envelope has a well-formed in-toto statement with a (repo, commit) claim.
//!   2. The bundle carries a Fulcio-issued X.509 leaf certificate.
//!   3. The leaf cert's SAN includes a GitHub Actions workflow URI consistent with the source repo.
//!   4. The signed entry is included in Rekor against an authenticated checkpoint.
//!   5. Full Cosign DSSE signature verification over the in-toto statement against the leaf cert's public key.
//!   6. SCT (Signed Certificate Timestamp) verification confirming Fulcio actually issued the certificate.

mod rekor;
mod sct;

use clearhash_core::ProvenanceClaim;
use clearhash_ecosystems::{AdapterError, EcosystemAdapter};
use sigstore::crypto::{CosignVerificationKey, Signature};
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
    #[error("Rekor inclusion verification failed: {0}")]
    RekorVerification(String),
    #[error("SCT verification failed: {0}")]
    SctVerification(String),
    #[error("attestation bundle missing DSSE envelope")]
    MissingDsseEnvelope,
    #[error("DSSE envelope has no signatures")]
    MissingDsseSignature,
    #[error("DSSE payload base64 decode failed: {0}")]
    BadDssePayload(String),
    #[error("DSSE signature base64 decode failed: {0}")]
    BadDsseSignature(String),
    #[error("leaf certificate public key invalid: {0}")]
    BadPublicKey(String),
    #[error("DSSE signature verification failed")]
    SignatureVerificationFailed,
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

    let root: serde_json::Value =
        serde_json::from_slice(bundle).map_err(|_| ProvenanceError::MissingCertChain)?;

    // Step B: extract & validate the Sigstore identity material.
    let (identity, cert_der) = extract_identity(&root, &claim)?;

    // Step C: full Cosign DSSE signature verification over the in-toto statement.
    let signature = verify_dsse(&root, &cert_der)?;

    // Step D: verify Signed Certificate Timestamp (SCT) to confirm Fulcio issued the certificate.
    sct::verify(&root, &cert_der)?;

    // Step E: authenticate the checkpoint, walk the Merkle proof, and bind the
    // committed entry to the payload, certificate, and signature just verified.
    rekor::verify(&root, &cert_der, &signature)?;

    tracing::debug!(
        "provenance: validated Cosign DSSE signature, certificate identity, Fulcio SCT, and Rekor inclusion"
    );

    Ok(VerifyOk { claim, identity })
}

/// Compute canonical DSSE Pre-Authentication Encoding (PAE):
/// `"DSSEv1" + " " + len(type) + " " + type + " " + len(body) + " " + body`
pub fn compute_dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let header = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    );
    let mut pae = header.into_bytes();
    pae.extend_from_slice(payload);
    pae
}

/// Convert a 64-byte raw IEEE P1363 ECDSA signature (r || s) into an ASN.1 DER SEQUENCE.
fn p1363_to_der(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.len() != 64 {
        return None;
    }
    let (r, s) = raw.split_at(32);
    fn encode_int(bytes: &[u8]) -> Vec<u8> {
        let mut b = bytes;
        while b.len() > 1 && b[0] == 0 {
            b = &b[1..];
        }
        let mut out = Vec::with_capacity(b.len() + 3);
        out.push(0x02);
        if b[0] >= 0x80 {
            out.push((b.len() + 1) as u8);
            out.push(0x00);
        } else {
            out.push(b.len() as u8);
        }
        out.extend_from_slice(b);
        out
    }
    let r_der = encode_int(r);
    let s_der = encode_int(s);
    let mut seq = Vec::with_capacity(2 + r_der.len() + s_der.len());
    seq.push(0x30);
    seq.push((r_der.len() + s_der.len()) as u8);
    seq.extend_from_slice(&r_der);
    seq.extend_from_slice(&s_der);
    Some(seq)
}

/// Verify the DSSE signature inside the bundle over the in-toto statement against the leaf cert's public key.
fn verify_dsse(root: &serde_json::Value, cert_der: &[u8]) -> Result<Vec<u8>, ProvenanceError> {
    let dsse = find_dsse_envelope(root).ok_or(ProvenanceError::MissingDsseEnvelope)?;

    let payload_type = dsse
        .get("payloadType")
        .and_then(|v| v.as_str())
        .unwrap_or("application/vnd.in-toto+json");

    let payload_b64 = dsse
        .get("payload")
        .or_else(|| dsse.get("statement"))
        .and_then(|v| v.as_str())
        .ok_or(ProvenanceError::MissingDsseEnvelope)?;

    let payload_bytes = base64_decode(payload_b64).map_err(ProvenanceError::BadDssePayload)?;

    let single_sig;
    let signatures: &[serde_json::Value] =
        if let Some(arr) = dsse.get("signatures").and_then(|v| v.as_array()) {
            arr.as_slice()
        } else if let Some(sig) = dsse.get("signature") {
            single_sig = [serde_json::json!({ "sig": sig })];
            &single_sig
        } else {
            return Err(ProvenanceError::MissingDsseSignature);
        };

    if signatures.is_empty() {
        return Err(ProvenanceError::MissingDsseSignature);
    }

    let (_, leaf) = X509Certificate::from_der(cert_der)
        .map_err(|e| ProvenanceError::BadLeafCert(e.to_string()))?;

    let spki_der = leaf.tbs_certificate.subject_pki.raw;
    let verification_key = CosignVerificationKey::try_from_der(spki_der)
        .map_err(|e| ProvenanceError::BadPublicKey(e.to_string()))?;

    let pae = compute_dsse_pae(payload_type, &payload_bytes);

    for sig_obj in signatures {
        let sig_b64 = match sig_obj.get("sig").and_then(|s| s.as_str()) {
            Some(s) => s,
            None => continue,
        };
        let sig_bytes = match base64_decode(sig_b64) {
            Ok(b) => b,
            Err(e) => return Err(ProvenanceError::BadDsseSignature(e)),
        };

        if verification_key
            .verify_signature(Signature::Raw(&sig_bytes), &pae)
            .is_ok()
        {
            return Ok(sig_bytes);
        }

        // If the signature was raw IEEE P1363 (64 bytes), try converting to ASN.1 DER.
        if sig_bytes.len() == 64 {
            if let Some(der_sig) = p1363_to_der(&sig_bytes) {
                if verification_key
                    .verify_signature(Signature::Raw(&der_sig), &pae)
                    .is_ok()
                {
                    return Ok(sig_bytes);
                }
            }
        }
    }

    Err(ProvenanceError::SignatureVerificationFailed)
}

/// Find the bundle's `dsseEnvelope` regardless of envelope variant (direct, npm, or PEP 740).
fn find_dsse_envelope(root: &serde_json::Value) -> Option<&serde_json::Value> {
    if let Some(dsse) = root.get("dsseEnvelope") {
        return Some(dsse);
    }
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
            if let Some(dsse) = att.pointer("/bundle/dsseEnvelope") {
                return Some(dsse);
            }
            if let Some(dsse) = att.get("dsseEnvelope") {
                return Some(dsse);
            }
        }
    }
    if let Some(bundles) = root.get("attestation_bundles").and_then(|b| b.as_array()) {
        for b in bundles {
            if let Some(arr) = b.get("attestations").and_then(|a| a.as_array()) {
                for att in arr {
                    if let Some(env) = att.get("envelope") {
                        return Some(env);
                    }
                    if let Some(dsse) = att.pointer("/bundle/dsseEnvelope") {
                        return Some(dsse);
                    }
                    if let Some(dsse) = att.get("dsseEnvelope") {
                        return Some(dsse);
                    }
                }
            }
        }
    }
    root.pointer("/bundle/dsseEnvelope")
}

/// Find the bundle's `verificationMaterial` regardless of which envelope variant npm/PyPI used,
/// then pull the leaf cert + Rekor log index.
fn extract_identity(
    root: &serde_json::Value,
    claim: &ProvenanceClaim,
) -> Result<(VerifiedIdentity, Vec<u8>), ProvenanceError> {
    // Locate the verificationMaterial. It may be nested under attestations[i].bundle.
    let vm = find_verification_material(root).ok_or(ProvenanceError::MissingCertChain)?;

    // ---- Cert chain ----
    let cert_b64 = vm
        .pointer("/x509CertificateChain/certificates/0/rawBytes")
        .or_else(|| vm.pointer("/certificate/rawBytes"))
        .or_else(|| vm.get("certificate"))
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
    let rekor_log_index = vm
        .pointer("/tlogEntries/0/logIndex")
        .or_else(|| vm.pointer("/transparency_entries/0/logIndex"))
        .and_then(|v| {
            v.as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .or_else(|| v.as_u64())
        });
    if rekor_log_index.is_none() {
        return Err(ProvenanceError::MissingRekorEntry);
    }

    Ok((
        VerifiedIdentity {
            workflow_uri,
            issuer_dn,
            rekor_log_index,
        },
        cert_der,
    ))
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
    // PEP 740 shape: { "attestation_bundles": [ { "attestations": [ { "verification_material": ... } ] } ] }
    if let Some(bundles) = root.get("attestation_bundles").and_then(|b| b.as_array()) {
        for b in bundles {
            if let Some(arr) = b.get("attestations").and_then(|a| a.as_array()) {
                for att in arr {
                    if let Some(vm) = att
                        .get("verification_material")
                        .or_else(|| att.pointer("/bundle/verificationMaterial"))
                    {
                        return Some(vm);
                    }
                }
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
    let clean: Vec<u8> = s.bytes().filter(|&b| !b.is_ascii_whitespace()).collect();
    if !clean.len().is_multiple_of(4) {
        return Err("base64: length not multiple of 4".into());
    }
    let mut out = Vec::with_capacity(clean.len() / 4 * 3);
    let (chunks, _remainder) = clean.as_chunks::<4>();
    for chunk in chunks {
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
    use clearhash_ecosystems::npm::NpmAdapter;
    use der::{Decode, Encode};

    const FIXTURE_SIGSTORE: &str =
        include_str!("../tests/fixtures/npm_sigstore_2.3.1_attestation.json");
    const FIXTURE_PYPI_SAMPLEPROJECT: &str =
        include_str!("../tests/fixtures/pypi_sampleproject_4.0.0_attestation.json");

    #[test]
    fn pae_spec_test_vector() {
        let pae = compute_dsse_pae("http://example.com/HelloWorld", b"hello world");
        assert_eq!(
            pae,
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
        );
    }

    #[tokio::test]
    async fn verifies_real_cosign_dsse_signature() {
        let res = verify(&NpmAdapter::default(), FIXTURE_SIGSTORE.as_bytes())
            .await
            .expect("real signature must verify");
        assert_eq!(
            res.claim.commit_sha,
            "46e7056ff9912ebfee5298d94024895a9fea76c0"
        );
        assert_eq!(
            res.identity.workflow_uri.as_deref(),
            Some("https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main")
        );
        assert_eq!(res.identity.rekor_log_index, Some(94408136));
    }

    fn base64_encode(data: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        let mut i = 0;
        while i < data.len() {
            let b0 = data[i] as u32;
            let b1 = if i + 1 < data.len() {
                data[i + 1] as u32
            } else {
                0
            };
            let b2 = if i + 2 < data.len() {
                data[i + 2] as u32
            } else {
                0
            };
            let triple = (b0 << 16) | (b1 << 8) | b2;
            out.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
            out.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);
            if i + 1 < data.len() {
                out.push(TABLE[((triple >> 6) & 0x3F) as usize] as char);
            } else {
                out.push('=');
            }
            if i + 2 < data.len() {
                out.push(TABLE[(triple & 0x3F) as usize] as char);
            } else {
                out.push('=');
            }
            i += 3;
        }
        out
    }

    #[tokio::test]
    async fn rejects_tampered_dsse_payload() {
        let mut bundle: serde_json::Value = serde_json::from_str(FIXTURE_SIGSTORE).unwrap();
        // Modify a string inside the valid in-toto statement JSON, keeping JSON valid
        let payload_str = bundle
            .pointer_mut("/attestations/1/bundle/dsseEnvelope/payload")
            .unwrap();
        let raw_payload = base64_decode(payload_str.as_str().unwrap()).unwrap();
        let payload_text = String::from_utf8(raw_payload).unwrap();
        let tampered_text = payload_text.replace("github-hosted", "github-hosteX");
        assert_ne!(payload_text, tampered_text);
        let clean_b64 = base64_encode(tampered_text.as_bytes());
        *payload_str = serde_json::Value::String(clean_b64);

        let err = verify(
            &NpmAdapter::default(),
            &serde_json::to_vec(&bundle).unwrap(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ProvenanceError::SignatureVerificationFailed));
    }

    #[tokio::test]
    async fn rejects_tampered_dsse_signature() {
        let mut bundle: serde_json::Value = serde_json::from_str(FIXTURE_SIGSTORE).unwrap();
        // Flip a byte in the signature
        let sig_str = bundle
            .pointer_mut("/attestations/1/bundle/dsseEnvelope/signatures/0/sig")
            .unwrap();
        let mut bytes = sig_str.as_str().unwrap().to_string().into_bytes();
        bytes[20] = if bytes[20] == b'A' { b'B' } else { b'A' };
        *sig_str = serde_json::Value::String(String::from_utf8(bytes).unwrap());

        let err = verify(
            &NpmAdapter::default(),
            &serde_json::to_vec(&bundle).unwrap(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ProvenanceError::SignatureVerificationFailed));
    }

    #[tokio::test]
    async fn rejects_missing_dsse_envelope() {
        let mut bundle: serde_json::Value = serde_json::from_str(FIXTURE_SIGSTORE).unwrap();
        bundle
            .pointer_mut("/attestations/1/bundle")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("dsseEnvelope");

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
                    source_repo: "git+https://github.com/sigstore/sigstore-js".into(),
                    commit_sha: "46e7056ff9912ebfee5298d94024895a9fea76c0".into(),
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

        let err = verify(&Stub, &serde_json::to_vec(&bundle).unwrap())
            .await
            .unwrap_err();
        assert!(matches!(err, ProvenanceError::MissingDsseEnvelope));
    }

    #[tokio::test]
    async fn rejects_empty_dsse_signatures() {
        let mut bundle: serde_json::Value = serde_json::from_str(FIXTURE_SIGSTORE).unwrap();
        *bundle
            .pointer_mut("/attestations/1/bundle/dsseEnvelope/signatures")
            .unwrap() = serde_json::json!([]);

        let err = verify(
            &NpmAdapter::default(),
            &serde_json::to_vec(&bundle).unwrap(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ProvenanceError::MissingDsseSignature));
    }

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

    #[tokio::test]
    async fn rejects_cert_without_sct_end_to_end() {
        let mut bundle: serde_json::Value = serde_json::from_str(FIXTURE_SIGSTORE).unwrap();
        let cert_b64 = bundle
            .pointer("/attestations/1/bundle/verificationMaterial/x509CertificateChain/certificates/0/rawBytes")
            .unwrap()
            .as_str()
            .unwrap();
        let cert_der = base64_decode(cert_b64).unwrap();

        // Strip the SCT extension using precert_tbs_der and wrap into a fake cert
        let stripped_tbs = sct::precert_tbs_der_for_test(&cert_der).unwrap();
        let cert_fields = Vec::<der::Any>::from_der(&cert_der).unwrap();
        let fake_cert = vec![
            der::Any::from_der(&stripped_tbs).unwrap(),
            cert_fields[1].clone(),
            cert_fields[2].clone(),
        ]
        .to_der()
        .unwrap();

        *bundle
            .pointer_mut("/attestations/1/bundle/verificationMaterial/x509CertificateChain/certificates/0/rawBytes")
            .unwrap() = serde_json::Value::String(base64_encode(&fake_cert));

        let err = verify(
            &NpmAdapter::default(),
            &serde_json::to_vec(&bundle).unwrap(),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, ProvenanceError::SctVerification(ref msg) if msg.contains("missing SCT extension")),
            "expected SCT verification error, got: {err}"
        );
    }

    #[tokio::test]
    async fn verifies_real_pep740_dsse_signature_sct_and_rekor() {
        use clearhash_ecosystems::pypi::PypiAdapter;

        let ok = verify(&PypiAdapter, FIXTURE_PYPI_SAMPLEPROJECT.as_bytes())
            .await
            .expect("PEP 740 verification should succeed end-to-end");

        assert_eq!(
            ok.claim.source_repo,
            "https://github.com/pypa/sampleproject"
        );
        assert_eq!(
            ok.claim.commit_sha,
            "621e4974ca25ce531773def586ba3ed8e736b3fc"
        );
        assert_eq!(ok.identity.rekor_log_index, Some(147137139));
        assert!(ok
            .identity
            .workflow_uri
            .unwrap()
            .contains("pypa/sampleproject/.github/workflows/release.yml"));
    }
}
