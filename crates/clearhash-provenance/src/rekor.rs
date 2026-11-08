//! Offline Rekor v1 verification. Trust comes from a pinned production log key,
//! never from a key supplied by the attestation or an unauthenticated log lookup.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sigstore::{
    crypto::{CosignVerificationKey, Signature},
    rekor::models::{checkpoint::SignedCheckpoint, InclusionProof},
};

use crate::{find_dsse_envelope, find_verification_material, ProvenanceError};

// Production Rekor v1 SPKI, valid from 2021-01-12. Source (also shipped in
// sigstore 0.15.0's trust_root/prod/trusted_root.json):
// https://github.com/sigstore/root-signing/blob/main/targets/trusted_root.json
// Key rotations require an explicit reviewed update. Unknown logs fail closed.
const REKOR_KEY: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==";

fn invalid(message: impl ToString) -> ProvenanceError {
    ProvenanceError::RekorVerification(message.to_string())
}

fn text<'a>(value: &'a Value, path: &str) -> Result<&'a str, ProvenanceError> {
    value
        .pointer(path)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("missing or invalid {path}")))
}

fn decode(value: &Value, path: &str) -> Result<Vec<u8>, ProvenanceError> {
    STANDARD
        .decode(text(value, path)?)
        .map_err(|e| invalid(format!("invalid base64 at {path}: {e}")))
}

// Protobuf JSON encodes int64 as decimal strings; tolerate JSON integers too.
fn integer(value: &Value, path: &str) -> Result<i64, ProvenanceError> {
    let n = value.pointer(path).and_then(|v| {
        v.as_i64()
            .or_else(|| v.as_str().and_then(|s| s.parse::<i64>().ok()))
    });
    n.filter(|n| *n >= 0)
        .ok_or_else(|| invalid(format!("missing or invalid nonnegative int64 at {path}")))
}

fn hash(value: &Value, path: &str) -> Result<[u8; 32], ProvenanceError> {
    decode(value, path)?
        .try_into()
        .map_err(|_| invalid(format!("expected SHA-256 hash at {path}")))
}

pub(super) fn verify(
    root: &Value,
    cert_der: &[u8],
    verified_signature: &[u8],
) -> Result<(), ProvenanceError> {
    let entry = find_verification_material(root)
        .and_then(|vm| {
            vm.pointer("/tlogEntries/0")
                .or_else(|| vm.pointer("/transparency_entries/0"))
        })
        .ok_or(ProvenanceError::MissingRekorEntry)?;
    let body = decode(entry, "/canonicalizedBody")?;
    let key_der = STANDARD.decode(REKOR_KEY).map_err(invalid)?;
    let log_id = decode(entry, "/logId/keyId")?;
    if log_id.as_slice() != Sha256::digest(&key_der).as_slice() {
        return Err(invalid("untrusted Rekor log ID"));
    }
    let key = CosignVerificationKey::try_from_der(&key_der).map_err(invalid)?;
    let proof = entry
        .get("inclusionProof")
        .ok_or_else(|| invalid("missing inclusionProof"))?;
    let log_index = integer(proof, "/logIndex")?;
    let tree_size = integer(proof, "/treeSize")? as u64;
    if log_index as u64 >= tree_size {
        return Err(invalid("inclusion proof index is outside the tree"));
    }
    let root_hash = hash(proof, "/rootHash")?;
    let hashes = proof
        .get("hashes")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("missing proof hashes"))?
        .iter()
        .map(|h| hash(h, ""))
        .collect::<Result<Vec<_>, _>>()?;
    let checkpoint: SignedCheckpoint = serde_json::from_value(
        proof
            .pointer("/checkpoint/envelope")
            .cloned()
            .ok_or_else(|| invalid("missing checkpoint envelope"))?,
    )
    .map_err(invalid)?;
    if checkpoint.note.size != tree_size || checkpoint.note.hash != root_hash {
        return Err(invalid("proof root or tree size differs from checkpoint"));
    }
    InclusionProof::new(log_index, root_hash, tree_size, hashes, Some(checkpoint))
        .verify(&body, &key)
        .map_err(invalid)?;

    // Rekor v1 has a global logIndex and a shard-local inclusionProof.logIndex.
    // They need not match. A SET authenticates the global index when different.
    let global_index = integer(entry, "/logIndex")?;
    if entry.get("inclusionPromise").is_some() || global_index != log_index {
        let set = decode(entry, "/inclusionPromise/signedEntryTimestamp")?;
        let payload = serde_json::json!({
            "body": STANDARD.encode(&body),
            "integratedTime": integer(entry, "/integratedTime")?,
            "logID": hex::encode(&log_id),
            "logIndex": global_index,
        });
        let canonical = serde_json_canonicalizer::to_vec(&payload).map_err(invalid)?;
        key.verify_signature(Signature::Raw(&set), &canonical)
            .map_err(invalid)?;
    }

    let logged: Value = serde_json::from_slice(&body).map_err(invalid)?;
    verify_body(&logged, root, cert_der, verified_signature)
}

/// A valid proof for an unrelated entry must never authenticate this bundle.
/// Match the payload hash AND the exact signature verified by verify_dsse AND
/// its certificate. Together these also bind the DSSE payload type through PAE.
fn verify_body(
    logged: &Value,
    root: &Value,
    cert_der: &[u8],
    verified_signature: &[u8],
) -> Result<(), ProvenanceError> {
    let dsse = find_dsse_envelope(root).ok_or(ProvenanceError::MissingDsseEnvelope)?;
    let payload = if dsse.pointer("/payload").is_some() {
        decode(dsse, "/payload")?
    } else {
        decode(dsse, "/statement")?
    };
    let (content, signatures, signature_field, cert_field, double_encoded) =
        match (text(logged, "/kind")?, text(logged, "/apiVersion")?) {
            ("intoto", "0.0.2") => {
                let content = &logged["spec"]["content"];
                if text(content, "/envelope/payloadType")? != text(dsse, "/payloadType")? {
                    return Err(invalid("logged payload type differs from DSSE envelope"));
                }
                (
                    content,
                    &content["envelope"]["signatures"],
                    "/sig",
                    "/publicKey",
                    true,
                )
            }
            ("dsse", "0.0.1") => (
                &logged["spec"],
                &logged["spec"]["signatures"],
                "/signature",
                "/verifier",
                false,
            ),
            _ => return Err(invalid("unsupported Rekor entry kind/version")),
        };
    if text(content, "/payloadHash/algorithm")? != "sha256"
        || text(content, "/payloadHash/value")? != hex::encode(Sha256::digest(&payload))
    {
        return Err(invalid("logged payload hash differs from DSSE payload"));
    }
    let signatures = signatures
        .as_array()
        .ok_or_else(|| invalid("missing logged signatures"))?;
    for signature in signatures {
        let mut bytes = decode(signature, signature_field)?;
        // intoto v0.0.2 stores base64(UTF-8 base64(signature)).
        if double_encoded {
            bytes = STANDARD.decode(&bytes).map_err(invalid)?;
        }
        if bytes != verified_signature {
            continue;
        }
        let pem = decode(signature, cert_field)?;
        let (rest, cert) = x509_parser::pem::parse_x509_pem(&pem).map_err(invalid)?;
        if cert.label == "CERTIFICATE"
            && cert.contents == cert_der
            && rest.iter().all(u8::is_ascii_whitespace)
        {
            return Ok(());
        }
    }
    Err(invalid(
        "logged signature/certificate differs from verified DSSE",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clearhash_ecosystems::npm::NpmAdapter;
    use serde_json::json;

    const FIXTURE: &str = include_str!("../tests/fixtures/npm_sigstore_2.3.1_attestation.json");
    const ENTRY: &str = "/attestations/1/bundle/verificationMaterial/tlogEntries/0";

    fn fixture() -> Value {
        serde_json::from_str(FIXTURE).unwrap()
    }

    fn signing_material(root: &Value) -> (Vec<u8>, Vec<u8>) {
        let cert = decode(
            find_verification_material(root).unwrap(),
            "/x509CertificateChain/certificates/0/rawBytes",
        )
        .unwrap();
        let signature = crate::verify_dsse(root, &cert).unwrap();
        (cert, signature)
    }

    #[tokio::test]
    async fn rejects_missing_or_tampered_rekor_material() {
        // The DSSE remains authentic in every case; failure must come from Rekor.
        let replacements = [
            ("/canonicalizedBody", Value::Null),
            ("/canonicalizedBody", json!("!!!!")),
            (
                "/canonicalizedBody",
                json!(STANDARD.encode(b"unlogged entry")),
            ),
            ("/logId/keyId", Value::Null),
            ("/logId/keyId", json!(STANDARD.encode([0; 32]))),
            ("/logIndex", json!(94408137)),
            ("/integratedTime", json!(1715879524)),
            ("/inclusionPromise", Value::Null),
            ("/inclusionPromise/signedEntryTimestamp", json!("AAAA")),
            ("/inclusionProof", Value::Null),
            ("/inclusionProof/logIndex", Value::Null),
            ("/inclusionProof/logIndex", json!(90244706)),
            ("/inclusionProof/logIndex", json!(-1)),
            ("/inclusionProof/logIndex", json!(90244708)),
            ("/inclusionProof/logIndex", json!("18446744073709551615")),
            ("/inclusionProof/logIndex", json!(1.5)),
            ("/inclusionProof/treeSize", json!(0)),
            ("/inclusionProof/treeSize", json!(-1)),
            ("/inclusionProof/treeSize", json!(90244709)),
            ("/inclusionProof/rootHash", json!(STANDARD.encode([0; 32]))),
            ("/inclusionProof/rootHash", json!(STANDARD.encode([0; 31]))),
            ("/inclusionProof/hashes", Value::Null),
            ("/inclusionProof/hashes", json!([])),
            ("/inclusionProof/hashes/0", json!(STANDARD.encode([0; 32]))),
            ("/inclusionProof/hashes/0", json!(STANDARD.encode([0; 33]))),
            ("/inclusionProof/hashes/0", json!("!!!!")),
            ("/inclusionProof/checkpoint", Value::Null),
            (
                "/inclusionProof/checkpoint/envelope",
                json!("not a checkpoint"),
            ),
        ];
        for (path, replacement) in replacements {
            let mut root = fixture();
            *root.pointer_mut(&format!("{ENTRY}{path}")).unwrap() = replacement;
            let error = crate::verify(&NpmAdapter, &serde_json::to_vec(&root).unwrap())
                .await
                .unwrap_err();
            assert!(
                matches!(error, ProvenanceError::RekorVerification(_)),
                "{path}: {error}"
            );
        }
    }

    #[test]
    fn rejects_short_and_extra_merkle_paths_and_forged_checkpoints() {
        let original = fixture();
        let (cert, signature) = signing_material(&original);
        for extra in [false, true] {
            let mut root = original.clone();
            let hashes = root.pointer_mut(ENTRY).unwrap()["inclusionProof"]["hashes"]
                .as_array_mut()
                .unwrap();
            if extra {
                hashes.push(hashes[0].clone());
            } else {
                hashes.pop();
            }
            assert!(verify(&root, &cert, &signature).is_err());
        }

        let envelope = original.pointer(ENTRY).unwrap()["inclusionProof"]["checkpoint"]["envelope"]
            .as_str()
            .unwrap();
        let (note, signatures) = envelope.split_once("\n\n").unwrap();
        let mut corrupt_signature = signatures.to_string().into_bytes();
        let last = corrupt_signature.len() - 6;
        corrupt_signature[last] = if corrupt_signature[last] == b'A' {
            b'B'
        } else {
            b'A'
        };
        for bad in [
            format!("{note}\n\n"),
            format!(
                "{note}\n\n{}",
                String::from_utf8(corrupt_signature).unwrap()
            ),
            envelope.replace("rekor.sigstore.dev -", "attacker.example -"),
            envelope.replacen("90244708", "90244709", 1),
            envelope.replace(
                "COSIc1jqxpbuuTChPdiTqtZBBve7GAVJqTYjqAaM940=",
                &STANDARD.encode([0; 32]),
            ),
        ] {
            let mut root = original.clone();
            root.pointer_mut(ENTRY).unwrap()["inclusionProof"]["checkpoint"]["envelope"] =
                json!(bad);
            assert!(verify(&root, &cert, &signature).is_err());
        }
    }

    #[tokio::test]
    async fn rejects_valid_proof_for_sibling_publish_entry() {
        let mut root = fixture();
        let other =
            root["attestations"][0]["bundle"]["verificationMaterial"]["tlogEntries"][0].clone();
        *root.pointer_mut(ENTRY).unwrap() = other;
        let error = crate::verify(&NpmAdapter, &serde_json::to_vec(&root).unwrap())
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("payload hash differs"),
            "{error}"
        );
    }

    #[test]
    fn supports_numeric_indices_and_direct_bundle_material() {
        let mut root = fixture();
        let (cert, signature) = signing_material(&root);
        let entry = root.pointer_mut(ENTRY).unwrap();
        for path in [
            "/logIndex",
            "/integratedTime",
            "/inclusionProof/logIndex",
            "/inclusionProof/treeSize",
        ] {
            let number = integer(entry, path).unwrap();
            *entry.pointer_mut(path).unwrap() = json!(number);
        }
        verify(&root, &cert, &signature).unwrap();
        verify(&root["attestations"][1]["bundle"], &cert, &signature).unwrap();
    }

    #[test]
    fn binds_both_supported_entry_formats_to_verified_signing_material() {
        let root = fixture();
        let (cert, signature) = signing_material(&root);
        let body = decode(root.pointer(ENTRY).unwrap(), "/canonicalizedBody").unwrap();
        let intoto: Value = serde_json::from_slice(&body).unwrap();
        let content = &intoto["spec"]["content"];
        let dsse = json!({
            "kind": "dsse", "apiVersion": "0.0.1",
            "spec": {
                "payloadHash": content["payloadHash"],
                "signatures": [{
                    "signature": STANDARD.encode(&signature),
                    "verifier": content["envelope"]["signatures"][0]["publicKey"],
                }],
            },
        });
        for logged in [intoto, dsse] {
            verify_body(&logged, &root, &cert, &signature).unwrap();
            assert!(verify_body(&logged, &root, &cert, b"different signature").is_err());
            assert!(verify_body(&logged, &root, b"different certificate", &signature).is_err());
            let content_path = if logged["kind"] == "intoto" {
                "/spec/content"
            } else {
                "/spec"
            };
            for (path, value) in [
                ("/payloadHash/algorithm", json!("sha512")),
                ("/payloadHash/value", json!("00".repeat(32))),
            ] {
                let mut bad = logged.clone();
                *bad.pointer_mut(&format!("{content_path}{path}")).unwrap() = value;
                assert!(verify_body(&bad, &root, &cert, &signature).is_err());
            }
            let mut unsupported = logged.clone();
            unsupported["apiVersion"] = json!("9.9.9");
            assert!(verify_body(&unsupported, &root, &cert, &signature).is_err());
        }
    }
}
