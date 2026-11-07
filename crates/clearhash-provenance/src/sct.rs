//! Offline Signed Certificate Timestamp (SCT) verification.
//!
//! Confirms that Fulcio actually submitted the precertificate to a trusted
//! Certificate Transparency (CT) log before issuance, preventing attackers
//! from presenting forged certificates carrying `O=sigstore.dev`.
//! Trust comes from pinned CT log public keys and pinned Fulcio CA keys from
//! Sigstore's trusted root.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use const_oid::db::rfc6962::CT_PRECERT_SCTS;
use der::{Any, Decode, Encode, Tag, TagNumber, Tagged};
use sha2::{Digest, Sha256};
use sigstore::crypto::{CosignVerificationKey, Signature};
use x509_cert::{
    ext::pkix::{sct::Version, SignedCertificateTimestampList},
    Certificate,
};

use crate::{find_verification_material, ProvenanceError};

fn invalid(message: impl ToString) -> ProvenanceError {
    ProvenanceError::SctVerification(message.to_string())
}

/// Pinned production CT log definition from Sigstore's trusted root.
struct PinnedCtLog {
    name: &'static str,
    spki_base64: &'static str,
}

/// Production Sigstore CT logs from targets/trusted_root.json.
/// Source: https://github.com/sigstore/root-signing/blob/main/targets/trusted_root.json
const PINNED_CT_LOGS: &[PinnedCtLog] = &[
    // Active production CT log (2022-present)
    PinnedCtLog {
        name: "ctfe.sigstore.dev/2022",
        spki_base64: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiPSlFi0CmFTfEjCUqF9HuCEcYXNKAaYalIJmBZ8yyezPjTqhxrKBpMnaocVtLJBI1eM3uXnQzQGAJdJ4gs9Fyw==",
    },
    // Historical production CT log (2021-2022)
    PinnedCtLog {
        name: "ctfe.sigstore.dev/test",
        spki_base64: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbfwR+RJudXscgRBRpKX1XFDy3PyudDxz/SfnRi1fT8ekpfBd2O1uoz7jr3Z8nKzxA69EUQ+eFCFI3zeubPWU7w==",
    },
];

/// Pinned production Fulcio CA SPKI SHA-256 hashes from Sigstore's trusted root.
/// In RFC 6962 PrecertEntry, `issuer_key_hash` is SHA-256 of the issuing CA's SPKI.
const PINNED_FULCIO_SPKI_HASHES: &[[u8; 32]] = &[
    // Fulcio intermediate CA: CN=sigstore-intermediate, O=sigstore.dev
    // SPKI: MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV77LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS0N/RgBJz/9jWCiXn
    [
        0xc3, 0x55, 0xee, 0x53, 0xd6, 0x9e, 0x68, 0xaa, 0xde, 0x04, 0xe5, 0xc6, 0xcc, 0x20, 0x2c,
        0xfa, 0xc1, 0x1f, 0xbc, 0xaa, 0x67, 0xe9, 0xa2, 0xba, 0x7a, 0x64, 0xce, 0xd2, 0xae, 0xc8,
        0xcc, 0xd0,
    ],
    // Fulcio 2021 root CA: CN=sigstore, O=sigstore.dev
    // SPKI: MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEtLIDsiLmT6k07xkRZjTKV6ZYOjA6Q1reQv4ZkTlnkZZ6Ev38D1tE0DdFuuxnmLQlxqy1pEvtKnl+n+MPl3Gpz9R1NWeW9LXpqf7Zh+zB79C4uiVFQKtw4Tb7aIDn63N3
    [
        0x80, 0x91, 0x7b, 0x65, 0xf0, 0x3a, 0xbf, 0x98, 0x8a, 0x5e, 0x81, 0x5c, 0x62, 0x5e, 0x42,
        0xb4, 0x8b, 0x04, 0x1b, 0x6d, 0x6a, 0x2d, 0x17, 0x85, 0x15, 0x18, 0xf2, 0x5d, 0x54, 0x51,
        0x7c, 0xf3,
    ],
    // Fulcio 2022 root CA: CN=sigstore, O=sigstore.dev
    // SPKI: MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+13hU+K29z0BsEuCGo7S5N/zpZ6YGp4GgXJWKbGAa+YvuMpwdO3Hm9yz9DiDmXcXsV+vXOYlbsiUUPh89OcovlBd7gVgJR6YkubIdPh9hhxO0l65NRAuZtU69fS/YIPd
    [
        0xfe, 0xf4, 0xe9, 0xbe, 0xb1, 0x7f, 0xaa, 0x47, 0x73, 0x52, 0x77, 0xcc, 0xa7, 0x63, 0x3a,
        0xe5, 0xe6, 0x70, 0xb8, 0xd8, 0x3d, 0xce, 0x91, 0x50, 0x83, 0x42, 0x39, 0x71, 0x48, 0xf4,
        0xe1, 0x3a,
    ],
];

const EXTENSIONS_TAG: Tag = Tag::ContextSpecific {
    constructed: true,
    number: TagNumber(3),
};

/// Reconstruct the precertificate's TBSCertificate DER by stripping the SCT list extension
/// (OID 1.3.6.1.4.1.11129.2.4.2) according to RFC 6962 Section 3.1.
fn precert_tbs_der(leaf_der: &[u8]) -> Result<Vec<u8>, ProvenanceError> {
    let cert_fields = Vec::<Any>::from_der(leaf_der)
        .map_err(|e| invalid(format!("malformed certificate DER: {e}")))?;
    let tbs = cert_fields
        .first()
        .ok_or_else(|| invalid("certificate missing TBSCertificate"))?;
    let mut tbs_fields: Vec<Any> = tbs
        .decode_as()
        .map_err(|e| invalid(format!("malformed TBSCertificate: {e}")))?;

    if let Some(extensions) = tbs_fields.iter_mut().find(|f| f.tag() == EXTENSIONS_TAG) {
        let mut kept = Vec::new();
        let raw_extensions: Vec<Any> = Vec::<Any>::from_der(extensions.value())
            .map_err(|e| invalid(format!("malformed extensions sequence: {e}")))?;
        for ext in raw_extensions {
            let parsed = ext
                .decode_as::<x509_cert::ext::Extension>()
                .map_err(|e| invalid(format!("malformed extension: {e}")))?;
            if parsed.extn_id != CT_PRECERT_SCTS {
                kept.push(ext);
            }
        }
        *extensions = Any::new(
            EXTENSIONS_TAG,
            kept.to_der()
                .map_err(|e| invalid(format!("failed to encode stripped extensions: {e}")))?,
        )
        .map_err(|e| invalid(format!("failed to construct extensions Any: {e}")))?;
    }

    tbs_fields
        .to_der()
        .map_err(|e| invalid(format!("failed to encode precert TBS: {e}")))
}

#[cfg(test)]
pub(super) fn precert_tbs_der_for_test(leaf_der: &[u8]) -> Result<Vec<u8>, ProvenanceError> {
    precert_tbs_der(leaf_der)
}

/// Serialize the RFC 6962 Section 3.2 DigitallySigned structure for a precertificate entry.
fn serialize_digitally_signed_precert(
    timestamp: u64,
    issuer_key_hash: &[u8; 32],
    tbs_precert_der: &[u8],
    extensions: &[u8],
) -> Result<Vec<u8>, ProvenanceError> {
    if tbs_precert_der.len() > 0x00ffffff {
        return Err(invalid(
            "TBS precertificate DER too large for 24-bit length",
        ));
    }
    if extensions.len() > 0xffff {
        return Err(invalid("SCT extensions too large for 16-bit length"));
    }

    let mut out =
        Vec::with_capacity(1 + 1 + 8 + 2 + 32 + 3 + tbs_precert_der.len() + 2 + extensions.len());
    out.push(0); // Version::V1 = 0
    out.push(0); // SignatureType::CertificateTimestamp = 0
    out.extend_from_slice(&timestamp.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // LogEntryType::PrecertEntry = 1
    out.extend_from_slice(issuer_key_hash);
    let tbs_len = tbs_precert_der.len() as u32;
    out.push((tbs_len >> 16) as u8);
    out.push((tbs_len >> 8) as u8);
    out.push(tbs_len as u8);
    out.extend_from_slice(tbs_precert_der);
    let ext_len = extensions.len() as u16;
    out.extend_from_slice(&ext_len.to_be_bytes());
    out.extend_from_slice(extensions);
    Ok(out)
}

/// Verify that the leaf certificate carries at least one valid Signed Certificate Timestamp (SCT)
/// from a pinned Certificate Transparency log, signed over a precertificate issued by Fulcio.
pub(super) fn verify(root: &serde_json::Value, cert_der: &[u8]) -> Result<(), ProvenanceError> {
    // 1. If an intermediate CA certificate is present in the chain, check that it matches a pinned Fulcio CA.
    if let Some(vm) = find_verification_material(root) {
        if let Some(interm_b64) = vm
            .pointer("/x509CertificateChain/certificates/1/rawBytes")
            .and_then(|v| v.as_str())
        {
            let interm_der = STANDARD
                .decode(interm_b64)
                .map_err(|e| invalid(format!("invalid base64 in intermediate cert: {e}")))?;
            let interm_cert = Certificate::from_der(&interm_der)
                .map_err(|e| invalid(format!("malformed intermediate certificate: {e}")))?;
            let spki_der = interm_cert
                .tbs_certificate()
                .subject_public_key_info()
                .to_der()
                .map_err(|e| invalid(format!("failed to encode intermediate SPKI: {e}")))?;
            let interm_hash: [u8; 32] = Sha256::digest(&spki_der).into();
            if !PINNED_FULCIO_SPKI_HASHES.contains(&interm_hash) {
                return Err(invalid(
                    "intermediate CA certificate does not match any pinned Fulcio CA",
                ));
            }
        }
    }

    // 2. Parse the leaf certificate.
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| invalid(format!("leaf certificate parsing error: {e}")))?;

    // 3. Extract the SCT list extension (OID 1.3.6.1.4.1.11129.2.4.2).
    let sct_list = match cert
        .tbs_certificate()
        .get_extension::<SignedCertificateTimestampList>()
    {
        Ok(Some((_critical, list))) => list,
        Ok(None) => return Err(invalid("leaf certificate missing SCT extension")),
        Err(e) => return Err(invalid(format!("malformed SCT list extension: {e}"))),
    };

    let serialized_scts = sct_list
        .parse_timestamps()
        .map_err(|e| invalid(format!("failed to parse SCT timestamps: {e:?}")))?;

    if serialized_scts.is_empty() {
        return Err(invalid("SCT list is empty"));
    }

    // 4. Reconstruct the precertificate TBS DER (with SCT extension stripped).
    let tbs_precert = precert_tbs_der(cert_der)?;

    // 5. Verify each SCT. At least one must be from a pinned CT log and verify successfully.
    let mut verified_count = 0;

    for serialized_sct in serialized_scts {
        let sct = serialized_sct
            .parse_timestamp()
            .map_err(|e| invalid(format!("malformed SCT entry: {e:?}")))?;

        if sct.version != Version::V1 {
            continue;
        }

        // Find the CT log matching this log ID.
        let log_id = sct.log_id.key_id;
        let ct_log = match PINNED_CT_LOGS.iter().find(|log| {
            if let Ok(key_der) = STANDARD.decode(log.spki_base64) {
                Sha256::digest(&key_der).as_slice() == log_id.as_slice()
            } else {
                false
            }
        }) {
            Some(log) => log,
            None => {
                tracing::debug!("skipping SCT with unpinned log ID: {:x?}", log_id);
                continue;
            }
        };

        // Issuer key hash from the SCT must match a pinned Fulcio CA.
        // Wait: where is issuer_key_hash in the SCT?
        // Note: The SCT in the certificate does NOT store issuer_key_hash inside its own payload;
        // rather, the signed DigitallySigned payload includes issuer_key_hash.
        // We verify the SCT against our pinned Fulcio CAs!
        let ct_key_der = STANDARD
            .decode(ct_log.spki_base64)
            .map_err(|e| invalid(format!("corrupt pinned CT log SPKI: {e}")))?;
        let ct_verifying_key = CosignVerificationKey::try_from_der(&ct_key_der)
            .map_err(|e| invalid(format!("failed to load CT log verifying key: {e}")))?;

        let sig_bytes = sct.signature.signature.as_slice();

        // Check against known Fulcio CA SPKI hashes
        let mut matched_fulcio = false;
        for fulcio_hash in PINNED_FULCIO_SPKI_HASHES {
            let digitally_signed = serialize_digitally_signed_precert(
                sct.timestamp,
                fulcio_hash,
                &tbs_precert,
                sct.extensions.as_slice(),
            )?;

            if ct_verifying_key
                .verify_signature(Signature::Raw(sig_bytes), &digitally_signed)
                .is_ok()
            {
                matched_fulcio = true;
                break;
            }
        }

        if matched_fulcio {
            tracing::debug!(
                "provenance: successfully verified SCT from CT log '{}' (timestamp: {})",
                ct_log.name,
                sct.timestamp
            );
            verified_count += 1;
        }
    }

    if verified_count == 0 {
        return Err(invalid(
            "no SCT could be verified against pinned CT logs and Fulcio CAs",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_SIGSTORE: &str =
        include_str!("../tests/fixtures/npm_sigstore_2.3.1_attestation.json");

    #[test]
    fn verifies_real_sct_from_fixture() {
        let bundle: serde_json::Value = serde_json::from_str(FIXTURE_SIGSTORE).unwrap();
        let cert_b64 = bundle
            .pointer("/attestations/1/bundle/verificationMaterial/x509CertificateChain/certificates/0/rawBytes")
            .unwrap()
            .as_str()
            .unwrap();
        let cert_der = STANDARD.decode(cert_b64).unwrap();

        verify(&bundle, &cert_der).expect("real SCT from fixture must verify");
    }

    #[test]
    fn rejects_missing_sct_extension() {
        let bundle: serde_json::Value = serde_json::from_str(FIXTURE_SIGSTORE).unwrap();
        let cert_b64 = bundle
            .pointer("/attestations/1/bundle/verificationMaterial/x509CertificateChain/certificates/0/rawBytes")
            .unwrap()
            .as_str()
            .unwrap();
        let cert_der = STANDARD.decode(cert_b64).unwrap();

        // Strip the SCT extension using precert_tbs_der and rebuild a cert without it
        let stripped_tbs = precert_tbs_der(&cert_der).unwrap();

        // Wrap the stripped TBS in a valid certificate sequence
        // (TBS, signatureAlgorithm, signatureValue)
        let cert_fields = Vec::<Any>::from_der(&cert_der).unwrap();
        let fake_cert = vec![
            Any::from_der(&stripped_tbs).unwrap(),
            cert_fields[1].clone(),
            cert_fields[2].clone(),
        ]
        .to_der()
        .unwrap();

        let err = verify(&bundle, &fake_cert).unwrap_err();
        assert!(
            matches!(err, ProvenanceError::SctVerification(ref msg) if msg.contains("missing SCT extension")),
            "expected missing SCT error, got: {err}"
        );
    }

    #[test]
    fn rejects_tampered_sct_signature() {
        let bundle: serde_json::Value = serde_json::from_str(FIXTURE_SIGSTORE).unwrap();
        let cert_b64 = bundle
            .pointer("/attestations/1/bundle/verificationMaterial/x509CertificateChain/certificates/0/rawBytes")
            .unwrap()
            .as_str()
            .unwrap();
        let mut cert_der = STANDARD.decode(cert_b64).unwrap();

        // Locate the exact SCT signature bytes inside the certificate DER and tamper them
        let cert = Certificate::from_der(&cert_der).unwrap();
        let sct_list = cert
            .tbs_certificate()
            .get_extension::<SignedCertificateTimestampList>()
            .unwrap()
            .unwrap()
            .1;
        let sct = sct_list.parse_timestamps().unwrap()[0]
            .parse_timestamp()
            .unwrap();
        let sig_bytes = sct.signature.signature.as_slice();
        let sig_pos = cert_der
            .windows(sig_bytes.len())
            .position(|window| window == sig_bytes)
            .expect("SCT signature must exist in cert DER");

        cert_der[sig_pos + 10] ^= 0xff;

        let err = verify(&bundle, &cert_der).unwrap_err();
        assert!(
            matches!(err, ProvenanceError::SctVerification(_)),
            "expected SCT verification error, got: {err}"
        );
    }

    #[test]
    fn rejects_tampered_precert_tbs() {
        let bundle: serde_json::Value = serde_json::from_str(FIXTURE_SIGSTORE).unwrap();
        let cert_b64 = bundle
            .pointer("/attestations/1/bundle/verificationMaterial/x509CertificateChain/certificates/0/rawBytes")
            .unwrap()
            .as_str()
            .unwrap();
        let mut cert_der = STANDARD.decode(cert_b64).unwrap();

        // Tamper a byte inside the SAN workflow URI in the certificate
        let uri = b"https://github.com/sigstore/sigstore-js";
        let uri_pos = cert_der
            .windows(uri.len())
            .position(|w| w == uri)
            .expect("SAN URI must exist in cert DER");
        cert_der[uri_pos + 10] ^= 0x01;

        let err = verify(&bundle, &cert_der).unwrap_err();
        assert!(
            matches!(err, ProvenanceError::SctVerification(_)),
            "tampered TBS must fail SCT verification, got: {err}"
        );
    }

    #[test]
    fn rejects_untrusted_ct_log_id() {
        let bundle: serde_json::Value = serde_json::from_str(FIXTURE_SIGSTORE).unwrap();
        let cert_b64 = bundle
            .pointer("/attestations/1/bundle/verificationMaterial/x509CertificateChain/certificates/0/rawBytes")
            .unwrap()
            .as_str()
            .unwrap();
        let mut cert_der = STANDARD.decode(cert_b64).unwrap();

        // Locate the log ID inside the SCT and tamper it
        let cert = Certificate::from_der(&cert_der).unwrap();
        let sct_list = cert
            .tbs_certificate()
            .get_extension::<SignedCertificateTimestampList>()
            .unwrap()
            .unwrap()
            .1;
        let sct = sct_list.parse_timestamps().unwrap()[0]
            .parse_timestamp()
            .unwrap();
        let log_id = sct.log_id.key_id;
        let log_id_pos = cert_der
            .windows(log_id.len())
            .position(|w| w == log_id)
            .expect("Log ID must exist in cert DER");

        cert_der[log_id_pos] ^= 0xff;

        let err = verify(&bundle, &cert_der).unwrap_err();
        assert!(
            matches!(err, ProvenanceError::SctVerification(ref msg) if msg.contains("no SCT could be verified")),
            "expected unpinned CT log error, got: {err}"
        );
    }

    #[test]
    fn rejects_untrusted_intermediate_cert() {
        let mut bundle: serde_json::Value = serde_json::from_str(FIXTURE_SIGSTORE).unwrap();
        // Add a fake intermediate cert into the chain
        let fake_intermediate_b64 = STANDARD.encode(b"not a valid cert");
        bundle
            .pointer_mut(
                "/attestations/1/bundle/verificationMaterial/x509CertificateChain/certificates",
            )
            .unwrap()
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({ "rawBytes": fake_intermediate_b64 }));

        let cert_b64 = bundle
            .pointer("/attestations/1/bundle/verificationMaterial/x509CertificateChain/certificates/0/rawBytes")
            .unwrap()
            .as_str()
            .unwrap();
        let cert_der = STANDARD.decode(cert_b64).unwrap();

        let err = verify(&bundle, &cert_der).unwrap_err();
        assert!(matches!(err, ProvenanceError::SctVerification(_)));
    }
}
