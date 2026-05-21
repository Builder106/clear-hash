//! npm adapter.
//!
//! Registry root: https://registry.npmjs.org
//! Attestation API: https://github.com/npm/registry/blob/main/docs/attestations.md
//! npm wraps a SLSA v1 in-toto statement in its own JSON envelope; the actual signed payload
//! is DSSE inside `bundle.dsseEnvelope`.

use async_trait::async_trait;
use clearhash_core::{Ecosystem, PackageRef, ProvenanceClaim};
use serde::Deserialize;
use url::Url;

use crate::{AdapterError, EcosystemAdapter};

pub struct NpmAdapter;

#[async_trait]
impl EcosystemAdapter for NpmAdapter {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Npm
    }

    fn artifact_url(&self, pkg: &PackageRef) -> Url {
        // Scoped names (`@scope/name`) embed in the URL with the `/` URL-encoded as-is —
        // npm's registry actually serves both `/@scope/name/...` and percent-encoded forms.
        // The `/-/<unscoped-name>-<version>.tgz` suffix uses the *unscoped* file name.
        let unscoped = pkg
            .name
            .rsplit_once('/')
            .map(|(_, n)| n)
            .unwrap_or(&pkg.name);
        let raw = format!(
            "https://registry.npmjs.org/{}/-/{}-{}.tgz",
            pkg.name, unscoped, pkg.version
        );
        Url::parse(&raw).expect("npm artifact URL")
    }

    fn attestation_url(&self, pkg: &PackageRef) -> Option<Url> {
        let raw = format!(
            "https://registry.npmjs.org/-/npm/v1/attestations/{}@{}",
            pkg.name, pkg.version
        );
        Some(Url::parse(&raw).expect("npm attestation URL"))
    }

    fn parse_attestation(&self, bundle: &[u8]) -> Result<ProvenanceClaim, AdapterError> {
        let env: NpmAttestationResponse = serde_json::from_slice(bundle)
            .map_err(|e| AdapterError::MalformedAttestation(format!("envelope: {e}")))?;

        // npm returns multiple attestations: a SLSA provenance one + a "publish" attestation.
        // We want the SLSA provenance.
        let slsa = env
            .attestations
            .into_iter()
            .find(|a| a.predicate_type.contains("slsa.dev/provenance"))
            .ok_or_else(|| {
                AdapterError::MalformedAttestation(
                    "no SLSA provenance attestation in envelope".into(),
                )
            })?;

        // The signed payload is base64'd JSON inside `bundle.dsseEnvelope.payload`.
        // (npm's "raw" `statement` field path is legacy and rarely present today.)
        let statement: InTotoStatement = match slsa.statement {
            Some(s) => s,
            None => {
                let bundle = slsa.bundle.ok_or_else(|| {
                    AdapterError::MalformedAttestation("missing statement and bundle".into())
                })?;
                let payload_b64 = bundle.dsse_envelope.payload;
                let payload = base64_decode_standard(&payload_b64)
                    .map_err(AdapterError::MalformedAttestation)?;
                serde_json::from_slice(&payload)
                    .map_err(|e| AdapterError::MalformedAttestation(format!("dsse payload: {e}")))?
            }
        };

        extract_claim_from_statement(statement)
    }

    fn rebuild_image(&self) -> &'static str {
        // Pin exact patch version; CI updates this via Renovate.
        "node:20.11.1-bookworm-slim"
    }

    fn rebuild_script(&self) -> &'static str {
        // Placeholders {REPO_URL}, {COMMIT_SHA}, {PKG_NAME}, {PKG_VERSION} are substituted by the
        // sandbox crate. Clone happens outside this script; source is mounted at /src.
        //
        // Monorepo handling: walk the source tree to find the package.json whose name+version
        // match the attested package. Run `npm ci` at the repo root (handles workspaces), then
        // `npm pack` from the target subdir.
        r#"set -eu
mkdir -p /out
cd /src
export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct {COMMIT_SHA} 2>/dev/null || echo 0)"
export TZ=UTC
export npm_config_update_notifier=false
export PKG_NAME='{PKG_NAME}'
export PKG_VERSION='{PKG_VERSION}'

TARGET_DIR=$(node -e '
  const fs = require("fs"); const path = require("path");
  function walk(dir) {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return null; }
    for (const e of entries) {
      if (e.name === "node_modules" || e.name === ".git") continue;
      const p = path.join(dir, e.name);
      if (e.isDirectory()) { const r = walk(p); if (r) return r; }
      else if (e.name === "package.json") {
        try {
          const j = JSON.parse(fs.readFileSync(p, "utf8"));
          if (j.name === process.env.PKG_NAME && j.version === process.env.PKG_VERSION) {
            return path.dirname(p);
          }
        } catch {}
      }
    }
    return null;
  }
  console.log(walk(process.cwd()) || "");
')
if [ -z "$TARGET_DIR" ]; then
  echo "clearhash: could not locate $PKG_NAME@$PKG_VERSION in source tree" >&2
  exit 1
fi
echo "clearhash: rebuilding from $TARGET_DIR" >&2

# Workspace install at the repo root (handles npm/yarn/pnpm workspaces).
if [ -f package-lock.json ]; then
  npm ci --ignore-scripts --no-audit --no-fund
elif [ -f yarn.lock ]; then
  corepack enable >/dev/null 2>&1 || true
  yarn install --frozen-lockfile --ignore-scripts >/dev/null
elif [ -f pnpm-lock.yaml ]; then
  corepack enable >/dev/null 2>&1 || true
  pnpm install --frozen-lockfile --ignore-scripts >/dev/null
else
  npm install --ignore-scripts --no-audit --no-fund
fi

cd "$TARGET_DIR"
# If a `prepack` / `prepare` script exists, run it explicitly (we used --ignore-scripts above).
# Many monorepos rely on this to generate dist/ before pack.
if node -e 'const p=require("./package.json"); process.exit(p.scripts && (p.scripts.build || p.scripts.prepack || p.scripts.prepare) ? 0 : 1)' 2>/dev/null; then
  npm run build --if-present || true
fi
npm pack --pack-destination=/out
"#
    }

    fn built_artifact_dir(&self) -> &'static str {
        "/out"
    }

    fn strip_archive_prefix(&self, _pkg: &PackageRef) -> Option<String> {
        // Every npm tarball wraps contents in a top-level `package/` directory.
        Some("package".into())
    }

    fn ignore_paths(&self) -> &'static [&'static str] {
        // Files that registries inject post-pack and rebuilds cannot reproduce.
        // Per-package-manager dotfiles can also vary across CLI versions.
        &[
            ".npmignore",
            // npm sometimes injects a top-level `.package-lock.json` into the published tarball
            // even though it's regenerated by `npm ci`; treat as cosmetic and skip.
        ]
    }

    fn normalize_file(&self, path: &str, bytes: Vec<u8>) -> Vec<u8> {
        if path != "package.json" {
            return bytes;
        }
        // Strip the four registry-injected metadata fields. We do a structural rewrite
        // rather than a regex so we don't corrupt source-controlled values that happen to
        // contain the same key names.
        let mut v: serde_json::Value = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => return bytes,
        };
        if let Some(obj) = v.as_object_mut() {
            for key in ["_id", "_integrity", "_resolved", "_from", "dist"] {
                obj.remove(key);
            }
        }
        serde_json::to_vec_pretty(&v).unwrap_or(bytes)
    }
}

// --- Envelope types: just enough fields to extract (repo, commit). ----------------------

#[derive(Deserialize)]
struct NpmAttestationResponse {
    attestations: Vec<NpmAttestation>,
}

#[derive(Deserialize)]
struct NpmAttestation {
    #[serde(rename = "predicateType")]
    predicate_type: String,
    /// Some npm responses embed the in-toto statement directly; older ones nest it under `bundle`.
    statement: Option<InTotoStatement>,
    bundle: Option<NpmBundle>,
}

#[derive(Deserialize)]
struct NpmBundle {
    #[serde(rename = "dsseEnvelope")]
    dsse_envelope: DsseEnvelope,
}

#[derive(Deserialize)]
struct DsseEnvelope {
    /// Base64-encoded JSON of the in-toto statement.
    payload: String,
}

/// Loose in-toto statement: parses both SLSA v0.2 (`predicate.materials`) and
/// SLSA v1 (`predicate.buildDefinition.resolvedDependencies`) shapes.
#[derive(Deserialize)]
struct InTotoStatement {
    predicate: serde_json::Value,
}

/// Walk a parsed predicate to extract (source_repo, commit_sha, builder_id).
fn extract_claim_from_statement(s: InTotoStatement) -> Result<ProvenanceClaim, AdapterError> {
    let pred = s.predicate;

    // ---- SLSA v1 path: predicate.buildDefinition.resolvedDependencies ----
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

    // ---- SLSA v0.2 path: predicate.materials[0] ----
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
        "could not find (repo, commit) in either SLSA v0.2 materials or v1 resolvedDependencies"
            .into(),
    ))
}

fn base64_decode_standard(s: &str) -> Result<Vec<u8>, String> {
    // Hand-rolled to avoid adding a dependency on `base64` purely for this one call.
    // Standard alphabet (RFC 4648), padded.
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
    use clearhash_core::Ecosystem;

    fn pkg(name: &str, ver: &str) -> PackageRef {
        PackageRef {
            ecosystem: Ecosystem::Npm,
            name: name.into(),
            version: ver.into(),
        }
    }

    #[test]
    fn artifact_url_unscoped() {
        let u = NpmAdapter.artifact_url(&pkg("litellm", "1.82.7"));
        assert_eq!(
            u.as_str(),
            "https://registry.npmjs.org/litellm/-/litellm-1.82.7.tgz"
        );
    }

    #[test]
    fn artifact_url_scoped_uses_unscoped_filename() {
        let u = NpmAdapter.artifact_url(&pkg("@sigstore/sign", "2.3.1"));
        // The path keeps the scope, the filename does not.
        assert_eq!(
            u.as_str(),
            "https://registry.npmjs.org/@sigstore/sign/-/sign-2.3.1.tgz"
        );
    }

    #[test]
    fn attestation_url_shape() {
        let u = NpmAdapter
            .attestation_url(&pkg("sigstore", "2.3.1"))
            .unwrap();
        assert_eq!(
            u.as_str(),
            "https://registry.npmjs.org/-/npm/v1/attestations/sigstore@2.3.1"
        );
    }

    #[test]
    fn base64_round_trip() {
        let original = b"hello world";
        // Hand-built encoding: "aGVsbG8gd29ybGQ="
        let decoded = base64_decode_standard("aGVsbG8gd29ybGQ=").unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn normalize_strips_registry_metadata() {
        let input = br#"{"name":"x","version":"1","_id":"x@1","_integrity":"sha512-...","dist":{"shasum":"abc"},"main":"index.js"}"#;
        let out = NpmAdapter.normalize_file("package.json", input.to_vec());
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert!(v.get("_id").is_none());
        assert!(v.get("_integrity").is_none());
        assert!(v.get("dist").is_none());
        assert_eq!(v.get("name").and_then(|x| x.as_str()), Some("x"));
        assert_eq!(v.get("main").and_then(|x| x.as_str()), Some("index.js"));
    }

    #[test]
    fn parses_slsa_v02_materials() {
        let bundle = serde_json::json!({
            "attestations": [{
                "predicateType": "https://slsa.dev/provenance/v0.2",
                "statement": {
                    "predicate": {
                        "builder": { "id": "https://github.com/actions/runner/github-hosted" },
                        "materials": [{
                            "uri": "git+https://github.com/example/repo@refs/tags/v1.0.0",
                            "digest": { "sha1": "7c2bdaa1e5d3fa6c2e1b1a1d4f5e6c7b8a9d0e1f" }
                        }]
                    }
                }
            }]
        });
        let claim = NpmAdapter
            .parse_attestation(&serde_json::to_vec(&bundle).unwrap())
            .unwrap();
        assert_eq!(claim.commit_sha, "7c2bdaa1e5d3fa6c2e1b1a1d4f5e6c7b8a9d0e1f");
        assert!(claim.source_repo.contains("example/repo"));
    }

    #[test]
    fn parses_slsa_v1_resolved_dependencies() {
        let bundle = serde_json::json!({
            "attestations": [{
                "predicateType": "https://slsa.dev/provenance/v1",
                "statement": {
                    "predicate": {
                        "buildDefinition": {
                            "resolvedDependencies": [{
                                "uri": "git+https://github.com/sigstore/sigstore-js@refs/tags/v2.3.1",
                                "digest": { "gitCommit": "deadbeefcafe1234567890abcdef0987654321ab" }
                            }]
                        },
                        "runDetails": {
                            "builder": { "id": "https://github.com/actions/runner/github-hosted" }
                        }
                    }
                }
            }]
        });
        let claim = NpmAdapter
            .parse_attestation(&serde_json::to_vec(&bundle).unwrap())
            .unwrap();
        assert_eq!(claim.commit_sha, "deadbeefcafe1234567890abcdef0987654321ab");
        assert!(claim.source_repo.contains("sigstore/sigstore-js"));
        assert!(claim.builder_id.contains("github-hosted"));
    }

    #[test]
    fn ignores_publish_attestation_and_picks_provenance() {
        let bundle = serde_json::json!({
            "attestations": [
                {
                    "predicateType": "https://github.com/npm/attestation/tree/main/specs/publish/v0.1",
                    "statement": { "predicate": { "name": "ignored" } }
                },
                {
                    "predicateType": "https://slsa.dev/provenance/v1",
                    "statement": {
                        "predicate": {
                            "buildDefinition": {
                                "resolvedDependencies": [{
                                    "uri": "git+https://github.com/example/repo",
                                    "digest": { "gitCommit": "abcdef1234567890abcdef1234567890abcdef12" }
                                }]
                            }
                        }
                    }
                }
            ]
        });
        let claim = NpmAdapter
            .parse_attestation(&serde_json::to_vec(&bundle).unwrap())
            .unwrap();
        assert_eq!(claim.commit_sha, "abcdef1234567890abcdef1234567890abcdef12");
    }
}
