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

use crate::{AdapterError, EcosystemAdapter, ReleaseUrls};

/// Linux/glibc execution targets supported by the pinned native build image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NpmPlatform {
    LinuxAmd64,
    LinuxArm64,
}

impl NpmPlatform {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LinuxAmd64 => "linux/amd64",
            Self::LinuxArm64 => "linux/arm64",
        }
    }

    fn cpu(self) -> &'static str {
        match self {
            Self::LinuxAmd64 => "x64",
            Self::LinuxArm64 => "arm64",
        }
    }
}

impl std::str::FromStr for NpmPlatform {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "linux/amd64" => Ok(Self::LinuxAmd64),
            "linux/arm64" => Ok(Self::LinuxArm64),
            _ => Err("supported npm platforms: linux/amd64, linux/arm64 (glibc); macOS, Windows and musl require different runners".into()),
        }
    }
}

#[derive(Default)]
pub struct NpmAdapter {
    platform: Option<NpmPlatform>,
}

impl NpmAdapter {
    pub fn for_platform(platform: NpmPlatform) -> Self {
        Self {
            platform: Some(platform),
        }
    }
}

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

    fn release_metadata_url(&self, pkg: &PackageRef) -> Option<Url> {
        self.platform.map(|_| {
            Url::parse(&format!(
                "https://registry.npmjs.org/{}/{}",
                pkg.name, pkg.version
            ))
            .expect("npm release metadata URL")
        })
    }

    fn parse_release_urls(
        &self,
        body: &[u8],
        pkg: &PackageRef,
    ) -> Result<ReleaseUrls, AdapterError> {
        let release: NativeRelease = serde_json::from_slice(body)
            .map_err(|e| AdapterError::InvalidRebuild(format!("npm release metadata: {e}")))?;
        if release.name != pkg.name || release.version != pkg.version {
            return Err(AdapterError::InvalidRebuild(
                "npm release name/version does not match requested package".into(),
            ));
        }
        let platform = self
            .platform
            .ok_or_else(|| AdapterError::InvalidRebuild("npm platform not selected".into()))?;
        for (field, values, target) in [
            ("os", release.os, "linux"),
            ("cpu", release.cpu, platform.cpu()),
            ("libc", release.libc, "glibc"),
        ] {
            if !allows_target(values.as_deref(), target) {
                return Err(AdapterError::InvalidRebuild(format!(
                    "npm {field} constraint does not support {} (glibc)",
                    platform.as_str()
                )));
            }
        }
        let artifact_url = Url::parse(&release.dist.tarball)
            .map_err(|e| AdapterError::InvalidRebuild(format!("npm dist.tarball: {e}")))?;
        if artifact_url.scheme() != "https" || artifact_url.host_str().is_none() {
            return Err(AdapterError::InvalidRebuild(
                "npm dist.tarball must be an HTTPS URL".into(),
            ));
        }
        Ok(ReleaseUrls {
            artifact_url,
            attestation_url: self.attestation_url(pkg),
        })
    }

    fn rebuild_platform(&self) -> Option<&'static str> {
        self.platform.map(NpmPlatform::as_str)
    }

    fn latest_version_url(&self, name: &str) -> Option<Url> {
        // Package metadata endpoint. Scoped names (`@scope/name`) are URL-safe as-is.
        let raw = format!("https://registry.npmjs.org/{name}");
        Some(Url::parse(&raw).expect("npm latest-version URL"))
    }

    fn parse_latest_version(&self, body: &[u8]) -> Result<String, AdapterError> {
        let v: serde_json::Value = serde_json::from_slice(body).map_err(|e| {
            AdapterError::MalformedAttestation(format!("npm package metadata: {e}"))
        })?;
        v.get("dist-tags")
            .and_then(|t| t.get("latest"))
            .and_then(|s| s.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                AdapterError::MalformedAttestation("npm response missing dist-tags.latest".into())
            })
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
        if self.platform.is_some() {
            // buildpack-deps supplies Python, make and the C/C++ compiler; Node headers
            // ship in /usr/local/include/node. No mutable apt install at build time.
            "node:24.11.0-bookworm"
        } else {
            // npm 10 runs prepare during pack even with --ignore-scripts. npm 11
            // in this exact Node release honors the lifecycle-hook restriction.
            "node:24.11.0-bookworm-slim"
        }
    }

    fn rebuild_script(&self) -> &'static str {
        // Placeholders {REPO_URL}, {COMMIT_SHA}, {PKG_NAME}, {PKG_VERSION} are substituted by the
        // sandbox crate. Clone happens outside this script; source is mounted at /src.
        //
        // Monorepo handling: walk the source tree to find the package.json whose name+version
        // match the attested package. Run `npm ci` at the repo root (handles workspaces), then
        // `npm pack` from the target subdir.
        if self.platform.is_some() {
            concat!(
                "export CLEARHASH_NATIVE_REBUILD=1\n",
                include_str!("npm-rebuild.sh")
            )
        } else {
            include_str!("npm-rebuild.sh")
        }
    }

    fn offline_dependencies(
        &self,
        source: &std::path::Path,
    ) -> Result<Option<Vec<crate::offline::Dependency>>, AdapterError> {
        crate::offline::npm(source).map(Some)
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

#[derive(Deserialize)]
struct NativeRelease {
    name: String,
    version: String,
    os: Option<Vec<String>>,
    cpu: Option<Vec<String>>,
    libc: Option<Vec<String>>,
    dist: NativeDist,
}

#[derive(Deserialize)]
struct NativeDist {
    tarball: String,
}

// npm permits positive allowlists and negative exclusions; exclusions take precedence.
fn allows_target(values: Option<&[String]>, target: &str) -> bool {
    let Some(values) = values else { return true };
    !values.iter().any(|v| v.strip_prefix('!') == Some(target))
        && (values.is_empty()
            || values.iter().all(|v| v.starts_with('!'))
            || values.iter().any(|v| v == target || v == "any"))
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
    let (chunks, _remainder) = s.as_chunks::<4>();
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
        let u = NpmAdapter::default().artifact_url(&pkg("litellm", "1.82.7"));
        assert_eq!(
            u.as_str(),
            "https://registry.npmjs.org/litellm/-/litellm-1.82.7.tgz"
        );
    }

    #[test]
    fn artifact_url_scoped_uses_unscoped_filename() {
        let u = NpmAdapter::default().artifact_url(&pkg("@sigstore/sign", "2.3.1"));
        // The path keeps the scope, the filename does not.
        assert_eq!(
            u.as_str(),
            "https://registry.npmjs.org/@sigstore/sign/-/sign-2.3.1.tgz"
        );
    }

    #[test]
    fn attestation_url_shape() {
        let u = NpmAdapter::default()
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
        let out = NpmAdapter::default().normalize_file("package.json", input.to_vec());
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
        let claim = NpmAdapter::default()
            .parse_attestation(&serde_json::to_vec(&bundle).unwrap())
            .unwrap();
        assert_eq!(claim.commit_sha, "7c2bdaa1e5d3fa6c2e1b1a1d4f5e6c7b8a9d0e1f");
        assert!(claim.source_repo.contains("example/repo"));
    }

    fn native_metadata() -> serde_json::Value {
        serde_json::json!({
            "name": "@example/addon-linux-arm64", "version": "1.0.0",
            "os": ["linux"], "cpu": ["arm64"], "libc": ["glibc"],
            "dist": { "tarball": "https://registry.npmjs.org/custom/addon-linux-arm64.tgz" }
        })
    }

    #[test]
    fn native_release_resolves_exact_platform_tarball_and_attestation() {
        let adapter = NpmAdapter::for_platform(NpmPlatform::LinuxArm64);
        let pkg = pkg("@example/addon-linux-arm64", "1.0.0");
        assert_eq!(adapter.rebuild_platform(), Some("linux/arm64"));
        assert_eq!(adapter.rebuild_image(), "node:24.11.0-bookworm");
        assert_eq!(
            adapter.release_metadata_url(&pkg).unwrap().as_str(),
            "https://registry.npmjs.org/@example/addon-linux-arm64/1.0.0"
        );
        let release = adapter
            .parse_release_urls(&serde_json::to_vec(&native_metadata()).unwrap(), &pkg)
            .unwrap();
        assert_eq!(
            release.artifact_url.as_str(),
            "https://registry.npmjs.org/custom/addon-linux-arm64.tgz"
        );
        assert_eq!(release.attestation_url, adapter.attestation_url(&pkg));
        let js = NpmAdapter::default();
        assert_eq!(js.rebuild_platform(), None);
        assert_eq!(js.release_metadata_url(&pkg), None);
        assert_eq!(js.rebuild_image(), "node:24.11.0-bookworm-slim");
    }

    #[test]
    fn native_metadata_rejects_incompatible_or_malformed_releases() {
        let adapter = NpmAdapter::for_platform(NpmPlatform::LinuxArm64);
        let pkg = pkg("@example/addon-linux-arm64", "1.0.0");
        for (field, value) in [
            ("os", serde_json::json!(["darwin"])),
            ("os", serde_json::json!(["linux", "!linux"])),
            ("cpu", serde_json::json!(["x64"])),
            ("cpu", serde_json::json!(["!arm64"])),
            ("libc", serde_json::json!(["musl"])),
            ("cpu", serde_json::json!("arm64")),
            ("cpu", serde_json::json!([42])),
            ("name", serde_json::json!("another-package")),
            ("version", serde_json::json!("2.0.0")),
            (
                "dist",
                serde_json::json!({"tarball": "file:///tmp/addon.tgz"}),
            ),
            ("dist", serde_json::json!({"tarball": "invalid-url"})),
            ("dist", serde_json::json!({})),
        ] {
            let mut metadata = native_metadata();
            metadata[field] = value;
            assert!(
                adapter
                    .parse_release_urls(&serde_json::to_vec(&metadata).unwrap(), &pkg)
                    .is_err(),
                "accepted {metadata}"
            );
        }
        assert!(adapter.parse_release_urls(b"not json", &pkg).is_err());
        assert!(NpmAdapter::for_platform(NpmPlatform::LinuxAmd64)
            .parse_release_urls(&serde_json::to_vec(&native_metadata()).unwrap(), &pkg)
            .is_err());
    }

    #[test]
    fn npm_platform_constraints_support_allowlists_and_exclusions() {
        for (values, expected) in [
            (None, true),
            (Some(vec![]), true),
            (Some(vec!["any"]), true),
            (Some(vec!["!darwin"]), true),
            (Some(vec!["linux", "darwin"]), true),
            (Some(vec!["darwin"]), false),
            (Some(vec!["!linux"]), false),
            (Some(vec!["any", "!linux"]), false),
        ] {
            let values: Option<Vec<String>> =
                values.map(|v| v.into_iter().map(String::from).collect());
            assert_eq!(allows_target(values.as_deref(), "linux"), expected);
        }
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
        let claim = NpmAdapter::default()
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
        let claim = NpmAdapter::default()
            .parse_attestation(&serde_json::to_vec(&bundle).unwrap())
            .unwrap();
        assert_eq!(claim.commit_sha, "abcdef1234567890abcdef1234567890abcdef12");
    }
}
