# ClearHash Verification & Architecture Specification

This document details the cryptographic attestation pipeline, container isolation guarantees, and differential tree matching algorithms implemented in ClearHash.

## Pipeline Architecture

ClearHash verifies supply-chain integrity through a five-stage pipeline:

1. **Registry Artifact Retrieval**: ClearHash downloads the package tarball from the upstream registry (npm, PyPI, or Cargo) and calculates its SHA-256 digest.
2. **Attestation Validation**: ClearHash extracts the SLSA provenance statement, checks the leaf certificate issuer against Fulcio's DN, verifies the Cosign DSSE signature over the in-toto statement using the leaf certificate's public key, and verifies embedded Signed Certificate Timestamps (SCTs) against pinned Sigstore Certificate Transparency log keys and Fulcio CA SPKI hashes to prove Fulcio issuance. It verifies the Rekor v1 checkpoint signature against the pinned production log key, requires the proof's root and tree size to match that checkpoint, and verifies the canonical entry's Merkle inclusion path. The logged payload hash, verified signature, and certificate must match this attestation. Rekor's signed entry timestamp authenticates the global index when it differs from the shard-local proof index. Missing proofs, invalid SCTs, and unsupported logs or entry formats fail closed.
3. **Container Sandbox Rebuild**: ClearHash clones the attested source repository on the host, checks out the exact commit, and confirms that `HEAD` matches it. For npm and PyPI, it walks the committed dependency lock, downloads archives over HTTPS on the host, and verifies their hashes before mounting the cache read-only into a fresh container with network mode `none`. The ecosystem's pinned Docker image runs the offline install and rebuild there. Cargo packaging retains its existing network policy.
4. **Differential Tree Hash Comparison**: ClearHash unpacks both the rebuilt tarball and the registry tarball into temporary trees and hashes each file by its content and executable bit, ignoring timestamps.
5. **Verdict Generation**: If the file trees match, ClearHash outputs a success verdict. If any injected files, content changes, mode flips, or missing files are detected, ClearHash returns a non-zero exit code and displays the exact diff breakdown.

## Differential Classification Taxonomy

ClearHash categorizes all tree discrepancies into four distinct categories:

| Category | Description | Example |
| --- | --- | --- |
| `OnlyInRegistry` | File exists in the registry tarball but not produced by source rebuild | Injected post-build backdoor script |
| `ContentDiffers` | File exists in both trees but byte hashes differ | Modified source file or altered binary build artifact |
| `ModeDiffers` | File contents match but POSIX executable bits differ | Executable bit added to non-executable script |
| `OnlyInRebuild` | File produced by source rebuild but missing from registry tarball | Excluded source file or deleted test asset |

## Security & Sandbox Boundaries

- **Container Isolation**: Rebuild steps run in read-only container root filesystems with dropped Linux capabilities (`--cap-drop=ALL`) and non-root UID execution.
- **Offline Dependency Cache**: npm lockfiles (v2/v3, including shrinkwrap) supply resolved tarball URLs and SHA-256/384/512 SRI hashes; PyPI pylock.toml files supply build-tool wheel URLs and SHA-256 hashes. The host verifies bytes against these committed hashes without running package code. Only verified archives enter the fresh cache, mounted at `/deps:ro`. npm uses `ci --offline --ignore-scripts`; PyPI uses a fresh venv and an offline wheelhouse, including backend isolation. Both containers run with network mode `none`. Incomplete locks, unsupported sources, hash mismatches, and missing wheels fail closed.
