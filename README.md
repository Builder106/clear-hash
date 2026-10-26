<picture>
  <source media="(prefers-color-scheme: dark)"  srcset="assets/banner-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="assets/banner-light.png">
  <img alt="ClearHash: A digital tamper-proof seal for software" src="assets/banner-dark.png">
</picture>

[![CI](https://img.shields.io/badge/CI-passing-success.svg)](.github/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Ecosystems](https://img.shields.io/badge/ecosystems-npm%20%7C%20PyPI%20%7C%20Cargo-7c3aed.svg)
[![Sigstore](https://img.shields.io/badge/SLSA-Sigstore%20%2B%20Rekor-22c55e.svg)](https://www.sigstore.dev/)
[![Demo](https://img.shields.io/badge/demo-clearhash.vercel.app-success.svg)](https://clearhash.vercel.app/)

> **A digital tamper-proof seal for software.** ClearHash verifies that downloaded packages match their exact original source code byte-for-byte.

## 💡 What is ClearHash?

Think of ClearHash like a verified safety seal on food packaging. When developers publish software, bad actors can secretly alter the final download. ClearHash independently rebuilds the software from scratch and checks every byte to prove nobody modified the program between the original source code and your computer.

ClearHash acts as a pre-install gatekeeper. It fetches a package, verifies its SLSA attestation through Sigstore and Rekor, rebuilds it from the attested source commit in an isolated Docker container, and compares the rebuilt file tree against the registry artifact. If anything differs, the install is blocked.

ClearHash answers a question almost nothing in the existing supply chain answers:
**"Is the binary I am about to install actually a build of the source code it claims to be?"**

---

## What it catches

The supply-chain attacks of the last five years (event-stream, ua-parser-js, the
post-install crypto-wallet stealers, xz-utils) all share one shape: the registry tarball
diverges from the source repo. Existing tools verify *who* signed the tarball (Cosign), or
*that the tarball matches itself across mirrors*(Sigstore transparency), but not*whether
the tarball is what the source code would produce*.

ClearHash actually does the rebuild and the comparison.

```text
$ clearhash verify npm:sigstore@2.3.1
[1/5] Fetching sigstore from npm
      sha256: 1b5041a35f86125db7f872742502470753fd2e1109521b7dbff8a61d229a03c2
[2/5] Verifying Sigstore attestation
      commit: 46e7056ff991  (workflow: https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main)
[3/5] Spinning up rebuild container (node:20.11.1-bookworm-slim)
[4/5] Rebuilding from source at commit 46e7056ff991
      built: /tmp/clearhash-rebuild-CuR0xW/rebuilt/out/sigstore-2.3.1.tgz
[5/5] Comparing file trees

✓ MATCH npm:sigstore@2.3.1 tree-hash ec714016d7e4ce742f9aa23b6f16f19cb967bf82b78c343297013dcc268b107e
```

A tampered package gets a different ending. To see what ClearHash actually catches, run
the verify with `--simulate-tamper`, which deliberately modifies the registry-extracted
tree before comparison (the underlying package from npm is clean; the simulation is
clearly announced):

```text
$ clearhash verify --simulate-tamper npm:sigstore@2.3.1
⚠ TAMPER SIMULATION: The registry-extracted tree will be modified before comparison (All mode).
                      The MISMATCH below is real but the registry package is clean.
[1/5] Fetching sigstore from npm
[2/5] Verifying Sigstore attestation
[3/5] Spinning up rebuild container (node:20.11.1-bookworm-slim)
[4/5] Rebuilding from source at commit 46e7056ff991
[5/5] Comparing file trees
      · tampered injectedpayload: dist/.clearhash-tamper-demo.js (added a file that the source rebuild did not produce)
      · tampered contentswap:    dist/index.js                  (appended bytes to an existing file)
      · tampered modeflip:       dist/index.js                  (flipped the executable bit)
      · tampered deletion:       README.md                       (removed a file)

✗ MISMATCH npm:sigstore@2.3.1: 4 difference(s)
    OnlyInRegistry  { path: "dist/.clearhash-tamper-demo.js" }
    ContentDiffers  { path: "dist/index.js" }
    ModeDiffers     { path: "dist/index.js" }
    OnlyInRebuild   { path: "README.md" }
```

The four tamper modes (`injected-payload`, `content-swap`, `mode-flip`, `deletion`, or
`all`) each surface a different diff category. Useful for demos, screenshots, and writing
integration tests against the diff-rendering paths without needing an actual malicious
package.

### Live demos

<details>
<summary><strong>clearhash verify npm:sigstore@2.3.1</strong> — full pipeline (~36s, 4× playback)</summary>

![verify demo](assets/demo-verify.gif)

</details>

<details>
<summary><strong>clearhash inspect npm:sigstore@2.3.1</strong> — attestation summary, no rebuild</summary>

![inspect demo](assets/demo-inspect.gif)

</details>

---

## How it works

1. Download the artifact and its SLSA attestation from npm, PyPI, or crates.io.
2. Check that the attestation's certificate was issued by Fulcio, that it references a Rekor log entry, and that its workflow URI names the source repository.
3. Clone the source repository, check out the attested commit, and confirm that `HEAD` matches it.
4. Rebuild the package in a pinned Docker image (`npm pack`, `python -m build --sdist`, or `cargo package`).
5. Extract both archives, drop the metadata the registry adds, and compare their Merkle-hashed file trees. A match exits 0. A mismatch exits 1 with a per-file diff.

The comparison model is **file-tree content hash**, not byte-identical tarball SHA-256.
Strict byte equality is difficult to achieve reliably due to npm package ordering, gzip compression levels, and registry-injected `package.json` metadata variations between `npm pack` invocations. ClearHash normalizes both sides (strips timestamps, normalizes file permissions, and drops registry-injected fields) and compares a cryptographic hash tree over the resulting file tree.

---

## Try it without installing

A hosted instance of the **inspect** endpoint runs at
[**clearhash.vercel.app**](https://clearhash.vercel.app). It performs package retrieval and certificate verification in the cloud. The full **verify** flow runs in the CLI because it requires a local Docker engine to perform safe rebuilds.

```bash
curl 'https://clearhash.vercel.app/api/inspect?package=npm:sigstore@2.3.1'
```

Or paste a package into the form at [`/inspect`](https://clearhash.vercel.app/inspect).

## Install the CLI

Requires Rust 1.88+ and a running Docker daemon (Docker Desktop or OrbStack on macOS).

```bash
git clone https://github.com/Builder106/clear-hash.git
cd clear-hash
cargo install --path crates/clearhash-cli
clearhash --version
```

---

## Use

```bash
# Full pipeline: fetch + attest + rebuild + compare
clearhash verify npm:sigstore@2.3.1

# Just fetch + parse the attestation envelope (no docker required)
clearhash inspect npm:sigstore@2.3.1

# JSON output for CI
clearhash verify npm:sigstore@2.3.1 --json

# Cargo packages without signatures: opt in explicitly
clearhash verify --allow-unattested cargo:serde@1.0.197

# Keep the temporary folder to inspect a mismatch
clearhash verify npm:foo@1.0.0 --keep-workdir

# Demo: deliberately simulate a modified package to test diff rendering
clearhash verify --simulate-tamper npm:sigstore@2.3.1
clearhash verify --simulate-tamper=content-swap npm:sigstore@2.3.1
```

## Exit codes

| Code | Meaning |
| ---- | ------------------------------------------------------------- |
| 0    | Tree-hash match. Safe to install. |
| 1    | Tree-hash mismatch or invalid signature. Block installation. |
| 2    | No signature found, and `--allow-unattested` was not passed. |
| 3    | Infrastructure failure (no docker, network down, etc.). |

---

## Ecosystem support

| Ecosystem | Status | Attestation source | Rebuild image |
| --------- | ------------------- | ---------------------------------------------- | ----------------------------- |
| **npm**   | ✅ end-to-end | `registry.npmjs.org/-/npm/v1/attestations/...` | `node:20.11.1-bookworm-slim` |
| **PyPI**  | 🚧 adapter scaffold | PEP 740 `/integrity/.../provenance` | `python:3.12.2-slim-bookworm` |
| **Cargo** | 🚧 adapter scaffold | none (`--allow-unattested` required) | `rust:1.78-slim-bookworm` |

The npm path is end-to-end working today. PyPI and Cargo land their full rebuild flows
behind the same adapter interface without engine changes.

---

## What v1 verifies (and what's deferred to v1.1)

**v1 (today):**

- Envelope structural integrity (SLSA v0.2 *and* v1 in-toto statements)
- X.509 leaf certificate extraction from the Sigstore bundle
- Issuer = Fulcio (rejects bundles with non-Fulcio leaf certs)
- Subject Alternative Name → GitHub Actions workflow URI
- **Cross-check**: workflow URI's `owner/repo` segment matches the attested source repo
- Rekor transparency-log entry presence
- Source repo `git clone`+ commit pinning with`HEAD == attested-commit` verification
- Network-isolated rebuild container (default bridge; build needs network for `npm ci`)
- File-tree Merkle compare with per-file diff output

**v1.1 (next):**

- Full Cosign DSSE signature verification using the leaf cert's public key
- Full Rekor Merkle inclusion-proof verification
- Air-gapped rebuilds via pre-fetched offline dep caches
- Wheel verification for PyPI (currently only sdists)

---

## Architecture

```text
ClearHash/
├── crates/
│   ├── clearhash-cli/             # CLI binary; clap, console, tokio
│   ├── clearhash-web/             # bin + lib; shared Axum router (clearhash_web::app)
│   ├── clearhash-core/            # shared types: PackageRef, ProvenanceClaim, FileTreeHash
│   ├── clearhash-registry/        # reqwest fetchers
│   ├── clearhash-provenance/      # Sigstore + Rekor + envelope parsing
│   ├── clearhash-sandbox/         # bollard Docker orchestration + tree compare
│   └── clearhash-ecosystems/      # EcosystemAdapter trait + npm/pypi/cargo impls
├── api/
│   └── clearhash.rs               # Vercel function; wraps clearhash_web::app with VercelLayer
├── Cargo.toml                     # workspace root *and* a [package] that builds api/clearhash.rs
├── vercel.json                    # Vercel rewrites + runtime config
├── Dockerfile                     # alternative: multi-stage build of clearhash-web binary
└── fly.toml                       # Fly.io deployment config (Docker-based)
```

Every ecosystem-specific quirk lives behind `EcosystemAdapter`. Engine crates depend only
on the trait — adding a new ecosystem is one new file under `clearhash-ecosystems/src/`.

## Deploy your own

The web frontend can deploy two ways. The primary target is **Vercel** — the entire Axum
router runs as a single Rust serverless function via the
[official Vercel Rust runtime](https://vercel.com/docs/functions/runtimes/rust). The
secondary target is any Dockerfile-friendly host (Fly.io, Render, Railway, plain VPS).

### Vercel (recommended)

```bash
# One-time: link this repo to a new Vercel project
vercel link

# Deploy
vercel deploy --prod
```

Vercel auto-detects [vercel.json](vercel.json) and the root `[package]`+`[[bin]]` entries
in [Cargo.toml](Cargo.toml). The function binary is built from [api/clearhash.rs](api/clearhash.rs),
which wraps the shared `clearhash_web::app`router with`vercel_runtime::axum::VercelLayer`
so every route runs through the same handler that powers the local server.

## Docker (Fly.io / Render / Railway)

```bash
# Fly.io (one-time)
flyctl launch --copy-config --no-deploy
flyctl deploy

# Or build + run locally
docker build -t clearhash-web .
docker run --rm -p 8080:8080 clearhash-web
open http://localhost:8080
```

The deployed Docker image is ~158 MB (debian:bookworm-slim + the ~5 MB Rust binary + assets).
No registry credentials, no DB, no secrets — it just proxies the live npm/PyPI APIs.

---

## Caveats and threat model

ClearHash narrows the attack surface from "the registry served you whatever it wanted" to
"the registry served you the artifact that the attested source code produces, built by
the workflow that signed the attestation." Caveats:

1. **The lockfile is part of the trust root.** If `package-lock.json` itself has been

   tampered with at HEAD of the attested commit, the rebuild will faithfully reproduce
   the tampered tree. This is correct: the attestation says "this is what the source
   produces" — the rebuild verifies that claim, not "the source is benign."

2. **The rebuild container has network access** for dependency installs (`npm ci`,

   `pip install`, `cargo download`). `--ignore-scripts` blocks the highest-impact
   exfiltration path (lifecycle hooks). Fully air-gapped builds are v1.1.

3. **Determinism failures look identical to tampering.** If `npm pack` is genuinely

   non-deterministic for a given package (e.g. embeds a hostname), ClearHash flags it
   as a mismatch. The `--keep-workdir` flag is for triaging these cases.

4. **Docker is required.** No daemon, no verification. macOS users: Docker Desktop or

   OrbStack.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

[MIT](LICENSE).
