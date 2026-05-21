# ClearHash roadmap

Concrete next steps, ordered by user-visible impact.

## v1.1 — full cryptographic verification

- **Full Cosign DSSE signature verification.** Today, the leaf cert is extracted and its
  issuer is checked against Fulcio's DN; the DSSE signature itself is not verified against
  the leaf's public key. v1.1 pulls in the `sigstore` crate and verifies the signature
  over the in-toto statement.
- **Full Rekor Merkle inclusion-proof verification.** Today, the Rekor log index is read
  out of `tlogEntries[0]` and required to be present. v1.1 walks the inclusion proof and
  confirms the entry is committed against a Rekor checkpoint.
- **SCT (Signed Certificate Timestamp) check.** Confirms Fulcio actually issued the cert
  (rather than someone presenting a forged cert with `O=sigstore.dev`).

## v1.2 — broader ecosystem coverage

- **PyPI end-to-end.** Scaffold is in place; needs (a) sdist URL resolution from
  `pypi.org/pypi/<pkg>/<ver>/json`, (b) PEP 740 envelope parsing, (c) `python -m build`
  rebuild flow validation. Estimated: ~1 day.
- **Cargo end-to-end with manual source pinning.** Cargo crates have no SLSA attestation;
  add `--source <git-url> --commit <sha>` flags so users can verify a crate against a
  manually-pinned source tree. The rebuild + compare pipeline already exists.
- **npm: wheel-equivalent platform-tagged tarballs.** Native modules (`fsevents`, etc.)
  publish per-platform tarballs. v1.1 verifies platform-independent JS only; v1.2 adds
  per-platform rebuilds.

## v1.3 — air-gapped rebuilds

Today the rebuild container has network access for `npm ci` / `pip install`. The lockfile
is part of the attested source, so the dependency closure is content-deterministic — but
an attacker who controls the registry could still serve different bytes for the same
content-hash within a 0-day window.

- **Pre-fetched offline dependency caches.** Walk the lockfile, fetch each dep's tarball
  on the host (verifying registry-published integrity hashes), copy into the container,
  then run `npm ci --offline` (or pip's wheel cache equivalent) with no network.
- This closes the "registry can lie during install" gap entirely.

## v2 — install-time integration

- **`clearhash-npm` PATH shim.** A wrapper binary that intercepts `npm install`, runs
  `clearhash verify` on each resolved package, and only proceeds if all match. Optional
  per-org policy: block / warn / log.
- **CI integration recipes.** GitHub Action, GitLab template, and `pre-commit` hook for
  verifying new lockfile entries on PRs.
- **VS Code extension.** Inline "verified by ClearHash" badge on `package.json` and
  `pyproject.toml` dependency lines.

## Out of scope

Per [CONTRIBUTING.md](CONTRIBUTING.md), ClearHash does not aim to:

- Detect malicious source code (use `semgrep`, `socket.dev`, `snyk`)
- Replace SCA/CVE scanners (`npm audit`, `pip-audit`, `cargo audit`)
- Sign packages — only verify
