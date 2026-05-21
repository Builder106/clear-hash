# Contributing

Thanks for your interest. This is a young project — patch reviews are quick.

## Dev setup

```bash
git clone https://github.com/Builder106/ClearHash.git
cd ClearHash
cargo build --workspace
cargo test --workspace
```

You'll need:

- Rust 1.88+
- A running Docker daemon (Docker Desktop, OrbStack, or `colima` on macOS; native on Linux)
- ~2 GB free disk for rebuild image layers

## Run the live demo

```bash
cargo run --bin clearhash -- verify npm:sigstore@2.3.1
```

The first run pulls `node:20.11.1-bookworm-slim` (~150 MB) and clones the sigstore-js
repo. Subsequent runs are cached.

## Project-specific guardrails

- **No skipping `--ignore-scripts`.** The npm rebuild script always passes
  `--ignore-scripts`. If your change needs lifecycle hooks, you've found a real determinism
  problem — fix it upstream, don't broaden the threat model.
- **Pin every Docker image to an exact patch version.** No `node:20`, no `node:latest`.
  CI updates pins via Renovate.
- **Adapter additions go in `clearhash-ecosystems/src/<name>.rs`.** Engine crates
  (`registry`, `provenance`, `sandbox`) should never grow ecosystem-specific branches.

## Tests

```bash
cargo test --workspace                          # unit + integration
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

Integration tests that hit Docker are gated on a reachable daemon and skip otherwise.

## Commit-message convention

One line, present-tense, no Claude/AI co-author trailers. Reference an issue if applicable.

```
fix(sandbox): handle monorepo subdirs in npm rebuild script
```

## PR process

1. One PR = one logical change. Refactors live in their own PR.
2. CI must be green.
3. Add a test that fails before your change and passes after.
4. Update `README.md` if you changed user-visible behavior (CLI flags, exit codes).

## Out of scope

To keep the surface honest, ClearHash explicitly *does not* try to:

- Detect *malicious source code*. ClearHash verifies that the binary matches the source.
  It does not judge whether the source is benign. Pair it with static analysis.
- Replace `npm audit` / `pip-audit` / `cargo audit`. Those check known CVEs in your
  dependency tree. ClearHash checks artifact provenance.
- Wrap `npm install` itself. v1 is a verifier you run before/in-CI alongside install.
  PATH-shim integration is on the v1.2 roadmap.

If a PR's purpose is one of the above, please open an issue first to discuss.
