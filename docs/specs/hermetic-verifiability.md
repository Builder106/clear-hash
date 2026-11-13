# Study plan: can attested npm and PyPI releases be verified with the network off?

Status: approved, 2026-11-11. This plan fixes the questions, sample, arms,
outcomes, and tests before any study rebuild runs. Log every later change in
`JOURNAL.md` with the reason. The paper must say which choices were made
after results were seen.

## Why this study and not a general rebuild study

The first idea was to measure how often packages with SLSA provenance rebuild
from source. Two 2026 papers already did that:

- Solarin, Kalu, Davis, and Amusuo, "Reproducibility is Not Enough: Artifact
  Verifiability in Decentralized-Build Package Ecosystems," arXiv:2608.18180.
  The study covers 34,005 artifacts across Crates.io, npm, PyPI, and RubyGems,
  stratified by attestation status, with equivalence tiers L1 to L4. With
  provenance, npm pipeline completion rose from 50.9% to 72.4%.
- Dietrich, Sun, White, and Hassanshahi, "No Snake Oil: Verifying Python
  Package Builds," arXiv:2607.21888. The study covers 12,180 PyPI releases,
  wheels only. 15.4% (Macaron) and 19.1% (OSS Rebuild) of rebuilds were byte
  identical, and 60.2% and 78.9% were equivalent after daleq4py normalization.

Both papers leave two things open. These notes come from full-text reads
through a summarizer on 2026-11-11, so check them again before citing.

1. Neither says whether rebuilds had network access, and neither compares
   networked rebuilds with rebuilds that use only hash-pinned dependencies.
   An attacker who controls a registry or mirror during a networked rebuild
   can make a tampered artifact "reproduce." ClearHash already rebuilds with
   the network off.
2. Neither tests whether its normalization is sound against an attacker.
   Solarin et al. say L3 is "not proof that all normalized differences are
   security-neutral." Dietrich et al. say their rules are "not
   machine-checked." ClearHash has the same gap. Its PyPI adapter excludes
   `PKG-INFO` and `*.egg-info/*` from the comparison.

## Audit of the current ClearHash claims

ClearHash has no corpus results to retract. The study and the paper must
account for these points.

1. **The comparison normalizes files before hashing.** npm `package.json`
   is parsed and re-serialized (key order and whitespace never count), and
   `_id`, `_integrity`, `_resolved`, `_from`, and `dist` are dropped.
   `.npmignore` is ignored. PyPI ignores `PKG-INFO`, `*.egg-info/*`, and
   `*.dist-info/*`. Symlinks and other non-regular files are skipped on both
   sides. Mode is reduced to the owner-execute bit.
2. **ClearHash uses its own rebuild recipe.** It does not replay the workflow
   named in the attestation. npm runs `npm ci`, `npm run build --if-present`, then
   `npm pack --ignore-scripts` on `node:24.11.0-bookworm-slim`, so `prepack`
   and `prepublishOnly` hooks never run. PyPI runs `python -m build --sdist`
   on `python:3.12.2-slim-bookworm`. Absolute match rates are lower bounds.
3. **The one real npm MATCH is out of date.** `npm:sigstore@2.3.1` matched
   before offline rebuilds were added. The current code refuses it because its
   lock lacks integrity hashes (journal, 2026-11-11). The README still shows
   that MATCH as current output.
4. **Cargo is out of scope.** ClearHash reads no Cargo attestations. The one
   Cargo smoke test (`ripgrep@14.1.1`) mismatched.

## Questions

- **Q1 (primary).** Among npm and PyPI releases with verified provenance, what
  share verify with the network off, using only dependencies hash-pinned at
  the attested commit? How much lower is that share than the share that verify
  when the rebuild may use the network?
- **Q2 (descriptive).** At which stage does each release fail without the
  network: missing lock, lock without hashes, unsupported lock source,
  dependency download, build, or tree comparison?
- **Q3 (security analysis).** What can an attacker change in a published
  artifact that ClearHash's normalization, and the equivalence rules
  published for OSS Rebuild, AVP (L2 and L3), and daleq4py, would not detect,
  and does the change alter what gets installed?

Q1 is the one confirmatory analysis. Q2 is descriptive. Q3 is a constructive
security analysis with fixtures and has no hypothesis test.

## Data

- **Frame source.** The deps.dev public BigQuery table
  `bigquery-public-data.deps_dev_v1.PackageVersions`, snapshot partition
  2026-11-09 (`SnapshotAt` 2026-11-09 21:00:02 UTC). Filter the partition with
  a date range, because an equality test on the displayed timestamp matches
  no rows. Run every query with `--maximum_bytes_billed`.
- **Frame counts on 2026-11-11.** Versions with a verified attestation that
  names a commit, published on or before 2026-10-31: npm 290,527 packages
  (7,458,865 versions). PyPI has 120,410 attested packages across all
  publication dates. deps.dev keeps roughly one attestation URL per PyPI
  version, usually a wheel's (119,737 packages by wheel URL, 1,482 by sdist
  URL). A direct check of `pyasn1-alt-modules` 0.4.10 found provenance on both
  its wheel and its sdist. The deps.dev URL therefore cannot tell whether an
  sdist is attested.
- **Committed inputs.** Commit the frame and sample SQL under
  `study/frame/`. Commit the exported sample CSV with its SHA-256 and the
  deps.dev partition timestamp. A test fails if the file changes.
- **Not redistributed.** Package tarballs and rebuilt trees. The released
  data holds names, versions, attestation URLs, commits, artifact hashes,
  stage outcomes, and per-file difference lists.

## Sample

- **Unit.** One release per package: the most recent version with a verified
  attestation that names a commit, published on or before
  2026-10-31 23:59:59 UTC. Ties break on version string.
- **Draw.** Order each ecosystem's packages by
  `FARM_FINGERPRINT(CONCAT('clearhash-hv-2026-11', System, Name))` and walk
  the list in that order. The order is fixed by the seed string and does not
  depend on query plans.
- **npm.** Take the first 600 packages in that order.
- **PyPI.** Walk the list in order. For each release, fetch
  `pypi.org/pypi/<name>/<version>/json` and request the sdist's Integrity API
  provenance. Keep releases with exactly one sdist that has provenance, and
  stop at 600. Record every screened release and why it was skipped (no sdist,
  sdist without provenance). The skip shares are reported under Q2.
- **Size.** n = 600 per ecosystem gives a 95% Wilson half-width of at most
  4.0 percentage points for any single proportion.
- **No exclusions after the draw.** Every sampled release gets a stage
  outcome in both arms, including native, platform-specific, and monorepo
  packages.

## Arms

Each release is rebuilt three times with the same ClearHash commit, the same
pinned image digest, and the same rebuild recipe. Only how dependencies are
obtained changes.

- **Arm H (no network).** The shipped verifier as is. Dependencies come only
  from a hash-pinned lock at the attested commit (npm v2/v3 lock with SRI
  hashes, PyPI `pylock.toml`). The container uses network mode `none`.
- **Arm N (network).** The container has network access. npm runs `npm ci`
  when a lock exists. Otherwise it runs `npm install --before=<publish time>`.
  PyPI first installs pip 26.2.2, then sets
  `PIP_UPLOADED_PRIOR_TO=<publish time>` and lets `build` fetch its backend
  from the index.
- **Arm I (inferred lock, no network).** A container with network access
  resolves the dependency closure as of the publish time and writes a
  hash-pinned lock in the format arm H reads. A committed lock that arm H
  already accepts is used as is. The build then runs exactly as in arm H,
  with the network off. Arm I separates "the project committed no usable
  lock" from "the build itself needs the network."

Arms N and I are measurement modes only. They must not be reachable from
`clearhash verify`, `clearhash-npm`, or `clearhash-ci`.

Each rebuild has a 30-minute limit. A rebuild that hits it is recorded as a
build-stage failure with reason `timeout`.

## Pilot

Before the main run, rebuild about 20 releases drawn with a different seed
string (`clearhash-hv-pilot`) to debug the tooling. Pilot results are not
findings. The paper reports that a pilot ran and which tool changes it caused.
Freeze the ClearHash commit after the pilot.

## Package-manager scope (added 2026-11-12, before any count)

The recipe installs npm dependencies with npm only, in every arm. The pilot
showed pnpm projects failing in all three arms. Adding pnpm or Yarn to arms N
and I alone would make the H-to-N gap measure package-manager support as well
as the network, so that option is ruled out. The remaining choice is between
npm only in all arms and pnpm and Yarn support in all arms, which means
extending the verifier. It is made from the input mix, never from outcomes:

1. Draw the first 100 npm releases in the pilot order (`clearhash-hv-pilot`).
2. For each attested commit, list the repository root and record which of
   `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`,
   `bun.lock`, and `bun.lockb` it contains. Releases whose root cannot be
   listed are counted as unknown and left out of the denominator.
3. A release needs pnpm or Yarn when its root has `pnpm-lock.yaml` or
   `yarn.lock` and has neither npm lockfile.
4. If at least 25% of listed releases need pnpm or Yarn, extend ClearHash to
   install from hash-pinned pnpm and Yarn locks with the network off, and use
   that support in all three arms. Otherwise keep npm only and report the
   share as a limitation.

The lockfile mix is reported as a descriptive result either way.

Result (2026-11-12): 46 of 96 listed releases (47.9%) need pnpm or Yarn, so
the verifier is extended as follows before any pnpm or Yarn rebuild runs.

### pnpm and Yarn support

The lockfile picks the package manager. npm locks take precedence over
`pnpm-lock.yaml`, which takes precedence over `yarn.lock`, so a release
already handled by npm is unchanged. A lock survey of the 46 releases found
pnpm lockfile 9.0 in all 38 pnpm roots, Yarn 2 or later in 7 of 8 Yarn roots
(lock formats 6 to 10), and Yarn 1 in one.

- **pnpm (lockfile 9.0 only).** Every `packages` entry must carry an SRI
  `integrity`. Registry entries are fetched from `registry.npmjs.org`;
  entries with a git, directory, or non-registry tarball resolution are
  rejected at the lock stage, as git sources already are for npm. Entries
  whose `os`, `cpu`, or `libc` excludes the build platform are skipped,
  because pnpm skips them too.
- **Yarn 1.** Every entry must carry a SHA-256, SHA-384, or SHA-512
  `integrity`. SHA-1-only entries are rejected, as for npm.
- **Yarn 2 and later.** The lock's `checksum` covers Yarn's own zip of the
  package, not the registry tarball, so the host cannot check the tarball
  against the lock. The host checks each tarball against the `dist.integrity`
  that `registry.npmjs.org` publishes for that exact version, and Yarn
  checks the lock checksum inside the network-off container with
  `checksumBehavior: throw`. `npm:` resolutions are fetched; `workspace:`,
  `link:`, `portal:`, and `patch:` entries need no download; any other
  protocol is rejected at the lock stage.
  Every entry is fetched whatever its platform, because Yarn fetches some
  packages for other platforms, such as the base of its built-in patches.
  Yarn leaves the checksum out of platform-specific entries (those with
  `conditions`) that the locking machine never fetched. Such entries rest
  on the registry integrity alone; any other entry without a checksum is
  rejected.

Inside the network-off container, a loopback-only server started by the
recipe serves the verified tarballs at registry paths to pnpm and Yarn 2+,
and stops before any build code runs. Yarn 1 reads them as an offline
mirror. Install, build, and pack use the project's package manager
(`pnpm pack`, `yarn pack`), because those rewrite `workspace:` and `catalog:`
ranges in the packed `package.json` and `npm pack` does not. Dependency
lifecycle scripts stay disabled. `yarn pack` in Yarn 2+ has no switch to
skip the project's own `prepack` and `postpack`, so those run for Yarn 2+
projects, in every arm alike. pnpm 11 and later check each locked
package's age (`minimumReleaseAge`) and trust history against registry
metadata after install. Those checks compare publish dates with the day of
the run, not with the release, so they are turned off in every arm.

**The package manager itself** is fetched on the host and mounted read-only
at `/tools` in all three arms, so arm N uses the same binary as arm H:

1. A committed Yarn `yarnPath` release is used as is (pinned by Git).
2. Otherwise `packageManager` names the version. A `+sha512` hash pins the
   pnpm 9 to 11 tarball. pnpm 12 ships a native binary in
   `@pnpm/exe.linux-<arch>`, which that hash does not cover, so its
   tarball, like any unhashed pin, is checked against the registry's
   published integrity. Yarn 2+ comes from `@yarnpkg/cli-dist`.
3. With no `packageManager`, pnpm 10.34.9 and Yarn 1.22.22 are used, pinned
   by hash in ClearHash. Yarn 2+ with no pin is rejected at the lock stage.

Arm I still writes or completes an npm lock when the root has no lock or an
npm lock that arm H rejects. A committed pnpm or Yarn lock that arm H
rejects is not re-resolved, so arm I records the same lock-stage failure. Re-resolving would replace the
dependency set the project chose, which arm I is not meant to measure.

## Outcomes

For each release and arm, record the first failing stage: attestation,
source checkout, dependency lock, dependency fetch, build, comparison. On
comparison, record the result at two levels:

- **T1 (primary): ClearHash normalized tree match**, as the shipped verifier
  computes it.
- **T0: strict per-file match.** Same regular files and symlinks, same bytes
  (a symlink's bytes are its target path), and the same owner-execute bit,
  with no `package.json` rewrite and no ignore list. Archive container
  differences (gzip, tar order, mtimes) still do not count.

Record the diff list, durations, image digests, and the ClearHash commit in a
JSONL ledger with one line per release and arm.

## Model

- **Primary estimand.** For each ecosystem, the T1 match rates in arm H and
  arm N and their paired difference (N minus H), with 95% CIs. Single rates
  use Wilson intervals. The paired difference uses the Newcombe interval for
  paired proportions.
- **Confirmatory test.** Exact McNemar test on the discordant pairs for each
  ecosystem. Holm correction across the two ecosystems at α = 0.05. Arm H is
  expected to match no more often than arm N, so the test mainly confirms
  direction. The contribution is the size of the gap and the Q2 breakdown.
- **Degenerate case.** If arm H has fewer than 10 T1 matches in PyPI (likely,
  since few projects commit `pylock.toml`), PyPI is reported descriptively and
  the McNemar test runs for npm only. That family then has one test.
- **Secondary.** Arm I rates and the paired differences I minus H and N minus
  I, with Newcombe intervals. These are outside the confirmatory family.
- **Exploratory.** T0 rates. Gap by dependent-count tier from deps.dev.
  Comparison of arm N rates with the Solarin et al. npm completion figure.
  These are labeled exploratory in the paper.

## Q3 method

1. List every normalization and exclusion rule in ClearHash, and the rules
   documented for OSS Rebuild stabilizers, AVP L2/L3, and daleq4py. Use each
   tool's source or paper.
2. For each rule, construct a fixture package with a change confined to the
   normalized or excluded content. Install it with the real package manager
   or build backend and check whether installed behavior or metadata changes.
3. Record each rule as sound, unsound with a working fixture, or untested.
4. First candidate: PyPI sdist `PKG-INFO` and `*.egg-info/*`. Check whether
   setuptools reads `egg-info` files (for example `requires.txt` or
   `SOURCES.txt`) when building a wheel from an sdist. Do not claim an escape
   until a fixture shows it.

Fixtures are constructed test inputs. Label them as fixtures in their file
names and test files. If an escape affects another tool, finish coordinated
disclosure with its maintainers before the paper gets a DOI.

## ClearHash changes needed

Each change is its own commit with tests. Freeze the tool at a tagged commit
before the main run.

1. A `clearhash-study` binary (separate from the verifier binaries) that
   reads the sample CSV, runs the three arms, writes the ledger, and resumes
   after interruption.
2. A stage-classified result for each arm, so that each failure maps to one
   stage instead of exit codes 1 to 3. The raw error text is kept in the
   ledger. Sub-reasons within a stage are assigned at analysis time by a
   committed, documented mapping.
3. The arm N and arm I dependency modes, callable only from
   `clearhash-study`.
4. T0 comparison alongside T1.
5. Cleanup of the rebuild container on every exit path and of work
   directories after each release, so the run fits the build host's free
   disk.
6. Network-off pnpm and Yarn installs, as set out under Package-manager
   scope.
7. Source fetched at depth 1 (added 2026-11-13, from the pilot). A full
   clone of `fontsource/font-files` holds 19 GB of history against a 5 GB
   tree at the attested commit, and filled the build disk. The verifier now
   fetches only the attested commit, as `actions/checkout` does by default,
   and falls back to a full fetch when a server refuses a single commit.
   `HEAD` is still checked against the attested commit. Builds that read
   Git history (tags, `git describe`) see only that commit, in every arm.

Statistics run in a small locked Python environment under `study/analysis/`.

## What the paper will claim

Only what Q1 to Q3 measure: rates and gaps for this frame, snapshot, recipe,
and image set. Absolute rates are lower bounds, because the recipe is not the
publisher's workflow and the build host is Linux ARM64. The paired gap is not
affected by either, because both arms share them. Nothing is said about
packages without provenance or about Cargo.

## Decisions made at approval (2026-11-11)

1. Arm I is added (see Arms).
2. Arm N bounds PyPI resolution with pip's `--uploaded-prior-to`, added in
   pip 26.0, through `PIP_UPLOADED_PRIOR_TO`. npm uses `--before`.
3. Venue: arXiv preprint first, then a software supply-chain security
   workshop such as ACM SCORED. Confirm the current call for papers before
   formatting. `tracks.md` lists only IEEE S&P, USENIX Security, ACM CCS, and
   NDSS, which are a stretch for this scope.

## Release

Preprint on arXiv, `cs.CR` with a `cs.SE` cross-list. Code, frame SQL, sample
CSV, ledger, and analysis go to Zenodo as a supplement linked to the arXiv DOI.
