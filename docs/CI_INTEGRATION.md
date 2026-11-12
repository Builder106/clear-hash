# CI lockfile verification

`clearhash-ci` verifies new npm lockfile entries on pull/merge requests and before
commits. Install it together with `clearhash` from a reviewed ClearHash revision:

```sh
git clone https://github.com/Builder106/clear-hash.git
cd clear-hash
git checkout --detach <reviewed-full-commit-sha>
cargo install --locked --path crates/clearhash-cli --bin clearhash --bin clearhash-ci
```

The runner needs Git, a running Docker daemon, and host network access for registry
downloads, source checkouts, and pinned rebuild images. Building the CLI also needs
Rust 1.88+. npm itself is not required on the host. Rebuilds run package build code
inside Docker; use isolated, disposable runners for untrusted contributions.

## Comparison contract

Run from anywhere inside the consumer repository; lock paths are relative to its root:

```sh
clearhash-ci --base <trusted-base-commit-sha>
clearhash-ci --base origin/main --lockfile services/api/package-lock.json
clearhash-ci --staged
```

The base must already exist locally. CI should supply the PR/MR's trusted base SHA,
not a value selected by the contribution. Missing/shallow refs fail with instructions
to fetch them; they never become an empty baseline. A missing lock in a valid base
means all current entries are new. `--staged` compares index blobs to `HEAD`, including
the first commit, and ignores unstaged working-tree edits. It conflicts with `--base`.

Supported input is npm `package-lock.json` or `npm-shrinkwrap.json`, lockfile version
2 or 3. Both old and current effective locks must use the supported subset.
A sibling shrinkwrap takes precedence independently in the old and new
snapshots. Nested lock paths work; run once per project. Yarn, pnpm, PyPI and Cargo
lock formats are outside this recipe's scope. Workspace links, bundled/local/Git
dependencies, missing integrity and non-HTTPS resolved URLs are rejected, matching
the install shim's strict registry-only lock parser. Missing/deleted current locks,
symlinks and unresolved index conflicts also fail closed.

Every unique added or changed `(name, version, integrity)` tuple invokes:

```sh
clearhash verify npm:<actual-name>@<exact-version> --expected-integrity <locked-SRI>
```

This includes nested, aliased, development, peer and optional dependencies. Duplicate
tuples and moves within the lock are checked once; unchanged tuples and removals are
not rebuilt. Changing only an integrity value forces verification. Registry artifact
bytes must match the locked SRI before provenance verification and source rebuild.
The lock is read without resolving dependencies, installing packages, or running
host lifecycle hooks. Verification still requires attestations and source locks
compatible with offline rebuilds; an unattested or unrebuildable package blocks
the gate. Native packages needing an explicit platform require a separate verification
job; this helper uses the standard JavaScript verification path.

Exit codes: `0` means all selected packages matched (or there were no additions),
`1` means at least one verification failed, `3` means configuration, lock parsing,
Git or process execution failed. Invalid CLI arguments use clap's exit code `2`.
All verifier failure codes and signal termination block the gate, without warn/log
policy overrides. Progress and per-package JSON records go to stderr alongside
the verifier's output. By default the sibling `clearhash` executable is used;
`CLEARHASH_VERIFY_BIN` can select an absolute trusted verifier path.

This is an incremental gate: it assumes existing base entries have already been
reviewed/verified. It does not certify the complete lock or prevent deleting a
dependency. Keep CI configuration and the trusted baseline under review.

## GitHub Action

The root `action.yml` is a composite action. It builds both binaries from the action
revision you select. Pin that revision to a reviewed full commit SHA; replace the
placeholder below. Use a Linux runner with Docker and Rust 1.88+ installed. The
standard Ubuntu hosted runner supplies these tools.

```yaml
name: Verify dependency additions
on:
  pull_request:
    paths:
      - package-lock.json
      - npm-shrinkwrap.json
permissions:
  contents: read
jobs:
  clearhash:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: Builder106/clear-hash@<reviewed-full-commit-sha>
        with:
          base: ${{ github.event.pull_request.base.sha }}
          lockfile: package-lock.json
```

Use `pull_request` with read-only permissions and no repository secrets. Do not run
contribution-controlled checkout/build steps in a privileged `pull_request_target`
workflow. For several projects, use a job matrix and pass each project's lock path;
update the workflow's path filters to match.

## GitLab template

Copy [ci/gitlab/clearhash.yml](../ci/gitlab/clearhash.yml) into your consumer repository
at the same path. The hidden job expects the CLI pair to be installed on a Linux
shell runner from a reviewed revision using the installation commands above. The
runner must provide Docker and network access. It does not require Docker-in-Docker
or a privileged container job. Assign a disposable runner suitable for untrusted
MRs; do not expose protected variables or production hosts to those jobs.

```yaml
include:
  - local: /ci/gitlab/clearhash.yml

verify-dependency-additions:
  extends: .clearhash-lockfile
  # Optional: tags selecting your prepared Linux shell runner.
  # tags: [clearhash]
```

The template uses `CI_MERGE_REQUEST_DIFF_BASE_SHA` for the baseline and requests a
full clone (`GIT_DEPTH: "0"`). Non-MR pipelines skip the job. For a nested project,
override `CLEARHASH_LOCKFILE`; use multiple extending jobs to check multiple locks.
The `.pre` stage is built in, so no custom stage list is required.

## pre-commit

Install the CLI pair as described above, then add this to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/Builder106/clear-hash
    rev: <reviewed-full-commit-sha>
    hooks:
      - id: clearhash-lockfile
```

Run `pre-commit install`. The `system` hook uses the installed CLI pair and Docker;
pre-commit does not compile or update ClearHash. Keep the installed version aligned
with the hook revision. It receives no filenames and checks the staged root lock
against `HEAD`. For a nested project, override `files` and `args`:

```yaml
      - id: clearhash-lockfile
        files: ^services/api/(package-lock\.json|npm-shrinkwrap\.json)$
        args: [--lockfile, services/api/package-lock.json]
```

`pre-commit run clearhash-lockfile --all-files` still checks the index; stage the
intended lock changes first. Local hooks are convenience checks and can be bypassed
by developers, so keep the CI gate as well.

Platform references: [composite actions](https://docs.github.com/en/actions/tutorials/create-actions/create-a-composite-action),
[GitLab predefined variables](https://docs.gitlab.com/ci/variables/predefined_variables/),
[GitLab YAML](https://docs.gitlab.com/ci/yaml/), and
[pre-commit hook configuration](https://pre-commit.com/#new-hooks).
