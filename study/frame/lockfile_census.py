"""Lockfile census for the package-manager scope rule in
docs/specs/hermetic-verifiability.md.

Reads a JSON Lines sample, lists each attested commit's repository root
through the GitHub API (`gh api`), and writes one JSON line per release with
the lockfiles found. Prints the share that needs pnpm or Yarn.

Usage: python3 lockfile_census.py SAMPLE.jsonl OUT.jsonl
"""

import json
import re
import subprocess
import sys

LOCKFILES = [
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
    "bun.lockb",
]
GITHUB = re.compile(r"github\.com[/:]([^/]+)/([^/@#?]+?)(?:\.git)?(?:[@#?/].*)?$")


def root_files(source_repo, commit):
    match = GITHUB.search(source_repo or "")
    if not match:
        return None, "not_github"
    owner, repo = match.groups()
    result = subprocess.run(
        ["gh", "api", f"repos/{owner}/{repo}/contents?ref={commit}", "--jq", ".[].name"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None, "listing_failed"
    return set(result.stdout.split()), None


def classify(files):
    npm = {"package-lock.json", "npm-shrinkwrap.json"} & files
    other = {"pnpm-lock.yaml", "yarn.lock"} & files
    return bool(other) and not npm


def main(sample_path, out_path):
    listed = needs = 0
    with open(sample_path) as sample, open(out_path, "w") as out:
        for line in sample:
            release = json.loads(line)
            files, problem = root_files(release.get("source_repo"), release.get("commit"))
            row = {key: release[key] for key in ("name", "version", "source_repo", "commit")}
            if files is None:
                row.update(status=problem)
            else:
                listed += 1
                row.update(
                    status="listed",
                    lockfiles=[name for name in LOCKFILES if name in files],
                    needs_pnpm_or_yarn=classify(files),
                )
                needs += row["needs_pnpm_or_yarn"]
            out.write(json.dumps(row, separators=(",", ":")) + "\n")
    share = needs / listed if listed else float("nan")
    print(f"listed {listed}; need pnpm or Yarn {needs} ({share:.1%})")


if __name__ == "__main__":
    main(*sys.argv[1:3])
