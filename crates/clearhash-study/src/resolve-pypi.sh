set -eu
# Arm I resolver (network on). Writes /src/pylock.toml with the wheel closure that
# the offline sdist build needs: `build` and its dependencies, then the backend's
# static and dynamic sdist requirements. All resolved as of the publish time.
cd /src
# {LOCATE_PROJECT}
export PIP_CONFIG_FILE=/dev/null
export PIP_DISABLE_PIP_VERSION_CHECK=1
python -m venv /tmp/clearhash-resolver
/tmp/clearhash-resolver/bin/python -m pip install --quiet pip==26.2.2
if [ -n "${CLEARHASH_RESOLVE_BEFORE:-}" ]; then
  export PIP_UPLOADED_PRIOR_TO="$CLEARHASH_RESOLVE_BEFORE"
fi
/tmp/clearhash-resolver/bin/python -m pip install --quiet build
/tmp/clearhash-resolver/bin/python - <<'PY'
import json
import subprocess
import sys
import tempfile
from importlib.metadata import version

import build
import build.env


def wheels(requirements):
    with tempfile.NamedTemporaryFile(suffix=".json") as report:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet", "--dry-run",
             "--ignore-installed", "--only-binary", ":all:",
             "--report", report.name, *requirements],
            check=True,
        )
        with open(report.name) as handle:
            return json.load(handle)["install"]


with build.env.DefaultIsolatedEnv() as env:
    builder = build.ProjectBuilder.from_isolated_env(env, ".")
    env.install(builder.build_system_requires)
    backend = sorted(builder.build_system_requires | builder.get_requires_for_build("sdist"))

locked = {}
for group in ([f"build=={version('build')}"], backend):
    if not group:
        continue
    for item in wheels(group):
        info = item["download_info"]
        hashes = info.get("archive_info", {}).get("hashes", {})
        digest = hashes.get("sha256")
        if digest is None:
            algorithm, _, value = info["archive_info"]["hash"].partition("=")
            if algorithm != "sha256":
                sys.exit(f"no sha256 for {info['url']}")
            digest = value
        locked[info["url"]] = (item["metadata"]["name"], item["metadata"]["version"], digest)

lines = ['lock-version = "1.0"', 'created-by = "clearhash-study"']
for url, (name, ver, digest) in sorted(locked.items()):
    lines += [
        "",
        "[[packages]]",
        f"name = {json.dumps(name)}",
        f"version = {json.dumps(ver)}",
        "[[packages.wheels]]",
        f"url = {json.dumps(url)}",
        "[packages.wheels.hashes]",
        f"sha256 = {json.dumps(digest)}",
    ]
# The host reads the lock at the source root, wherever the project is.
with open("/src/pylock.toml", "w") as handle:
    handle.write("\n".join(lines) + "\n")
PY
