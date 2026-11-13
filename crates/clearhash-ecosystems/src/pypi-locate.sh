# Build the project that names the distribution. In a monorepo that is a
# subdirectory; otherwise, or when no project declares the name statically,
# the repository root. Expects the source root as the working directory.
PROJECT_DIR=$(python - <<'PY'
import configparser
import os
import re
import tomllib


def normalize(name):
    return re.sub(r"[-_.]+", "-", name).lower()


wanted = normalize(os.environ["PKG_NAME"])
skip = {"node_modules", "venv", "build", "dist", "site-packages"}
for root, dirs, files in os.walk("."):
    dirs[:] = sorted(d for d in dirs if d not in skip and not d.startswith("."))
    name = None
    if "pyproject.toml" in files:
        try:
            with open(os.path.join(root, "pyproject.toml"), "rb") as handle:
                name = tomllib.load(handle).get("project", {}).get("name")
        except (OSError, tomllib.TOMLDecodeError):
            pass
    if name is None and "setup.cfg" in files:
        config = configparser.ConfigParser(interpolation=None)
        try:
            config.read(os.path.join(root, "setup.cfg"))
            name = config.get("metadata", "name", fallback=None)
        except configparser.Error:
            pass
    if isinstance(name, str) and normalize(name) == wanted:
        print(root)
        break
else:
    print(".")
PY
)
if [ "$PROJECT_DIR" != . ]; then
  echo "clearhash: building from $PROJECT_DIR" >&2
fi
cd "$PROJECT_DIR"
