set -eu
mkdir -p /out
cd /src
export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct {COMMIT_SHA} 2>/dev/null || echo 0)"
export TZ=UTC
export npm_config_update_notifier=false
export PKG_NAME='{PKG_NAME}'
export PKG_VERSION='{PKG_VERSION}'

TARGET_DIR=$(node -e '
  const fs = require("fs"); const path = require("path");
  function walk(dir) {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return null; }
    for (const e of entries) {
      if (e.name === "node_modules" || e.name === ".git") continue;
      const p = path.join(dir, e.name);
      if (e.isDirectory()) { const r = walk(p); if (r) return r; }
      else if (e.name === "package.json") {
        try {
          const j = JSON.parse(fs.readFileSync(p, "utf8"));
          if (j.name === process.env.PKG_NAME && j.version === process.env.PKG_VERSION) {
            return path.dirname(p);
          }
        } catch {}
      }
    }
    return null;
  }
  console.log(walk(process.cwd()) || "");
')
if [ -z "$TARGET_DIR" ]; then
  echo "clearhash: could not locate $PKG_NAME@$PKG_VERSION in source tree" >&2
  exit 1
fi
echo "clearhash: rebuilding from $TARGET_DIR" >&2

# Validate the pinned source manifest as well as the registry metadata. Never emulate
# a foreign platform by overriding npm_config_os/arch: Node and the compiler must
# actually execute on the selected Docker platform.
node - "$TARGET_DIR/package.json" <<'NODE'
const p = require(process.argv[2]);
const targets = { os: process.platform, cpu: process.arch, libc: "glibc" };
for (const [field, target] of Object.entries(targets)) {
  const values = p[field];
  if (values === undefined) continue;
  if (!Array.isArray(values) || values.some(v => typeof v !== "string")) {
    throw new Error(`clearhash: invalid ${field} constraint`);
  }
  const denied = values.includes(`!${target}`);
  const allowed = values.length === 0 || values.every(v => v.startsWith("!")) ||
    values.includes(target) || values.includes("any");
  if (denied || !allowed) throw new Error(`clearhash: source ${field} does not support ${target}`);
}
NODE

# Workspace install at the repo root (handles npm/yarn/pnpm workspaces).
if [ -f package-lock.json ]; then
  npm ci --ignore-scripts --no-audit --no-fund
elif [ -f yarn.lock ]; then
  corepack enable >/dev/null 2>&1 || true
  yarn install --frozen-lockfile --ignore-scripts >/dev/null
elif [ -f pnpm-lock.yaml ]; then
  corepack enable >/dev/null 2>&1 || true
  pnpm install --frozen-lockfile --ignore-scripts >/dev/null
else
  npm install --ignore-scripts --no-audit --no-fund
fi

cd "$TARGET_DIR"
if [ "${CLEARHASH_NATIVE_REBUILD:-0}" = 1 ]; then
  # Compile from the attested tree, bypassing installers that can download opaque
  # prebuilt binaries. Dependency lifecycle hooks remain disabled.
  if [ -f binding.gyp ]; then
    node /usr/local/lib/node_modules/npm/node_modules/node-gyp/bin/node-gyp.js rebuild --nodedir=/usr/local
  elif ! node -e 'const p=require("./package.json"); process.exit(p.scripts && p.scripts.build ? 0 : 1)'; then
    echo "clearhash: native rebuild requires binding.gyp or an explicit build script in the selected source package" >&2
    exit 1
  fi
  npm run build --ignore-scripts --if-present
  # Explicit native compilation above replaces automatic prepack/prepare hooks.
  npm pack --ignore-scripts --pack-destination=/out
  exit 0
fi
# If a `prepack` / `prepare` script exists, run it explicitly (we used --ignore-scripts above).
# Many monorepos rely on this to generate dist/ before pack.
if node -e 'const p=require("./package.json"); process.exit(p.scripts && (p.scripts.build || p.scripts.prepack || p.scripts.prepare) ? 0 : 1)' 2>/dev/null; then
  npm run build --if-present || true
fi
npm pack --pack-destination=/out
