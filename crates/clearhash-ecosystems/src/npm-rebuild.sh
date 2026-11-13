set -eu
mkdir -p /out
cd /src
export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct {COMMIT_SHA} 2>/dev/null || echo 0)"
export TZ=UTC
export npm_config_update_notifier=false
export npm_config_offline=true
export npm_config_ignore_scripts=true
export npm_config_cache=/tmp/clearhash-npm-cache
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

# The lockfile picks the package manager, with the host's precedence: npm locks,
# then pnpm-lock.yaml, then yarn.lock (Yarn 2+ locks start with __metadata).
if [ -f npm-shrinkwrap.json ] || [ -f package-lock.json ]; then PM=npm
elif [ -f pnpm-lock.yaml ]; then PM=pnpm
elif [ -f yarn.lock ]; then
  if grep -q '^__metadata:' yarn.lock; then PM=yarn-berry; else PM=yarn; fi
else PM=npm
fi

if [ "$PM" != npm ]; then
  # Run the host-verified release from /tools, or the Yarn release committed at
  # yarnPath. A shim puts it on PATH for build scripts that call it by name.
  case $PM in pnpm) COMMAND=pnpm ;; *) COMMAND=yarn ;; esac
  mkdir -p /tmp/clearhash-bin /tmp/clearhash-pm
  if [ -f /tools/package-manager.tgz ]; then
    tar -xzf /tools/package-manager.tgz -C /tmp/clearhash-pm
    ENTRY=$(node -e '
      const p = require("/tmp/clearhash-pm/package/package.json");
      const bin = typeof p.bin === "string" ? p.bin : (p.bin || {})[process.argv[1]];
      console.log(bin ? `node /tmp/clearhash-pm/package/${bin}` : `/tmp/clearhash-pm/package/${process.argv[1]}`);
    ' "$COMMAND")
  elif [ -f /tools/yarn.js ]; then
    ENTRY="node /tools/yarn.js"
  else
    RELEASE=$(sed -n 's/^yarnPath:[[:space:]]*//p' .yarnrc.yml 2>/dev/null | tr -d "\"'" | tr -d '[:space:]')
    if [ "$PM" != yarn-berry ] || [ -z "$RELEASE" ]; then
      echo "clearhash: no $COMMAND release was provided" >&2
      exit 1
    fi
    ENTRY="node /src/$RELEASE"
  fi
  printf '#!/bin/sh\nexec %s "$@"\n' "$ENTRY" > "/tmp/clearhash-bin/$COMMAND"
  chmod +x "/tmp/clearhash-bin/$COMMAND"
  export PATH="/tmp/clearhash-bin:$PATH"
  # pnpm and Yarn read npm_config_* too. They fetch from the loopback registry
  # below, so npm's offline flag must not apply to them.
  # pnpm 11 and later read pnpm_config_* instead.
  # pnpm 11 and later also check each locked package's age and trust history
  # against registry metadata. Those compare publish dates with today, not with
  # the release, so they are off in every arm. pnpm ignores --config.* flags
  # for these during install, so they are set here.
  for prefix in npm_config pnpm_config; do
    export "${prefix}_offline=false" "${prefix}_ignore_scripts=true"
    export "${prefix}_manage_package_manager_versions=false"
    export "${prefix}_package_manager_strict=false"
    export "${prefix}_minimum_release_age=0" "${prefix}_trust_policy=off"
    export "${prefix}_update_notifier=false"
  done
  export CI=true
  export YARN_ENABLE_TELEMETRY=false YARN_ENABLE_SCRIPTS=false
  export YARN_ENABLE_GLOBAL_CACHE=false YARN_CACHE_FOLDER=/tmp/clearhash-yarn-cache
  export YARN_ENABLE_HARDENED_MODE=false YARN_CHECKSUM_BEHAVIOR=throw
fi

# A registry on the loopback interface, serving only the host-verified tarballs in
# /deps under Yarn 1's offline-mirror names. The container still has no network.
start_registry() {
  cat > /tmp/clearhash-registry.js <<'NODE'
const fs = require("fs");
const http = require("http");
// Yarn 1's getTarballNameFromUrl, which also named the files on the host.
const NAME = /\/(?:(@[^/]+)(?:\/|%2f))?[^/]+\/(?:-|_attachments)\/(?:@[^/]+\/)?([^/]+)$/;
const server = http.createServer((request, response) => {
  const match = new URL(request.url, "http://127.0.0.1").pathname.match(NAME);
  const file = match && (match[1] ? `${match[1]}-${match[2]}` : match[2]);
  const path = file && !file.startsWith(".") ? `/deps/${file}` : null;
  fs.stat(path || "/nonexistent", (error, stat) => {
    if (error || !stat.isFile()) {
      response.writeHead(404).end();
      return;
    }
    response.writeHead(200, { "content-type": "application/octet-stream", "content-length": stat.size });
    fs.createReadStream(path).pipe(response);
  });
});
server.listen(0, "127.0.0.1", () => {
  fs.writeFileSync("/tmp/clearhash-registry-port", String(server.address().port));
});
NODE
  rm -f /tmp/clearhash-registry-port
  node /tmp/clearhash-registry.js &
  REGISTRY_PID=$!
  tries=0
  while [ ! -s /tmp/clearhash-registry-port ]; do
    tries=$((tries + 1))
    if [ "$tries" -gt 100 ]; then
      echo "clearhash: loopback registry did not start" >&2
      exit 1
    fi
    sleep 0.1
  done
  REGISTRY="http://127.0.0.1:$(cat /tmp/clearhash-registry-port)"
}
stop_registry() {
  kill "$REGISTRY_PID" 2>/dev/null || true
  wait "$REGISTRY_PID" 2>/dev/null || true
}

PNPM_INSTALL="pnpm install --frozen-lockfile --ignore-scripts --store-dir=/tmp/clearhash-pnpm-store --reporter=append-only"
if [ "${CLEARHASH_DEPENDENCY_MODE:-offline}" = network ]; then
# Measurement mode only (clearhash-study): install from the registry. The verifier
# never sets this variable, and its containers have no network.
export npm_config_offline=false pnpm_config_offline=false
case $PM in
npm)
  if [ -f npm-shrinkwrap.json ] || [ -f package-lock.json ]; then
    npm ci --ignore-scripts --no-audit --no-fund --cache=/tmp/clearhash-npm-cache
  else
    npm install --ignore-scripts --no-audit --no-fund --cache=/tmp/clearhash-npm-cache \
      ${CLEARHASH_RESOLVE_BEFORE:+"--before=$CLEARHASH_RESOLVE_BEFORE"}
  fi
  ;;
pnpm) $PNPM_INSTALL ;;
yarn) yarn install --frozen-lockfile --ignore-scripts --non-interactive ;;
yarn-berry) yarn install --immutable --mode=skip-build ;;
esac
else
case $PM in
npm)
  # Populate npm's content-addressed cache from host-verified tarballs, inside the
  # network-disabled container. No host npm installation or dependency code execution.
  restore_lock() {
    if [ -f /tmp/clearhash-original-lock ]; then
      node -e 'const fs=require("fs"); fs.copyFileSync("/tmp/clearhash-original-lock", fs.existsSync("npm-shrinkwrap.json") ? "npm-shrinkwrap.json" : "package-lock.json"); fs.unlinkSync("/tmp/clearhash-original-lock")'
    fi
  }
  trap restore_lock EXIT
  node <<'NODE'
const fs = require("fs");
const cacache = require("/usr/local/lib/node_modules/npm/node_modules/cacache");
const lockPath = fs.existsSync("npm-shrinkwrap.json") ? "npm-shrinkwrap.json" : "package-lock.json";
const original = fs.readFileSync(lockPath);
const lock = JSON.parse(original);
for (const [location, entry] of Object.entries(lock.packages)) {
  if (!location.split("/").includes("node_modules") || entry.link || entry.inBundle || entry.resolved != null) continue;
  const name = entry.name || location.split("node_modules/").pop();
  entry.resolved = `https://registry.npmjs.org/${name}/-/${name.split("/").pop()}-${entry.version}.tgz`;
}
// npm otherwise requests packuments for URL-less locks even with cached integrity.
// Restore the exact committed bytes before any source build/pack code runs.
fs.writeFileSync("/tmp/clearhash-original-lock", original);
fs.writeFileSync(lockPath, JSON.stringify(lock));
(async () => {
  for (const name of fs.readdirSync("/deps").filter(n => n.endsWith(".tgz"))) {
    const bytes = fs.readFileSync(`/deps/${name}`);
    // npm normally writes SHA-512; seed other supported lockfile SRI algorithms too.
    for (const algorithm of ["sha256", "sha384", "sha512"]) {
      await cacache.put(`${process.env.npm_config_cache}/_cacache`, `clearhash:${name}:${algorithm}`, bytes, { algorithms: [algorithm] });
    }
  }
})().catch(error => { console.error(error); process.exit(1); });
NODE
  npm ci --offline --ignore-scripts --no-audit --no-fund --cache=/tmp/clearhash-npm-cache
  restore_lock
  trap - EXIT
  ;;
pnpm)
  start_registry
  trap stop_registry EXIT
  $PNPM_INSTALL --registry="$REGISTRY/"
  stop_registry
  trap - EXIT
  ;;
yarn)
  printf 'yarn-offline-mirror "/deps"\n' > /tmp/clearhash-yarnrc
  yarn install --frozen-lockfile --offline --ignore-scripts --non-interactive \
    --use-yarnrc /tmp/clearhash-yarnrc --cache-folder /tmp/clearhash-yarn-cache
  ;;
yarn-berry)
  # Yarn checks each package against the lock checksum (checksumBehavior: throw).
  start_registry
  trap stop_registry EXIT
  YARN_NPM_REGISTRY_SERVER="$REGISTRY" YARN_UNSAFE_HTTP_WHITELIST=127.0.0.1 \
    yarn install --immutable --mode=skip-build
  stop_registry
  trap - EXIT
  ;;
esac
fi

# Build and pack with the project's package manager. pnpm and Yarn rewrite
# workspace: and catalog: ranges in the packed package.json; npm does not.
run_build() {
  case $PM in
  npm) npm run build --ignore-scripts --if-present ;;
  pnpm) pnpm run --if-present build ;;
  *)
    if node -e 'const p=require("./package.json"); process.exit(p.scripts && p.scripts.build ? 0 : 1)'; then
      yarn run build
    fi
    ;;
  esac
}
pack() {
  case $PM in
  npm) npm pack --ignore-scripts --pack-destination=/out ;;
  pnpm) pnpm pack --pack-destination /out ;;
  yarn) yarn pack --ignore-scripts --filename /out/package.tgz ;;
  # Yarn 2+ has no switch to skip the project's own prepack and postpack.
  yarn-berry) yarn pack --out /out/package.tgz ;;
  esac
}

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
  run_build
  # Explicit native compilation above replaces automatic prepack/prepare hooks.
  pack
  exit 0
fi
run_build
pack
