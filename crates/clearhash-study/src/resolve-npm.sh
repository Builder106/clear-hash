set -eu
# Arm I resolver (network on). Writes or completes the npm lock as of the publish
# time. The rebuild that follows runs with the network off, as in arm H.
cd /src
export npm_config_update_notifier=false
npm install --package-lock-only --ignore-scripts --no-audit --no-fund \
  --cache=/tmp/clearhash-npm-cache \
  ${CLEARHASH_RESOLVE_BEFORE:+"--before=$CLEARHASH_RESOLVE_BEFORE"}
