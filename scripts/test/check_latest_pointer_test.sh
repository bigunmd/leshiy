#!/bin/sh
# Unit test for check-latest-pointer.sh's pure invariant (no network): GitHub's shared
# "latest" pointer must sit on the server/CLI train (vX.Y.Z) — the only release carrying
# install.sh/install-client.sh/leshiyctl. A desktop-v*/android-v* tag winning "latest"
# makes the README's releases/latest/download/install.sh URLs 404, so assert_server_train
# must reject those.
set -eu
here="$(cd "$(dirname "$0")/.." && pwd)"

# Source the real script with main() guarded off so we test the actual function.
export LESHIY_SOURCED=1
. "$here/check-latest-pointer.sh"

fails=0
ok()   { echo "ok   - $1"; }
bad()  { echo "FAIL - $1"; fails=$((fails + 1)); }

# Tags on the server/CLI train must pass.
for tag in v1.3.0 v0.1.0 v10.20.30; do
  if ( assert_server_train "$tag" ) >/dev/null 2>&1; then ok "accepts $tag"
  else bad "rejected server-train tag $tag"; fi
done

# Desktop/android tags (and empty/garbage) must be rejected — they have no install assets.
for tag in desktop-v1.3.0 android-v1.3.0 untagged-b5ece23ec16d767dd471 "" notav1; do
  if ( assert_server_train "$tag" ) >/dev/null 2>&1; then bad "wrongly accepted '$tag'"
  else ok "rejects '$tag'"; fi
done

if [ "$fails" -ne 0 ]; then
  echo "FAILED: $fails case(s)"; exit 1
fi
echo "PASS"
