#!/bin/sh
# CI guard: assert GitHub's shared "latest" release pointer stays on the server/CLI train.
#
# The repo ships three release trains that all compete for the single /releases/latest pointer:
# the server/CLI train (vX.Y.Z — the ONLY one carrying install.sh, install-client.sh, leshiyctl
# and the Linux binary), plus desktop-v* and android-v*. The README's quick start bootstraps via
#   curl .../releases/latest/download/install.sh
# so if a desktop/android release ever wins "latest", that URL 404s and the quick start breaks.
#
# desktop-release.yml / android-release.yml already set make_latest:false to stay off it; this
# script is the fail-loud backstop so a workflow regression (or a manual un-draft) goes red in CI
# instead of silently 404ing users. POSIX sh.
set -eu

REPO="${LESHIY_REPO:-bigunmd/leshiy}"
API="${LESHIY_API_URL:-https://api.github.com/repos/$REPO/releases/latest}"
DL_BASE="${LESHIY_DL_BASE:-https://github.com/$REPO/releases/latest/download}"
# Assets the README's releases/latest install URLs depend on; only the v* train publishes them.
REQUIRED_ASSETS="install.sh install-client.sh leshiyctl"

die() { echo "FAIL: $*" >&2; exit 1; }

# Print the tag_name that /releases/latest currently resolves to.
latest_tag() {
  curl -fsSL "$API" | grep '"tag_name"' | head -n1 | cut -d'"' -f4
}

# The invariant: "latest" must be a server/CLI tag (vX.Y.Z), not desktop-v*/android-v*.
# `v[0-9]*` matches v1.3.0 but not desktop-v1.3.0 / android-v1.3.0 / empty / garbage.
assert_server_train() {
  tag="$1"
  [ -n "$tag" ] || die "could not read tag_name from $API"
  case "$tag" in
    v[0-9]*) : ;;
    *) die "GitHub 'latest' points at '$tag', not the v* server/CLI train.
       The README quick start (releases/latest/download/install.sh) will 404.
       A desktop-v*/android-v* release stole 'latest' — set make_latest:false on it." ;;
  esac
}

# Belt-and-suspenders: prove the install assets actually resolve from releases/latest/download.
assert_assets_resolve() {
  for a in $REQUIRED_ASSETS; do
    code="$(curl -sS -o /dev/null -w '%{http_code}' -L "$DL_BASE/$a")"
    [ "$code" = 200 ] || die "$DL_BASE/$a returned HTTP $code (expected 200)"
  done
}

main() {
  command -v curl >/dev/null 2>&1 || die "curl is required"
  tag="$(latest_tag)"
  assert_server_train "$tag"
  assert_assets_resolve
  echo "OK: 'latest' = $tag carries [$REQUIRED_ASSETS]"
}

# Run main unless sourced for testing (the unit test sources this to exercise assert_server_train).
[ "${LESHIY_SOURCED:-}" = 1 ] || main
