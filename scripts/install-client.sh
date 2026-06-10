#!/bin/sh
# Leshiy CLIENT installer — downloads + verifies the signed binary into ~/.local/bin (no root)
# and prints how to start the local SOCKS5 proxy. POSIX sh.
set -eu

REPO="${LESHIY_REPO:-bigunmd/leshiy}"     # override with LESHIY_REPO for forks
BINDIR="${LESHIY_BINDIR:-$HOME/.local/bin}"
# Embedded minisign public key — the base64 key line of scripts/minisign.pub.
MINISIGN_PUB="RWTdtVTZBm+928JVtALfb1pBJf013uPjatAh3WwNV20EqaEoQmulZgXU"

URI=""; SOCKS="127.0.0.1:1080"; VERSION="latest"
while [ $# -gt 0 ]; do
  case "$1" in
    --uri) URI="$2"; shift ;;
    --socks) SOCKS="$2"; shift ;;
    --version) VERSION="$2"; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done

die() { echo "error: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

detect_target() {
  case "$(uname -m)" in
    x86_64|amd64) echo "x86_64-unknown-linux-musl" ;;
    aarch64|arm64) echo "aarch64-unknown-linux-musl" ;;
    *) die "unsupported arch $(uname -m); build from source: cargo build --release" ;;
  esac
}

resolve_version() {
  if [ "$VERSION" = "latest" ]; then
    v="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
      | grep -m1 '"tag_name"' | cut -d'"' -f4)"
    [ -n "$v" ] || die "could not resolve latest release for $REPO (try --version vX.Y.Z)"
    echo "$v"
  else
    echo "$VERSION"
  fi
}

install_client() {
  have curl || die "curl is required"
  have minisign || die "minisign is required to verify the download. Install it first:
    Debian/Ubuntu:  sudo apt install minisign
    Fedora:         sudo dnf install minisign
    Arch:           sudo pacman -S minisign
    Alpine:         sudo apk add minisign
    macOS:          brew install minisign
  then re-run this installer."
  target="$(detect_target)"
  ver="$(resolve_version)"
  base="${LESHIY_BASE_URL:-https://github.com/$REPO/releases/download/$ver}"
  tarball="leshiy-$ver-$target.tar.gz"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  echo "downloading leshiy $ver ($target)..."
  curl -fsSL "$base/$tarball" -o "$tmp/$tarball"
  curl -fsSL "$base/SHA256SUMS" -o "$tmp/SHA256SUMS"
  curl -fsSL "$base/SHA256SUMS.minisig" -o "$tmp/SHA256SUMS.minisig"
  # Pass the pubkey via -P (bare key line), then verify the artifact's checksum.
  minisign -Vm "$tmp/SHA256SUMS" -P "$MINISIGN_PUB" -x "$tmp/SHA256SUMS.minisig" \
    || die "signature verification FAILED — aborting"
  ( cd "$tmp" && grep "$tarball" SHA256SUMS | sha256sum -c - ) \
    || die "checksum mismatch — aborting"
  tar -C "$tmp" -xzf "$tmp/$tarball"
  mkdir -p "$BINDIR"
  install -m755 "$tmp/leshiy" "$BINDIR/leshiy"
  echo "installed $BINDIR/leshiy"
}

main() {
  install_client
  # Use a bare `leshiy` in the printed command only if BINDIR is on PATH.
  case ":${PATH}:" in
    *":$BINDIR:"*) cmd="leshiy" ;;
    *) cmd="$BINDIR/leshiy"
       echo "note: $BINDIR is not on your PATH — add it to PATH, or use the full path below." ;;
  esac
  echo ""
  echo "Start the local SOCKS5 proxy with your server's leshiy:// URI:"
  if [ -n "$URI" ]; then
    echo "    $cmd connect '$URI' --socks $SOCKS"
  else
    echo "    $cmd connect 'leshiy://...' --socks $SOCKS"
  fi
  echo ""
  echo "Then point any app at SOCKS5 $SOCKS, e.g.:"
  echo "    curl --socks5-hostname $SOCKS https://example.com"
}

# Run main unless sourced for testing (the smoke test sources this to exercise install_client).
[ "${LESHIY_SOURCED:-}" = 1 ] || main
