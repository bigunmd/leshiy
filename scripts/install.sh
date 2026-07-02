#!/bin/sh
# Leshiy installer — downloads + verifies a signed release, then hands off to
# `leshiy quickstart` and wires up systemd + firewall. POSIX sh.
set -eu

REPO="${LESHIY_REPO:-bigunmd/leshiy}"    # override with LESHIY_REPO for forks
BINDIR="${LESHIY_BINDIR:-/usr/local/bin}"
CFGDIR="/etc/leshiy"
# Embedded minisign public key — the base64 key line of scripts/minisign.pub.
MINISIGN_PUB="RWTdtVTZBm+928JVtALfb1pBJf013uPjatAh3WwNV20EqaEoQmulZgXU"

DOCKER=0; ASSUME_YES=0; HOST=""; DEST=""; QUIC=0; VERSION="latest"
ROLE="single"; EXIT_URI=""; QUIC_SNI=""; PORT=443; QUIC_PORT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --docker) DOCKER=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    --host) HOST="$2"; shift ;;
    --dest) DEST="$2"; shift ;;
    --port) PORT="$2"; shift ;;
    --quic)
      QUIC=1
      # Optional port arg: bare `--quic` enables QUIC on the REALITY port; `--quic 10560`
      # picks the UDP port. Anything starting with `-` is the next flag, not our value.
      case "${2:-}" in
        ''|-*) ;;
        *) QUIC_PORT="$2"; shift ;;
      esac
      ;;
    --quic-port) QUIC_PORT="$2"; shift ;;
    --quic-sni) QUIC_SNI="$2"; shift ;;
    --version) VERSION="$2"; shift ;;
    --role) ROLE="$2"; shift ;;
    --exit-uri) EXIT_URI="$2"; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done
# Default the QUIC UDP port to the REALITY/TCP port once both are finalized.
[ -n "$QUIC_PORT" ] || QUIC_PORT="$PORT"

die() { echo "error: $*" >&2; exit 1; }
need_root() { [ "$(id -u)" -eq 0 ] || die "run as root (sudo)"; }
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
    # The repo ships three release trains that all share GitHub's single "latest" pointer:
    # the server/CLI train (vX.Y.Z, the only one carrying the Linux binary + these scripts),
    # plus desktop-v* and android-v*. /releases/latest can therefore resolve to a desktop or
    # android tag that has none of our assets. List releases (newest first) and pick the newest
    # server-train tag instead — `^v[0-9]` matches vX.Y.Z but not desktop-v*/android-v*.
    v="$(curl -fsSL "https://api.github.com/repos/$REPO/releases?per_page=100" \
      | grep '"tag_name"' | cut -d'"' -f4 | grep -m1 '^v[0-9]')"
    [ -n "$v" ] || die "could not resolve a server release (vX.Y.Z) for $REPO (try --version vX.Y.Z)"
    echo "$v"
  else
    echo "$VERSION"
  fi
}

verify_and_install_binary() {
  target="$(detect_target)"
  ver="$(resolve_version)"
  base="${LESHIY_BASE_URL:-https://github.com/$REPO/releases/download/$ver}"
  tarball="leshiy-$ver-$target.tar.gz"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  echo "downloading leshiy $ver ($target)..."
  # Download under the REAL artifact name so `sha256sum -c` (which checks the names listed
  # inside SHA256SUMS) can find the file.
  curl -fsSL "$base/$tarball" -o "$tmp/$tarball"
  curl -fsSL "$base/SHA256SUMS" -o "$tmp/SHA256SUMS"
  curl -fsSL "$base/SHA256SUMS.minisig" -o "$tmp/SHA256SUMS.minisig"
  # 1) signature over the checksum file — pass the pubkey as a base64 string via -P (no file;
  #    minisign -p expects a 2-line key FILE, -P takes the bare key line we embed above).
  have minisign || install_pkg minisign
  minisign -Vm "$tmp/SHA256SUMS" -P "$MINISIGN_PUB" -x "$tmp/SHA256SUMS.minisig" \
    || die "signature verification FAILED — aborting"
  # 2) checksum over the artifact we actually downloaded
  ( cd "$tmp" && grep "$tarball" SHA256SUMS | sha256sum -c - ) \
    || die "checksum mismatch — aborting"
  tar -C "$tmp" -xzf "$tmp/$tarball"
  install -Dm755 "$tmp/leshiy" "$BINDIR/leshiy"
  echo "installed $BINDIR/leshiy"
}

install_pkg() {  # best-effort installer for a host tool ($1)
  if have apt-get; then apt-get update -qq && apt-get install -y "$1"
  elif have dnf; then dnf install -y "$1"
  elif have apk; then apk add --no-cache "$1"
  elif have pacman; then pacman -Sy --noconfirm "$1"
  else die "install $1 manually (no known package manager)"; fi
}

public_ip() { curl -fsSL https://api.ipify.org || curl -fsSL https://ifconfig.me; }

# Run the leshiy server as a plain, restart-on-failure docker container named `leshiy`.
# Host networking so it binds the public :443 (tcp+udp); root in-container to bind the
# privileged port and own its files in the /etc/leshiy bind mount. Idempotent (removes any
# existing container first).
run_server_container() {  # $1 = image ref
  docker rm -f leshiy >/dev/null 2>&1 || true
  docker run -d --name leshiy --restart unless-stopped \
    --user 0:0 --network host \
    -v "$CFGDIR":/etc/leshiy \
    "$1" server --config /etc/leshiy/server.toml
}

install_leshiyctl() {  # day-2 dispatcher, published alongside install.sh in each server release
  # Resolve the server train explicitly (NOT /releases/latest, which may be a desktop/android
  # release without leshiyctl); honor LESHIY_BASE_URL so the smoke test / mirrors still work.
  lver="$(resolve_version)"
  lbase="${LESHIY_BASE_URL:-https://github.com/$REPO/releases/download/$lver}"
  if curl -fsSL "$lbase/leshiyctl" -o /usr/local/bin/leshiyctl 2>/dev/null; then
    chmod +x /usr/local/bin/leshiyctl
  else
    echo "note: leshiyctl not fetched (older release?); manage directly instead"
  fi
}

open_firewall() {
  if have ufw; then
    ufw allow "$PORT/tcp"
    if [ "$QUIC" -eq 1 ]; then ufw allow "$QUIC_PORT/udp"; fi
  elif have firewall-cmd; then
    firewall-cmd --add-port="$PORT/tcp" --permanent
    if [ "$QUIC" -eq 1 ]; then firewall-cmd --add-port="$QUIC_PORT/udp" --permanent; fi
    firewall-cmd --reload
  else
    echo "no ufw/firewalld found — ensure $PORT/tcp (and $QUIC_PORT/udp if QUIC) is open"
  fi
}

ensure_user() {  # create an unprivileged system user `leshiy` if missing
  id leshiy >/dev/null 2>&1 && return 0
  if have useradd; then
    useradd --system --no-create-home --shell /usr/sbin/nologin leshiy
  elif have adduser; then  # busybox/alpine
    adduser -S -D -H -s /sbin/nologin leshiy
  else
    die "cannot create 'leshiy' system user (no useradd/adduser found)"
  fi
}

write_unit_and_start() {
  ensure_user
  # The service runs as the unprivileged `leshiy` user, which must own its
  # config+state dir (config 0600, plus the sqlite DB and control socket).
  chown -R leshiy "$CFGDIR"
  cat > /etc/systemd/system/leshiy.service <<'UNIT'
[Unit]
Description=Leshiy stealth tunnel
After=network-online.target
Wants=network-online.target

[Service]
User=leshiy
ExecStart=/usr/local/bin/leshiy server --config /etc/leshiy/server.toml
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
ReadWritePaths=/etc/leshiy
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable leshiy >/dev/null 2>&1 || true
  systemctl restart leshiy
}

quic_sni_arg() {  # append the optional --quic-sni override (no-op when unset)
  [ -n "$QUIC_SNI" ] && printf '%s' " --quic-sni $QUIC_SNI"
  return 0
}
quic_args() {  # echo the quic flags (word-split intentionally by caller) when enabled
  if [ "$QUIC" -eq 1 ]; then
    printf '%s' "--quic-listen 0.0.0.0:$QUIC_PORT"
    quic_sni_arg
  fi
  return 0
}

role_args() {  # echo role/exit/quic flags (word-split intentionally by caller)
  printf '%s' "--role $ROLE"
  [ -n "$EXIT_URI" ] && printf '%s' " --exit-uri $EXIT_URI"
  # Exit role needs a QUIC carrier; bind all interfaces (NAT-friendly). The server advertises
  # it to clients on the public --host, so binding 0.0.0.0 here is correct.
  if [ "$ROLE" = "exit" ] && [ "$QUIC" -eq 0 ]; then
    printf '%s' " --quic-listen 0.0.0.0:$QUIC_PORT"
    quic_sni_arg
  fi
  return 0
}

# ASSUME_YES is consumed by interactive prompts in later phases of the installer;
# reference it here so shellcheck knows it is intentionally kept for future use.
: "$ASSUME_YES"

main() {
  need_root
  have curl || install_pkg curl
  [ -n "$HOST" ] || HOST="$(public_ip):$PORT"
  [ -n "$DEST" ] || DEST="www.microsoft.com:443"

  if [ "$DOCKER" -eq 1 ]; then
    have docker || sh -c "$(curl -fsSL https://get.docker.com)"
    install -d -m700 "$CFGDIR"
    IMG_TAG="$VERSION"
    if [ "$IMG_TAG" = "latest" ]; then
      IMG_TAG="$(resolve_version)"
    fi
    IMG="ghcr.io/$REPO:$IMG_TAG"
    if [ -f "$CFGDIR/server.toml" ]; then
      echo "existing install detected at $CFGDIR/server.toml — keeping identity, recreating container."
    else
      # Generate config inside the image, mounting the config dir. Run as root (--user 0:0):
      # the image's default 'nonroot' user can't write the root-owned /etc/leshiy bind mount.
      # shellcheck disable=SC2046  # intentional word-splitting of quic_args (0 or 2 args)
      docker run --rm --user 0:0 -v "$CFGDIR":/etc/leshiy "$IMG" \
        quickstart --host "$HOST" --dest "$DEST" --out /etc/leshiy/server.toml \
        $(quic_args) $(role_args)
    fi
    printf '{"mode":"docker","image":"%s"}\n' "$IMG" > "$CFGDIR/install.json"
    open_firewall
    run_server_container "$IMG"
    install_leshiyctl
    echo "leshiy running in docker (container: leshiy). Logs: docker logs -f leshiy"
    exit 0
  fi

  verify_and_install_binary
  install_leshiyctl
  install -d -m700 "$CFGDIR"
  if [ -f "$CFGDIR/server.toml" ]; then
    echo "existing install detected at $CFGDIR/server.toml — upgrading binary, keeping identity."
    # Ensure leshiyctl can detect the mode even on boxes first provisioned by an older installer.
    [ -f "$CFGDIR/install.json" ] || printf '{"mode":"native"}\n' > "$CFGDIR/install.json"
  else
    # Hand off to the Rust wizard; capture the JSON summary line.
    # shellcheck disable=SC2046  # intentional word-splitting of quic_args (0 or 2 args)
    summary="$("$BINDIR/leshiy" quickstart \
        --host "$HOST" --dest "$DEST" --out "$CFGDIR/server.toml" \
        $(quic_args) $(role_args) \
        --summary-json | tee /dev/tty | grep -m1 '^{')"
    printf '%s\n{"mode":"native"}\n' "$summary" > "$CFGDIR/install.json"
  fi
  open_firewall
  write_unit_and_start
  if systemctl is-active --quiet leshiy; then
    echo "leshiy is running."
  else
    die "service failed to start"
  fi
}
# Run main unless sourced for testing (the smoke test sources this file to exercise
# verify_and_install_binary directly against a local fake release).
[ "${LESHIY_SOURCED:-}" = 1 ] || main
