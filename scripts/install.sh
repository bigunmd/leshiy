#!/bin/sh
# Leshiy installer — downloads + verifies a signed release, then hands off to
# `leshiy quickstart` and wires up systemd + firewall. POSIX sh.
set -eu

REPO="${LESHIY_REPO:-bigunmd/leshiy}"    # override with LESHIY_REPO for forks
BINDIR="/usr/local/bin"
CFGDIR="/etc/leshiy"
# Embedded minisign public key (matches scripts/minisign.pub):
MINISIGN_PUB="RWQ_REPLACE_WITH_REAL_PUBKEY_LINE"

DOCKER=0; ASSUME_YES=0; HOST=""; DEST=""; QUIC=0; VERSION="latest"
ROLE="single"; EXIT_URI=""
while [ $# -gt 0 ]; do
  case "$1" in
    --docker) DOCKER=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    --host) HOST="$2"; shift ;;
    --dest) DEST="$2"; shift ;;
    --quic) QUIC=1 ;;
    --version) VERSION="$2"; shift ;;
    --role) ROLE="$2"; shift ;;
    --exit-uri) EXIT_URI="$2"; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done

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
    v="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
      | grep -m1 '"tag_name"' | cut -d'"' -f4)"
    [ -n "$v" ] || die "could not resolve latest release for $REPO (try --version vX.Y.Z)"
    echo "$v"
  else
    echo "$VERSION"
  fi
}

verify_and_install_binary() {
  target="$(detect_target)"
  ver="$(resolve_version)"
  base="https://github.com/$REPO/releases/download/$ver"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  echo "downloading leshiy $ver ($target)..."
  curl -fsSL "$base/leshiy-$ver-$target.tar.gz" -o "$tmp/pkg.tgz"
  curl -fsSL "$base/SHA256SUMS" -o "$tmp/SHA256SUMS"
  curl -fsSL "$base/SHA256SUMS.minisig" -o "$tmp/SHA256SUMS.minisig"
  # 1) signature over the checksum file
  echo "$MINISIGN_PUB" > "$tmp/minisign.pub"
  have minisign || install_pkg minisign
  minisign -Vm "$tmp/SHA256SUMS" -p "$tmp/minisign.pub" -x "$tmp/SHA256SUMS.minisig" \
    || die "signature verification FAILED — aborting"
  # 2) checksum over the artifact we actually downloaded
  ( cd "$tmp" && grep "leshiy-$ver-$target.tar.gz" SHA256SUMS | sha256sum -c - ) \
    || die "checksum mismatch — aborting"
  tar -C "$tmp" -xzf "$tmp/pkg.tgz"
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

open_firewall() {
  if have ufw; then
    ufw allow 443/tcp
    if [ "$QUIC" -eq 1 ]; then ufw allow 443/udp; fi
  elif have firewall-cmd; then
    firewall-cmd --add-port=443/tcp --permanent
    if [ "$QUIC" -eq 1 ]; then firewall-cmd --add-port=443/udp --permanent; fi
    firewall-cmd --reload
  else
    echo "no ufw/firewalld found — ensure 443/tcp (and 443/udp if QUIC) is open"
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

quic_args() {  # echo the quic flag (word-split intentionally by caller) when enabled
  [ "$QUIC" -eq 1 ] && printf '%s' "--quic-listen 0.0.0.0:443"
  return 0
}

role_args() {  # echo role/exit/quic flags (word-split intentionally by caller)
  printf '%s' "--role $ROLE"
  [ -n "$EXIT_URI" ] && printf '%s' " --exit-uri $EXIT_URI"
  # Exit role needs a reachable QUIC carrier; default it to the public host if unset.
  if [ "$ROLE" = "exit" ] && [ "$QUIC" -eq 0 ]; then
    printf '%s' " --quic-listen ${HOST}"
  fi
  return 0
}

# ASSUME_YES is consumed by interactive prompts in later phases of the installer;
# reference it here so shellcheck knows it is intentionally kept for future use.
: "$ASSUME_YES"

main() {
  need_root
  have curl || install_pkg curl
  [ -n "$HOST" ] || HOST="$(public_ip):443"
  [ -n "$DEST" ] || DEST="www.microsoft.com:443"

  if [ "$DOCKER" -eq 1 ]; then
    have docker || sh -c "$(curl -fsSL https://get.docker.com)"
    install -d -m700 "$CFGDIR"
    IMG_TAG="$VERSION"
    if [ "$IMG_TAG" = "latest" ]; then
      IMG_TAG="$(resolve_version)"
    fi
    # Generate config inside the image, mounting the config dir.
    # shellcheck disable=SC2046  # intentional word-splitting of quic_args (0 or 2 args)
    docker run --rm -v "$CFGDIR":/etc/leshiy "ghcr.io/$REPO:$IMG_TAG" \
      quickstart --host "$HOST" --dest "$DEST" --out /etc/leshiy/server.toml \
      $(quic_args) $(role_args)
    cat > "$CFGDIR/docker-compose.yaml" <<COMPOSE
services:
  leshiy:
    image: ghcr.io/$REPO:$IMG_TAG
    command: server --config /etc/leshiy/server.toml
    network_mode: host
    volumes: ["$CFGDIR:/etc/leshiy"]
    restart: unless-stopped
COMPOSE
    open_firewall
    ( cd "$CFGDIR" && docker compose up -d )
    echo "leshiy running under docker compose."
    exit 0
  fi

  verify_and_install_binary
  install -d -m700 "$CFGDIR"
  if [ -f "$CFGDIR/server.toml" ]; then
    echo "existing install detected at $CFGDIR/server.toml — upgrading binary, keeping identity."
  else
    # Hand off to the Rust wizard; capture the JSON summary line.
    # shellcheck disable=SC2046  # intentional word-splitting of quic_args (0 or 2 args)
    summary="$("$BINDIR/leshiy" quickstart \
        --host "$HOST" --dest "$DEST" --out "$CFGDIR/server.toml" \
        $(quic_args) $(role_args) \
        --summary-json | tee /dev/tty | grep -m1 '^{')"
    echo "$summary" > "$CFGDIR/install.json"
  fi
  open_firewall
  write_unit_and_start
  if systemctl is-active --quiet leshiy; then
    echo "leshiy is running."
  else
    die "service failed to start"
  fi
}
main
