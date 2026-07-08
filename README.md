# LESHIY

**Secure, fast, and highly stealthy tunnel for censored networks.**

A greenfield, self-hostable censorship-circumvention tunnel written in pure Rust,
designed to resist modern Deep Packet Inspection (DPI) — with Russia / TSPU as the
primary target threat model. You run your own server(s); clients connect with a
single `leshiy://` URI.

> **Maturity: beta.** The protocol and the **Linux, Windows, and Android** clients
> work reliably in day-to-day use; the apps may still have occasional edge-case bugs.
> Leshiy has **not yet had an independent security audit** and hasn't been formally
> field-tested against a live censor — so for genuinely high-stakes situations, prefer
> tools that have been audited and battle-proven. The design follows published,
> peer-reviewed anti-censorship research.

---

## Table of contents

- [What it does](#what-it-does)
- [Features](#features)
- [Desktop and mobile apps](#desktop-and-mobile-apps)
- [How it compares](#how-it-compares)
- [Quick start (self-host a server)](#quick-start)
  - [One-command install](#0-one-command-install-recommended)
  - [Run a server](#1-run-a-server)
  - [Connect a client (CLI)](#2-connect-a-client)
  - [Manage users](#3-manage-users-optional)
  - [Enable QUIC](#4-enable-the-quic-transport-optional)
  - [Entry → Exit connector](#5-set-up-an-entry--exit-connector-optional-advanced)
  - [Provision a server from the client](#6-provision-a-server-from-the-client)
- [License](#license)

---

## What it does

Leshiy gives the client a local **SOCKS5 proxy** (or, in the apps, a **full-device
VPN**). Traffic sent through it is wrapped so that, to a censor on the wire, it looks
like an ordinary visit to a real website — not a VPN.

```
                  censored network            │   open internet
  ┌────────┐   REALITY (TLS) or HTTP/3-QUIC   │
  │ client │ ──────── (auto-selected) ───────▶│  Entry  ──connector──▶  Exit  ──▶  Internet
  └────────┘     looks like real HTTPS to     │  (cloak +              (clean
   SOCKS5         the censor; cert-verified    │   per-user limits)     egress)
                                               │      └── chainable: Entry ▶ A ▶ B ▶ … ▶ Exit
```

## Features

- **Two cloaked transports, picked automatically.**
  - **REALITY (TCP/443):** borrows a real site's TLS identity (SNI-borrowing). To a
    prober, an unauthenticated connection is transparently relayed to that real site —
    with **per-SNI origins** when you advertise several names, so each borrowed cert
    matches its name.
  - **QUIC / HTTP-3:** a real HTTP/3 server; authenticated clients tunnel via HTTP/3
    `CONNECT`, while probers get a normal web response — a static page or, for a more
    convincing cover, a **reverse proxy to a real backend** you run. Cert-pinned.
  - **`--transport auto`** uses QUIC where UDP is open and **falls back to REALITY/TCP
    when UDP is blocked** — automatically.
- **Carries UDP, not just TCP.** DNS, QUIC, WebRTC, games and other UDP apps ride the
  tunnel: the full-device VPN tunnels UDP over **either** transport (REALITY mux
  datagrams or QUIC `CONNECT-UDP`, RFC 9298), and the local proxy speaks **SOCKS5 UDP
  ASSOCIATE**.
- **Full dual-stack (IPv6).** IPv6 is carried through the tunnel alongside IPv4, with a
  fail-closed kill-switch so it can never leak around a v6-unaware path; split-tunnel
  include/exclude rules apply to IPv6 domains and CIDRs too.
- **Post-quantum key exchange** (X25519MLKEM768 hybrid) on the REALITY path.
- **Anti-active-probing** on both transports (a wrong key / no key never reveals a proxy),
  with replay protection and handshake deadlines that shrug off connection-holding probes.
- **Stream multiplexing** — the published defense against TLS-in-TLS traffic analysis.
- **Built-in multi-user management** — per-user **data caps, up/down speed limits, and
  expiry**, enforced in the data path and persisted (no external panel required); manage
  live with `leshiy user …`.
- **Entry/Exit connector (the differentiator).** Split the censor-facing **entry** from
  the internet-facing **exit**, joined by a built-in QUIC carrier — **chainable** across
  multiple hops. The chain lives in server-side config, so a leaked client config exposes
  only the entry, not your topology.
- **Pure Rust, no C TLS stack** — easy to cross-compile and audit; `#![forbid(unsafe_code)]`
  in the core crates.

## Desktop and mobile apps

Besides the `leshiy` CLI, there are graphical clients so non-technical users can
connect in one tap — paste a `leshiy://` link (or scan its QR) and go.

**Platforms:** desktop apps for **Linux, Windows, and macOS**, plus an **Android**
app. Download the latest build from the
[Releases page](https://github.com/bigunmd/leshiy/releases). (Linux, Windows, and
Android are tested and working; macOS builds are provided but less exercised. No iOS app.)

**Two modes:**

- **Proxy (SOCKS5)** — a local proxy you point apps at; no elevated privileges.
- **VPN (full tunnel)** — routes the whole device. On desktop a small privileged
  helper is launched on demand (one admin prompt); on Android the system VPN is used
  (approve the on-screen consent the first time). On Android the VPN keeps running in
  the background after you leave the app.

**Add a server config** by pasting a `leshiy://` link, scanning a **QR code** (live
camera on Android, or from an image file), or reading it from the clipboard.

**Split tunnel — decide what actually goes through the tunnel:**

- **By network / domain** — include or exclude specific IP ranges (CIDRs) and domains,
  IPv4 and IPv6 alike.
- **Community rule lists** — subscribe to curated preset lists (e.g. route or bypass
  whole regions); they refresh automatically.
- **Per-app (Android)** — tunnel only the apps you choose, or everything _except_ them.

**Live status:** connection state, real-time throughput, and round-trip latency to
your server.

> The apps are clients — you still need a server to connect to. Self-host one with the
> [Quick start](#quick-start) below, then share its `leshiy://` URI (or QR) with the app.

## How it compares

Capability-level comparison (not a benchmark; the alternatives are mature and widely
deployed, Leshiy is new):

|                               |           **Leshiy**            |    Xray (VLESS+REALITY)    |      AmneziaWG       |     Hysteria2     |
| ----------------------------- | :-----------------------------: | :------------------------: | :------------------: | :---------------: |
| Censor-facing cloak           | REALITY **+** HTTP/3 masquerade |    REALITY (SNI-borrow)    | obfuscated WireGuard | HTTP/3 masquerade |
| Transports                    |       **TCP _and_ QUIC**        |       TCP (primary)        |       UDP only       |  UDP (QUIC) only  |
| Auto QUIC↔TCP fallback        |           ✅ built-in           |             ❌             |          ❌          |        ❌         |
| Anti-active-probing           |          ✅ both paths          |             ✅             |       partial        |        ✅         |
| Stream multiplexing           |            ✅ native            |       optional (mux)       |     n/a (L3 VPN)     |     ✅ (QUIC)     |
| Post-quantum key exchange     |           ✅ default            |          optional          |          ❌          |      via TLS      |
| Per-user caps / rate / expiry |      ✅ built-in (+sqlite)      | via panels (3x-ui/Marzban) |   external tooling   |      partial      |
| Entry/Exit relay chaining     |   ✅ **built-in, chainable**    |   manual (`dialerProxy`)   |          ❌          |        ❌         |
| Implementation                |          **pure Rust**          |             Go             |          Go          |        Go         |
| Maturity                      |      **beta / unaudited**       |           mature           |        mature        |      mature       |

**Where Leshiy aims to differ:** one tool that runs _both_ a REALITY/TCP and a QUIC/HTTP-3
transport with automatic fallback, ships a built-in **entry/exit connector with relay
chaining**, includes **multi-user management** without a separate panel, and is **pure
Rust** (no BoringSSL/C dependency). The trade-off is track record — Xray, AmneziaWG, and
Hysteria2 are battle-tested and audited over years; Leshiy works well today but is newer
and not yet independently audited.

---

## Quick start

Build (or grab a release binary):

```sh
cargo build --release    # binary at ./target/release/leshiy
```

### 0. One-command install (recommended)

On a fresh VPS, as root:

```sh
curl -fsSL https://github.com/bigunmd/leshiy/releases/latest/download/install.sh | sh
```

This downloads a **signed** static binary (verified with minisign + SHA-256), runs the
setup wizard, installs a hardened systemd service on 443, and prints your client
`leshiy://` URI + a QR code.

To pass flags, append them after `sh -s --` (the `-s` makes `sh` read the script from
stdin; `--` ends `sh`'s own options so the rest go to the installer):

```sh
URL=https://github.com/bigunmd/leshiy/releases/latest/download/install.sh

# Also enable the QUIC/HTTP-3 transport (443/udp) alongside REALITY:
curl -fsSL $URL | sh -s -- --quic

# Run on non-default ports (REALITY/TCP + QUIC/UDP), e.g. behind a shared IP:
curl -fsSL $URL | sh -s -- --port 10559 --quic 10560

# Install as a Docker container instead of a native systemd service:
curl -fsSL $URL | sh -s -- --docker

# QUIC with a custom SNI (the qsni in the URI); defaults to the --dest hostname:
curl -fsSL $URL | sh -s -- --quic --quic-sni cdn.cloudflare.com
```

Other flags: `--host <ip:port>`, `--dest <host:port>`, `--port <tcp-port>` (REALITY/TCP
listen port, default 443), `--quic [udp-port]` (bare = same as `--port`), `--quic-sni <domain>`,
`--role single|entry|exit`, `--exit-uri '<leshiy://…>'`, `--yes`. Prefer to inspect first? The script is short — read it
at the URL above before piping to `sh`.

### 1. Run a server

```sh
# Generate the server identity + config, and print the client share URI.
#   --host : the public address clients dial (goes into the URI)
#   --dest : a real, popular, regionally-plausible TLS 1.3 site to camouflage as
leshiy server-init \
    --host <public-ip>:443 \
    --dest www.microsoft.com:443 \
    --out leshiy-server.toml
# → prints:  leshiy://<pubkey>@<public-ip>:443?sni=www.microsoft.com&sid=<hex>

# Start it (foreground; run under systemd/your supervisor in production):
leshiy server --config leshiy-server.toml
```

### 2. Connect a client

On the machine you want to tunnel from (Linux, **no root needed** — the client only opens a
local port), install the verified binary into `~/.local/bin`:

```sh
# minisign is required to verify the download (one-time): apt/dnf/pacman/apk install minisign, or `brew install minisign`
curl -fsSL https://github.com/bigunmd/leshiy/releases/latest/download/install-client.sh | sh
```

Then start the local SOCKS5 proxy with the `leshiy://` URI your server printed:

```sh
leshiy connect 'leshiy://<pubkey>@<public-ip>:443?sni=www.microsoft.com&sid=<hex>'
# `connect` defaults to SOCKS5 on 127.0.0.1:1080, transport auto. Point any app at it:
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

`connect` is shorthand for the full form, if you prefer explicit flags:

```sh
leshiy client \
    --uri 'leshiy://…' \
    --transport auto \
    --socks 127.0.0.1:1080
```

`--transport`: `auto` (default — QUIC then REALITY), `quic`, or `tcp`.
`--socks`: change the local listen address (default `127.0.0.1:1080`).

### 3. Manage users (optional)

`server-init` creates one user. Add and control more on a **running** server:

```sh
leshiy user add --data-cap 50GB --rate-down 50Mbps --expires +30d
#   → prints a new leshiy:// URI to share with that user
leshiy user list
leshiy user show   <short-id>
leshiy user disable <short-id>      # cut access instantly
leshiy user reset-usage <short-id>
```

Add `--qr` to print a scannable QR for any share URI:

```sh
leshiy user add --data-cap 50GB --qr      # prints the leshiy:// URI + a QR to scan
```

### Day-2 management (`leshiyctl`)

The installer drops a `leshiyctl` helper that works for both native and Docker installs:

```sh
leshiyctl status      # native: service + config summary;  docker: container status + logs
leshiyctl upgrade     # native: verified binary swap + restart;  docker: pull image + recreate
leshiyctl uninstall   # stop + remove the server (add --purge to delete config/keys)
leshiyctl user ...    # manage users (runs inside the container on a docker install)
```

### 4. Enable the QUIC transport (optional)

Add a QUIC/HTTP-3 endpoint so clients can use the UDP path (auto-fallback handles the rest):

```sh
leshiy server-init --host <public-ip>:443 --dest www.microsoft.com:443 \
    --quic-listen <public-ip>:443 --out leshiy-server.toml
# The printed URI now also carries the QUIC endpoint + a pinned cert fingerprint.
```

### 5. Set up an Entry → Exit connector (optional, advanced)

With the installer (recommended), on each box:

```sh
# On the EXIT (clean egress): note the printed connector-credential URI.
curl -fsSL https://github.com/bigunmd/leshiy/releases/latest/download/install.sh | sh -s -- \
    --role exit --dest www.cloudflare.com:443 --quic
# → prints EXIT_URI = leshiy://…

# On the ENTRY (censor-facing): point it at the exit; hand its printed URI to clients.
curl -fsSL https://github.com/bigunmd/leshiy/releases/latest/download/install.sh | sh -s -- \
    --role entry --dest www.microsoft.com:443 --exit-uri '<EXIT_URI>'
```

Stand the **exit up first** (you need its URI for the entry). Chain further hops by giving the
exit its own `--exit-uri`. The chain lives only in server-side config, so a leaked client
config exposes just the entry.

Keep the censor-facing **entry** small and disposable; do the real egress on a separate,
clean **exit**.

```sh
# On the EXIT (clean-egress server): set it up and note its URI.
leshiy server-init --host <exit-ip>:443 --dest www.cloudflare.com:443 \
    --quic-listen <exit-ip>:443 --out exit.toml
# → EXIT_URI = leshiy://...   (this is the connector credential)

# On the ENTRY (censor-facing server): forward to the exit instead of egressing directly.
leshiy server-init --host <entry-ip>:443 --dest www.microsoft.com:443 \
    --connector '<EXIT_URI>' --out entry.toml
# Give clients the ENTRY's URI. Chain further by giving the EXIT its own --connector.
```

### 6. Provision a server from the client

Stand up a fresh VPS into a leshiy server over SSH:

```sh
leshiy remote provision --host root@203.0.113.5 --dest www.microsoft.com:443
# ... live progress, then your first client config:
#   leshiy://...   (stdout)
#   <QR code>      (stderr)

# Non-root user with sudo — prompts for the sudo password (day-2 ops re-prompt):
leshiy remote provision --host deploy@203.0.113.5 --dest www.microsoft.com:443 --sudo
# Automate it (feed the sudo password on stdin instead of prompting):
printf '%s' "$SUDO_PW" | leshiy remote provision --host deploy@HOST --dest D --sudo-password-stdin
```

> **Note:** the server image must be built from this release for `--dest` and `--quic` to take effect.
> Re-running `provision` against an already-provisioned host **reuses the existing server config**
> (keys persist on a Docker volume); to change `--dest`/`--quic`, `teardown` the server first, then provision again.
> `--port <n>` sets the REALITY/TCP listen port (default 443).

Saved servers live in an encrypted vault (`~/.config/leshiy/servers.lvault`,
Argon2id + XChaCha20-Poly1305). Manage them with `leshiy remote ls`,
`leshiy remote user add <server> --label phone`, `leshiy remote status <server>`,
`leshiy remote backup <server> --out server.lvault` (add `--connection-only`
to share without SSH credentials), `leshiy remote restore server.lvault`, and
`leshiy remote teardown <server> [--purge]`.

`leshiy remote user ls <server>` lists the users currently on the server (live),
and `leshiy remote user rm <server> <short_id>` deletes one. (Live `user ls`
needs a server image built from this release or newer — it relies on
`leshiy user list --json`.)

**Chained (Entry ▶ Exit):** provision the exit first, then the entry selecting it.

```sh
# 1. Exit (terminal clean egress; QUIC carrier auto-enabled):
leshiy remote provision --role exit --host root@EXIT_IP --dest www.cloudflare.com:443
#    → prints a connector credential and saves the server (e.g. id EXIT_IP-22)

# 2. Entry (censor-facing; forwards to the exit):
leshiy remote provision --role entry --host root@ENTRY_IP --dest www.microsoft.com:443 \
    --downstream EXIT_IP-22
#    → issues the client config (QR). Clients connect to the entry; traffic exits via the exit.
```

Add `--role middle --downstream <prev>` nodes for extra hops. `leshiy remote ls` shows each server's role and downstream.

**Prerequisite:** a published server image (default `ghcr.io/leshiy/leshiy:1.5.0`);
override with `--image`.

---

## License

Licensed under the GNU Affero General Public License v3.0 — see
[LICENSE](LICENSE) or <https://www.gnu.org/licenses/agpl-3.0.html>.

AGPL-3.0 is strong copyleft: if you modify Leshiy and let others use it over a
network (e.g. you run a modified server), you must offer them your modified source.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in the work by you shall be licensed under AGPL-3.0 as above, without any
additional terms or conditions.
