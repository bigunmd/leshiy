# LESHIY

**Secure, fast, and highly stealthy tunnel for censored networks.**

A greenfield, self-hostable censorship-circumvention tunnel written in pure Rust,
designed to resist modern Deep Packet Inspection (DPI) — with Russia / TSPU as the
primary target threat model. You run your own server(s); clients connect with a
single `leshiy://` URI.

> ⚠️ **Maturity:** Leshiy is **new and has not been independently security-audited
> or field-tested against a live censor.** The design is built on published,
> peer-reviewed anti-censorship research, but treat it as **alpha** software — use
> it at your own risk and prefer mature, vetted tools for high-stakes situations.

---

## What it does

Leshiy gives the client a local **SOCKS5 proxy**. Traffic sent through it is wrapped
so that, to a censor on the wire, it looks like an ordinary visit to a real website —
not a VPN.

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
    prober, an unauthenticated connection is transparently relayed to that real site.
  - **QUIC / HTTP-3:** a real HTTP/3 server; authenticated clients tunnel via HTTP/3
    `CONNECT`, while probers get a normal web response (masquerade). Cert-pinned.
  - **`--transport auto`** uses QUIC where UDP is open and **falls back to REALITY/TCP
    when UDP is blocked** — automatically.
- **Post-quantum key exchange** (X25519MLKEM768 hybrid) on the REALITY path.
- **Anti-active-probing** on both transports (a wrong key / no key never reveals a proxy).
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

## How it compares

Capability-level comparison (not a benchmark; the alternatives are mature and widely
deployed, Leshiy is new):

| | **Leshiy** | Xray (VLESS+REALITY) | AmneziaWG | Hysteria2 |
|---|:---:|:---:|:---:|:---:|
| Censor-facing cloak | REALITY **+** HTTP/3 masquerade | REALITY (SNI-borrow) | obfuscated WireGuard | HTTP/3 masquerade |
| Transports | **TCP _and_ QUIC** | TCP (primary) | UDP only | UDP (QUIC) only |
| Auto QUIC↔TCP fallback | ✅ built-in | ❌ | ❌ | ❌ |
| Anti-active-probing | ✅ both paths | ✅ | partial | ✅ |
| Stream multiplexing | ✅ native | optional (mux) | n/a (L3 VPN) | ✅ (QUIC) |
| Post-quantum key exchange | ✅ default | optional | ❌ | via TLS |
| Per-user caps / rate / expiry | ✅ built-in (+sqlite) | via panels (3x-ui/Marzban) | external tooling | partial |
| Entry/Exit relay chaining | ✅ **built-in, chainable** | manual (`dialerProxy`) | ❌ | ❌ |
| Implementation | **pure Rust** | Go | Go | Go |
| Maturity | **alpha / unaudited** | mature | mature | mature |

**Where Leshiy aims to differ:** one tool that runs *both* a REALITY/TCP and a QUIC/HTTP-3
transport with automatic fallback, ships a built-in **entry/exit connector with relay
chaining**, includes **multi-user management** without a separate panel, and is **pure
Rust** (no BoringSSL/C dependency). The trade-off is maturity — Xray, AmneziaWG, and
Hysteria2 are battle-tested; Leshiy is not yet.

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

# Install via Docker + compose instead of native systemd:
curl -fsSL $URL | sh -s -- --docker

# QUIC with a custom SNI (the qsni in the URI); defaults to the --dest hostname:
curl -fsSL $URL | sh -s -- --quic --quic-sni cdn.cloudflare.com
```

Other flags: `--host <ip:port>`, `--dest <host:port>`, `--quic-sni <domain>`,
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
leshiyctl status      # service + config summary (or `docker compose ps`)
leshiyctl upgrade     # verified binary download + restart (or `compose pull && up -d`)
leshiyctl uninstall   # stop + remove service and binary (add --purge to delete config/keys)
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
