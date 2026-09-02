# LESHIY

**A tunnel that looks like ordinary HTTPS.**

Self-hosted censorship circumvention in pure Rust, built to resist modern Deep Packet
Inspection — with Russia / TSPU as the primary threat model. You run the server; clients
connect with a single `leshiy://` link.

> **Beta.** The protocol is stable and the Linux, Windows and Android clients are used
> daily. The core crates (~16k LOC) had a full line-by-line adversarial review in July
> 2026 — every Critical, High and Medium finding is fixed, most with regression tests.
> 716 tests, and CI gates every push.
>
> **But there has been no independent security audit**, and no systematic field testing
> against a live censor. If being identified as a circumvention user carries real
> consequences for you, prefer a tool that has been audited and battle-proven.

---

## Table of contents

- [What it does](#what-it-does)
- [Features](#features)
- [Quick start](#quick-start)
  - [1. Install](#1-install)
  - [2. Get a server](#2-get-a-server)
  - [3. Connect](#3-connect)
  - [4. Manage users](#4-manage-users)
- [Interactive mode](#interactive-mode)
- [Going further](#going-further)
- [Desktop and mobile apps](#desktop-and-mobile-apps)
- [How it compares](#how-it-compares)
- [License](#license)

---

## What it does

Leshiy gives you a local **SOCKS5 proxy** or a **full-device VPN**. To a censor watching
the wire, your traffic looks like an ordinary visit to a real website.

```
                  censored network            │   open internet
  ┌────────┐   REALITY (TLS) or HTTP/3-QUIC   │
  │ client │ ──────── (auto-selected) ───────▶│  Entry  ──connector──▶  Exit  ──▶  Internet
  └────────┘     looks like real HTTPS to     │  (cloak +              (clean
   SOCKS5         the censor; cert-verified    │   per-user limits)     egress)
                                               │      └── chainable: Entry ▶ A ▶ B ▶ … ▶ Exit
```

## Features

- **Two cloaked transports, picked automatically.** **REALITY** borrows a real site's TLS
  identity on TCP/443; **QUIC/HTTP-3** runs a real HTTP/3 server. `auto` uses QUIC where
  UDP is open and **falls back to TCP when it is blocked**.
- **Anti-active-probing on both paths.** A wrong key never reveals a proxy — probers are
  transparently relayed to the real site, or get a normal web page.
- **Carries UDP, not just TCP.** DNS, QUIC, WebRTC and games ride the tunnel.
- **Full dual-stack IPv6**, with a fail-closed kill-switch so it cannot leak around a
  v6-unaware path.
- **Post-quantum key exchange** (X25519MLKEM768 hybrid) on the REALITY path.
- **Stream multiplexing** — the published defense against TLS-in-TLS traffic analysis.
- **Built-in multi-user management** — per-user data caps, speed limits and expiry,
  enforced in the data path. No external panel.
- **Entry/Exit chaining.** Split the censor-facing entry from the internet-facing exit,
  joined by a built-in QUIC carrier and chainable across hops. The chain lives in
  server-side config, so a leaked client link exposes only the entry.
- **Pure Rust, no C TLS stack.** `#![forbid(unsafe_code)]` in the core crates.

---

## Quick start

Every setup command below takes **`-i`**, which asks you what it needs instead of making
you look up flags. That is the recommended path; the flags are all still there for
scripting.

### 1. Install

On the machine you want to tunnel *from*, no root needed:

```sh
curl -fsSL https://github.com/bigunmd/leshiy/releases/latest/download/install-client.sh | sh
```

Needs `minisign` on PATH to verify the download (`apt install minisign`, `brew install minisign`, …).
Or build it yourself: `cargo build --release`.

### 2. Get a server

**From your laptop, onto a fresh VPS** — the easiest path. Leshiy SSHes in, installs
everything, and hands you a client link:

```sh
leshiy remote provision -i
```

It asks for the SSH target, offers a list of camouflage sites (and **live-probes** the one
you pick for TLS 1.3), lets you choose the role and ports, then shows you exactly what it
is about to do before touching anything. Saved servers go into an encrypted vault, so
later commands just let you pick one from a list.

> Provisioning pulls the container image matching your CLI
> (`ghcr.io/bigunmd/leshiy:v<version>`), so run a released build — or point `--image`
> somewhere else.

**Or, if you are already on the VPS**, as root:

```sh
curl -fsSL https://github.com/bigunmd/leshiy/releases/latest/download/install.sh | sh
```

This installs a signed binary, runs the setup, and starts a hardened systemd service on
443. To do it by hand instead — including entry/exit roles — use `leshiy quickstart -i`,
which detects the machine's public address for you.

Either way you end up with a `leshiy://…` link and a QR code.

### 3. Connect

```sh
leshiy connect -i
```

It asks **how** you want to connect:

```
? How do you want to connect? ›
❯ Local SOCKS5 proxy                  no root needed; point your apps at 127.0.0.1:1080
  Full-device VPN                     routes everything on this machine; will prompt for sudo
  Full-device VPN via the helper      same, but no sudo prompt
  Background proxy service            a systemd user unit; survives logout
  Background full-device VPN service  survives reboot, needs root
```

…then **which server** — picked from the ones you provisioned, so there is nothing to copy
and paste. Given a link by someone else? Paste it instead.

With a proxy running, point any app at it:

```sh
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

Already know what you want? Skip straight to it:

```sh
leshiy connect 'leshiy://…'      # proxy, one shot
leshiy tun -i                    # full-device VPN
leshiy service start -i          # background service
```

### 4. Manage users

Your server starts with one user. Add more to a **running** server:

```sh
leshiy remote user add -i                             # a server you provisioned
leshiy user add --data-cap 50GB --expires +30d --qr   # on the server itself
```

Each prints a new `leshiy://` link to hand out. Also `user list`, `user show <id>`,
`user disable <id>` (cuts access instantly) and `user rm <id>`.

---

## Interactive mode

`-i` works across the whole CLI. Anything you pass as a flag is not asked about, and every
wizard ends by printing the equivalent flag-only command — so it teaches you the scriptable
form as you go.

| Command | What `-i` gives you |
| --- | --- |
| `leshiy connect -i` | pick proxy / VPN / background service, then a saved server |
| `leshiy remote provision -i` | stand up a remote VPS over SSH |
| `leshiy remote <cmd> -i` | pick a saved server from a list instead of typing its id |
| `leshiy quickstart -i` | stand up a server on this machine |
| `leshiy tun -i`, `leshiy vpn -i` | full-device VPN, directly |
| `leshiy service start -i` | install and start the background service |

It needs a terminal — in a script it refuses immediately rather than hanging.

---

## Going further

**Entry → Exit chain.** Keep the censor-facing entry small and disposable; do the real
egress on a separate, clean box. Stand the **exit up first**, then point an entry at it:

```sh
leshiy remote provision -i --role exit     # prints a connector credential
leshiy remote provision -i --role entry    # pick the exit from a list
```

Give clients the **entry's** link. Add `--role middle` nodes for extra hops. The chain is
server-side only, so a leaked client link never exposes your topology.

**QUIC.** Turned on by answering yes in `quickstart -i` / `remote provision -i`, or with
`--quic-listen <host:port>`. Clients pick it up automatically and fall back to TCP when
UDP is blocked.

**Day-2 management.** The installer drops `leshiyctl`, which works for both native and
Docker installs: `leshiyctl status | upgrade | uninstall | user …`.

For servers you provisioned remotely: `leshiy remote ls`, `status`, `upgrade`, `backup`
(add `--connection-only` to share without SSH credentials), `restore` and `teardown` —
all of them take `-i`.

**Scripting.** Every wizard has a flag-only equivalent: run it once with `-i` and copy the
command it prints. Credentials are never echoed into that line — keep a `leshiy://` link
in a `0600` file and pass `--uri-file` to stay out of shell history and `ps`.

---

## Desktop and mobile apps

Graphical clients for **Linux, Windows, macOS and Android** — paste a link or scan its QR
and connect in one tap. Grab them from the
[Releases page](https://github.com/bigunmd/leshiy/releases).

Both proxy and full-VPN modes, **split tunnelling** (by domain, by CIDR, or per-app on
Android), community rule lists that refresh themselves, and live throughput and latency.

The **Android** app (native Kotlin/Compose, min Android 8.0) goes furthest: Quick Settings
tile, home-screen widget, always-on VPN, biometric lock, signed in-app updates — and it can
**provision and manage your servers from the phone**, including entry/exit cascades, with
credentials in an encrypted on-device vault.

> Linux, Windows and Android are tested and working; macOS is provided but less exercised.
> There is no iOS app. The Android app is unit-tested in CI but has no on-device matrix
> across vendors yet — OEM battery managers vary a lot in how aggressively they kill
> background VPNs.

---

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

**Where Leshiy differs:** one tool running *both* transports with automatic fallback, a
built-in chainable entry/exit connector, multi-user management without a separate panel,
and pure Rust with no BoringSSL/C dependency. The trade-off is track record — Xray,
AmneziaWG and Hysteria2 are battle-tested over years.

---

## License

[AGPL-3.0](LICENSE). Strong copyleft: if you modify Leshiy and let others use it over a
network, you must offer them your modified source.

Contributions are accepted under the same license unless you state otherwise.
