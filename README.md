# LESHIY

Secure, fast and highly stealthy VPN protocol.

A greenfield, self-hostable censorship-circumvention tunnel written in Rust,
designed to resist modern DPI (with Russia/TSPU as the primary target threat model).

> **Status:** M1.4b — REALITY-style stealth tunnel, user-runnable via a single
> `leshiy://` URI. The handshake is camouflaged as a normal TLS 1.3 ClientHello
> to a real site (configurable via `--dest`). See [`docs/`](docs/) for the design
> spec, ADRs, and roadmap.

## Quick start

```sh
# 1. On the server — generate keys, write config, and print the share URI.
#    --host   : public address clients will dial (goes into the URI)
#    --dest   : a real TLS 1.3 site to borrow for camouflage (your server
#               acts as a transparent relay for unauthenticated probers)
leshiy server-init \
    --host <public-ip>:443 \
    --dest www.microsoft.com:443 \
    --out leshiy-server.toml
# Prints something like:
#   leshiy://<base64-pubkey>@<public-ip>:443?sni=www.microsoft.com&sid=<hex>

# 2. On the server — start the REALITY tunnel.
leshiy server --config leshiy-server.toml

# 3. On the client — start a local SOCKS5 proxy that tunnels through REALITY.
leshiy client --uri 'leshiy://<base64-pubkey>@<public-ip>:443?sni=www.microsoft.com&sid=<hex>' \
              --socks 127.0.0.1:1080
# Then point your browser / curl / any app at the SOCKS5 proxy on 127.0.0.1:1080.
```

## License

Licensed under the Apache License, Version 2.0 ([LICENSE](LICENSE) or
<https://www.apache.org/licenses/LICENSE-2.0>).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
licensed as above, without any additional terms or conditions.
