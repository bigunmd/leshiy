# Ground-Truth Yandex Browser ClientHello Fixture — Provenance

## Status: AUTHENTIC — Yandex Browser 26.4.0.0 (Chromium 146, Windows 11)

**Authenticity:** AUTHENTIC capture. The committed fixtures (`yandex.ja4`,
`yandex.ja4_r`, `yandex.ja3`) and `Profile::yandex()` were verified field-by-field
against a live Yandex Browser 26.4.0.0 ClientHello on 2026-06-10.

**Confidence level:** HIGH. The JA4 was reported identically by two independent
fingerprinting endpoints (tls.peet.ws and browserleaks.com/tls), and the raw `ja4_r`
field lists (ciphers, extensions, signature algorithms) match `Profile::yandex()`
exactly.

> Historical note: prior to 2026-06-10 these fixtures were a documented Chrome 134
> (Mac) fallback (no authentic Yandex capture was available in public databases).
> The authentic capture confirmed the fallback was already correct at the JA4 level —
> Chromium 134→146 kept the same cipher suites and extension set (ALPS still present),
> so the JA4 `t13d1516h2_8daaf6152771_d8a2da3f94cd` was unchanged.

---

## Browser Version

- **Yandex Browser version:** 26.4.0.0
- **Underlying Chromium base:** Chromium 146
  - Evidence: UA `Chrome/146.0.0.0 YaBrowser/26.4.0.0`; client hint
    `sec-ch-ua: "Chromium";v="146", "Not-A.Brand";v="24", "YaBrowser";v="26.4", "Yowser";v="2.5"`
- **Platform:** Windows 11 (Version 25H2, Build 26200.8457)
- **Capture date:** 2026-06-10
- **Capture method:** live ClientHello reported by tls.peet.ws (`/api/all`) and
  browserleaks.com/tls; cross-checked against three raw last-segment packet captures
  (Wireshark) of connections to www.gosuslugi.ru / www.mos.ru.

---

## Fingerprint Values Recorded

### JA4 (in `yandex.ja4`)
```
t13d1516h2_8daaf6152771_d8a2da3f94cd
```
Confirmed identical by **two independent endpoints**: tls.peet.ws and browserleaks.

JA4 part A breakdown `t13d1516h2`:
- protocol = `t` (TCP/TLS)
- version  = `13` (TLS 1.3)
- sni      = `d` (domain present)
- ciphers  = `15` (15 non-GREASE cipher suites)
- exts     = `16` (16 non-GREASE extensions, incl. SNI + ALPN)
- alpn     = `h2`

### JA4_r (in `yandex.ja4_r`)
The raw, unhashed JA4 — pins the exact cipher / extension / sig-alg content:
```
t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601
```
Source: tls.peet.ws `ja4_r` for Yandex 26.4.0.0 (2026-06-10). The test
`ja::tests::ja4_r_reproduces_authentic_yandex_capture` asserts `Profile::yandex()`
reproduces this string exactly.

### JA3 — UNSTABLE, do not rely on (in `yandex.ja3`)
JA3 is **not stable** for Chrome-family browsers: Chromium shuffles its TLS extension
order on every connection (`ShuffleChromeTLSExtensions`) and randomizes GREASE values
per connection, so the JA3 hash changes connection-to-connection. Three different JA3
hashes were observed for the *same* browser:

| Source                         | JA3 hash                           |
|--------------------------------|------------------------------------|
| tls.peet.ws (2026-06-10)       | `3ebe815087b9f632dc0ff06e977bf80d` |
| browserleaks (2026-06-10)      | `af56fea52b1a3d53f9eb86a4f55ce442` |
| committed `yandex.ja3` snapshot| `845db3b4e398789bdeb5b15594360a29` |

The committed `yandex.ja3` records the JA3 of the *canonical (unshuffled) `Profile`
order* only — useful as a characterization of the declared profile, **not** as
something observable on the wire. Leshiy itself shuffles extensions per connection
(see `camouflage::chrome_ext_permutation`), so it does not emit a single fixed JA3.
**JA4 is the reliable fingerprint for this project.**

---

## Complete Field Breakdown (authentic Yandex 26.4)

### Cipher Suites (15 non-GREASE + 1 GREASE placeholder)

ClientHello order (GREASE first, then these 15):

| Position | Decimal | Hex    | Name |
|----------|---------|--------|------|
| 0        | GREASE  | 0x?A?A | GREASE placeholder (randomized per connection) |
| 1        | 4865    | 0x1301 | TLS_AES_128_GCM_SHA256 |
| 2        | 4866    | 0x1302 | TLS_AES_256_GCM_SHA384 |
| 3        | 4867    | 0x1303 | TLS_CHACHA20_POLY1305_SHA256 |
| 4        | 49195   | 0xC02B | TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 |
| 5        | 49199   | 0xC02F | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 |
| 6        | 49196   | 0xC02C | TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 |
| 7        | 49200   | 0xC030 | TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 |
| 8        | 52393   | 0xCCA9 | TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 |
| 9        | 52392   | 0xCCA8 | TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 |
| 10       | 49171   | 0xC013 | TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA |
| 11       | 49172   | 0xC014 | TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA |
| 12       | 156     | 0x009C | TLS_RSA_WITH_AES_128_GCM_SHA256 |
| 13       | 157     | 0x009D | TLS_RSA_WITH_AES_256_GCM_SHA384 |
| 14       | 47      | 0x002F | TLS_RSA_WITH_AES_128_CBC_SHA |
| 15       | 53      | 0x0035 | TLS_RSA_WITH_AES_256_CBC_SHA |

### Extensions (16 non-GREASE + 2 GREASE)

Chromium shuffles the non-GREASE extensions per connection and pins one GREASE
extension first and one last. Two real captures showed completely different orders
(below), confirming the shuffle. The canonical SET (sorted) is what JA4 part C hashes.

Observed order, tls.peet.ws capture:
```
GREASE, 0x000a, 0x002b, 0x0010, 0x000b, 0x0017, 0x002d, 0x44cd, 0xfe0d,
0x0005, 0x0012, 0x001b, 0xff01, 0x0000, 0x0033, 0x000d, 0x0023, GREASE
```
Observed order, browserleaks capture (different!):
```
GREASE, 0x0023, 0x0005, 0x002b, 0x000d, 0x0012, 0xff01, 0xfe0d, 0x000a,
0x0033, 0x44cd, 0x0000, 0x0017, 0x0010, 0x002d, 0x001b, 0x000b, GREASE
```

Canonical set:

| Dec   | Hex    | Name |
|-------|--------|------|
| 0     | 0x0000 | server_name (SNI) |
| 5     | 0x0005 | status_request |
| 10    | 0x000A | supported_groups |
| 11    | 0x000B | ec_point_formats |
| 13    | 0x000D | signature_algorithms |
| 18    | 0x0012 | signed_certificate_timestamp (SCT) |
| 23    | 0x0017 | extended_master_secret |
| 27    | 0x001B | compress_certificate |
| 16    | 0x0010 | ALPN |
| 35    | 0x0023 | session_ticket |
| 43    | 0x002B | supported_versions |
| 45    | 0x002D | psk_key_exchange_modes |
| 51    | 0x0033 | key_share |
| 17613 | 0x44CD | application_settings (ALPS) |
| 65037 | 0xFE0D | encrypted_client_hello (GREASE-ECH outer) |
| 65281 | 0xFF01 | renegotiation_info |

**JA4 Part C sorted extension list** (SNI=0x0000 and ALPN=0x0010 excluded):
```
0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01
```

### Supported Groups (extension 0x000A)

| Position | Decimal | Hex    | Name |
|----------|---------|--------|------|
| 0        | GREASE  | 0x?A?A | GREASE (shares the per-connection value used in key_share) |
| 1        | 4588    | 0x11EC | X25519MLKEM768 (hybrid post-quantum) |
| 2        | 29      | 0x001D | x25519 |
| 3        | 23      | 0x0017 | secp256r1 (P-256) |
| 4        | 24      | 0x0018 | secp384r1 (P-384) |

### Signature Algorithms (extension 0x000D), in hello order (NOT sorted)
```
0403,0804,0401,0503,0805,0501,0806,0601
```
ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, rsa_pkcs1_sha256, ecdsa_secp384r1_sha384,
rsa_pss_rsae_sha384, rsa_pkcs1_sha384, rsa_pss_rsae_sha512, rsa_pkcs1_sha512.

### ALPN
`h2`, `http/1.1`

### application_settings / ALPS (0x44CD)
Body advertises a single protocol: `h2`.

### Supported Versions (0x002B)
GREASE, 0x0304 (TLS 1.3), 0x0303 (TLS 1.2).

### key_share (0x0033)
1. GREASE (group = the per-connection supported_groups GREASE value, 1-byte `00` key)
2. X25519MLKEM768 (0x11EC) — 1216-byte hybrid share (ML-KEM-768 ek ‖ x25519)
3. X25519 (0x001D) — 32-byte key

### encrypted_client_hello / GREASE-ECH (0xFE0D)
Chromium sends a GREASE-ECH **outer**:
- type = outer (0x00)
- kdf_id = 0x0001 (HKDF-SHA256), aead_id = 0x0001 (AES-128-GCM)
- config_id = 1 random byte
- enc = 32-byte X25519 public key
- payload = ~144–192 random "encrypted" bytes
(browserleaks decoded one as: config_id=21, enc_length=32, payload_length=176.)

### compress_certificate (0x001B): brotli (0x0002)
### psk_key_exchange_modes (0x002D): psk_dhe_ke (0x01)
### ec_point_formats (0x000B): uncompressed (0x00)
### session_ticket (0x0023): empty
### renegotiation_info (0xFF01): empty

### Per-connection GREASE
GREASE values are randomized per connection following BoringSSL's derivation: a single
seed produces distinct values for cipher / group / extension1 / extension2 / version,
where the **supported_groups GREASE equals the key_share GREASE**, and the two
extension-list GREASE values must differ. Observed pairs:
- tls.peet.ws: cipher=0xCACA, group=0x6A6A (groups & key_share), ext=0x5A5A/0x4A4A, version=0x0A0A
- browserleaks: cipher=0x9A9A, group=0x4A4A, ext=0xEAEA/0xFAFA, version=0x2A2A

---

## HTTP/2 fingerprint (informational; not emitted by Leshiy)

tls.peet.ws also reported the Akamai HTTP/2 fingerprint
`1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`. Leshiy speaks its own tunnel mux
after the TLS handshake, not real HTTP/2, so it never emits these frames. Recorded here
only for completeness should HTTP/2 emulation ever be added.

---

## Sources

1. tls.peet.ws `/api/all` — Yandex 26.4.0.0 JA4, JA4_r, JA3, peetprint, full ordered field lists (2026-06-10)
2. browserleaks.com/tls — independent JA4 + decoded extension/cipher breakdown (2026-06-10)
3. Three Wireshark last-segment packet captures (gosuslugi.ru / mos.ru) — confirmed ECH outer, key_share, shuffle
4. JA4 specification: https://github.com/FoxIO-LLC/ja4
5. IANA TLS extension registry: https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
6. BoringSSL GREASE derivation + extension permutation (ssl_get_grease_value / ShuffleChromeTLSExtensions)
