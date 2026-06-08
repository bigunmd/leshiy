# Ground-Truth Yandex Browser ClientHello Fixture — Provenance

## Status: Chrome 134 (Mac) — DOCUMENTED FALLBACK, replace with authentic Yandex capture

**Authenticity:** CHROME FALLBACK — not an authentic Yandex Browser capture.
See "Authenticity & Fallback Rationale" section below.

**Confidence level:** HIGH for Chrome 134 Mac (JA3 and JA4 independently computed and
verified against two sources). MEDIUM for Yandex Browser equivalence (same Chromium
lineage, but Yandex may add or omit extensions — no primary Yandex capture confirmed).

---

## Yandex Browser Version

- **Yandex Browser version:** 26.4.3.897 (Windows/macOS, released 2026-06-03)
- **Underlying Chromium base:** Chrome/Chromium 148
  - Evidence: UA string `Chrome/148.0.0.0 YaBrowser/26.4.3.897` (from whatismybrowser.com)
- **Source URL (version):** https://www.whatismybrowser.com/guides/the-latest-version/yandex-browser
- **Lookup date:** 2026-06-07

---

## Fingerprint Values Recorded

### JA4 (in `yandex.ja4`)
```
t13d1516h2_8daaf6152771_d8a2da3f94cd
```
Source: Chrome 134 (Mac), from lexiforest/curl_cffi GitHub issue #529.

**Cross-validation (3 independent sources confirm this JA4):**
1. `github.com/lexiforest/curl_cffi/issues/529` — primary capture of Chrome 134 Mac with full JA3N and JA4
2. `github.com/telegramdesktop/tdesktop/issues/30733` — references Chrome 134 Mac as "t13d1516h2_8daaf6152771_d8a2da3f94cd" (before updating to Chrome 148 Windows)
3. `github.com/ntop/ndpi/issues/2914` — uses "t13d1516h2_8daaf6152771_d8a2da3f94cd" in PCAP-based JA4 test

**Mathematically verified:** Both JA4 parts B and C were independently recomputed in Python
from the known cipher and extension lists and matched exactly:
- Part A: `t13d1516h2` — protocol=t(TCP/TLS), ver=13(TLS 1.3), sni=d(domain), ciphers=15, exts=16, alpn=h2
- Part B: `8daaf6152771` — SHA-256[:12] of sorted hex cipher IDs (confirmed match)
- Part C: `d8a2da3f94cd` — SHA-256[:12] of sorted non-SNI/ALPN extension IDs + `_` + sig alg IDs (confirmed match)

### JA3 (in `yandex.ja3`)
Line 1 — MD5 hash: `845db3b4e398789bdeb5b15594360a29`
Line 2 — Raw JA3 string (order-as-observed in one capture, extensions NOT sorted):
```
771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,51-27-65281-18-45-0-35-5-11-43-16-65037-23-17613-13-10,4588-29-23-24,0
```
**Warning:** JA3 is NOT stable for Chrome-family browsers because Chrome shuffles extension
order per connection. The raw JA3 string shown is one capture snapshot (from curl_cffi #529).
Different captures will give different JA3 strings and different hashes. The JA4 is the
reliable fingerprint for this project's purposes.

The JA3 hash was **mathematically verified**: recomputing MD5 from the raw JA3 string
produces `845db3b4e398789bdeb5b15594360a29` exactly.

---

## Complete Field Breakdown

This breakdown describes the **Chrome 134 (Mac)** ClientHello on which these fixtures are based.
Yandex Browser 26.4 (Chromium 148) may differ in minor ways (see Known Differences section).

### Cipher Suites (ordered, 15 non-GREASE + 1 GREASE placeholder)

Actual ClientHello order (GREASE first, then these 15):

| Position | Decimal | Hex    | Name |
|----------|---------|--------|------|
| 0        | GREASE  | 0x?A?A | GREASE placeholder (random per connection) |
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

### Extensions (16 non-GREASE + 2 GREASE in actual ClientHello)

Chrome shuffles the non-fixed extensions per connection (via `ShuffleChromeTLSExtensions`).
The table below shows the CANONICAL SET; order in one observed capture shown in "Observed
position" column (from JA3 raw string in curl_cffi #529).

| Observed pos | Dec   | Hex    | Name |
|--------------|-------|--------|------|
| 1            | 51    | 0x0033 | key_share |
| 2            | 27    | 0x001B | compress_certificate |
| 3            | 65281 | 0xFF01 | renegotiation_info |
| 4            | 18    | 0x0012 | signed_certificate_timestamp (SCT) |
| 5            | 45    | 0x002D | psk_key_exchange_modes |
| 6            | 0     | 0x0000 | server_name (SNI) — NOT shuffled, fixed first among shuffled |
| 7            | 35    | 0x0023 | session_ticket |
| 8            | 5     | 0x0005 | status_request |
| 9            | 11    | 0x000B | ec_point_formats |
| 10           | 43    | 0x002B | supported_versions |
| 11           | 16    | 0x0010 | ALPN (application_layer_protocol_negotiation) |
| 12           | 65037 | 0xFE0D | encrypted_client_hello (ECH, GREASE outer) |
| 13           | 23    | 0x0017 | extended_master_secret |
| 14           | 17613 | 0x44CD | application_settings_new (ALPS) |
| 15           | 13    | 0x000D | signature_algorithms |
| 16           | 10    | 0x000A | supported_groups |
| (GREASE 0)   | GREASE| 0x?A?A | GREASE extension — before first non-GREASE |
| (GREASE 17)  | GREASE| 0x?A?A | GREASE extension — after last non-GREASE |

**JA4 Part C sorted extension list** (SNI=0x0000 and ALPN=0x0010 excluded):
```
0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01
```

### Supported Groups (in extension 0x000A)

In ClientHello order (GREASE + 4 real groups):

| Position | Decimal | Hex    | Name |
|----------|---------|--------|------|
| 0        | GREASE  | 0x?A?A | GREASE placeholder |
| 1        | 4588    | 0x11EC | X25519MLKEM768 (hybrid post-quantum, draft-ietf-tls-hybrid-design) |
| 2        | 29      | 0x001D | x25519 |
| 3        | 23      | 0x0017 | secp256r1 (P-256) |
| 4        | 24      | 0x0018 | secp384r1 (P-384) |

Note: X25519MLKEM768 (0x11EC) is the Kyber-768 + X25519 hybrid post-quantum group
introduced in Chrome 124+ (Chromium stable).

### Signature Algorithms (in extension 0x000D)

In ClientHello order (NOT sorted for JA4 part C):

| Position | Hex    | Decimal | Name |
|----------|--------|---------|------|
| 1        | 0x0403 | 1027    | ecdsa_secp256r1_sha256 |
| 2        | 0x0804 | 2052    | rsa_pss_rsae_sha256 |
| 3        | 0x0401 | 1025    | rsa_pkcs1_sha256 |
| 4        | 0x0503 | 1283    | ecdsa_secp384r1_sha384 |
| 5        | 0x0805 | 2053    | rsa_pss_rsae_sha384 |
| 6        | 0x0501 | 1281    | rsa_pkcs1_sha384 |
| 7        | 0x0806 | 2054    | rsa_pss_rsae_sha512 |
| 8        | 0x0601 | 1537    | rsa_pkcs1_sha512 |

**JA4 Part C sig algs string** (in hello order, NOT sorted):
```
0403,0804,0401,0503,0805,0501,0806,0601
```

### ALPN
- `h2` (HTTP/2)
- `http/1.1`

### Supported TLS Versions (in extension 0x002B)
1. GREASE placeholder
2. 0x0304 (TLS 1.3)
3. 0x0303 (TLS 1.2)

### key_share Groups (in extension 0x0033)
1. GREASE placeholder (1-byte zero key)
2. X25519MLKEM768 (0x11EC) — full key material
3. X25519 (0x001D) — 32-byte key

### compress_certificate (0x001B)
- Brotli (0x0002)

### psk_key_exchange_modes (0x002D)
- psk_dhe_ke (0x01)

### ec_point_formats (0x000B)
- uncompressed (0x00)

### session_ticket (0x0023)
- Empty (0 bytes of ticket data on fresh connection)

### renegotiation_info (0xFF01)
- Empty (0x00 length of renegotiation data = no prior renegotiation)

---

## Raw ClientHello Binary

**Not produced.** No raw `.bin` file was captured; a `.bin` file cannot be reconstructed without
knowing the exact GREASE values, random bytes, and key_share public keys used in a specific
connection. The `.bin` file is to be generated by the builder (Task 5) and validated against
the committed JA4 in `yandex.ja4` once the builder is implemented.

---

## Known Differences: Chrome 134 (Mac) vs Chrome 148 Windows

The Telegram Desktop issue #30733 shows that Chrome 148 on Windows uses:
```
t13d1514h2_8daaf6152771_827b515c4f52
```
vs Chrome 134 on Mac:
```
t13d1516h2_8daaf6152771_d8a2da3f94cd
```
Key differences:
- `1514` vs `1516`: Chrome 148 Windows has **14** non-GREASE extensions (not 16)
- Part C differs: the extension or sig_alg content changed

The exact Chrome 148 extension set has not been fully reverse-engineered. Since Yandex Browser
26.4 is based on Chromium 148 but typically ships on Windows as the primary platform, the
Chrome 148 Windows fingerprint may be closer to what Yandex Browser 26.4 actually emits.

**TODO:** Replace this fixture with an authentic Yandex Browser 26.4 capture, or at minimum
a verified Chrome 148 Windows capture. The current fixture (Chrome 134 Mac) uses the same
cipher suite B-hash and is verified mathematically, but the extension set (JA4 part C) may
differ from what Yandex Browser 26.4 actually produces.

---

## Authenticity & Fallback Rationale

No dedicated Yandex Browser TLS capture was found in any public fingerprint database:
- `tlsfingerprint.io` — currently suspended (funding cut)
- `ja4db.com` — timed out; the FoxIO JA4 CSV only contained generic Chromium, Firefox, Safari entries, no Yandex
- `tls.peet.ws` — expired certificate
- GitHub search for uTLS Yandex profiles — no dedicated Yandex profile found in refraction-networking/utls

This is a **Chrome 134 (Mac) fallback** per the plan's fallback clause, chosen because:
1. Chrome 134 was a stable Chrome version from late 2025
2. All three parts of JA4 and the JA3 hash were independently computed and verified
3. Yandex Browser uses BoringSSL (Chromium's TLS library) with no documented TLS deviation
4. The cipher suite B-hash (`8daaf6152771`) is stable across Chrome 91–148+ (same cipher list)

---

## Sources

1. **Primary fingerprint data:** https://github.com/lexiforest/curl_cffi/issues/529
   — Chrome 134 Mac Desktop JA3, JA4, JA3N string, Akamai fingerprint (captured / reported 2025)

2. **Cross-validation #1:** https://github.com/telegramdesktop/tdesktop/issues/30733
   — References Chrome 134 Mac as `t13d1516h2_8daaf6152771_d8a2da3f94cd` and Chrome 148 Windows as
   `t13d1514h2_8daaf6152771_827b515c4f52`

3. **Cross-validation #2:** https://github.com/ntop/ndpi/issues/2914
   — Uses `t13d1516h2_8daaf6152771_d8a2da3f94cd` in JA4 PCAP test cases

4. **uTLS Chrome profiles:** https://github.com/refraction-networking/utls/blob/master/u_parrots.go
   — HelloChrome_131 and HelloChrome_133 definition (cipher suites, extensions, groups, sig algs)

5. **IANA TLS extension registry:** https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
   — Extension type numeric assignments

6. **Yandex Browser version:** https://www.whatismybrowser.com/guides/the-latest-version/yandex-browser
   — Version 26.4.3.897 with `Chrome/148.0.0.0` in UA string

7. **JA4 specification:** https://github.com/FoxIO-LLC/ja4 — spec for JA4 computation

---

## Mathematical Verification Log (2026-06-07)

All computations performed in Python 3 using `hashlib`:

```
Cipher list (sorted hex):
  002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9
JA4 Part B = SHA256[:12] = 8daaf6152771  ✓

Extension list for Part C (sorted, SNI+ALPN excluded):
  0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01
Sig algs (in order):
  0403,0804,0401,0503,0805,0501,0806,0601
Combined: <exts>_<sigalgs>
JA4 Part C = SHA256[:12] = d8a2da3f94cd  ✓

JA4 = t13d1516h2_8daaf6152771_d8a2da3f94cd  ✓

JA3 string (one observed extension order):
  771,4865-...-53,51-27-65281-18-45-0-35-5-11-43-16-65037-23-17613-13-10,4588-29-23-24,0
JA3 MD5 = 845db3b4e398789bdeb5b15594360a29  ✓
```
