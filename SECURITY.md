# Security Policy

Leshiy is a censorship-circumvention tunnel whose users may rely on it in
adversarial network environments. We take security and privacy bugs seriously.

> **Maturity:** Leshiy is **beta**. The core protocol/crypto/transport crates have
> been through a full internal adversarial review (see below), but Leshiy has **not**
> had an **independent** security audit. For genuinely high-stakes situations, prefer
> tools that have been audited and battle-proven.

## Security posture

What has been done, so you can calibrate how much to trust this:

- **Internal adversarial review (July 2026)** of the five core crates —
  `leshiy-core`, `leshiy-reality`, `leshiy-tls`, `leshiy-quic`, `leshiy-tun` (~16k LOC),
  read line by line. Every **Critical (1)**, **High (7)** and **Medium (13)** finding is
  fixed in the current release, most with regression tests. Findings clustered on
  pre-auth resource exhaustion (missing timeouts and admission control), one
  process-killing accept-loop bug, and one split-tunnel traffic leak on disconnect.
- **Not yet reviewed at that depth:** the application-level crates — `leshiy` (bin),
  `leshiy-client`, `leshiy-helper`, `leshiy-provision`, `leshiy-mobile` — and the
  desktop and Android app code. These are a known follow-up.
- **No independent third-party audit** has been performed.
- **No systematic field testing against a live censor.** The design follows published
  anti-censorship research, but "works against a real DPI deployment, over time, at
  scale" is not something we have established.
- **Continuous gates:** ~590 tests, `clippy -D warnings`, `cargo fmt`, and a RustSec
  advisory/supply-chain check (`cargo-deny`) on every push.
- `#![forbid(unsafe_code)]` in `leshiy-core`; any `unsafe` elsewhere requires an ADR.

## Supported versions

Security fixes land on the latest release line. Older versions are not
maintained — please upgrade before reporting.

| Version | Supported          |
| ------- | ------------------ |
| 1.11.x  | :white_check_mark: |
| < 1.11  | :x:                |

## Reporting a vulnerability

**Please do not open a public issue, pull request, or discussion for security
vulnerabilities.** Disclosing an exploit publicly before a fix is available can
put real users at risk.

Instead, report privately through GitHub:

1. Go to the repository's **[Security tab](https://github.com/bigunmd/leshiy/security)**.
2. Click **"Report a vulnerability"** to open a private advisory.
3. Include as much detail as you can:
   - affected component (CLI server, CLI client, desktop app, Android app,
     REALITY transport, QUIC transport, key handling, etc.),
   - version (`leshiy --version`) and platform,
   - a description of the impact and, ideally, a proof of concept or repro steps.

If you cannot use GitHub's private reporting, you may open a regular issue that
says only *"I'd like to report a security issue privately"* (with **no
details**) so a maintainer can establish a private channel with you.

## What to expect

- **Acknowledgement:** we aim to acknowledge a report within **7 days**.
- **Coordination:** we'll work with you to understand and validate the issue,
  prepare a fix, and agree on a coordinated disclosure timeline.
- **Credit:** with your permission, we're happy to credit you in the advisory
  and release notes once the fix ships.

Please give us reasonable time to release a fix before any public disclosure.
Thank you for helping keep Leshiy and its users safe.
