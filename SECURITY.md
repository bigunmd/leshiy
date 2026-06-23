# Security Policy

Leshiy is a censorship-circumvention tunnel whose users may rely on it in
adversarial network environments. We take security and privacy bugs seriously.

> **Maturity:** Leshiy is **beta** and has **not** had an independent security
> audit. For genuinely high-stakes situations, prefer tools that have been
> audited and battle-proven.

## Supported versions

Security fixes land on the latest release line. Older versions are not
maintained — please upgrade before reporting.

| Version | Supported          |
| ------- | ------------------ |
| 1.4.x   | :white_check_mark: |
| < 1.4   | :x:                |

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
