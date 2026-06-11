# Windows Code-Signing — quick guide

How to sign the Windows desktop `.exe` / installers (NSIS/MSI) with **Authenticode**. Signed
binaries avoid the "Unknown publisher" block and (with an EV cert or enough reputation) the
SmartScreen warning. Signing is **already wired** in `.github/workflows/desktop-release.yml`
and `tauri.conf.json` — you just supply a certificate.

> **Two different "signings" — don't confuse them.** Tauri's **updater** signature
> (`TAURI_SIGNING_PRIVATE_KEY`) is *not* OS code signing. This guide is **Windows
> Authenticode** — the OS-trust signature on the `.exe`/installer, driven by
> `bundle.windows.certificateThumbprint`. The two are independent.

---

## Quick start — self-signed (what's wired here)

Self-signed is fine for internal/test builds. It is **not** trusted on machines that haven't
imported the cert, so public users still see SmartScreen / "Unknown publisher". For public
distribution use a CA cert (§2).

1. **Generate the cert** on your Windows box (one time):

   ```powershell
   pwsh ./scripts/gen-windows-cert.ps1 -PfxPassword 'choose-a-strong-pass' -TrustLocally
   ```

   It creates the cert in your store, exports `scripts/leshiy-codesign.pfx`, and prints the
   **thumbprint**, a **base64 of the .pfx**, and the next steps. (`-TrustLocally` makes *this*
   machine trust the resulting signatures; `*.pfx`/`*.cer`/base64 are git-ignored.)

2. **Enable CI signing** — add two repository secrets
   (*Settings → Secrets and variables → Actions*):

   | Secret | Value |
   |---|---|
   | `WINDOWS_CERTIFICATE` | contents of `scripts/leshiy-codesign.pfx.base64.txt` |
   | `WINDOWS_CERTIFICATE_PASSWORD` | the PFX password from step 1 |

3. **Release** — push a `desktop-v*` tag (e.g. `git tag desktop-v1.2.0 && git push <remote> desktop-v1.2.0`).
   The workflow imports the `.pfx`, writes the thumbprint into a Windows config overlay, and
   `tauri build` signs the bundles. **No secrets → unsigned build** (forks/PRs still pass).

4. **Delete the local key material** once the secrets are set:
   `Remove-Item scripts/leshiy-codesign.pfx, scripts/leshiy-codesign.pfx.base64.txt`.

That's it. The rest of this doc is reference (manual cert creation, production certs, local
signed builds, verification).

---

## 1. Self-signed certificate by hand (what the script does)

`scripts/gen-windows-cert.ps1` automates this; here's the underlying PowerShell:

```powershell
$cert = New-SelfSignedCertificate `
  -Type CodeSigningCert `
  -Subject "CN=Leshiy, O=Leshiy, C=US" `
  -KeyUsage DigitalSignature -KeyAlgorithm RSA -KeyLength 3072 `
  -CertStoreLocation Cert:\CurrentUser\My `
  -NotAfter (Get-Date).AddYears(3)
$cert.Thumbprint                                  # identifies the cert to tauri/signtool

$pw = ConvertTo-SecureString "a-strong-password" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath .\leshiy-codesign.pfx -Password $pw
```

To trust it on the **local** machine only:

```powershell
Export-Certificate -Cert $cert -FilePath .\leshiy-codesign.cer
Import-Certificate -FilePath .\leshiy-codesign.cer -CertStoreLocation Cert:\CurrentUser\Root
```

---

## 2. Production certificate (for public distribution)

Since **June 2023** the CA/Browser Forum requires code-signing private keys on
**FIPS 140-2 L2 / EAL4+ hardware** — no more bare `.pfx` downloads for new public certs.

| Option | SmartScreen | Key storage | Notes |
|---|---|---|---|
| **Azure Trusted Signing** (recommended) | builds reputation; instant if org is established | Microsoft-run HSM (no token) | ~$10/mo, CI-friendly via `signtool` + Azure dlib. Requires a verified org identity. |
| **EV cert** | **instant** trust | USB token / cloud HSM | Most trusted, most expensive. |
| **OV cert** | reputation-based | USB token / cloud HSM | Cheaper than EV; no longer a bare `.pfx`. |

For a CA cert that lives in the Windows store as a normal cert (or is imported from a `.pfx`),
the wiring below is unchanged — just use that cert's `.pfx`/thumbprint instead of a
self-signed one. For HSM/token-backed keys, switch `bundle.windows` to a `signCommand` that
invokes your signing tool (e.g. the Azure Trusted Signing dlib) instead of a thumbprint.

---

## 3. How signing is wired (reference)

- `apps/desktop/src-tauri/tauri.conf.json` → `bundle.windows` already sets
  `digestAlgorithm: "sha256"` and `timestampUrl` (timestamping keeps signatures valid past
  cert expiry). It deliberately has **no `certificateThumbprint`**, so default builds are
  **unsigned**.
- Signing is activated by adding the thumbprint via Tauri's **platform overlay**
  `src-tauri/tauri.windows.conf.json` (auto-merged on Windows, RFC 7396):

  ```json
  { "bundle": { "windows": { "certificateThumbprint": "ABCD…" } } }
  ```

  In CI the import step writes this file from the imported cert; the file is git-ignored so a
  per-machine thumbprint never lands in git.

---

## 4. Local signed build

The cert must be in your store (step 1). Then either re-run the generator with
`-WriteLocalOverlay` (it writes the git-ignored overlay), or create the overlay yourself, and
build from `apps/desktop`:

```powershell
pwsh ./scripts/gen-windows-cert.ps1 -PfxPassword '…' -WriteLocalOverlay   # writes the overlay
cd apps/desktop
pnpm tauri build                                                          # signs the bundles
```

> Prefer the overlay file over `tauri build --config '{…}'`: PowerShell mangles quotes in
> inline JSON passed to native commands, which corrupts the `--config` payload.

---

## 5. Verify & timestamp

- **`timestampUrl` is set** (in `tauri.conf.json`) so signatures stay valid after the cert
  expires. Alternatives: `http://timestamp.sectigo.com`, `http://timestamp.comodoca.com`.
- **Verify** a built artifact:

```powershell
Get-AuthenticodeSignature .\Leshiy_1.2.0_x64-setup.exe | Format-List
# or, with the Windows SDK:
signtool verify /pa /v .\Leshiy_1.2.0_x64-setup.exe
```

`Status: Valid` + the expected publisher + a countersignature (timestamp) = success.
Self-signed certs report `Valid` only on machines that trust the cert (§1).
