# Windows Code-Signing — quick guide

How to generate / obtain a code-signing certificate and wire it into the Windows desktop
build so the `.exe` and installers (NSIS/MSI) are **Authenticode-signed**. Signed binaries
avoid the "Unknown publisher" block and (with an EV cert or enough reputation) the SmartScreen
warning.

> **Two different "signings" — don't confuse them.** Tauri's **updater** signature
> (`TAURI_SIGNING_PRIVATE_KEY` / `…_PASSWORD`, used by the auto-updater) is *not* OS code
> signing. This guide is about **Windows Authenticode** — the OS-trust signature on the
> `.exe`/installer, configured via `bundle.windows.certificateThumbprint` in
> `src-tauri/tauri.conf.json`. The two are independent; a release can use either, both, or
> neither. See `.github/workflows/desktop-release.yml` (the signing env block is deferred).

---

## 1. Self-signed certificate (LOCAL / TEST ONLY)

Self-signed certs prove the build pipeline works but are **not** trusted by Windows on other
machines — SmartScreen/"Unknown publisher" will still fire. Never ship one. Run in
**PowerShell (Windows)**:

```powershell
# Create a code-signing cert in the current user's store. CN must match your publisher name.
$cert = New-SelfSignedCertificate `
  -Type CodeSigningCert `
  -Subject "CN=Leshiy, O=Leshiy, C=US" `
  -KeyUsage DigitalSignature `
  -FriendlyName "Leshiy Dev Code Signing" `
  -CertStoreLocation Cert:\CurrentUser\My `
  -KeyAlgorithm RSA -KeyLength 3072 `
  -NotAfter (Get-Date).AddYears(3)

$cert.Thumbprint   # <-- copy this; it goes into tauri.conf.json

# Optional: export to a password-protected .pfx (needed for CI import — see §4).
$pw = ConvertTo-SecureString -String "choose-a-strong-password" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath .\leshiy-codesign.pfx -Password $pw
```

To make the **local** machine trust it (so signed test builds verify clean on *this* box
only), import the cert's public part into the Trusted Root + Trusted Publishers stores:

```powershell
Export-Certificate -Cert $cert -FilePath .\leshiy-codesign.cer
Import-Certificate -FilePath .\leshiy-codesign.cer -CertStoreLocation Cert:\LocalMachine\Root
Import-Certificate -FilePath .\leshiy-codesign.cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher
```

---

## 2. Production certificate (what to actually ship with)

Since **June 2023** the CA/Browser Forum requires code-signing private keys to live on
**FIPS 140-2 L2 / EAL4+ hardware** — so you can no longer just download a `.pfx` for a new
public cert. Pick one:

| Option | SmartScreen | Key storage | Notes |
|---|---|---|---|
| **Azure Trusted Signing** (recommended) | builds reputation; instant if org is established | Microsoft-run HSM (no token) | ~$10/mo. CI-friendly via `signtool` + the Azure dlib. Requires a verified org identity (public trust generally needs the org to be 3+ yrs old). |
| **EV cert** (DigiCert, Sectigo, …) | **instant** trust | USB token (SafeNet) or cloud HSM | Most trusted, most expensive; hardware token is awkward in CI (use a cloud-HSM variant). |
| **OV cert** | reputation-based (warns until enough installs) | USB token / cloud HSM | Cheaper than EV; no longer issued as a bare `.pfx`. |

For Leshiy (a censorship-circumvention tool), **Azure Trusted Signing** is the pragmatic
choice: cheap, no hardware token, scriptable in GitHub Actions.

---

## 3. Wire the cert into the Tauri build

### a) Thumbprint method (self-signed, or any cert already in the Windows cert store)

Add to `apps/desktop/src-tauri/tauri.conf.json` under `bundle`:

```jsonc
"bundle": {
  "windows": {
    "certificateThumbprint": "ABCD1234…",   // the $cert.Thumbprint from §1 (no spaces)
    "digestAlgorithm": "sha256",
    "timestampUrl": "http://timestamp.digicert.com"   // ALWAYS timestamp (see §5)
  }
}
```

Then build: `pnpm tauri build` (from `apps/desktop`). Tauri runs `signtool` against the cert
matching that thumbprint in the local store.

> Keep the thumbprint **out of git if it's tied to a private cert** — prefer injecting it in
> CI (below) over committing it. A self-signed dev thumbprint is harmless to commit but
> useless to others, so don't.

### b) signCommand method (cloud HSM / Azure Trusted Signing / token)

For keys that aren't a plain store-resident cert, use a custom sign command instead of a
thumbprint (Tauri passes the file to sign as `%1`):

```jsonc
"bundle": {
  "windows": {
    "signCommand": "trusted-signing-cli -e https://eus.codesigning.azure.net -a <account> -c <cert-profile> %1"
  }
}
```

(or any wrapper that ends up calling `signtool sign /dlib Azure.CodeSigning.Dlib.dll …`.)

---

## 4. CI wiring (GitHub Actions, `.pfx`-based)

For a self-signed or cloud-HSM-exported `.pfx`, base64 it and store it + its password as repo
**secrets** (`Settings → Secrets and variables → Actions`):

```sh
base64 -w0 leshiy-codesign.pfx > pfx.b64    # paste into secret WINDOWS_PFX_BASE64
# secret WINDOWS_PFX_PASSWORD = the export password
```

Add a step **before** `tauri-apps/tauri-action` in `desktop-release.yml`, guarded to the
Windows runner, that imports the pfx and exposes the thumbprint:

```yaml
      - name: Import Windows signing cert
        if: matrix.platform == 'windows-latest' && secrets.WINDOWS_PFX_BASE64 != ''
        shell: pwsh
        run: |
          [IO.File]::WriteAllBytes("cert.pfx", [Convert]::FromBase64String("${{ secrets.WINDOWS_PFX_BASE64 }}"))
          $pw = ConvertTo-SecureString "${{ secrets.WINDOWS_PFX_PASSWORD }}" -AsPlainText -Force
          $c = Import-PfxCertificate -FilePath cert.pfx -CertStoreLocation Cert:\CurrentUser\My -Password $pw
          "WINDOWS_CERT_THUMBPRINT=$($c.Thumbprint)" | Out-File -FilePath $env:GITHUB_ENV -Append
          Remove-Item cert.pfx
```

Reference `${{ env.WINDOWS_CERT_THUMBPRINT }}` from a templated `certificateThumbprint`, or
keep the thumbprint static in `tauri.conf.json` and just rely on the import putting the
matching cert in the store. For **Azure Trusted Signing**, skip the pfx entirely: authenticate
with `azure/login` (OIDC) and use the `signCommand` from §3b — no secret key touches the runner.

---

## 5. Verify & timestamp

- **Always set `timestampUrl`** — a timestamped signature stays valid after the cert expires;
  an un-timestamped one goes invalid the day the cert lapses. Common URLs:
  `http://timestamp.digicert.com`, `http://timestamp.sectigo.com`.
- **Verify** a built artifact:

```powershell
# PowerShell
Get-AuthenticodeSignature .\Leshiy_1.2.0_x64-setup.exe | Format-List
# or, with the Windows SDK signtool:
signtool verify /pa /v .\Leshiy_1.2.0_x64-setup.exe
```

A good result shows `Status: Valid`, the expected publisher, and a countersignature
(timestamp). Self-signed certs report `Valid` only on machines that trust the cert (§1).
