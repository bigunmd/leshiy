<#
.SYNOPSIS
  Generate a self-signed Authenticode code-signing certificate for the Leshiy Windows
  desktop build, and emit everything needed to wire it into CI.

.DESCRIPTION
  Run on Windows (PowerShell 5.1+ or PowerShell 7). Creates a self-signed code-signing
  cert in the CurrentUser\My store, exports a password-protected .pfx, and prints:
    - the certificate thumbprint,
    - a base64 of the .pfx (for the WINDOWS_CERTIFICATE GitHub Actions secret),
    - the exact next steps for CI and local signed builds.

  NOTE: a self-signed cert is trusted ONLY on machines where its public cert is imported
  (use -TrustLocally for this machine). Other users still see SmartScreen / "Unknown
  publisher". For public distribution use a CA-issued cert — see
  apps/gui/WINDOWS-SIGNING.md.

.EXAMPLE
  pwsh ./scripts/gen-windows-cert.ps1 -PfxPassword 'S0me-Strong-Pass' -TrustLocally
#>
[CmdletBinding()]
param(
  [string]$Subject = 'CN=Leshiy, O=Leshiy, C=US',
  [string]$FriendlyName = 'Leshiy Code Signing (self-signed)',
  [string]$OutDir,
  [int]$Years = 3,
  [string]$PfxPassword,
  [switch]$TrustLocally,
  [switch]$WriteLocalOverlay
)

$ErrorActionPreference = 'Stop'

# Resolve the output directory in the BODY (not as a param default): $PSScriptRoot is empty
# in a param default in some hosts and over a \\wsl.localhost UNC path, which caused
# "Cannot bind argument to parameter 'Path' because it is an empty string." Prefer
# $PSCommandPath (always the full script path under -File), then fall back.
if ([string]::IsNullOrWhiteSpace($OutDir)) {
  if (-not [string]::IsNullOrWhiteSpace($PSCommandPath)) {
    $OutDir = Split-Path -Parent $PSCommandPath
  } elseif (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
    $OutDir = $PSScriptRoot
  } else {
    $OutDir = (Get-Location).Path
  }
}
Write-Host "Output directory: $OutDir"

if ([string]::IsNullOrEmpty($PfxPassword)) {
  $sec = Read-Host -AsSecureString 'Choose a PFX export password'
} else {
  $sec = ConvertTo-SecureString -String $PfxPassword -Force -AsPlainText
}

Write-Host 'Creating self-signed code-signing certificate...'
$cert = New-SelfSignedCertificate `
  -Type CodeSigningCert `
  -Subject $Subject `
  -FriendlyName $FriendlyName `
  -KeyUsage DigitalSignature `
  -KeyAlgorithm RSA -KeyLength 3072 `
  -CertStoreLocation 'Cert:\CurrentUser\My' `
  -NotAfter (Get-Date).AddYears($Years)

$pfx = Join-Path $OutDir 'leshiy-codesign.pfx'
Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $sec | Out-Null

$b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($pfx))
$b64Path = Join-Path $OutDir 'leshiy-codesign.pfx.base64.txt'
Set-Content -Path $b64Path -Value $b64 -NoNewline

if ($TrustLocally) {
  $cer = Join-Path $OutDir 'leshiy-codesign.cer'
  Export-Certificate -Cert $cert -FilePath $cer | Out-Null
  Import-Certificate -FilePath $cer -CertStoreLocation 'Cert:\CurrentUser\Root' | Out-Null
  Write-Host 'Imported the public cert into CurrentUser\Root — THIS machine now trusts signed builds.'
}

$tp = $cert.Thumbprint

# The git-ignored Windows config overlay tauri merges on Windows builds. Writing the
# thumbprint here (rather than passing inline --config JSON) avoids PowerShell's native
# argument quote-mangling. Same mechanism the CI workflow uses.
$overlay = Join-Path $OutDir '..\apps\desktop\src-tauri\tauri.windows.conf.json'
$overlayJson = @{ bundle = @{ windows = @{ certificateThumbprint = $tp } } } | ConvertTo-Json -Depth 6
if ($WriteLocalOverlay) {
  Set-Content -Path $overlay -Value $overlayJson -Encoding utf8
  Write-Host "Wrote local signing overlay: $overlay"
}

Write-Host ''
Write-Host '================ DONE ================'
Write-Host "Thumbprint : $tp"
Write-Host "PFX        : $pfx"
Write-Host "PFX base64 : $b64Path"
Write-Host ''
Write-Host 'CI (GitHub Actions) — set these repository secrets'
Write-Host '  (Settings -> Secrets and variables -> Actions):'
Write-Host '    WINDOWS_CERTIFICATE          = contents of leshiy-codesign.pfx.base64.txt'
Write-Host '    WINDOWS_CERTIFICATE_PASSWORD = the PFX password you just chose'
Write-Host '  Then push a desktop-v* tag. .github/workflows/desktop-release.yml imports the'
Write-Host '  PFX and signs the build automatically (thumbprint is derived in CI).'
Write-Host ''
Write-Host 'Local signed build (cert already in your store): re-run with -WriteLocalOverlay'
Write-Host '  (or create apps/gui/src-tauri/tauri.windows.conf.json with:'
Write-Host "     $overlayJson )"
Write-Host '  then, from apps/gui:  pnpm tauri build'
Write-Host ''
Write-Host 'SECURITY: leshiy-codesign.pfx and the .base64.txt hold the PRIVATE KEY. They are'
Write-Host 'git-ignored; delete them once the secrets are set:'
Write-Host "    Remove-Item '$pfx','$b64Path'"
