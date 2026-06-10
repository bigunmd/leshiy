# Release runbook

The release pipeline (`.github/workflows/release.yml`) builds signed, static musl binaries
and a multi-arch GHCR image whenever a `v*` tag is pushed. Two one-time setup steps are
required before the first real release, because the project's signing identity must be
created by a maintainer (not committed to the repo).

## 1. The minisign signing key

`scripts/minisign.pub` holds the real public key, and its **base64 line** is embedded in
`scripts/install.sh` as `MINISIGN_PUB="RWT…"`. The native installer verifies downloads with
`minisign -P "$MINISIGN_PUB"` — the **bare key line passed as a string**, not a two-line key
*file* (`minisign -p <file>` would fail with "Error while loading the public key file").

**To rotate the key** (or set one up on a fork):

```sh
# Generates a real keypair. Keep the secret key OUT of git.
minisign -G -p scripts/minisign.pub -s /tmp/leshiy-minisign.key

# Embed the new public key's base64 line into install.sh's MINISIGN_PUB=.
PUB="$(tail -1 scripts/minisign.pub)"
sed -i -E "s|^MINISIGN_PUB=\".*\"|MINISIGN_PUB=\"$PUB\"|" scripts/install.sh
```

Commit both updated files. (`leshiy upgrade` embeds `scripts/minisign.pub` at build time via
`include_str!`, so a rebuild picks up the new key automatically.)

## 2. Store the secret key as GitHub Actions secrets (one-time)

In the repo: **Settings → Secrets and variables → Actions**, add:

- `MINISIGN_SECRET_KEY` — the full contents of `/tmp/leshiy-minisign.key`
- `MINISIGN_PASSWORD` — the password chosen during `minisign -G`

Then securely delete the local secret key:

```sh
shred -u /tmp/leshiy-minisign.key 2>/dev/null || rm -f /tmp/leshiy-minisign.key
```

## 3. Cut a release

```sh
git tag v1.0.0 && git push github v1.0.0
```

The workflow will publish (to the GitHub Release): both arch tarballs, `SHA256SUMS`,
`SHA256SUMS.minisig`, `install.sh`, and `minisign.pub`; and push + cosign-sign the image at
`ghcr.io/bigunmd/leshiy:v1.0.0` and `:latest`.

## 4. Verify a release locally (recommended)

After the run, download `SHA256SUMS` and `SHA256SUMS.minisig` from the release and check:

```sh
minisign -Vm SHA256SUMS -p scripts/minisign.pub
# → "Signature and comment signature verified"
```

## Notes / risks

- **musl cross-compile is the riskiest step.** The first CI run is also the real spike for
  `cargo-zigbuild` building `aws-lc-rs` + bundled SQLite for both `x86_64` and `aarch64`
  musl. If a target fails, the CI install of `nasm`/`cmake` (already in the workflow) is the
  usual fix; check the build logs for the failing C dependency.
- **Image name casing:** `ghcr.io/${{ github.repository }}` is `ghcr.io/bigunmd/leshiy`
  (lowercase) — valid for GHCR. If the repo is ever moved to an owner with uppercase letters,
  add a step to lowercase the image name before build + cosign.
- The signing key is the **root of trust** for the native installer. Treat the secret key
  like any production signing key; rotating it means re-publishing `minisign.pub` and the
  embedded `MINISIGN_PUB` line in `install.sh`.
- **Pin third-party actions to commit SHAs before the first signed release.** The `release`
  job has `MINISIGN_SECRET_KEY` in its environment, so any action it runs is inside the
  signing-key blast radius. The workflow currently pins to mutable tags
  (`actions/checkout@v4`, `actions/download-artifact@v4`, `softprops/action-gh-release@v2`,
  `docker/*@v3`/`@v6`, `sigstore/cosign-installer@v3`). Replace each `@vN` with the action's
  full commit SHA (the tag is mutable; the SHA is not) before tagging `v1.0.0`. Per-job
  `permissions:` are already scoped to least privilege.
