# Release runbook

The release pipeline (`.github/workflows/release.yml`) builds signed, static musl binaries
and a multi-arch GHCR image whenever a `v*` tag is pushed. Two one-time setup steps are
required before the first real release, because the project's signing identity must be
created by a maintainer (not committed to the repo).

## 1. Generate the minisign signing key (one-time, offline)

`scripts/minisign.pub` currently holds a **placeholder** (`RWQ_REPLACE_WITH_REAL_PUBKEY_LINE`).
Replace it with a real key:

```sh
# Generates a real keypair. Keep the secret key OUT of git.
minisign -G -p scripts/minisign.pub -s /tmp/leshiy-minisign.key
```

This overwrites `scripts/minisign.pub` with the real public key (safe to commit) and writes
the secret key to `/tmp/leshiy-minisign.key`.

Then propagate the public key line into the installer so it can verify downloads. The second
line of `scripts/minisign.pub` (the one starting `RWQ…`) must replace
`RWQ_REPLACE_WITH_REAL_PUBKEY_LINE` inside `scripts/install.sh` (the `MINISIGN_PUB="…"` line):

```sh
PUB="$(tail -1 scripts/minisign.pub)"
sed -i "s|RWQ_REPLACE_WITH_REAL_PUBKEY_LINE|$PUB|" scripts/install.sh
```

Commit both updated files.

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
git tag v0.1.0 && git push github v0.1.0
```

The workflow will publish (to the GitHub Release): both arch tarballs, `SHA256SUMS`,
`SHA256SUMS.minisig`, `install.sh`, and `minisign.pub`; and push + cosign-sign the image at
`ghcr.io/bigunmd/leshiy:v0.1.0` and `:latest`.

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
