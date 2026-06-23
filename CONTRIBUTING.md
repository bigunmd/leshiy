# Contributing to Leshiy

Thanks for your interest in improving Leshiy! This document covers how to build,
test, and submit changes. By participating you agree to abide by our
[Code of Conduct](CODE_OF_CONDUCT.md).

> **Security bugs do not go here.** Never report a vulnerability in a public
> issue or PR — follow the [Security Policy](SECURITY.md) instead.

## Ways to contribute

- **Bugs, features, and questions:** open an issue using one of the
  [issue templates](.github/ISSUE_TEMPLATE). Please search existing issues first.
- **Code and docs:** open a pull request (see below).

For larger changes, it's worth opening an issue to discuss the approach before
investing significant effort.

## Prerequisites

- **Rust** — the toolchain is pinned via [`rust-toolchain.toml`](rust-toolchain.toml)
  (stable, with `rustfmt` and `clippy`). With `rustup` installed, the right
  toolchain and components are selected automatically.
- **cargo-deny** (for the supply-chain check): `cargo install cargo-deny`.

The Android app lives under `apps/` and has its own toolchain; see its
directory and the `android-ci` workflow if you're working there.

## Build and test

The workspace builds with standard Cargo commands:

```sh
cargo build              # build all crates
cargo test --all         # run the full test suite
```

Before opening a PR, run the same checks CI does (see
[`.github/workflows/ci.yml`](.github/workflows/ci.yml)) — they must all pass:

```sh
cargo fmt --all --check                  # formatting
cargo clippy --all-targets -- -D warnings # lints (warnings are errors)
cargo test --all                          # tests
cargo deny check advisories bans sources  # supply-chain / advisory gate
sh scripts/test/check_latest_pointer_test.sh  # shell unit tests
```

Tip: run `cargo fmt --all` (without `--check`) to auto-format before committing.

## Commit messages

We use [Conventional Commits](https://www.conventionalcommits.org/) with a scope,
matching the existing history. Examples from this repo:

```
feat(cli): add ui styling module
fix(reality): cap mux frames to one TLS record
refactor(leshiy): migrate PEM parsing off unmaintained rustls-pemfile
test(cli): assert --qr puts the URI on stdout
chore: bump version across workspace
ci: guard GitHub "latest" pointer
```

Common types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `ci`. Keep the
subject in the imperative mood and reasonably short.

Please **do not add `Co-Authored-By` trailers** — keep commits to their real
authors.

## Pull requests

1. Branch from `master`.
2. Keep changes focused; smaller PRs are easier to review.
3. Make sure all the CI checks above pass locally.
4. Fill out the [pull request template](.github/PULL_REQUEST_TEMPLATE.md),
   including a note on any security or threat-model impact. Leshiy's job is to be
   indistinguishable from ordinary HTTPS to a censor — when touching the
   transports (REALITY / QUIC), cloaking/masquerade behavior, the entry/exit
   connector, or key handling, think about how the change looks to a network
   observer.
5. Link the issue your PR addresses (e.g. `Closes #123`).

A maintainer will review and may request changes before merging.

## Licensing of contributions

Leshiy is licensed under **AGPL-3.0-only**. Unless you explicitly state
otherwise, any contribution you intentionally submit for inclusion in the work
shall be licensed under AGPL-3.0, without any additional terms or conditions.
