<!--
Thanks for contributing to Leshiy! Please fill out the sections below.
Security vulnerabilities must NOT be reported here — see SECURITY.md.
-->

## Summary

<!-- What does this PR do, and why? -->

## Related issue

<!-- e.g. Closes #123. If there's no issue, briefly explain the motivation above. -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor / cleanup (no behavior change)
- [ ] Documentation
- [ ] Build / CI / tooling

## Checklist

- [ ] PR title follows [Conventional Commits](https://www.conventionalcommits.org/) (e.g. `fix(reality): ...`)
- [ ] `cargo fmt --all --check` passes
- [ ] `cargo clippy --all-targets -- -D warnings` passes
- [ ] `cargo test --all` passes
- [ ] `cargo deny check advisories bans sources` passes (if dependencies changed)
- [ ] Docs / README updated if behavior or usage changed

## Security & threat-model impact

<!--
Leshiy must look like ordinary HTTPS to a censor. If this PR touches the
transports (REALITY / QUIC), cloaking/masquerade behavior, the entry/exit
connector, or key handling, describe how the change looks to a network observer.
Write "none" if not applicable.
-->
