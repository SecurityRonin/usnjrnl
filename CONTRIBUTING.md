# Contributing to usnjrnl-forensic

Thanks for your interest in improving `usnjrnl-forensic`. This tool parses
forensic disk artifacts that may be attacker-controlled, so correctness and
discipline matter more than speed. Please read this guide before opening a PR.

## Test-Driven Development is mandatory

All code changes follow strict Red-Green-Refactor TDD, with **two separate
commits** per change:

1. **RED** — write the failing test(s) first that define the expected behaviour.
   Run them and confirm they fail. Commit *only* the tests.
2. **GREEN** — write the minimal implementation that makes the tests pass. Run
   them and confirm they pass. Commit the implementation.
3. **REFACTOR** — clean up while keeping the tests green (may be folded into the
   GREEN commit or a follow-up).

The separate RED commit is the verifiable proof that the tests were written
first. PRs that bundle tests and implementation into one commit will be asked to
split them. The only exception is a trivial one-line change.

## Quality gates

Every change must pass the same gates CI and the pre-commit hooks enforce
(see `.pre-commit-config.yaml`):

```bash
cargo fmt --check                          # formatting
cargo clippy --all-targets -- -D warnings  # lints (warnings are errors)
cargo test --lib                           # unit tests
cargo deny check                           # licenses, advisories, bans (deny.toml)
```

Install the pre-commit hooks so these run automatically:

```bash
pre-commit install
```

## Running tests

Run the full suite (unit + integration):

```bash
cargo test
```

Disk-image features live behind the `image` feature flag — exercise them with:

```bash
cargo test --features image
```

While iterating, prefer **targeted** runs over the full suite, and run test
processes **one at a time** (heavy parallel runs can saturate the machine):

```bash
cargo test --lib rewind::          # a single module
cargo test test_run_csv_output     # a single test
```

## Commit signing (gitsign)

Commits to this repository are signed with [gitsign](https://github.com/sigstore/gitsign)
using ephemeral Sigstore identities. Unsigned commits will not be accepted.

Configure signing once:

```bash
git config gpg.x509.program gitsign
git config gpg.format x509
git config commit.gpgsign true
```

If you are making several commits in one session, start the credential cache so
each commit shares one OIDC token instead of triggering a browser flow per
commit:

```bash
gitsign credential-cache start
export GITSIGN_CREDENTIAL_CACHE="$HOME/Library/Caches/sigstore/gitsign/cache.sock"
```

## Code conventions

- Match the surrounding style — read two or three neighbouring files before
  writing in an unfamiliar module and mirror their naming, error handling, and
  layout.
- Comments explain *why*, not *what*. Delete narration; keep rationale.
- Keep diffs minimal: change only what the task requires; no drive-by
  reformatting of unrelated code.
- Distrust the input. These parsers consume untrusted, possibly malicious disk
  artifacts — fail loud with context, never silently produce a wrong path or
  swallow an error.

## Reporting security issues

Do **not** open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md)
for the private disclosure process.

## Licensing of contributions

Unless you explicitly state otherwise, any contribution you submit for inclusion
in this project, as defined in the Apache-2.0 license, shall be licensed under
the same terms as the project (see [LICENSE](LICENSE)), without any additional
terms or conditions.
