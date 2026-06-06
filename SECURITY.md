# Security Policy

## Threat model

`usnjrnl-forensic` is a forensic parser. By design, it consumes **untrusted and
potentially malicious input**: disk images, `$UsnJrnl:$J`, `$MFT`, `$LogFile`,
and `$MFTMirr` artifacts pulled from suspect or compromised systems. An attacker
who controls the analysed system controls the bytes this tool parses.

The security-relevant goals are therefore:

- A malformed, truncated, or adversarially crafted artifact must **never** cause
  memory unsafety, and must not silently produce a wrong path, timestamp, or
  record without surfacing the problem.
- Parsing failures must **fail loud** with enough context to diagnose them, not
  degrade into plausible-looking but incorrect forensic output.
- The tool must remain safe to run against evidence on an analyst workstation;
  it reads artifacts and writes reports, and does not execute extracted content.

If you find a way to violate any of these — a crash, a panic on hostile input
that should be a recoverable error, a path/timestamp that can be silently
forged, or any memory-safety issue — please report it privately.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately through one of:

- GitHub's [private vulnerability reporting](https://github.com/SecurityRonin/usnjrnl-forensic/security/advisories/new)
  ("Report a vulnerability" under the Security tab), or
- email **albert@securityronin.com** with the subject line
  `[SECURITY] usnjrnl-forensic`.

Please include:

- the affected version (or commit), platform, and feature flags (e.g. `image`);
- a description of the issue and its impact;
- a minimal reproducing artifact or steps. A sample input that triggers the bug
  is the fastest path to a fix — note that it may be attacker-controlled, so we
  will handle it accordingly.

We aim to acknowledge a report within 5 business days and to agree a
coordinated disclosure timeline with you. Please give us a reasonable window to
release a fix before any public disclosure.

## Supported versions

Security fixes are applied to the latest released `0.6.x` line and to `main`.
Older releases are not maintained.

| Version | Supported |
|---------|:---------:|
| 0.6.x   | Yes       |
| < 0.6   | No        |

## Hardening and fuzzing posture

- The crate builds clean under `cargo clippy --all-targets -- -D warnings`, and
  dependency advisories, licenses, and bans are gated in CI with
  `cargo deny check` (see `deny.toml`).
- The binary parsers — `usn` (USN_RECORD V2/V3/V4), `mft`, `logfile`, and the
  unallocated carver — are the primary attack surface for hostile input and are
  the intended targets for differential and fuzz testing.
- Fuzzing is run with [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz)
  (libFuzzer). Coverage-guided harnesses live under `fuzz/` for every raw-byte
  parser — `usn_record`, `usn_carve`, `logfile`, `logfile_usn_extract`,
  `mft_parse`, `mft_carve`, and `mftmirr` — and each must never panic on
  arbitrary input (a parse error is the correct outcome). CI builds all targets
  on nightly and smoke-runs each for 30 s on every push. Contributions of new
  fuzz targets are welcome — open a PR following [CONTRIBUTING.md](CONTRIBUTING.md).

If you would like to run the existing harnesses or contribute one:

```bash
cargo install cargo-fuzz
cargo fuzz list          # show available targets
cargo fuzz run <target>  # run a target
```
