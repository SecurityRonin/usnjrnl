# Privacy Policy

**Effective date:** 2026-06-06  
**Product:** usnjrnl-forensic CLI and library  
**Operator:** Security Ronin Ltd

---

## What usnjrnl-forensic collects

usnjrnl-forensic is a local command-line tool and Rust library. It does not
operate a server, does not have a backend, and does not transmit data to
Security Ronin or any third party.

It contacts **no external service**. There is no account, no login, and no cloud
component.

---

## Artifact and evidence data

usnjrnl-forensic reads forensic artifacts — disk images (E01/raw) and NTFS
artifacts such as `$UsnJrnl:$J`, `$MFT`, `$LogFile`, and `$MFTMirr` — to
reconstruct file activity timelines. All processing happens **entirely on your
local machine**:

- Input artifacts are read from paths you provide.
- Extracted artifacts (when using `--image`) are written to a temporary
  directory, or to the `--output-dir` you specify.
- Output reports (CSV, JSONL, SQLite, body, TLN, XML, HTML) are written only to
  the paths you choose.

No artifact content, path, timestamp, or report is ever uploaded anywhere.

---

## Telemetry

usnjrnl-forensic has no telemetry, no crash reporting, no analytics, and no
update checks. It never phones home.

---

## Open source

usnjrnl-forensic is fully open source under the Apache-2.0 licence. You can audit
every line — and confirm there are no network calls — at
[github.com/SecurityRonin/usnjrnl-forensic](https://github.com/SecurityRonin/usnjrnl-forensic).

---

## Changes

If this policy changes materially, the effective date above will be updated and a
note will appear in the release changelog.

---

## Contact

Security Ronin Ltd — [github.com/SecurityRonin](https://github.com/SecurityRonin)
