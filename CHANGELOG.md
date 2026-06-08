# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.0] — 2026-06-08

### Changed

- **Normalized onto `forensicnomicon::report` (breaking).** The local 5-level
  `Severity` is now the re-exported `forensicnomicon::report::Severity`, and
  `RuleMatch` gains `to_finding()` — a pattern-rule match becomes a canonical
  `Finding` (dynamic `USN-<RULE>` code, code-derived category, filename/reason/
  timestamp evidence). The typed `Rule`/`RuleMatch`/`RuleSet` API is unchanged.
- **NTFS layer migrated onto `ntfs-forensic`.** Disk-image artifact extraction
  now runs through the sibling [`ntfs-forensic`](../ntfs-forensic) crate (now at
  0.3), which becomes the sole NTFS-layer dependency. NTFS volume parsing,
  `$ATTRIBUTE_LIST` traversal, and named-stream resolution come from a single
  self-owned reader shared across the SecurityRonin forensic tooling.

### Added

- **Named-stream `$UsnJrnl:$J` extraction.** The USN change journal is now read
  directly as the named `$DATA` stream `$UsnJrnl:$J` off the NTFS volume via
  `ntfs_forensic::NtfsFs::read_named_stream(r"\$Extend\$UsnJrnl", "$J")`, instead
  of reaching for the journal through a third-party MFT abstraction.

### Removed

- **Dropped the `mft` crate.** `$MFT` parsing and entry handling that previously
  depended on the external `mft` crate are gone; the functionality is provided by
  `ntfs-forensic` and this crate's own `mft` module.
- **Dropped the `ntfs` crate.** Volume and stream access through the external
  `ntfs` crate has been removed in favour of `ntfs-forensic`. Both legacy crates
  are no longer dependencies.

---

[Unreleased]: https://github.com/SecurityRonin/usnjrnl-forensic/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/SecurityRonin/usnjrnl-forensic/compare/v0.6.0...v0.7.0
