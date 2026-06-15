# usnjrnl-forensic

**Point it at an E01. Get a fully path-resolved USN journal timeline — no UNKNOWNs, no pre-extraction, no Windows.**

`usnjrnl-forensic` opens a forensic disk image directly, pulls the `$UsnJrnl:$J` named stream straight off the NTFS volume, correlates it with `$MFT`, and reconstructs every file path through the CyberCX "Rewind" algorithm — including paths that other tools render as `UNKNOWN\UNKNOWN` because Windows reused the MFT entry.

## 30 seconds to a timeline

```bash
cargo run --release --features image -- --image disk.E01 --jsonl out.jsonl
```

One line of `out.jsonl`:

```json
{"timestamp":"2018-04-25T04:29:21.350215100Z","usn":1428395768,"entry_number":6226,"sequence_number":6,"parent_entry_number":116012,"parent_sequence_number":4,"parent_path":".\\Windows\\Temp","full_path":".\\Windows\\Temp\\GUR865E.exe","filename":"GUR865E.exe","extension":"exe","file_attributes":"ARCHIVE","reasons":"FILE_CREATE","source_info":0,"security_id":0,"major_version":2}
```

The `full_path` is reconstructed from `$MFT` even if entry 6226 has since been reassigned to a different file. Beyond the live `$UsnJrnl:$J`, the timeline also merges records **carved** from unallocated space and **ghost** records recovered from `$LogFile` that the journal has already cycled past — so deletion that wiped the journal entry still leaves a trace.

## Install

```bash
cargo install usnjrnl-forensic --features image
```

This builds the `usnjrnl-forensic` binary with E01/raw disk image support. Runs on Windows, macOS, and Linux. No runtime dependencies. Without image support (pre-extracted artifacts only), drop `--features image`.

## What it does

`usnjrnl-forensic` opens E01 and raw (dd) forensic images directly, extracts four NTFS artifacts (`$UsnJrnl:$J`, `$MFT`, `$LogFile`, `$MFTMirr`), reconstructs full file paths through MFT entry reuse, carves deleted records from unallocated space, and runs 12 forensic triage questions against the results.

```bash
usnjrnl-forensic --image evidence.E01 --carve-unallocated --report triage.html
```

Open the report in any browser. The **Story** tab answers 12 IR questions; the **Explore** tab is a full timeline workbench with search, reason-flag filters, source pills (allocated / carved / ghost), and an activity sparkline.

The NTFS layer is built on [`ntfs-forensic`](https://github.com/SecurityRonin/ntfs-forensic), the fleet's from-scratch NTFS reader.

## Validation

The path-reconstruction and carving results are validated against the DEF CON DFIR CTF image and independent reference tooling — see the [Validation](VALIDATION.md) report.

---

[Privacy Policy](privacy.md) · [Terms of Service](terms.md) · [GitHub](https://github.com/SecurityRonin/usnjrnl-forensic) · © 2026 Security Ronin Ltd
