# usnjrnl-forensic

[![Crates.io](https://img.shields.io/crates/v/usnjrnl-forensic.svg)](https://crates.io/crates/usnjrnl-forensic)
[![Docs.rs](https://img.shields.io/docsrs/usnjrnl-forensic)](https://docs.rs/usnjrnl-forensic)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/usnjrnl-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/usnjrnl-forensic/actions/workflows/ci.yml)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

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

(A real dropper from the DEF CON DFIR CTF image — `GUR865E.exe` is created in `\Windows\Temp`, then deleted seconds later.) The `full_path` is reconstructed from `$MFT` even if entry 6226 has since been reassigned to a different file. Beyond the live `$UsnJrnl:$J`, the timeline also merges records **carved** from unallocated space and **ghost** records recovered from `$LogFile` that the journal has already cycled past — so deletion that wiped the journal entry still leaves a trace.

## Install

```bash
cargo install usnjrnl-forensic --features image
```

This builds the `usnjrnl-forensic` binary with E01/raw disk image support. Runs on Windows, macOS, and Linux. No runtime dependencies.

Without image support (pre-extracted artifacts only):

```bash
cargo install usnjrnl-forensic
```

### Build from source

```bash
git clone https://github.com/SecurityRonin/usnjrnl-forensic
cd usnjrnl-forensic
cargo build --release --features image
```

## What it does

`usnjrnl-forensic` opens E01 and raw (dd) forensic images directly, extracts four NTFS artifacts (`$UsnJrnl:$J`, `$MFT`, `$LogFile`, `$MFTMirr`), reconstructs full file paths through MFT entry reuse, carves deleted records from unallocated space, and runs 12 forensic triage questions against the results.

```text
$ usnjrnl-forensic --image evidence.E01 --carve-unallocated --report triage.html

[*] Opening disk image: evidence.E01
[*] Detected format: Ewf
[+] Extracted $MFT, $MFTMirr, $LogFile, $UsnJrnl:$J
[+] 847,293 USN records parsed
[+] 112,448 MFT entries parsed
[+] 5,378 USN records recovered from $LogFile
[+] 771 ghost records found in $LogFile (not present in $UsnJrnl)
[+] Carved 1,247 USN records + 89 MFT entries from unallocated space
[+] All paths fully resolved (0 UNKNOWN)
[+] Triage report written to triage.html
```

### NTFS layer: built on `ntfs-forensic`

Image extraction goes through the sibling [`ntfs-forensic`](../ntfs-forensic) crate — its **sole NTFS-layer dependency**. `usnjrnl-forensic` reads the USN change journal as the named `$DATA` stream `$UsnJrnl:$J` directly off the volume:

```rust
fs.read_named_stream(r"\$Extend\$UsnJrnl", "$J")?;
```

The previous `mft` and `ntfs` third-party crates have been dropped entirely. NTFS volume parsing, `$ATTRIBUTE_LIST` traversal, and named-stream extraction now come from a single self-owned reader shared across the SecurityRonin forensic tooling. See [CHANGELOG.md](CHANGELOG.md) for the migration details.

## Usage

### Rapid triage (recommended starting point)

Point at an E01, get a self-contained HTML report:

```bash
usnjrnl-forensic --image evidence.E01 --carve-unallocated --report triage.html
```

Open it in any browser. The **Story** tab answers 12 IR questions; the **Explore** tab is a full timeline workbench with search, reason-flag filters, source pills (allocated / carved / ghost), and an activity sparkline.

### Timeline export

```bash
usnjrnl-forensic --image evidence.E01 --jsonl out.jsonl
usnjrnl-forensic --image evidence.E01 --csv timeline.csv
usnjrnl-forensic --image evidence.E01 --carve-unallocated --sqlite analysis.db
```

Keep extracted artifacts for later use, and work with raw (dd) images:

```bash
usnjrnl-forensic -i evidence.E01 --output-dir ./extracted --sqlite analysis.db
usnjrnl-forensic --image disk.raw --csv output.csv
```

### From pre-extracted artifacts

Parse `$UsnJrnl:$J` with MFT path resolution:

```bash
usnjrnl-forensic -j $J -m $MFT --csv output.csv
```

Full QuadLink analysis — correlate all four artifacts:

```bash
usnjrnl-forensic -j $J -m $MFT --mftmirr $MFTMirr --logfile $LogFile --sqlite analysis.db
```

Detect timestomping:

```bash
usnjrnl-forensic -j $J -m $MFT --detect-timestomping
```

All output formats at once:

```bash
usnjrnl-forensic -j $J -m $MFT --csv out.csv --jsonl out.jsonl --sqlite out.db --body out.body --tln out.tln --xml out.xml
```

Journal-only mode (no MFT) produces partial paths (parent MFT entry numbers only) — useful when `$MFT` is unavailable:

```bash
usnjrnl-forensic -j $J --csv output.csv
```

## Why this tool exists

Every USN journal parser on the market has blind spots. MFTECmd produces `UNKNOWN` parent paths when MFT entries get reused. ntfs-linker requires C++ compilation and has no maintained builds. NTFS Log Tracker runs only on Windows. None of them open an E01 directly.

`usnjrnl-forensic` closes the gaps. It implements the CyberCX Rewind algorithm for 100% path resolution, four-artifact QuadLink correlation (extending David Cowen's TriForce with `$MFTMirr` integrity verification), unallocated-space carving, and anti-forensics detection — all from a raw disk image, on any platform.

## Evidence it works

Record-level comparison against MFTECmd, usn.py, dfir_ntfs, usnrs, usnjrnl_rewind, and Velociraptor across three publicly available forensic disk images (757,491 total records). All tools agree on record counts and USN offsets. For path resolution:

| Tool | Paths resolved correctly |
|---|:---:|
| **usnjrnl-forensic** | **100%** |
| usnjrnl_rewind | 94.0% |
| MFTECmd | 83.7% |
| dfir_ntfs | 62.3% |
| usnrs | 54.6% |

usnjrnl_rewind's 6% incorrect paths are caused by retroactive rename application and ADS name inclusion — verified by USN chronology against the journal's own rename events. Full methodology: **[docs/VALIDATION.md](docs/VALIDATION.md)**.

On an Apple M4, the tool produces a complete HTML triage report from a 15 GiB E01 image in **4 seconds** — correctly identifying malware delivery, System32 deployment, Prefetch execution proof, and data staging that took [Szechuan Sauce](https://dfirmadness.com/the-stolen-szechuan-sauce/) CTF participants hours to reconstruct across 6-10 tools. Full assessment: **[docs/TRIAGE_PERFORMANCE.md](docs/TRIAGE_PERFORMANCE.md)**.

## Features

### Path reconstruction with journal rewind

Standard tools resolve parent directory references against the *current* MFT state. When Windows reuses an MFT entry number, those references break, scattering `UNKNOWN` parent paths through your timeline. The Rewind algorithm, first described by [CyberCX](https://cybercx.com.au/blog/ntfs-usnjrnl-rewind/), processes journal entries in reverse chronological order, tracking every `(entry, sequence) → (filename, parent)` mapping and rebuilding the directory tree as it existed at each point in time.

```text
Before Rewind:  UNKNOWN\UNKNOWN\malware.exe
After Rewind:   .\Users\admin\AppData\Local\Temp\malware.exe
```

### QuadLink correlation

`usnjrnl-forensic` correlates four NTFS artifacts — more than any other tool:

1. **`$UsnJrnl:$J`** records file creates, deletes, renames, and data changes
2. **`$MFT`** stores the current file system state with timestamps
3. **`$LogFile`** contains transaction logs that embed USN records
4. **`$MFTMirr`** mirrors the first four critical MFT entries for integrity verification

This builds on the [TriForce](https://www.hecfblog.com/2013/01/ntfs-triforce-deeper-look-inside.html) technique (David Cowen, 2013), which pioneered three-artifact correlation of `$MFT` + `$LogFile` + `$UsnJrnl`, and adds `$MFTMirr` byte-level integrity verification to detect tampering with critical system metadata — a consistency check no other tool performs.

The `$LogFile` retains copies of recent USN records in its RCRD pages. `usnjrnl-forensic` extracts these, cross-references them against the journal, and flags records that exist *only* in `$LogFile` as **ghost records** — a signature of either normal journal wrapping or intentional `fsutil usn deletejournal` clearing.

### Unallocated space carving

The `--carve-unallocated` flag scans the entire NTFS partition for USN records and MFT directory entries that survived in unallocated clusters after their files were deleted and entries reused. It validates each candidate (record structure, timestamp sanity, filename encoding, attribute chains), deduplicates against already-parsed allocated records, merges survivors into the timeline, and seeds the Rewind engine with carved MFT entries so carved records get full path resolution. Requires `--image`.

### Anti-forensics detection

Built-in detectors flag four categories of suspicious activity: secure deletion (SDelete / CCleaner rename patterns), journal clearing (`$LogFile` gaps and ghost records), ransomware (mass rename/delete with known extensions in short windows), and timestomping (cross-validating `$STANDARD_INFORMATION` against `$FILE_NAME` and USN `FILE_CREATE` events).

### Custom rule engine

Define detection rules matching on filenames, extensions, reason flags, or combinations:

```rust
use usnjrnl_forensic::rules::{Rule, RuleSet, Severity, FilenameMatch};
use usnjrnl_forensic::usn::UsnReason;

let mut rules = RuleSet::with_builtins(); // 5 pre-loaded forensic rules

rules.add_rule(Rule {
    name: "lateral_movement_tools".into(),
    description: "Known lateral movement binaries".into(),
    severity: Severity::Critical,
    filename_match: Some(FilenameMatch::Regex(
        r"(?i)(psexec|wmiexec|smbexec|atexec)".into()
    )),
    exclude_pattern: None,
    any_reasons: Some(UsnReason::FILE_CREATE),
    all_reasons: None,
});
```

Built-in rules cover offensive tools (mimikatz, psexec, procdump, lazagne, rubeus, sharphound), ransomware extensions, SDelete patterns, script execution, and credential access (ntds.dit, SAM, SECURITY, SYSTEM).

### ReFS support

ReFS volumes use 128-bit file reference numbers. `usnjrnl-forensic` preserves the full identifiers, auto-detects ReFS from V3 record patterns, and reconstructs paths using journal-only rewind (ReFS has no traditional MFT to seed from).

### Real-time monitoring

The `monitor` module provides a `JournalSource` trait for polling live USN journals on Windows, tracking the last-read USN position, detecting journal wraps, and emitting structured events for each new record.

## Output formats

| Format | Flag | Description |
|--------|------|-------------|
| CSV | `--csv` | MFTECmd-compatible columns |
| JSON Lines | `--jsonl` | One JSON object per line |
| SQLite | `--sqlite` | Indexed database with USNJRNL_FullPaths and MFT tables |
| Sleuthkit body | `--body` | Pipe-delimited, feeds into `mactime` and `log2timeline` |
| TLN | `--tln` | 5-field pipe-delimited timeline format |
| XML | `--xml` | Structured XML with full record fields |
| HTML Report | `--report` | Self-contained triage report with Story + Explore tabs |

## As a library

```toml
[dependencies]
usnjrnl-forensic = "0.6"
```

Available modules: `usn`, `mft`, `rewind`, `logfile`, `mftmirr`, `correlation`, `analysis`, `triage`, `rules`, `refs`, `monitor`, `image`, `output`.

- `image`: E01/raw image opening, NTFS partition discovery, artifact extraction via `ntfs-forensic`, unallocated scanning (optional `image` feature)
- `usn`: Binary parsing of USN_RECORD_V2, V3, V4 with streaming, parallel, and carving modes
- `mft`: `$MFT` entry extraction with SI/FN timestamp pairs and MFT entry carving
- `rewind`: CyberCX Rewind algorithm for path reconstruction
- `logfile`: `$LogFile` RCRD page analysis and embedded USN extraction
- `mftmirr`: `$MFTMirr` integrity verification
- `correlation`: QuadLink engine linking all four artifacts
- `analysis`: Anti-forensics detection (secure delete, ransomware, timestomping, journal clearing)
- `triage`: Rapid IR triage engine with 12 built-in questions and source-aware filtering
- `rules`: Pattern-matching rule engine with glob, regex, and reason-flag conditions
- `refs`: ReFS 128-bit file ID handling
- `monitor`: Real-time journal polling abstraction
- `output`: CSV, JSONL, SQLite, Sleuthkit body, TLN, XML, and HTML triage report exporters

## Contributing

Strict TDD (separate RED and GREEN commits), `cargo fmt`/`clippy`/`deny` gates, and gitsign commit signing. See [CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability, see [SECURITY.md](SECURITY.md).

## References

- [CyberCX: Rewriting the USN Journal](https://cybercx.com.au/blog/ntfs-usnjrnl-rewind/) (Rewind algorithm)
- [NTFS TriForce](https://www.hecfblog.com/2013/01/ntfs-triforce-deeper-look-inside.html) (David Cowen, `$MFT` + `$LogFile` + `$UsnJrnl` correlation)
- [ntfs-linker](https://github.com/strozfriedberg/ntfs-linker) (Stroz Friedberg, `$LogFile` USN extraction)
- [MFTECmd](https://github.com/EricZimmerman/MFTECmd) (Eric Zimmerman, MFT/USN parsing)
- [dfir_ntfs](https://github.com/msuhanov/dfir_ntfs) (Maxim Suhanov, Python NTFS parser)
- [Microsoft USN_RECORD_V2](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v2) · [V3](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v3) · [V4](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v4)
- [Forensic Analysis of ReFS Journaling](https://dfrws.org/wp-content/uploads/2021/01/2021_APAC_paper-forensic_analysis_of_refs_journaling.pdf) (DFRWS APAC 2021)

## Author

**Albert Hui** ([@h4x0r](https://github.com/h4x0r)) of [@SecurityRonin](https://github.com/SecurityRonin) — digital forensics practitioner building open-source DFIR tools that close the gaps left by commercial software.

---

[Privacy Policy](https://securityronin.github.io/usnjrnl-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/usnjrnl-forensic/terms/) · © 2026 Security Ronin Ltd
