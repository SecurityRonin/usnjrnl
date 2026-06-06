# Security Ronin Katana: Pipeline Stage Specifications

> **Parent**: [ARCHITECTURE_BLUEPRINT.md](../ARCHITECTURE_BLUEPRINT.md)
> **Created**: 2026-03-10
> **Status**: Active
> **Generation Step**: 7 of 13

Detailed input/output contracts, performance budgets, error handling, and edge-case documentation for every stage in the Security Ronin Katana forensic processing pipeline.

---

## 1. Pipeline Engineering Principles

### 1.1 JTBD Framework (Adapted for Pipeline Stages)

Each pipeline stage exists to perform a single, well-defined **Job-to-be-Done**. Stage contracts follow this structure:

```
StageContract:
  stage_id: string           # Unique identifier (e.g., "ewf_parser")
  crate: string              # Rust crate that implements this stage
  job: string                # One-sentence purpose
  input_contract: Schema     # Expected input types and format
  output_contract: Schema    # Produced output types and format
  success_criteria:
    functional: list         # What constitutes correct output
    performance: list        # Time/memory budgets
    forensic: list           # Evidence integrity requirements
  error_handling: Strategy   # What happens on failure
  edge_cases: list           # Known tricky scenarios
  dependencies: list         # Which stages must complete first
  never: list                # Absolute prohibitions
```

### 1.2 Governing Axioms

Every stage must honor these axioms in priority order:

1. **Forensic Integrity > Feature Velocity** -- When speed of shipping and accuracy conflict, choose accuracy.
2. **Practitioner Autonomy > Platform Lock-in** -- Community CLI works fully offline, no accounts, no internet.
3. **35-Second Answers > Comprehensive Coverage** -- Answer 12 questions well, not 100 questions poorly.
4. **Open Core Trust > Revenue Extraction** -- Community features never move to enterprise; trust is the moat.
5. **Assume Breach > Assume Safety** -- Agent compromise must never mean server compromise.

### 1.3 Universal Stage Requirements

Every stage in the pipeline MUST:

- Produce deterministic output for identical input (SHA-256 verified)
- Never silently drop records during parsing
- Never silently modify evidence or input data
- Propagate structured errors with stage ID, error code, and context
- Respect its allocated performance budget
- Log byte offsets for any skipped or malformed data

Every stage MUST NEVER:

- Require internet connectivity for forensic analysis
- Accept non-deterministic output
- Use `unsafe` without documented justification
- Ship without test corpus verification

---

## 2. Pipeline Overview

### 2.1 Community Pipeline (9 stages, 35s P95 budget)

```
E01/Raw Image
    |
    v
[1. EWF Parser] ──2s──> Volume Data
    |
    v
[2. NTFS Volume Handler] ──1s──> Filesystem Structures
    |
    ├──────────────────────┐
    v                      v
[3. USN Journal Parser]  [4. MFT Parser]     <- parallel (rayon)
    5s                     5s
    |                      |
    v                      v
[5. Ghost Recovery] ──3s──> Recovered Records
    |
    v
[6. Unallocated Carver] ──5s──> Carved Records
    |
    v
[7. QuadLink Correlator] ──3s──> Correlated Timeline
    |
    v
[8. Triage Engine] ──5s──> IR Answers
    |
    v
[9. Output Formatter] ──3s──> Reports (7 formats)

Total budget: 32s (3s margin to 35s P95)
```

### 2.2 Enterprise Services (7 additional stages)

```
[10. Collection Agent] ──gRPC──> [11. Import Adapter]
                                       |
                                       v
                              [Community Pipeline]
                                       |
                                       v
                          [12. Multi-Device Correlator]
                                       |
                                       v
                           [13. PCAP/NetFlow Parser]
                                       |
                                       v
                          [14. Collaboration Engine]
                                       |
                          [15. RBAC Gateway] (middleware on all enterprise endpoints)
                          [16. Audit Logger] (observes all state transitions)
```

---

## 3. Community Stage Contracts

### 3.1 EWF Parser

**Stage ID**: `ewf_parser`
**Crate**: `katana-ewf`
**Tier**: Community (Apache-2.0)
**Parallelism**: Single-threaded

#### Job

Read E01 (Expert Witness Format) or raw disk images via libewf FFI bindings and expose volume data as a seekable byte stream for downstream NTFS parsing.

#### Input Contract

| Field | Type | Description |
|-------|------|-------------|
| `image_path` | `PathBuf` | Path to E01 or raw disk image file |
| `image_type` | `ImageType` | Enum: `E01`, `Raw`, `Auto` |
| `segment_paths` | `Option<Vec<PathBuf>>` | Additional E01 segments (`.E02`, `.E03`, ...) |

```rust
pub struct EwfInput {
    pub image_path: PathBuf,
    pub image_type: ImageType,
    pub segment_paths: Option<Vec<PathBuf>>,
}

pub enum ImageType {
    E01,
    Raw,
    Auto, // detect from file header
}
```

#### Output Contract

| Field | Type | Description |
|-------|------|-------------|
| `volume_data` | `VolumeReader` | Seekable byte stream over the disk image |
| `image_metadata` | `ImageMetadata` | Hash, size, acquisition info from E01 header |
| `partitions` | `Vec<Partition>` | Detected partition table entries |

```rust
pub struct EwfOutput {
    pub volume_data: VolumeReader,  // implements Read + Seek
    pub image_metadata: ImageMetadata,
    pub partitions: Vec<Partition>,
}

pub struct ImageMetadata {
    pub total_size: u64,
    pub sector_size: u32,
    pub stored_hash: Option<String>,  // MD5/SHA-1 from E01 header
    pub acquisition_date: Option<DateTime<Utc>>,
    pub case_number: Option<String>,
    pub evidence_number: Option<String>,
}
```

#### Success Criteria

- **Functional**: Volume data is readable and seekable; all E01 segments are correctly concatenated.
- **Performance**: Completes in under 2 seconds for a 1GB E01 image.
- **Forensic**: Stored hash from E01 header is extracted and available for downstream verification. No bytes are modified during reading.

#### Error Handling

| Error | Strategy | Fallback |
|-------|----------|----------|
| File not found | Return `EwfError::FileNotFound` with path | Abort pipeline |
| Invalid E01 header | Return `EwfError::InvalidFormat` with byte offset | Abort pipeline |
| Missing E01 segment | Return `EwfError::MissingSegment` with segment number | Abort pipeline |
| Hash verification failure | Emit warning, set `hash_verified: false` | Continue with warning |
| libewf FFI panic | Catch at FFI boundary, return `EwfError::FfiFailure` | Abort pipeline |

#### Performance Budget

- **Time**: 2 seconds maximum
- **Memory**: Memory-mapped I/O via `memmap2`; resident memory proportional to active read window, not image size
- **I/O**: Sequential read pattern; single pass over segment files

#### Dependencies

None. This is the pipeline entry point.

#### Edge Cases

- **Split E01 archives**: Some acquisition tools produce `.E01`, `.E02`, ..., `.E99`, `.EAA` naming. The parser must handle both numeric and alphabetic segment extensions.
- **Raw images without extension**: When `image_type` is `Auto`, fall back to magic byte detection (E01 starts with `EVF\x09\x0d\x0a\xff\x00`).
- **Compressed E01**: libewf handles decompression transparently, but budget accounts for up to 2x decompression overhead.
- **E01 with no stored hash**: Some acquisition tools omit the hash. Set `stored_hash: None` and log a warning rather than failing.
- **Images larger than available RAM**: Memory-mapped I/O ensures the full image never resides in memory simultaneously.

---

### 3.2 NTFS Volume Handler

**Stage ID**: `ntfs_volume`
**Crate**: `katana-ntfs`
**Tier**: Community (Apache-2.0)
**Parallelism**: Single-threaded

#### Job

Parse NTFS filesystem structures from the volume data stream, locating and extracting `$MFT`, `$UsnJrnl:$J`, and `$LogFile` for downstream parsers.

#### Input Contract

| Field | Type | Description |
|-------|------|-------------|
| `volume_data` | `VolumeReader` | Seekable byte stream from EWF Parser |
| `partition` | `Option<Partition>` | Specific partition to parse (default: first NTFS) |

```rust
pub struct NtfsInput {
    pub volume_data: VolumeReader,
    pub partition: Option<Partition>,
}
```

#### Output Contract

| Field | Type | Description |
|-------|------|-------------|
| `mft_data` | `MftData` | Raw `$MFT` content (memory-mapped) |
| `usnjrnl_data` | `UsnJrnlData` | Raw `$UsnJrnl:$J` stream (memory-mapped) |
| `logfile_data` | `Option<LogFileData>` | Raw `$LogFile` content (optional) |
| `volume_info` | `VolumeInfo` | NTFS version, cluster size, volume serial |
| `unallocated_ranges` | `Vec<ByteRange>` | Unallocated cluster ranges for carving |

```rust
pub struct NtfsOutput {
    pub mft_data: MftData,
    pub usnjrnl_data: UsnJrnlData,
    pub logfile_data: Option<LogFileData>,
    pub volume_info: VolumeInfo,
    pub unallocated_ranges: Vec<ByteRange>,
}

pub struct VolumeInfo {
    pub ntfs_version: (u8, u8),       // e.g., (3, 1)
    pub cluster_size: u32,            // typically 4096
    pub volume_serial: u64,
    pub total_sectors: u64,
    pub bytes_per_sector: u16,
}
```

#### Success Criteria

- **Functional**: `$MFT` and `$UsnJrnl:$J` are extracted completely. Unallocated ranges are identified for carving.
- **Performance**: Completes in under 1 second (filesystem metadata traversal only, not full data reads).
- **Forensic**: Raw artifact bytes are read without modification. Byte offsets are recorded for all extracted structures.

#### Error Handling

| Error | Strategy | Fallback |
|-------|----------|----------|
| No NTFS partition found | Return `NtfsError::NoNtfsPartition` | Abort pipeline |
| Corrupt NTFS boot sector | Return `NtfsError::CorruptBootSector` with offset | Abort pipeline |
| `$MFT` not found at expected offset | Scan for MFT signature (`FILE0`) | Continue with warning |
| `$UsnJrnl` missing | Set `usnjrnl_data` to empty, emit warning | MFT-only fallback |
| `$LogFile` missing | Set `logfile_data: None` | Continue without LogFile correlation |
| Non-standard cluster size | Accept any power-of-2 cluster size | Continue with warning |

#### Performance Budget

- **Time**: 1 second maximum
- **Memory**: MFT and UsnJrnl are memory-mapped, not fully loaded into heap

#### Dependencies

- Stage 1 (EWF Parser): requires `volume_data`

#### Edge Cases

- **Bitlocker-encrypted volumes**: Detect Bitlocker signature in boot sector and return `NtfsError::EncryptedVolume` with clear messaging. Katana does not decrypt.
- **NTFS 3.0 vs 3.1**: Handle both versions; 3.0 lacks `$UsnJrnl` (Windows 2000). Fall back to MFT-only parsing.
- **Dual-boot systems with multiple NTFS partitions**: When `partition` is `None`, iterate all NTFS partitions and let the user select (CLI flag `--partition`).
- **Sparse `$UsnJrnl:$J`**: The journal is stored as a sparse file. Read only allocated data runs, tracking sparse gaps as potential ghost recovery zones.
- **Very large MFT (>1GB)**: Use memory-mapped I/O; never allocate the full MFT on heap.

---

### 3.3 USN Journal Parser

**Stage ID**: `usn_parser`
**Crate**: `katana-core`
**Tier**: Community (Apache-2.0)
**Parallelism**: Rayon (data-parallel)

#### Job

Parse USN Journal (`$UsnJrnl:$J`) records from raw bytes, extracting all fields including timestamps, filenames, reasons, and MFT references with full V2/V3/V4 record support.

#### Input Contract

| Field | Type | Description |
|-------|------|-------------|
| `usnjrnl_data` | `UsnJrnlData` | Raw `$UsnJrnl:$J` bytes from NTFS handler |
| `volume_info` | `VolumeInfo` | Cluster size and volume metadata |

```rust
pub struct UsnParserInput {
    pub usnjrnl_data: UsnJrnlData,
    pub volume_info: VolumeInfo,
}
```

#### Output Contract

| Field | Type | Description |
|-------|------|-------------|
| `records` | `Vec<UsnRecord>` | Parsed USN records |
| `parse_stats` | `ParseStats` | Count of parsed, skipped, malformed records |
| `journal_bounds` | `JournalBounds` | Earliest and latest USN in the journal |

```rust
pub struct UsnRecord {
    pub usn: u64,                     // USN offset
    pub timestamp: DateTime<Utc>,     // FILETIME converted
    pub reason: UsnReason,            // Bitfield: FILE_CREATE, DATA_EXTEND, etc.
    pub source_info: u32,             // Source information flags
    pub mft_entry: u64,               // Parent MFT entry number
    pub mft_sequence: u16,            // MFT sequence number
    pub parent_mft_entry: u64,        // Parent directory MFT entry
    pub parent_mft_sequence: u16,     // Parent directory sequence
    pub filename: String,             // UTF-16LE decoded filename
    pub file_attributes: u32,         // FILE_ATTRIBUTE_* flags
    pub record_version: UsnVersion,   // V2, V3, or V4
    pub record_offset: u64,           // Byte offset in $UsnJrnl:$J
}

pub struct ParseStats {
    pub total_parsed: u64,
    pub total_skipped: u64,    // zero-filled gaps
    pub total_malformed: u64,  // non-zero but unparseable
    pub version_counts: HashMap<UsnVersion, u64>,
}
```

#### Success Criteria

- **Functional**: All well-formed USN records are parsed. Zero records silently dropped. Malformed records are counted and their offsets logged.
- **Performance**: Completes in under 5 seconds. Achieves 100K+ events/second parse rate via rayon parallelism.
- **Forensic**: Byte offsets preserved for every record. Timestamps converted from FILETIME with nanosecond precision.

#### Error Handling

| Error | Strategy | Fallback |
|-------|----------|----------|
| Invalid record length field | Skip to next 8-byte boundary, log offset | Continue parsing |
| UTF-16LE decode failure | Replace invalid chars with U+FFFD, flag record | Continue with lossy filename |
| Unexpected USN version | Log warning with version number and offset | Skip record, count as malformed |
| Zero-filled region | Skip efficiently (detect zero runs), record gap | Continue; gaps feed Ghost Recovery |
| Truncated record at EOF | Parse available fields, flag as partial | Include partial record with warning |

#### Performance Budget

- **Time**: 5 seconds maximum (parallel with MFT Parser)
- **Memory**: Records stored in a `Vec` sized to estimated journal entry count; typically 50-200 bytes per record
- **CPU**: Rayon work-stealing across all available cores; chunk size tuned for cache locality

#### Dependencies

- Stage 2 (NTFS Volume Handler): requires `usnjrnl_data`, `volume_info`

#### Edge Cases

- **V2 vs V3 records**: V2 uses 32-bit MFT references, V3 uses 128-bit. Parser must detect version from the `MajorVersion` field in each record header.
- **Mixed-version journals**: Some Windows upgrades produce journals with both V2 and V3 records. Handle per-record version detection.
- **Extremely large journals (>4GB)**: Process in streaming chunks via rayon parallel iterators, never loading the full journal into a single `Vec`.
- **Journal wrap-around**: When the journal circular buffer wraps, records at the end of the allocated space may be older than records at the beginning. Detect via USN monotonicity.
- **Timestamps at epoch (Jan 1, 1601)**: FILETIME of zero is a sentinel, not a real timestamp. Flag these records for manual review.
- **Filenames with embedded nulls**: Malformed records may have null bytes within the filename field. Truncate at first null, log warning.

---

### 3.4 MFT Parser

**Stage ID**: `mft_parser`
**Crate**: `katana-core`
**Tier**: Community (Apache-2.0)
**Parallelism**: Rayon (data-parallel)

#### Job

Parse `$MFT` entries to extract file metadata, all four NTFS timestamps (`$STANDARD_INFORMATION` and `$FILE_NAME`), and parent directory references for path reconstruction (CyberCX Rewind algorithm).

#### Input Contract

| Field | Type | Description |
|-------|------|-------------|
| `mft_data` | `MftData` | Raw `$MFT` bytes from NTFS handler |
| `volume_info` | `VolumeInfo` | Cluster size and volume metadata |

```rust
pub struct MftParserInput {
    pub mft_data: MftData,
    pub volume_info: VolumeInfo,
}
```

#### Output Contract

| Field | Type | Description |
|-------|------|-------------|
| `entries` | `Vec<MftEntry>` | Parsed MFT entries |
| `path_map` | `HashMap<u64, String>` | MFT entry number to full path resolution |
| `parse_stats` | `MftParseStats` | Counts and diagnostics |

```rust
pub struct MftEntry {
    pub entry_number: u64,
    pub sequence_number: u16,
    pub flags: MftFlags,              // IN_USE, DIRECTORY, etc.
    pub si_timestamps: Timestamps,    // $STANDARD_INFORMATION
    pub fn_timestamps: Timestamps,    // $FILE_NAME
    pub filename: String,
    pub parent_entry: u64,
    pub parent_sequence: u16,
    pub file_size: u64,
    pub is_resident: bool,
    pub data_runs: Option<Vec<DataRun>>,
}

pub struct Timestamps {
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>,
    pub mft_modified: DateTime<Utc>,
    pub accessed: DateTime<Utc>,
}
```

#### Success Criteria

- **Functional**: All in-use MFT entries parsed. Path reconstruction achieves 100% resolution (zero UNKNOWN paths). Both `$SI` and `$FN` timestamps extracted for timestomping detection.
- **Performance**: Completes in under 5 seconds (parallel with USN Journal Parser).
- **Forensic**: All four timestamp pairs preserved. Deleted entries (flag not IN_USE) still parsed and included for ghost correlation.

#### Error Handling

| Error | Strategy | Fallback |
|-------|----------|----------|
| Invalid MFT entry signature | Skip entry, log offset, increment malformed count | Continue |
| Circular parent references | Detect cycle, break at depth 256, mark path as `CIRCULAR_REF` | Include entry with partial path |
| Orphaned entries (parent not found) | Mark path as `ORPHAN/<filename>` | Include entry |
| Fixup array validation failure | Apply fixup, log if values unexpected | Continue with warning |
| Entry size mismatch | Use minimum of declared size and MFT record size | Log discrepancy |

#### Performance Budget

- **Time**: 5 seconds maximum (parallel with USN Journal Parser; stages 3 and 4 run concurrently)
- **Memory**: MFT entries parsed in rayon parallel chunks; path map is a `HashMap<u64, String>` sized to MFT entry count
- **CPU**: Rayon with chunk size of 1024 entries for optimal cache behavior

#### Dependencies

- Stage 2 (NTFS Volume Handler): requires `mft_data`, `volume_info`

#### Edge Cases

- **Very large MFTs (millions of entries)**: A 1TB volume can have 4M+ MFT entries. Rayon parallelism and memory-mapped input are essential.
- **Alternate data streams (ADS)**: MFT entries may contain multiple `$DATA` attributes. Parse all named streams; primary stream is the unnamed one.
- **Short (8.3) vs long filenames**: MFT entries can have multiple `$FILE_NAME` attributes. Prefer the long name (namespace Win32 or Win32+DOS).
- **Deleted entries in MFT slack**: Entries with cleared IN_USE flag still contain recoverable metadata. Parse these for ghost correlation.
- **Timestomping indicators**: When `$SI` timestamps differ significantly from `$FN` timestamps on the same entry, flag for triage. `$FN` timestamps are harder to forge.
- **MFT entry 0 (self-reference)**: The MFT's own entry. Skip for path resolution but include in metadata output.

---

### 3.5 Ghost Recovery Engine

**Stage ID**: `ghost_recovery`
**Crate**: `katana-core`
**Tier**: Community (Apache-2.0)
**Parallelism**: Single-threaded

#### Job

Recover deleted or overwritten USN Journal records from journal gaps (zero-filled sparse regions) by scanning for valid record signatures in areas where the filesystem has marked data as deallocated.

#### Input Contract

| Field | Type | Description |
|-------|------|-------------|
| `usnjrnl_data` | `UsnJrnlData` | Full `$UsnJrnl:$J` bytes (including sparse gaps) |
| `parsed_records` | `&[UsnRecord]` | Already-parsed live records (to avoid duplicates) |
| `journal_bounds` | `JournalBounds` | Known USN range of live records |
| `volume_info` | `VolumeInfo` | Cluster size for alignment calculations |

```rust
pub struct GhostRecoveryInput<'a> {
    pub usnjrnl_data: &'a UsnJrnlData,
    pub parsed_records: &'a [UsnRecord],
    pub journal_bounds: JournalBounds,
    pub volume_info: VolumeInfo,
}
```

#### Output Contract

| Field | Type | Description |
|-------|------|-------------|
| `ghost_records` | `Vec<GhostRecord>` | Recovered records with confidence scores |
| `recovery_stats` | `RecoveryStats` | Recovery metrics |

```rust
pub struct GhostRecord {
    pub record: UsnRecord,            // Same structure as live records
    pub confidence: f64,              // 0.0-1.0 confidence score
    pub recovery_source: RecoverySource, // SparseGap, OverwrittenRegion
    pub validation_flags: ValidationFlags, // Which fields validated
}

pub struct RecoveryStats {
    pub gaps_scanned: u64,            // Number of sparse gaps examined
    pub bytes_scanned: u64,           // Total bytes searched
    pub candidates_found: u64,        // Records with valid signatures
    pub candidates_validated: u64,    // Records passing validation
    pub duplicates_filtered: u64,     // Already in live records
    pub recovery_rate: f64,           // validated / gaps_with_data
}
```

#### Success Criteria

- **Functional**: Recovery rate >95% on reference corpus. Zero false positives from random data misidentified as records.
- **Performance**: Completes in under 3 seconds.
- **Forensic**: Every ghost record includes a confidence score and validation flags. Ghost records are clearly distinguished from live records in all downstream output.

#### Error Handling

| Error | Strategy | Fallback |
|-------|----------|----------|
| No sparse gaps found | Return empty `ghost_records`, log info | Continue (no ghost records) |
| Candidate record fails validation | Discard silently, increment filtered count | Continue scanning |
| Ambiguous record (partial overwrite) | Include with low confidence (<0.5) and `PARTIAL` flag | Let triage engine decide relevance |
| Memory pressure from large gap scan | Process gaps in 1MB windows | Continue with windowed approach |

#### Performance Budget

- **Time**: 3 seconds maximum
- **Memory**: Processes gaps in streaming windows; does not buffer all gap data simultaneously
- **CPU**: Single-threaded sequential scan (gaps are typically small and scattered)

#### Dependencies

- Stage 2 (NTFS Volume Handler): requires `usnjrnl_data`
- Stage 3 (USN Journal Parser): requires `parsed_records`, `journal_bounds`

#### Edge Cases

- **Journal with no sparse gaps**: Some systems have small, never-wrapped journals. Ghost recovery returns empty results; this is normal.
- **Fully overwritten gaps**: Gaps where new data has completely replaced old records yield no candidates. The scanner must not confuse non-USN data for records.
- **Partially overwritten records**: A record where the header is intact but the filename is corrupted. Include with confidence <0.3 and `PARTIAL_FILENAME` flag.
- **Very old ghost records**: Timestamps predating the volume creation date suggest data from a previous NTFS format. Include but flag as `PRE_FORMAT`.
- **Anti-forensic wiping**: If gaps are filled with a pattern (0xDEADBEEF, sequential bytes), detect and report as `WIPED_GAP` rather than scanning for records.

---

### 3.6 Unallocated Carver

**Stage ID**: `unallocated_carver`
**Crate**: `katana-core`
**Tier**: Community (Apache-2.0)
**Parallelism**: Rayon (data-parallel)

#### Job

Carve USN Journal record signatures from unallocated disk space (clusters not assigned to any file) to recover evidence that has been deleted from both the journal and the filesystem.

#### Input Contract

| Field | Type | Description |
|-------|------|-------------|
| `volume_data` | `VolumeReader` | Seekable byte stream (from EWF Parser) |
| `unallocated_ranges` | `Vec<ByteRange>` | Unallocated cluster ranges from NTFS handler |
| `known_records` | `&RecordIndex` | Index of live + ghost records (for deduplication) |
| `volume_info` | `VolumeInfo` | Cluster and sector sizes |

```rust
pub struct CarverInput<'a> {
    pub volume_data: &'a VolumeReader,
    pub unallocated_ranges: Vec<ByteRange>,
    pub known_records: &'a RecordIndex,
    pub volume_info: VolumeInfo,
}
```

#### Output Contract

| Field | Type | Description |
|-------|------|-------------|
| `carved_records` | `Vec<CarvedRecord>` | Records found in unallocated space |
| `carving_stats` | `CarvingStats` | Metrics on unallocated scanning |

```rust
pub struct CarvedRecord {
    pub record: UsnRecord,
    pub confidence: f64,
    pub disk_offset: u64,              // Absolute byte offset on disk
    pub cluster_number: u64,           // Which unallocated cluster
    pub recovery_source: RecoverySource, // UnallocatedSpace
}

pub struct CarvingStats {
    pub clusters_scanned: u64,
    pub bytes_scanned: u64,
    pub candidates_found: u64,
    pub candidates_validated: u64,
    pub duplicates_filtered: u64,
    pub scan_coverage: f64,            // proportion of unallocated space scanned
}
```

#### Success Criteria

- **Functional**: All USN record signatures in unallocated space are identified. Duplicates against live and ghost records are filtered. False positive rate <1%.
- **Performance**: Completes in under 5 seconds for typical unallocated space on a 1GB image.
- **Forensic**: Absolute disk offsets recorded for every carved record (court-admissible sourcing).

#### Error Handling

| Error | Strategy | Fallback |
|-------|----------|----------|
| No unallocated space | Return empty results, log info | Continue |
| I/O error reading cluster | Skip cluster, log error with cluster number | Continue scanning remaining clusters |
| High false-positive rate detected | Tighten validation heuristics dynamically | Log warning |
| Budget exceeded mid-scan | Stop scanning, return partial results with `incomplete: true` | Partial results with coverage metric |

#### Performance Budget

- **Time**: 5 seconds maximum
- **Memory**: Read unallocated clusters in 64KB windows; rayon parallel over cluster ranges
- **CPU**: Rayon work-stealing; embarrassingly parallel per cluster range
- **I/O**: Sequential reads within each range; random seeks between ranges

#### Dependencies

- Stage 1 (EWF Parser): requires `volume_data`
- Stage 2 (NTFS Volume Handler): requires `unallocated_ranges`, `volume_info`
- Stage 3 (USN Journal Parser): requires `known_records` (for dedup)
- Stage 5 (Ghost Recovery): requires `known_records` (includes ghost records)

#### Edge Cases

- **Heavily fragmented volumes**: Many small unallocated ranges increase seek overhead. Batch nearby ranges to amortize seek cost.
- **SSD-trimmed regions**: TRIM commands may zero unallocated space. Detect large zero-filled regions and skip them efficiently.
- **Non-USN data matching signature**: Random byte patterns can coincidentally match USN record headers. Multi-field validation (length, version, timestamp range, reason flags) reduces false positives.
- **Cross-cluster records**: A USN record spanning two clusters where only one is unallocated. Attempt to read the adjacent cluster even if allocated (it may contain the record continuation).
- **Very large unallocated space (>50% of volume)**: Prioritize clusters adjacent to `$UsnJrnl` data runs, as these are most likely to contain journal remnants.

---

### 3.7 QuadLink Correlator

**Stage ID**: `quadlink_correlator`
**Crate**: `katana-core`
**Tier**: Community (Apache-2.0)
**Parallelism**: Single-threaded

#### Job

Cross-reference records from four artifact sources (USN Journal, MFT, `$LogFile`, and file metadata) into a unified, timestamped event timeline with full path resolution and anomaly detection.

#### Input Contract

| Field | Type | Description |
|-------|------|-------------|
| `usn_records` | `Vec<UsnRecord>` | Live USN records from parser |
| `ghost_records` | `Vec<GhostRecord>` | Recovered ghost records |
| `carved_records` | `Vec<CarvedRecord>` | Carved unallocated records |
| `mft_entries` | `Vec<MftEntry>` | Parsed MFT entries |
| `path_map` | `HashMap<u64, String>` | MFT entry to full path map |
| `logfile_data` | `Option<LogFileData>` | Parsed `$LogFile` (if available) |

```rust
pub struct CorrelatorInput {
    pub usn_records: Vec<UsnRecord>,
    pub ghost_records: Vec<GhostRecord>,
    pub carved_records: Vec<CarvedRecord>,
    pub mft_entries: Vec<MftEntry>,
    pub path_map: HashMap<u64, String>,
    pub logfile_data: Option<LogFileData>,
}
```

#### Output Contract

| Field | Type | Description |
|-------|------|-------------|
| `timeline` | `Vec<TimelineEvent>` | Unified chronological timeline |
| `anomalies` | `Vec<Anomaly>` | Detected inconsistencies (timestomping, orphans) |
| `correlation_stats` | `CorrelationStats` | Join metrics |

```rust
pub struct TimelineEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: EventType,
    pub full_path: String,             // Resolved via path_map
    pub filename: String,
    pub mft_entry: u64,
    pub usn: Option<u64>,
    pub reason: Option<UsnReason>,
    pub source: EventSource,           // Live, Ghost, Carved, MFT
    pub si_timestamps: Option<Timestamps>,
    pub fn_timestamps: Option<Timestamps>,
    pub confidence: f64,               // 1.0 for live, <1.0 for recovered
    pub anomaly_flags: Vec<AnomalyFlag>,
}

pub struct Anomaly {
    pub anomaly_type: AnomalyType,     // Timestomping, OrphanedEntry, GapInSequence, etc.
    pub affected_entries: Vec<u64>,    // MFT entry numbers
    pub description: String,
    pub severity: Severity,            // Info, Warning, Critical
}

pub struct CorrelationStats {
    pub total_events: u64,
    pub usn_matched_to_mft: u64,
    pub unmatched_usn: u64,
    pub unmatched_mft: u64,
    pub paths_resolved: u64,
    pub paths_unknown: u64,            // Target: 0
    pub anomalies_detected: u64,
}
```

#### Success Criteria

- **Functional**: All USN records (live, ghost, carved) correlated with MFT entries where possible. Path resolution completeness = 100% (zero UNKNOWN). Timestomping detection operational.
- **Performance**: Completes in under 3 seconds using in-memory hash-join.
- **Forensic**: Timeline is strictly chronologically sorted. Source provenance (live/ghost/carved) preserved on every event. Anomalies include severity ratings.

#### Error Handling

| Error | Strategy | Fallback |
|-------|----------|----------|
| MFT entry referenced by USN not found | Mark path as `DELETED/<filename>` | Include event with partial data |
| Path resolution produces UNKNOWN | Retry with parent chain traversal | Mark as `UNRESOLVED/<mft_entry>/<filename>` |
| `$LogFile` parse failure | Omit LogFile correlation column | Continue with 3-source correlation |
| Timestamp paradox (effect before cause) | Flag as `TIMESTAMP_ANOMALY` | Include in timeline at recorded time |
| Memory exhaustion from large join | Abort with clear error | Suggest `--low-memory` mode |

#### Performance Budget

- **Time**: 3 seconds maximum
- **Memory**: Hash-join requires ~100 bytes per event in the index; for 500K events, approximately 50MB
- **Algorithm**: Hash-join on `(mft_entry, mft_sequence)` as the primary key

#### Dependencies

- Stage 3 (USN Journal Parser): requires `usn_records`
- Stage 4 (MFT Parser): requires `mft_entries`, `path_map`
- Stage 5 (Ghost Recovery): requires `ghost_records`
- Stage 6 (Unallocated Carver): requires `carved_records`

#### Edge Cases

- **MFT entry number reuse**: NTFS reuses MFT entry numbers after deletion. The sequence number distinguishes incarnations. Join on `(entry, sequence)` to avoid false correlations.
- **USN records referencing future MFT entries**: Can occur with journal wrap-around or clock skew. Include but flag with `SEQUENCE_MISMATCH`.
- **Extremely dense timelines**: Thousands of events per second (e.g., build processes). Correlator must handle high-cardinality joins efficiently.
- **Ghost records with corrupted MFT references**: If `mft_entry` in a ghost record points to an invalid MFT entry, correlate on filename + timestamp proximity instead.
- **Multiple files with identical names**: Common with temp files. Disambiguate via MFT entry number and parent directory.

---

### 3.8 Triage Engine

**Stage ID**: `triage_engine`
**Crate**: `katana-core`
**Tier**: Community (Apache-2.0)
**Parallelism**: Rayon (per-question parallel)

#### Job

Evaluate 12 incident response triage questions against the correlated timeline, producing deterministic yes/no/inconclusive answers with supporting evidence citations and confidence scores.

#### Input Contract

| Field | Type | Description |
|-------|------|-------------|
| `timeline` | `Vec<TimelineEvent>` | Correlated timeline from QuadLink |
| `anomalies` | `Vec<Anomaly>` | Detected anomalies |
| `correlation_stats` | `CorrelationStats` | Quality metrics for confidence calibration |
| `custom_rules` | `Option<Vec<TriageRule>>` | User-defined YAML rules (optional) |

```rust
pub struct TriageInput {
    pub timeline: Vec<TimelineEvent>,
    pub anomalies: Vec<Anomaly>,
    pub correlation_stats: CorrelationStats,
    pub custom_rules: Option<Vec<TriageRule>>,
}
```

#### Output Contract

| Field | Type | Description |
|-------|------|-------------|
| `answers` | `Vec<TriageAnswer>` | Answer to each IR question |
| `triage_summary` | `TriageSummary` | Overall triage result |

```rust
pub struct TriageAnswer {
    pub question_id: u8,
    pub question: String,              // Human-readable question text
    pub verdict: Verdict,              // Yes, No, Inconclusive
    pub confidence: f64,               // 0.0-1.0
    pub supporting_events: Vec<TimelineEvent>, // Evidence citations
    pub reasoning: String,             // Why this verdict
    pub false_positive_notes: Option<String>,  // Known FP patterns
}

pub enum Verdict {
    Yes,          // Evidence supports affirmative answer
    No,           // No evidence found
    Inconclusive, // Evidence is ambiguous
}

pub struct TriageSummary {
    pub total_questions: u8,
    pub yes_count: u8,
    pub no_count: u8,
    pub inconclusive_count: u8,
    pub overall_severity: Severity,
    pub completion_rate: f64,           // non-inconclusive / total
    pub triage_duration_ms: u64,
}
```

#### Success Criteria

- **Functional**: Triage completion rate >95%. False positive rate <5%. Every answer includes supporting evidence or explicit reasoning for "No" / "Inconclusive".
- **Performance**: Completes in under 5 seconds. All 12 questions evaluated in parallel via rayon.
- **Forensic**: Answers are deterministic -- identical timeline input produces identical answers. Published precision/recall metrics per question.

#### Error Handling

| Error | Strategy | Fallback |
|-------|----------|----------|
| Empty timeline | Return all answers as `Inconclusive` with reason | Complete triage with warnings |
| Custom rule parse failure | Skip invalid rule, log warning, continue with built-in rules | Partial custom rules |
| Question logic panic | Catch panic, return `Inconclusive` for that question | Continue other questions |
| Timeline too large for per-question scan | Pre-index timeline by event type | Continue with indexed scan |

#### Performance Budget

- **Time**: 5 seconds maximum
- **Memory**: Timeline is read-only shared reference; each question evaluator reads without copying
- **CPU**: Rayon spawns one task per question; questions are independent and embarrassingly parallel

#### Dependencies

- Stage 7 (QuadLink Correlator): requires `timeline`, `anomalies`, `correlation_stats`

#### Edge Cases

- **No USB activity on a server image**: USB-related questions should return `No` with high confidence, not `Inconclusive`. Context-aware question evaluation.
- **Timestomping detected**: When anomalies include timestomping, increase suspicion scores across all related triage answers.
- **Ghost-only evidence**: When a triage answer relies solely on ghost-recovered records (confidence <1.0), adjust the answer confidence proportionally and note the evidence source.
- **Conflicting evidence**: USN says file was created, but MFT shows no corresponding entry. Verdict should be `Inconclusive` with detailed reasoning.
- **Custom rules overriding built-in logic**: Custom YAML rules take precedence over built-in heuristics for the same question. Log when override occurs.
- **Extremely short timelines (<100 events)**: Small images or narrow time ranges. Adjust false-positive thresholds to avoid noise on sparse data.

---

### 3.9 Output Formatter

**Stage ID**: `output_formatter`
**Crate**: `katana-formats`
**Tier**: Community (Apache-2.0)
**Parallelism**: Single-threaded

#### Job

Generate final reports from triage results and correlated timeline in all 7 supported output formats, with version headers and integrity hashes for court admissibility.

#### Input Contract

| Field | Type | Description |
|-------|------|-------------|
| `timeline` | `Vec<TimelineEvent>` | Full correlated timeline |
| `triage_answers` | `Vec<TriageAnswer>` | IR question answers |
| `triage_summary` | `TriageSummary` | Overall triage result |
| `parse_stats` | `AggregateStats` | Stats from all pipeline stages |
| `output_config` | `OutputConfig` | Which formats to emit, output directory |

```rust
pub struct FormatterInput {
    pub timeline: Vec<TimelineEvent>,
    pub triage_answers: Vec<TriageAnswer>,
    pub triage_summary: TriageSummary,
    pub parse_stats: AggregateStats,
    pub output_config: OutputConfig,
}

pub struct OutputConfig {
    pub formats: Vec<OutputFormat>,     // Which formats to generate
    pub output_dir: PathBuf,            // Target directory
    pub case_id: Option<String>,        // Optional case identifier
    pub examiner: Option<String>,       // Examiner name for reports
    pub include_timeline: bool,         // Include full timeline (can be large)
    pub include_ghost: bool,            // Include ghost/carved records
}

pub enum OutputFormat {
    Sqlite,   // Full database with indexed tables
    Jsonl,    // Newline-delimited JSON (streaming-friendly)
    Csv,      // Flat CSV with denormalized fields
    Xml,      // DFXML-compatible schema
    Tln,      // TLN 5-field pipe-delimited (SANS format)
    Html,     // Interactive HTML report with charts
    Body,     // Sleuthkit body file format (mactime compatible)
}
```

#### Output Contract

| Field | Type | Description |
|-------|------|-------------|
| `generated_files` | `Vec<GeneratedFile>` | Paths and hashes of output files |
| `format_stats` | `Vec<FormatStats>` | Per-format generation metrics |

```rust
pub struct GeneratedFile {
    pub path: PathBuf,
    pub format: OutputFormat,
    pub sha256: String,                 // Integrity hash of output file
    pub size_bytes: u64,
    pub record_count: u64,
    pub generation_time_ms: u64,
}
```

#### Success Criteria

- **Functional**: All requested formats generated successfully. Every output file includes a SHA-256 integrity hash. SQLite output has proper indexes for analyst queries.
- **Performance**: Completes in under 3 seconds for all 7 formats combined.
- **Forensic**: Output format versioned with Katana version string and format schema version. HTML report is self-contained (no external dependencies). SHA-256 hash appended to each output file.

#### Error Handling

| Error | Strategy | Fallback |
|-------|----------|----------|
| Output directory not writable | Return `FormatterError::PermissionDenied` | Abort |
| Disk space insufficient | Check before writing, return `FormatterError::DiskFull` | Abort with estimate |
| Individual format failure | Log error, skip that format, continue others | Partial output |
| HTML template missing | Fall back to minimal HTML generation | Simplified report |
| SQLite database locked | Retry with exponential backoff (3 attempts) | Fall back to JSONL |

#### Performance Budget

- **Time**: 3 seconds maximum (all formats combined)
- **Memory**: Streaming writes for JSONL, CSV, TLN, Body; batch writes for SQLite (transaction-based); HTML generated from in-memory template
- **I/O**: Sequential writes; SQLite uses WAL mode for concurrent read access

#### Dependencies

- Stage 7 (QuadLink Correlator): requires `timeline`
- Stage 8 (Triage Engine): requires `triage_answers`, `triage_summary`

#### Edge Cases

- **Very large timelines (>1M events)**: JSONL and CSV stream without issue. SQLite uses batched inserts (1000 per transaction). HTML limits inline data to 10K events and provides a "download full dataset" link.
- **Unicode filenames in CSV**: Use BOM-prefixed UTF-8 for Excel compatibility. Escape commas and newlines within filenames.
- **Body file timestamp format**: Sleuthkit body format uses Unix epoch integers. Ensure FILETIME-to-epoch conversion handles dates before 1970 (negative epoch values).
- **TLN format field length limits**: Some TLN consumers expect fields under 256 characters. Truncate long paths with `...` and log full path in notes field.
- **HTML report with no JavaScript**: The HTML report must function without JavaScript for air-gapped environments. Charts rendered as SVG, not Canvas/JS.
- **Concurrent output to same directory**: Multiple Katana runs outputting to the same directory. Use case ID or timestamp in filenames to prevent overwrites.

---

## 4. Enterprise Stage Contracts

### 4.1 Collection Agent

**Stage ID**: `collection_agent`
**Crate**: `katana-agent`
**Tier**: Enterprise (Proprietary)
**Framework**: tonic gRPC

#### Job

Lightweight endpoint agent that collects forensic artifacts (`$MFT`, `$UsnJrnl`, `$LogFile`, registry hives) from live Windows systems and transmits them to the Katana Server via mTLS-authenticated gRPC streaming.

#### Input Contract

| Field | Type | Description |
|-------|------|-------------|
| `collection_manifest` | `CollectionManifest` | Server-issued manifest specifying what to collect |
| `server_endpoint` | `String` | gRPC server address |
| `client_certificate` | `CertificateChain` | mTLS client cert for authentication |

```rust
pub struct CollectionManifest {
    pub case_id: String,
    pub artifacts: Vec<ArtifactSpec>,   // What to collect
    pub priority: Priority,             // Normal, Urgent
    pub max_bandwidth: Option<u64>,     // Throttle in bytes/sec
    pub expiry: DateTime<Utc>,          // Manifest valid until
}

pub struct ArtifactSpec {
    pub artifact_type: ArtifactType,    // MFT, UsnJrnl, LogFile, Registry, etc.
    pub volume: Option<String>,         // e.g., "C:" (None = all NTFS volumes)
}
```

#### Output Contract

| Field | Type | Description |
|-------|------|-------------|
| `collected_artifacts` | `Vec<CollectedArtifact>` | Artifacts with integrity hashes |
| `collection_report` | `CollectionReport` | Timing, errors, system info |

```rust
pub struct CollectedArtifact {
    pub artifact_type: ArtifactType,
    pub sha256: String,                 // Hash computed before transmission
    pub size_bytes: u64,
    pub source_path: String,            // Original path on endpoint
    pub collection_timestamp: DateTime<Utc>,
    pub system_info: SystemInfo,        // Hostname, OS version, timezone
}
```

#### Success Criteria

- **Functional**: All specified artifacts collected from live system. SHA-256 hash computed before transmission and verified server-side.
- **Performance**: Binary size <5MB. Cold start <50ms. Collection of standard artifacts completes in <30 seconds per volume.
- **Forensic**: Chain of custody maintained via hash-before-transmit. System clock offset recorded. No modification to source artifacts.

#### Error Handling

| Error | Strategy | Fallback |
|-------|----------|----------|
| Artifact locked by OS | Volume shadow copy (VSS) fallback | Raw device read as last resort |
| Server unreachable | Queue artifacts locally with exponential backoff | Resume transmission when server available |
| Certificate expired | Refuse to transmit, log error | Require re-enrollment |
| Insufficient permissions | Report per-artifact access errors | Collect accessible artifacts, skip others |
| Network interruption mid-transfer | Resume from last acknowledged chunk | Automatic retry with checkpointing |

#### Dependencies

None at the pipeline level. Triggered by server-issued manifest.

#### Edge Cases

- **Locked `$MFT` on live system**: Windows locks the MFT. Use raw NTFS device read (`\\.\C:`) or VSS snapshot to access.
- **Agent running under non-admin context**: Some artifacts require admin privileges. Report capability limitations rather than failing silently.
- **Bandwidth-constrained networks**: Respect `max_bandwidth` throttle to avoid disrupting production systems during live IR.
- **Anti-virus interference**: AV may flag raw disk reads. Agent binary should be signed with a code-signing certificate.
- **Multi-boot systems**: Enumerate all NTFS volumes, not just the system volume.

---

### 4.2 Import Adapter

**Stage ID**: `import_adapter`
**Crate**: `katana-import`
**Tier**: Enterprise (Proprietary)

#### Job

Ingest forensic artifact collections from third-party tools (Velociraptor and Binalyze IREC) and normalize them into Katana's internal format for processing by the community pipeline.

#### Input Contract

| Field | Type | Description |
|-------|------|-------------|
| `import_source` | `ImportSource` | Source type and path |
| `collection_path` | `PathBuf` | Path to imported collection |

```rust
pub enum ImportSource {
    Velociraptor {
        flow_id: String,
        client_id: String,
    },
    Binalyze {
        case_id: String,
    },
    RawDirectory {
        artifact_map: HashMap<ArtifactType, PathBuf>,
    },
}
```

#### Output Contract

| Field | Type | Description |
|-------|------|-------------|
| `normalized_input` | `NormalizedCollection` | Artifacts in Katana internal format |
| `import_report` | `ImportReport` | What was found, mapped, and skipped |

```rust
pub struct NormalizedCollection {
    pub mft_data: Option<MftData>,
    pub usnjrnl_data: Option<UsnJrnlData>,
    pub logfile_data: Option<LogFileData>,
    pub source_metadata: SourceMetadata,  // Original tool, collection time, system info
    pub integrity_hashes: HashMap<ArtifactType, String>,
}
```

#### Success Criteria

- **Functional**: Velociraptor `Windows.NTFS.MFT` and `Windows.Forensics.Usn` artifact types correctly mapped. Binalyze IREC directory structure parsed.
- **Performance**: Import normalization completes in <5 seconds.
- **Forensic**: Original hashes from source tool preserved and cross-referenced against Katana's computed hashes.

#### Error Handling

| Error | Strategy | Fallback |
|-------|----------|----------|
| Unknown collection format | Return `ImportError::UnrecognizedFormat` | Suggest `RawDirectory` manual mapping |
| Missing expected artifact | Import available artifacts, log missing ones | Partial import with warnings |
| Hash mismatch vs source tool | Log critical warning, do not suppress | Continue but flag in audit trail |
| Velociraptor API version mismatch | Fall back to file-based import | Manual artifact extraction |

#### Dependencies

None at the pipeline level. Produces input for Stage 2 (NTFS Volume Handler) or directly for Stages 3-4.

#### Edge Cases

- **Velociraptor encrypted containers**: Some Velociraptor collections are password-protected ZIP files. Prompt for password or accept via config.
- **Binalyze partial collections**: IREC may time out mid-collection. Import what is available, clearly marking partial artifacts.
- **Artifact naming variations across Velociraptor versions**: Different VQL artifact names across versions. Maintain a mapping table.
- **Mixed-OS collections**: Velociraptor collects from Linux/macOS too. Reject non-NTFS artifacts with clear error.

---

### 4.3 Multi-Device Correlator

**Stage ID**: `multi_device_correlator`
**Crate**: `katana-multi`
**Tier**: Enterprise (Proprietary)
**Approach**: Streaming (incremental)

#### Job

Correlate forensic timelines across multiple disk images (devices) to identify lateral movement, coordinated activity, and cross-device evidence chains in multi-endpoint investigations.

#### Input Contract

| Field | Type | Description |
|-------|------|-------------|
| `device_timelines` | `Vec<DeviceTimeline>` | Per-device correlated timelines |
| `correlation_keys` | `Vec<CorrelationKey>` | Keys to correlate on (timestamp, username, IP, hash) |
| `time_window` | `Duration` | Maximum time difference for correlation |

```rust
pub struct DeviceTimeline {
    pub device_id: String,
    pub hostname: String,
    pub timeline: Vec<TimelineEvent>,
    pub triage_answers: Vec<TriageAnswer>,
    pub timezone_offset: i32,           // UTC offset in minutes
}

pub enum CorrelationKey {
    Timestamp,
    Username,
    IpAddress,
    FileHash,
    ProcessName,
    SessionId,
}
```

#### Output Contract

| Field | Type | Description |
|-------|------|-------------|
| `cross_device_events` | `Vec<CrossDeviceEvent>` | Correlated multi-device events |
| `lateral_movement` | `Vec<LateralMovementChain>` | Detected movement patterns |
| `correlation_stats` | `MultiDeviceStats` | Cross-device metrics |

```rust
pub struct CrossDeviceEvent {
    pub events: Vec<(String, TimelineEvent)>,  // (device_id, event) pairs
    pub correlation_type: CorrelationKey,
    pub time_spread: Duration,
    pub confidence: f64,
}
```

#### Success Criteria

- **Functional**: All specified correlation keys evaluated across all device pairs. Lateral movement chains reconstructed when evidence exists.
- **Performance**: Streaming approach handles incremental device additions without re-processing existing correlations.
- **Forensic**: Timezone normalization applied before correlation. Device provenance preserved on every correlated event.

#### Error Handling

| Error | Strategy | Fallback |
|-------|----------|----------|
| Timezone mismatch detected | Normalize all timestamps to UTC, log original offsets | Continue with warning |
| No correlations found | Return empty results (legitimate for unrelated devices) | No fallback needed |
| Memory exhaustion (too many devices) | Switch to disk-backed merge-sort | Continue with degraded performance |
| Clock skew between devices | Detect via system event correlation, apply offset | Widen time_window |

#### Dependencies

- Stage 7 (QuadLink Correlator): requires per-device `timeline` output

#### Edge Cases

- **Devices in different timezones**: UTC normalization is mandatory. Log original timezone for audit.
- **Identical hostnames**: Different devices with the same hostname (common in DHCP environments). Disambiguate via volume serial number.
- **Large device counts (>20)**: Pairwise correlation is O(n^2). Use inverted index on correlation keys for efficiency.
- **Temporal gaps between device acquisitions**: Device A imaged Monday, Device B imaged Friday. Timeline comparison must account for evidence aging.

---

### 4.4 PCAP/NetFlow Parser

**Stage ID**: `pcap_netflow_parser`
**Crate**: `katana-pcap`
**Tier**: Enterprise (Proprietary)
**Implements**: `EvidenceSource` trait

#### Job

Parse network capture files (PCAP/PCAPNG) and NetFlow v5/v9/IPFIX records to extract network events that can be correlated with disk-based forensic timelines via timestamps, IP addresses, and hostnames.

#### Input Contract

| Field | Type | Description |
|-------|------|-------------|
| `capture_path` | `PathBuf` | Path to PCAP/PCAPNG/NetFlow file |
| `capture_type` | `CaptureType` | PCAP, PCAPNG, NetFlowV5, NetFlowV9, IPFIX |
| `filter` | `Option<NetworkFilter>` | BPF-style filter for targeted parsing |

```rust
pub enum CaptureType {
    Pcap,
    PcapNg,
    NetFlowV5,
    NetFlowV9,
    Ipfix,
    Auto,  // detect from file header
}

pub struct NetworkFilter {
    pub ip_addresses: Option<Vec<IpAddr>>,
    pub ports: Option<Vec<u16>>,
    pub protocols: Option<Vec<Protocol>>,
    pub time_range: Option<(DateTime<Utc>, DateTime<Utc>)>,
}
```

#### Output Contract

| Field | Type | Description |
|-------|------|-------------|
| `network_events` | `Vec<NetworkEvent>` | Parsed network events |
| `dns_resolutions` | `HashMap<IpAddr, Vec<String>>` | IP-to-hostname mappings from DNS traffic |
| `parse_stats` | `NetworkParseStats` | Packet/flow counts |

```rust
pub struct NetworkEvent {
    pub timestamp: DateTime<Utc>,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
    pub bytes_transferred: u64,
    pub flags: Option<TcpFlags>,
    pub dns_query: Option<String>,
    pub event_type: NetworkEventType,
}
```

#### Success Criteria

- **Functional**: All supported capture formats parsed. DNS resolutions extracted for IP-to-hostname correlation. Implements `EvidenceSource` trait for pipeline integration.
- **Performance**: Processes 100K+ packets/second.
- **Forensic**: Packet timestamps preserved at microsecond precision. Original capture file hash recorded.

#### Error Handling

| Error | Strategy | Fallback |
|-------|----------|----------|
| Corrupt capture file | Parse until corruption, return partial results | Partial output with byte offset of corruption |
| Unknown protocol | Skip packet, log protocol number | Continue parsing |
| Truncated packets | Parse available headers, flag as truncated | Include partial event |
| Unsupported NetFlow template | Log template ID, skip records using it | Continue with known templates |

#### Dependencies

None directly. Output feeds into Multi-Device Correlator or QuadLink Correlator (extended mode).

#### Edge Cases

- **Encrypted traffic (TLS)**: Parse TLS handshake metadata (SNI, certificate info) but not encrypted payload. Log as `EncryptedSession`.
- **VLAN-tagged frames**: Strip 802.1Q tags before IP parsing. Preserve VLAN ID in event metadata.
- **Jumbo frames**: Handle packets >1500 bytes without buffer overflow.
- **Capture files >10GB**: Stream-process without loading into memory.
- **Nanosecond-precision timestamps (PCAPNG)**: Preserve full precision; do not truncate to microseconds.

---

### 4.5 Collaboration Engine

**Stage ID**: `collaboration_engine`
**Crate**: `katana-collab`
**Tier**: Enterprise (Proprietary)
**Protocol**: WebSocket pub/sub

#### Job

Enable real-time multi-analyst collaboration on forensic investigations via WebSocket-based pub/sub, providing shared timeline views, annotation synchronization, and conflict-free concurrent analysis.

#### Input Contract

| Field | Type | Description |
|-------|------|-------------|
| `case_id` | `String` | Investigation case identifier |
| `analyst_session` | `AnalystSession` | Authenticated analyst session (from RBAC) |
| `action` | `CollabAction` | Subscribe, annotate, bookmark, share filter |

```rust
pub enum CollabAction {
    Subscribe { case_id: String },
    Annotate { event_id: u64, note: String, tags: Vec<String> },
    Bookmark { event_id: u64, label: String },
    ShareFilter { filter: TimelineFilter },
    CursorUpdate { position: TimelinePosition },
    Unsubscribe,
}
```

#### Output Contract

| Field | Type | Description |
|-------|------|-------------|
| `broadcast` | `CollabBroadcast` | Messages pushed to subscribed analysts |

```rust
pub enum CollabBroadcast {
    AnnotationAdded { analyst: String, event_id: u64, note: String },
    BookmarkAdded { analyst: String, event_id: u64, label: String },
    FilterShared { analyst: String, filter: TimelineFilter },
    CursorMoved { analyst: String, position: TimelinePosition },
    AnalystJoined { analyst: String },
    AnalystLeft { analyst: String },
}
```

#### Success Criteria

- **Functional**: Annotations and bookmarks synchronized across all connected analysts within 100ms. No data loss on disconnect/reconnect.
- **Performance**: Supports 50+ concurrent analysts per case. WebSocket message latency <100ms.
- **Forensic**: All annotations are immutable and timestamped. Analyst identity attached to every action via RBAC session.

#### Error Handling

| Error | Strategy | Fallback |
|-------|----------|----------|
| WebSocket disconnection | Buffer messages, replay on reconnect | 5-minute buffer window |
| Conflicting annotations | Both preserved with timestamps (no overwrites) | CRDT-style merge |
| Unauthorized action | Reject with RBAC error, log attempt | No fallback |
| Case not found | Return error, do not create implicitly | Require explicit case creation |

#### Dependencies

- Stage 15 (RBAC Gateway): requires authenticated analyst sessions

#### Edge Cases

- **Analyst reconnects after long disconnection**: Replay buffered messages up to 5-minute window. Beyond that, send full state snapshot.
- **High annotation volume**: Rate-limit individual analysts to 10 annotations/second to prevent spam.
- **Cross-timezone teams**: All timestamps in UTC. Client renders in local timezone.
- **Concurrent edits to same annotation**: Annotations are append-only. "Edits" are new annotations referencing the original.

---

### 4.6 RBAC Gateway

**Stage ID**: `rbac_gateway`
**Crate**: `katana-server` (Tower middleware)
**Tier**: Enterprise (Proprietary)
**Framework**: Tower middleware layer on Axum

#### Job

Enforce role-based access control on all enterprise API endpoints, authenticating users via JWT tokens and authorizing actions based on role-case scope assignments.

#### Input Contract

| Field | Type | Description |
|-------|------|-------------|
| `request` | `HttpRequest` | Incoming API request with `Authorization: Bearer <JWT>` header |
| `route` | `Route` | Target endpoint and HTTP method |

```rust
pub struct RbacContext {
    pub token: JwtClaims,
    pub requested_resource: Resource,  // Case, Evidence, Report, User, AuditLog
    pub requested_action: Action,      // Read, Write, Delete, Admin
    pub case_id: Option<String>,       // Scope-limiting case ID
}
```

#### Output Contract

| Field | Type | Description |
|-------|------|-------------|
| `decision` | `AccessDecision` | Allow or Deny with reason |

```rust
pub enum AccessDecision {
    Allow { effective_role: Role },
    Deny { reason: String, required_role: Role },
}
```

#### Roles and Permissions

| Role | Cases | Evidence | Reports | Users | Audit Logs |
|------|-------|----------|---------|-------|------------|
| **Admin** | CRUD | CRUD | CRUD | CRUD | Read |
| **Case Manager** | CRUD (own) | Read | CRUD (own) | - | Read (own) |
| **Examiner** | Read (assigned) | CRUD (assigned) | CRUD (assigned) | - | Read (own) |
| **Reviewer** | Read (assigned) | Read (assigned) | Read (assigned) | - | - |
| **Auditor** | - | - | - | - | Read (all) |

#### Success Criteria

- **Functional**: Zero unauthorized access. All role-case assignments enforced. SSO/SAML integration operational.
- **Performance**: Authorization decision in <1ms (in-memory role cache). Token validation in <5ms.
- **Forensic**: Every access decision (allow and deny) logged to audit trail with full context.

#### Error Handling

| Error | Strategy | Fallback |
|-------|----------|----------|
| Expired JWT | Return 401 Unauthorized | Client must re-authenticate |
| Invalid JWT signature | Return 401, log as security event | No fallback |
| Insufficient permissions | Return 403 Forbidden with required role | No fallback (deny-by-default) |
| SSO provider unavailable | Fall back to local JWT validation | Cached tokens valid for configured TTL |
| Role cache stale | Refresh from database on cache miss | Accept brief staleness (max 60s) |

#### Dependencies

None. This is middleware applied to all enterprise endpoints.

#### Edge Cases

- **Token issued before role change**: Cached role may be stale. Force re-fetch on sensitive operations (Delete, Admin).
- **Multi-tenant isolation**: Schema-per-tenant in PostgreSQL. RBAC must enforce tenant boundary even if JWT is valid.
- **Service-to-service calls**: Internal microservice calls use service accounts with dedicated roles. No human analyst session required.
- **Admin lockout**: If all admin accounts are disabled, a break-glass procedure via CLI is required (not API-accessible).

---

### 4.7 Audit Logger

**Stage ID**: `audit_logger`
**Crate**: `katana-server` (integrated component)
**Tier**: Enterprise (Proprietary)

#### Job

Maintain an append-only, hash-chain audit trail of all state transitions, access decisions, and evidence operations for SOC 2 compliance and forensic chain-of-custody documentation.

#### Input Contract

| Field | Type | Description |
|-------|------|-------------|
| `audit_event` | `AuditEvent` | Event to log |

```rust
pub struct AuditEvent {
    pub event_type: AuditEventType,
    pub timestamp: DateTime<Utc>,
    pub actor: ActorIdentity,           // User, service account, or system
    pub resource: Resource,
    pub action: Action,
    pub result: ActionResult,           // Success or Failure(reason)
    pub metadata: serde_json::Value,    // Action-specific details
    pub client_ip: IpAddr,
    pub request_id: Uuid,
}

pub enum AuditEventType {
    Authentication,
    Authorization,
    EvidenceAccess,
    CaseManagement,
    CollectionTriggered,
    ReportGenerated,
    ConfigChange,
    UserManagement,
}
```

#### Output Contract

| Field | Type | Description |
|-------|------|-------------|
| `log_entry` | `AuditLogEntry` | Persisted log entry with hash chain |

```rust
pub struct AuditLogEntry {
    pub sequence: u64,                  // Monotonic sequence number
    pub event: AuditEvent,
    pub sha256: String,                 // SHA-256(previous_hash + serialized_event)
    pub previous_hash: String,          // Hash of previous entry (chain link)
}
```

#### Success Criteria

- **Functional**: Every auditable action produces a log entry. Hash chain is unbroken and independently verifiable. Tamper-evident: any modification to historical entries breaks the chain.
- **Performance**: Audit logging adds <1ms latency to any request. Append-only writes are fast.
- **Forensic**: SOC 2 Type II compliance. Audit logs exportable for external review. Retention policy configurable (default: 7 years).

#### Error Handling

| Error | Strategy | Fallback |
|-------|----------|----------|
| Database write failure | Buffer in memory (max 1000 entries), retry | If buffer full, block request (audit is non-optional) |
| Hash chain discontinuity detected | Alert admin, flag all entries after break | Investigation required |
| Clock drift detected | Use monotonic sequence as primary ordering | Log clock offset in metadata |
| Storage approaching capacity | Alert at 80% threshold | Enforce retention policy |

#### Dependencies

None. This is an observer that receives events from all other enterprise stages.

#### Edge Cases

- **Concurrent writes**: Use database sequence (PostgreSQL `SERIAL`) for ordering, not application-level counters. Hash chain computed after sequence assignment.
- **System restart**: On startup, verify hash chain integrity of last N entries. Log startup event with chain verification result.
- **Bulk operations**: A single API call that processes 100 evidence items produces 100 audit entries. Batch insert with single hash-chain computation.
- **Audit log of audit log access**: Auditors reading audit logs generates audit events. Prevent infinite recursion by exempting audit-read events from generating child audit events.
- **Export for legal proceedings**: Export includes hash chain verification script so opposing counsel can independently verify integrity.

---

## 5. Cross-Stage Testing Requirements

### 5.1 Reference Corpus

Every pipeline stage must pass against the reference corpus before release:

| Corpus | Description | Size | Purpose |
|--------|-------------|------|---------|
| `corpus-minimal` | Single NTFS volume, 100 USN records | 50MB E01 | Smoke test, CI pipeline |
| `corpus-standard` | Typical workstation, 500K USN records | 1GB E01 | Performance benchmark |
| `corpus-ghost` | Known deleted records, pre-computed ground truth | 500MB E01 | Ghost recovery validation |
| `corpus-carved` | Known unallocated records, pre-computed ground truth | 500MB E01 | Carving validation |
| `corpus-adversarial` | Timestomped files, anti-forensic artifacts | 1GB E01 | Triage accuracy testing |
| `corpus-edge` | Corrupt MFT, missing UsnJrnl, Bitlocker volume | 200MB E01 | Error handling validation |

### 5.2 Per-Stage Metrics

| Stage | Metric | Target |
|-------|--------|--------|
| EWF Parser | E01 open time (1GB) | <2s |
| NTFS Volume | Artifact extraction time | <1s |
| USN Journal Parser | Parse rate | >100K events/s |
| MFT Parser | Path resolution completeness | 100% |
| Ghost Recovery | Recovery rate (reference corpus) | >95% |
| Unallocated Carver | False positive rate | <1% |
| QuadLink Correlator | Correlation join time (500K events) | <3s |
| Triage Engine | Triage completion rate | >95% |
| Triage Engine | False positive rate | <5% |
| Output Formatter | All 7 formats (500K events) | <3s |
| Full Pipeline | End-to-end P95 (1GB E01) | <35s |

### 5.3 Determinism Verification

Every release must pass the determinism gate:

```bash
# Run pipeline twice on same input
katana triage --image corpus-standard.E01 --output /tmp/run1
katana triage --image corpus-standard.E01 --output /tmp/run2

# Verify identical output
sha256sum /tmp/run1/* /tmp/run2/*
# Every file pair must match
```

Non-deterministic output is a release-blocking defect. No exceptions.

---

## 6. Stage Contract Versioning

### 6.1 Version Control

Stage contracts follow semantic versioning:

| Change Type | Version Bump | Example |
|-------------|-------------|---------|
| Input/output schema change | Major | `UsnRecord` adds new field |
| Performance budget adjustment | Minor | EWF Parser budget 2s -> 3s |
| Documentation clarification | Patch | Edge case added |

Current version: **1.0.0**

### 6.2 Contract Changelog

| Version | Date | Change |
|---------|------|--------|
| 1.0.0 | 2026-03-10 | Initial pipeline stage specifications |

---

*Generated by North Star Advisor v1.6.0 for Security Ronin Katana*
*Pipeline topology: sequential_pipeline_with_parallel_inner_stages*
*Total stages: 16 (9 community + 7 enterprise)*
