# Security Ronin Katana: Handoff Protocol

> **Version**: 1.0.0 | **Generated**: 2026-03-10
> **Pipeline Model**: Sequential pipeline with parallel inner stages (9 stages, 35-second budget)
> **Language**: Rust (zero-copy where possible, owned types at stage boundaries)

Data contracts between pipeline stages, tier boundary transitions, role-based workflow handoffs, and court-readiness packaging.

---

## 1. Handoff Protocol Overview

Security Ronin Katana processes forensic evidence through a sequential pipeline with parallel inner stages. Each handoff is a typed data transfer with strict ownership semantics. Forensic integrity demands that every handoff is traceable, deterministic, and verifiable.

This document covers five handoff domains:

| Domain | Description | Tier |
|--------|-------------|------|
| **Pipeline Stage Handoffs** | Typed Rust data contracts between the 9 community parsing stages | Community |
| **Community-to-Enterprise Handoff** | CLI output ingestion into Katana Server via SQLite import or JSONL streaming | Enterprise |
| **Collection-to-Analysis Handoff** | gRPC agent evidence delivery from live endpoints to triage pipeline | Enterprise |
| **Analyst-to-Reviewer Handoff** | RBAC workflow transition between Examiner and Reviewer roles | Enterprise |
| **Tool-to-Court Handoff** | Evidence packaging for Daubert compliance and chain of custody | Both |

### Design Principles

1. **Ownership Transfer**: Each stage fully owns its output. The producing stage validates before handoff. The consuming stage never mutates received data.
2. **Fail-Fast Propagation**: Any stage detecting corruption, missing fields, or integrity violations halts the pipeline immediately. Partial results are never silently passed downstream.
3. **Hash-Chain Continuity**: SHA-256 hashes accompany every data handoff. The receiving stage verifies the hash before processing. Broken chains abort the run.
4. **Budget Enforcement**: Each stage has a time budget (total pipeline: 35 seconds). Exceeding a budget emits `BudgetExceeded` and aborts the pipeline -- no silent degradation.
5. **Provenance Tracking**: Every record carries a `RecordSource` enum (`Allocated`, `Carved`, `JournalOnly`, `Ghost`) so downstream stages know the evidentiary weight.

```
E01 DISK IMAGE
     |
     v
┌──────────┐     ┌────────────┐     ┌──────────────────────────────────────┐
│EWF Parser│────>│NTFS Volume │────>│  Parallel Inner Stages               │
│ 2s       │     │ 1s         │     │  ┌─────────────┐ ┌─────────────┐    │
└──────────┘     └────────────┘     │  │ USN Parser   │ │ MFT Parser  │    │
                                    │  │ 5s (rayon)   │ │ 5s (rayon)  │    │
                                    │  └──────┬───────┘ └──────┬──────┘    │
                                    │         │                │           │
                                    │  ┌──────┴───────┐ ┌──────┴──────┐   │
                                    │  │Ghost Recovery │ │Unalloc Carve│   │
                                    │  │ 3s           │ │ 5s (rayon)  │   │
                                    │  └──────┬───────┘ └──────┬──────┘   │
                                    └─────────┼────────────────┼──────────┘
                                              │                │
                                              v                v
                                    ┌─────────────────────────────────┐
                                    │ QuadLink Correlator  3s         │
                                    └────────────────┬────────────────┘
                                                     │
                                                     v
                                    ┌─────────────────────────────────┐
                                    │ Triage Engine  5s (rayon)       │
                                    └────────────────┬────────────────┘
                                                     │
                                                     v
                                    ┌─────────────────────────────────┐
                                    │ Output Formatter  3s            │
                                    └─────────────────────────────────┘
                                                     │
                    ┌──────┬──────┬───────┬─────┬────┴──┬──────┬──────┐
                    v      v      v       v     v       v      v      v
                  CSV   JSONL  SQLite   Body   TLN    XML   HTML   _run_stats
```

---

## 2. Pipeline Stage Handoff Contracts

### 2.1 Handoff Envelope

Every inter-stage handoff is wrapped in a typed envelope:

```rust
// src/pipeline/handoff.rs

pub trait StageHandoff {
    type Input: Validate + DeserializeOwned;
    type Output: Validate + Serialize + HashVerifiable;

    fn validate_input(&self, input: &Self::Input) -> Result<(), HandoffError>;
    fn execute(&self, input: Self::Input) -> Result<HandoffEnvelope<Self::Output>, StageError>;
}

#[derive(Serialize, Deserialize)]
pub struct HandoffEnvelope<T: Serialize> {
    pub stage_id: StageId,
    pub payload: T,
    pub sha256: [u8; 32],
    pub timestamp: DateTime<Utc>,
    pub duration_ms: u64,
    pub record_count: u64,
    pub warnings: Vec<StageWarning>,
}

pub trait HashVerifiable {
    fn compute_hash(&self) -> [u8; 32];
    fn verify(&self, expected: &[u8; 32]) -> Result<(), IntegrityError>;
}
```

### 2.2 Stage 1: EWF Parser (katana-ewf)

| Direction | Field | Type | Description |
|-----------|-------|------|-------------|
| **In** | `image_path` | `PathBuf` | Path to E01 or raw disk image |
| **In** | `image_type` | `ImageType` | Enum: `E01`, `Raw`, `VMDK` |
| **In** | `segment_paths` | `Vec<PathBuf>` | Split E01 segment files (optional) |
| **Out** | `volume_data` | `VolumeStream` | Seekable byte stream over decompressed volume |
| **Out** | `image_metadata` | `ImageMetadata` | Examiner name, case number, acquisition hash, tool version |
| **Out** | `partitions` | `Vec<Partition>` | MBR/GPT partition table entries with byte offsets |

**Edge Cases Handled Before Handoff:**
- Split E01 archives: All segments located and ordered before `volume_data` is emitted
- Compressed E01: Decompressed on-the-fly via libewf FFI; `VolumeStream` abstracts this
- Images larger than RAM: Memory-mapped I/O via `memmap2`; `VolumeStream` is lazy

**Failure Modes:**

| Error | Severity | Pipeline Action |
|-------|----------|-----------------|
| `ImageCorrupt` | Fatal | E01 header checksum mismatch. Abort with hash details. |
| `SegmentMissing` | Fatal | Split archive has gaps. Abort with segment list. |
| `UnsupportedFormat` | Fatal | Not E01/Raw/VMDK. Abort with format detection result. |

### 2.3 Stage 2: NTFS Volume (katana-ntfs)

| Direction | Field | Type | Description |
|-----------|-------|------|-------------|
| **In** | `volume_data` | `VolumeStream` | From EWF Parser |
| **In** | `partition` | `Partition` | Selected NTFS partition |
| **Out** | `mft_data` | `MftStream` | Raw $MFT byte stream with record boundaries |
| **Out** | `usnjrnl_data` | `Option<UsnJrnlStream>` | Raw $UsnJrnl:$J byte stream |
| **Out** | `logfile_data` | `Option<LogFileStream>` | Raw $LogFile byte stream |
| **Out** | `volume_info` | `VolumeInfo` | Cluster size, MFT zone, volume serial, NTFS version |
| **Out** | `unallocated_ranges` | `Vec<ByteRange>` | Unallocated cluster runs for carving |

**Edge Cases Handled Before Handoff:**
- BitLocker volumes: Detected at VBR parse. Abort with `EncryptedVolume` error (decryption out of scope).
- NTFS without UsnJrnl: `usnjrnl_data` is `None`. Downstream stages skip USN-dependent logic. Pipeline continues with MFT-only analysis.
- Sparse UsnJrnl: Sparse runs resolved into contiguous stream. Zero-filled gaps marked in stream metadata.

**Failure Modes:**

| Error | Severity | Pipeline Action |
|-------|----------|-----------------|
| `NotNtfs` | Recoverable | Skip partition, try next. |
| `MftCorrupt` | Fatal | $MFT FILE0 signature missing. Abort. |
| `NoArtifacts` | Fatal | Neither $MFT nor $UsnJrnl found. Abort with diagnostic. |

### 2.4 Stage 3: USN Journal Parser (katana-core)

| Direction | Field | Type | Description |
|-----------|-------|------|-------------|
| **In** | `usnjrnl_data` | `UsnJrnlStream` | From NTFS Volume |
| **In** | `volume_info` | `VolumeInfo` | Cluster size for offset calculations |
| **Out** | `records` | `Vec<UsnRecord>` | Parsed V2/V3/V4 records with all fields extracted |
| **Out** | `parse_stats` | `ParseStats` | Records parsed, skipped, version distribution, error count |
| **Out** | `journal_bounds` | `JournalBounds` | Earliest/latest USN, earliest/latest timestamp |

```rust
pub struct UsnRecord {
    pub mft_entry: u64,
    pub mft_sequence: u16,
    pub parent_mft_entry: u64,
    pub parent_mft_sequence: u16,
    pub usn: i64,
    pub timestamp: DateTime<Utc>,
    pub reason: UsnReason,
    pub source_info: u32,
    pub security_id: u32,
    pub file_attributes: FileAttributes,
    pub filename: String,
    pub record_version: u16,   // 2, 3, or 4
}
```

**Parallelism:** Rayon work-stealing across 64KB chunks. Each chunk is independently parseable (USN records are self-delimiting via `RecordLength`).

**Edge Cases Handled Before Handoff:**
- Mixed-version journals: V2, V3, V4 records intermixed. Each record's version field determines parse path.
- Journal wrap-around: USN monotonically increases but byte offsets wrap. `journal_bounds` tracks both.
- FILETIME epoch sentinels: Timestamps of `0x0` or `0x7FFFFFFFFFFFFFFF` normalized to `None`. Downstream stages treat `None` timestamps as "unknown time, still valid record."

**Failure Modes:**

| Error | Severity | Pipeline Action |
|-------|----------|-----------------|
| `JournalEmpty` | Degraded | Zero parseable records. Continue (ghost recovery may find evidence). |
| `CorruptionThreshold` | Warning | >10% records fail parse. Continue with valid subset, warning in report. |

### 2.5 Stage 4: MFT Parser (katana-core)

| Direction | Field | Type | Description |
|-----------|-------|------|-------------|
| **In** | `mft_data` | `MftStream` | From NTFS Volume |
| **In** | `volume_info` | `VolumeInfo` | For cluster-to-byte conversion |
| **Out** | `mft_entries` | `Vec<MftEntry>` | Parsed MFT records with $SI, $FN, $DATA attributes |
| **Out** | `path_index` | `PathIndex` | MFT reference -> full path lookup table (Rewind algorithm) |
| **Out** | `parse_stats` | `ParseStats` | Entries parsed, orphaned, resident vs non-resident |

```rust
pub struct MftEntry {
    pub entry_number: u64,
    pub sequence_number: u16,
    pub parent_entry: u64,
    pub parent_sequence: u16,
    pub filename: String,
    pub is_directory: bool,
    pub is_allocated: bool,
    pub si_created: Option<DateTime<Utc>>,
    pub si_modified: Option<DateTime<Utc>>,
    pub si_mft_modified: Option<DateTime<Utc>>,
    pub si_accessed: Option<DateTime<Utc>>,
    pub fn_created: Option<DateTime<Utc>>,
    pub fn_modified: Option<DateTime<Utc>>,
    pub fn_mft_modified: Option<DateTime<Utc>>,
    pub fn_accessed: Option<DateTime<Utc>>,
}
```

**Parallelism:** Rayon across 1024-record blocks. Path resolution (Rewind) is single-threaded post-parse (requires parent traversal).

**Validation at boundary:**
- Entry 5 (NTFS root `.`) must exist with sequence 5
- Self-referential parents (entry points to itself) detected and broken
- Entries with sequence number 0 treated as uninitialized

**Optional bypass:** If no MFT is available, this stage is skipped. The Rewind engine operates in journal-only mode, reconstructing paths solely from `RENAME_OLD_NAME`/`RENAME_NEW_NAME` pairs and `FILE_CREATE` events.

**Failure Modes:**

| Error | Severity | Pipeline Action |
|-------|----------|-----------------|
| `OrphanedEntries` | Degraded | Broken parent refs placed under `$Orphan/` synthetic path. Continue. |
| `MftTruncated` | Warning | Shorter than expected. Process available entries. |

### 2.6 Stage 5: Ghost Recovery (katana-core)

| Direction | Field | Type | Description |
|-----------|-------|------|-------------|
| **In** | `records` | `Vec<UsnRecord>` | From USN Parser |
| **In** | `mft_entries` | `Vec<MftEntry>` | From MFT Parser |
| **In** | `path_index` | `PathIndex` | From MFT Parser |
| **Out** | `ghost_records` | `Vec<GhostRecord>` | Recovered records for files no longer in MFT |
| **Out** | `recovery_stats` | `RecoveryStats` | Ghosts found, confidence distribution, recovery rate |

```rust
pub struct GhostRecord {
    pub mft_entry: u64,
    pub mft_sequence: u16,
    pub deleted_name: String,
    pub last_seen: DateTime<Utc>,
    pub current_name: Option<String>,
    pub current_sequence: Option<u16>,
    pub confidence: f64,   // 0.0-1.0
}
```

**Edge Cases Handled Before Handoff:**
- USN references to purged MFT entries: Ghost created with USN-derived metadata only. Confidence score reflects missing MFT corroboration.
- Sequence number collisions: MFT entry reuse detected via sequence number mismatch. Both original and reuse tracked.

**Target:** >95% ghost recovery rate.

### 2.7 Stage 6: Unallocated Carving (katana-core)

| Direction | Field | Type | Description |
|-----------|-------|------|-------------|
| **In** | `unallocated_ranges` | `Vec<ByteRange>` | From NTFS Volume |
| **In** | `volume_info` | `VolumeInfo` | Cluster alignment |
| **Out** | `carved_records` | `Vec<CarvedRecord>` | USN records recovered from unallocated space |
| **Out** | `carve_stats` | `CarveStats` | Bytes scanned, records carved, false positive estimate |

```rust
pub struct CarvedRecord {
    pub record: UsnRecord,
    pub disk_offset: u64,
    pub confidence: f64,   // 0.0-1.0
}
```

**Parallelism:** Rayon across unallocated ranges. Each range scanned independently for USN V2/V3 signatures.

**Failure Modes:**

| Error | Severity | Pipeline Action |
|-------|----------|-----------------|
| `NoUnallocated` | Normal | Volume fully allocated. Empty output. Continue. |
| `HighFalsePositive` | Warning | >20% suspected false positives. Warning in stats, records passed with confidence scores. |

### 2.8 Stage 7: QuadLink Correlator (katana-core)

| Direction | Field | Type | Description |
|-----------|-------|------|-------------|
| **In** | `records` | `Vec<UsnRecord>` | From USN Parser |
| **In** | `mft_entries` | `Vec<MftEntry>` | From MFT Parser |
| **In** | `ghost_records` | `Vec<GhostRecord>` | From Ghost Recovery |
| **In** | `carved_records` | `Vec<CarvedRecord>` | From Unallocated Carving |
| **In** | `path_index` | `PathIndex` | From MFT Parser |
| **Out** | `timeline` | `Vec<TimelineEvent>` | Unified, deduplicated, chronologically sorted event timeline |
| **Out** | `anomalies` | `Vec<Anomaly>` | Timestamp inconsistencies, anti-forensics indicators |
| **Out** | `correlation_stats` | `CorrelationStats` | Events correlated, dedup rate, anomaly count |

```rust
pub struct TimelineEvent {
    pub record: ResolvedRecord,
    pub sources: Vec<RecordSource>,   // Provenance: which artifacts confirmed this event
    pub anomaly_flags: AnomalyFlags,  // Timestomping, clock skew, etc.
}

pub struct ResolvedRecord {
    pub record: UsnRecord,
    pub full_path: String,
    pub parent_path: String,
    pub source: RecordSource,
}

pub enum RecordSource {
    Allocated,    // From active $UsnJrnl:$J stream
    Carved,       // From unallocated space
    JournalOnly,  // Path resolved from journal rename chains (no MFT)
    Ghost,        // MFT entry was reallocated, path reconstructed via Rewind
}
```

**Provenance Semantics:**

| Source | Evidentiary Weight | Meaning |
|--------|-------------------|---------|
| `Allocated` | High | Record from active journal, path confirmed by current MFT |
| `JournalOnly` | Medium | Path resolved from journal rename chains only (no MFT) |
| `Ghost` | Medium-Low | MFT entry was reallocated; path reconstructed from historical journal state |
| `Carved` | Low | Record recovered from unallocated space; may be incomplete or from prior volume |

**Correlation Logic:**
- USN + MFT: Match by MFT reference number + sequence number
- USN + Ghost: Match by MFT reference where MFT entry is missing/reallocated
- USN + Carved: Match by file reference, timestamp proximity (within 1 second), and reason code
- Cross-source deduplication: Same event from multiple sources collapsed into single `TimelineEvent` with provenance array

**Failure Modes:**

| Error | Severity | Pipeline Action |
|-------|----------|-----------------|
| `TimelineEmpty` | Fatal | No events after correlation. Abort (no evidence to triage). |
| `ClockSkew` | Warning | >1 hour gap between artifact timestamps. Continue with skew annotation. |

### 2.9 Stage 8: Triage Engine (katana-core)

| Direction | Field | Type | Description |
|-----------|-------|------|-------------|
| **In** | `timeline` | `Vec<TimelineEvent>` | From QuadLink Correlator |
| **In** | `anomalies` | `Vec<Anomaly>` | From QuadLink Correlator |
| **In** | `correlation_stats` | `CorrelationStats` | From QuadLink Correlator |
| **In** | `custom_rules` | `Vec<TriageRule>` | YAML-loaded custom detection rules (optional) |
| **Out** | `answers` | `Vec<TriageAnswer>` | Responses to 12 automated IR questions |
| **Out** | `triage_summary` | `TriageSummary` | Overall risk assessment, key findings, evidence citations |

```rust
pub struct TriageAnswer {
    pub question_id: &'static str,
    pub category: &'static str,
    pub question: &'static str,
    pub has_hits: bool,
    pub hit_count: usize,
    pub confidence: f64,              // 0.0-1.0
    pub evidence: Vec<EvidenceRef>,   // References to specific TimelineEvents
    pub explanation: String,          // Human-readable answer
}

pub struct TriageQuery {
    pub path_patterns: Vec<&'static str>,
    pub extension_filter: Vec<&'static str>,
    pub reasons: Option<UsnReason>,
    pub exclude_patterns: Vec<&'static str>,
    pub filename_filter: Vec<&'static str>,
    pub source_filter: Vec<&'static str>,
}
```

**Quality Targets:**
- Completion rate: >95% of questions answered (not "insufficient evidence")
- False positive rate: <5%
- Time budget: 5 seconds

**Failure Modes:**

| Error | Severity | Pipeline Action |
|-------|----------|-----------------|
| `NoAnswers` | Degraded | Zero questions answered. Continue to output (empty triage section). |
| `RuleParseError` | Warning | Malformed custom YAML rule skipped. Built-in rules unaffected. |

### 2.10 Stage 9: Output Formatter (katana-formats)

| Direction | Field | Type | Description |
|-----------|-------|------|-------------|
| **In** | `timeline` | `Vec<TimelineEvent>` | From QuadLink Correlator |
| **In** | `triage_answers` | `Vec<TriageAnswer>` | From Triage Engine |
| **In** | `triage_summary` | `TriageSummary` | From Triage Engine |
| **In** | `parse_stats` | `AggregateStats` | Merged stats from all stages |
| **In** | `output_config` | `OutputConfig` | Requested formats, paths, options |
| **Out** | `generated_files` | `Vec<GeneratedFile>` | Paths and sizes of generated output files |
| **Out** | `format_stats` | `FormatStats` | Records written per format, file sizes, duration |

**Supported Formats:**

| Format | Extension | Target Tool | Handoff Contract |
|--------|-----------|-------------|------------------|
| CSV | `.csv` | Timeline Explorer | Header row, comma-separated, quoted when needed, MFTECmd column ordering |
| JSONL | `.jsonl` | Velociraptor, SIEM | One valid JSON object per line, snake_case fields, no array wrapper |
| SQLite | `.db` | Custom SQL, pandas | WAL mode, batch transactions (1000/tx), indexes after bulk insert |
| Body | `.body` | Sleuthkit mactime | Pipe-delimited, no header, 11 fields per line |
| TLN | `.tln` | Supertimelines | 5-field pipe-delimited, epoch seconds |
| XML | `.xml` | DFXML, XSLT | UTF-8 with declaration, streaming write, XML-escaped |
| HTML | `.html` | Browser triage | Self-contained (CSS/JS inlined), zero external dependencies |

**Integrity:** Every output file includes a version header (`Katana vX.Y.Z`), generation timestamp, and SHA-256 hash of the content body appended as a trailer or metadata field.

**Edge Cases:**
- Timelines >1M events: CSV and JSONL stream to disk without holding full dataset in memory
- Unicode CSV: BOM-prefixed UTF-8 for Excel compatibility
- Air-gapped HTML: All CSS/JS inlined, zero external dependencies, deterministic output (no random IDs)

### 2.11 State Ownership Model

Stages do not share mutable state. Each stage receives owned or borrowed data from the previous stage and produces new owned data:

```
main() orchestrates:
  volume_data: VolumeStream          -- owned by main, consumed by NTFS stage
  usnjrnl_data: UsnJrnlStream       -- owned by main, consumed by USN parser
  records: Vec<UsnRecord>            -- owned by main, borrowed by downstream
  mft_entries: Vec<MftEntry>         -- owned by main, borrowed by downstream
  path_index: PathIndex              -- owned by main, borrowed by downstream
  ghost_records: Vec<GhostRecord>    -- owned by main, borrowed by correlator
  carved_records: Vec<CarvedRecord>  -- owned by main, borrowed by correlator
  timeline: Vec<TimelineEvent>       -- owned by main, borrowed by triage + output
  triage_answers: Vec<TriageAnswer>  -- owned by main, borrowed by output
```

No contention, no locking, no shared mutable state. The `main()` function is the pipeline orchestrator.

---

## 3. Community-to-Enterprise Handoff

The community CLI produces local output files. The enterprise tier (Katana Server) ingests these files to enable multi-user collaboration, RBAC, and cross-device correlation.

### 3.1 SQLite Import Protocol

```
Community CLI                       Katana Server (axum)
─────────────                       ────────────────────
katana-output.db ─────────────────> POST /api/v1/cases/{case_id}/import
  with _meta table                    │
  with content_hash                   ├─ Validate schema version
                                      ├─ Verify SHA-256 (content_hash vs computed)
                                      ├─ Import into tenant-isolated DuckDB schema
                                      ├─ Record provenance (filename, timestamp, user, device)
                                      └─ Mark imported data as immutable
```

**Import Steps:**

1. CLI generates `katana-output.db` with standardized schema and a `_meta` table containing schema version and `content_hash`
2. Analyst uploads via REST: `POST /api/v1/cases/{case_id}/import` (multipart/form-data)
3. Server validates schema version against compatibility matrix
4. Server computes SHA-256 of the uploaded database body and compares against `_meta.content_hash`
5. Hash mismatch: reject with `IntegrityViolation` (HTTP 422) -- file was modified in transit
6. Server imports records into tenant-isolated DuckDB (schema-per-tenant isolation, FT-06 mitigation)
7. Provenance recorded: original filename, import timestamp, importing user ID, source device hostname
8. Imported data is immutable. Analyst annotations and findings stored in separate tables linked by event ID.

### 3.2 JSONL Streaming Protocol

For real-time ingestion from collection agents or large datasets:

```
Collection Agent / CLI              Katana Server (tonic gRPC)
──────────────────────              ──────────────────────────
JSONL record stream ──────────────> StreamIngest (bidirectional)
  per-batch SHA-256   <────────────   batch ACK (count + running hash)
  final hash          <────────────   final ACK or IntegrityViolation
```

1. gRPC `StreamIngest` accepts a bidirectional stream of JSONL record batches
2. Server acknowledges each batch with record count and running hash
3. On stream completion, server computes final hash and compares with client-reported hash
4. Hash mismatch: entire stream rejected, no partial import

### 3.3 Schema Version Compatibility

| CLI Version | Server Version | Compatible | Action |
|-------------|---------------|------------|--------|
| 0.6.x | 1.0.x | Yes | Auto-migrate on import (new columns added with defaults) |
| 0.5.x | 1.0.x | Yes | Schema upgrade applied (additive changes only) |
| 0.4.x | 1.0.x | No | Reject with `SchemaIncompatible`, CLI upgrade required |

Forward-compatible changes (new columns, new tables) are auto-migrated. Breaking changes (removed columns, type changes) require CLI upgrade.

---

## 4. Collection-to-Analysis Handoff

Enterprise collection agents deployed on Windows endpoints collect live forensic artifacts and stream them to Katana Server for triage.

### 4.1 Architecture

```
Windows Endpoint                     Katana Server
┌──────────────────────┐             ┌──────────────────────┐
│  Katana Agent (<5MB) │             │  gRPC Server (tonic)  │
│  Cold start: <50ms   │             │                      │
│  ┌────────────────┐  │   mTLS     │  ┌────────────────┐  │
│  │ Collector      │──┼───────────>┼──│ Task Dispatcher │  │
│  │ Engine         │  │  HTTP/2    │  └───────┬────────┘  │
│  ├────────────────┤  │  cert pin  │  ┌───────┴────────┐  │
│  │ NTFS/USN       │  │           │  │ Pipeline       │  │
│  │ Parser         │  │           │  │ Runner         │  │
│  └────────────────┘  │           │  └───────┬────────┘  │
└──────────────────────┘           │  ┌───────┴────────┐  │
                                    │  │ DuckDB Store   │  │
                                    │  │ (tenant-iso)   │  │
                                    │  └────────────────┘  │
                                    └──────────────────────┘
```

### 4.2 gRPC Collection Contract

```protobuf
// proto/collection.proto

service CollectionService {
  // Server dispatches collection task to agent
  rpc DispatchTask(TaskRequest) returns (TaskAck);

  // Agent streams collected artifacts back
  rpc StreamArtifacts(stream ArtifactChunk) returns (CollectionResult);

  // Agent reports health and capabilities
  rpc Heartbeat(AgentStatus) returns (HeartbeatAck);
}

message TaskRequest {
  string task_id = 1;
  string case_id = 2;
  repeated ArtifactType requested_artifacts = 3;  // USN_JOURNAL, MFT, LOGFILE, REGISTRY
  uint64 max_bytes = 4;           // Collection size limit
  uint32 timeout_seconds = 5;     // Agent-side timeout
  bytes server_cert_hash = 6;     // Certificate pinning verification
}

message ArtifactChunk {
  string task_id = 1;
  ArtifactType artifact_type = 2;
  uint64 offset = 3;
  bytes data = 4;
  bytes chunk_sha256 = 5;         // Per-chunk integrity
  bool is_final = 6;
}

message CollectionResult {
  string task_id = 1;
  bool success = 2;
  repeated ArtifactManifest artifacts = 3;
  bytes collection_sha256 = 4;    // Hash of entire collection
  ChainOfCustodyEntry custody = 5; // Auto-generated CoC entry
}
```

### 4.3 Handoff to Pipeline

Once artifacts are collected and verified:

1. Server writes artifacts to case-isolated temporary storage (encrypted at rest, AES-256-GCM)
2. Server creates `PipelineInput` from collected artifacts (same struct the CLI uses)
3. Server spawns pipeline run in background task with tenant isolation
4. Pipeline stages execute identically to CLI mode (same crates, same code paths)
5. Results written to tenant DuckDB schema
6. WebSocket notification sent to connected analysts: `case.analysis.complete`

### 4.4 Security Constraints

| Constraint | Implementation | Threat Mitigated |
|------------|----------------|------------------|
| mTLS authentication | tonic + rustls, certificate pinning | FT-02: Agent Weaponization |
| Agent binary signing | Code-signed binary; server rejects unsigned | FT-02: Agent Weaponization |
| Unidirectional data flow | Agent can only stream data, never query or modify server | FT-02: Assume Breach (Axiom 5) |
| Encrypted at rest | AES-256-GCM for collected artifacts before pipeline ingestion | FT-01: Evidence Tampering |
| Tenant isolation | Schema-per-tenant in DuckDB, tenant ID in Tower middleware | FT-06: Multi-Tenant Data Leak |

---

## 5. Analyst-to-Reviewer Handoff

Enterprise workflow supports formal finding review before case closure or court submission.

### 5.1 RBAC Role Hierarchy

```
System Admin ─── Full system config, user management, audit access
    │
Case Manager ─── Create/close cases, assign examiners, review reports
    │
    ├── Examiner ─── Collect, analyze, annotate, create findings
    │
    ├── Reviewer ─── Read-only case data, approve/reject findings
    │
    └── Auditor ──── Read-only audit trail, no case data modification
```

**Two-person integrity:** The Examiner and Reviewer for a case must be different users. The system enforces this at assignment time.

### 5.2 Workflow State Machine

```
┌──────────┐     assign       ┌─────────────┐     submit     ┌─────────────┐
│  Created  │───────────────>│  Examining   │──────────────>│  In Review  │
└──────────┘  Case Manager   └─────────────┘   Examiner    └──────┬──────┘
                                                                    │
                                                       ┌────────────┼────────────┐
                                                       │ reject     │            │ approve
                                                       v            │            v
                                                ┌──────────┐       │     ┌──────────┐
                                                │  Rework   │       │     │ Approved │
                                                └─────┬────┘       │     └─────┬────┘
                                                      │ resubmit   │           │ close
                                                      └────────────┘           v
                                                                         ┌──────────┐
                                                                         │  Closed  │
                                                                         └──────────┘
```

### 5.3 Review Handoff Contract

When an Examiner submits findings for review:

```rust
pub struct ReviewHandoff {
    pub case_id: CaseId,
    pub examiner_id: UserId,
    pub submitted_at: DateTime<Utc>,
    pub findings: Vec<Finding>,
    pub annotations: Vec<Annotation>,
    pub evidence_refs: Vec<EvidenceRef>,       // Links to specific timeline events
    pub triage_overrides: Vec<TriageOverride>,  // Where examiner disagreed with automated triage
    pub narrative: String,                      // Free-text analysis narrative
    pub hash: [u8; 32],                         // SHA-256 of findings + annotations + narrative
}

pub struct ReviewDecision {
    pub case_id: CaseId,
    pub reviewer_id: UserId,
    pub decided_at: DateTime<Utc>,
    pub decision: ReviewOutcome,   // Approved, Rejected, NeedsRework
    pub comments: Vec<ReviewComment>,
    pub disputed_findings: Vec<FindingDispute>,
}
```

### 5.4 Reviewer Constraints

- Reviewers have read-only access to all case evidence and findings
- Reviewers cannot modify findings -- they approve, reject, or comment only
- Rejected findings return to the original Examiner with reviewer comments attached
- Review decisions are append-only -- a reviewer cannot retract a decision (they issue a new superseding decision)
- Every state transition generates an immutable entry in the hash-chain append-only audit log (FT-10 mitigation)

---

## 6. Tool-to-Court Handoff

Forensic output must be defensible in legal proceedings. This section defines how Katana output is packaged for Daubert compliance and chain of custody documentation.

### 6.1 Daubert Compliance Package

Katana maintains a standing Daubert compliance package at `docs/daubert/` satisfying the five Daubert factors:

| Daubert Factor | Katana Evidence |
|----------------|-----------------|
| **Testable methodology** | Open-source parsing code (Apache-2.0); deterministic output from identical input; public test corpus with expected results |
| **Peer review** | Published precision/recall benchmarks per release; community code review on GitHub; public issue tracker |
| **Known error rate** | Precision/recall tables per triage question per release at `docs/daubert/precision_recall.html`; false positive rate <5% target with measured actuals |
| **Standards compliance** | NTFS specification adherence; USN Journal V2/V3/V4 format compliance; DFXML output compatibility; Sleuthkit bodyfile interop |
| **General acceptance** | Open-source adoption metrics; practitioner testimonials; DFIR conference presentations; Velociraptor/KAPE integration ecosystem |

### 6.2 Chain of Custody Record

Every pipeline run generates a Chain of Custody (CoC) record:

```rust
pub struct ChainOfCustody {
    pub case_id: String,
    pub evidence_id: String,
    pub run_id: Uuid,

    // Source identification
    pub image_path: String,
    pub image_sha256: [u8; 32],
    pub image_metadata: ImageMetadata,  // Examiner, case number from E01 header

    // Processing record
    pub tool_version: String,           // "Katana v0.6.0"
    pub tool_sha256: [u8; 32],          // Hash of the katana binary itself
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub host_info: HostInfo,            // OS, hostname, user running the tool

    // Output verification
    pub output_files: Vec<OutputFileRecord>,
    pub pipeline_hash: [u8; 32],        // Hash of all stage hashes chained together

    // Reproducibility
    pub command_line: String,           // Exact CLI invocation
    pub config_hash: [u8; 32],          // Hash of any config/rule files used
    pub environment: HashMap<String, String>,
}

pub struct OutputFileRecord {
    pub path: String,
    pub format: OutputFormat,
    pub sha256: [u8; 32],
    pub record_count: u64,
    pub file_size_bytes: u64,
}
```

### 6.3 Court-Ready Report Format

The HTML output format serves as the primary court submission artifact:

1. **Cover Page**: Case ID, evidence ID, examiner name, examination date, tool version
2. **Chain of Custody**: Full CoC record as formatted table
3. **Executive Summary**: Triage answers in plain language, key findings highlighted
4. **Timeline Visualization**: Chronological event display with source attribution (USN/MFT/Ghost/Carved)
5. **Detailed Findings**: Per-question evidence with direct citations to timeline events
6. **Methodology**: Link to Daubert package, explanation of each pipeline stage
7. **Integrity Verification**: All hashes, how to reproduce the analysis
8. **Appendix**: Full event listing (collapsible), parse statistics, warnings

**Formatting Requirements:**
- Air-gapped: All CSS and JavaScript inlined; zero external resources
- Printable: CSS `@media print` rules for clean paper output
- Accessible: Semantic HTML, alt text on diagrams, screen-reader compatible
- Deterministic: Same input produces byte-identical HTML (no random IDs, no current-time injection beyond the documented run timestamp)

### 6.4 Expert Witness Support Artifacts

| Artifact | Location | Purpose |
|----------|----------|---------|
| Daubert package | `docs/daubert/` | Pre-prepared methodology defense |
| Precision/recall report | `docs/daubert/precision_recall.html` | Error rate documentation |
| Source code | Public GitHub repository (Apache-2.0) | Methodology transparency |
| Test corpus results | `docs/daubert/test_corpus/` | Reproducibility evidence |
| Release notes | `CHANGELOG.md` | Version-specific behavior documentation |
| Chain of custody record | Generated per-run | Evidence handling documentation |
| Binary hash | Published per-release | Tool integrity verification |

---

## 7. Error Propagation Protocol

### 7.1 Error Categories

```rust
pub enum HandoffError {
    // Fatal: pipeline stops immediately
    IntegrityViolation { stage: StageId, expected_hash: String, actual_hash: String },
    InputCorrupt { stage: StageId, detail: String },
    BudgetExceeded { stage: StageId, budget_ms: u64, actual_ms: u64 },

    // Degraded: pipeline continues with warnings
    PartialData { stage: StageId, records_ok: u64, records_failed: u64 },
    OptionalMissing { stage: StageId, field: String },

    // Recoverable: stage retries internally
    TransientIo { stage: StageId, path: String, retries: u32 },
}
```

### 7.2 Propagation Rules

| Error Type | Propagation | Pipeline State |
|------------|-------------|----------------|
| `IntegrityViolation` | Immediate abort | All prior stage outputs preserved; run marked `failed` |
| `InputCorrupt` | Immediate abort | Error includes diagnostic for root cause |
| `BudgetExceeded` | Immediate abort | Partial output from timed-out stage discarded |
| `PartialData` | Continue with warning | Downstream stages receive valid subset; warning in final report |
| `OptionalMissing` | Continue silently | Stage proceeds without optional field |
| `TransientIo` | Retry 3x with exponential backoff | After 3 failures, promotes to `InputCorrupt` |

### 7.3 Error Context Chain

Every error carries the full stage chain for forensic analysis of pipeline failures:

```rust
pub struct ErrorContext {
    pub originating_stage: StageId,
    pub stage_chain: Vec<StageId>,        // e.g., [ewf_parser, ntfs_volume, usn_parser]
    pub input_hashes: Vec<[u8; 32]>,      // Hash of input to each stage in chain
    pub timestamps: Vec<DateTime<Utc>>,   // When each stage started
    pub partial_outputs: Option<PathBuf>,  // Path to salvaged partial output
}
```

### 7.4 Error Recovery Strategies

| Failure | Recovery | Trade-off |
|---------|----------|-----------|
| MFT not provided | Skip MFT stage, use JournalOnly source | Paths may be incomplete |
| MFT corrupt | Log warning, continue without MFT | Same as above |
| MFTMirr mismatch | Log count of mismatches, continue | Analyst should investigate |
| LogFile gaps | Log gap time ranges, continue | Missing events in gap period |
| Rewind path unresolvable | Use `UNKNOWN\<filename>` | Record still emitted with degraded path |
| Output file not writable | Abort that format with context error | Other formats still written if independent |
| No NTFS partition | Abort with "No NTFS partition found" | Cannot proceed |
| Carved record low confidence | Include with `source: "carved"` | Analyst filters by source |
| Parallel parse chunk boundary | Records spanning chunks re-parsed | Slight performance cost, zero data loss |

---

## 8. Observability

### 8.1 Community Tier: Run Stats

Community CLI outputs a `_run_stats.json` alongside other output files:

```json
{
  "version": "0.6.0",
  "total_seconds": 28.4,
  "stages": [
    {"id": "ewf_parser", "duration_ms": 1200, "records_in": 0, "records_out": 1, "warnings": 0},
    {"id": "ntfs_volume", "duration_ms": 800, "records_in": 1, "records_out": 5, "warnings": 0},
    {"id": "usn_parser", "duration_ms": 4200, "records_in": 1, "records_out": 847293, "warnings": 12},
    {"id": "mft_parser", "duration_ms": 3800, "records_in": 1, "records_out": 234891, "warnings": 3},
    {"id": "ghost_recovery", "duration_ms": 2100, "records_in": 847293, "records_out": 1247, "warnings": 0},
    {"id": "unallocated_carver", "duration_ms": 4800, "records_in": 1, "records_out": 389, "warnings": 2},
    {"id": "quadlink_correlator", "duration_ms": 2900, "records_in": 1083820, "records_out": 891204, "warnings": 1},
    {"id": "triage_engine", "duration_ms": 4100, "records_in": 891204, "records_out": 12, "warnings": 0},
    {"id": "output_formatter", "duration_ms": 2800, "records_in": 891204, "records_out": 7, "warnings": 0}
  ],
  "integrity": {
    "pipeline_hash": "a3f8c2...",
    "all_checks_passed": true
  }
}
```

### 8.2 Enterprise Tier: OpenTelemetry

Enterprise server exposes OpenTelemetry-compatible traces:

| Telemetry | Scope | Details |
|-----------|-------|---------|
| Root span | Pipeline run | `katana.pipeline.run` with `case_id`, `image_type`, `outcome` |
| Child spans | Per stage | `stage.id`, `stage.records_in`, `stage.records_out`, `stage.budget_ms`, `stage.actual_ms` |
| Span events | Handoff verification | Hash check results at each stage boundary |
| Separate traces | Collection agent ops | Linked by `case_id` and `task_id` |

### 8.3 Pipeline Metrics

| Metric | Type | Labels |
|--------|------|--------|
| `katana_stage_duration_seconds` | Histogram | `stage_id`, `outcome` |
| `katana_stage_records_processed` | Counter | `stage_id` |
| `katana_stage_records_skipped` | Counter | `stage_id`, `reason` |
| `katana_handoff_bytes` | Histogram | `source_stage`, `target_stage` |
| `katana_pipeline_total_seconds` | Histogram | `image_type`, `outcome` |
| `katana_integrity_checks` | Counter | `stage_id`, `result` (pass/fail) |

### 8.4 Alerting Thresholds

| Condition | Severity | Action |
|-----------|----------|--------|
| Stage exceeds 80% of time budget | Warning | Log for capacity planning |
| Stage exceeds 100% of time budget | Critical | Pipeline abort, operator notification |
| Integrity check failure | Critical | Pipeline abort, security alert, case flagged |
| >10% parse errors in any stage | Warning | Continue but flag in report |
| Collection agent heartbeat missed (>60s) | Warning | Retry connection |
| Collection agent heartbeat missed (>300s) | Critical | Mark agent offline, alert operator |
| Review pending >48 hours | Warning | Notify Case Manager |

---

## 9. Integration Handoffs

### 9.1 KAPE Module Input

```
Executable: katana.exe
CommandLine: --image %sourceDirectory% --csv %destinationDirectory%\usnjrnl.csv
             --sqlite %destinationDirectory%\usnjrnl.db
             --report %destinationDirectory%\usnjrnl_triage.html
ExportFormat: csv,sqlite,html
```

- KAPE provides `%sourceDirectory%` (collected artifacts) and `%destinationDirectory%` (output location)
- Exit code 0 = success, non-zero = failure (KAPE checks exit code)
- Stderr progress messages captured by KAPE's log

### 9.2 Velociraptor VQL Artifact

```sql
LET results = SELECT * FROM parse_jsonl(
    filename=tempfile(
        extension=".jsonl",
        data=shell(argv=[
            "katana", "--image", ImagePath, "--jsonl", "/dev/stdout"
        ])
    )
)
SELECT timestamp, full_path, reason, source, entry_number
FROM results
WHERE reason =~ "FILE_CREATE" AND full_path =~ "Users.*Downloads"
```

- JSONL to stdout (`--jsonl /dev/stdout`) for direct pipe to Velociraptor
- Field names match Velociraptor column conventions (snake_case)
- No binary data in output (all fields are strings or numbers)

### 9.3 Sleuthkit / Plaso Integration

```bash
# mactime timeline generation
katana --image evidence.E01 --body /tmp/usn.body
mactime -b /tmp/usn.body -d > timeline.csv

# log2timeline/plaso integration
katana --image evidence.E01 --body /tmp/usn.body
log2timeline.py --parsers bodyfile plaso.dump /tmp/usn.body
psort.py -o l2tcsv plaso.dump > supertimeline.csv
```

---

## Validation Schema

```yaml
handoff_protocol_version: "1.0.0"

inputs_required:
  - arch.pipeline_topology: from_architecture_blueprint
  - arch.enterprise_services: from_architecture_blueprint
  - agent_prompts.stage_contracts: from_agent_prompts

outputs_produced:
  - handoff.pipeline_contracts: 9 stage input/output contracts
  - handoff.community_enterprise: SQLite + JSONL ingestion protocols
  - handoff.collection_analysis: gRPC protobuf contract
  - handoff.analyst_reviewer: RBAC workflow state machine
  - handoff.tool_court: Daubert package + CoC record
  - handoff.error_protocol: Error categories + propagation rules
  - handoff.observability: Metrics + alerting thresholds

validation_gate:
  required_sections:
    - "Handoff Protocol Overview"
    - "Pipeline Stage Handoff Contracts"
    - "Community-to-Enterprise Handoff"
    - "Collection-to-Analysis Handoff"
    - "Analyst-to-Reviewer Handoff"
    - "Tool-to-Court Handoff"
    - "Error Propagation Protocol"
    - "Observability"
    - "Integration Handoffs"

  minimum_content:
    pipeline_stage_contracts: 9
    enterprise_handoff_protocols: 3
    error_recovery_strategies: 9
    integration_handoffs: 3
    output_formats: 7

cross_references:
  - pipeline_stages: must_match: arch.pipeline_topology.stages
  - rbac_roles: must_match: security.rbac_roles
  - enterprise_services: must_match: arch.enterprise_services
  - daubert_compliance: must_match: security.daubert_compliance
  - time_budgets: must_align_with: arch.latency_budget (35s total)

quality_checks:
  - integrity_verification: sha256_at_every_boundary
  - provenance_tracking: RecordSource_enum_propagated
  - error_context_chains: full_stage_chain_in_errors
  - deterministic_output: same_input_same_output
```

**Verification:**
- [x] All 9 community pipeline stages have typed input/output contracts with Rust struct definitions
- [x] Edge cases documented per stage with specific failure modes and severity
- [x] Community-to-Enterprise ingestion protocol defined (SQLite import + JSONL streaming)
- [x] Collection agent gRPC contract specified with protobuf schema
- [x] RBAC workflow state machine documented with role constraints
- [x] Chain of custody record structure defined with all required fields
- [x] Daubert compliance package mapped to all five factors
- [x] Court-ready HTML report format specified with 8 sections
- [x] Error propagation rules with category-specific handling (fatal/degraded/recoverable)
- [x] Observability metrics defined for both community (_run_stats.json) and enterprise (OpenTelemetry)
- [x] Alerting thresholds set with severity levels
- [x] SHA-256 hash-chain integrity enforced at every handoff boundary
- [x] Three integration handoffs documented (KAPE, Velociraptor, Sleuthkit/Plaso)
