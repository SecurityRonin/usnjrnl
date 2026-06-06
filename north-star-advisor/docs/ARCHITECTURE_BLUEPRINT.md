# Security Ronin Katana: Architecture Blueprint

> **North Star Metric**: Number of Paying Enterprise Customers (50 within 12 months of enterprise launch)
>
> **Performance Budget**: P95 triage completion in <35 seconds for 1GB E01 image
>
> **Core Axiom**: Forensic Integrity > Feature Velocity

---

## Document Structure

This architecture blueprint is modularized for maintainability. The core document contains:
- Executive Summary and Pipeline Topology
- Technology Stack
- Enterprise Extensions
- Deployment Checklist
- Appendices

Detailed implementation specifications are in `north-star-advisor/docs/architecture/`:

| Document | Content |
|----------|---------|
| [PIPELINE_ORCHESTRATION.md](architecture/PIPELINE_ORCHESTRATION.md) | Pipeline stages, state schema, execution flow, error recovery |
| [RESILIENCE_PATTERNS.md](architecture/RESILIENCE_PATTERNS.md) | Fallback chains, timeout handling, graceful degradation |
| [AGENT_PROMPTS.md](architecture/AGENT_PROMPTS.md) | Pipeline stage contracts with inputs, outputs, and invariants |
| [IMPLEMENTATION_SCAFFOLD.md](architecture/IMPLEMENTATION_SCAFFOLD.md) | Cargo workspace structure, crate boundaries, trait definitions |
| [OBSERVABILITY.md](architecture/OBSERVABILITY.md) | Tracing infrastructure, performance counters, North Star instrumentation |
| [TESTING_STRATEGY.md](architecture/TESTING_STRATEGY.md) | Test categories, golden datasets, forensic correctness verification |
| [HANDOFF_PROTOCOL.md](architecture/HANDOFF_PROTOCOL.md) | Data flow contracts between pipeline stages |

---

## Executive Summary

Security Ronin Katana is a two-tier DFIR forensic triage system built in Rust. The community tier (`katana`) is a single-binary CLI that processes E01 disk images through a sequential forensic pipeline, delivering incident response answers in under 35 seconds. The enterprise tier (`katana-pro`) extends this core with multi-device correlation, team collaboration, collection agents, and PCAP/NetFlow analysis via a client-server architecture.

The system is NOT an AI/ML agent platform. It is a deterministic forensic data processing pipeline where every output must be reproducible, verifiable, and court-admissible under Daubert standards.

### Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Language | Rust 2021 edition | Zero-cost abstractions, static binaries, memory safety without GC pauses (Velociraptor's Go GC is a known bottleneck) |
| Open-core model | Two repos, trait-based extension | Clean Apache-2.0/proprietary license separation; enterprise implements shared traits |
| Community pipeline | Sequential with Rayon parallelism | Parse > Correlate > Triage > Report; parallel within stages, sequential between stages |
| Enterprise comms | gRPC via tonic + mTLS | Bidirectional streaming for evidence upload, mutual TLS for assume-breach posture |
| Storage (community) | SQLite via rusqlite | Embedded, zero-config, fits 35-second budget |
| Storage (enterprise) | PostgreSQL + tantivy | Scalable relational store + Rust-native full-text search |
| Correlation | Batch (community) / streaming (enterprise) | Community: single-device, all-in-memory; Enterprise: multi-device, incremental |
| Orchestration pattern | Sequential pipeline with parallel inner stages | Not a supervisor-worker or pub/sub system -- deterministic forensic pipeline |

---

## 1. Pipeline Topology

### 1.1 Community Tier: Forensic Triage Pipeline

```
                     +-----------------+
                     |   E01 / Raw     |
                     |   Disk Image    |
                     +--------+--------+
                              |
                     +--------v--------+
                     |  EWF Parser     |  (katana-ewf)
                     |  Image mount,   |
                     |  memory-mapped   |
                     +--------+--------+
                              |
                     +--------v--------+
                     |  NTFS Volume    |  (katana-ntfs)
                     |  Volume detect, |
                     |  partition walk  |
                     +--------+--------+
                              |
              +---------------+---------------+
              |                               |
    +---------v---------+           +---------v---------+
    |  USN Journal      |           |  MFT Parser       |
    |  Parser           |           |  (katana-core)    |
    |  (katana-core)    |           |  File metadata,   |
    |  Change records,  |           |  path resolution  |
    |  timestamps       |           |                   |
    +---------+---------+           +---------+---------+
              |                               |
    +---------v---------+                     |
    |  Ghost Recovery   |                     |
    |  (katana-core)    |                     |
    |  Deleted record   |                     |
    |  reconstruction   |                     |
    +---------+---------+                     |
              |                               |
    +---------v---------+                     |
    |  Unallocated      |                     |
    |  Carving          |                     |
    |  (katana-core)    |                     |
    |  Deep recovery    |                     |
    +---------+---------+                     |
              |                               |
              +---------------+---------------+
                              |
                     +--------v--------+
                     |  QuadLink       |
                     |  Correlator     |
                     |  (katana-core)  |
                     |  Cross-source   |
                     |  event linking  |
                     +--------+--------+
                              |
                     +--------v--------+
                     |  Triage Engine  |
                     |  (katana-core)  |
                     |  12 IR questions|
                     |  scored answers |
                     +--------+--------+
                              |
                     +--------v--------+
                     |  Output         |
                     |  Formatter      |
                     |  (katana-formats)|
                     |  7 formats      |
                     +--------+--------+
                              |
                     +--------v--------+
                     |  Triage Report  |
                     |  JSON/CSV/JSONL |
                     |  XML/TLN/HTML   |
                     |  SQLite         |
                     +-----------------+
```

### 1.2 Pipeline Stage Specifications

| Stage | Crate | Input | Output | Parallelism | Budget |
|-------|-------|-------|--------|-------------|--------|
| EWF Parser | `katana-ewf` | E01/raw image path | Memory-mapped evidence buffer | Single-threaded (sequential I/O) | ~2s |
| NTFS Volume | `katana-ntfs` | Evidence buffer | Volume handle, partition table | Single-threaded | <1s |
| USN Journal Parser | `katana-core` | Volume handle | `Vec<UsnRecord>` with timestamps, reasons, filenames | Rayon parallel chunks | ~5s |
| MFT Parser | `katana-core` | Volume handle | `Vec<MftEntry>` with paths, metadata, timestamps | Rayon parallel chunks | ~5s |
| Ghost Recovery | `katana-core` | USN records + MFT entries | Recovered deleted records with confidence scores | Single-threaded (sequential scan) | ~3s |
| Unallocated Carving | `katana-core` | Evidence buffer + known record offsets | Carved USN records from unallocated space | Rayon parallel regions | ~5s |
| QuadLink Correlator | `katana-core` | USN records + MFT entries + ghost/carved records | Correlated timeline events with path resolution | Single-threaded (hash-join) | ~3s |
| Triage Engine | `katana-core` | Correlated events | `Vec<TriageAnswer>` for 12 IR questions | Rayon parallel per-question | ~5s |
| Output Formatter | `katana-formats` | Triage answers + raw events | Formatted report files | Single-threaded (I/O bound) | ~3s |

**Total budget**: ~32s (with ~3s margin under 35s P95 target)

### 1.3 Stage Contracts (Trait-Based Extension)

The `katana-core` crate defines three extension traits that enable the open-core architecture:

```rust
// katana-core/src/traits.rs (Apache-2.0)

/// An evidence source that can parse raw bytes into timeline events.
pub trait EvidenceSource: Send + Sync {
    fn name(&self) -> &str;
    fn parse(&self, input: &[u8]) -> Result<Vec<TimelineEvent>>;
}

/// A triage engine that evaluates events against investigative questions.
pub trait TriageEngine: Send + Sync {
    fn evaluate(&self, event: &TimelineEvent) -> TriageResult;
}

/// An output sink that emits formatted results.
pub trait OutputSink: Send + Sync {
    fn emit(&self, event: &TimelineEvent) -> Result<()>;
}
```

The community tier provides implementations for USN Journal, MFT, and standard output formats. The enterprise tier extends these traits for PCAP (`PcapSource`), NetFlow (`NetFlowSource`), and multi-device correlation (`MultiDeviceEngine`).

### 1.4 Cross-Stage Data Flows

```
EWF Parser ──[EvidenceBuffer]──> NTFS Volume
NTFS Volume ──[VolumeHandle]──> USN Parser, MFT Parser  (parallel fork)
USN Parser ──[Vec<UsnRecord>]──> Ghost Recovery
Ghost Recovery ──[Vec<UsnRecord> (expanded)]──> Unallocated Carving
Unallocated Carving ──[Vec<UsnRecord> (complete)]──> QuadLink Correlator
MFT Parser ──[Vec<MftEntry>]──────────────────────> QuadLink Correlator  (join)
QuadLink Correlator ──[Vec<CorrelatedEvent>]──> Triage Engine
Triage Engine ──[Vec<TriageAnswer>]──> Output Formatter
```

**Key data structures:**

| Structure | Description | Approximate Size (1GB image) |
|-----------|-------------|------------------------------|
| `EvidenceBuffer` | Memory-mapped view of E01 image | Bounded by OS page cache, not RSS |
| `UsnRecord` | Single USN change journal entry | ~200 bytes each, ~500K-2M records |
| `MftEntry` | File metadata with path, timestamps | ~1KB each, ~100K-500K entries |
| `CorrelatedEvent` | Linked USN + MFT with resolved path | ~500 bytes each |
| `TriageAnswer` | Answer to one IR question with evidence | ~2KB each, 12 answers |

---

## 2. Enterprise Tier Architecture

### 2.1 System Overview

```
+--------------------------------------------------+
|  Endpoints (1..N)                                |
|  +--------------------+  +--------------------+  |
|  | Katana Agent       |  | Katana Agent       |  |
|  | (katana-agent)     |  | (katana-agent)     |  |
|  | ~4-8MB binary      |  | ~4-8MB binary      |  |
|  | gRPC client + mTLS |  | gRPC client + mTLS |  |
|  +--------+-----------+  +--------+-----------+  |
|           |                        |              |
+-----------|------------------------|--------------+
            |  HTTP/2 + mTLS        |
            v                        v
+--------------------------------------------------+
|  Katana Server (katana-server, Axum)             |
|                                                  |
|  +----------------------------------------------+|
|  | Tower Middleware Stack                        ||
|  | +---------+ +-----------+ +----------------+ ||
|  | | mTLS    | | JWT Auth  | | RBAC           | ||
|  | | Termin- | | (json-    | | (Case+Evidence | ||
|  | | ation   | | webtoken) | |  level)        | ||
|  | +---------+ +-----------+ +----------------+ ||
|  +----------------------------------------------+|
|                                                  |
|  +----------------------------------------------+|
|  | Core Services                                 ||
|  | +--------------+  +------------------------+ ||
|  | | gRPC Server  |  | REST API (Axum)        | ||
|  | | (tonic)      |  | /cases, /evidence,     | ||
|  | | Agent comms  |  | /triage, /reports      | ||
|  | +--------------+  +------------------------+ ||
|  |                                               ||
|  | +--------------+  +------------------------+ ||
|  | | Multi-Device |  | Collaborative Engine   | ||
|  | | Correlator   |  | (WebSocket pub/sub)    | ||
|  | | (katana-     |  | (katana-collab)        | ||
|  | |  multi)      |  | per-case channels      | ||
|  | +--------------+  +------------------------+ ||
|  |                                               ||
|  | +--------------+  +------------------------+ ||
|  | | PCAP/NetFlow |  | Import Adapters        | ||
|  | | Parser       |  | (katana-import)        | ||
|  | | (katana-pcap)|  | Velociraptor, Binalyze | ||
|  | +--------------+  +------------------------+ ||
|  +----------------------------------------------+|
|                                                  |
|  +----------------------------------------------+|
|  | Storage Layer                                 ||
|  | +------------+ +------------+ +-----------+  ||
|  | | PostgreSQL | | tantivy    | | Audit     |  ||
|  | | (sqlx)     | | Full-text  | | Hash-     |  ||
|  | | Cases,     | | search     | | Chain     |  ||
|  | | evidence,  | | index      | | Log       |  ||
|  | | timelines  | |            | |           |  ||
|  | +------------+ +------------+ +-----------+  ||
|  +----------------------------------------------+|
+--------------------------------------------------+
```

### 2.2 Collection Agent (katana-agent)

The collection agent is a minimal static binary deployed to endpoints for remote evidence collection.

| Property | Specification |
|----------|--------------|
| Binary size | 4-8 MB (stripped + UPX compressed) |
| Cold start | <50ms |
| Memory baseline | ~10 MB |
| Communication | gRPC via tonic, HTTP/2, mutual TLS via rustls |
| Authentication | Client certificate (mTLS) + cert pinning |
| Update mechanism | `self_update` crate with cryptographic signature verification |
| Compression | zstd for artifact streaming |
| Resource limits | CPU/memory throttling to avoid impacting endpoint operations |

**Security posture (assume-breach):**
- mTLS with certificate pinning -- compromised CA cannot forge agent identity
- No static credentials embedded in binary
- Code signing required for agent binaries
- Agent compromise must not lead to server compromise (unidirectional trust)
- All collected artifacts are integrity-hashed before transmission
- Resource throttling prevents agent weaponization as DoS tool

**Agent-server protocol:**

```protobuf
// katana.proto
service KatanaAgent {
    rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);
    rpc CollectEvidence(CollectionTask) returns (stream EvidenceChunk);
    rpc StreamTriage(stream TriageEvent) returns (TriageAck);
    rpc UpdateAgent(UpdateRequest) returns (UpdateResponse);
}
```

### 2.3 RBAC Model

Five roles with case-level and evidence-level permissions:

| Role | Capabilities |
|------|-------------|
| **Admin** | System configuration, user management, audit log access, all case operations |
| **Case Manager** | Create/close cases, assign investigators, manage evidence lifecycle, generate reports |
| **Examiner** | Ingest evidence, run triage, annotate timelines, view case evidence |
| **Reviewer** | Read-only access to cases, evidence, and reports (for legal/compliance review) |
| **Auditor** | Read-only access to audit logs and system configuration (external auditors) |

**Permission enforcement** is implemented as Tower middleware extracting roles from JWT claims and evaluating against the requested resource:

```rust
pub enum Permission {
    CaseCreate, CaseView(CaseId), CaseManage(CaseId), CaseClose(CaseId),
    EvidenceIngest(CaseId), EvidenceView(CaseId, EvidenceId),
    EvidenceAnnotate(CaseId, EvidenceId), EvidenceExport(CaseId, EvidenceId),
    EvidenceDelete(CaseId, EvidenceId),  // Audit-logged, CaseManager+ only
    TimelineView(CaseId), TimelineAnnotate(CaseId),
    TriageRun(CaseId), ReportGenerate(CaseId),
    UserManage, SystemConfig, AuditView,
}
```

### 2.4 Audit Trail (Hash-Chain)

Every evidence action is logged to an immutable append-only hash-chain log for legal admissibility:

```rust
pub struct AuditEntry {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,       // NTP-synced UTC
    pub actor_id: UserId,
    pub actor_role: Role,
    pub action: AuditAction,            // EvidenceIngested, TriageExecuted, etc.
    pub resource_type: ResourceType,
    pub resource_id: String,
    pub details: serde_json::Value,
    pub source_ip: IpAddr,
    pub session_id: Uuid,
    pub integrity_hash: String,         // SHA-256(previous_hash + this_entry)
}
```

Properties: tamper-evident (any modification breaks hash chain), non-repudiable (tied to authenticated sessions), exportable (for legal proceedings), retained 7+ years (configurable).

### 2.5 Collaborative Investigation (WebSocket)

Simple pub/sub pattern over Axum WebSocket -- no CRDT/OT complexity needed at this stage:

```
Client -> Server: { "type": "subscribe", "case_id": "..." }
Server -> Client: { "type": "event_added", "case_id": "...", "event": {...} }
Server -> Client: { "type": "annotation_added", "case_id": "...", "annotation": {...} }
Server -> Client: { "type": "tag_added", "case_id": "...", "tag": {...} }
```

Last-write-wins semantics with WebSocket broadcast. Investigators see real-time updates to shared timelines and annotations.

### 2.6 Multi-Device Correlation

| Approach | Tier | Description |
|----------|------|-------------|
| Batch correlation | Community | Single-device, in-memory hash-join during QuadLink stage |
| Streaming correlation | Enterprise | Multi-device, incremental correlation as new evidence arrives |

**Correlation keys**: timestamps (configurable window), usernames, IP addresses, file hashes (SHA-256), process names, session IDs.

**Storage schema** (PostgreSQL, enterprise tier):

```sql
CREATE TABLE timeline_events (
    event_id UUID PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    device_id VARCHAR NOT NULL,
    source_type VARCHAR NOT NULL,     -- 'mft', 'usn', 'evtx', 'pcap'
    event_type VARCHAR NOT NULL,
    message TEXT,
    username VARCHAR,
    hostname VARCHAR,
    ip_address VARCHAR,
    file_hash VARCHAR,
    file_path VARCHAR,
    process_name VARCHAR,
    raw_data BLOB,
    triage_score INTEGER,
    tags VARCHAR[],
    investigation_id UUID
);

CREATE INDEX idx_timeline ON timeline_events (timestamp, device_id);
CREATE INDEX idx_entity ON timeline_events (username, ip_address, hostname);
CREATE INDEX idx_triage ON timeline_events (triage_score DESC);
```

### 2.7 Multi-Tenancy (MSSP Support)

Schema-per-tenant isolation in PostgreSQL:
- Each MSSP client gets a dedicated schema (`tenant_{id}`)
- Cross-tenant queries are architecturally impossible
- Tenant provisioning is automated via migration scripts
- Audit logs are tenant-scoped but exportable by Admin role

---

## 3. Implementation Scaffold

### 3.1 Cargo Workspace Structure

```
~/src/
  katana/                         # Public repo (Apache-2.0)
    Cargo.toml                    # Virtual workspace manifest, resolver = "2"
    crates/
      katana-core/                # Shared types, traits (EvidenceSource, TriageEngine, OutputSink)
        src/
          lib.rs                  # Re-exports
          traits.rs               # Extension traits
          usn/                    # USN Journal parser
          mft/                    # MFT parser
          ghost/                  # Ghost recovery engine
          carving/                # Unallocated carving
          correlator/             # QuadLink correlator
          triage/                 # Triage engine (12 questions)
          types.rs                # UsnRecord, MftEntry, TimelineEvent, TriageAnswer
      katana-cli/                 # Community CLI binary (clap)
        src/
          main.rs                 # Entry point, argument parsing
          pipeline.rs             # Pipeline orchestration
          progress.rs             # Progress bar / status output
      katana-formats/             # Output formatters
        src/
          json.rs, csv.rs, jsonl.rs, xml.rs, tln.rs, html.rs, sqlite.rs
      katana-ewf/                 # E01/raw image handling
        src/
          reader.rs               # EWF format reader
          mmap.rs                 # Memory-mapped I/O wrapper
      katana-ntfs/                # NTFS parsing wrappers
        src/
          volume.rs               # Volume detection
          partition.rs            # Partition table parsing

  katana-pro/                     # Private repo (Proprietary)
    Cargo.toml                    # Separate workspace, path deps to katana/crates/*
    crates/
      katana-server/              # Axum API + RBAC + WebSocket
        src/
          main.rs                 # Server entry point
          routes/                 # REST API handlers
          middleware/             # Tower auth, RBAC, rate limiting
          ws/                     # WebSocket collaboration
      katana-agent/               # Collection agent (tonic gRPC, ~4-8MB binary)
        src/
          main.rs                 # Agent entry point
          collector.rs            # Evidence collection engine
          grpc.rs                 # tonic gRPC client
          update.rs               # Self-update mechanism
      katana-pcap/                # PCAP (pcap-parser + etherparse) / NetFlow (netflow_parser)
        src/
          pcap.rs                 # PCAP file parsing
          netflow.rs              # NetFlow V5/V7/V9/IPFIX
          dissect.rs              # Protocol dissection
      katana-collab/              # Collaborative investigation
        src/
          pubsub.rs               # WebSocket pub/sub engine
          presence.rs             # Investigator presence tracking
      katana-import/              # Import adapters
        src/
          velociraptor.rs         # Velociraptor hunt result importer
          binalyze.rs             # Binalyze AIR collection importer
      katana-multi/               # Multi-device correlation
        src/
          streaming.rs            # Streaming correlation engine
          keys.rs                 # Correlation key extraction
```

### 3.2 Dependency Pattern

```toml
# katana-pro/Cargo.toml
[workspace.dependencies]
katana-core = { path = "../katana/crates/katana-core" }
katana-formats = { path = "../katana/crates/katana-formats" }
katana-ewf = { path = "../katana/crates/katana-ewf" }
katana-ntfs = { path = "../katana/crates/katana-ntfs" }
```

Enterprise crates import community traits via path dependencies during development. CI uses git dependencies pointing to the public repo. All enterprise crates use `publish = false`.

---

## 4. Technology Stack

### 4.1 Community Tier

| Layer | Crate / Technology | Version | Rationale |
|-------|-------------------|---------|-----------|
| Language | Rust | 2021 edition | Zero-cost abstractions, static binaries, memory safety without GC |
| CLI | `clap` | 4.x | Already in use, derive macros for ergonomic argument parsing |
| Parallelism | `rayon` | 1.x | Data parallelism for multi-core parsing stages |
| Memory-mapped I/O | `memmap2` | 0.9+ | Stable mmap successor, bounded memory via OS page cache |
| Zero-copy parsing | `zerocopy` | 0.7+ | Zero-copy deserialization of binary NTFS/USN structures |
| Database | `rusqlite` | 0.31+ | Embedded SQLite, fits single-device 35s budget |
| Serialization | `serde` + `serde_json` | 1.x | Standard Rust serialization ecosystem |
| Error handling | `thiserror` + `anyhow` | 1.x/1.x | Typed errors in library crates, dynamic errors in binary |
| Progress | `indicatif` | 0.17+ | Terminal progress bars for CLI UX |

### 4.2 Enterprise Tier (Additional)

| Layer | Crate / Technology | Version | Rationale |
|-------|-------------------|---------|-----------|
| Web framework | `axum` | 0.8 | Shares Tokio runtime with tonic, Tower middleware ecosystem |
| HTTP middleware | `tower-http` | 0.6 | CORS, compression, tracing, auth layers |
| gRPC framework | `tonic` | 0.14+ | Bidirectional streaming, HTTP/2 native, Rust-native |
| Protobuf | `prost` | 0.13+ | Protocol Buffers codegen for agent-server contracts |
| TLS | `rustls` | 0.23+ | Pure-Rust TLS, no OpenSSL dependency, mTLS support |
| Authentication | `jsonwebtoken` | 9 | JWT signing/verification for API auth |
| Password hashing | `argon2` | 0.5 | Argon2id for user credentials |
| Database (enterprise) | `sqlx` | 0.8 | Async PostgreSQL driver |
| Full-text search | `tantivy` | 0.22+ | Rust-native Lucene equivalent, no JVM dependency |
| PCAP parsing | `pcap-parser` | 0.15+ | Pure Rust, zero-copy, PCAP + PCAPNG support |
| Protocol dissection | `etherparse` | 0.15+ | Pure Rust, zero-allocation layer 2-4 parsing |
| NetFlow | `netflow_parser` | 0.4+ | V5/V7/V9/IPFIX, zero-allocation iterator |
| Compression | `zstd` | 0.13+ | Agent artifact compression, 3-5x better than gzip |
| Agent updates | `self_update` | 0.39+ | Cryptographically signed self-update mechanism |
| Rate limiting | `governor` | 0.6 | API rate limiting |
| API docs | `utoipa` | 5 | Auto-generated OpenAPI documentation |
| Filesystem traversal | `walkdir` | 2.x | Agent evidence collection directory walking |

### 4.3 Key Technologies Not Used (and Why)

| Technology | Reason for Exclusion | Kill List Reference |
|------------|---------------------|---------------------|
| Any ML/AI library | Triage is rule-based, deterministic, court-defensible | "AI/ML-based triage classification" |
| Electron / Tauri | CLI-first, no GUI | "GUI-first application" |
| Cloud SDKs | Fully offline operation | "Cloud-based processing" |
| Plugin frameworks | Fixed pipeline, trait-based extension instead | "Plugin/extension system" |
| DuckDB | Evaluated but SQLite sufficient for community; PostgreSQL for enterprise | "Database-first architecture" |

---

## 5. Performance Architecture

### 5.1 Community Tier (35-Second Budget)

```
E01 Image (disk)
    |
    v  mmap (memmap2, OS readahead)
[Memory-Mapped Evidence Buffer]
    |
    v  Zero-copy parsing (zerocopy)
[Parsed Artifacts: USN Journal + MFT]
    |
    v  Rayon parallel iterators
[Ghost Recovery + Unallocated Carving + Correlation]
    |
    v  Rayon parallel per-question
[Triage Evaluation: 12 IR questions scored]
    |
    v  Sequential write
[Output: 7 format options]
```

**Performance targets:**
- Parse rate: 100K+ events/second
- Memory: bounded by mmap window, not full image RSS
- CPU: saturate all available cores via Rayon work-stealing
- I/O: sequential reads via mmap with OS readahead optimization

### 5.2 Enterprise Tier Performance

- Core triage speed: identical to community (same crate, same code path)
- Network overhead: gRPC streaming adds <500ms for evidence transfer
- Multi-device correlation: incremental -- does not re-process existing devices
- Collection agent cold start: <50ms
- Collection agent binary: <5MB (stripped + UPX)

---

## 6. Enterprise Extensions

### 6.1 PCAP/NetFlow Analysis (katana-pcap)

Extends the `EvidenceSource` trait for network evidence:

| Component | Implementation |
|-----------|---------------|
| PCAP file reading | `pcap-parser` -- pure Rust, zero-copy, PCAP + PCAPNG |
| Protocol dissection | `etherparse` -- layer 2-4 headers, zero-allocation |
| NetFlow collection | `netflow_parser` -- V5/V7/V9/IPFIX with template caching |
| Output | `TimelineEvent` entries correlated with host-based evidence |

**Scope guard**: PCAP analysis is forensic (file-based), not live capture. No raw socket access, no `libpcap` dependency. NetFlow is prioritized before PCAP per roadmap guidance.

### 6.2 Import Adapters (katana-import)

| Source | Format | Strategy |
|--------|--------|----------|
| Velociraptor | Hunt results (JSON/CSV) | Parse VQL output into `TimelineEvent` stream |
| Binalyze | AIR collection (ZIP/structured) | Extract and normalize into standard evidence format |

Adapters implement the `EvidenceSource` trait, making imported data indistinguishable from locally parsed evidence in the triage pipeline.

### 6.3 Collection Agent Deployment

Phased deployment per roadmap:
1. **Enterprise Phase 1**: Import adapters only (Velociraptor/Binalyze results imported manually)
2. **Enterprise Phase 2**: Collaborative investigation (WebSocket)
3. **Enterprise Phase 3**: Collection agent deployment with mTLS, cert pinning, code signing

---

## 7. Resilience Patterns

### 7.1 Pipeline Resilience (Community)

| Failure | Recovery Strategy |
|---------|-------------------|
| Corrupt E01 image | Report corruption offset, process remaining data, warn in output |
| Missing USN Journal | Skip USN stages, proceed with MFT-only triage, degrade gracefully |
| MFT parse failure | Fallback to USN-only mode, reduce triage question coverage |
| Path resolution failure | Mark as UNKNOWN, continue (target: zero UNKNOWN in production) |
| Ghost recovery timeout | Produce partial results within budget, flag incomplete recovery |
| Output write failure | Retry once, then report error with partial results to stderr |

### 7.2 Enterprise Resilience

| Failure | Recovery Strategy |
|---------|-------------------|
| Agent connection lost | Automatic reconnection with exponential backoff, resume from last acknowledged chunk |
| Server unavailable | Agent queues evidence locally (bounded buffer), retries on configurable interval |
| Database unreachable | Read-only mode for API, queue writes, alert admin |
| WebSocket disconnect | Client auto-reconnect, replay missed events from server-side buffer |
| Certificate expiry | Alert 30 days before expiry, automated renewal via ACME where possible |

---

## 8. Testing Strategy

> **Extracted to**: [architecture/TESTING_STRATEGY.md](architecture/TESTING_STRATEGY.md)

Summary:

| Category | Scope | Coverage Target |
|----------|-------|----------------|
| Unit tests | Individual parsers, triage questions, formatters | >90% line coverage |
| Integration tests | Full pipeline E01-to-report | 100% of 12 triage questions |
| Golden dataset | Known-answer E01 images with verified triage output | 100% recall on critical paths |
| Forensic correctness | Output matches reference tools (AXIOM, KAPE) for same evidence | Bit-identical where applicable |
| Performance regression | P95 triage time tracked per commit | <35s or CI fails |
| Enterprise integration | Agent-server-database round trip | gRPC + mTLS verified |
| Security tests | mTLS enforcement, RBAC boundary, cert pinning verification | Zero bypass paths |

---

## 9. Deployment Checklist

### Pre-Launch (Community)

- [ ] All 12 triage questions produce correct answers on golden dataset
- [ ] Ghost recovery rate >95% on test images
- [ ] Path resolution completeness: zero UNKNOWN entries
- [ ] P95 triage time <35 seconds on 1GB E01 image
- [ ] All 7 output formats validated
- [ ] Static binary builds verified for Linux (x86_64, aarch64), macOS (aarch64), Windows (x86_64)
- [ ] `cargo clippy` and `cargo fmt` clean
- [ ] SPDX Apache-2.0 headers on all community crate files
- [ ] GitHub Actions CI green on all platforms
- [ ] Release binary size within budget (<20MB)

### Pre-Launch (Enterprise)

- [ ] mTLS agent-server communication verified
- [ ] RBAC boundaries tested: no privilege escalation paths
- [ ] Audit hash-chain integrity verified after 10K+ operations
- [ ] Multi-device correlation tested with 5+ devices
- [ ] WebSocket collaboration tested with 10+ concurrent investigators
- [ ] PostgreSQL migration scripts tested (up and rollback)
- [ ] Rate limiting configured and tested
- [ ] Collection agent <5MB binary size verified
- [ ] Agent self-update mechanism tested with signature verification
- [ ] Import adapters validated against real Velociraptor/Binalyze exports

### Post-Launch

- [ ] Monitor triage completion rate (target: >95%)
- [ ] Monitor P95 triage latency weekly
- [ ] Monitor false positive rate (target: <5%)
- [ ] Track North Star metric: paying enterprise customers
- [ ] Review audit log integrity weekly
- [ ] Monitor agent fleet health (heartbeat success rate)
- [ ] Track MRR growth toward $50K target

---

## Appendix A: Competitive Architecture Comparison

| Capability | Katana (Community) | Katana (Enterprise) | Velociraptor | Timesketch | AXIOM |
|------------|-------------------|--------------------|--------------|-----------:|-------|
| Language | Rust | Rust | Go | Python | C++/.NET |
| Deployment | Single binary | Server + agents | Single binary | Docker + 4 services | Desktop installer |
| Collection | Local only | gRPC agents | Go agents | Manual import | Proprietary |
| Storage | SQLite | PostgreSQL + tantivy | File-based | PostgreSQL + OpenSearch | Proprietary DB |
| Collaboration | None | WebSocket real-time | None | Shared timelines | None |
| USN Journal | Native + ghost + carving | Same core | Via VQL artifacts | Via plaso | Native |
| RBAC | N/A | Case + evidence level | Server-level only | Basic | License-based |
| Audit trail | N/A | Hash-chain | Server logs | Basic logging | Proprietary |
| PCAP analysis | N/A | Pure Rust | Via VQL | Via plaso | Native |
| Performance | <35s P95 / 1GB | Same core + network | GC-limited | Minutes-hours | Minutes |

---

## Appendix B: Decision Log

| Date | Decision | Choice | Alternatives Considered | Rationale |
|------|----------|--------|------------------------|-----------|
| 2026-03-10 | Repo structure | Two repos, two workspaces | Monorepo with feature flags | Clean license separation; enterprise never leaks into open-source releases |
| 2026-03-10 | Agent comms | gRPC via tonic + mTLS | HTTP/2 REST, QUIC | Bidirectional streaming, type-safe protobuf contracts, no OpenSSL |
| 2026-03-10 | Enterprise DB | PostgreSQL + tantivy | DuckDB only, OpenSearch | PostgreSQL for relational (RBAC, cases); tantivy for search without JVM |
| 2026-03-10 | Community DB | SQLite via rusqlite | DuckDB, in-memory only | Proven, embedded, minimal overhead, fits 35s budget |
| 2026-03-10 | PCAP approach | pcap-parser + etherparse | libpcap FFI, pnet | Pure Rust, zero-copy, no system dependencies |
| 2026-03-10 | Correlation strategy | Batch (community) + streaming (enterprise) | Streaming only | Community has no server; batch fits single-device model |
| 2026-03-10 | Audit mechanism | Append-only hash chain | Database triggers, external audit service | Tamper-evident, self-contained, legally defensible |
| 2026-03-10 | Multi-tenancy | Schema-per-tenant | Row-level security, separate databases | Good isolation without operational burden for MSSP customers |
| 2026-03-10 | Web framework | Axum | Actix-web, Rocket, Warp | Shares Tokio runtime with tonic, Tower middleware ecosystem |
| 2026-03-10 | No AI/ML triage | Rule-based deterministic | ML classifiers, LLM-based | Court-admissibility requires reproducible, explainable decisions |
