# Two-Tier (Community + Enterprise) DFIR Forensic Triage Architecture Research

**Project:** Security Ronin Katana
**Date:** 2026-03-09
**Purpose:** Architecture patterns research for open-core Rust DFIR tool

---

## 1. Rust Cargo Workspace for Open-Core

### Recommended Repo Structure

```
~/src/
  katana/                    # Public repo (Apache-2.0)
    Cargo.toml               # Workspace root
    crates/
      katana-core/           # Shared types, traits, parsers
      katana-cli/            # Community CLI binary
      katana-mft/            # $MFT parser
      katana-usn/            # USN Journal parser
      katana-evtx/           # Event log parser
      katana-timeline/       # Timeline construction

  katana-pro/                # Private repo (Proprietary)
    Cargo.toml               # Separate workspace
    crates/
      katana-pro-cli/        # Enterprise CLI binary
      katana-agent/          # Collection agent
      katana-rbac/           # RBAC module
      katana-collab/         # Collaborative investigation
      katana-pcap/           # PCAP/NetFlow analysis
      katana-multi/          # Multi-device correlation
```

### Dependency Pattern

In `katana-pro/Cargo.toml`:
```toml
[workspace]
resolver = "2"
members = ["crates/*"]

[workspace.dependencies]
# Path dependency for local dev, git for CI
katana-core = { path = "../katana/crates/katana-core" }
katana-timeline = { path = "../katana/crates/katana-timeline" }
```

### Type/Trait Sharing Strategy

The `katana-core` crate should define extension traits that the enterprise crate implements:

```rust
// katana-core/src/lib.rs (Apache-2.0)
pub trait EvidenceSource: Send + Sync {
    fn name(&self) -> &str;
    fn parse(&self, input: &[u8]) -> Result<Vec<TimelineEvent>>;
}

pub trait TriageEngine: Send + Sync {
    fn evaluate(&self, event: &TimelineEvent) -> TriageResult;
}

pub trait OutputSink: Send + Sync {
    fn emit(&self, event: &TimelineEvent) -> Result<()>;
}

// Enterprise crate implements these traits for PCAP, NetFlow, etc.
```

### Feature Flags vs Separate Binaries: Use Both

- **Separate binary targets** for community (`katana`) vs enterprise (`katana-pro`) CLIs
- **Feature flags** within the enterprise crate for sub-licensing (e.g., `pcap`, `agent`, `collab`)
- Do NOT gate enterprise code behind feature flags in the public crate -- this leaks proprietary code

### Conditional Compilation Pattern

```rust
// In katana-pro crates only
#[cfg(feature = "pcap")]
mod pcap_parser;

#[cfg(feature = "agent")]
mod collection_agent;
```

### Licensing Per Crate

Each crate declares its own license in `Cargo.toml`:
```toml
# katana-core/Cargo.toml
[package]
license = "Apache-2.0"

# katana-pro-cli/Cargo.toml
[package]
license-file = "LICENSE-PROPRIETARY"
```

### Real-World Precedents

| Project | Pattern | License |
|---------|---------|---------|
| **InfluxDB 3** | Core (MIT/Apache-2.0) + commercial (proprietary), same FDAP stack | Dual |
| **Apache OpenDAL** | Core crate with feature-flag gated services/layers | Apache-2.0 |
| **r3bl-open-core** | Monorepo workspace, each crate published separately | Mixed |
| **Zff** | Forensic format alternative to EWF, pure Rust | Open |

### CI Considerations

- Public CI (GitHub Actions) builds and tests `katana` workspace only
- Private CI builds both workspaces via `--manifest-path` or workspace overlay
- Use `[patch]` section in `katana-pro` to override path deps for CI:
  ```toml
  [patch.crates-io]
  katana-core = { git = "https://github.com/h4x0r/katana", branch = "main" }
  ```

**Sources:**
- [Cargo Features Reference](https://doc.rust-lang.org/cargo/reference/features.html)
- [Cargo Workspace Best Practices](https://reintech.io/blog/cargo-workspace-best-practices-large-rust-projects)
- [Cargo Specifying Dependencies](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html)
- [r3bl-open-core GitHub](https://github.com/r3bl-org/r3bl-open-core)
- [InfluxDB 3 Architecture](https://www.infoq.com/articles/timeseries-db-rust/)
- [Rust Forum: Proprietary Library Discussion](https://users.rust-lang.org/t/how-would-you-create-a-proprietary-library-in-rust/62928)
- [Cargo Workspace RFC](https://rust-lang.github.io/rfcs/2906-cargo-workspace-deduplicate.html)
- [Rust 1.34 Alternative Registries](https://www.infoq.com/news/2019/04/rust-1.34-additional-registries/)

---

## 2. Velociraptor Architecture Analysis

### Client-Server Model

```
Endpoints (10k-100k+)          Server Infrastructure
+------------------+           +------------------+
| Velociraptor     |  gRPC/    | Frontend         |
| Client Agent     |---------->| (Go binary)      |
| (same binary as  |  HTTP/2   |                  |
|  server, diff    |           | +--- VQL Engine   |
|  CLI flags)      |           | +--- Hunt Mgr    |
+------------------+           | +--- Artifact DB  |
                               +--------+---------+
                                        |
                               +--------v---------+
                               | File-based        |
                               | Datastore         |
                               | (single machine)  |
                               +-------------------+
```

**Key design decisions:**
- Single binary for client AND server (CLI flags determine mode)
- Clients connect and wait for VQL instructions
- Collection runs entirely on the endpoint; server only sends queries and receives results
- File-based datastore (no database backend)
- Client snapshot file stores all client records in memory (rewritten in 0.7.0)

### VQL Design Philosophy

- Purpose-built query language for forensic artifact collection
- Avoids the deploy-new-binary cycle: new IOCs/detections via VQL artifacts
- Artifacts are reusable VQL code snippets defining what/how to collect
- Extensible: users write custom artifacts without modifying core
- Sigma rule integration via analyzers

### Architectural Weaknesses (Competitor Opportunities)

| Weakness | Katana Opportunity |
|----------|-------------------|
| **File-based datastore only** -- limited to single machine, no database backend | Use embedded DB (SQLite/DuckDB) or pluggable storage |
| **Scalability ceiling** -- traditional full-triage doesn't scale past thousands of endpoints | Memory-mapped I/O + streaming pipeline for 35s budget on single device |
| **Go performance ceiling** -- GC pauses, higher memory usage | Rust: zero-cost abstractions, no GC, predictable latency |
| **Disk-full cascading failures** -- clients queue 1GB buffers, flood server on recovery | Backpressure-aware streaming with configurable limits |
| **Single binary = attack surface** -- same binary for client/server, abused by threat actors (CVE-2025-6264) | Separate client/server binaries, minimal agent surface area |
| **VQL learning curve** -- requires specialized knowledge | Structured triage questions (natural language) + optional query language |
| **No native collaboration** -- single-user focused | Enterprise tier: multi-user, RBAC, case management |
| **No built-in timeline correlation** -- outputs raw results | Built-in timeline construction with cross-source correlation |

**Sources:**
- [Velociraptor Deployment Overview](https://docs.velociraptor.app/docs/deployment/)
- [VQL Documentation](https://docs.velociraptor.app/docs/vql/)
- [Velociraptor Performance](https://docs.velociraptor.app/blog/html/2019/02/10/velociraptor_performance/)
- [Velociraptor Server Resources](https://docs.velociraptor.app/docs/deployment/resources/)
- [Velociraptor In Depth](https://itinnovationstation.com/2025/04/14/velociraptor-in-depth-forensic-and-threat-hunting-capabilities/)
- [Velociraptor GitHub](https://github.com/Velocidex/velociraptor)
- [CVE-2025-6264 Abuse Report](https://www.fortra.com/blog/velociraptor-dfir-tool-abused-wsus-rce-cve-2025-59287)
- [Velociraptor 0.7.0 Release](https://www.rapid7.com/blog/post/2023/08/31/velociraptor-0-7-0-release-dig-deeper-with-enhanced-client-search-server-improvements-and-expanded-vql-library/)
- [Velociraptor AI Integration 2025](https://rioasmara.com/2025/12/18/supercharging-velociraptor-with-ai-and-cursor/)

---

## 3. Timesketch Architecture Analysis

### Architecture Overview

```
Investigators (Browser)
        |
+-------v--------+
| Timesketch Web  |    REST API
| (Flask/Python)  |
+---+--------+---+
    |        |
    v        v
+-------+ +----------+
|Celery | |PostgreSQL |  Metadata: sketches, users, stories
|Workers| +----------+
+---+---+
    |
+---v-----------+
| OpenSearch /   |  All timeline events stored here
| Elasticsearch  |  Full-text search, aggregation
+----------------+
    |
+---v---+
| Redis |  Task queue broker
+-------+
```

### Data Ingestion Pipeline

1. **Input formats:** Plaso (log2timeline) output, CSV, JSONL, Hayabusa
2. **Upload:** via web UI or REST API
3. **Processing:** Celery workers normalize and index data into OpenSearch
4. **Indexing:** Each event gets timestamp, message, source fields
5. **Analyzers:** Python-based background workers (Sigma rules, domain analysis, etc.)

### Collaboration Model

- **Sketches** = investigation containers with multiple timelines
- Multi-user: tag, star, comment, annotate events
- **Stories** = narrative documents linking to timeline evidence
- Shared sketch access with per-sketch permissions

### Limitations (Katana Opportunities)

| Limitation | Katana Opportunity |
|-----------|-------------------|
| **OpenSearch dependency** -- heavy infrastructure requirement | Embedded search (tantivy crate for Rust-native full-text search) |
| **Shard limits** -- max ~1,500 open shards, 150-index search limit | DuckDB or custom storage avoiding shard overhead |
| **Python performance** -- Celery bottlenecks on large ingestions | Rust processing pipeline with zero-copy deserialization |
| **Configuration complexity** -- requires significant tuning | Single-binary deployment with sane defaults |
| **No built-in collection** -- requires separate tools (Plaso, etc.) | Integrated collection + analysis pipeline |
| **No real-time streaming** -- batch ingestion only | Streaming timeline construction during evidence processing |

**Sources:**
- [Timesketch GitHub](https://github.com/google/timesketch)
- [Timesketch Basic Concepts](https://github.com/google/timesketch/blob/master/docs/guides/user/basic-concepts.md)
- [Timesketch Search Query Guide](https://github.com/google/timesketch/blob/master/docs/guides/user/search-query-guide.md)
- [Timesketch Scaling and Limits](https://github.com/google/timesketch/blob/master/docs/guides/admin/scaling-and-limits.md)
- [Timesketch Helm Chart](https://google.github.io/osdfir-infrastructure/charts/timesketch/)
- [Timeline Analysis from the Future (Medium)](https://medium.com/timesketch/timeline-analysis-from-the-future-59a7ad7da498)
- [Hunt and Hackett: Scalable Forensics with Dissect + Timesketch](https://www.huntandhackett.com/blog/scalable-forensics-timeline-analysis-using-dissect-and-timesketch)
- [Timesketch Config](https://github.com/google/timesketch/blob/master/data/timesketch.conf)

---

## 4. Collection Agent Patterns in Rust

### Communication: gRPC via Tonic

**Recommended stack:**
```
Agent (Endpoint)              Server (Katana-Pro)
+------------------+         +------------------+
| tonic gRPC client|  mTLS   | tonic gRPC server|
| (HTTP/2, streams)|-------->| (HTTP/2)         |
| prost (protobuf) |         | prost (protobuf) |
+------------------+         +------------------+
```

**Why gRPC + tonic over plain HTTP/2:**
- Bi-directional streaming for real-time evidence upload
- Strong typing via protobuf schemas (`.proto` files shared between agent/server)
- Built-in mTLS support via `tonic`'s TLS feature
- HTTP/2 multiplexing: multiple RPCs on single connection
- Efficient binary serialization (protobuf vs JSON)
- `tonic-health` for agent health checking
- `tonic-reflection` for service discoverability

**Key crates:**
| Crate | Purpose |
|-------|---------|
| `tonic` (0.14.x) | gRPC client/server framework |
| `prost` | Protocol Buffers codegen |
| `tonic-tls` | Additional TLS options |
| `tonic-health` | gRPC health checking |
| `tonic-reflection` | Service reflection |
| `rustls` | TLS implementation (no OpenSSL dependency) |

### Agent Update/Deployment Mechanism

**`self_update` crate pattern:**
```rust
use self_update::backends::github::Update;

fn check_for_updates() -> Result<()> {
    let status = Update::configure()
        .repo_owner("h4x0r")
        .repo_name("katana-pro-agent")
        .bin_name("katana-agent")
        .current_version(env!("CARGO_PKG_VERSION"))
        .build()?
        .update()?;
    Ok(())
}
```

**For enterprise: custom update server**
- Serve signed binaries from private S3/internal server
- Verify Ed25519 signatures before replacing binary
- Staged rollouts: canary -> percentage -> full fleet
- Rollback mechanism: keep previous version alongside

### Agent Binary Characteristics (Rust Advantage)

| Metric | Rust Agent | Python Equivalent |
|--------|-----------|-------------------|
| Binary size | ~4-8 MB (stripped) | 50+ MB (PyInstaller) |
| Cold start | ~50ms | ~2-5s |
| Memory usage | ~10 MB base | ~50-100 MB |
| Dependencies | Zero (static binary) | Python runtime + venv |

### Evidence Collection and Streaming

```protobuf
// evidence.proto
service EvidenceCollector {
    // Server sends collection tasks, agent streams results
    rpc Collect(CollectionRequest) returns (stream EvidenceChunk);

    // Agent heartbeat with resource usage
    rpc Heartbeat(AgentStatus) returns (HeartbeatResponse);

    // Bi-directional for interactive investigation
    rpc Investigate(stream InvestigateRequest) returns (stream InvestigateResponse);
}

message EvidenceChunk {
    string artifact_name = 1;
    bytes data = 2;
    uint64 offset = 3;
    uint64 total_size = 4;
    string sha256_running = 5;
}
```

### Endpoint Resource Management

```rust
// Resource limiter for agent
struct ResourceLimits {
    max_cpu_percent: f32,     // e.g., 15% CPU cap
    max_memory_mb: u64,       // e.g., 256 MB
    max_disk_io_mbps: u64,    // e.g., 50 MB/s
    collection_timeout: Duration,
    nice_level: i32,          // Process priority
}
```

Implementation approaches:
- `rlimit` crate for POSIX resource limits
- `sysinfo` crate for monitoring CPU/memory usage
- Tokio's `Semaphore` for concurrency control
- `governor` crate for rate limiting I/O operations

### Security Model

1. **Mutual TLS (mTLS):** Agent and server both present certificates
2. **Certificate pinning:** Agent embeds server CA certificate at build time
3. **Rustls over OpenSSL:** No C dependency, memory-safe TLS
4. **Agent authentication:** Unique client certificate per agent, tied to device ID
5. **Enrollment flow:** Agent presents enrollment token -> server issues client cert
6. **Channel encryption:** All gRPC traffic over TLS 1.3

**Sources:**
- [Tonic GitHub](https://github.com/hyperium/tonic)
- [Tonic Documentation](https://docs.rs/tonic)
- [gRPC Basics for Rust (DockYard)](https://dockyard.com/blog/2025/04/08/grpc-basics-for-rust-developers)
- [Building gRPC APIs with Rust (Kong)](https://konghq.com/blog/engineering/building-grpc-apis-with-rust)
- [gRPC in Rust with Tonic (Thorsten Hans)](https://www.thorsten-hans.com/grpc-services-in-rust-with-tonic/)
- [self_update Crate (HN Discussion)](https://news.ycombinator.com/item?id=22182728)
- [self_update Rust Forum Announcement](https://users.rust-lang.org/t/self-update-in-place-updates-for-rust-executables/12075)
- [ZeroClaw Agent Framework](https://zeroclaw.bot/)
- [tonic-tls Crate](https://crates.io/crates/tonic-tls)

---

## 5. Multi-Device Correlation Architecture

### Architecture for Cross-Device Evidence Correlation

```
Device A (Windows)     Device B (Linux)      Device C (Network)
  MFT, USN, EVTX        /var/log, .bash      PCAP, NetFlow
       |                     |                     |
       v                     v                     v
+------+---------------------+---------------------+------+
|              Normalization Layer                         |
|  Timestamp normalization (UTC), field mapping,           |
|  source tagging, deduplication                           |
+------+---------------------------------------------------+
       |
       v
+------+---------------------------------------------------+
|              Correlation Engine                          |
|  +-- Timestamp correlation (configurable window)         |
|  +-- Entity resolution (users, IPs, hostnames, hashes)   |
|  +-- Causal chain detection (A caused B)                 |
|  +-- Statistical anomaly detection                       |
+------+---------------------------------------------------+
       |
       v
+------+---------------------------------------------------+
|              Unified Timeline Store                       |
|  DuckDB / SQLite with full-text search (tantivy)         |
|  Indexed by: timestamp, device_id, entity, event_type    |
+------+---------------------------------------------------+
       |
       v
+------+---------------------------------------------------+
|              Presentation Layer                          |
|  CLI output, JSON export, web dashboard (enterprise)     |
+----------------------------------------------------------+
```

### Correlation Keys

| Key Type | Examples | Matching Strategy |
|----------|----------|-------------------|
| **Timestamps** | File creation, log entry, packet capture time | Window-based (configurable tolerance, e.g., +/- 5s) |
| **User identifiers** | SID, username, email, UID | Exact match + alias resolution |
| **Network identifiers** | IP address, MAC, hostname | Exact match + DHCP lease correlation |
| **File identifiers** | SHA256, file path, file name | Hash match (strong) or path match (weak) |
| **Process identifiers** | PID + timestamp, command line hash | Fuzzy match within device |
| **Session identifiers** | RDP session ID, SSH session, logon ID | Exact match |

### Storage Architecture

**Recommended: DuckDB for analytical queries + tantivy for full-text search**

Rationale:
- DuckDB: columnar storage, excellent for time-range queries and aggregation
- Single-file database, no server process (fits community tier)
- Tantivy: Rust-native full-text search (Lucene-equivalent), no Java/JVM dependency
- Both support memory-mapped I/O for performance

Schema design:
```sql
CREATE TABLE timeline_events (
    event_id UUID PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    device_id VARCHAR NOT NULL,
    source_type VARCHAR NOT NULL,       -- 'mft', 'usn', 'evtx', 'pcap', etc.
    event_type VARCHAR NOT NULL,
    message TEXT,
    -- Correlation keys
    username VARCHAR,
    hostname VARCHAR,
    ip_address VARCHAR,
    file_hash VARCHAR,
    file_path VARCHAR,
    process_name VARCHAR,
    -- Metadata
    raw_data BLOB,
    triage_score INTEGER,
    tags VARCHAR[],
    -- Partitioning
    investigation_id UUID
);

-- Optimized indexes
CREATE INDEX idx_timeline ON timeline_events (timestamp, device_id);
CREATE INDEX idx_entity ON timeline_events (username, ip_address, hostname);
CREATE INDEX idx_triage ON timeline_events (triage_score DESC);
```

### Real-Time vs Batch Correlation

| Approach | When to Use | Implementation |
|----------|------------|----------------|
| **Batch** | Post-acquisition analysis, community tier | Process all evidence, build full timeline, then correlate |
| **Streaming** | Live investigation, enterprise agent tier | Agent streams events, server correlates in real-time |
| **Hybrid** | Best of both | Batch for historical, streaming for active collection |

For community tier (35s budget): **Batch only** -- process E01 image with memory-mapped I/O pipeline, construct timeline, apply triage questions.

For enterprise tier: **Hybrid** -- agents stream live events, server correlates with existing historical data.

### Academic Foundations

- **Cross-Drive Analysis (Garfinkel):** Five-step architecture: imaging -> feature extraction -> first-order CDA -> cross-drive correlation -> reporting
- **Stitcher (IoT):** Automated evidence classification using ISO standards, correlation of firmware + PCAP + system processes
- **MADIK:** Multi-agent system with case-based reasoning for automated evidence correlation

**Sources:**
- [Cross-Drive Analysis Using Automated Timelines (Garfinkel)](https://www.researchgate.net/publication/264543999_The_Potential_for_Cross-Drive_Analysis_Using_Automated_Digital_Forensic_Timelines)
- [Stitcher: IoT Evidence Correlation](https://www.sciencedirect.com/science/article/abs/pii/S2666281720303681)
- [Belkasoft X: Multi-Source Timeline](https://belkasoft.com/digital-forensic-timeline-analysis)
- [Cellebrite: Cross-Device Analysis](https://cellebrite.com/en/10-best-practices-for-digital-evidence-collection/)
- [MADIK: Multi-Agent Forensic System](https://www.researchgate.net/publication/221155509_A_Cooperative_Multi-agent_Approach_to_Computer_Forensics)
- [Mobile Cloud Correlated Forensic Process Model](https://www.warse.org/IJATCSE/static/pdf/file/ijatcse333942020.pdf)

---

## 6. RBAC Architecture for Forensic Tools

### Role Model for Katana Enterprise

```
+-------------------+
|    System Admin    |  Full system config, user management, audit access
+-------------------+
         |
+-------------------+
|   Case Manager    |  Create/close cases, assign examiners, review reports
+-------------------+
         |
+--------+---------+
|                  |
v                  v
+-----------+ +----------+
|  Examiner | | Reviewer |  Examiner: collect, analyze, annotate
+-----------+ +----------+  Reviewer: read-only, approve findings
                  |
          +-------v-------+
          |   Auditor     |  Read-only audit trail access
          +---------------+
```

### Permission Model: Evidence-Level + Case-Level

```rust
// katana-rbac/src/permissions.rs
#[derive(Debug, Clone)]
pub enum Permission {
    // Case-level
    CaseCreate,
    CaseView(CaseId),
    CaseManage(CaseId),
    CaseClose(CaseId),

    // Evidence-level
    EvidenceIngest(CaseId),
    EvidenceView(CaseId, EvidenceId),
    EvidenceAnnotate(CaseId, EvidenceId),
    EvidenceExport(CaseId, EvidenceId),
    EvidenceDelete(CaseId, EvidenceId),  // Restricted: audit-logged

    // Analysis-level
    TimelineView(CaseId),
    TimelineAnnotate(CaseId),
    TriageRun(CaseId),
    ReportGenerate(CaseId),

    // Admin
    UserManage,
    SystemConfig,
    AuditView,
}

#[derive(Debug, Clone)]
pub enum Role {
    Admin,
    CaseManager,
    Examiner,
    Reviewer,
    Auditor,
}

impl Role {
    pub fn permissions(&self, case_id: CaseId) -> Vec<Permission> {
        match self {
            Role::Examiner => vec![
                Permission::CaseView(case_id),
                Permission::EvidenceIngest(case_id),
                Permission::EvidenceView(case_id, EvidenceId::All),
                Permission::EvidenceAnnotate(case_id, EvidenceId::All),
                Permission::TimelineView(case_id),
                Permission::TimelineAnnotate(case_id),
                Permission::TriageRun(case_id),
            ],
            // ... other roles
        }
    }
}
```

### Audit Trail Requirements for Legal Admissibility

Every action on evidence MUST be logged immutably:

```rust
// katana-rbac/src/audit.rs
#[derive(Debug, Serialize)]
pub struct AuditEntry {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub actor_id: UserId,
    pub actor_role: Role,
    pub action: AuditAction,
    pub resource_type: ResourceType,  // Case, Evidence, Timeline, etc.
    pub resource_id: String,
    pub details: serde_json::Value,   // Action-specific metadata
    pub source_ip: IpAddr,
    pub session_id: Uuid,
    pub integrity_hash: String,       // SHA-256 of previous entry + this entry (hash chain)
}

#[derive(Debug, Serialize)]
pub enum AuditAction {
    EvidenceIngested,
    EvidenceViewed,
    EvidenceExported,
    EvidenceAnnotated,
    EvidenceDeleted,        // Requires CaseManager+ role
    TriageExecuted,
    ReportGenerated,
    UserAuthenticated,
    UserAuthFailed,
    PermissionDenied,
    CaseCreated,
    CaseClosed,
    ConfigChanged,
}
```

**Key requirements for legal admissibility:**
1. **Immutable append-only log** -- hash chain linking each entry to the previous one
2. **Tamper detection** -- any modification breaks the hash chain
3. **Timestamp integrity** -- use NTP-synced UTC timestamps
4. **Actor identification** -- every action tied to authenticated user
5. **Non-repudiation** -- user sessions tied to authentication events
6. **Retention policy** -- audit logs retained for 7+ years (configurable)
7. **Export capability** -- audit logs exportable for legal proceedings
8. **Separation of duties** -- auditors cannot modify evidence, examiners cannot modify audit logs

### Multi-Tenancy for MSSP Customers

```
+-------------------------------+
|        Katana-Pro Server      |
|                               |
|  +----------+ +----------+   |
|  | Tenant A | | Tenant B |   |  Logical isolation
|  | (MSSP    | | (Corp    |   |
|  |  Client) | |  Client) |   |
|  +----+-----+ +----+-----+   |
|       |             |        |
|  +----v-------------v----+   |
|  |  Shared Infrastructure |   |
|  |  (compute, storage)   |   |
|  +------------------------+   |
+-------------------------------+
```

**Isolation strategies:**
| Strategy | Pros | Cons | Recommendation |
|----------|------|------|----------------|
| **Database-per-tenant** | Strongest isolation | Operational overhead | For regulated/gov clients |
| **Schema-per-tenant** | Good isolation, shared infra | Migration complexity | Default for MSSP |
| **Row-level security** | Simplest, lowest cost | Weaker isolation | For low-risk tenants |

**For Katana-Pro:** Start with schema-per-tenant using DuckDB's schema support. Tenant ID embedded in every query via middleware.

### MSSP-Specific Requirements

- **Tenant data never co-mingles** -- strict row/schema-level isolation
- **Per-tenant encryption keys** -- each tenant's evidence encrypted with their key
- **Tenant-scoped RBAC** -- roles are per-tenant, not global
- **Data residency** -- support deploying in tenant's region/on-prem
- **Offboarding** -- cryptographic deletion (destroy tenant key = data unrecoverable)

**Sources:**
- [Azure Forensics Chain of Custody Architecture](https://learn.microsoft.com/en-us/azure/architecture/example-scenario/forensics/)
- [RBAC and Audit Logs: Designing for Chain-of-Evidence (Inteliate)](https://www.inteliate.com/post/rolebasedaccesscontrol)
- [Chain of Custody in Digital Forensics (Champlain)](https://online.champlain.edu/blog/chain-custody-digital-forensics)
- [Digital Evidence Chain of Custody SoK (ASU/TPS 2024)](https://sefcom.asu.edu/publications/CoC-SoK-tps2024.pdf)
- [Evidence Chain of Custody Best Practices (Lab Manager)](https://www.labmanager.com/evidence-chain-of-custody-best-practices-building-trust-and-traceability-across-scientific-and-forensic-labs-34564)
- [NIST IR 8006: Cloud Forensics Challenges](https://nvlpubs.nist.gov/nistpubs/ir/2020/NIST.IR.8006.pdf)
- [Forensics-as-a-Service Architecture](https://www.researchgate.net/publication/301553168_Forensics_as_a_Service_Three-Tier_Architecture_for_Cloud_Based_Forensic_Analysis)
- [Chain of Custody with Blockchain](https://papers.academic-conferences.org/index.php/iccws/article/download/2025/1940/7598)

---

## 7. Memory-Mapped I/O Pipeline (Community Tier Performance)

### Recommended Crates

| Crate | Purpose |
|-------|---------|
| `memmap2` | Stable, widely-used mmap (successor to `memmap`) |
| `mmap-rs` (TIVerse) | Huge page support, prefaulting, advanced features |
| `zerocopy` | Zero-copy deserialization of binary structures |
| `rayon` | Data parallelism for multi-core processing |
| `duckdb` | Analytical query engine for timeline storage |
| `tantivy` | Full-text search indexing |

### Pipeline Architecture (35s Budget)

```
E01 Image (disk)
    |
    v  mmap (memmap2, huge pages if available)
[Memory-Mapped Evidence]
    |
    v  Zero-copy parsing (zerocopy + custom parsers)
[Parsed Artifacts: MFT, USN, EVTX, Registry]
    |
    v  rayon parallel iterator
[Triage Evaluation] -- apply 20-30 triage questions per event
    |
    v  Streaming insert
[DuckDB Timeline + tantivy index]
    |
    v
[Triage Report Output]
```

**Performance targets:**
- Parse rate: 100k+ events/second
- Memory: bounded by mmap window, not full image size
- CPU: saturate all available cores via rayon
- I/O: sequential reads via mmap with OS readahead

### Rust Forensic Ecosystem

| Project | What It Does |
|---------|-------------|
| **ForensicRS** | Framework with trait-based artifact abstraction |
| **Artemis** | Cross-platform DFIR collector (Windows/macOS/Linux) |
| **Zff** | Alternative to E01/AFF formats, pure Rust, faster than ewf |
| **AVML** | Volatile memory acquisition, static binary |

**E01 parsing:** No pure-Rust E01 parser exists. Options:
1. FFI bindings to `libewf` (C library) -- pragmatic, proven
2. Pure Rust implementation -- significant effort but eliminates C dependency
3. Support Zff natively + E01 via libewf -- recommended hybrid approach

**Sources:**
- [memmap2 Crate](https://docs.rs/memmap/latest/memmap/struct.Mmap.html)
- [mmap-rs (TIVerse)](https://github.com/TIVerse/mmap-rs)
- [mmap-sync (Cloudflare)](https://github.com/cloudflare/mmap-sync)
- [Advanced Memory Mapping in Rust](https://medium.com/@FAANG/advanced-memory-mapping-in-rust-the-hidden-superpower-for-high-performance-systems-a47679aa205e)
- [ForensicRS](https://lib.rs/crates/forensic-rs)
- [Artemis](https://github.com/puffyCid/artemis)
- [Zff Format](https://lib.rs/crates/zff)
- [Forensic Tool Development with Rust](https://blog.getreu.net/projects/forensic-tool-development-with-rust/)
- [DFRWS: Python to Rust for Forensic Tools](https://dfrws.org/presentation/transitioning-from-python-to-rust-for-forensic-tool-creation/)
- [ForensicRS GitHub](https://github.com/ForensicRS)
- [Rust for Forensics Forum](https://users.rust-lang.org/t/rust-for-forensics-also-accessing-bytes-on-a-raw-disk/21353)

---

## Architecture Decision Summary

| Decision | Recommendation | Rationale |
|----------|---------------|-----------|
| **Repo structure** | Two repos, two workspaces, path dependencies | Clean license separation, solo dev manageable |
| **Type sharing** | Trait-based core crate (Apache-2.0) | Enterprise extends via trait impls, no code leakage |
| **Agent comms** | gRPC via tonic + mTLS via rustls | Streaming, type-safe, Rust-native, no OpenSSL |
| **Agent updates** | self_update crate + custom signed update server | Self-contained, cryptographically verified |
| **Timeline storage** | DuckDB (analytical) + tantivy (full-text) | No server process, fast, Rust-native search |
| **Evidence format** | Zff native + E01 via libewf FFI | Pragmatic: pure Rust where possible, FFI for legacy |
| **RBAC** | Case-level + evidence-level permissions | Meets legal admissibility requirements |
| **Audit trail** | Append-only hash chain log | Tamper-evident, legally defensible |
| **Multi-tenancy** | Schema-per-tenant in DuckDB | Good isolation without operational burden |
| **Correlation** | Batch (community) + streaming (enterprise) | Matches tier performance requirements |
| **Mmap pipeline** | memmap2 + zerocopy + rayon | Hits 35s budget on single-device examination |
