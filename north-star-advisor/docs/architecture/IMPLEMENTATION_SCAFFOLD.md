# Security Ronin Katana: Implementation Scaffold

> **Parent**: [ARCHITECTURE_BLUEPRINT.md](../ARCHITECTURE_BLUEPRINT.md)
> **Created**: 2026-03-10
> **Status**: Active

Directory structure, shared trait definitions, pipeline stage implementations, API routes, and configuration for the Katana two-repo Cargo workspace.

---

## 1. Directory Structure

Katana uses a two-repository open-core model. The community repo (`katana`) contains all forensic parsing logic under Apache-2.0. The enterprise repo (`katana-pro`) adds server, collaboration, and network forensics under a proprietary license. Both repos are Cargo workspaces that link via path dependencies during local development and git dependencies in CI.

```
# ── Community Repository: katana (Apache-2.0) ──────────────────────────

katana/
├── Cargo.toml                        # Workspace root
├── LICENSE-APACHE                    # Apache-2.0
├── deny.toml                         # cargo-deny configuration
├── .github/
│   └── workflows/
│       ├── ci.yml                    # Test, clippy, fmt, audit
│       ├── release.yml               # Binary packaging + crates.io
│       └── bench.yml                 # Criterion benchmarks on PR
│
├── crates/
│   ├── katana-core/                  # Shared types, traits, parsers
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── traits/
│   │       │   ├── mod.rs
│   │       │   ├── evidence_source.rs    # EvidenceSource trait
│   │       │   ├── triage_engine.rs      # TriageEngine trait
│   │       │   └── output_sink.rs        # OutputSink trait
│   │       ├── types/
│   │       │   ├── mod.rs
│   │       │   ├── record.rs             # UsnRecord, MftEntry, TimelineEvent
│   │       │   ├── evidence.rs           # EvidenceMetadata, VolumeInfo
│   │       │   ├── triage.rs             # TriageResult, Severity, TriageQuestion
│   │       │   └── error.rs             # KatanaError enum
│   │       ├── usn/
│   │       │   ├── mod.rs
│   │       │   ├── parser.rs             # USN V2/V3/V4 record parsing
│   │       │   ├── carver.rs             # Journal carving from raw bytes
│   │       │   └── reason.rs             # USN reason flag decoding
│   │       ├── mft/
│   │       │   ├── mod.rs
│   │       │   ├── parser.rs             # MFT entry parsing
│   │       │   └── attributes.rs         # $STANDARD_INFORMATION, $FILE_NAME
│   │       ├── rewind/
│   │       │   ├── mod.rs
│   │       │   └── resolver.rs           # Full path reconstruction via journal rewind
│   │       ├── correlation/
│   │       │   ├── mod.rs
│   │       │   └── quadlink.rs           # Cross-artifact correlation engine
│   │       ├── triage/
│   │       │   ├── mod.rs
│   │       │   ├── engine.rs             # Rule evaluation engine
│   │       │   └── queries.rs            # Built-in triage questions
│   │       └── timeline/
│   │           ├── mod.rs
│   │           └── builder.rs            # Unified timeline construction
│   │
│   ├── katana-cli/                   # Community CLI binary
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs
│   │       ├── args.rs                   # clap argument definitions
│   │       ├── commands/
│   │       │   ├── mod.rs
│   │       │   ├── triage.rs             # katana triage <image>
│   │       │   ├── parse.rs              # katana parse <image>
│   │       │   ├── timeline.rs           # katana timeline <image>
│   │       │   └── verify.rs             # katana verify <report>
│   │       └── progress.rs              # indicatif progress bars
│   │
│   ├── katana-formats/               # Output formatters
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── csv.rs                    # CSV output (default)
│   │       ├── json.rs                   # JSON/JSONL output
│   │       ├── bodyfile.rs               # Sleuthkit bodyfile format
│   │       ├── tln.rs                    # 5-field TLN format
│   │       ├── xml.rs                    # DFXML output
│   │       ├── sqlite.rs                # SQLite output
│   │       └── report.rs                # Triage report (Markdown + HTML)
│   │
│   ├── katana-ewf/                   # E01/raw disk image handling
│   │   ├── Cargo.toml
│   │   ├── build.rs                      # libewf-sys FFI build script
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── reader.rs                 # EwfReader: seekable byte stream
│   │       ├── metadata.rs              # Image metadata extraction
│   │       └── raw.rs                    # Raw/dd image fallback
│   │
│   └── katana-ntfs/                  # NTFS filesystem parsing
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── volume.rs                 # NTFS volume header parsing
│           ├── mft.rs                    # $MFT location and streaming
│           ├── usnjrnl.rs               # $UsnJrnl:$J extraction
│           ├── logfile.rs               # $LogFile parsing
│           └── partition.rs             # GPT/MBR partition discovery
│
├── tests/
│   ├── integration/
│   │   ├── pipeline_e2e.rs               # Full pipeline: E01 -> triage report
│   │   ├── image_integration.rs          # Real E01 image parsing
│   │   └── report_integration.rs         # Report generation verification
│   └── corpus/                           # Test images (git-lfs)
│       ├── small.e01                     # 50MB test image
│       └── README.md                     # Corpus provenance documentation
│
├── benches/
│   ├── parse_throughput.rs               # Events/second benchmark
│   └── triage_latency.rs                # End-to-end latency benchmark
│
└── docs/
    └── daubert/                          # Daubert compliance packet
        ├── methodology.md
        ├── precision_recall.html
        └── test_corpus.md


# ── Enterprise Repository: katana-pro (Proprietary) ────────────────────

katana-pro/
├── Cargo.toml                        # Workspace root
├── LICENSE                           # Proprietary
├── deny.toml                         # cargo-deny (stricter: no GPL)
├── proto/
│   └── agent/
│       └── v1/
│           ├── agent.proto               # Agent <-> Server gRPC service
│           └── evidence.proto            # Evidence submission messages
│
├── .github/
│   └── workflows/
│       ├── ci.yml                    # Test, clippy, audit, integration
│       ├── release.yml               # Docker images + binary packaging
│       └── agent-release.yml         # Standalone agent binary
│
├── crates/
│   ├── katana-server/                # Enterprise API server
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs
│   │       ├── app.rs                    # Axum router assembly
│   │       ├── config.rs                 # Environment-based configuration
│   │       ├── api/
│   │       │   ├── mod.rs
│   │       │   ├── cases.rs              # POST/GET/PUT /api/v1/cases
│   │       │   ├── evidence.rs           # POST /api/v1/evidence/upload
│   │       │   ├── triage.rs             # POST /api/v1/triage/run
│   │       │   ├── timeline.rs           # GET /api/v1/timeline/:case_id
│   │       │   ├── search.rs             # POST /api/v1/search
│   │       │   └── health.rs             # GET /health, GET /ready
│   │       ├── grpc/
│   │       │   ├── mod.rs
│   │       │   ├── agent_service.rs      # AgentService gRPC implementation
│   │       │   └── evidence_service.rs   # EvidenceService gRPC implementation
│   │       ├── middleware/
│   │       │   ├── mod.rs
│   │       │   ├── auth.rs               # JWT validation (Tower layer)
│   │       │   ├── rbac.rs               # Role-based access control
│   │       │   ├── tenant.rs             # Tenant extraction + isolation
│   │       │   ├── audit.rs              # Hash-chain audit logging
│   │       │   └── rate_limit.rs         # governor-based rate limiting
│   │       ├── db/
│   │       │   ├── mod.rs
│   │       │   ├── postgres.rs           # sqlx PostgreSQL connection pool
│   │       │   ├── duckdb.rs             # DuckDB per-tenant forensic data
│   │       │   └── migrations/           # sqlx migrations
│   │       └── ws/
│   │           ├── mod.rs
│   │           └── collab.rs             # WebSocket collaboration hub
│   │
│   ├── katana-agent/                 # Remote collection agent
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs
│   │       ├── collector.rs              # Evidence collection + hashing
│   │       ├── uploader.rs               # gRPC streaming upload
│   │       ├── tls.rs                    # mTLS + certificate pinning
│   │       └── heartbeat.rs             # Health reporting to server
│   │
│   ├── katana-pcap/                  # PCAP/NetFlow analysis
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── pcap_source.rs            # impl EvidenceSource for PcapSource
│   │       ├── netflow_source.rs         # impl EvidenceSource for NetFlowSource
│   │       ├── reassembly.rs             # TCP stream reassembly
│   │       └── protocol.rs              # Protocol identification
│   │
│   ├── katana-collab/                # Collaborative investigation
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── session.rs                # Investigation session management
│   │       ├── presence.rs               # User presence tracking
│   │       ├── annotations.rs           # Evidence annotations
│   │       └── broadcast.rs             # WebSocket pub/sub broadcaster
│   │
│   ├── katana-import/                # Third-party tool importers
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── velociraptor.rs           # Velociraptor artifact import
│   │       ├── binalyze.rs              # Binalyze AIR import
│   │       └── generic_csv.rs           # Generic CSV timeline import
│   │
│   └── katana-multi/                 # Multi-device correlation
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── correlator.rs             # Cross-device event correlation
│           ├── timeline_merge.rs         # Multi-source timeline merging
│           └── scoring.rs               # Correlation confidence scoring
│
├── tests/
│   ├── integration/
│   │   ├── api_e2e.rs                    # Full API lifecycle tests
│   │   ├── agent_e2e.rs                  # Agent connection + upload tests
│   │   ├── rbac_test.rs                  # Permission boundary tests
│   │   └── multi_tenant.rs              # Tenant isolation verification
│   └── fixtures/
│       ├── test_certs/                   # mTLS test certificates
│       └── sample_pcaps/                # Test PCAP files
│
└── docker/
    ├── Dockerfile.server                 # Multi-stage server build
    ├── Dockerfile.agent                  # Minimal agent image (<5MB)
    └── docker-compose.yml               # Full stack: server + postgres + duckdb
```

---

## 2. Shared Trait Definitions

All pipeline stages in both community and enterprise repos implement one of three traits defined in `katana-core`. These traits form the extension boundary that allows enterprise crates to plug into the same pipeline without modifying community code.

### 2.1 EvidenceSource Trait

```rust
// katana-core/src/traits/evidence_source.rs

use crate::types::{
    error::KatanaError,
    evidence::{EvidenceMetadata, ParsedArtifacts},
};
use std::path::Path;

/// Represents a source of forensic evidence that can be parsed into artifacts.
///
/// Implementors: katana-ewf (E01/raw images), katana-ntfs (NTFS volumes),
///               katana-pcap (PCAP files), katana-import (third-party tools)
pub trait EvidenceSource: Send + Sync {
    /// Human-readable name for logging and audit trails.
    /// Example: "EWF Parser", "PCAP Analyzer", "Velociraptor Importer"
    fn name(&self) -> &str;

    /// Parse the evidence at the given path, producing structured artifacts.
    ///
    /// Implementations must:
    /// - Compute SHA-256 hash of input before any parsing (Axiom 1: Forensic Integrity)
    /// - Emit structured errors via KatanaError, never panic
    /// - Respect the memory budget (stream large files, do not buffer entirely)
    /// - Record provenance metadata (source path, hash, parse timestamp)
    fn parse(&self, path: &Path, metadata: &EvidenceMetadata) -> Result<ParsedArtifacts, KatanaError>;

    /// Returns the file extensions this source can handle.
    /// Used by the CLI and server to route evidence to the correct parser.
    fn supported_extensions(&self) -> &[&str];

    /// Optional: estimate parse duration for progress reporting.
    /// Default returns None (indeterminate progress bar).
    fn estimated_duration_secs(&self, file_size_bytes: u64) -> Option<f64> {
        let _ = file_size_bytes;
        None
    }
}
```

### 2.2 TriageEngine Trait

```rust
// katana-core/src/traits/triage_engine.rs

use crate::types::{
    error::KatanaError,
    record::TimelineEvent,
    triage::{TriageQuestion, TriageResult},
};

/// Evaluates forensic events against triage questions to produce scored results.
///
/// The engine applies a set of questions (pattern-based rules) against parsed
/// timeline events and produces severity-scored results. Each question targets
/// specific forensic indicators (ransomware staging, lateral movement, etc.).
pub trait TriageEngine: Send + Sync {
    /// Evaluate a batch of timeline events against all active triage questions.
    ///
    /// Returns one TriageResult per event that matched at least one question.
    /// Non-matching events are excluded from results (not scored zero).
    ///
    /// Implementations must:
    /// - Process events in parallel where possible (rayon)
    /// - Track per-question precision/recall metadata
    /// - Never modify the input events (read-only evaluation)
    fn evaluate(
        &self,
        events: &[TimelineEvent],
        questions: &[TriageQuestion],
    ) -> Result<Vec<TriageResult>, KatanaError>;

    /// Returns the set of built-in triage questions this engine supports.
    fn default_questions(&self) -> Vec<TriageQuestion>;

    /// Validate a custom question definition before adding it to the active set.
    fn validate_question(&self, question: &TriageQuestion) -> Result<(), KatanaError>;
}
```

### 2.3 OutputSink Trait

```rust
// katana-core/src/traits/output_sink.rs

use crate::types::{
    error::KatanaError,
    record::TimelineEvent,
    triage::TriageResult,
    evidence::EvidenceMetadata,
};
use std::io::Write;

/// Emits forensic results to a specific output format.
///
/// Implementors: katana-formats (CSV, JSON, bodyfile, TLN, XML, SQLite, report)
/// Enterprise sinks: DuckDB insert, tantivy index, WebSocket broadcast
pub trait OutputSink: Send + Sync {
    /// Human-readable format name for CLI --format flag.
    /// Example: "csv", "json", "bodyfile", "tln", "sqlite", "report"
    fn format_name(&self) -> &str;

    /// Emit a batch of timeline events to the output.
    ///
    /// Implementations must:
    /// - Stream output (do not buffer all events in memory)
    /// - Include evidence provenance in output headers/metadata
    /// - Flush on completion (caller should not need to flush)
    fn emit(
        &self,
        writer: &mut dyn Write,
        events: &[TimelineEvent],
        triage_results: &[TriageResult],
        metadata: &EvidenceMetadata,
    ) -> Result<(), KatanaError>;

    /// Returns the default file extension for this format.
    /// Used by CLI to auto-name output files when --output is a directory.
    fn default_extension(&self) -> &str;

    /// Whether this sink supports streaming (line-by-line) output.
    /// Sinks that return true will receive events incrementally via emit().
    /// Sinks that return false receive all events in a single emit() call.
    fn supports_streaming(&self) -> bool {
        true
    }
}
```

### 2.4 Default Constants

```rust
// katana-core/src/types/mod.rs (re-exported constants)

/// Pipeline latency budgets per stage (seconds).
/// Total budget: 35s P95 for a 1GB E01 image.
pub mod budgets {
    pub const EWF_PARSER_BUDGET_SECS: u64 = 2;
    pub const NTFS_VOLUME_BUDGET_SECS: u64 = 1;
    pub const USN_PARSER_BUDGET_SECS: u64 = 5;
    pub const MFT_PARSER_BUDGET_SECS: u64 = 5;
    pub const PATH_RESOLVER_BUDGET_SECS: u64 = 5;
    pub const TRIAGE_ENGINE_BUDGET_SECS: u64 = 5;
    pub const OUTPUT_FORMATTER_BUDGET_SECS: u64 = 3;
    pub const CORRELATION_BUDGET_SECS: u64 = 5;
    pub const OVERHEAD_BUDGET_SECS: u64 = 4;
    pub const TOTAL_BUDGET_SECS: u64 = 35;
}

/// Parse throughput targets.
pub mod throughput {
    pub const MIN_EVENTS_PER_SECOND: u64 = 100_000;
    pub const TARGET_EVENTS_PER_SECOND: u64 = 200_000;
}

/// Enterprise agent constraints.
pub mod agent {
    pub const MAX_BINARY_SIZE_MB: u64 = 5;
    pub const MAX_COLD_START_MS: u64 = 50;
    pub const HEARTBEAT_INTERVAL_SECS: u64 = 30;
}
```

---

## 3. Pipeline Stage Implementations

### 3.1 Community Pipeline (Sequential with Parallel Inner Stages)

The community pipeline processes a single forensic image through seven stages. Stages 3 and 4 (USN parsing and MFT parsing) run in parallel via rayon since they operate on independent byte ranges. All other stages execute sequentially.

```rust
// katana-cli/src/commands/triage.rs

use katana_core::{
    budgets,
    traits::{EvidenceSource, TriageEngine, OutputSink},
    types::{evidence::EvidenceMetadata, error::KatanaError},
};
use katana_ewf::EwfSource;
use katana_ntfs::NtfsVolume;
use std::time::Instant;

pub fn run_triage(args: &TriageArgs) -> Result<(), KatanaError> {
    let total_start = Instant::now();

    // Stage 1: EWF Parser (budget: 2s)
    // Read E01/raw disk image, expose seekable byte stream
    let ewf = EwfSource::new();
    let evidence_meta = EvidenceMetadata::from_path(&args.image_path)?;
    let parsed_image = ewf.parse(&args.image_path, &evidence_meta)?;
    log_stage_timing("ewf_parser", total_start.elapsed(), budgets::EWF_PARSER_BUDGET_SECS);

    // Stage 2: NTFS Volume (budget: 1s)
    // Parse NTFS structures, locate $MFT and $UsnJrnl:$J
    let ntfs = NtfsVolume::new();
    let volumes = ntfs.discover_volumes(&parsed_image)?;
    log_stage_timing("ntfs_volume", total_start.elapsed(), budgets::NTFS_VOLUME_BUDGET_SECS);

    // Stage 3 + 4: USN Parser + MFT Parser (parallel, budget: 5s each)
    // These stages operate on independent byte ranges and run concurrently
    let (usn_records, mft_entries) = rayon::join(
        || {
            let usn_parser = katana_core::usn::UsnParser::new();
            usn_parser.parse_journal(&volumes.usnjrnl_data, &volumes.volume_info)
        },
        || {
            let mft_parser = katana_core::mft::MftParser::new();
            mft_parser.parse_entries(&volumes.mft_data)
        },
    );
    let usn_records = usn_records?;
    let mft_entries = mft_entries?;

    // Stage 5: Path Resolver (budget: 5s)
    // Reconstruct full file paths via journal rewind algorithm
    let resolver = katana_core::rewind::PathResolver::new();
    let resolved_events = resolver.resolve(&usn_records, &mft_entries)?;

    // Stage 6: Triage Engine (budget: 5s)
    // Evaluate events against triage questions, produce scored results
    let engine = katana_core::triage::DefaultTriageEngine::new();
    let questions = engine.default_questions();
    let triage_results = engine.evaluate(&resolved_events, &questions)?;

    // Stage 7: Output Formatter (budget: 3s)
    // Emit results in the requested format
    let sink = resolve_output_sink(&args.format)?;
    let mut writer = open_output(&args.output)?;
    sink.emit(&mut writer, &resolved_events, &triage_results, &evidence_meta)?;

    let total_elapsed = total_start.elapsed();
    eprintln!(
        "Triage complete: {} events, {} findings, {:.1}s",
        resolved_events.len(),
        triage_results.len(),
        total_elapsed.as_secs_f64()
    );

    Ok(())
}
```

### 3.2 Enterprise Pipeline Extensions

Enterprise stages plug into the same trait system. The server orchestrates community pipeline stages plus enterprise-specific stages (PCAP, multi-device correlation, import adapters).

```rust
// katana-server/src/api/triage.rs

use axum::{extract::State, Json};
use katana_core::traits::EvidenceSource;
use katana_pcap::PcapSource;
use katana_import::{VelociraptorImporter, BinalyzeImporter};
use katana_multi::MultiDeviceCorrelator;

/// POST /api/v1/triage/run
///
/// Accepts evidence (disk images, PCAPs, third-party exports) and runs
/// the full triage pipeline with enterprise extensions.
pub async fn run_triage(
    State(app): State<AppState>,
    Json(request): Json<TriageRequest>,
) -> Result<Json<TriageResponse>, ApiError> {
    // Verify RBAC: requires Examiner role or higher
    // (enforced by middleware, but double-check for defense in depth)

    let tenant_id = app.tenant_id();
    let case_id = request.case_id;

    // Route evidence to the correct source based on type
    let source: Box<dyn EvidenceSource> = match request.evidence_type {
        EvidenceType::DiskImage => Box::new(katana_ewf::EwfSource::new()),
        EvidenceType::Pcap => Box::new(PcapSource::new()),
        EvidenceType::Velociraptor => Box::new(VelociraptorImporter::new()),
        EvidenceType::Binalyze => Box::new(BinalyzeImporter::new()),
    };

    // Run community pipeline stages (same code path as CLI)
    let pipeline_result = app
        .pipeline_runner
        .run(source.as_ref(), &request.evidence_path)
        .await?;

    // Enterprise extension: multi-device correlation
    if request.correlate_devices {
        let correlator = MultiDeviceCorrelator::new();
        let correlated = correlator
            .correlate(case_id, tenant_id, &pipeline_result.events)
            .await?;
        pipeline_result.extend_events(correlated);
    }

    // Store results in tenant-isolated DuckDB
    app.duckdb
        .insert_events(tenant_id, case_id, &pipeline_result.events)
        .await?;

    // Index in tantivy for full-text search
    app.search_index
        .index_events(tenant_id, case_id, &pipeline_result.events)
        .await?;

    // Audit log entry (hash-chain append)
    app.audit
        .log_action(tenant_id, AuditAction::TriageRun { case_id })
        .await?;

    Ok(Json(TriageResponse {
        case_id,
        events_processed: pipeline_result.events.len(),
        findings: pipeline_result.triage_results.len(),
        timeline_url: format!("/api/v1/timeline/{}", case_id),
    }))
}
```

### 3.3 Collection Agent

The remote collection agent is a minimal gRPC client that runs on endpoint machines, collects evidence, and streams it to the server with integrity verification.

```rust
// katana-agent/src/main.rs

use katana_agent::{collector::EvidenceCollector, uploader::GrpcUploader, tls::MtlsConfig};
use std::time::Duration;
use tokio::time;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = katana_agent::config::load()?;

    // Establish mTLS connection with certificate pinning
    let tls = MtlsConfig::from_paths(
        &config.client_cert,
        &config.client_key,
        &config.ca_cert,
        &config.pinned_server_fingerprint,
    )?;

    let uploader = GrpcUploader::connect(&config.server_url, tls).await?;

    // Start heartbeat loop
    let heartbeat_handle = tokio::spawn({
        let uploader = uploader.clone();
        async move {
            let mut interval = time::interval(Duration::from_secs(
                katana_core::agent::HEARTBEAT_INTERVAL_SECS,
            ));
            loop {
                interval.tick().await;
                let _ = uploader.heartbeat().await;
            }
        }
    });

    // Collect and stream evidence
    let collector = EvidenceCollector::new();
    for evidence_path in &config.evidence_paths {
        let stream = collector.collect_and_hash(evidence_path)?;
        uploader.stream_evidence(stream).await?;
    }

    heartbeat_handle.abort();
    Ok(())
}
```

---

## 4. API Routes

### 4.1 REST API (Axum)

```rust
// katana-server/src/app.rs

use axum::{
    middleware,
    routing::{get, post, put},
    Router,
};
use tower_http::{
    compression::CompressionLayer,
    cors::CorsLayer,
    trace::TraceLayer,
};

pub fn build_router(state: AppState) -> Router {
    let api_v1 = Router::new()
        // Case management
        .route("/cases", post(api::cases::create))
        .route("/cases", get(api::cases::list))
        .route("/cases/:id", get(api::cases::get))
        .route("/cases/:id", put(api::cases::update))
        // Evidence handling
        .route("/evidence/upload", post(api::evidence::upload))
        .route("/evidence/:id/status", get(api::evidence::status))
        // Triage execution
        .route("/triage/run", post(api::triage::run_triage))
        .route("/triage/:case_id/results", get(api::triage::results))
        // Timeline and search
        .route("/timeline/:case_id", get(api::timeline::get))
        .route("/search", post(api::search::query))
        // Apply auth + RBAC + tenant + audit middleware
        .layer(middleware::from_fn_with_state(
            state.clone(),
            middleware::auth::validate_jwt,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            middleware::tenant::extract_tenant,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            middleware::audit::log_request,
        ));

    Router::new()
        .nest("/api/v1", api_v1)
        // Health endpoints (no auth required)
        .route("/health", get(api::health::health))
        .route("/ready", get(api::health::ready))
        // WebSocket for collaboration (auth handled at upgrade)
        .route("/ws/collab/:case_id", get(ws::collab::upgrade))
        // Global middleware
        .layer(CompressionLayer::new().zstd(true))
        .layer(CorsLayer::permissive()) // Tightened per-deployment via config
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn(middleware::rate_limit::check))
        .with_state(state)
}
```

### 4.2 gRPC Service (Tonic)

```rust
// katana-server/src/grpc/agent_service.rs

use tonic::{Request, Response, Status, Streaming};
use crate::proto::agent::v1::{
    agent_service_server::AgentService,
    HeartbeatRequest, HeartbeatResponse,
    EvidenceChunk, UploadResponse,
};

pub struct AgentServiceImpl {
    db: DatabasePool,
    audit: AuditLogger,
}

#[tonic::async_trait]
impl AgentService for AgentServiceImpl {
    /// Receive streaming evidence upload from remote agent.
    /// Verifies mTLS identity, computes running SHA-256 hash,
    /// writes to tenant-isolated storage.
    async fn upload_evidence(
        &self,
        request: Request<Streaming<EvidenceChunk>>,
    ) -> Result<Response<UploadResponse>, Status> {
        let agent_id = extract_agent_id_from_mtls(&request)?;
        let tenant_id = self.resolve_tenant(agent_id).await?;
        let mut stream = request.into_inner();
        let mut hasher = sha2::Sha256::new();
        let mut total_bytes: u64 = 0;

        let storage_path = self.db.allocate_evidence_path(tenant_id).await
            .map_err(|e| Status::internal(e.to_string()))?;

        let mut file = tokio::fs::File::create(&storage_path).await
            .map_err(|e| Status::internal(e.to_string()))?;

        while let Some(chunk) = stream.message().await? {
            hasher.update(&chunk.data);
            total_bytes += chunk.data.len() as u64;
            tokio::io::AsyncWriteExt::write_all(&mut file, &chunk.data).await
                .map_err(|e| Status::internal(e.to_string()))?;
        }

        let hash = format!("{:x}", hasher.finalize());

        self.audit.log_action(
            tenant_id,
            AuditAction::EvidenceUploaded {
                agent_id,
                hash: hash.clone(),
                bytes: total_bytes,
            },
        ).await.map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(UploadResponse {
            evidence_id: storage_path.to_string_lossy().to_string(),
            sha256: hash,
            bytes_received: total_bytes,
        }))
    }

    /// Agent heartbeat. Updates last-seen timestamp, returns server status.
    async fn heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatResponse>, Status> {
        let agent_id = extract_agent_id_from_mtls(&request)?;
        let req = request.into_inner();

        self.db.update_agent_heartbeat(agent_id, &req.system_info).await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(HeartbeatResponse {
            server_time: chrono::Utc::now().timestamp(),
            pending_tasks: 0,
        }))
    }
}
```

### 4.3 Health Check

```rust
// katana-server/src/api/health.rs

use axum::Json;
use serde::Serialize;

#[derive(Serialize)]
pub struct HealthResponse {
    status: &'static str,
    version: &'static str,
    uptime_secs: u64,
}

#[derive(Serialize)]
pub struct ReadyResponse {
    postgres: bool,
    duckdb: bool,
    search_index: bool,
}

/// GET /health -- liveness probe, always returns 200 if process is running.
pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        uptime_secs: crate::UPTIME.elapsed().as_secs(),
    })
}

/// GET /ready -- readiness probe, verifies all dependencies are connected.
pub async fn ready(
    State(app): State<AppState>,
) -> Result<Json<ReadyResponse>, StatusCode> {
    let pg = app.postgres.ping().await.is_ok();
    let duck = app.duckdb.ping().await.is_ok();
    let search = app.search_index.is_ready();

    let response = ReadyResponse {
        postgres: pg,
        duckdb: duck,
        search_index: search,
    };

    if pg && duck && search {
        Ok(Json(response))
    } else {
        Err(StatusCode::SERVICE_UNAVAILABLE)
    }
}
```

---

## 5. Configuration

### 5.1 Environment Variables

```bash
# -- Community CLI -----------------------------------------------------------
# No environment variables required. Fully offline, zero configuration.
# All settings via CLI flags: katana triage --format csv --output report.csv image.e01

# -- Enterprise Server -------------------------------------------------------

# Database
KATANA_POSTGRES_URL=postgresql://katana:secret@localhost:5432/katana
KATANA_DUCKDB_DIR=/var/lib/katana/duckdb           # Per-tenant DuckDB files

# Authentication
KATANA_JWT_SECRET=<256-bit secret>                  # JWT signing key
KATANA_JWT_ISSUER=https://auth.example.com          # OIDC issuer URL
KATANA_JWT_AUDIENCE=katana-server                   # Expected audience claim

# gRPC / Agent Communication
KATANA_GRPC_PORT=50051                              # Agent gRPC listen port
KATANA_GRPC_TLS_CERT=/etc/katana/tls/server.crt    # Server TLS certificate
KATANA_GRPC_TLS_KEY=/etc/katana/tls/server.key      # Server TLS private key
KATANA_GRPC_CA_CERT=/etc/katana/tls/ca.crt          # CA for agent client certs

# Search
KATANA_TANTIVY_DIR=/var/lib/katana/tantivy          # Full-text search index
KATANA_TANTIVY_HEAP_MB=256                          # Writer heap size

# Observability
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317   # OpenTelemetry collector
OTEL_SERVICE_NAME=katana-server
KATANA_LOG_LEVEL=info                               # tracing subscriber level
KATANA_LOG_FORMAT=json                              # json | pretty

# Rate Limiting
KATANA_RATE_LIMIT_RPS=100                           # Requests per second per tenant
KATANA_RATE_LIMIT_BURST=200                         # Burst capacity

# Server
KATANA_HTTP_PORT=8080                               # REST API listen port
KATANA_WS_MAX_CONNECTIONS=1000                      # WebSocket connection limit

# -- Collection Agent --------------------------------------------------------
KATANA_AGENT_SERVER_URL=https://katana.example.com:50051
KATANA_AGENT_CLIENT_CERT=/etc/katana/agent/client.crt
KATANA_AGENT_CLIENT_KEY=/etc/katana/agent/client.key
KATANA_AGENT_CA_CERT=/etc/katana/agent/ca.crt
KATANA_AGENT_PINNED_FINGERPRINT=sha256:AB12CD34...  # Server cert fingerprint
```

### 5.2 Configuration Validation

```rust
// katana-server/src/config.rs

use serde::Deserialize;
use std::path::PathBuf;

#[derive(Deserialize)]
pub struct ServerConfig {
    // Database
    pub postgres_url: String,
    pub duckdb_dir: PathBuf,

    // Auth
    pub jwt_secret: String,
    pub jwt_issuer: String,
    pub jwt_audience: String,

    // gRPC
    pub grpc_port: u16,
    pub grpc_tls_cert: PathBuf,
    pub grpc_tls_key: PathBuf,
    pub grpc_ca_cert: PathBuf,

    // Search
    pub tantivy_dir: PathBuf,
    pub tantivy_heap_mb: u32,

    // Server
    pub http_port: u16,
    pub log_level: String,
    pub log_format: LogFormat,
    pub rate_limit_rps: u32,
    pub rate_limit_burst: u32,
    pub ws_max_connections: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Json,
    Pretty,
}

impl ServerConfig {
    /// Load configuration from environment variables with KATANA_ prefix.
    /// Validates all required fields and file paths before returning.
    pub fn from_env() -> Result<Self, ConfigError> {
        let config = envy::prefixed("KATANA_").from_env::<ServerConfig>()?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        // Verify TLS certificate files exist and are readable
        for path in [&self.grpc_tls_cert, &self.grpc_tls_key, &self.grpc_ca_cert] {
            if !path.exists() {
                return Err(ConfigError::MissingFile(path.clone()));
            }
        }

        // Verify DuckDB and tantivy directories are writable
        for dir in [&self.duckdb_dir, &self.tantivy_dir] {
            std::fs::create_dir_all(dir)
                .map_err(|e| ConfigError::DirectoryCreate(dir.clone(), e))?;
        }

        // Validate JWT secret length (minimum 256 bits)
        if self.jwt_secret.len() < 32 {
            return Err(ConfigError::WeakJwtSecret);
        }

        // Validate port ranges
        if self.http_port == 0 || self.grpc_port == 0 {
            return Err(ConfigError::InvalidPort);
        }

        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ConfigError {
    #[error("Missing environment variable: {0}")]
    MissingEnv(#[from] envy::Error),

    #[error("TLS file not found: {0}")]
    MissingFile(PathBuf),

    #[error("Cannot create directory {0}: {1}")]
    DirectoryCreate(PathBuf, std::io::Error),

    #[error("JWT secret must be at least 32 bytes (256 bits)")]
    WeakJwtSecret,

    #[error("Port must be non-zero")]
    InvalidPort,
}
```

---

## 6. Cargo.toml Configurations

### 6.1 Community Workspace Root

```toml
# katana/Cargo.toml

[workspace]
resolver = "2"
members = [
    "crates/katana-core",
    "crates/katana-cli",
    "crates/katana-formats",
    "crates/katana-ewf",
    "crates/katana-ntfs",
]

[workspace.package]
edition = "2021"
license = "Apache-2.0"
repository = "https://github.com/SecurityRonin/katana"
authors = ["Albert Hui <albert@securityronin.com>"]

[workspace.dependencies]
# Shared across community crates
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"
anyhow = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
chrono = { version = "0.4", features = ["serde"] }
rayon = "1.10"
sha2 = "0.10"
memmap2 = "0.9"
byteorder = "1"
clap = { version = "4", features = ["derive"] }
indicatif = "0.17"
rusqlite = { version = "0.32", features = ["bundled"] }

# Internal crate dependencies
katana-core = { path = "crates/katana-core" }
katana-formats = { path = "crates/katana-formats" }
katana-ewf = { path = "crates/katana-ewf" }
katana-ntfs = { path = "crates/katana-ntfs" }

[workspace.lints.rust]
unsafe_code = "deny"
missing_docs = "warn"

[workspace.lints.clippy]
pedantic = { level = "warn", priority = -1 }
unwrap_used = "deny"
expect_used = "warn"

[profile.release]
lto = "fat"
codegen-units = 1
strip = true
panic = "abort"
opt-level = 3
```

### 6.2 katana-core Crate

```toml
# katana/crates/katana-core/Cargo.toml

[package]
name = "katana-core"
version = "0.1.0"
description = "Core types, traits, and forensic parsers for Security Ronin Katana"
edition.workspace = true
license.workspace = true
repository.workspace = true
authors.workspace = true

[dependencies]
serde = { workspace = true }
serde_json = { workspace = true }
thiserror = { workspace = true }
chrono = { workspace = true }
rayon = { workspace = true }
sha2 = { workspace = true }
memmap2 = { workspace = true }
byteorder = { workspace = true }
tracing = { workspace = true }

[dev-dependencies]
criterion = { version = "0.5", features = ["html_reports"] }
proptest = "1"
tempfile = "3"

[[bench]]
name = "parse_throughput"
harness = false
```

### 6.3 katana-cli Crate

```toml
# katana/crates/katana-cli/Cargo.toml

[package]
name = "katana-cli"
version = "0.1.0"
description = "Community CLI for Security Ronin Katana forensic triage"
edition.workspace = true
license.workspace = true
repository.workspace = true
authors.workspace = true

[[bin]]
name = "katana"
path = "src/main.rs"

[dependencies]
katana-core = { workspace = true }
katana-formats = { workspace = true }
katana-ewf = { workspace = true }
katana-ntfs = { workspace = true }
clap = { workspace = true }
indicatif = { workspace = true }
tracing = { workspace = true }
tracing-subscriber = { workspace = true }
anyhow = { workspace = true }
```

### 6.4 Enterprise Workspace Root

```toml
# katana-pro/Cargo.toml

[workspace]
resolver = "2"
members = [
    "crates/katana-server",
    "crates/katana-agent",
    "crates/katana-pcap",
    "crates/katana-collab",
    "crates/katana-import",
    "crates/katana-multi",
]

[workspace.package]
edition = "2021"
license = "LicenseRef-Proprietary"
repository = "https://github.com/SecurityRonin/katana-pro"
authors = ["Albert Hui <albert@securityronin.com>"]

[workspace.dependencies]
# Community crate dependencies (path for local dev, git for CI)
katana-core = { path = "../katana/crates/katana-core" }
katana-formats = { path = "../katana/crates/katana-formats" }
katana-ewf = { path = "../katana/crates/katana-ewf" }
katana-ntfs = { path = "../katana/crates/katana-ntfs" }

# Enterprise dependencies
axum = { version = "0.8", features = ["ws", "macros"] }
tower = { version = "0.5", features = ["full"] }
tower-http = { version = "0.6", features = ["cors", "compression-zstd", "trace"] }
tonic = { version = "0.12", features = ["tls-ring", "gzip"] }
tonic-build = "0.12"
prost = "0.13"
tokio = { version = "1", features = ["full"] }
sqlx = { version = "0.8", features = ["runtime-tokio", "postgres", "uuid", "chrono", "migrate"] }
duckdb = { version = "1.1", features = ["bundled"] }
tantivy = "0.22"
jsonwebtoken = "9"
governor = "0.6"
pcap-parser = "0.16"
etherparse = "0.16"
netflow_parser = "0.6"
zstd = "0.13"
utoipa = { version = "5", features = ["axum_extras"] }
utoipa-swagger-ui = { version = "8", features = ["axum"] }

# Shared dependencies
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"
anyhow = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
tracing-opentelemetry = "0.27"
opentelemetry = "0.27"
opentelemetry-otlp = "0.27"
chrono = { version = "0.4", features = ["serde"] }
sha2 = "0.10"
uuid = { version = "1", features = ["v7", "serde"] }
envy = "0.4"
rustls = "0.23"

# Internal enterprise crates
katana-pcap = { path = "crates/katana-pcap" }
katana-collab = { path = "crates/katana-collab" }
katana-import = { path = "crates/katana-import" }
katana-multi = { path = "crates/katana-multi" }

[workspace.lints.rust]
unsafe_code = "deny"

[workspace.lints.clippy]
pedantic = { level = "warn", priority = -1 }
unwrap_used = "deny"

[profile.release]
lto = "fat"
codegen-units = 1
strip = true
panic = "abort"

# Agent profile: optimize for binary size
[profile.release-agent]
inherits = "release"
opt-level = "z"
strip = true
```

### 6.5 katana-server Crate

```toml
# katana-pro/crates/katana-server/Cargo.toml

[package]
name = "katana-server"
version = "0.1.0"
description = "Enterprise server for Security Ronin Katana"
edition.workspace = true
license.workspace = true
authors.workspace = true

[[bin]]
name = "katana-server"
path = "src/main.rs"

[dependencies]
# Community crates
katana-core = { workspace = true }
katana-formats = { workspace = true }
katana-ewf = { workspace = true }
katana-ntfs = { workspace = true }

# Enterprise crates
katana-pcap = { workspace = true }
katana-collab = { workspace = true }
katana-import = { workspace = true }
katana-multi = { workspace = true }

# Web framework
axum = { workspace = true }
tower = { workspace = true }
tower-http = { workspace = true }
tokio = { workspace = true }

# gRPC
tonic = { workspace = true }
prost = { workspace = true }

# Database
sqlx = { workspace = true }
duckdb = { workspace = true }

# Search
tantivy = { workspace = true }

# Auth
jsonwebtoken = { workspace = true }
rustls = { workspace = true }

# Observability
tracing = { workspace = true }
tracing-subscriber = { workspace = true }
tracing-opentelemetry = { workspace = true }
opentelemetry = { workspace = true }
opentelemetry-otlp = { workspace = true }

# API docs
utoipa = { workspace = true }
utoipa-swagger-ui = { workspace = true }

# Shared
serde = { workspace = true }
serde_json = { workspace = true }
thiserror = { workspace = true }
anyhow = { workspace = true }
chrono = { workspace = true }
sha2 = { workspace = true }
uuid = { workspace = true }
envy = { workspace = true }
governor = { workspace = true }

[build-dependencies]
tonic-build = { workspace = true }

[dev-dependencies]
reqwest = { version = "0.12", features = ["json"] }
testcontainers = "0.23"
wiremock = "0.6"
```

### 6.6 katana-agent Crate

```toml
# katana-pro/crates/katana-agent/Cargo.toml

[package]
name = "katana-agent"
version = "0.1.0"
description = "Remote evidence collection agent for Security Ronin Katana"
edition.workspace = true
license.workspace = true
authors.workspace = true

[[bin]]
name = "katana-agent"
path = "src/main.rs"

[dependencies]
katana-core = { workspace = true }
tonic = { workspace = true }
prost = { workspace = true }
tokio = { workspace = true }
rustls = { workspace = true }
sha2 = { workspace = true }
tracing = { workspace = true }
tracing-subscriber = { workspace = true }
serde = { workspace = true }
envy = { workspace = true }
thiserror = { workspace = true }

[build-dependencies]
tonic-build = { workspace = true }
```

---

## 7. CI/CD Setup

### 7.1 Community Repository CI (GitHub Actions)

```yaml
# katana/.github/workflows/ci.yml

name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: "-D warnings"

jobs:
  check:
    name: Check + Clippy + Format
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy, rustfmt
      - uses: Swatinem/rust-cache@v2
      - run: cargo fmt --all -- --check
      - run: cargo clippy --workspace --all-targets -- -D warnings
      - run: cargo check --workspace

  test:
    name: Test
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo test --workspace
      - run: cargo test --workspace --release

  audit:
    name: Security Audit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: rustsec/audit-check@v2
        with:
          token: ${{ secrets.GITHUB_TOKEN }}

  deny:
    name: License + Dependency Check
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: EmbarkStudios/cargo-deny-action@v2
        with:
          command: check
          arguments: --all-features

  bench:
    name: Benchmarks (PR only)
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo bench --workspace -- --output-format bencher | tee bench_output.txt
      - name: Comment benchmark results
        uses: benchmark-action/github-action-benchmark@v1
        with:
          tool: cargo
          output-file-path: bench_output.txt
          github-token: ${{ secrets.GITHUB_TOKEN }}
          comment-on-alert: true
          alert-threshold: "120%"
```

### 7.2 Community Release Workflow

```yaml
# katana/.github/workflows/release.yml

name: Release

on:
  push:
    tags: ["v*"]

permissions:
  contents: write

jobs:
  build:
    name: Build ${{ matrix.target }}
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        include:
          - target: x86_64-unknown-linux-gnu
            os: ubuntu-latest
            archive: tar.gz
          - target: x86_64-unknown-linux-musl
            os: ubuntu-latest
            archive: tar.gz
          - target: aarch64-unknown-linux-gnu
            os: ubuntu-latest
            archive: tar.gz
          - target: x86_64-apple-darwin
            os: macos-latest
            archive: tar.gz
          - target: aarch64-apple-darwin
            os: macos-latest
            archive: tar.gz
          - target: x86_64-pc-windows-msvc
            os: windows-latest
            archive: zip
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: ${{ matrix.target }}
      - name: Install cross-compilation tools
        if: matrix.target == 'aarch64-unknown-linux-gnu'
        run: |
          sudo apt-get update
          sudo apt-get install -y gcc-aarch64-linux-gnu
      - name: Install musl tools
        if: matrix.target == 'x86_64-unknown-linux-musl'
        run: sudo apt-get install -y musl-tools
      - name: Build release binary
        run: cargo build --release --target ${{ matrix.target }} -p katana-cli
      - name: Package binary
        shell: bash
        run: |
          BINARY_NAME="katana"
          if [ "${{ matrix.os }}" = "windows-latest" ]; then
            BINARY_NAME="katana.exe"
          fi
          ARCHIVE_NAME="katana-${{ github.ref_name }}-${{ matrix.target }}"
          mkdir -p "$ARCHIVE_NAME"
          cp "target/${{ matrix.target }}/release/$BINARY_NAME" "$ARCHIVE_NAME/"
          cp LICENSE-APACHE README.md "$ARCHIVE_NAME/"
          if [ "${{ matrix.archive }}" = "zip" ]; then
            7z a "$ARCHIVE_NAME.zip" "$ARCHIVE_NAME"
          else
            tar czf "$ARCHIVE_NAME.tar.gz" "$ARCHIVE_NAME"
          fi
      - uses: actions/upload-artifact@v4
        with:
          name: katana-${{ matrix.target }}
          path: katana-${{ github.ref_name }}-${{ matrix.target }}.*

  release:
    name: GitHub Release
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          merge-multiple: true
      - name: Create SHA256 checksums
        run: sha256sum katana-* > SHA256SUMS.txt
      - uses: softprops/action-gh-release@v2
        with:
          files: |
            katana-*
            SHA256SUMS.txt
          generate_release_notes: true
```

### 7.3 Enterprise Repository CI

```yaml
# katana-pro/.github/workflows/ci.yml

name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: "-D warnings"

jobs:
  check:
    name: Check + Clippy + Format
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # Checkout community repo alongside enterprise
      - uses: actions/checkout@v4
        with:
          repository: SecurityRonin/katana
          path: ../katana
          token: ${{ secrets.COMMUNITY_REPO_TOKEN }}
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy, rustfmt
      - uses: Swatinem/rust-cache@v2
      - run: cargo fmt --all -- --check
      - run: cargo clippy --workspace --all-targets -- -D warnings

  test:
    name: Test
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_DB: katana_test
          POSTGRES_USER: katana
          POSTGRES_PASSWORD: test_secret
        ports:
          - 5432:5432
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    env:
      KATANA_POSTGRES_URL: postgresql://katana:test_secret@localhost:5432/katana_test
      KATANA_JWT_SECRET: test_secret_minimum_32_bytes_long_enough
      KATANA_JWT_ISSUER: https://test.example.com
      KATANA_JWT_AUDIENCE: katana-test
    steps:
      - uses: actions/checkout@v4
      - uses: actions/checkout@v4
        with:
          repository: SecurityRonin/katana
          path: ../katana
          token: ${{ secrets.COMMUNITY_REPO_TOKEN }}
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - name: Run migrations
        run: cargo sqlx migrate run --source crates/katana-server/src/db/migrations
      - run: cargo test --workspace
      - run: cargo test --workspace --release

  audit:
    name: Security Audit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: rustsec/audit-check@v2
        with:
          token: ${{ secrets.GITHUB_TOKEN }}

  deny:
    name: License Check (No GPL)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/checkout@v4
        with:
          repository: SecurityRonin/katana
          path: ../katana
          token: ${{ secrets.COMMUNITY_REPO_TOKEN }}
      - uses: EmbarkStudios/cargo-deny-action@v2
        with:
          command: check licenses

  agent-size:
    name: Agent Binary Size Check
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/checkout@v4
        with:
          repository: SecurityRonin/katana
          path: ../katana
          token: ${{ secrets.COMMUNITY_REPO_TOKEN }}
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: x86_64-unknown-linux-musl
      - run: sudo apt-get install -y musl-tools
      - name: Build agent with size-optimized profile
        run: cargo build --profile release-agent --target x86_64-unknown-linux-musl -p katana-agent
      - name: Verify binary size < 5MB
        run: |
          SIZE=$(stat -c%s target/x86_64-unknown-linux-musl/release-agent/katana-agent)
          MAX=$((5 * 1024 * 1024))
          echo "Agent binary size: $SIZE bytes (max: $MAX)"
          if [ "$SIZE" -gt "$MAX" ]; then
            echo "FAIL: Agent binary exceeds 5MB limit"
            exit 1
          fi
```

### 7.4 Enterprise Release Workflow

```yaml
# katana-pro/.github/workflows/release.yml

name: Release

on:
  push:
    tags: ["v*"]

permissions:
  contents: write
  packages: write

env:
  REGISTRY: ghcr.io
  SERVER_IMAGE: ghcr.io/securityronin/katana-server
  AGENT_IMAGE: ghcr.io/securityronin/katana-agent

jobs:
  docker-server:
    name: Build Server Docker Image
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/checkout@v4
        with:
          repository: SecurityRonin/katana
          path: ../katana
          token: ${{ secrets.COMMUNITY_REPO_TOKEN }}
      - uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v6
        with:
          context: .
          file: docker/Dockerfile.server
          push: true
          tags: |
            ${{ env.SERVER_IMAGE }}:${{ github.ref_name }}
            ${{ env.SERVER_IMAGE }}:latest
          cache-from: type=gha
          cache-to: type=gha,mode=max

  docker-agent:
    name: Build Agent Docker Image
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/checkout@v4
        with:
          repository: SecurityRonin/katana
          path: ../katana
          token: ${{ secrets.COMMUNITY_REPO_TOKEN }}
      - uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v6
        with:
          context: .
          file: docker/Dockerfile.agent
          push: true
          tags: |
            ${{ env.AGENT_IMAGE }}:${{ github.ref_name }}
            ${{ env.AGENT_IMAGE }}:latest

  binary-agent:
    name: Standalone Agent Binary
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        include:
          - target: x86_64-unknown-linux-musl
            os: ubuntu-latest
          - target: aarch64-unknown-linux-musl
            os: ubuntu-latest
          - target: x86_64-pc-windows-msvc
            os: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/checkout@v4
        with:
          repository: SecurityRonin/katana
          path: ../katana
          token: ${{ secrets.COMMUNITY_REPO_TOKEN }}
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: ${{ matrix.target }}
      - name: Build agent
        run: cargo build --profile release-agent --target ${{ matrix.target }} -p katana-agent
      - uses: actions/upload-artifact@v4
        with:
          name: katana-agent-${{ matrix.target }}
          path: target/${{ matrix.target }}/release-agent/katana-agent*
```

---

## 8. Development Workflow

### 8.1 Local Setup

Both repositories must be cloned as siblings for path dependencies to resolve during local development.

```bash
# Initial setup
mkdir -p ~/src/securityronin && cd ~/src/securityronin
git clone git@github.com:SecurityRonin/katana.git
git clone git@github.com:SecurityRonin/katana-pro.git

# Verify workspace resolution
cd katana && cargo check --workspace
cd ../katana-pro && cargo check --workspace

# Install development tools
cargo install cargo-watch cargo-nextest cargo-deny cargo-audit
```

### 8.2 Development Commands

```bash
# -- Community Repo ----------------------------------------------------------

# Run community CLI against a test image
cargo run -p katana-cli -- triage --format csv --output triage.csv tests/corpus/small.e01

# Run all tests with nextest (parallel, better output)
cargo nextest run --workspace

# Watch mode for rapid iteration
cargo watch -x "check --workspace" -x "test --workspace"

# Run benchmarks
cargo bench --workspace

# Check for security advisories
cargo audit
cargo deny check

# -- Enterprise Repo ---------------------------------------------------------

# Start development dependencies
docker compose -f docker/docker-compose.yml up -d postgres

# Run database migrations
cargo sqlx migrate run --source crates/katana-server/src/db/migrations

# Start the server in development mode
KATANA_LOG_LEVEL=debug KATANA_LOG_FORMAT=pretty cargo run -p katana-server

# Run integration tests (requires postgres)
cargo nextest run --workspace

# Generate OpenAPI spec
cargo run -p katana-server -- --dump-openapi > openapi.json
```

### 8.3 Build Scripts

```rust
// katana-pro/crates/katana-server/build.rs

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compile protobuf definitions for agent gRPC service
    tonic_build::configure()
        .build_server(true)
        .build_client(false)  // Server does not need client stubs
        .out_dir("src/grpc/generated")
        .compile_protos(
            &[
                "../../proto/agent/v1/agent.proto",
                "../../proto/agent/v1/evidence.proto",
            ],
            &["../../proto"],
        )?;

    // Trigger rebuild when protos change
    println!("cargo:rerun-if-changed=../../proto");

    Ok(())
}
```

```rust
// katana-pro/crates/katana-agent/build.rs

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compile protobuf definitions for agent gRPC client
    tonic_build::configure()
        .build_server(false)
        .build_client(true)  // Agent only needs client stubs
        .out_dir("src/grpc/generated")
        .compile_protos(
            &[
                "../../proto/agent/v1/agent.proto",
                "../../proto/agent/v1/evidence.proto",
            ],
            &["../../proto"],
        )?;

    println!("cargo:rerun-if-changed=../../proto");

    Ok(())
}
```

```rust
// katana/crates/katana-ewf/build.rs

fn main() {
    // Build libewf FFI bindings
    // libewf must be installed on the system or vendored
    println!("cargo:rerun-if-changed=wrapper.h");

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .allowlist_function("libewf_.*")
        .allowlist_type("libewf_.*")
        .generate()
        .expect("Failed to generate libewf bindings");

    let out_dir = std::env::var("OUT_DIR").unwrap();
    bindings
        .write_to_file(std::path::Path::new(&out_dir).join("libewf_bindings.rs"))
        .expect("Failed to write bindings");

    // Link to libewf
    println!("cargo:rustc-link-lib=ewf");
}
```

---

## 9. Docker Configuration

### 9.1 Server Dockerfile

```dockerfile
# katana-pro/docker/Dockerfile.server

# Stage 1: Build
FROM rust:1.84-bookworm AS builder

WORKDIR /build

# Copy community repo (mounted or pre-fetched)
COPY ../katana /build/katana

# Copy enterprise repo
COPY . /build/katana-pro

WORKDIR /build/katana-pro

# Build release binary
RUN cargo build --release -p katana-server

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/false katana

COPY --from=builder /build/katana-pro/target/release/katana-server /usr/local/bin/

USER katana
WORKDIR /home/katana

EXPOSE 8080 50051

HEALTHCHECK --interval=30s --timeout=5s \
    CMD curl -f http://localhost:8080/health || exit 1

ENTRYPOINT ["katana-server"]
```

### 9.2 Agent Dockerfile

```dockerfile
# katana-pro/docker/Dockerfile.agent

# Stage 1: Build with musl for static linking
FROM rust:1.84-bookworm AS builder

RUN apt-get update && apt-get install -y musl-tools
RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /build
COPY ../katana /build/katana
COPY . /build/katana-pro

WORKDIR /build/katana-pro

RUN cargo build --profile release-agent --target x86_64-unknown-linux-musl -p katana-agent

# Stage 2: Minimal runtime (scratch-based for <5MB)
FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/katana-pro/target/x86_64-unknown-linux-musl/release-agent/katana-agent /

ENTRYPOINT ["/katana-agent"]
```

### 9.3 Development Compose

```yaml
# katana-pro/docker/docker-compose.yml

services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: katana
      POSTGRES_USER: katana
      POSTGRES_PASSWORD: dev_secret
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U katana"]
      interval: 5s
      timeout: 5s
      retries: 5

  server:
    build:
      context: ..
      dockerfile: docker/Dockerfile.server
    depends_on:
      postgres:
        condition: service_healthy
    ports:
      - "8080:8080"
      - "50051:50051"
    environment:
      KATANA_POSTGRES_URL: postgresql://katana:dev_secret@postgres:5432/katana
      KATANA_DUCKDB_DIR: /data/duckdb
      KATANA_TANTIVY_DIR: /data/tantivy
      KATANA_JWT_SECRET: dev_secret_at_least_32_bytes_long_enough_for_hs256
      KATANA_JWT_ISSUER: https://dev.local
      KATANA_JWT_AUDIENCE: katana-dev
      KATANA_GRPC_PORT: "50051"
      KATANA_GRPC_TLS_CERT: /certs/server.crt
      KATANA_GRPC_TLS_KEY: /certs/server.key
      KATANA_GRPC_CA_CERT: /certs/ca.crt
      KATANA_HTTP_PORT: "8080"
      KATANA_LOG_LEVEL: debug
      KATANA_LOG_FORMAT: pretty
      KATANA_RATE_LIMIT_RPS: "1000"
      KATANA_RATE_LIMIT_BURST: "2000"
      KATANA_WS_MAX_CONNECTIONS: "100"
      KATANA_TANTIVY_HEAP_MB: "128"
    volumes:
      - duckdb_data:/data/duckdb
      - tantivy_data:/data/tantivy
      - ./test_certs:/certs:ro

  otel-collector:
    image: otel/opentelemetry-collector:0.114.0
    ports:
      - "4317:4317"
      - "4318:4318"
    volumes:
      - ./otel-config.yml:/etc/otelcol/config.yaml

volumes:
  postgres_data:
  duckdb_data:
  tantivy_data:
```

---

## 10. Protobuf Definitions

```protobuf
// katana-pro/proto/agent/v1/agent.proto

syntax = "proto3";

package agent.v1;

service AgentService {
  // Agent sends periodic heartbeats to report health and system info.
  rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);

  // Agent streams evidence chunks to the server.
  // Server returns final hash and receipt after all chunks received.
  rpc UploadEvidence(stream EvidenceChunk) returns (UploadResponse);

  // Server pushes collection tasks to the agent.
  rpc GetPendingTasks(TaskRequest) returns (stream CollectionTask);
}

message HeartbeatRequest {
  string agent_id = 1;
  SystemInfo system_info = 2;
  int64 uptime_secs = 3;
}

message HeartbeatResponse {
  int64 server_time = 1;
  int32 pending_tasks = 2;
}

message SystemInfo {
  string hostname = 1;
  string os = 2;
  string os_version = 3;
  uint64 total_memory_bytes = 4;
  uint64 available_disk_bytes = 5;
}

message EvidenceChunk {
  string evidence_id = 1;
  uint64 sequence_number = 2;
  bytes data = 3;
  bool is_final = 4;
}

message UploadResponse {
  string evidence_id = 1;
  string sha256 = 2;
  uint64 bytes_received = 3;
}

message TaskRequest {
  string agent_id = 1;
}

message CollectionTask {
  string task_id = 1;
  string evidence_path = 2;
  EvidenceType evidence_type = 3;
  int32 priority = 4;
}

enum EvidenceType {
  EVIDENCE_TYPE_UNSPECIFIED = 0;
  EVIDENCE_TYPE_DISK_IMAGE = 1;
  EVIDENCE_TYPE_PCAP = 2;
  EVIDENCE_TYPE_MEMORY_DUMP = 3;
  EVIDENCE_TYPE_LOG_BUNDLE = 4;
}
```

---

## 11. cargo-deny Configuration

### 11.1 Community

```toml
# katana/deny.toml

[advisories]
vulnerability = "deny"
unmaintained = "warn"

[licenses]
unlicensed = "deny"
allow = [
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Unicode-3.0",
    "Zlib",
]
copyleft = "deny"

[bans]
multiple-versions = "warn"
wildcards = "deny"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
```

### 11.2 Enterprise

```toml
# katana-pro/deny.toml

[advisories]
vulnerability = "deny"
unmaintained = "deny"  # Stricter than community

[licenses]
unlicensed = "deny"
allow = [
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Unicode-3.0",
    "Zlib",
    "OpenSSL",
]
copyleft = "deny"

# Community crates are Apache-2.0 (allowed)
# Enterprise crates use LicenseRef-Proprietary (allowed via exception)
exceptions = [
    { allow = ["LicenseRef-Proprietary"], crate = "katana-server" },
    { allow = ["LicenseRef-Proprietary"], crate = "katana-agent" },
    { allow = ["LicenseRef-Proprietary"], crate = "katana-pcap" },
    { allow = ["LicenseRef-Proprietary"], crate = "katana-collab" },
    { allow = ["LicenseRef-Proprietary"], crate = "katana-import" },
    { allow = ["LicenseRef-Proprietary"], crate = "katana-multi" },
]

[bans]
multiple-versions = "warn"
wildcards = "deny"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
```

---

## 12. Binary Packaging

### 12.1 Community CLI Package Matrix

| Target | OS | Arch | Format | Static |
|--------|-----|------|--------|--------|
| `x86_64-unknown-linux-gnu` | Linux | x86_64 | tar.gz | No |
| `x86_64-unknown-linux-musl` | Linux | x86_64 | tar.gz | Yes |
| `aarch64-unknown-linux-gnu` | Linux | ARM64 | tar.gz | No |
| `x86_64-apple-darwin` | macOS | Intel | tar.gz | No |
| `aarch64-apple-darwin` | macOS | Apple Silicon | tar.gz | No |
| `x86_64-pc-windows-msvc` | Windows | x86_64 | zip | No |

### 12.2 Enterprise Agent Package Matrix

| Target | OS | Arch | Max Size | Static |
|--------|-----|------|----------|--------|
| `x86_64-unknown-linux-musl` | Linux | x86_64 | 5 MB | Yes |
| `aarch64-unknown-linux-musl` | Linux | ARM64 | 5 MB | Yes |
| `x86_64-pc-windows-msvc` | Windows | x86_64 | 5 MB | No |

### 12.3 Enterprise Server Distribution

The server is distributed exclusively as Docker images via `ghcr.io/securityronin/katana-server`. Multi-arch images (amd64 + arm64) are built on release tags.

### 12.4 SHA-256 Verification

Every release artifact includes a `SHA256SUMS.txt` file signed with the project GPG key. Users verify integrity before deployment:

```bash
# Verify community CLI
sha256sum -c SHA256SUMS.txt

# Verify agent binary
sha256sum -c SHA256SUMS.txt

# Verify Docker image digest
docker pull ghcr.io/securityronin/katana-server:v1.0.0
docker inspect --format='{{.RepoDigests}}' ghcr.io/securityronin/katana-server:v1.0.0
```
