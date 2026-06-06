# Security Ronin Katana: Resilience Patterns

> Axiom: **Partial results are better than no results.** Every stage in the pipeline must produce whatever it can, report what it skipped, and never silently swallow evidence. A corrupt E01 segment, a truncated USN journal, a malformed MFT entry -- each is a degradation, not a halt.

---

## 1. Circuit Breaker Pattern

Circuit breakers protect the enterprise tier's networked services from cascade failures. The community CLI runs as a single-process pipeline with no network dependencies, so it uses data-level circuit breakers (consecutive-corrupt-record thresholds) rather than service-level ones.

### 1.1 Community Tier: Record-Level Circuit Breakers

Each parser tracks consecutive failures. If a region produces more than 1,000 consecutive corrupt records, the parser advances past the region rather than burning CPU on garbage bytes.

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Max consecutive corrupt records | 1,000 | Prevents infinite loops in fully corrupted regions |
| Corrupt record action | Log + Skip + Increment counter | Forensic audit trail without halting |
| Zero-filled region handling | Skip silently (8-byte alignment) | Normal $UsnJrnl behavior -- sparse file gaps |
| Invalid version field | Log warning, advance 8 bytes | Scan forward for next valid record boundary |
| Oversized record (>64KB) | Log error, advance 8 bytes | Sanity bound prevents buffer overallocation |
| Truncated record at EOF | Log partial, emit what was readable | Final record may span page boundary |

### 1.2 Enterprise Tier: Service Circuit Breakers

```rust
// katana-server/src/resilience/circuit_breaker.rs

pub struct CircuitBreakerConfig {
    pub failure_threshold: u32,
    pub success_threshold: u32,
    pub open_timeout: Duration,
    pub reset_window: Duration,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CircuitState {
    Closed,   // Normal operation, requests flow through
    Open,     // Failing, reject immediately with fallback
    HalfOpen, // Testing recovery, allow limited probes
}
```

| Service | Failure Threshold | Success Threshold | Open Timeout | Reset Window | Rationale |
|---------|:-:|:-:|:-:|:-:|-----------|
| PostgreSQL (sqlx pool) | 3 | 2 | 30s | 60s | Persistent storage; fast failover expected |
| OpenSearch | 5 | 3 | 45s | 120s | Search index; tolerate brief unavailability |
| gRPC Agent Channel (tonic) | 3 | 1 | 15s | 30s | Agent connections are transient; fast retry |
| WebSocket Collaboration | 3 | 2 | 10s | 20s | Real-time collab; users notice immediately |
| Redis (task queue) | 3 | 2 | 20s | 60s | Async task broker; queue locally if down |

### 1.3 Circuit Breaker Implementation

```rust
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    state: AtomicCell<CircuitState>,
    failure_count: AtomicU32,
    success_count: AtomicU32,
    last_failure: Mutex<Option<Instant>>,
    service_name: String,
}

impl CircuitBreaker {
    pub async fn call<F, T, E>(&self, operation: F) -> Result<T, ResilienceError<E>>
    where
        F: Future<Output = Result<T, E>>,
    {
        match self.state.load() {
            CircuitState::Open => {
                if self.should_attempt_reset() {
                    self.state.store(CircuitState::HalfOpen);
                } else {
                    return Err(ResilienceError::CircuitOpen);
                }
            }
            CircuitState::HalfOpen | CircuitState::Closed => {}
        }

        match operation.await {
            Ok(result) => {
                self.record_success();
                Ok(result)
            }
            Err(e) => {
                self.record_failure();
                Err(ResilienceError::Inner(e))
            }
        }
    }

    fn record_failure(&self) {
        let count = self.failure_count.fetch_add(1, Ordering::Relaxed) + 1;
        *self.last_failure.lock() = Some(Instant::now());
        if count >= self.config.failure_threshold {
            self.state.store(CircuitState::Open);
            tracing::warn!(
                service = %self.service_name,
                failures = count,
                "circuit breaker opened"
            );
        }
    }

    fn record_success(&self) {
        if self.state.load() == CircuitState::HalfOpen {
            let count = self.success_count.fetch_add(1, Ordering::Relaxed) + 1;
            if count >= self.config.success_threshold {
                self.state.store(CircuitState::Closed);
                self.failure_count.store(0, Ordering::Relaxed);
                self.success_count.store(0, Ordering::Relaxed);
                tracing::info!(service = %self.service_name, "circuit breaker closed");
            }
        } else {
            self.failure_count.store(0, Ordering::Relaxed);
        }
    }
}
```

---

## 2. Fallback Chains

### 2.1 Community Tier: Artifact Degradation Tiers

The community CLI analyzes up to four NTFS artifacts. Each missing artifact removes a capability but never prevents analysis of the artifacts that are available.

```
QuadLink (4 artifacts)
  |-- $MFTMirr missing --> TriForce+ (3 artifacts, no integrity check)
  |     |-- $LogFile missing --> Dual (2 artifacts, no ghost records)
  |     |     |-- $MFT missing --> USN-Only (1 artifact, no path resolution)
  |     |     |     |-- $UsnJrnl corrupt --> Carve-Only (unallocated scanning)
  |     |     |     |     |-- No valid records --> Empty result with stats
```

| Tier | Artifacts | Path Resolution | Ghost Records | Integrity Check | Timestomping | Anti-Forensics |
|------|-----------|-----------------|---------------|-----------------|--------------|----------------|
| **QuadLink** | $UsnJrnl + $MFT + $LogFile + $MFTMirr | Full Rewind | Yes | Yes | Yes (SI vs FN) | Full suite |
| **TriForce+** | $UsnJrnl + $MFT + $LogFile | Full Rewind | Yes | No | Yes (SI vs FN) | No MFTMirr tampering |
| **Dual** | $UsnJrnl + $MFT | Full Rewind | No | No | Yes (SI vs FN) | SDelete + Ransomware |
| **USN-Only** | $UsnJrnl | Filename only, no parent paths | No | No | No | Pattern-based only |
| **Carve-Only** | Unallocated space | Best-effort from carved MFT | No | No | No | None |
| **Empty** | None viable | N/A | N/A | N/A | N/A | N/A |

### 2.2 Community Tier: Per-Stage Fallback Table

Every pipeline stage follows the same contract: attempt full processing, degrade to partial processing, report what was skipped. No stage returns an error that halts the pipeline.

| Stage | Level 1 (Full) | Level 2 (Degraded) | Level 3 (Minimal) | Level 4 (Skip) |
|-------|---------------|-------------------|-----------------|---------------|
| EWF Parser | Parse all E01 segments, expose full volume stream | Skip corrupt segments, expose partial volume | Fall back to raw dd-image reader if E01 headers invalid | Report image unreadable, halt with diagnostic |
| NTFS Volume | Extract $MFT + $UsnJrnl:$J + $LogFile | Extract available artifacts; mark missing ones | Parse boot sector only for volume geometry | Report volume unreadable, produce empty artifact set |
| USN Parser | Parse all V2/V3/V4 records with full field extraction | Skip malformed records, count skips in `parse_stats` | Parse record headers only (timestamp + reason + filename) | Produce zero records with `parse_stats.skipped_count` |
| MFT Parser | Full CyberCX Rewind path reconstruction | Skip circular parent refs, mark paths UNKNOWN | Parse $STANDARD_INFORMATION only (timestamps, no paths) | Produce entries without paths |
| Ghost Recovery | Recover deleted records from sparse gaps (>95% target) | Recover from intact gaps only, skip corrupted regions | Skip recovery entirely, report 0 ghosts | Return empty ghost set with recovery_stats |
| Unallocated Carving | Carve full MFT entries from unallocated clusters | Carve partial entries (>80% intact threshold) | Skip carving, report unallocated range sizes only | Return empty carved set |
| QuadLink Correlator | Full 4-artifact correlation (USN + MFT + Ghost + Carved) | Correlate available artifacts only (2-of-4 minimum) | Timestamp-only correlation (no path/hash matching) | Pass-through uncorrelated records |
| Triage Engine | Answer all 12 IR questions with confidence scores | Answer questions with available data, mark low-confidence | Answer timestamp-range questions only | Report "insufficient data" per question |
| Output Formatter | Generate all requested formats (JSONL/CSV/XML/TLN/HTML/SQLite) | Generate parseable formats only (JSONL/CSV), skip rendering-heavy | Generate JSONL only (always succeeds) | Write error report in JSONL |

### 2.3 Enterprise Tier: Service Fallbacks

| Service | Level 1 (Primary) | Level 2 (Degraded) | Level 3 (Minimal) |
|---------|-------------------|-------------------|-----------------|
| PostgreSQL | Read/write via sqlx connection pool | Read-only from replica; queue writes to local WAL | Serve from in-memory cache; queue all mutations |
| OpenSearch | Full-text search + aggregation | Degrade to PostgreSQL `LIKE` queries (slower, functional) | Return "search unavailable" with cached recent results |
| gRPC Agent Channel | Bidirectional streaming via tonic with mTLS | Retry with exponential backoff; buffer results locally | Agent operates offline, queues results for later sync |
| WebSocket Collab | Real-time collaboration via katana-collab | Poll-based collaboration (REST fallback, 5s interval) | Single-user mode with conflict resolution on reconnect |
| Redis Task Queue | Async task distribution | In-process task queue (tokio::spawn) | Synchronous execution on the request thread |

### 2.4 Fallback Implementation

```rust
// src/main.rs -- artifact resolution with graceful degradation
struct ArtifactPaths {
    journal: PathBuf,
    mft: Option<PathBuf>,      // None = degrade to USN-Only
    mftmirr: Option<PathBuf>,  // None = skip integrity check
    logfile: Option<PathBuf>,   // None = no ghost record recovery
}

fn determine_tier(paths: &ArtifactPaths) -> CorrelationTier {
    match (&paths.mft, &paths.logfile, &paths.mftmirr) {
        (Some(_), Some(_), Some(_)) => CorrelationTier::QuadLink,
        (Some(_), Some(_), None)    => CorrelationTier::TriForce,
        (Some(_), None, _)          => CorrelationTier::Dual,
        (None, _, _)                => CorrelationTier::UsnOnly,
    }
}

fn run_with_tier(tier: CorrelationTier, paths: &ArtifactPaths) -> Result<AnalysisResult> {
    log::info!("Operating in {:?} mode", tier);

    if tier < CorrelationTier::QuadLink {
        log::warn!("$MFTMirr not available -- integrity check skipped");
    }
    if tier < CorrelationTier::TriForce {
        log::warn!("$LogFile not available -- ghost record recovery disabled");
    }
    if tier < CorrelationTier::Dual {
        log::warn!("$MFT not available -- path resolution degraded to filename-only");
    }

    // Pipeline proceeds with whatever artifacts are present
    // ...
}
```

### 2.5 Image Extraction Fallback Tree

When using `--image` to open E01/raw disk images, artifact extraction can fail independently:

```
Image opened successfully
  |-- NTFS partition found
  |     |-- $UsnJrnl extracted --> continue
  |     |-- $UsnJrnl NOT found --> try --carve-unallocated, else exit with clear error
  |     |-- $MFT extracted --> seed Rewind engine
  |     |-- $MFT NOT found --> log warning, proceed in USN-Only mode
  |     |-- $LogFile extracted --> enable ghost recovery
  |     |-- $LogFile NOT found --> log warning, skip ghost recovery
  |     |-- $MFTMirr extracted --> enable integrity check
  |     |-- $MFTMirr NOT found --> log warning, skip integrity check
  |-- NTFS partition NOT found --> scan all partitions, report which were found
  |-- Image read error --> report specific I/O error with byte offset
```

### 2.6 Corrupt Record Handling

Every parser implements the `RecoverableParser` pattern, which enforces "skip and report":

```rust
// src/usn/record.rs -- actual pattern used
pub fn parse_usn_journal(data: &[u8]) -> Result<Vec<UsnRecord>> {
    let mut records = Vec::new();
    let mut offset = 0;
    let mut stats = ParseStats::default();

    while offset + 8 <= data.len() {
        // Skip zero-filled regions (normal $UsnJrnl sparse gaps)
        if data[offset..offset + 4] == [0, 0, 0, 0] {
            offset += 8; // USN records are 8-byte aligned
            continue;
        }

        let record_len = u32::from_le_bytes(
            data[offset..offset + 4].try_into().unwrap_or([0; 4])
        ) as usize;

        // Sanity check: reject absurd sizes
        if record_len < 0x3C || record_len > 65536 {
            log::warn!("Invalid record length {} at offset {:#x}, scanning forward",
                       record_len, offset);
            stats.corrupt_records += 1;
            offset += 8;
            continue;
        }

        // Bounds check: truncated record at end of data
        if offset + record_len > data.len() {
            log::warn!("Truncated record at offset {:#x} (need {} bytes, have {})",
                       offset, record_len, data.len() - offset);
            stats.truncated_records += 1;
            break;
        }

        match parse_usn_record_at(&data[offset..offset + record_len]) {
            Ok(record) => {
                records.push(record);
                offset += record_len;
            }
            Err(e) => {
                log::warn!("Corrupt USN record at offset {:#x}: {}", offset, e);
                stats.corrupt_records += 1;
                offset += 8;
            }
        }
    }

    log::info!("Parsed {} records ({} corrupt, {} truncated)",
               records.len(), stats.corrupt_records, stats.truncated_records);
    Ok(records) // Always returns Ok -- errors are per-record, not fatal
}
```

**Key invariant**: `parse_usn_journal` always returns `Ok(Vec<...>)`. Record-level errors are logged and counted, never propagated as pipeline-fatal errors. The caller receives whatever valid records were found.

---

## 3. Timeout Handling

### 3.1 Community Tier: Pipeline Timeout Budget

The community tier targets 35 seconds end-to-end on a 40GB E01 with ~847K records. Each stage has a time budget. If a stage exceeds its budget, it returns partial results.

| Stage | Budget | Parallelism | Timeout Behavior |
|-------|--------|-------------|-----------------|
| EWF Parser | 2s | single-threaded | Return partial volume if segments timeout individually |
| NTFS Volume | 1s | single-threaded | Extract whatever artifacts are found within budget |
| USN Parser | 5s | rayon (data-parallel) | Flush parsed records, report remaining byte range |
| MFT Parser | 5s | rayon (data-parallel) | Flush parsed entries, degrade path resolution |
| Ghost Recovery | 3s | single-threaded | Return recovered ghosts so far, report coverage % |
| Unallocated Carving | 5s | rayon (data-parallel) | Return carved entries so far, report cluster coverage |
| QuadLink Correlator | 3s | single-threaded | Return partial correlations, mark uncorrelated records |
| Triage Engine | 5s | rayon (per-question parallel) | Answer completed questions, mark timed-out questions |
| Output Formatter | 3s | single-threaded | Write completed formats, skip remaining |
| **Pipeline Total** | **32s** | | **3s buffer for overhead, logging, summary** |

### 3.2 Enterprise Tier: Service Timeouts

| Component | Timeout | Rationale |
|-----------|---------|-----------|
| gRPC Agent Submission | 10s | Agent sends case results; large payloads over WAN |
| gRPC Agent Heartbeat | 5s | Lightweight keepalive; detect disconnects fast |
| PostgreSQL Query | 5s | Indexed queries should complete sub-second; 5s catches locks |
| PostgreSQL Transaction | 30s | Batch inserts for large cases need headroom |
| OpenSearch Query | 10s | Aggregation queries on large indices |
| OpenSearch Bulk Index | 30s | Indexing a full case with 800K+ records |
| WebSocket Ping/Pong | 10s | Detect stale connections |
| REST API Response | 15s | Worst-case query + render cycle |

### 3.3 Graceful Degradation on Timeout

```rust
/// Execute a pipeline stage with timeout, returning partial results on expiry.
pub async fn execute_with_budget<F, T>(
    stage_name: &str,
    budget: Duration,
    operation: F,
    partial_extractor: impl FnOnce() -> StageFallback<T>,
) -> StageFallback<T>
where
    F: Future<Output = StageFallback<T>>,
{
    match tokio::time::timeout(budget, operation).await {
        Ok(result) => result,
        Err(_elapsed) => {
            tracing::warn!(
                stage = stage_name,
                budget_ms = budget.as_millis(),
                "stage exceeded time budget, extracting partial results"
            );
            let mut fallback = partial_extractor();
            fallback.degradation_level = DegradationLevel::Degraded;
            fallback.add_warning(
                "timeout",
                format!("Stage exceeded {:.1}s budget", budget.as_secs_f64()),
                0,
            );
            fallback
        }
    }
}
```

### 3.4 Memory Pressure Management

Forensic images can exceed available RAM. The pipeline uses streaming where possible and enforces memory limits per stage.

```rust
// Pattern: Streaming/chunked processing to avoid loading entire images into memory

// 1. Parallel USN parsing: 1 MB chunks via rayon
const CHUNK_SIZE: usize = 1024 * 1024; // 1 MB
// Data is split into CHUNK_SIZE pieces, each parsed independently
// Results merged and sorted by USN offset for deterministic output

// 2. Unallocated carving: 4 MB overlapping chunks
// Scans partition in bounded windows, not loading full unallocated space

// 3. MFT parsing: Entry-by-entry (1024 bytes each)
// Never loads all MFT entries into a single buffer

// 4. Output: BufWriter with buffered I/O
let writer = BufWriter::new(File::create(path)?);
// Flushes automatically, prevents unbounded in-memory accumulation

// 5. Rewind lookup table: HashMap<EntryKey, EntryInfo>
// Bounded by number of unique (entry, sequence) pairs in the journal
// Typical: 100K-2M entries for a busy system, ~100-500 MB RAM
```

### 3.5 Large Image Safeguards

| Image Size | Expected Behavior | Memory Profile |
|------------|-------------------|----------------|
| < 1 GB | Completes in seconds | < 200 MB RAM |
| 1-50 GB | Completes in minutes, progress bars shown | < 1 GB RAM |
| 50-500 GB | May take 10-60 minutes with carving | < 2 GB RAM (streaming) |
| > 500 GB | Hours possible with full carving | < 4 GB RAM (streaming) |
| Multi-TB | Carving-only mode recommended | Bounded by chunk pipeline |

---

## 4. Idempotency Patterns

### 4.1 Community Tier: Deterministic Output

The community CLI produces byte-identical output for identical input. This is a forensic requirement: re-running the same image must produce the same evidence file. Non-determinism destroys courtroom defensibility.

| Mechanism | Purpose | Implementation |
|-----------|---------|----------------|
| USN offset sorting | Canonical record ordering | `records.sort_by_key(\|r\| r.usn_offset)` after parallel merge |
| Stable sort for ties | Reproducible tie-breaking | Records with same USN offset maintain parse order |
| No HashMap iteration in output | HashMap order is non-deterministic | All output iterates sorted Vec, not HashMap |
| Timestamp normalization | UTC epoch for invalid timestamps | `unwrap_or_else(\|\| DateTime::from_timestamp(0, 0))` |
| Carved record deduplication | Deterministic merge | Dedup by (MFT entry, sequence, USN offset) tuple |
| RecordSource tagging | Provenance tracking | Every record tagged: `Journal`, `LogFile`, `Carved`, or `Ghost` |

Parallel processing determinism:

```rust
// src/usn/parallel.rs
pub fn parse_usn_journal_parallel(data: &[u8]) -> Result<Vec<UsnRecord>> {
    let chunks: Vec<_> = data.chunks(CHUNK_SIZE).enumerate().collect();

    let mut all_records: Vec<UsnRecord> = chunks
        .par_iter()
        .flat_map(|(chunk_idx, chunk)| {
            parse_usn_journal(chunk).unwrap_or_else(|e| {
                log::warn!("Chunk {} parse failed: {}", chunk_idx, e);
                Vec::new() // Empty on failure, not a pipeline error
            })
        })
        .collect();

    // Deterministic ordering: sort by USN offset
    all_records.sort_by_key(|r| r.usn_offset);
    Ok(all_records)
}
```

**Chunk boundary handling**: The parallel parser uses `find_first_record_boundary()` to scan forward from each chunk start, finding the first valid record header at an 8-byte-aligned offset. Records that span chunk boundaries are handled by the next chunk's boundary scan.

### 4.2 Enterprise Tier: Case Submission Idempotency

Agent-to-server case submissions use idempotency keys to handle network retries without duplicating case data.

```rust
pub struct CaseSubmission {
    pub idempotency_key: Uuid,  // Generated by agent, sent in gRPC metadata
    pub agent_id: AgentId,
    pub case_hash: [u8; 32],    // SHA-256 of case payload
    pub submitted_at: DateTime<Utc>,
}

// Server-side deduplication:
// 1. Check idempotency_key in PostgreSQL before processing
// 2. If exists and case_hash matches, return cached response
// 3. If exists and case_hash differs, reject (corrupt retry)
// 4. If not exists, process and store with idempotency_key
```

```sql
-- Case evidence insertion is idempotent via ON CONFLICT
INSERT INTO case_evidence (
    case_id, evidence_hash, file_path, record_count,
    ghost_count, carved_count, submitted_at
) VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (case_id, evidence_hash)
DO UPDATE SET
    record_count = EXCLUDED.record_count,
    ghost_count = EXCLUDED.ghost_count,
    carved_count = EXCLUDED.carved_count,
    submitted_at = EXCLUDED.submitted_at
RETURNING id;
```

---

## 5. Retry Strategies

The community CLI has no network dependencies and therefore no retry logic. Retry strategies apply to enterprise tier services only.

### 5.1 Per-Service Retry Configuration

```rust
pub struct RetryConfig {
    pub max_retries: u32,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub backoff_multiplier: f64,
    pub jitter_factor: f64,
}

impl RetryConfig {
    pub fn grpc_agent() -> Self {
        Self {
            max_retries: 5,
            initial_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 2.0,
            jitter_factor: 0.25,
        }
    }

    pub fn database() -> Self {
        Self {
            max_retries: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(5),
            backoff_multiplier: 2.0,
            jitter_factor: 0.1,
        }
    }

    pub fn opensearch() -> Self {
        Self {
            max_retries: 3,
            initial_delay: Duration::from_millis(200),
            max_delay: Duration::from_secs(10),
            backoff_multiplier: 2.0,
            jitter_factor: 0.15,
        }
    }

    pub fn websocket_reconnect() -> Self {
        Self {
            max_retries: 10,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            backoff_multiplier: 1.5,
            jitter_factor: 0.3,
        }
    }
}
```

### 5.2 Exponential Backoff with Jitter

```rust
pub async fn retry_with_backoff<F, T, E>(
    config: &RetryConfig,
    operation_name: &str,
    mut operation: impl FnMut() -> F,
) -> Result<T, E>
where
    F: Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let mut delay = config.initial_delay;
    let mut last_error = None;

    for attempt in 0..=config.max_retries {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                tracing::warn!(
                    operation = operation_name,
                    attempt = attempt + 1,
                    max = config.max_retries + 1,
                    error = %e,
                    next_delay_ms = delay.as_millis(),
                    "retryable operation failed"
                );
                last_error = Some(e);

                if attempt < config.max_retries {
                    let jitter = rand::thread_rng()
                        .gen_range(0.0..config.jitter_factor)
                        * delay.as_secs_f64();
                    tokio::time::sleep(delay + Duration::from_secs_f64(jitter)).await;
                    delay = Duration::from_secs_f64(
                        (delay.as_secs_f64() * config.backoff_multiplier)
                            .min(config.max_delay.as_secs_f64()),
                    );
                }
            }
        }
    }

    Err(last_error.unwrap())
}
```

### 5.3 Agent Reconnection Protocol

When a collection agent loses its gRPC connection to katana-server:

```
1. Detect disconnect (missed heartbeat or gRPC UNAVAILABLE)
2. Buffer pending results to local SQLite WAL
3. Retry with exponential backoff (500ms -> 1s -> 2s -> 4s -> 8s -> 16s -> 30s cap)
4. On reconnect:
   a. Re-authenticate with mTLS (certificate must still be valid)
   b. Send buffered results with idempotency keys
   c. Resume heartbeat cycle
5. After 10 failed retries (~2 minutes):
   a. Switch to "offline mode"
   b. Continue processing cases locally
   c. Queue all results with timestamps
   d. Attempt reconnect every 60s in background
6. On server recovery:
   a. Bulk-submit queued results (oldest first)
   b. Server deduplicates via idempotency keys
   c. Agent resumes normal streaming
```

### 5.4 Connection Pool Resilience

```rust
/// PostgreSQL connection pool with health-aware configuration
pub fn create_pg_pool(config: &DatabaseConfig) -> PgPoolOptions {
    PgPoolOptions::new()
        .max_connections(config.max_connections)  // 20 default
        .min_connections(config.min_connections)   // 2 default
        .acquire_timeout(Duration::from_secs(5))
        .idle_timeout(Duration::from_secs(300))
        .max_lifetime(Duration::from_secs(1800))  // Recycle every 30 min
        .test_before_acquire(true)                 // Validate connection health
}

/// OpenSearch client with retry-aware transport
pub fn create_opensearch_client(config: &SearchConfig) -> OpenSearchClient {
    let transport = TransportBuilder::new(config.hosts.clone())
        .retry_on_status(&[429, 502, 503, 504])
        .retry_on_timeout(true)
        .max_retries(3)
        .timeout(Duration::from_secs(10))
        .build()
        .expect("opensearch transport");

    OpenSearchClient::new(transport)
}
```

---

## 6. Health Checks

### 6.1 Community Tier: Pre-flight Validation

The CLI runs pre-flight checks before beginning pipeline execution, catching configuration and environment problems before spending time on processing.

```rust
pub fn run_preflight(config: &KatanaConfig) -> PreflightResult {
    let mut checks = Vec::new();
    let mut warnings = Vec::new();
    let mut can_proceed = true;

    // Verify image file exists and is readable
    match std::fs::metadata(&config.image_path) {
        Ok(meta) => checks.push(PreflightCheck::ImageReadable {
            path: config.image_path.clone(),
            size_bytes: meta.len(),
        }),
        Err(e) => {
            checks.push(PreflightCheck::ImageUnreadable {
                path: config.image_path.clone(),
                error: e.to_string(),
            });
            can_proceed = false;
        }
    }

    // Check available disk space (need ~2x image size for outputs)
    let required = estimate_output_size(&config);
    let available = disk_space_available(&config.output_dir);
    if available < required {
        warnings.push(format!(
            "Low disk space: need {}MB, have {}MB",
            required / 1_048_576, available / 1_048_576
        ));
    }

    // Check libewf availability for E01 images
    if config.image_format == ImageFormat::E01 {
        match libewf_version() {
            Some(version) => checks.push(PreflightCheck::LibewfAvailable { version }),
            None => {
                warnings.push("libewf not found; E01 support unavailable".into());
                can_proceed = false;
            }
        }
    }

    PreflightResult { checks, can_proceed, warnings }
}
```

### 6.2 Community Tier: Post-Analysis Health Report

Every run emits a deterministic health summary to stderr:

```rust
struct AnalysisHealth {
    tier: CorrelationTier,
    total_records_parsed: u64,
    corrupt_records_skipped: u64,
    truncated_records: u64,
    paths_resolved: u64,
    paths_unresolved: u64,
    ghost_records_found: u64,
    carved_usn_records: u64,
    carved_mft_entries: u64,
    mftmirr_mismatches: u64,
    triage_questions_answered: u64,
    triage_questions_inconclusive: u64,
    output_formats_succeeded: Vec<String>,
    output_formats_failed: Vec<(String, String)>,
}

impl AnalysisHealth {
    fn status(&self) -> HealthStatus {
        if self.corrupt_records_skipped > self.total_records_parsed {
            HealthStatus::Unhealthy // More corrupt than valid
        } else if self.paths_unresolved as f64 / self.total_records_parsed as f64 > 0.1 {
            HealthStatus::Degraded // >10% unresolved paths
        } else {
            HealthStatus::Healthy
        }
    }
}
```

Example output:

```
[*] Analysis Health: Healthy
[*]   Tier: QuadLink (4 artifacts)
[*]   Records: 847,293 parsed, 12 corrupt, 1 truncated
[*]   Paths: 847,280 resolved, 13 unresolved (0.002%)
[*]   Ghost records: 142 recovered from $LogFile
[*]   Carved: 1,247 USN + 89 MFT from unallocated
[*]   $MFTMirr: 0 mismatches
[*]   Triage: 12/12 questions answered
[*]   Output: CSV, JSONL, SQLite (all succeeded)
```

### 6.3 Enterprise Tier: Service Health Endpoints

katana-server exposes health endpoints compatible with Kubernetes liveness and readiness probes.

```rust
// katana-server/src/health.rs

/// GET /health/live -- Kubernetes liveness probe
/// Returns 200 if the process is running. No dependency checks.
pub async fn liveness() -> StatusCode {
    StatusCode::OK
}

/// GET /health/ready -- Kubernetes readiness probe
/// Returns 200 only if all critical dependencies are reachable.
pub async fn readiness(State(deps): State<AppDeps>) -> (StatusCode, Json<HealthReport>) {
    let mut report = HealthReport::default();

    report.postgres = match deps.pg_pool.acquire().await {
        Ok(mut conn) => match sqlx::query("SELECT 1").execute(&mut *conn).await {
            Ok(_) => ServiceHealth::Healthy,
            Err(e) => ServiceHealth::Unhealthy(e.to_string()),
        },
        Err(e) => ServiceHealth::Unhealthy(e.to_string()),
    };

    report.opensearch = match deps.search_client.ping().await {
        Ok(_) => ServiceHealth::Healthy,
        Err(e) => ServiceHealth::Unhealthy(e.to_string()),
    };

    report.redis = match deps.redis_pool.get().await {
        Ok(mut conn) => match redis::cmd("PING").query_async::<_, String>(&mut conn).await {
            Ok(_) => ServiceHealth::Healthy,
            Err(e) => ServiceHealth::Unhealthy(e.to_string()),
        },
        Err(e) => ServiceHealth::Unhealthy(e.to_string()),
    };

    let status = if report.all_healthy() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status, Json(report))
}

/// GET /health/agents -- Agent fleet health
pub async fn agent_health(State(deps): State<AppDeps>) -> Json<Vec<AgentStatus>> {
    let agents = deps.agent_registry.connected_agents().await;
    Json(agents.into_iter().map(|a| AgentStatus {
        agent_id: a.id,
        hostname: a.hostname,
        last_heartbeat: a.last_heartbeat,
        cases_processed: a.cases_processed,
        status: if a.last_heartbeat.elapsed() < Duration::from_secs(30) {
            "healthy"
        } else {
            "stale"
        },
    }).collect())
}
```

### 6.4 Health Check Summary

| Check | Tier | Mechanism | Interval | Failure Action |
|-------|------|-----------|----------|---------------|
| Image readable | Community | Pre-flight CLI check | Once at start | Abort with diagnostic |
| Disk space | Community | Pre-flight CLI check | Once at start | Warn, continue |
| libewf available | Community | Pre-flight CLI check | Once at start | Abort if E01 image |
| Memory available | Community | Pre-flight CLI check | Once at start | Adjust batch sizes |
| Process alive | Enterprise | `GET /health/live` | 10s (K8s) | Restart pod |
| Dependencies ready | Enterprise | `GET /health/ready` | 10s (K8s) | Remove from load balancer |
| Agent connected | Enterprise | `GET /health/agents` | 15s (heartbeat) | Mark stale after 30s |
| PostgreSQL | Enterprise | Readiness probe | 10s | Circuit breaker opens |
| OpenSearch | Enterprise | Readiness probe | 10s | Degrade to SQL search |
| Redis | Enterprise | Readiness probe | 10s | Switch to in-process queue |

---

## 7. Malformed NTFS Data Handling

Disk images from compromised systems frequently contain anti-forensic modifications, partially overwritten structures, and filesystem corruption. Every corruption type has a defined detection and recovery path.

### 7.1 USN Record Corruption Patterns

| Corruption Type | Detection | Recovery |
|-----------------|-----------|----------|
| Invalid record length (0 or >64KB) | Length sanity check | Skip 8 bytes, scan for next valid header |
| Wrong version field (not 2 or 3) | Version check after length | Skip record, advance by length |
| Truncated filename | `filename_length + filename_offset > record_length` | Log warning, use empty filename |
| Invalid FILETIME (pre-2000 or post-2030) | Timestamp sanity range | Normalize to Unix epoch 0 |
| Zero-filled journal regions | 4-byte zero check | Skip silently (normal sparse file behavior) |
| Partial record at data end | `offset + record_len > data.len()` | Log, break parse loop |
| V4 records (range-tracking) | Major version == 4 | Skip entirely (no per-file data) |
| Garbage between valid records | `is_valid_record_start()` scan | Forward-scan in 8-byte increments |

### 7.2 MFT Entry Corruption Patterns

| Corruption Type | Detection | Recovery |
|-----------------|-----------|----------|
| Missing "FILE" signature | First 4 bytes != `FILE` | Skip entry, advance 1024 bytes |
| Invalid fixup array | Fixup signature mismatch | Log warning, skip entry |
| Reused entry (sequence mismatch) | Sequence number comparison | Rewind algorithm handles naturally |
| Corrupted attribute chain | Invalid attribute type/length | Stop parsing entry, use partial data |
| Overwritten by file data | Heuristic: entropy check | Skip entry |
| $MFT itself truncated | Fewer entries than expected | Parse what exists, log count |
| Circular parent references | Depth limit (256) | Emit `UNRESOLVED(entry:seq)` path |

### 7.3 $LogFile Corruption Patterns

| Corruption Type | Detection | Recovery |
|-----------------|-----------|----------|
| Invalid RCRD page header | Magic bytes check | Skip to next 4096-byte page boundary |
| Embedded USN with bad length | Same checks as USN parser | Skip that embedded record |
| Circular log wrapping | Sequence number tracking | Follow wrap-around, deduplicate |
| $LogFile cleared by attacker | No valid RCRD pages found | Log warning, continue without ghost records |
| Partial page at file end | Page size check | Skip partial page |

### 7.4 $MFTMirr Integrity Failure Handling

```rust
// $MFTMirr contains copies of the first 4 MFT entries (entries 0-3).
// A byte-level mismatch indicates either:
// 1. Normal: $MFTMirr not synced after recent changes (common)
// 2. Suspicious: Targeted tampering with critical metadata
//
// Response: Log detailed mismatch report, flag for analyst review,
// but NEVER halt the pipeline -- the $MFT data itself is still usable.

fn check_mftmirr_integrity(mft_data: &[u8], mirr_data: &[u8]) -> IntegrityResult {
    let entries_to_check = [0, 1, 2, 3];
    let mut mismatches = Vec::new();

    for &entry_num in &entries_to_check {
        let offset = entry_num * 1024;

        if offset + 1024 > mft_data.len() || offset + 1024 > mirr_data.len() {
            mismatches.push(IntegrityMismatch::TruncatedData(entry_num));
            continue;
        }

        let mft_entry = &mft_data[offset..offset + 1024];
        let mirr_entry = &mirr_data[offset..offset + 1024];

        if mft_entry != mirr_entry {
            mismatches.push(IntegrityMismatch::ByteMismatch {
                entry: entry_num,
                first_diff_offset: mft_entry.iter().zip(mirr_entry)
                    .position(|(a, b)| a != b)
                    .unwrap_or(0),
            });
        }
    }

    IntegrityResult { mismatches }
    // Pipeline continues regardless -- mismatches are informational
}
```

---

## 8. Unallocated Space Carving Resilience

Carved data is inherently unreliable. Resilience here means validating aggressively and never trusting carved structures implicitly.

### 8.1 Carved USN Record Validation Pipeline

```
Raw bytes from unallocated cluster
  |
  v
[1] Structural check: Valid record header?
  |-- No --> discard
  v
[2] Size sanity: record_len in [0x3C, 65536]?
  |-- No --> discard
  v
[3] Version check: major_version in {2, 3}?
  |-- No --> discard
  v
[4] Timestamp sanity: year in [2000, 2030]?
  |-- No --> discard (or flag as suspicious)
  v
[5] Filename validation: valid UTF-16LE? No control chars?
  |-- No --> discard
  v
[6] Deduplication: (entry, sequence, usn_offset) already seen?
  |-- Yes --> discard duplicate
  v
[7] Accept as carved record, tag with RecordSource::Carved
```

### 8.2 Carved MFT Entry Validation Pipeline

```
Raw 1024 bytes at 1024-byte-aligned offset
  |
  v
[1] Signature: first 4 bytes == "FILE"?
  |-- No --> discard
  v
[2] Fixup array: valid offset and count?
  |-- No --> discard
  v
[3] Attribute chain: at least one valid attribute?
  |-- No --> discard
  v
[4] Filename attribute: extractable and valid UTF-16LE?
  |-- No --> discard
  v
[5] Parent reference: non-zero entry number?
  |-- No --> accept but cannot resolve path
  v
[6] Deduplication: (entry, sequence) already in allocated MFT?
  |-- Yes --> discard (allocated version is authoritative)
  v
[7] Accept, seed into RewindEngine via seed_carved_entries()
```

### 8.3 Confidence Tagging for Carved Records

Carved records are never presented as equivalent to allocated records:

| Field | Treatment |
|-------|-----------|
| `source` column in output | `Carved` (distinct from `Journal`, `LogFile`, `Ghost`) |
| Path resolution | Prefixed with `[CARVED]` if MFT entry was also carved |
| Triage inclusion | Carved records included in triage queries but flagged |
| Statistics | Separate count: "Carved: 1,247 USN + 89 MFT from unallocated" |

---

## 9. Output Module Resilience

If one output format fails (e.g., SQLite write error), other requested formats must still succeed.

### 9.1 Independent Output Isolation

```rust
fn generate_outputs(records: &[ResolvedRecord], cli: &Cli) -> Vec<OutputResult> {
    let mut results = Vec::new();

    if let Some(csv_path) = &cli.csv {
        results.push(("CSV", write_csv(records, csv_path)));
    }
    if let Some(jsonl_path) = &cli.jsonl {
        results.push(("JSONL", write_jsonl(records, jsonl_path)));
    }
    if let Some(sqlite_path) = &cli.sqlite {
        results.push(("SQLite", write_sqlite(records, sqlite_path)));
    }
    if let Some(body_path) = &cli.body {
        results.push(("Body", write_body(records, body_path)));
    }
    if let Some(tln_path) = &cli.tln {
        results.push(("TLN", write_tln(records, tln_path)));
    }
    if let Some(xml_path) = &cli.xml {
        results.push(("XML", write_xml(records, xml_path)));
    }

    for (format, result) in &results {
        match result {
            Ok(_) => log::info!("[+] {} output written successfully", format),
            Err(e) => log::error!("[-] {} output failed: {}", format, e),
        }
    }

    results
}
```

### 9.2 Output Error Scenarios

| Scenario | Behavior |
|----------|----------|
| Disk full during CSV write | CSV fails, JSONL/SQLite/others still attempted |
| SQLite locked by another process | SQLite fails with clear error, others proceed |
| Invalid path (permissions) | That format fails, others proceed |
| BufWriter flush error | Logged, partial output may exist (documented) |
| HTML report template error | Report fails, timeline exports unaffected |

---

## 10. Triage Engine Resilience

Each of the 12 triage questions runs independently. A regex compilation failure or unexpected data pattern in one question does not prevent the other 11 from executing.

### 10.1 Per-Question Isolation

```rust
pub fn run_triage(records: &[ResolvedRecord], questions: &[TriageQuestion]) -> Vec<TriageResult> {
    questions.iter().map(|q| {
        match evaluate_question(records, q) {
            Ok(result) => result,
            Err(e) => {
                log::warn!("Triage question '{}' failed: {}", q.id, e);
                TriageResult {
                    question: q.clone(),
                    evidence_found: false,
                    matched_indices: vec![],
                    error: Some(format!("{}", e)),
                }
            }
        }
    }).collect()
}
```

### 10.2 Source-Aware Confidence

| Source | Triage Weight | Display |
|--------|---------------|---------|
| `Journal` | Full confidence | Normal display |
| `LogFile` | Full confidence (ghost) | Flagged as recovered |
| `Carved` | Lower confidence | Marked as carved |
| `Ghost` | Full confidence | Flagged as wiped-then-recovered |

---

## 11. Error Reporting Philosophy

Security Ronin Katana follows a "log everything, crash nothing" philosophy. Every anomaly is a forensic finding, not a bug.

### 11.1 Error Classification

| Category | Examples | Response | Retry |
|----------|----------|----------|-------|
| **Configuration** | Missing libewf, bad image path, invalid output format | Abort with diagnostic (exit code 1) | No |
| **Corrupt Data** | Malformed USN record, bad MFT entry, truncated E01 segment | Skip record, continue parsing | No |
| **Resource Exhaustion** | OOM, disk full, file descriptor limit | Reduce batch size, flush buffers, degrade | No |
| **Transient (Enterprise)** | Network timeout, connection reset, 503 | Retry with exponential backoff | Yes |
| **Security (Enterprise)** | Invalid mTLS cert, expired token, unauthorized agent | Reject immediately, log to audit trail | No |
| **Fatal** | Kernel panic, SIGKILL, hardware failure | Crash. On restart, check idempotency and resume | N/A |

### 11.2 Never Panic Guarantee

The following patterns are forbidden in production code paths (enforced by code review):

```rust
// FORBIDDEN in data-handling code:
.unwrap()           // Use .unwrap_or_default() or ? operator
.expect("...")      // Use .context("...")? with anyhow
panic!("...")       // Use bail!("...") or return Err(...)
unreachable!()      // Use a safe default or log::error + fallback

// ALLOWED only in:
// - Test code (#[cfg(test)])
// - Proven-safe conversions (e.g., known-valid constant construction)
// - CLI argument validation (pre-analysis)
```

### 11.3 anyhow Error Chain

All errors use `anyhow::Result` with `.context()` for rich error chains:

```rust
let data = std::fs::read(&path)
    .with_context(|| format!("Failed to read $UsnJrnl at {}", path.display()))?;
```

Produces human-readable messages:

```
Error: Failed to parse $MFT (1073741824 bytes)

Caused by:
    Invalid MFT entry at offset 0x4A000: fixup signature mismatch
```

---

## 12. Resilience Decision Matrix

| Situation | Decision | Rationale |
|-----------|----------|-----------|
| Corrupt USN record | Log + skip + count | One bad record must not halt 847,293 good ones |
| Missing $MFT | Degrade to USN-Only mode | Filenames without paths are still valuable |
| Missing $LogFile | Skip ghost recovery | Reduced visibility, not a failure |
| Missing $MFTMirr | Skip integrity check | Informational only, not blocking |
| Circular parent reference | Depth limit (256) + UNRESOLVED tag | Prevents infinite recursion |
| Invalid timestamp | Normalize to epoch 0 | Preserves record, flags anomaly |
| Multi-TB image | Streaming chunks + bounded RAM | Never OOM on large inputs |
| Output format fails | Isolate per-format | One broken pipe does not poison others |
| Triage query fails | Per-question isolation | 11/12 answers better than 0/12 |
| Carved data untrusted | Validate + tag + separate stats | Analyst decides trustworthiness |
| All artifacts corrupt | Exit with clear diagnostic | No silent empty output |
| Agent disconnects (enterprise) | Buffer locally, backoff, offline mode | Cases processed regardless |
| Database unreachable (enterprise) | Circuit breaker, read-only fallback | Search degrades, never stops |
| Server overwhelmed (enterprise) | Circuit breaker on inbound channels | Shed load, protect core |

---

## Cross-References

| Document | Relationship |
|----------|-------------|
| [Architecture Blueprint](../ARCHITECTURE_BLUEPRINT.md) | Defines pipeline topology and stage budgets referenced in timeout configuration |
| [Pipeline Specifications](./PIPELINE_SPECIFICATIONS.md) | Defines stage contracts and edge cases that drive fallback chain design |
| [Observability Framework](./OBSERVABILITY_FRAMEWORK.md) | Consumes health check data, circuit breaker state, and degradation events |
| [North Star Extract](../NORTHSTAR_EXTRACT.md) | Axiom 1 ("Forensic Integrity > Feature Velocity") governs the partial-results principle |
| [Brand Guidelines](../BRAND_GUIDELINES.md) | "Deterministic, reproducible, court-defensible" drives idempotency requirements |
