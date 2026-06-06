# Security Ronin Katana: Observability

> Structured tracing, pipeline stage timing, and forensic-safe metrics for a Rust deterministic processing pipeline.

**Product:** Security Ronin Katana (usnjrnl-forensic)
**Version:** 2.0
**Date:** 2026-03-10
**Status:** Active
**Cross-references:** [ARCHITECTURE_BLUEPRINT.md](../ARCHITECTURE_BLUEPRINT.md) | [NORTHSTAR.md](../NORTHSTAR.md) | [SECURITY_ARCHITECTURE.md](../SECURITY_ARCHITECTURE.md)

---

## 1. Trace Architecture

Security Ronin Katana is a deterministic Rust processing pipeline, not an agent-based system. Traces map to pipeline stage execution rather than LLM request lifecycles.

### 1.1 Trace Hierarchy

```
Pipeline Run Trace (root span)
|
+-- Image Parsing Span
|   +-- EWF Decompression Span
|   +-- Partition Detection Span (MBR/GPT)
|   +-- NTFS Volume Discovery Span
|
+-- Artifact Parsing Span (parallel)
|   +-- USN Journal Parser Span
|   +-- MFT Parser Span
|   +-- LogFile Parser Span
|   +-- Unallocated Carver Span
|
+-- Correlation Span
|   +-- Rewind Engine Span
|   +-- QuadLink Correlator Span
|
+-- Triage Span
|   +-- Triage Engine Span (21 questions)
|   +-- Rule Engine Span (YAML rules)
|
+-- Output Span
    +-- Format Writer Span (per format: CSV, JSONL, SQLite, Body, TLN, XML, HTML)
```

Each span carries a pipeline-scoped `run_id` (UUIDv7) that ties all stages together. The community tier writes spans to `tracing` crate structured logs. The enterprise tier exports spans via OpenTelemetry to a collector.

### 1.2 Event Types

| Event | Description | Attributes |
|-------|-------------|------------|
| `pipeline.start` | Pipeline execution begins | `run_id`, `image_hash` (SHA-256 of first 4KB), `image_size_bytes` |
| `pipeline.end` | Pipeline execution completes | `duration_ms`, `success`, `total_records`, `output_formats[]` |
| `stage.start` | Individual pipeline stage begins | `stage_name`, `crate`, `parallelism` |
| `stage.end` | Individual pipeline stage completes | `duration_ms`, `records_processed`, `records_per_second` |
| `stage.error` | Stage encounters a recoverable error | `stage_name`, `error_type`, `error_message` |
| `artifact.discovered` | NTFS artifact located on volume | `artifact_type` ($UsnJrnl, $MFT, $LogFile), `offset`, `size_bytes` |
| `parser.chunk` | Parser completes a rayon chunk | `chunk_index`, `chunk_size`, `records_parsed` |
| `triage.question` | Triage question evaluated | `question_id`, `tier`, `result` (true/false), `evidence_count` |
| `triage.rule` | Custom YAML rule fired | `rule_name`, `match_count` |
| `ghost.recovered` | Ghost record recovered from unallocated space | `recovery_method`, `record_count` |
| `output.written` | Output file written | `format`, `record_count`, `file_size_bytes` |
| `correlation.match` | QuadLink cross-artifact correlation | `source_artifacts[]`, `correlation_type`, `confidence` |
| `rewind.resolution` | Path resolved by Rewind Engine | `resolution_depth`, `unknown_paths_remaining` |

### 1.3 Span Attribute Schema

Every span includes these base attributes:

| Attribute | Type | Description |
|-----------|------|-------------|
| `run_id` | string | UUIDv7, unique per pipeline invocation |
| `service.name` | string | `katana-cli` (community) or `katana-server` (enterprise) |
| `service.version` | string | Cargo package version from `CARGO_PKG_VERSION` |
| `host.arch` | string | Target architecture (x86_64, aarch64) |
| `os.type` | string | Operating system (linux, macos, windows) |

Enterprise spans add:

| Attribute | Type | Description |
|-----------|------|-------------|
| `tenant.id` | string | Schema-per-tenant identifier |
| `user.role` | string | RBAC role (Admin, Case Manager, Examiner, Reviewer, Auditor) |
| `request.id` | string | HTTP request ID from axum middleware |

---

## 2. Trace Handler Interface

The trace handler is a Rust trait that abstracts over community and enterprise observability backends. All pipeline stages instrument through this trait so the same code paths work in both tiers.

### 2.1 Trace Handler Trait

```rust
// src/observability/handler.rs

use std::collections::HashMap;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct TraceEvent {
    pub event_type: String,
    pub timestamp: Instant,
    pub run_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub attributes: HashMap<String, serde_json::Value>,
}

pub trait TraceHandler: Send + Sync {
    fn name(&self) -> &str;
    fn on_event(&self, event: &TraceEvent);
    fn flush(&self) {}
    fn shutdown(&self) {}
}

pub struct TraceManager {
    handlers: Vec<Box<dyn TraceHandler>>,
}

impl TraceManager {
    pub fn new() -> Self {
        Self { handlers: Vec::new() }
    }

    pub fn register(&mut self, handler: Box<dyn TraceHandler>) {
        self.handlers.push(handler);
    }

    pub fn emit(&self, event: &TraceEvent) {
        for handler in &self.handlers {
            handler.on_event(event);
        }
    }

    pub fn flush(&self) {
        for handler in &self.handlers {
            handler.flush();
        }
    }

    pub fn shutdown(&self) {
        for handler in &self.handlers {
            handler.flush();
            handler.shutdown();
        }
    }
}
```

### 2.2 Community Handler (tracing crate)

The community tier handler emits structured logs via the `tracing` crate with `tracing-subscriber`. This handler is always active and requires zero configuration.

```rust
// src/observability/community.rs

use tracing::{info, warn};

pub struct TracingCrateHandler {
    verbose: bool,
}

impl TracingCrateHandler {
    pub fn new(verbose: bool) -> Self {
        Self { verbose }
    }
}

impl TraceHandler for TracingCrateHandler {
    fn name(&self) -> &str {
        "tracing-crate"
    }

    fn on_event(&self, event: &TraceEvent) {
        let sanitized = sanitize_attributes(&event.attributes);

        match event.event_type.as_str() {
            "pipeline.start" => {
                info!(
                    run_id = %event.run_id,
                    image_size = %sanitized.get("image_size_bytes")
                        .and_then(|v| v.as_u64()).unwrap_or(0),
                    "Pipeline started"
                );
            }
            "stage.end" => {
                info!(
                    run_id = %event.run_id,
                    stage = %sanitized.get("stage_name")
                        .and_then(|v| v.as_str()).unwrap_or("unknown"),
                    duration_ms = %sanitized.get("duration_ms")
                        .and_then(|v| v.as_u64()).unwrap_or(0),
                    records = %sanitized.get("records_processed")
                        .and_then(|v| v.as_u64()).unwrap_or(0),
                    "Stage completed"
                );
            }
            "stage.error" => {
                warn!(
                    run_id = %event.run_id,
                    stage = %sanitized.get("stage_name")
                        .and_then(|v| v.as_str()).unwrap_or("unknown"),
                    error = %sanitized.get("error_message")
                        .and_then(|v| v.as_str()).unwrap_or("unknown"),
                    "Stage error"
                );
            }
            _ if self.verbose => {
                info!(
                    run_id = %event.run_id,
                    event_type = %event.event_type,
                    "Trace event"
                );
            }
            _ => {}
        }
    }
}
```

---

## 3. OpenTelemetry Handler (Enterprise)

The enterprise tier exports traces and metrics via OpenTelemetry to a collector. This handler activates only when `katana-server` runs with `OTEL_EXPORTER_OTLP_ENDPOINT` configured.

### 3.1 Implementation

```rust
// src/observability/otel.rs

use opentelemetry::{global, trace::{Tracer, SpanKind}};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::trace::TracerProvider;

pub struct OtelHandler {
    tracer: Box<dyn opentelemetry::trace::Tracer + Send + Sync>,
}

impl OtelHandler {
    pub fn new(service_name: &str, endpoint: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .build()?;

        let provider = TracerProvider::builder()
            .with_batch_exporter(exporter)
            .build();

        global::set_tracer_provider(provider.clone());
        let tracer = provider.tracer(service_name.to_string());

        Ok(Self {
            tracer: Box::new(tracer),
        })
    }
}

impl TraceHandler for OtelHandler {
    fn name(&self) -> &str {
        "opentelemetry"
    }

    fn on_event(&self, event: &TraceEvent) {
        let sanitized = sanitize_attributes(&event.attributes);
        let mut span = self.tracer.span_builder(&event.event_type)
            .with_kind(SpanKind::Internal)
            .start(&*self.tracer);

        for (key, value) in &sanitized {
            span.set_attribute(opentelemetry::KeyValue::new(
                key.clone(),
                value.to_string(),
            ));
        }

        span.end();
    }

    fn flush(&self) {
        if let Err(e) = global::tracer_provider().force_flush() {
            tracing::warn!("OTel flush failed: {e}");
        }
    }

    fn shutdown(&self) {
        global::shutdown_tracer_provider();
    }
}
```

### 3.2 Bootstrap

```rust
// src/observability/bootstrap.rs

use std::env;

pub fn init_telemetry(verbose: bool) -> TraceManager {
    let mut manager = TraceManager::new();

    // Community handler is always active
    manager.register(Box::new(TracingCrateHandler::new(verbose)));

    // Enterprise handler activates when OTEL endpoint is configured
    if let Ok(endpoint) = env::var("OTEL_EXPORTER_OTLP_ENDPOINT") {
        let service_name = env::var("OTEL_SERVICE_NAME")
            .unwrap_or_else(|_| "katana-server".to_string());

        match OtelHandler::new(&service_name, &endpoint) {
            Ok(handler) => {
                manager.register(Box::new(handler));
                tracing::info!("OpenTelemetry exporter initialized: {endpoint}");
            }
            Err(e) => {
                tracing::warn!("Failed to initialize OTel exporter: {e}");
            }
        }
    }

    manager
}

pub fn shutdown_telemetry(manager: &TraceManager) {
    manager.shutdown();
    tracing::info!("Telemetry shutdown complete");
}
```

---

## 4. Pipeline Stage Timing

Security Ronin Katana has a 35-second P95 latency budget. Observability tracks each stage against its individual budget to identify regressions before they compound.

### 4.1 Stage Budgets and Metrics

| Stage | Crate | Budget (s) | Parallelism | Key Metric |
|-------|-------|-----------|-------------|------------|
| EWF Parser | `katana-ewf` | 2 | single-threaded | `stage.ewf.duration_ms` |
| NTFS Volume | `katana-ntfs` | 1 | single-threaded | `stage.ntfs.duration_ms` |
| USN Journal Parser | `katana-core` | 5 | rayon | `stage.usn.duration_ms`, `stage.usn.records_per_sec` |
| MFT Parser | `katana-core` | 5 | rayon | `stage.mft.duration_ms`, `stage.mft.entries_parsed` |
| Ghost Recovery | `katana-core` | 3 | single-threaded | `stage.ghost.duration_ms`, `stage.ghost.records_recovered` |
| Unallocated Carving | `katana-core` | 5 | rayon | `stage.carve.duration_ms`, `stage.carve.records_carved` |
| QuadLink Correlator | `katana-core` | 3 | single-threaded | `stage.quadlink.duration_ms`, `stage.quadlink.correlations` |
| Triage Engine | `katana-core` | 5 | rayon | `stage.triage.duration_ms`, `stage.triage.questions_fired` |
| Output Formatter | `katana-formats` | 3 | single-threaded | `stage.output.duration_ms`, `stage.output.formats_written` |

**Total Budget:** 32 seconds active processing + 3 seconds I/O margin = 35 seconds P95.

### 4.2 Stage Timing Implementation

```rust
// src/observability/timing.rs

use std::time::Instant;
use tracing::{info, warn};

pub struct StageTimer {
    stage_name: String,
    budget_ms: u64,
    start: Instant,
}

impl StageTimer {
    pub fn start(stage_name: &str, budget_seconds: u64) -> Self {
        info!(stage = stage_name, "Stage started");
        Self {
            stage_name: stage_name.to_string(),
            budget_ms: budget_seconds * 1000,
            start: Instant::now(),
        }
    }

    pub fn finish(self, records_processed: u64) -> StageTiming {
        let duration_ms = self.start.elapsed().as_millis() as u64;
        let records_per_sec = if duration_ms > 0 {
            (records_processed as f64 / duration_ms as f64 * 1000.0) as u64
        } else {
            0
        };
        let over_budget = duration_ms > self.budget_ms;

        if over_budget {
            warn!(
                stage = %self.stage_name,
                duration_ms = duration_ms,
                budget_ms = self.budget_ms,
                overage_ms = duration_ms - self.budget_ms,
                "Stage exceeded budget"
            );
        } else {
            info!(
                stage = %self.stage_name,
                duration_ms = duration_ms,
                budget_ms = self.budget_ms,
                records = records_processed,
                records_per_sec = records_per_sec,
                "Stage completed within budget"
            );
        }

        StageTiming {
            stage_name: self.stage_name,
            duration_ms,
            budget_ms: self.budget_ms,
            records_processed,
            records_per_sec,
            over_budget,
        }
    }
}

#[derive(Debug, Clone)]
pub struct StageTiming {
    pub stage_name: String,
    pub duration_ms: u64,
    pub budget_ms: u64,
    pub records_processed: u64,
    pub records_per_sec: u64,
    pub over_budget: bool,
}
```

### 4.3 CLI Progress Output (Community)

The `--verbose` flag enables per-stage timing output to stderr. Without the flag, the CLI shows a compact progress bar via `indicatif`.

```
# Default output (stderr, indicatif progress bar)
[===========>        ] 67% Parsing USN Journal... 568K/847K records

# --verbose output (stderr, structured tracing)
[2026-03-10T14:22:01Z INFO  katana] Pipeline started run_id=019532a1-...
[2026-03-10T14:22:03Z INFO  katana] Stage completed stage=ewf duration_ms=1823 budget_ms=2000 records=1
[2026-03-10T14:22:04Z INFO  katana] Stage completed stage=ntfs duration_ms=612 budget_ms=1000 records=3
[2026-03-10T14:22:08Z INFO  katana] Stage completed stage=usn duration_ms=4201 budget_ms=5000 records=847291 records_per_sec=201592
[2026-03-10T14:22:12Z INFO  katana] Stage completed stage=mft duration_ms=3918 budget_ms=5000 records=524288 records_per_sec=133821
[2026-03-10T14:22:14Z INFO  katana] Stage completed stage=ghost duration_ms=2103 budget_ms=3000 records=1247
[2026-03-10T14:22:18Z INFO  katana] Stage completed stage=carve duration_ms=4512 budget_ms=5000 records=89432 records_per_sec=19822
[2026-03-10T14:22:20Z INFO  katana] Stage completed stage=quadlink duration_ms=2344 budget_ms=3000 correlations=412891
[2026-03-10T14:22:24Z INFO  katana] Stage completed stage=triage duration_ms=3891 budget_ms=5000 questions_fired=21
[2026-03-10T14:22:26Z INFO  katana] Stage completed stage=output duration_ms=2201 budget_ms=3000 formats=7
[2026-03-10T14:22:26Z INFO  katana] Pipeline completed duration_ms=24605 total_records=847291 success=true
```

When stderr is not a TTY (piped), `indicatif` falls back to periodic percentage updates every 10% to avoid flooding log files.

---

## 5. PII Sanitization

Forensic evidence paths are sensitive. They reveal case names, suspect identifiers, organization names, and investigation details. All observability output sanitizes these values before they reach any log sink or trace backend.

### 5.1 Sanitization Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `strict` | Hash all file paths, redact case identifiers, strip hostnames | Production (both tiers) |
| `moderate` | Hash file paths but preserve directory depth and extension | Staging / internal debugging |
| `permissive` | Log everything as-is | Development with synthetic data only |

The default mode is `strict`. The `permissive` mode requires both `--permissive-logging` flag AND the `KATANA_DEV_MODE=1` environment variable. This two-key interlock prevents accidental exposure in production.

### 5.2 What Gets Sanitized

| Field | Strict | Moderate | Permissive | Rationale |
|-------|--------|----------|------------|-----------|
| Evidence file path (E01 source) | SHA-256 hash | Hash, preserve extension | As-is | Path contains case name, suspect ID |
| NTFS file paths (parsed records) | SHA-256 hash | Hash, preserve depth + extension | As-is | Reveals file activity under investigation |
| Hostname | `[REDACTED]` | First 4 chars + `***` | As-is | Identifies target machine |
| SID / Username | `[REDACTED]` | SHA-256 hash | As-is | Identifies persons of interest |
| IP addresses | `[REDACTED]` | Preserve subnet (/24) | As-is | Identifies network location |
| Volume serial number | SHA-256 hash | SHA-256 hash | As-is | Unique device identifier |
| `run_id` | Preserved | Preserved | Preserved | No PII, needed for trace correlation |
| `stage_name` | Preserved | Preserved | Preserved | No PII, system metadata |
| `duration_ms` | Preserved | Preserved | Preserved | No PII, performance data |
| `records_processed` | Preserved | Preserved | Preserved | No PII, aggregate count |

### 5.3 Implementation

```rust
// src/observability/sanitize.rs

use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SanitizationMode {
    Strict,
    Moderate,
    Permissive,
}

impl SanitizationMode {
    pub fn from_env() -> Self {
        if std::env::var("KATANA_DEV_MODE").is_ok() {
            match std::env::var("KATANA_SANITIZATION_MODE").as_deref() {
                Ok("permissive") => Self::Permissive,
                Ok("moderate") => Self::Moderate,
                _ => Self::Strict,
            }
        } else {
            match std::env::var("KATANA_SANITIZATION_MODE").as_deref() {
                Ok("moderate") => Self::Moderate,
                // Permissive silently upgrades to strict outside dev mode
                _ => Self::Strict,
            }
        }
    }
}

const PII_FIELDS: &[&str] = &[
    "evidence_path", "file_path", "ntfs_path", "hostname",
    "sid", "username", "ip_address", "volume_serial",
];

const SAFE_FIELDS: &[&str] = &[
    "run_id", "stage_name", "duration_ms", "records_processed",
    "records_per_sec", "event_type", "budget_ms", "format",
    "question_id", "tier", "result", "error_type",
    "image_size_bytes", "chunk_index", "chunk_size",
    "correlation_type", "recovery_method", "record_count",
];

pub fn sanitize_attributes(
    attrs: &HashMap<String, serde_json::Value>,
) -> HashMap<String, serde_json::Value> {
    let mode = SanitizationMode::from_env();
    if mode == SanitizationMode::Permissive {
        return attrs.clone();
    }

    let mut sanitized = HashMap::new();
    for (key, value) in attrs {
        if SAFE_FIELDS.contains(&key.as_str()) {
            sanitized.insert(key.clone(), value.clone());
        } else if PII_FIELDS.contains(&key.as_str()) {
            sanitized.insert(key.clone(), sanitize_value(key, value, mode));
        } else {
            // Unknown fields default to strict treatment
            sanitized.insert(key.clone(), sanitize_value(key, value, mode));
        }
    }
    sanitized
}

fn sanitize_value(
    key: &str,
    value: &serde_json::Value,
    mode: SanitizationMode,
) -> serde_json::Value {
    match mode {
        SanitizationMode::Strict => {
            match key {
                "hostname" | "sid" | "username" | "ip_address" => {
                    serde_json::Value::String("[REDACTED]".to_string())
                }
                _ => {
                    let hash = sha256_short(&value.to_string());
                    serde_json::Value::String(hash)
                }
            }
        }
        SanitizationMode::Moderate => {
            if let Some(path_str) = value.as_str() {
                if key.contains("path") {
                    let p = Path::new(path_str);
                    let depth = p.components().count();
                    let ext = p.extension()
                        .and_then(|e| e.to_str())
                        .unwrap_or("none");
                    let hash = sha256_short(path_str);
                    serde_json::Value::String(
                        format!("[depth={depth},ext={ext}]{hash}")
                    )
                } else {
                    let hash = sha256_short(path_str);
                    serde_json::Value::String(hash)
                }
            } else {
                let hash = sha256_short(&value.to_string());
                serde_json::Value::String(hash)
            }
        }
        SanitizationMode::Permissive => value.clone(),
    }
}

fn sha256_short(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result)[..16].to_string()
}
```

---

## 6. Request-Scoped Isolation (Enterprise)

When `katana-server` handles concurrent HTTP requests from multiple tenants, each request gets an isolated tracing context. Community CLI invocations skip this layer entirely since they process a single pipeline run in a single process.

### 6.1 Context Management

```rust
// src/observability/context.rs

use tokio::task_local;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct RequestContext {
    pub request_id: String,
    pub run_id: String,
    pub tenant_id: String,
    pub user_role: String,
    pub start_time: std::time::Instant,
}

task_local! {
    static REQUEST_CTX: RequestContext;
}

impl RequestContext {
    pub fn new(tenant_id: &str, user_role: &str) -> Self {
        Self {
            request_id: Uuid::now_v7().to_string(),
            run_id: Uuid::now_v7().to_string(),
            tenant_id: tenant_id.to_string(),
            user_role: user_role.to_string(),
            start_time: std::time::Instant::now(),
        }
    }
}

pub async fn with_request_context<F, R>(ctx: RequestContext, f: F) -> R
where
    F: std::future::Future<Output = R>,
{
    REQUEST_CTX.scope(ctx, f).await
}

pub fn current_run_id() -> String {
    REQUEST_CTX
        .try_with(|ctx| ctx.run_id.clone())
        .unwrap_or_else(|_| "cli-standalone".to_string())
}

pub fn current_tenant_id() -> Option<String> {
    REQUEST_CTX
        .try_with(|ctx| ctx.tenant_id.clone())
        .ok()
}
```

### 6.2 Axum Middleware Integration

```rust
// src/server/middleware/tracing.rs

use axum::{extract::Request, middleware::Next, response::Response};

pub async fn tracing_middleware(req: Request, next: Next) -> Response {
    let tenant_id = req.headers()
        .get("X-Tenant-ID")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");
    let user_role = req.headers()
        .get("X-User-Role")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");

    let ctx = RequestContext::new(tenant_id, user_role);
    let request_id = ctx.request_id.clone();

    let response = with_request_context(ctx, next.run(req)).await;

    tracing::info!(
        request_id = %request_id,
        status = %response.status().as_u16(),
        "Request completed"
    );

    response
}
```

### 6.3 Tenant Isolation in Traces

Every OTel span emitted from an enterprise request includes `tenant.id` as a span attribute. This enables per-tenant filtering in Grafana Tempo without risk of cross-tenant data leakage in dashboards. The schema-per-tenant DuckDB isolation (documented in SECURITY_ARCHITECTURE.md) extends to the observability layer: tenant ID is injected into the span context by the axum middleware and propagated through all child spans via `task_local`.

---

## 7. North Star Instrumentation

The North Star metric is **Paying Enterprise Customers** (target: 50). Observability feeds three input metrics that drive conversions: community adoption, product quality, and enterprise conversion rate.

### 7.1 Metric Collection

| Metric | Definition | Target | Collection Method |
|--------|------------|--------|-------------------|
| **Paying Enterprise Customers** | Active enterprise subscriptions | 50 | Billing system query (enterprise server) |
| **Community Active Users** | Unique users running triage per month | 500 | Opt-in telemetry counter or GitHub release download count |
| **Triage Completion Rate** | Pipeline runs completing without fatal error | >95% | `pipeline.end` events where `success=true` |
| **Time-to-First-Answer (P95)** | Wall-clock from CLI invocation to first triage answer rendered | <35s | `pipeline.end.duration_ms` P95 aggregation |
| **False Positive Rate** | Triage questions flagging benign activity as suspicious | <5% | Ground-truth corpus comparison in CI, updated per release |
| **Enterprise Conversion Rate** | Community orgs converting to paid within 90 days | 15% | CRM tracking (manual, not instrumented in code) |
| **Parse Rate** | Events processed per second across all artifact parsers | >100K/s | `stage.end.records_per_second` for USN and MFT stages |

### 7.2 Community Tier Metrics (tracing + --verbose)

Community metrics are computed locally and printed at pipeline completion. No data leaves the user's machine. The tool makes zero network connections in community mode.

```
# Printed at end of every run (stderr)
Pipeline complete: 847,291 records in 24.6s (34,443 records/sec)
Triage: 21 questions evaluated, 8 flagged, 0 errors
Output: 7 formats written (CSV, JSONL, SQLite, Body, TLN, XML, HTML)

# Additional output with --verbose
Stage budgets: 9/9 within budget
Peak memory: 142 MB
Ghost records recovered: 1,247
QuadLink correlations: 412,891
Rewind coverage: 847,291/847,291 (100%)
```

### 7.3 Enterprise Tier Metrics (Prometheus)

The enterprise server exposes a `/metrics` endpoint in Prometheus exposition format. These counters and histograms feed Grafana dashboards.

```rust
// src/server/metrics.rs

use prometheus::{
    register_counter_vec, register_histogram_vec,
    register_gauge, CounterVec, HistogramVec, Gauge,
};
use lazy_static::lazy_static;

lazy_static! {
    // Pipeline metrics
    pub static ref PIPELINE_RUNS: CounterVec = register_counter_vec!(
        "katana_pipeline_runs_total",
        "Total pipeline runs",
        &["tenant_id", "status"]
    ).unwrap();

    pub static ref PIPELINE_DURATION: HistogramVec = register_histogram_vec!(
        "katana_pipeline_duration_seconds",
        "Pipeline end-to-end duration",
        &["tenant_id"],
        vec![5.0, 10.0, 15.0, 20.0, 25.0, 30.0, 35.0, 45.0, 60.0]
    ).unwrap();

    pub static ref STAGE_DURATION: HistogramVec = register_histogram_vec!(
        "katana_stage_duration_seconds",
        "Per-stage duration",
        &["stage_name"],
        vec![0.5, 1.0, 2.0, 3.0, 5.0, 8.0, 10.0]
    ).unwrap();

    pub static ref RECORDS_PROCESSED: CounterVec = register_counter_vec!(
        "katana_records_processed_total",
        "Total records processed",
        &["stage_name"]
    ).unwrap();

    // Triage metrics
    pub static ref TRIAGE_QUESTIONS_FIRED: CounterVec = register_counter_vec!(
        "katana_triage_questions_fired_total",
        "Triage questions that returned true",
        &["question_id", "tier"]
    ).unwrap();

    pub static ref TRIAGE_COMPLETION: CounterVec = register_counter_vec!(
        "katana_triage_completion_total",
        "Triage runs by outcome",
        &["status"]
    ).unwrap();

    // Agent fleet metrics (enterprise collection agents)
    pub static ref ACTIVE_AGENTS: Gauge = register_gauge!(
        "katana_active_agents",
        "Number of connected collection agents"
    ).unwrap();

    pub static ref COLLECTION_QUEUE_DEPTH: Gauge = register_gauge!(
        "katana_collection_queue_depth",
        "Pending collection tasks in queue"
    ).unwrap();

    pub static ref AGENT_ERRORS: CounterVec = register_counter_vec!(
        "katana_agent_errors_total",
        "Agent-reported errors",
        &["agent_id", "error_type"]
    ).unwrap();

    pub static ref AGENT_LAST_HEARTBEAT: Gauge = register_gauge!(
        "katana_agent_last_heartbeat_seconds",
        "Seconds since last agent heartbeat"
    ).unwrap();
}
```

---

## 8. Dashboards and Alerts

### 8.1 Community Tier Dashboard

The community tier has no external dashboard. Observability is accessed through four mechanisms:

1. **CLI output**: End-of-run summary printed to stderr on every invocation. Prefixes convey severity: `[*]` informational, `[+]` success, `[!]` warning, `[-]` skip.
2. **`--verbose` flag**: Per-stage timing with budget comparison, record counts, and throughput rates.
3. **Structured logs**: `RUST_LOG=info katana ... 2>run.log` captures structured output. Pass `--json-logs` for machine-parseable JSON format enabling `jq` queries against the log file.
4. **Benchmark mode**: `katana benchmark --corpus corpus-standard` runs the 1GB reference corpus and reports P95 timing per stage with pass/fail against budget thresholds.

### 8.2 Enterprise Dashboard Panels (Grafana)

Recommended deployment: Grafana Cloud free tier (10K metrics, 50GB logs, 50GB traces) or self-hosted Grafana + Prometheus + Tempo stack on a single VPS.

```yaml
panels:
  - name: "Pipeline Health"
    type: stat + timeseries
    metrics:
      - katana_pipeline_runs_total (rate, by status)
      - katana_pipeline_duration_seconds (p50, p95, p99)
      - katana_triage_completion_total (rate, by status)

  - name: "Stage Performance"
    type: heatmap + table
    metrics:
      - katana_stage_duration_seconds (by stage_name, with budget line overlay)
      - katana_records_processed_total (rate, by stage_name)

  - name: "Agent Fleet"
    type: stat + timeseries
    metrics:
      - katana_active_agents (current gauge)
      - katana_collection_queue_depth (current gauge)
      - katana_agent_errors_total (rate, by agent_id)
      - katana_agent_last_heartbeat_seconds (staleness check)

  - name: "Triage Accuracy"
    type: bar + table
    metrics:
      - katana_triage_questions_fired_total (by question_id, tier)
      - False positive rate (computed from CI corpus runs, updated per release)

  - name: "North Star Tracking"
    type: stat + trend
    metrics:
      - Enterprise customer count (manual entry or billing API)
      - Community active users (GitHub API / opt-in telemetry)
      - P95 time-to-first-answer trend
      - Parse rate trend (records/sec P50)
```

### 8.3 Alert Rules

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| Pipeline failure rate > 5% | `rate(katana_pipeline_runs_total{status="error"}[5m]) / rate(katana_pipeline_runs_total[5m]) > 0.05` | Critical | Page on-call. Check parser regression against recent deploy. |
| P95 latency > 35s | `histogram_quantile(0.95, katana_pipeline_duration_seconds) > 35` | Warning | Inspect stage-level heatmap to identify bottleneck stage. |
| Stage budget exceeded 3x | Any stage exceeds its budget for 3 consecutive runs | Warning | Profile specific stage with `cargo flamegraph`. Check for input size anomaly. |
| Agent disconnected > 5 min | `katana_active_agents < expected_count` for 5 minutes | Warning | Check agent host connectivity. Verify mTLS cert expiry dates. |
| Collection queue depth > 100 | `katana_collection_queue_depth > 100` | Warning | Scale processing capacity or throttle intake rate. |
| Triage completion < 90% | `rate(katana_triage_completion_total{status="success"}[1h]) < 0.9` | Critical | Investigate corrupt input patterns or parser bug in recent release. |
| Zero pipeline runs in 1 hour | `absent(rate(katana_pipeline_runs_total[1h]))` during business hours | Info | Verify server health. Expected during off-hours; unexpected during active shifts. |
| Agent error spike | `rate(katana_agent_errors_total[5m]) > 10` | Warning | Check specific agent_id and error_type. May indicate endpoint host issue. |

### 8.4 Log Aggregation (Enterprise)

Enterprise structured logs flow through `tracing-subscriber` with a JSON formatter layer into the collector:

```
katana-server
  -> tracing-subscriber (JSON layer + PII sanitization filter)
  -> stdout
  -> log collector (Grafana Alloy / Promtail)
  -> Grafana Loki (or Grafana Cloud Logs)
```

Log retention: 30 days hot, 90 days cold. Forensic audit logs (hash-chain, documented in SECURITY_ARCHITECTURE.md) are retained separately for 7 years per compliance requirements and are not part of the observability log pipeline.

---

## 9. Rust Crate Dependencies

| Crate | Version | Purpose | Tier |
|-------|---------|---------|------|
| `tracing` | 0.1 | Structured instrumentation spans and events | Both |
| `tracing-subscriber` | 0.3 | Log formatting (fmt + JSON layers) | Both |
| `indicatif` | 0.17 | CLI progress bars with TTY detection | Community |
| `opentelemetry` | 0.28 | OTel trace API | Enterprise |
| `opentelemetry-otlp` | 0.28 | OTLP exporter (gRPC via tonic) | Enterprise |
| `opentelemetry_sdk` | 0.28 | OTel SDK (batch span processor) | Enterprise |
| `prometheus` | 0.13 | Prometheus metrics exposition | Enterprise |
| `sha2` | 0.10 | SHA-256 for PII field hashing in sanitization | Both |
| `uuid` | 1.0 | UUIDv7 for run_id and request_id generation | Both |
| `lazy_static` | 1.4 | Static metric registry initialization | Enterprise |

All enterprise crates are behind the `enterprise` Cargo feature flag. The community binary includes zero networking dependencies.

```toml
[features]
default = []
enterprise = [
    "dep:opentelemetry",
    "dep:opentelemetry-otlp",
    "dep:opentelemetry_sdk",
    "dep:prometheus",
    "dep:lazy_static",
    "dep:tokio",
]
```

---

## 10. Configuration Reference

### 10.1 Environment Variables

| Variable | Default | Description | Tier |
|----------|---------|-------------|------|
| `RUST_LOG` | `warn` | `tracing-subscriber` filter directive (e.g., `katana=info`, `katana::usn=debug`) | Both |
| `KATANA_SANITIZATION_MODE` | `strict` | PII sanitization level: strict, moderate, permissive | Both |
| `KATANA_DEV_MODE` | unset | Required interlock for permissive sanitization | Dev only |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | unset | OTel collector URL; presence activates OTel handler | Enterprise |
| `OTEL_SERVICE_NAME` | `katana-server` | Service name in OTel spans | Enterprise |

### 10.2 CLI Flags

| Flag | Description |
|------|-------------|
| `--verbose` / `-v` | Enable per-stage timing output to stderr with budget comparison |
| `--json-logs` | Emit structured JSON logs to stderr instead of human-readable format |
| `--quiet` / `-q` | Suppress all progress output; only exit code indicates success/failure |
| `--audit-log <path>` | Write forensic audit trail JSON sidecar alongside output |
| `--stats` / `--no-stats` | Toggle reason breakdown summary (default: enabled) |

### 10.3 Grafana Cloud Free Tier Limits

| Resource | Free Tier Limit | Katana Usage Estimate (50 customers) |
|----------|-----------------|--------------------------------------|
| Metrics | 10,000 series | ~200 series (well within limit) |
| Logs | 50 GB/month | ~5 GB/month at 100 runs/day |
| Traces | 50 GB/month | ~2 GB/month at 100 runs/day |
| Retention | 13 months (metrics), 30 days (logs/traces) | Sufficient for trend analysis |

Self-hosted alternative: Prometheus + Grafana + Tempo + Loki on a single VPS ($20/month) handles the expected enterprise load through the first 50 customers. Upgrade to dedicated infrastructure when fleet size or query volume justifies the operational cost.
