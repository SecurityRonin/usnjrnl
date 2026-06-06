# Security Ronin Katana: Two-Tier Tech Stack Research

> Research date: 2026-03-09
> Purpose: Technology stack decisions for community (Apache-2.0) + enterprise (proprietary) DFIR triage tool

---

## 1. Rust Open-Core Patterns

### Recommendation: Separate Crates in Two Repos + Local Cargo Workspace

**Architecture:**

```
# Public repo (GitHub, Apache-2.0)
katana/
  Cargo.toml          # virtual manifest, resolver = "2"
  crates/
    katana-core/      # USN Journal, MFT parsing, timeline engine
    katana-cli/       # clap-based CLI (community product)
    katana-formats/   # output formatters (JSON, CSV, JSONL, etc.)
    katana-ewf/       # E01/raw image handling
    katana-ntfs/      # NTFS parsing wrappers

# Private repo (GitHub private, proprietary)
katana-enterprise/
  Cargo.toml          # virtual manifest
  crates/
    katana-server/    # Axum API + RBAC + WebSocket
    katana-agent/     # collection agent (tonic gRPC)
    katana-pcap/      # PCAP/NetFlow analysis
    katana-collab/    # collaborative investigation
    katana-import/    # Velociraptor/Binalyze importers
```

**Linking pattern (local development):**

```toml
# katana-enterprise/Cargo.toml
[workspace.dependencies]
katana-core = { path = "../katana/crates/katana-core" }
katana-formats = { path = "../katana/crates/katana-formats" }
```

**Key decisions:**

| Decision | Choice | Rationale |
|---|---|---|
| Workspace linking | Path dependencies | Same pattern as chatham/chatham-pro with pnpm. No private registry needed for solo dev. |
| Feature flags | Use sparingly in core | Gate optional heavy deps (e.g., `rayon` parallelism). Don't gate licensing — that's the crate boundary. |
| Publishing core | crates.io (later) | Publish `katana-core` and `katana-formats` to crates.io for community adoption. |
| Enterprise publish guard | `publish = false` | Set in all enterprise crate Cargo.tomls to prevent accidental crates.io publish. |
| Licensing headers | Per-file SPDX | `// SPDX-License-Identifier: Apache-2.0` in public, `// SPDX-License-Identifier: LicenseRef-Proprietary` in private. |

**Private registry (future):** When team grows beyond solo dev, consider [Kellnr](https://kellnr.io/) (self-hosted, Rust-native) or [Shipyard.rs](https://shipyard.rs/) (hosted). Until then, path deps are simpler.

**References:**
- [Cargo Workspaces (Rust Book)](https://doc.rust-lang.org/book/ch14-03-cargo-workspaces.html)
- [Cargo Features (Cargo Book)](https://doc.rust-lang.org/cargo/reference/features.html)
- [Cargo Alternative Registries RFC](https://rust-lang.github.io/rfcs/2141-alternative-registries.html)
- [Large Rust Workspaces (matklad)](https://matklad.github.io/2021/08/22/large-rust-workspaces.html)
- [Kellnr Private Registry](https://kellnr.io/)
- [Shipyard.rs](https://shipyard.rs/)
- [Dual Licensing vs Open Core (TermsFeed)](https://www.termsfeed.com/blog/dual-licensing-vs-open-core/)
- [Open Core Handbook (OCV)](https://handbook.opencoreventures.com/how-we-work/open-core)
- [Private Crate in Rust (Rust Forum)](https://users.rust-lang.org/t/how-would-you-create-a-proprietary-library-in-rust/62928)

---

## 2. Enterprise Forensic Tool Stacks — Lessons Learned

### Tool Architecture Comparison

| Tool | Language | Storage | Agent Model | Key Insight |
|---|---|---|---|---|
| **Velociraptor** | Go | File store + SQLite | Client-server, single binary, VQL | Single binary is brilliant for deployment. VQL-style query language is the killer feature. |
| **Timesketch** | Python | OpenSearch + PostgreSQL | Web app, no agent | Collaborative sketches + stories = how teams actually investigate. Redis/Celery for background processing. |
| **Autopsy/TSK** | Java/C | SQLite/PostgreSQL + Solr | Desktop app, NetBeans RCP | Ingest module plugin system drives extensibility. Multi-user mode (v4) added PostgreSQL. |
| **KAPE** | .NET | File-based output | Standalone collector | Target/module pattern (collect then parse) is clean separation of concerns. |
| **Plaso** | Python | SQLite/Elasticsearch | CLI processor | Super-timeline generation from 100+ parsers. CPU-bound, benefits from parallelism. |

### Architecture Lessons for Katana

1. **Single binary distribution** (Velociraptor pattern): Rust already compiles to static binaries. Ship one binary that acts as CLI, server, or agent based on subcommand.
2. **Query language**: VQL's power is letting analysts write custom collection logic. Consider a mini-DSL or filter expression language for triage rules (you already have triage questions).
3. **Timeline-first design** (Timesketch pattern): The unified timeline is the core abstraction. All parsers produce timestamped events into a common schema.
4. **Ingest module pattern** (Autopsy pattern): Define a trait-based parser interface so new artifact types can be added without modifying core.
5. **Collect-then-parse** (KAPE pattern): Separate collection from analysis. The agent collects; the server/CLI parses.
6. **Background processing**: Use Tokio tasks (not Celery) for async processing in the enterprise tier.

**References:**
- [Velociraptor Overview](https://docs.velociraptor.app/docs/overview/)
- [Velociraptor API (gRPC)](https://docs.velociraptor.app/docs/server_automation/server_api/)
- [Scaling Velociraptor](https://docs.velociraptor.app/blog/2021/2021-04-29-scaling-velociraptor-57acc4df76ed/)
- [Timesketch (GitHub)](https://github.com/google/timesketch)
- [Timesketch Architecture (Medium)](https://medium.com/timesketch/timeline-analysis-from-the-future-59a7ad7da498)
- [Autopsy Description](https://www.sleuthkit.org/autopsy/desc.php)
- [Autopsy Ingest Module API](https://sleuthkit.org/autopsy/docs/api-docs/4.3/mod_ingest_page.html)
- [Scaling Enterprise Forensic Timelining (Recon InfoSec)](https://blog.reconinfosec.com/scaling-enterprise-forensic-timelining)
- [Hayabusa + Velociraptor + Timesketch Pipeline](https://freedurok.github.io/posts/01_velociraptor-to-timesketch/)

---

## 3. PCAP/NetFlow Parsing in Rust

### Recommended Crate Stack

| Layer | Crate | Why |
|---|---|---|
| **PCAP file reading** | `pcap-parser` | Pure Rust, zero-copy, supports PCAP + PCAPNG, no libpcap dependency. Ideal for forensic file analysis (not live capture). |
| **Protocol dissection** | `etherparse` | Pure Rust, no allocations, no syscalls. Parses Ethernet/IPv4/IPv6/TCP/UDP/ICMP headers. Best for layer 2-4 analysis. |
| **Deep packet inspection** | `pnet` (optional) | Lower-level, requires libpcap. Use only if you need raw socket access or live capture in the agent. |
| **NetFlow v5/v7/v9** | `netflow_parser` | Most actively maintained (72K+ downloads). Zero-allocation iterator. Supports V5, V7, V9, IPFIX. Template caching for V9/IPFIX. |
| **IPFIX** | `netflow_parser` or `rsipfix` | `netflow_parser` covers IPFIX. `rsipfix` is RFC7011-focused if you need strict compliance. |
| **Flow service** | `netgauze-flow-service` | Building blocks for IPFIX/NetFlow collectors. Use if building a standalone collector component. |

### Architecture for Forensic PCAP Analysis

```
E01/raw image -> katana-core (mount/extract) -> PCAP files
                                                    |
                                              pcap-parser (zero-copy read)
                                                    |
                                              etherparse (protocol dissection)
                                                    |
                                              Timeline events (common schema)
```

**Performance notes:**
- `etherparse` uses zero-copy slice-based parsing — ideal for multi-GB PCAP files
- `pcap-parser` supports streaming parse (don't load entire file into memory)
- Combine with `rayon` for parallel processing of independent PCAP files
- Rust achieves ~85% of C performance for packet processing (acceptable tradeoff for safety)

**References:**
- [pcap-parser (GitHub)](https://github.com/rusticata/pcap-parser)
- [etherparse (GitHub)](https://github.com/JulianSchmid/etherparse)
- [pcap crate (docs.rs)](https://docs.rs/pcap)
- [netflow_parser (crates.io)](https://crates.io/crates/netflow_parser/0.6.2)
- [netgauze-flow-service (crates.io)](https://crates.io/crates/netgauze-flow-service)
- [rsipfix (crates.io)](https://crates.io/crates/rsipfix)
- [Network Analysis in Rust (Medium)](https://medium.com/@akmot9/title-network-analysis-in-rust-using-the-pcap-and-pnet-crates-to-capture-and-analyze-network-94e1627536b1)
- [Building a Network Protocol Analyzer in Rust](https://r3zz.io/posts/simple-network-protocol-analyzer-rust/)
- [Rust vs C Performance (CodiLime)](https://codilime.com/blog/rust-vs-c-safety-and-performance-in-low-level-network-programming/)

---

## 4. Collection Agent Architecture

### Velociraptor's Agent Model (Reference Architecture)

Velociraptor's agent is instructive:
- **Single binary** acts as both client and server
- **Persistent HTTP/2 connection** to server (not polling)
- **VQL engine** runs locally on endpoint for flexible collection
- **Mutual TLS** with Velociraptor CA for authentication
- **gRPC API** for external automation and multi-frontend scaling

### Recommended Rust Collection Agent Stack

| Component | Crate/Technology | Purpose |
|---|---|---|
| **gRPC framework** | `tonic` (v0.12+) | Client-server communication. 171M+ downloads, async/await, HTTP/2 native. |
| **Protobuf** | `prost` | Protocol Buffers codegen, used by tonic. |
| **mTLS** | `tonic` + `rustls` | Mutual TLS via `tls-ring` feature flag. No OpenSSL dependency. |
| **Async runtime** | `tokio` | Foundation for tonic, already in your stack. |
| **Serialization** | `serde` + `bincode` | Efficient binary serialization for collected artifacts. |
| **File collection** | `walkdir` + `memmap2` | Fast filesystem traversal and memory-mapped file reading. |
| **Compression** | `zstd` | Compress collected data before transmission. ~3-5x better than gzip at similar speed. |
| **Binary size** | `cargo build --release` + `strip` + `upx` | Target < 5MB agent binary. |

### Agent Architecture Design

```
┌─────────────────────────────────┐
│  Katana Agent (single binary)   │
│                                 │
│  ┌───────────┐ ┌──────────────┐ │
│  │ Collector  │ │ NTFS/USN     │ │
│  │ Engine     │ │ Parser       │ │
│  └─────┬─────┘ └──────┬───────┘ │
│        │               │         │
│  ┌─────┴───────────────┴──────┐  │
│  │  gRPC Client (tonic+mTLS)  │  │
│  └─────────────┬──────────────┘  │
│                │                 │
└────────────────┼─────────────────┘
                 │ HTTP/2 + mTLS
┌────────────────┼─────────────────┐
│  Katana Server                   │
│  ┌─────────────┴──────────────┐  │
│  │  gRPC Server (tonic)       │  │
│  └─────────────┬──────────────┘  │
│  ┌─────────────┴──────────────┐  │
│  │  Task Dispatcher           │  │
│  └─────────────┬──────────────┘  │
│  ┌─────────────┴──────────────┐  │
│  │  SQLite/PostgreSQL Store   │  │
│  └────────────────────────────┘  │
└──────────────────────────────────┘
```

### gRPC vs HTTP/2 REST Decision

| Factor | gRPC (tonic) | HTTP/2 REST (axum) |
|---|---|---|
| **Schema enforcement** | Protobuf (strong) | JSON Schema (weak) |
| **Streaming** | Bidirectional native | SSE or WebSocket |
| **Binary efficiency** | Protobuf (compact) | JSON (verbose) |
| **mTLS** | Built-in via tonic | Manual via rustls |
| **Client codegen** | Automatic from .proto | Manual |
| **Browser compat** | Needs grpc-web proxy | Native |

**Verdict:** Use **gRPC (tonic)** for agent-to-server communication (binary efficiency, streaming, mTLS). Use **HTTP/2 REST (axum)** for the web UI API (browser compatibility).

**References:**
- [Tonic (GitHub)](https://github.com/hyperium/tonic)
- [Tonic docs.rs](https://docs.rs/tonic/latest/tonic/)
- [gRPC Basics for Rust Developers](https://dockyard.com/blog/2025/04/08/grpc-basics-for-rust-developers)
- [Tonic Rust Guide 2025](https://generalistprogrammer.com/tutorials/tonic-rust-crate-guide)
- [gRPC Rust Joining gRPC Family (2025)](https://tldrecap.tech/posts/2025/grpconf-india/grpc-ai-rust-proxyless/)
- [Velociraptor Client Deployment](https://docs.velociraptor.app/docs/deployment/clients/)
- [Velociraptor API (gRPC)](https://docs.velociraptor.app/docs/server_automation/server_api/)
- [velociraptor-api-rs (Rust client)](https://github.com/hillu/velociraptor-api-rs)

---

## 5. Multi-Device Evidence Correlation

### Approaches from Existing Tools

| Tool | Correlation Method |
|---|---|
| **Timesketch** | Multiple timelines in one sketch, unified search across all, tagging + annotations for cross-device links |
| **Autopsy** | Multi-user case with shared PostgreSQL, timeline visualization across data sources |
| **FACE Framework** | Automated correlation of disk image + memory + network capture + logs into coherent system view |
| **FTK** | Single case ingests mobile + computer + cloud data, unified processing engine |
| **Belkasoft X** | Timeline analysis + geolocation mapping across mobile, cloud, computer evidence |

### Recommended Correlation Architecture for Katana Enterprise

**1. Common Event Schema (the foundation)**

```rust
pub struct ForensicEvent {
    pub timestamp: DateTime<Utc>,
    pub timestamp_type: TimestampType, // Created, Modified, Accessed, MFTModified, etc.
    pub source_device: DeviceId,       // Which disk image / agent
    pub source_artifact: ArtifactType, // USN, MFT, EventLog, PCAP, etc.
    pub source_path: String,           // Original evidence path
    pub description: String,
    pub metadata: serde_json::Value,   // Artifact-specific fields
    pub tags: Vec<String>,
    pub iocs: Vec<IoC>,               // Extracted indicators
}
```

**2. Correlation Strategies**

| Strategy | Description | Implementation |
|---|---|---|
| **Temporal proximity** | Events within N seconds across devices | Sort unified timeline, sliding window comparison |
| **IoC matching** | Same IP, hash, domain, user across devices | Index IoCs in HashMap, cross-reference on insert |
| **Lateral movement detection** | Login on Device A -> execution on Device B | Pattern match on authentication + process creation events |
| **File hash correlation** | Same file appearing on multiple devices | SHA-256 index across all MFT/USN data |
| **Network session linking** | PCAP shows connection between Device A IP and Device B IP | Join on IP:port pairs with temporal overlap |

**3. Storage for Correlation**

- **Community tier:** SQLite with FTS5 for full-text search (already using `rusqlite`)
- **Enterprise tier:** PostgreSQL for multi-user + OpenSearch for full-text search and aggregation (mirrors Timesketch architecture)
- **Correlation index:** In-memory HashMap for active investigation, persisted to DB

**References:**
- [FACE: Automated Evidence Correlation (ScienceDirect)](https://www.sciencedirect.com/science/article/pii/S1742287608000340)
- [DFRWS 2021 Challenge: Multisource Correlation](https://dfrws.org/forensic-challenges/)
- [Autopsy 2025 Timeline Analysis](https://www.onlinehashcrack.com/guides/security-tools/autopsy-forensics-2025-analyze-disk-images.php)
- [Timesketch (GitHub)](https://github.com/google/timesketch)
- [Timesketch.org](https://timesketch.org/)
- [FTK Forensic Toolkit](https://www.exterro.com/digital-forensics-software/ftk-forensic-toolkit)

---

## 6. Web Framework for Enterprise Features

### Recommendation: Axum for API + WebSocket

| Factor | Axum (recommended) | Actix-Web |
|---|---|---|
| **Ecosystem alignment** | Built by Tokio team; tonic also uses Tokio | Separate actor runtime |
| **Middleware** | Tower layers (composable, shared with tonic) | Custom middleware system |
| **Learning curve** | Easier for solo dev | Steeper (actor model) |
| **WebSocket** | Supported via tokio-tungstenite | Built-in actors (overkill for your scale) |
| **Performance** | 1M requests in 6s (hello-world) | 10-15% faster raw throughput |
| **gRPC coexistence** | Shares Tokio runtime with tonic | Separate runtime complexity |

**Why Axum wins for Katana:** You're already using Tokio (via rayon/async). Tonic (agent gRPC) shares the Tokio runtime. Axum + tonic + tokio = one unified async runtime. Actix-Web's actor model adds complexity you don't need as a solo dev.

### Recommended Enterprise API Stack

| Component | Crate | Version | Purpose |
|---|---|---|---|
| **Web framework** | `axum` | 0.8 | REST API + WebSocket |
| **HTTP middleware** | `tower-http` | 0.6 | CORS, compression, tracing, auth layers |
| **Authentication** | `jsonwebtoken` | 9 | JWT signing/verification |
| **Password hashing** | `argon2` | 0.5 | Argon2id for user passwords |
| **RBAC** | Custom Tower middleware | — | Role extraction from JWT claims |
| **Database** | `sqlx` | 0.8 | Async PostgreSQL (enterprise) |
| **WebSocket** | `axum` built-in | — | Real-time collaboration events |
| **Rate limiting** | `governor` | 0.6 | API rate limiting |
| **Serialization** | `serde` + `serde_json` | — | Already in your stack |
| **OpenAPI docs** | `utoipa` | 5 | Auto-generated API documentation |

### RBAC Design

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Role {
    Analyst,       // Read-only, run queries, view timelines
    Investigator,  // Analyst + create cases, add evidence, annotate
    Admin,         // Investigator + manage users, configure system
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,           // user ID
    pub roles: Vec<Role>,
    pub org_id: Uuid,        // tenant isolation
    pub exp: usize,
    pub iat: usize,
}
```

### WebSocket Collaboration Protocol

For collaborative investigation (Timesketch-style), use a simple pub/sub pattern over WebSocket:

```
Client -> Server: { "type": "subscribe", "case_id": "..." }
Server -> Client: { "type": "event_added", "case_id": "...", "event": {...} }
Server -> Client: { "type": "annotation_added", "case_id": "...", "annotation": {...} }
Server -> Client: { "type": "tag_added", "case_id": "...", "tag": {...} }
```

No need for a full CRDT/OT system at this stage. Simple last-write-wins with WebSocket broadcast is sufficient.

**References:**
- [Axum vs Actix vs Rocket 2026 (Medium)](https://aarambhdevhub.medium.com/rust-web-frameworks-in-2026-axum-vs-actix-web-vs-rocket-vs-warp-vs-salvo-which-one-should-you-2db3792c79a2)
- [Rust Web Development 2026 (Calmops)](https://calmops.com/programming/rust-web-development-2026/)
- [Axum vs Actix 2025 Data-Backed (Medium)](https://ritik-chopra28.medium.com/rust-web-frameworks-in-2025-actix-vs-axum-a-data-backed-verdict-b956eb1c094e)
- [JWT Auth with Axum (CodeVoWeb)](https://codevoweb.com/jwt-authentication-in-rust-using-axum-framework/)
- [JWT Auth with Axum (Conzit)](https://conzit.com/post/mastering-jwt-authentication-in-rust-with-axum-framework)
- [Securing Rust APIs 2026 (OneUpTime)](https://oneuptime.com/blog/post/2026-01-07-rust-api-security/view)
- [jsonwebtoken (GitHub)](https://github.com/Keats/jsonwebtoken)
- [Actix-Web JWT Tokens (CodeVoWeb)](https://codevoweb.com/rust-actix-web-jwt-access-and-refresh-tokens/)
- [Rust Web Frameworks Compared (DEV)](https://dev.to/leapcell/rust-web-frameworks-compared-actix-vs-axum-vs-rocket-4bad)

---

## Summary: Complete Enterprise Stack

```
┌─────────────────────────────────────────────────────────┐
│                  Security Ronin Katana                   │
├─────────────────────────┬───────────────────────────────┤
│  Community (Apache-2.0) │  Enterprise (Proprietary)     │
├─────────────────────────┼───────────────────────────────┤
│  katana-core            │  katana-server (axum)         │
│  katana-cli (clap)      │  katana-agent (tonic+gRPC)    │
│  katana-formats         │  katana-pcap (pcap-parser+    │
│  katana-ewf             │    etherparse)                │
│  katana-ntfs            │  katana-collab (WebSocket)    │
│                         │  katana-import (Velo/Binalyze)│
├─────────────────────────┼───────────────────────────────┤
│  Storage: rusqlite      │  Storage: sqlx+PostgreSQL     │
│                         │  Search: OpenSearch           │
│                         │  Auth: jsonwebtoken+argon2    │
│                         │  Agent comms: tonic+mTLS      │
├─────────────────────────┴───────────────────────────────┤
│  Shared: tokio, serde, rayon, chrono                    │
└─────────────────────────────────────────────────────────┘
```

### Key Cargo Dependencies (New for Enterprise)

```toml
# Enterprise Cargo.toml additions
[workspace.dependencies]
axum = { version = "0.8", features = ["ws", "macros"] }
tower-http = { version = "0.6", features = ["cors", "compression-zstd", "trace"] }
tonic = { version = "0.12", features = ["tls-ring"] }
prost = "0.13"
sqlx = { version = "0.8", features = ["runtime-tokio", "postgres", "uuid", "chrono"] }
jsonwebtoken = "9"
argon2 = "0.5"
governor = "0.6"
pcap-parser = "0.16"
etherparse = "0.16"
netflow_parser = "0.6"
zstd = "0.13"
utoipa = { version = "5", features = ["axum_extras"] }
```
