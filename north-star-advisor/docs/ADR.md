# Security Ronin Katana: Architecture Decision Records

> **Parent**: [INDEX.md](INDEX.md)
> **Format**: ADR-NNNN (sequential, never reused)
> **Product**: Security Ronin Katana (usnjrnl-forensic)
> **Date**: 2026-03-10

Architecture decisions that shape Security Ronin Katana's forensic triage system, from licensing strategy through security posture.

---

## ADR Index

| ADR | Title | Status | Date |
|-----|-------|--------|------|
| [ADR-0001](#adr-0001-two-repo-open-core-apache-20--proprietary) | Two-Repo Open Core (Apache-2.0 + Proprietary) | Accepted | 2026-03-10 |
| [ADR-0002](#adr-0002-rust-2021-as-primary-language) | Rust 2021 as Primary Language | Accepted | 2026-03-10 |
| [ADR-0003](#adr-0003-trait-based-extension-architecture) | Trait-Based Extension Architecture | Accepted | 2026-03-10 |
| [ADR-0004](#adr-0004-axum--tonic-for-enterprise-layer) | Axum + Tonic for Enterprise Layer | Accepted | 2026-03-10 |
| [ADR-0005](#adr-0005-assume-breach-collection-agent-security) | Assume-Breach Collection Agent Security | Accepted | 2026-03-10 |
| [ADR-0006](#adr-0006-hash-chain-audit-trail) | Hash-Chain Audit Trail | Accepted | 2026-03-10 |
| [ADR-0007](#adr-0007-buyer-based-open-core-tier-split) | Buyer-Based Open Core Tier Split | Accepted | 2026-03-10 |
| [ADR-0008](#adr-0008-netflow-first-network-forensics) | NetFlow-First Network Forensics | Accepted | 2026-03-10 |
| [ADR-0009](#adr-0009-sqlite-community--postgresql--tantivy-enterprise) | SQLite (Community) / PostgreSQL + Tantivy (Enterprise) | Accepted | 2026-03-10 |
| [ADR-0010](#adr-0010-buy-sso-delay-soc-2) | Buy SSO, Delay SOC 2 | Accepted | 2026-03-10 |

---

## ADR-0001: Two-Repo Open Core (Apache-2.0 + Proprietary)

**Date:** 2026-03-10
**Status:** Accepted
**Axioms:** [Axiom 4] Open Core Trust > Revenue Extraction

### Context

Security Ronin Katana targets two distinct buyer profiles: solo DFIR consultants who need free, auditable tools (community tier) and MSSP/enterprise IR teams willing to pay for collaboration and scale (enterprise tier). The business model requires monetization without eroding the community trust that drives adoption. Forensic tools used in court proceedings must have auditable source code to satisfy Daubert admissibility standards. Mixing proprietary and open-source code in a single repository creates licensing ambiguity that undermines both goals.

### Decision

Maintain two separate repositories with independent Cargo workspaces:

- **katana** (public, Apache-2.0): Community crates including `katana-core`, `katana-cli`, `katana-ewf`, `katana-ntfs`, `katana-formats`. Contains all extension traits (`EvidenceSource`, `TriageEngine`, `OutputSink`).
- **katana-pro** (private, Proprietary): Enterprise crates including `katana-server`, `katana-agent`, `katana-rbac`, `katana-collab`, `katana-pcap`, `katana-multi`, `katana-import`. Depends on community crates via path dependencies (dev) or git dependencies (CI).

Each crate declares its own license in `Cargo.toml`. Community features never migrate to the enterprise tier.

### Alternatives Rejected

| Alternative | Reason Rejected |
|-------------|-----------------|
| **Monorepo with license headers** | Per-file licensing creates confusion for contributors and complicates compliance audits. A single contributor license becomes ambiguous when files carry different headers. |
| **Feature flags in single crate** | `cargo build --features enterprise` leaks proprietary code into the public repo. Even with `.cargo/config.toml` guards, accidental exposure is one misconfigured CI pipeline away. |
| **Single permissive license (Apache-2.0 for everything)** | No monetization path. Enterprise features like RBAC, collection agents, and collaborative investigation represent significant engineering investment with no revenue mechanism. |
| **AGPL for community tier** | AGPL deters enterprise adoption and government buyers. The forensic market includes federal agencies (FBI, Secret Service) with strict license policies that exclude copyleft. |

### Consequences

**Positive:**
- Clear, auditable license boundary that satisfies legal review for both community and enterprise buyers
- Community contributors know exactly what license applies to their work
- Court-defensible: all community code is fully open for Daubert scrutiny
- Enterprise value remains protectable as trade secrets

**Trade-offs:**
- Two CI pipelines to maintain (separate build/test/release for each repo)
- Cross-repo dependency management adds friction to development workflow
- Enterprise developers must clone both repos and configure path dependencies locally
- Version synchronization between repos requires disciplined release cadence

---

## ADR-0002: Rust 2021 as Primary Language

**Date:** 2026-03-10
**Status:** Accepted
**Axioms:** [Axiom 1] Forensic Integrity > Feature Velocity, [Axiom 3] 35-Second Answers > Comprehensive Coverage

### Context

Security Ronin Katana must parse 1GB E01 forensic images and produce triage answers within a 35-second P95 latency budget at a rate exceeding 100K events/second. The tool processes binary forensic formats (EWF, NTFS, MFT, USN Journal) where off-by-one errors or memory corruption produce incorrect forensic output -- a failure mode that can invalidate court evidence. The DFIR tool ecosystem is split between Go (Velociraptor), Python (Timesketch, plaso), and C++ (Sleuthkit, EnCase internals).

### Decision

Use Rust 2021 edition for all components across both community and enterprise tiers. Key crates: `clap` for CLI, `rayon` for parallelism, `memmap2` for memory-mapped I/O, `zerocopy` for zero-copy parsing, `serde` for serialization.

### Alternatives Rejected

| Alternative | Reason Rejected |
|-------------|-----------------|
| **Go** | Velociraptor uses Go successfully, but Go's garbage collector introduces non-deterministic pauses that threaten the 35-second budget on large images. Go's lack of zero-cost abstractions means parsing binary formats requires more unsafe-equivalent code (`unsafe.Pointer`) with fewer compiler guardrails. |
| **Python** | Timesketch and plaso demonstrate Python's viability for forensics, but Python is 10-100x slower for binary parsing workloads. A 1GB image would take minutes, not seconds. Python's GIL prevents true parallelism for CPU-bound parsing. |
| **C++** | Traditional forensics choice (Sleuthkit). Equivalent raw performance to Rust, but no memory safety guarantees. Buffer overflows in forensic parsers are a documented attack vector. C++ lacks a modern package manager comparable to Cargo, increasing supply chain risk. |
| **Zig** | Promising for systems work, but ecosystem immaturity means critical libraries (EWF parsing, NTFS structures) would need to be written from scratch. Hiring pool is effectively zero in 2026. |

### Consequences

**Positive:**
- Memory safety without garbage collection -- deterministic performance for latency budget
- `rayon` provides data parallelism for USN Journal, MFT, and triage engine stages with zero unsafe code
- `zerocopy` and `memmap2` enable zero-copy parsing of binary forensic formats, critical for 100K+ events/second
- Cargo workspace maps cleanly to the two-repo open core model (ADR-0001)
- Type system catches forensic parsing errors at compile time rather than at trial

**Trade-offs:**
- Steeper learning curve limits contributor pool compared to Python or Go
- Compile times are significant (5-10 minutes for full workspace rebuild)
- Async Rust complexity for enterprise services (Axum, tonic) adds cognitive overhead
- Fewer forensic-specific libraries compared to Python ecosystem (must build more in-house)

---

## ADR-0003: Trait-Based Extension Architecture

**Date:** 2026-03-10
**Status:** Accepted
**Axioms:** [Axiom 2] Practitioner Autonomy > Platform Lock-in, [Axiom 4] Open Core Trust > Revenue Extraction

### Context

The enterprise tier (`katana-pro`) must extend community functionality without modifying `katana-core`. Enterprise features include new evidence sources (PCAP, NetFlow, Velociraptor imports), enhanced triage engines (multi-device correlation), and additional output sinks (PostgreSQL, collaborative dashboards). The extension mechanism must enforce the open-core boundary: community traits live in Apache-2.0 code, enterprise implementations live in proprietary code.

### Decision

Define three core traits in `katana-core` (Apache-2.0):

```rust
pub trait EvidenceSource: Send + Sync {
    fn name(&self) -> &str;
    fn parse(&self, input: &[u8]) -> Result<Vec<Event>, ParseError>;
}

pub trait TriageEngine: Send + Sync {
    fn evaluate(&self, events: &[Event]) -> Result<TriageResult, TriageError>;
}

pub trait OutputSink: Send + Sync {
    fn emit(&self, result: &TriageResult) -> Result<(), OutputError>;
}
```

Enterprise crates implement these traits for proprietary functionality. The community CLI uses concrete types directly; the enterprise server uses `dyn Trait` dispatch to load both community and enterprise implementations.

### Alternatives Rejected

| Alternative | Reason Rejected |
|-------------|-----------------|
| **Plugin system (dynamic loading)** | `dlopen`/`libloading` introduces ABI compatibility issues across Rust versions. Plugin crashes can take down the host process. Distribution complexity (shipping `.so`/`.dll` files alongside the binary) conflicts with the single-binary deployment model. On the kill list as an explicit non-goal. |
| **Feature flags** | `#[cfg(feature = "enterprise")]` in community crates leaks enterprise logic into the public repo. Even with conditional compilation, the code is visible in the source tree. Violates ADR-0001's clean repo separation. |
| **Dynamic loading via WASM** | WASM sandboxing adds overhead (10-30% for compute-heavy parsing). WASM modules cannot directly access the filesystem, requiring a host-function bridge that adds complexity without forensic benefit. |

### Consequences

**Positive:**
- Clean compilation boundary: community crate compiles without enterprise code present
- Rust's trait system enforces the interface contract at compile time
- Enterprise developers extend functionality by implementing known traits, not by forking community code
- Future community contributors can add new `EvidenceSource` implementations (e.g., ext4, APFS) without touching enterprise code

**Trade-offs:**
- `dyn Trait` dispatch adds ~2-5ns per call compared to static dispatch (negligible at 100K events/second but measurable in microbenchmarks)
- Trait design must be forward-compatible; changing trait signatures is a breaking change across both repos
- Three traits may not cover all extension points (monitoring, alerting, workflow hooks may need additional traits later)

---

## ADR-0004: Axum + Tonic for Enterprise Layer

**Date:** 2026-03-10
**Status:** Accepted
**Axioms:** [Axiom 5] Assume Breach > Assume Safety

### Context

The enterprise tier requires two network interfaces: a REST API for the web-based investigation dashboard (used by Case Managers and Examiners) and a gRPC interface for collection agents deployed to endpoints (used by the `katana-agent` binary). Both services need TLS termination, authentication middleware, and must share the same Tokio async runtime to avoid thread proliferation on the server.

### Decision

Use Axum 0.8 for the REST API and tonic 0.14+ for gRPC, both running on a shared Tokio runtime within `katana-server`. Authentication and RBAC middleware implemented as Tower layers, shared between both protocol stacks. TLS via `rustls` 0.23+ (no OpenSSL dependency).

### Alternatives Rejected

| Alternative | Reason Rejected |
|-------------|-----------------|
| **Actix-web** | Actix uses its own actor runtime, which conflicts with tonic's requirement for Tokio. Running two runtimes wastes threads and complicates graceful shutdown. Actix's actor model adds abstraction without benefit for request/response APIs. |
| **Warp** | Warp's filter-based composition is elegant but produces opaque type errors that slow development. Warp has lower community momentum than Axum and fewer Tower middleware integrations. |
| **Raw hyper** | Hyper is the HTTP layer under both Axum and tonic. Using it directly provides no abstraction for routing, middleware, or request extraction -- all boilerplate that Axum handles. No benefit to dropping down a layer. |
| **Separate processes for REST and gRPC** | Running `katana-rest` and `katana-grpc` as separate binaries doubles deployment complexity, requires inter-process communication for shared state (case data, session management), and doubles the attack surface for network listeners. |

### Consequences

**Positive:**
- Shared Tokio runtime means one thread pool handles both REST and gRPC, efficient resource usage
- Tower middleware (RBAC, rate limiting, tenant isolation) applies uniformly across both protocols
- `rustls` eliminates OpenSSL as a dependency, reducing supply chain attack surface and simplifying cross-compilation
- Axum's extractor pattern maps cleanly to forensic domain types (CaseId, ExaminerId, TenantId)

**Trade-offs:**
- Axum 0.8 is relatively new; some Tower middleware ecosystem crates may lag behind
- Single-process model means a crash in either REST or gRPC handler affects both services
- `rustls` does not support all TLS features (e.g., no post-handshake authentication), though this is not required for our use case

---

## ADR-0005: Assume-Breach Collection Agent Security

**Date:** 2026-03-10
**Status:** Accepted
**Axioms:** [Axiom 5] Assume Breach > Assume Safety, [Axiom 1] Forensic Integrity > Feature Velocity

### Context

Velociraptor, the most widely deployed open-source DFIR collection agent, was weaponized by Storm-2603 as a command-and-control channel (CVE-2025-6264). The attack exploited Velociraptor's broad capability set -- file upload, process execution, arbitrary VQL queries -- to pivot from a compromised endpoint to full network access via the Velociraptor server. Security Ronin Katana's collection agent (`katana-agent`) must avoid this failure mode. The agent deploys to potentially compromised endpoints where adversaries have root/SYSTEM access and can reverse-engineer the binary.

### Decision

Implement defense-in-depth security for `katana-agent`:

1. **mTLS with certificate pinning**: Agent authenticates to server via mutual TLS. Server certificate fingerprint is compiled into the agent binary. Compromised CA cannot issue rogue server certificates.
2. **Code signing**: Agent binaries are signed. The server validates the signature before accepting agent connections. Prevents modified agents from exfiltrating data.
3. **Unidirectional trust**: Agent initiates all connections. Server cannot push commands to the agent. Agent only performs pre-defined collection tasks (USN Journal, MFT, Event Logs) -- no arbitrary code execution.
4. **Resource throttling**: Agent consumes <5% CPU and <100MB RAM. Binary size <5MB. Cold start <50ms. Cannot be repurposed as a resource-intensive attack tool.
5. **Integrity hashing**: Evidence is hashed (SHA-256) on the endpoint before transmission. Server verifies hash on receipt. Tampering during transit is detected.

### Alternatives Rejected

| Alternative | Reason Rejected |
|-------------|-----------------|
| **API key authentication** | Static API keys in the agent binary are trivially extractable via `strings` or a debugger. No mutual authentication -- the agent cannot verify the server's identity. Replay attacks are possible if the key is intercepted. |
| **OAuth 2.0 / OIDC** | OAuth requires an identity provider accessible from the endpoint. Collection agents operate on networks where internet access may be restricted or monitored by the adversary. OAuth tokens have expiry/refresh complexity that adds failure modes during time-sensitive collection. |
| **VPN-only (no agent auth)** | Assumes the VPN perimeter is trustworthy. If the endpoint is compromised, the adversary is inside the VPN. VPN provides network-level access control, not application-level authentication. Does not address the core threat (compromised endpoint abusing agent capabilities). |
| **Velociraptor-style broad agent** | Velociraptor's power (arbitrary VQL, file upload, process execution) is exactly what made it weaponizable. A forensic collection agent must do less, not more. Capability reduction is the primary defense. |

### Consequences

**Positive:**
- Compromised agent cannot be repurposed as C2: no arbitrary execution, no file upload, unidirectional communication
- mTLS + pinning prevents man-in-the-middle even if the adversary controls DNS and CA infrastructure
- Evidence integrity is verifiable end-to-end (endpoint hash matches server hash)
- Resource throttling prevents the agent from being used as a denial-of-service tool

**Trade-offs:**
- Certificate pinning requires agent binary rebuild when server certificates rotate (mitigated by long-lived certs with planned rotation schedule)
- Unidirectional trust means the server cannot recall or update agents remotely -- updates require endpoint access
- Narrow capability set means separate tools are needed for memory acquisition, registry hives, or other non-filesystem artifacts
- Code signing infrastructure (key management, signing service) adds operational complexity

---

## ADR-0006: Hash-Chain Audit Trail

**Date:** 2026-03-10
**Status:** Accepted
**Axioms:** [Axiom 1] Forensic Integrity > Feature Velocity

### Context

Forensic investigations produce evidence that may be presented in court. The Daubert standard requires that forensic methods be testable, peer-reviewed, and have known error rates. Beyond the tool's analytical output, the investigative process itself must be auditable: who accessed what evidence, when, and what actions were taken. A standard database audit table (INSERT with timestamp) can be silently modified by anyone with database access, destroying the tamper-evidence property.

### Decision

Implement an append-only audit log where each entry contains the SHA-256 hash of the previous entry, forming a hash chain:

```
Entry N: { action, user, timestamp, data, prev_hash: SHA-256(Entry N-1) }
```

- Storage is append-only: no UPDATE or DELETE operations permitted at the application or database level
- Daily automated integrity verification checks the chain from genesis to HEAD
- Legal export produces a PDF with hash-chain verification attestation for court submission
- Tampering with any entry breaks the chain, making modification detectable

### Alternatives Rejected

| Alternative | Reason Rejected |
|-------------|-----------------|
| **Standard database audit table** | INSERT-only by convention, but the database engine permits UPDATE and DELETE. A compromised admin or SQL injection can silently modify history. No cryptographic tamper evidence. |
| **File-based logs (syslog, JSON lines)** | Files can be edited, truncated, or replaced. No integrity verification mechanism unless combined with external signing (which replicates the hash-chain approach with more complexity). |
| **Blockchain / distributed ledger** | Massive engineering overhead for a problem that does not require decentralized consensus. Single-organization audit trails do not benefit from Byzantine fault tolerance. Adds latency, storage bloat, and operational complexity disproportionate to the threat model. |
| **Write-once storage (WORM)** | Hardware WORM (NetApp SnapLock, AWS S3 Object Lock) provides tamper resistance but ties the solution to specific infrastructure. Community tier runs fully offline on local hardware. Enterprise tier should not mandate specific cloud providers. |

### Consequences

**Positive:**
- Cryptographic tamper evidence: any modification to any historical entry is detectable by verifying the hash chain
- Satisfies Daubert requirements for auditable, verifiable forensic process
- Works identically in community (local SQLite) and enterprise (PostgreSQL) tiers
- Legal export with attestation provides court-ready documentation

**Trade-offs:**
- Append-only storage grows monotonically; requires archival/rotation strategy for long-running enterprise deployments
- Hash-chain verification is O(n) for the full chain; daily verification is sufficient but real-time verification of the full chain is impractical for large deployments
- Correcting a genuinely erroneous audit entry requires appending a correction entry (not modifying the original), which complicates audit review
- Single-node hash chain does not protect against an attacker who controls the application and rebuilds the entire chain from scratch (mitigated by periodic external attestation snapshots)

---

## ADR-0007: Buyer-Based Open Core Tier Split

**Date:** 2026-03-10
**Status:** Accepted
**Axioms:** [Axiom 4] Open Core Trust > Revenue Extraction, [Axiom 2] Practitioner Autonomy > Platform Lock-in

### Context

Open-core products must define a boundary between free and paid tiers. The boundary determines community trust, enterprise willingness to pay, and long-term product strategy. Common failure modes include: moving previously-free features to paid (destroys trust), giving away too much (no revenue), or drawing the line at technical boundaries that do not map to buyer willingness to pay. Security Ronin Katana serves two distinct buyer profiles with different budgets, workflows, and purchase authority.

### Decision

Split tiers based on buyer profile, not technical capability:

**Community (Apache-2.0) -- Individual Practitioner:**
- USN Journal parsing with ghost recovery and unallocated carving
- MFT parsing with CyberCX Rewind path reconstruction
- QuadLink 4-artifact correlation
- 12 automated IR triage questions
- Single-device E01/raw image examination
- 7 output formats (SQLite, JSONL, CSV, XML, TLN, HTML, body)

**Enterprise (Proprietary) -- Team/Management:**
- Phase 1: RBAC, multi-device examination, Velociraptor/Binalyze import, live triage
- Phase 2: PCAP/NetFlow analysis, collaborative investigation
- Phase 3: Targeted collection agent

The guiding principle: if a solo consultant doing 3-5 cases/month needs it, it is free. If it requires team coordination, multi-device scale, or management oversight, it is enterprise.

### Alternatives Rejected

| Alternative | Reason Rejected |
|-------------|-----------------|
| **Feature-based split (e.g., ghost recovery = enterprise)** | Core forensic capabilities in the paid tier undermines court defensibility. An expert witness cannot testify about tool accuracy if the defense attorney can argue the full tool was not available for independent verification. |
| **Usage limits (e.g., 10 images/month free)** | Arbitrary limits frustrate users without corresponding to genuine cost differences. A solo consultant with 15 cases in a busy month should not hit a paywall. Usage-based pricing works for SaaS, not for offline CLI tools. |
| **Time-limited trial (30 days full, then community)** | Creates urgency that erodes trust. Forensic practitioners evaluate tools over months, not days. A 30-day trial does not align with the forensic case lifecycle (cases can span 6-12 months). |
| **Dual license (GPL + commercial)** | GPL deters enterprise adoption. The community tier must be permissively licensed (Apache-2.0) to maximize adoption in corporate and government environments where GPL is prohibited by policy. |

### Consequences

**Positive:**
- Community features never move to enterprise -- trust is preserved and codified as Axiom 4
- Clear buyer-profile mapping makes sales conversations straightforward: "Do you work alone or on a team?"
- Solo practitioners get a complete, court-defensible tool at no cost, driving adoption and word-of-mouth
- Enterprise features (RBAC, multi-device, collaboration) have natural team-size pricing anchors

**Trade-offs:**
- Some features are ambiguous (e.g., Velociraptor import could serve solo users). Requires ongoing judgment calls.
- Generous community tier means enterprise conversion rate may be lower than feature-gated models
- Community tier must remain genuinely useful (not a crippled demo) to sustain adoption, requiring continued investment in free features
- Competitors could fork the Apache-2.0 community tier and build their own enterprise layer (mitigated by execution speed and brand trust)

---

## ADR-0008: NetFlow-First Network Forensics

**Date:** 2026-03-10
**Status:** Accepted
**Axioms:** [Axiom 3] 35-Second Answers > Comprehensive Coverage

### Context

Enterprise Phase 2 introduces network forensics. Two primary data sources exist: PCAP (full packet capture) and NetFlow (connection metadata). PCAP captures complete packet payloads but generates approximately 1000x more data than NetFlow for the same time window. With TLS 1.3 adoption exceeding 90% of web traffic in 2026, deep packet inspection (DPI) of encrypted payloads yields diminishing returns. The forensic question is typically "what communicated with what, when, and how much?" -- answerable from NetFlow metadata -- rather than "what was the payload content?" -- which requires PCAP of unencrypted traffic.

### Decision

Implement network forensics in this order:

1. **NetFlow parsing first** (`netflow_parser` 0.4+ crate): Parse NetFlow v5/v9/IPFIX records. Integrate with QuadLink correlator for timeline enrichment. Answer connection-level questions (source, destination, duration, bytes transferred).
2. **PCAP second** (`pcap-parser` + `etherparse` crates): Parse PCAP/PCAPng files. Focus on DNS queries, TLS handshake metadata (SNI, JA3/JA4 fingerprints), and unencrypted protocols.
3. **Alert-driven capture**: Rather than storing full PCAP, trigger targeted packet capture based on triage alerts (suspicious IP contacted, unusual port, anomalous data volume).

### Alternatives Rejected

| Alternative | Reason Rejected |
|-------------|-----------------|
| **PCAP-first** | 1GB of PCAP covers minutes of network activity; 1GB of NetFlow covers weeks. Starting with PCAP means most enterprise deployments would lack sufficient storage for meaningful coverage. PCAP-first also implies building DPI capabilities that TLS 1.3 renders largely moot. |
| **Full NDR platform** | Building a full Network Detection and Response platform (Zeek/Suricata competitor) is a multi-year engineering effort that diverges from Katana's core competency in filesystem forensics. Explicitly on the kill list. Integrate with existing NDR tools, do not compete. |
| **Skip network forensics entirely** | Network context is essential for incident response triage. "Was data exfiltrated?" and "What external IPs were contacted?" are standard IR questions that cannot be answered from filesystem artifacts alone. Omitting network forensics limits enterprise value. |

### Consequences

**Positive:**
- NetFlow-first delivers 90% of network forensic answers at 0.1% of the storage cost of PCAP
- TLS 1.3 makes this decision future-proof: encrypted payload inspection becomes less valuable over time, not more
- Alert-driven PCAP capture preserves the forensic option without the storage burden of continuous full capture
- Integration with Wireshark (via PCAP export) leverages existing practitioner skills rather than forcing tool migration

**Trade-offs:**
- NetFlow metadata cannot reconstruct payload content (e.g., exfiltrated file contents)
- Alert-driven capture misses events that were not flagged as suspicious at the time of occurrence
- Two parsing pipelines (NetFlow + PCAP) in `katana-pcap` increases crate complexity
- NetFlow availability depends on network infrastructure (routers/switches must be configured to export NetFlow records)

---

## ADR-0009: SQLite (Community) / PostgreSQL + Tantivy (Enterprise)

**Date:** 2026-03-10
**Status:** Accepted
**Axioms:** [Axiom 2] Practitioner Autonomy > Platform Lock-in, [Axiom 3] 35-Second Answers > Comprehensive Coverage

### Context

The community tier operates fully offline on a single machine. The enterprise tier handles multi-device investigations with 15-30 concurrent cases, team collaboration, and full-text search across millions of forensic events. A single database engine cannot optimally serve both use cases. The community tier prioritizes zero-configuration deployment (no database server to install). The enterprise tier prioritizes concurrent access, full-text search, and multi-tenant isolation.

### Decision

- **Community tier**: SQLite via `rusqlite`. Single-file database co-located with output artifacts. No server process. Included as one of seven output formats.
- **Enterprise tier**: PostgreSQL via `sqlx` for structured forensic data with schema-per-tenant multi-tenancy. Tantivy 0.22+ for full-text search and analytical queries across forensic events (Rust-native alternative to OpenSearch/Elasticsearch).
- **Multi-tenancy**: Tenant ID enforced in Tower middleware. Each tenant gets a separate PostgreSQL schema. Tantivy indexes are partitioned per tenant.

### Alternatives Rejected

| Alternative | Reason Rejected |
|-------------|-----------------|
| **DuckDB for both tiers** | DuckDB excels at analytical queries but has limited concurrent write support (single-writer model). Enterprise collaborative investigations require multiple examiners writing findings simultaneously. DuckDB's Rust bindings (`duckdb-rs`) are less mature than `rusqlite` and `sqlx`. Retained as an option for future analytical query offloading but not as the primary data store. |
| **Single database for both tiers** | SQLite cannot handle enterprise concurrency. PostgreSQL cannot run without a server process, violating the community tier's offline, zero-dependency requirement. No single engine satisfies both constraints. |
| **Flat files only (JSONL/CSV)** | Flat files lack indexing, making triage queries over 100K+ events prohibitively slow. The community tier already supports JSONL and CSV as export formats, but SQLite provides the queryable interface needed for the triage engine's 12 IR questions. |
| **OpenSearch/Elasticsearch** | JVM-based, heavy operational footprint. Requires dedicated cluster management. Tantivy provides equivalent full-text search capability as a Rust library embedded in the application, eliminating a major infrastructure dependency. |

### Consequences

**Positive:**
- Community tier requires zero infrastructure: `katana` produces a SQLite file as naturally as it produces CSV
- PostgreSQL's schema-per-tenant model provides strong multi-tenant isolation without application-level workarounds
- Tantivy runs in-process, eliminating the operational overhead of a separate search cluster
- Both storage engines are well-supported in the Rust ecosystem with mature, actively maintained crates

**Trade-offs:**
- Two database engines means two sets of schema migrations, query patterns, and operational procedures
- Tantivy indexes must be managed (compaction, rebuilds) alongside PostgreSQL data -- two storage systems to monitor
- Schema-per-tenant in PostgreSQL creates many schemas in large MSSP deployments (100+ tenants); requires connection pooling discipline
- SQLite-to-PostgreSQL migration path for users upgrading from community to enterprise must be explicitly built and maintained

---

## ADR-0010: Buy SSO, Delay SOC 2

**Date:** 2026-03-10
**Status:** Accepted
**Axioms:** [Axiom 4] Open Core Trust > Revenue Extraction

### Context

Enterprise DFIR buyers have two non-negotiable procurement requirements: Single Sign-On (SSO/SAML) integration and SOC 2 Type II compliance certification. Industry data indicates 83% of enterprise buyers require SOC 2, and SSO is a universal deal-blocker for organizations with >50 employees. However, SOC 2 Type II certification requires 6-12 months of audited operations, costs $50-150K, and requires an established operational history. SSO integration, by contrast, can be achieved in days using third-party providers. Security Ronin Katana is pre-revenue with no paying enterprise customers.

### Decision

1. **Buy SSO immediately**: Integrate WorkOS or Scalekit for SSO/SAML authentication in the enterprise tier. JWT-based session management after SSO authentication. Local fallback authentication via Argon2id password hashing + TOTP 2FA for environments without SSO infrastructure.
2. **Delay SOC 2 until paying customers exist**: Begin SOC 2 Type II audit process only after securing initial enterprise customers who can validate operational requirements. Use the hash-chain audit trail (ADR-0006) and open-source community code as interim trust signals.

### Alternatives Rejected

| Alternative | Reason Rejected |
|-------------|-----------------|
| **Build SSO in-house** | SAML/OIDC implementation is a known minefield of XML parsing vulnerabilities, token validation edge cases, and IdP-specific quirks (Okta vs Azure AD vs Google Workspace). Building in-house diverts 2-4 engineering months from forensic features. "Buy Auth, Build Forensics" is a security principle. |
| **Pursue SOC 2 immediately** | SOC 2 Type II requires 6-12 months of audited operational history that does not yet exist. Starting the audit before having customers means auditing hypothetical procedures. The $50-150K cost is disproportionate to pre-revenue stage. |
| **Skip SSO, offer API keys only** | API keys do not satisfy enterprise security teams. Organizations with SSO mandates will not make exceptions for a forensic tool. SSO is a checkbox requirement, not a feature preference. |
| **Self-hosted identity (Keycloak)** | Keycloak adds a JVM dependency and significant operational overhead. Enterprise customers already have IdPs (Okta, Azure AD); adding another identity system creates friction rather than reducing it. |

### Consequences

**Positive:**
- SSO integration removes the primary enterprise procurement blocker with minimal engineering effort (days, not months)
- WorkOS/Scalekit handle IdP-specific quirks (Okta, Azure AD, Google) without in-house SAML expertise
- Delaying SOC 2 preserves engineering focus on forensic features that differentiate the product
- Hash-chain audit trail (ADR-0006) provides interim evidence of security posture for prospects who ask about compliance

**Trade-offs:**
- SOC 2 absence will disqualify Katana from some enterprise procurement processes (estimated 30% of pipeline)
- WorkOS/Scalekit introduces a third-party dependency in the authentication path (mitigated by local fallback)
- Monthly SaaS cost for SSO provider scales with enterprise seat count
- Delayed SOC 2 means the 6-12 month clock does not start until the decision is made, pushing certification to 12-18 months after first enterprise customer

---

## Cross-Reference to Strategic Axioms

| Axiom | ADRs Referencing |
|-------|-----------------|
| **Axiom 1**: Forensic Integrity > Feature Velocity | ADR-0002, ADR-0005, ADR-0006 |
| **Axiom 2**: Practitioner Autonomy > Platform Lock-in | ADR-0003, ADR-0007, ADR-0009 |
| **Axiom 3**: 35-Second Answers > Comprehensive Coverage | ADR-0002, ADR-0008, ADR-0009 |
| **Axiom 4**: Open Core Trust > Revenue Extraction | ADR-0001, ADR-0007, ADR-0010 |
| **Axiom 5**: Assume Breach > Assume Safety | ADR-0004, ADR-0005 |
