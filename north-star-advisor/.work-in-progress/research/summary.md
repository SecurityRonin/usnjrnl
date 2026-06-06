# Research Summary

## Generated
2026-03-09T06:55:00+08:00

## Project Context
- **Name:** Security Ronin Katana
- **Company:** Security Ronin (also: Security Ronin General)
- **Type:** Two-tier DFIR forensic triage tool (community + enterprise)
- **Users:** Solo DFIR consultants (community), MSSP analysts + enterprise IR teams (enterprise)
- **Stack:** Rust CLI, Apache-2.0 (community) + Proprietary (enterprise)

---

## Technology Stack

### Recommended / Validated
| Layer | Recommendation | Rationale |
|-------|---------------|-----------|
| Language | Rust 2021 | Already in use; zero-cost abstractions, static binaries, memory safety |
| Community CLI | clap + katana-core crate | Current stack, proven |
| Enterprise API | Axum | Shares Tokio runtime with tonic (gRPC), Tower middleware |
| Agent Comms | tonic (gRPC) + rustls (mTLS) | 171M+ downloads, bidirectional streaming, mutual TLS built-in |
| PCAP Parsing | pcap-parser + etherparse | Pure Rust, zero-copy, zero-allocation |
| NetFlow Parsing | netflow_parser | 72K+ downloads, V5/V7/V9/IPFIX, zero-alloc |
| Auth | jsonwebtoken v9 + argon2 v0.5 | Standard JWT + password hashing |
| RBAC | Custom Tower middleware | Case-level + evidence-level permissions |
| Collaboration | WebSocket (simple pub/sub) | No CRDT needed at this stage |
| Enterprise DB | PostgreSQL + OpenSearch | Mirrors Timesketch evolution |
| Community DB | SQLite (rusqlite) | Already in use, fits 35s budget |
| Agent Binary | ~4-8MB static, zstd compression | Self-updating via self_update crate |

### Key Cargo Workspace Structure
```
katana/                     # Public repo (Apache-2.0)
  crates/
    katana-core/            # Shared types, traits, parsers
    katana-cli/             # Community CLI
    katana-formats/         # Output formatters
    katana-ewf/             # E01/raw image handling
    katana-ntfs/            # NTFS parsing wrappers

katana-pro/                 # Private repo (Proprietary)
  crates/
    katana-server/          # Axum API + RBAC + WebSocket
    katana-agent/           # Collection agent (tonic gRPC)
    katana-pcap/            # PCAP/NetFlow analysis
    katana-collab/          # Collaborative investigation
    katana-import/          # Velociraptor/Binalyze importers
    katana-multi/           # Multi-device correlation
```

---

## Features & UX

### Tier Split Pattern (Buyer-Based Open Core)
| Tier | Target Buyer | Features |
|------|-------------|----------|
| Community (free) | Individual practitioner | Core analysis, single-device, CLI, 7 formats |
| Enterprise (paid) | Team lead / CISO | RBAC, multi-device, collaboration, collection, audit |

### Enterprise Features Teams Pay For
1. Case management with multi-case dashboards
2. RBAC (examiner / reviewer / admin roles)
3. Immutable audit logging and chain of custody
4. Multi-analyst concurrent analysis
5. SSO/SAML (use WorkOS/Scalekit, don't build)
6. Collection agent with hunt management

### Pricing Recommendation
- Per-investigator/seat: $99-149/month ($1,188-1,788/yr)
- Positioned below AXIOM (~$2,995/yr), above X-Ways (~$850/yr)
- Volume discounts at 5+ and 10+ seats
- Custom MSSP tier with multi-tenant support
- 30-day full enterprise trial

### Collection Agent UX (Velociraptor Model)
- Three modes: online client-server, offline pre-baked, adaptive
- Hunt management with label-based targeting
- VQL-style query language for custom artifacts

### Multi-Device UX
- Unified timeline with source-tagged events
- Cross-Drive Analysis (CDA) for statistical correlation
- Pivot between host and network evidence

---

## Architecture

### Open-Core Cargo Pattern
- Two repos + local Cargo workspace (path deps for dev, git deps for CI)
- Shared EvidenceSource, TriageEngine, OutputSink traits in katana-core
- Enterprise crate implements traits for PCAP, NetFlow, multi-device
- publish = false on all enterprise crates
- SPDX license headers per-file

### Velociraptor Weaknesses (Competitor Opportunities)
1. File-based datastore locked to single machine, no database backend
2. Traditional full-triage doesn't scale past thousands of endpoints
3. Go's GC pauses vs Rust's zero-cost abstractions
4. Single binary weaponized by Storm-2603 for ransomware C2 (CVE-2025-6264)
5. No native collaboration or timeline correlation

### Timesketch Limitations
1. Heavy OpenSearch infrastructure dependency (shard limits at ~1,500)
2. Python/Celery bottlenecks during large ingestions
3. No built-in evidence collection or real-time streaming
4. Significant configuration tuning for scale

### Multi-Device Correlation Architecture
- Batch processing for community (35s budget), streaming for enterprise
- Correlation keys: timestamps (window), users, IPs, file hashes, sessions
- DuckDB for analytical queries + tantivy for full-text search

### RBAC Architecture
- Case-level + evidence-level permissions
- Append-only hash-chain audit log for tamper detection
- Schema-per-tenant multi-tenancy for MSSP customers

---

## Pitfalls to Avoid

### Open-Core Pitfalls
1. Never move features from free to paid -- every case (Elastic, HashiCorp, Redis) triggered community forks within 30 days
2. Skip CLAs -- they create contribution-hostile friction
3. Commit to Apache 2.0 publicly and permanently
4. Use buyer-based framework: individual features = free, management features = enterprise

### Forensic Tool Integrity
1. Deterministic output is non-negotiable -- non-determinism breaks Daubert standard
2. Maintain a public test corpus for reproducibility
3. Build a Daubert packet documenting methodology, error rates, peer review
4. Version output format with hash verification

### Collection Agent Security
1. Velociraptor weaponized as ransomware C2 by Storm-2603 (2025)
2. CVE-2025-6264 allowed privilege escalation
3. Prevention: mTLS + certificate pinning, no static credentials, code signing, resource throttling
4. Assume-breach architecture -- agent compromise must not mean server compromise

### Solo Multi-Product Pitfalls
1. Context switching costs up to 40% productivity (APA)
2. Prevention: sequential parallelism -- one product to maintenance before the other
3. Full-day/week time blocks per product
4. Predefined kill criteria for each product

### PCAP/NetFlow Scope Creep
1. PCAP is 1000x larger than NetFlow on disk
2. TLS 1.3 makes deep packet inspection a dead-end
3. Prevention: NetFlow-first, PCAP-second, alert-driven capture
4. Integrate with Wireshark, don't compete

### Enterprise Sales
1. 83% of enterprise buyers require SOC 2 ($30-50K/year) -- delay until paying customers
2. SAML SSO is a deal-blocker -- buy (WorkOS/Scalekit), don't build
3. Solo founders consistently underprice
4. Validate demand before building features

---

## Generation Guidance

These findings should inform:
- **Phase 1 (BRAND_GUIDELINES):** "Security Ronin Katana" within the Security Ronin product family. Brand voice: precision, reliability, forensic integrity.
- **Phase 3 (COMPETITIVE_LANDSCAPE):** Velociraptor weaknesses (single-machine datastore, GC pauses, no collaboration), Timesketch limitations (heavy infra, no collection), AXIOM/KAPE comparison.
- **Phase 6 (ARCHITECTURE_BLUEPRINT):** Cargo workspace two-repo pattern, trait-based extension architecture, Axum + tonic for enterprise layer, batch vs streaming correlation.
- **Phase 7 (AGENT_PROMPTS):** Not AI agents -- forensic pipeline stages (USN parser, MFT parser, triage engine, etc.)
- **Phase 8 (SECURITY_ARCHITECTURE):** Agent-as-attack-vector threat (Storm-2603), mTLS + cert pinning, hash-chain audit logs, Daubert compliance, assume-breach for collection agent.
- **Phase 12 (ACTION_ROADMAP):** Enterprise Phase 1 (RBAC, multi-device, import, live triage) -> Phase 2 (PCAP/NetFlow, collab) -> Phase 3 (collection agent). NetFlow before PCAP. Buy SSO, delay SOC 2.
