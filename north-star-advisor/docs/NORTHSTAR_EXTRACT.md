# Security Ronin Katana: North Star Extract

> Your project's design DNA -- the decisions that should NOT be re-litigated.
> **Generation Step**: 4 of 13 -- Derived from `brand.beliefs[]`, `northstar.metric`, `northstar.kill_list[]`, `competitive.rejected_moves[]`

**Project:** Security Ronin Katana
**Created:** 2026-03-10
**Last Updated:** 2026-03-10

---

## How to Use This Document

This document captures the foundational decisions for Security Ronin Katana. It exists to prevent re-litigation of settled questions and to give every contributor (human or AI) a shared decision framework.

**When making any product, architecture, or prioritization decision:**

1. Check if the decision conflicts with a **Core Axiom**. If it does, the axiom wins unless a **Re-evaluation Trigger** has fired.
2. Check if the proposed work appears in **Explicit Non-Goals**. If it does, reject it without discussion unless new evidence warrants re-evaluation.
3. Check if an existing **Structural Pattern** applies. If it does, follow the pattern rather than inventing a new approach.
4. Verify the implementation follows **What We Always Do** and avoids **What We Never Do**.

**This document is not a backlog.** It does not tell you what to build next. It tells you what constraints apply to everything you build.

---

## Core Axioms

These are the 5 non-negotiable principles. When two good ideas conflict, these axioms determine which one wins. They are derived from brand beliefs and validated against competitive positioning.

### Axiom 1: Forensic Integrity > Feature Velocity

Every output must be deterministic, verifiable, and court-admissible. When speed of shipping and accuracy of results conflict, choose accuracy. A forensic tool that produces non-reproducible output is not a forensic tool -- it is a liability.

**When this applies:** A new feature would introduce non-deterministic behavior (e.g., AI classification, probabilistic scoring, floating-point timestamp rounding). The feature does not ship until determinism is guaranteed.

**Derived from:** Brand Belief 1 (forensic integrity is non-negotiable), Brand Belief 5 (auditable code is court-defensible code)

### Axiom 2: Practitioner Autonomy > Platform Lock-in

The community CLI must work fully offline, without accounts, without internet, without telemetry. Never require the enterprise tier to perform forensic analysis. Practitioners on air-gapped networks, classified environments, and hostile incident scenes must have full analytical capability from a single binary.

**When this applies:** A proposed feature requires network connectivity, user accounts, or cloud services. If it cannot function offline, it belongs in enterprise tier workflow tooling -- never in the forensic analysis path.

**Derived from:** Brand Belief 4 (practitioners deserve tools, not platforms), Competitive whitespace (government/defense IR teams on classified networks)

### Axiom 3: 35-Second Answers > Comprehensive Coverage

Triage is about speed to useful answers, not exhaustive analysis. We answer 12 IR questions well in 35 seconds, not 100 questions poorly in 10 minutes. The first 60 minutes of incident response determine containment success -- every minute saved in triage is a minute gained for containment.

**When this applies:** A feature request would expand artifact coverage at the cost of triage speed. If adding a new artifact type pushes P95 triage time beyond 35 seconds on the benchmark corpus, it becomes opt-in or deferred.

**Derived from:** Brand Belief 2 (speed-to-answers is a forensic imperative), North Star supporting metric (time-to-first-answer P95 < 35 seconds)

### Axiom 4: Open Core Trust > Revenue Extraction

Community features never move to the enterprise tier. The Apache-2.0 commitment is permanent. Trust is the moat -- not licensing leverage. Enterprise monetizes workflow (RBAC, multi-device, integrations, audit trails), never forensic accuracy or evidence recovery.

**When this applies:** Revenue pressure suggests gating a community feature behind enterprise licensing. The answer is always no. Enterprise value comes from team workflow features that solo practitioners do not need.

**Derived from:** Brand Belief 4 (open source earns trust, trust earns adoption), Competitive positioning (court-defensible open-source forensics whitespace)

### Axiom 5: Assume Breach > Assume Safety

The collection agent operates in hostile environments. Design every component assuming the endpoint is already compromised. mTLS, certificate pinning, code signing, and least-privilege execution are not optional hardening -- they are baseline requirements.

**When this applies:** An architecture decision trades security for convenience (e.g., shared secrets, unsigned binaries, HTTP fallback). The secure option wins. Agent compromise must never mean server compromise.

**Derived from:** Brand Belief 3 (deleted evidence is still evidence -- recovery is baseline), Enterprise security requirements (collection in adversary-controlled environments)

---

## Explicit Non-Goals

These paths are explicitly rejected. This prevents scope creep and stops reopening closed doors.

### Features We Will Never Build

| Feature | Why We Reject It | Axiom Conflict |
|---------|-------------------|----------------|
| GUI-first application | The HTML report is the visual interface. A GUI adds maintenance burden without serving CLI-native practitioners. Contradicts tool-not-platform philosophy. | Axiom 2 (Practitioner Autonomy) |
| Plugin/extension system | Plugins introduce non-deterministic behavior from third-party code. Every output must be reproducible from the same binary and input. | Axiom 1 (Forensic Integrity) |
| Cloud-based processing | Forensic evidence cannot leave the examiner's custody. Cloud processing breaks chain of custody and fails on air-gapped networks. | Axiom 2 (Practitioner Autonomy), Axiom 5 (Assume Breach) |
| AI/ML-based triage classification | Non-deterministic, non-reproducible, non-court-defensible. Opposing counsel will challenge any AI-generated conclusion. Own deterministic accuracy as the ground truth AI must beat. | Axiom 1 (Forensic Integrity), Axiom 3 (35-Second Answers) |
| Database-first architecture | SQLite is an output format, not an input requirement. The tool must work with a single binary and a disk image -- no database setup, no migrations, no server. | Axiom 2 (Practitioner Autonomy) |
| Memory forensics | Different domain entirely. Violates depth-over-breadth. Established tools (Volatility, Rekall) have a decade head start. Focus on NTFS artifact mastery. | Axiom 3 (35-Second Answers) |
| Real-time monitoring | Katana is a triage tool, not an EDR. Real-time monitoring is a fundamentally different architecture that would compromise triage speed. | Axiom 3 (35-Second Answers) |
| Case management system | Case management is enterprise workflow, but building a full CMS splits focus. Integrate with existing case management tools via structured output formats. | Axiom 3 (35-Second Answers) |
| Collection agent | Collection is a solved problem (KAPE, Velociraptor, Binalyze AIR). Building one splits focus, introduces security liability (see CVE-2025-6264), and competes with integration partners. | Axiom 4 (Open Core Trust) |
| Mobile forensics | Different domain, different filesystem, different evidence types. Established competitors have a decade head start. Depth over breadth. | Axiom 3 (35-Second Answers) |
| SaaS/cloud-hosted platform | Contradicts offline-first, evidence-custody, and air-gap requirements. Also creates vendor lock-in that violates practitioner autonomy. | Axiom 2 (Practitioner Autonomy), Axiom 5 (Assume Breach) |
| Full NDR platform | Network detection and response is a different product category. Katana analyzes host artifacts, not network traffic. | Axiom 3 (35-Second Answers) |
| Replacing Velociraptor entirely | Velociraptor is a collection and hunting platform. Katana is a triage analysis engine. They are complementary, not competitive. Integration > replacement. | Axiom 4 (Open Core Trust) |

### Technical Approaches We Rejected

| Approach | Why Rejected | What We Do Instead |
|----------|--------------|---------------------|
| AI-powered triage summaries | Non-deterministic, non-reproducible, non-court-defensible. Contradicts forensic integrity axiom. | Deterministic rule-based triage with 12 structured IR questions and measurable precision/recall. |
| GUI desktop application | HTML report serves as the visual interface. GUI adds maintenance surface without serving CLI-native practitioners. | CLI-first with `--report` generating interactive HTML. Single command, single output. |
| VC funding | Growth expectations distort product decisions. Pressure to monetize aggressively undermines open-core trust model. | Bootstrapped open-core. Enterprise revenue funds development. Community trust drives adoption. |
| Probabilistic scoring | Scores without deterministic thresholds are not court-defensible and create false confidence. | Binary triage flags with explicit thresholds, documented precision/recall, and reproducible benchmarks. |
| Multi-language codebase | Polyglot architectures increase build complexity, reduce contributor pool, and complicate determinism verification. | Pure Rust. Single toolchain. Single binary. Zero runtime dependencies. |

**Why this matters:** Every "no" in this list is a "yes" to focus. Features on this list don't get discussed again without new evidence and a fired re-evaluation trigger.

---

## Structural Patterns

These patterns repeat across the architecture. They are reusable motifs that inform every design decision.

### Parse > Correlate > Triage > Report Pipeline

```
Raw Image -> Parse (USN + MFT + LogFile + Unallocated) -> Correlate (QuadLink) -> Triage (12 IR Questions) -> Report (7 formats)
```

**When to use:** Every new artifact type or analysis capability must fit into this pipeline. If it cannot be expressed as a parse step feeding correlation feeding triage, it does not belong in the core path.

**Why it exists:** Linear pipelines are deterministic, testable, and debuggable. Each stage has well-defined inputs and outputs. Failures are isolated to a stage, not spread across the system.

### Community Crate > Enterprise Crate (Trait Extension)

```
katana (Apache-2.0)          katana-pro (Proprietary)
+-- core parsing             +-- RBAC + multi-user
+-- ghost recovery           +-- multi-device correlation
+-- triage questions         +-- Velociraptor integration
+-- all output formats       +-- audit trail + compliance
+-- trait definitions        +-- trait implementations (extends core)
```

**When to use:** Every new feature must be classified as community or enterprise at design time. Community features define traits. Enterprise features implement additional trait variants. Enterprise never gates community functionality.

**Why it exists:** The open-core trust model requires a clear, permanent boundary. Trait extension ensures community crate compiles and runs independently. Enterprise is additive, never subtractive.

### Buyer-Based Open Core Boundary

```
Individual practitioner needs -> Community (free, Apache-2.0)
Team/org management needs    -> Enterprise (paid, proprietary)
```

**When to use:** When deciding tier placement for any feature. Ask: "Does a solo consultant working one case need this?" If yes, it is community. "Does a team lead managing 6 analysts across 30 cases need this?" If yes, it is enterprise.

**Why it exists:** Prevents the common open-core failure mode of gating power-user features. The solo consultant gets the full forensic engine. The team lead pays for workflow orchestration.

### Fallback Chain

When things fail, degrade gracefully:

```
Full 4-artifact correlation -> Available artifacts only -> Single-artifact parse -> Raw hex fallback -> Error with evidence hash
```

- Partial results with provenance tags are better than failure
- Missing artifacts reduce correlation depth but never block triage
- Every output includes a completeness indicator showing which artifacts contributed

**When to use:** Any error handling or edge case in the pipeline. Never fail silently. Never produce empty output when partial output is possible. Always report what was available and what was missing.

**Why it exists:** Real-world forensic images are messy. Damaged disks, partial acquisitions, and anti-forensic wiping mean the tool must handle degraded input gracefully.

### Conflict Resolution Hierarchy

When design decisions conflict:

```
Forensic Integrity > Practitioner Autonomy > 35-Second Answers > Open Core Trust > Assume Breach
```

Axiom 1 always wins. If two axioms conflict, the higher-numbered axiom yields. This hierarchy is itself non-negotiable.

---

## What We Always Do

Behaviors that must remain consistent across every commit, release, and design decision.

| Behavior | Example |
|----------|---------|
| Deterministic output for identical input | Same E01 image + same flags = byte-identical output. Verified by SHA-256 hash in CI on every PR. |
| Version output format with hash | Every output file includes `format_version` and `content_hash` fields. Format changes require version bump. |
| SPDX license headers on every file | Every `.rs` file begins with `// SPDX-License-Identifier: Apache-2.0`. No exceptions. CI enforces. |
| Court-admissible chain of custody tracking | Output includes image hash, tool version, command invocation, timestamps, and completeness indicators. |
| CLI-first interface design | Every feature is accessible via command-line flags before any other interface. `--help` is always current. |
| Test against reference corpus | The Szechuan Sauce CTF corpus and internal test images run in CI. No release ships without corpus verification. |
| Publish precision/recall metrics | Every triage question has documented precision, recall, and false positive/negative rates. Updated on each release. |
| Zero-UNKNOWN path resolution | MFT path reconstruction must resolve 100% of paths. Any UNKNOWN is a bug, not a limitation. |

## What We Never Do

Behaviors that are explicitly prohibited across every commit, release, and design decision.

| Behavior | Why |
|----------|-----|
| Move community features to enterprise | Destroys the trust moat. Practitioners who adopted based on Apache-2.0 availability will never trust us again. Permanent commitment. |
| Require internet for forensic analysis | Air-gapped networks, classified environments, and hostile incident scenes have no connectivity. The tool must work with a binary and an image, nothing else. |
| Silently modify evidence or input data | Forensic tools must never alter input. Read-only access to disk images. Any transformation is applied to output copies with provenance tracking. |
| Ship without test corpus verification | A release that has not passed the reference corpus is a release that might miss evidence. Unacceptable in forensic tooling. |
| Accept non-deterministic output | If the same input produces different output on two runs, the tool is broken. Non-determinism is a P0 bug, not a feature request. |
| Use `unsafe` without documented justification | Every `unsafe` block requires a comment explaining why it is necessary and what invariants it maintains. Reviewed by two contributors. |
| Ship unsigned binaries for enterprise | Enterprise binaries are code-signed. Unsigned binaries in enterprise collection scenarios are an attacker's gift. |
| Silently drop records during parsing | Every input record must appear in output or be explicitly logged as unparseable with the raw hex and byte offset. No silent data loss. |

---

## When to Re-evaluate

These triggers indicate that foundational assumptions may have changed. When a trigger fires, pause feature work and re-examine the relevant axiom or non-goal.

### Metric Triggers

| Signal | Threshold | What to Do |
|--------|-----------|------------|
| Enterprise customer count stalls | Below 10 customers after 6 months of enterprise launch | Re-examine enterprise feature set, pricing, and go-to-market. Do not move community features to enterprise. |
| Community adoption plateaus | Below 200 GitHub stars after 90 days | Re-examine positioning, developer experience, and conference strategy. Validate that the problem is real. |
| Triage completion rate drops | Below 90% for 3 consecutive releases | Pipeline reliability issue. Halt new features. Fix parsing edge cases. |
| False positive rate climbs | Above 10% for any triage question for 4 weeks | Triage question logic needs refinement. Review precision/recall benchmarks. |
| P95 triage time exceeds 45 seconds | On benchmark corpus for 2 consecutive releases | Performance regression. Profile and fix before adding new artifact types. |
| Ghost recovery rate drops | Below 90% on reference corpus | Core differentiator degradation. Investigate $LogFile parsing changes immediately. |

### External Triggers

| Event | What to Reconsider |
|-------|-------------------|
| CrowdStrike ships native NTFS triage in Falcon | Re-evaluate enterprise positioning for Fortune 500 segment. Community tier unaffected. |
| Microsoft adds forensic triage to Defender for Endpoint | Assess overlap with Katana's 12 IR questions. Double down on ghost recovery and open-source differentiators. |
| Velociraptor adds built-in triage questions | Accelerate Velociraptor integration. Position Katana as the analysis engine behind VQL. |
| Major court rejects open-source tool output | Crisis. Publish methodology paper, seek Daubert expert validation, engage forensic community. |
| NTFS specification changes materially | Rare but possible. Update parsers. Validate against new test images. |
| Regulatory changes to digital evidence handling | Review chain of custody output format. Ensure compliance. Engage legal review. |

### Strategic Triggers

| Trigger | Questions to Ask |
|---------|------------------|
| Revenue exceeds $100K MRR | Do we need dedicated support staff? Does the architecture scale to enterprise SLAs? |
| Community requests a rejected feature with 50+ upvotes | Re-examine with evidence. Default answer is still "no." Require demonstrated harm from absence, not just desire for presence. |
| A competitor open-sources ghost recovery | Differentiator eroded. Accelerate next differentiator (multi-artifact correlation, triage accuracy leadership). |
| Collection agent CVE affects Katana users | Validate assume-breach architecture held. Publish incident response. Reinforce why we do not build collection. |
| Enterprise crate size exceeds 2x community crate | Architecture review. Enterprise may be accumulating responsibilities that belong in separate services. |

---

## Document Governance

| Field | Value |
|-------|-------|
| **Owner** | Product lead (Security Ronin Katana) |
| **Review cadence** | Quarterly, or when a re-evaluation trigger fires |
| **Change process** | Axiom changes require written justification with evidence. Non-goal removals require demonstrated harm from absence. Pattern additions follow existing motifs. |
| **Version** | 1.0.0 |
| **Upstream dependencies** | BRAND_GUIDELINES, NORTHSTAR, COMPETITIVE_LANDSCAPE |
| **Downstream consumers** | ARCHITECTURE_BLUEPRINT, AGENT_PROMPTS, SECURITY_ARCHITECTURE, all implementation decisions |
