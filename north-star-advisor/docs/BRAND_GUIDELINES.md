# Security Ronin Katana: Brand Guidelines

<!-- GENERATION: This is Step 1 of 13 in the generation order. See GENERATION_MANIFEST.md -->

> **Tier**: 3 — Supporting (see [INDEX.md](INDEX.md))
> **Created**: 2026-03-10
> **Status**: Active
> **Generation Step**: 1 of 13 — Generate this FIRST before all other templates

Identity, positioning, and principles for the Security Ronin Katana brand.

---

## Brand Essence

**Security Ronin Katana** — The katana is the samurai's primary weapon: precise, sharp, purpose-built for a single devastating cut. Within the Security Ronin family, Katana is the cutting tool -- forensic triage that slices through disk images to extract answers. Security Ronin General is the commander (CISO sidekick); Katana is what the commander draws when evidence needs examining.

Precision DFIR triage -- from disk image to incident response answers in 35 seconds.

### Positioning Statement

> **Security Ronin Katana is a Rust-powered forensic triage CLI** that delivers end-to-end USN journal analysis -- from E01 disk image to 12 answered IR questions -- in 35 seconds for solo DFIR consultants and enterprise incident response teams. Unlike monolithic forensic suites (EnCase, X-Ways, Magnet) or fragmented open-source tools (MFTECmd + manual correlation), Security Ronin Katana recovers ghost records from $LogFile, carves deleted evidence from unallocated space, reconstructs every file path to zero unknowns, and presents findings in an interactive HTML report ordered by what the incident commander needs to communicate first.

### Core Tagline

> "35-second NTFS forensic triage -- from disk image to incident response answers."

---

## Brand Identity

### The Name

**Security Ronin** is the company. **Katana** is the forensic triage product.

- **Security Ronin Katana** -- Full product name for formal contexts (documentation headers, legal, marketing)
- **Katana** -- Acceptable short form in conversation among practitioners who know the product family
- **`katana`** -- CLI binary name (monospace, lowercase)
- **Never**: "SR Katana", "SecurityRonin Katana", "Katana by Security Ronin", "security-ronin-katana"

**Product Family:**

| Product | Role | Status |
|---------|------|--------|
| **Security Ronin General** | CISO sidekick -- strategic security advisory | Active |
| **Security Ronin Katana** | Forensic triage -- disk image to IR answers | Active |

### Logo

The logo evokes forensic precision and the deliberate, single-stroke philosophy of the katana:

| Element | Meaning |
|---------|---------|
| **Katana blade silhouette** | Precision, purpose-built design, a single tool for a decisive cut |
| **Binary/hex overlay on blade** | Data carved from evidence -- forensic recovery emerging from noise |
| **Monochrome default** | Works in terminals, dark SOCs, and print. No color dependency |

**Usage Requirements:**
- Use the full "Security Ronin Katana" mark in headers and first reference; "Katana" thereafter
- Minimum clear space: 1x the height of the blade element on all sides
- Monochrome is the primary usage; accent color (blue `#58a6ff`) permitted on web/docs only
- Logo assets available in the brand repository under `/assets/logo/`

### Color Philosophy

**Primary: Dark mode by default**

Designed for practitioners pulling 14-hour shifts in dim SOCs and home offices. These colors are derived from the actual HTML triage report template.

| Color Option | Why We Rejected It |
|--------------|-------------------|
| Light/white backgrounds | Eye strain during extended forensic analysis sessions; practitioners live in dark terminals |
| Neon/cyberpunk palettes | Distracting, unprofessional in court presentations and formal reports |
| Corporate blue-on-white | Signals "enterprise vendor," not "practitioner tool" |

**Dark palette signals:**
- Seriousness -- forensic work demands focus, not visual noise
- Practitioner solidarity -- we use what they use (dark terminals, dim labs)
- Evidence clarity -- high-contrast text on dark backgrounds makes timestamps, paths, and hex values immediately legible

| Token | Hex | Usage |
|-------|-----|-------|
| `--bg-primary` | `#0d1117` | App background, terminal theme |
| `--bg-surface` | `#161b22` | Cards, panels, elevated surfaces |
| `--border` | `#30363d` | Subtle separation, table borders |
| `--text-primary` | `#e6edf3` | Body text, high readability on dark |
| `--text-secondary` | `#7d8590` | Labels, metadata, de-emphasized text |
| `--accent` | `#58a6ff` | Links, interactive elements, highlights |
| `--critical` | `#f85149` | Critical findings, alerts, severity markers |
| `--warning` | `#d29922` | Warnings, medium severity |
| `--success` | `#3fb950` | Resolved items, positive indicators |
| `--recovered` | `#bc8cff` | Ghost records, carved data -- visually distinct from live data |

**Accessibility:** All color combinations meet WCAG AA standards (4.5:1 minimum contrast ratio).

### Typography

| Use | Font | Character |
|-----|------|-----------|
| Data display | `ui-monospace, SFMono-Regular, Menlo, Consolas, monospace` | Hex offsets, timestamps, file paths, reason flags must align and be individually legible |
| Prose & UI | `Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif` | Clean readability for report narratives, documentation, marketing |
| Terminal output | User's configured monospace font | Never override the practitioner's terminal setup |

**Rules:**
- All forensic data (timestamps, paths, MFT references, hex values) must render in monospace
- Report narratives and explanatory text use sans-serif
- Font size minimum: 13px for data, 14px for prose
- Line height: 1.5 minimum for all text

---

## Voice & Tone

### Personality

| Trait | Expression |
|-------|------------|
| **Practitioner-to-practitioner** | Speaks like a senior forensic examiner briefing a peer, not a vendor pitching a product. "The carved MFT entries seed the rewind engine for path resolution." |
| **Technically precise** | Uses correct forensic terminology without apology. "USN_RECORD_V2 structures at 8-byte alignment boundaries," not "we scan the disk for deleted stuff." |
| **Confident but honest** | States what Katana does and does not do with equal directness. "Zero unknown paths on every dataset we've tested" alongside "Phase 1 focuses on NTFS journal triage. Memory forensics is not in the binary." |
| **Numbers over adjectives** | "35 seconds. 847,293 records. 12 questions answered." Never "blazingly fast," "comprehensive," or "powerful." |
| **Evidence-driven** | Every claim is backed by reproducible data. "Benchmarked against Szechuan Sauce CTF: 92.3% precision, 99.7% recall." |

### Writing Principles

**Do:**
- Lead with what the practitioner gets, not what the tool does ("Answer 12 IR questions in 35 seconds")
- Use precise forensic terminology -- our audience knows what $MFT entry reuse means
- Show the command and its output instead of claiming "powerful" or "comprehensive"
- Acknowledge limitations directly ("Phase 1 focuses on NTFS journal triage. Memory forensics is not in scope.")

**Don't:**
- Use vendor-speak: "next-generation," "AI-powered," "revolutionary," "seamless," "enterprise-grade," "best-in-class," "solution," "leverage," "utilize," "empower"
- Make unquantified claims ("fast," "scalable," "comprehensive" without numbers)
- Dumb down forensic concepts for marketing purposes
- Hide limitations or imply capabilities that do not exist yet

### Language Examples

| Instead of... | Write... |
|---------------|----------|
| "Our AI-powered solution leverages advanced algorithms" | "The carved MFT entries seed the rewind engine for path resolution" |
| "Blazingly fast forensic analysis" | "35 seconds on a 40GB E01 with 847K records on an M1 MacBook Air" |
| "Comprehensive forensic suite" | "12 triage questions answered, 7 output formats, ghost recovery + unallocated carving" |
| "Enterprise-grade security platform" | "Rust CLI, Apache-2.0 core, deterministic output you can defend in court" |

---

## Core Beliefs

These beliefs shape every brand decision. They are design constraints, not slogans. Every feature, decision, and tradeoff must be traceable to one of these beliefs.

### Forensic Integrity Is Non-Negotiable

Every output must be deterministic, verifiable, and court-admissible. Speed without accuracy is worse than slow. A forensic tool that produces different results on different runs, silently drops records, or cannot explain its findings is not a forensic tool -- it is a liability.

**Design implication:** Results are deterministic across platforms and runs. CI/CD runs integration tests against pinned forensic images. Precision/recall benchmarks are published and reproducible. If a speed optimization would reduce accuracy, we choose accuracy.

### Speed-to-Answers Is a Forensic Imperative

The first 60 minutes of an incident response determine whether containment succeeds or the attacker pivots. Every hour a practitioner spends stitching tools together is an hour the adversary has to exfiltrate, persist, or destroy evidence. Fast triage is not a convenience feature -- it is an operational necessity.

**Design implication:** The default workflow (`--image` + `--report`) must produce actionable answers in under 60 seconds on commodity hardware. If a feature slows the critical path, it becomes opt-in.

### Deleted Evidence Is Still Evidence

Attackers clear journals, overwrite MFT entries, and wipe logs. But NTFS scatters metadata across $LogFile transaction records, unallocated clusters, and $MFTMirr shadow copies. A tool that only reads allocated data is giving the attacker a veto over what the investigator can see. Recovery is not optional -- it is the baseline.

**Design implication:** Ghost record recovery and unallocated carving are first-class features, not plugins or add-ons. Recovered evidence is visually distinguished but never treated as second-class.

### Practitioners Deserve Tools, Not Platforms

Solo consultants do not need a 6-month procurement cycle, a vendor relationship manager, or a training certification to parse a USN journal. They need a binary that works, documentation they can read, and output formats that fit their existing workflow (Sleuthkit body files, Timeline Explorer CSVs, SOAR-ready JSONL).

**Design implication:** CLI-first. No mandatory account creation, no telemetry, no license key for core functionality. Output in every format the DFIR ecosystem expects.

### Open Source Earns Trust, Trust Earns Adoption

In forensics, tool credibility matters in court. A closed-source binary is a black box that opposing counsel can challenge. Open source means the algorithm is auditable, the precision/recall is reproducible, and the community can verify claims. We publish our source, our benchmarks, and our methodology because that is what a defensible forensic tool requires.

**Design implication:** Apache-2.0 core. Benchmarks published and reproducible. Validation methodology documented. Enterprise features add workflow capabilities (integrations, reporting, collaboration), never gatekeep forensic accuracy.

---

## What We're Not

These are explicit, permanent "no" decisions for the community tier. They exist to prevent scope creep and to communicate honestly about what Security Ronin Katana is.

| We Are NOT | Why This Matters | Revisit When |
|------------|------------------|--------------|
| **A GUI-first application** | Our primary users live in terminals. GUI overhead slows iteration, increases maintenance surface, and adds zero value for CLI-native practitioners. The HTML report IS the visual interface. | When paying enterprise customers explicitly request and fund it. |
| **A plugin/extension system** | Plugin architectures invite complexity, security surface, and maintenance burden for a solo developer. Katana does one thing with depth. | When team size and revenue justify the support burden. |
| **A cloud-based processing tool** | Forensic evidence stays on the examiner's machine. Uploading disk images to cloud infrastructure introduces chain-of-custody issues, bandwidth bottlenecks, and data sovereignty concerns. | Never for community tier. Enterprise tier may offer optional managed infrastructure. |
| **An AI/ML-based triage classifier** | Deterministic, auditable logic is court-defensible. ML classifiers are black boxes that opposing counsel can challenge. "The neural network said so" is not expert testimony. | When ML interpretability matures enough to produce court-admissible explanations. |
| **A database-first architecture** | Katana processes evidence in a streaming pipeline. Requiring a database server adds deployment friction and operational overhead for solo consultants. | SQLite output exists for post-processing; a database engine will not gate the critical path. |
| **A memory forensics tool** | Memory analysis (Volatility-style) is a separate domain with its own data structures, acquisition challenges, and validation requirements. | Not on roadmap. Partner with Volatility/MemProcFS rather than compete. |
| **A real-time monitoring agent** | Katana is post-mortem triage from disk images. Live monitoring is a fundamentally different architecture (kernel driver, event subscription, streaming pipeline). | Phase 3+: when the triage engine is proven and the business model supports it. |
| **A case management system** | Case management is a workflow problem, not a forensic analysis problem. Integrate with existing systems (TheHive, DFIR-IRIS) rather than building one. | Enterprise tier: API/webhook integration points, not a built-in case manager. |

---

## Design Principles

### Visual Aesthetic

| Principle | Expression |
|-----------|------------|
| **One Command, First Answers** | The most common workflow is expressible in a single command. New user to answered questions without reading documentation. |
| **Progressive Disclosure** | Story tab (12 questions) by default. Explore tab for depth. SQLite export for power users. Each layer reveals more without overwhelming. |
| **Forensic Fidelity Over Convenience** | Never silently discard, merge, or alter evidence. Show both conflicting records with provenance clearly marked. |
| **Interoperability Is a Feature** | Output formats plug directly into existing DFIR workflows: `--body` for mactime, `--csv` for Timeline Explorer, `--jsonl` for SOAR, `--sqlite` for custom analysis. |

### Why These Choices?

**CLI-first, HTML report as visual layer:**
Practitioners live in terminals. A GUI adds maintenance surface and deployment friction without improving forensic output. The HTML triage report provides the visual analysis experience when needed, without requiring a running application or server.

**Dark color palette derived from the product:**
The brand colors are pulled from the actual triage report template. The brand follows the product, not the other way around. When the report evolves, the brand palette evolves with it.

**Monospace for data, sans-serif for prose:**
Forensic data (timestamps, hex offsets, file paths) demands character-aligned monospace rendering. Explanatory text demands readable sans-serif. Mixing them based on content type respects both readability needs.

---

## Anti-Patterns

What we explicitly avoid in brand expression:

| Anti-Pattern | Why We Avoid It |
|--------------|-----------------|
| "Blazingly fast" marketing | Every Rust CLI claims this. State wall-clock times: "35 seconds on a 40GB E01 with 847K records on an M1 MacBook Air." |
| Silent data loss | Dropping records that fail to parse hides evidence. Parse failures go to stderr with record offset and reason. |
| Vendor lock-in formats | Proprietary output formats force practitioners into our ecosystem. Every output format is an open standard or community convention. |
| "Works on my machine" validation | Forensic tools must produce identical results across platforms. CI/CD tests against pinned images. Deterministic, cross-platform verified. |
| Feature gates on forensic accuracy | Putting ghost recovery behind a paywall means the free tier produces incomplete results. All forensic analysis stays in the open-source core. |
| Ignoring false positives | Triage questions with high false-positive rates teach practitioners to ignore alerts. Every question has documented precision/recall. |

---

## Social Positioning

How users describe Security Ronin Katana to others matters. We design for the moment when someone asks "What's Katana?"

### What Users Tell Others

Different audiences need different framings:

| Audience | Preferred Framing |
|----------|-------------------|
| Solo DFIR consultant at a SANS summit | "You know how MFTECmd gives you 40% UNKNOWN paths? Katana does path reconstruction automatically, carves deleted records, answers 12 IR questions in 35 seconds. One command, one HTML report. Open source, Apache-2.0." |
| MSSP team lead evaluating tools | "Katana handles the triage pipeline -- disk image in, answered IR questions out. Community edition is free and open source for evaluation. Enterprise tier adds collaboration, multi-device, and integrations." |
| CISO receiving an IR briefing | "Our IR team uses Security Ronin Katana for initial forensic triage. It processes the USN journal from disk images in 35 seconds and produces a structured report answering 12 standard IR questions." |
| Expert witness in court testimony | "Timeline analysis was performed using Security Ronin Katana v0.6.0 (Apache-2.0), which parsed [N] USN journal records including [N] recovered from $LogFile and [N] carved from unallocated space." |
| Developer evaluating the codebase | "Rust, Apache-2.0, well-documented parsing logic. The USN journal parser handles V2/V3/V4 records with full path reconstruction via the CyberCX Rewind algorithm." |

### Addressing Skepticism

| Skepticism | Reframe |
|------------|---------|
| "Another forensic tool? I already have EnCase/X-Ways." | "Katana is not a replacement for your suite. It is a 35-second triage step that tells you what to investigate deeply. It runs before you open EnCase, not instead of it." |
| "Open source forensic tools lack validation." | "Katana publishes precision/recall benchmarks against real CTF datasets. The source is auditable. That is more validation transparency than any closed-source vendor provides." |
| "A solo developer cannot maintain a forensic tool." | "The community core is Apache-2.0. If the maintainer disappears, the code and benchmarks remain. That is the point of open source." |

### Brand Voice in Social Context

When users share or discuss Security Ronin Katana publicly:

**Do:**
- Share specific results: record counts, timing, findings
- Reference reproducible benchmarks and CTF datasets
- Acknowledge what Katana does not do alongside what it does
- Credit the forensic research community (CyberCX Rewind, Eric Zimmerman's tools)

**Don't:**
- Use vendor marketing language ("next-gen," "AI-powered," "revolutionary")
- Make unquantified superiority claims ("best forensic tool")
- Disparage competing tools or their authors
- Promise capabilities that are on the roadmap but not shipped

### Social Proof Strategy

We let the evidence speak, but do emphasize:
- Benchmark results against real CTF datasets (Szechuan Sauce, others)
- Record counts and timing on specific hardware configurations
- Community contributions and issue engagement
- Conference demos and practitioner testimonials with specific case outcomes

---

## Licensing & Ethics

### Dual License: Apache-2.0 + Proprietary

We chose the Apache-2.0 license for the community core over MIT and GPL because it provides explicit patent protection, enterprise legal familiarity, and open-core compatibility.

**Why not other licenses?**

| License | Why We Rejected It |
|---------|-------------------|
| MIT | No patent protection. In forensics, patent claims on algorithms could threaten users and contributors. |
| GPL | Corporate legal teams create friction with GPL. Enterprise adoption requires easy license approval. |
| AGPL | Overly restrictive for a CLI tool. Would prevent legitimate use in proprietary forensic workflows. |
| Proprietary-only | Forensic tools must be auditable. Closed source is a courtroom liability and a trust deficit. |

**Open-Core Model:**

| Tier | License | What's Included |
|------|---------|-----------------|
| **Community** | Apache-2.0 | Full forensic engine: parsing, path reconstruction, ghost recovery, unallocated carving, 12 triage questions, all output formats, HTML report, rule engine |
| **Enterprise** | Proprietary | Collaboration features, multi-device analysis, collection capabilities, managed infrastructure, integrations (Velociraptor, TheHive, Cortex XSOAR), SSO/SAML, audit logging, SLA-backed support |

**The license explicitly prohibits:**
- Removing attribution or copyright notices
- Claiming the software as proprietary without modification
- Using the "Security Ronin" or "Katana" trademarks without authorization
- Redistributing enterprise-tier features under the Apache-2.0 license

**The license requires:**
- Preservation of copyright and license notices in all copies
- Disclosure of significant modifications to the Apache-2.0 core
- Patent grant for contributed code
- Clear distinction between community and enterprise components in derivative works

**Iron rule:** No forensic analysis capability is ever gated behind a paid tier. If it affects the accuracy or completeness of forensic findings, it belongs in the open-source core. Enterprise tier adds workflow features, never forensic depth.

### Ethical Guidelines

1. **Dual-use awareness:** Katana recovers deleted evidence. It can investigate crimes AND reveal what evidence recovery is possible. We accept this duality and mitigate by focusing on defensive/investigative use cases.
2. **No law enforcement exclusivity:** Available to everyone -- defense attorneys, civil litigants, journalists, researchers, individuals examining their own systems. Access to forensic analysis is not limited to one side.
3. **Accuracy over speed:** If a speed optimization would reduce forensic accuracy, we choose accuracy. Speed without accuracy is worse than slow.
4. **Transparent limitations:** Documentation clearly states what Katana does not do. "Carved USN entries give you the what, when, and where. They do not guarantee file content is still on disk."

---

## Brand Governance

### Trademark

**Security Ronin Katana** is a trademark of Security Ronin.

The trademark should be used consistently across:
- Website header and footer
- Page titles and metadata
- Documentation (first reference uses full name, subsequent uses may use "Katana")
- Marketing materials
- Conference presentations

### Questions?

Brand-related questions should be directed to the Security Ronin team via GitHub Discussions or the project's communication channels.

---

*Document generated by North Star Advisor*
