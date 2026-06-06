# Security Ronin Katana: North Star Specification

> Precision DFIR triage -- from disk image to incident response answers in 35 seconds.

**Product:** Security Ronin Katana (usnjrnl-forensic)
**Company:** Security Ronin
**Version:** 2.0
**Date:** 2026-03-10
**Status:** Active
**Cross-references:** [BRAND_GUIDELINES.md](./BRAND_GUIDELINES.md) | [COMPETITIVE_LANDSCAPE.md](./COMPETITIVE_LANDSCAPE.md) | [ARCHITECTURE_BLUEPRINT.md](./ARCHITECTURE_BLUEPRINT.md)

---

# Part 1: Strategic Foundation

## 1.1 North Star Metric

### The Metric

> **Number of Paying Enterprise Customers**

**Definition**: The count of organizations with at least one active paid seat ($99-149/month per investigator) that have processed at least one case in the trailing 30-day period.

**Target**: 50 paying enterprise customers within 12 months of enterprise tier launch.

**Measurement method**: Enterprise license management system tracks active seats and case processing events. A customer counts as "paying" when at least one seat is billed and "active" when at least one triage is executed in the trailing 30 days. During pre-enterprise phases, proxy via community adoption metrics that predict enterprise readiness.

### Why This Metric

| Criterion | How It Qualifies |
|-----------|------------------|
| **Leading** | Enterprise customer count predicts revenue sustainability, community health (enterprise customers drive contributor activity), and product-market fit for the paid tier. Each new customer validates the open-core model. |
| **Actionable** | The team can influence this metric through community-to-enterprise conversion, feature development for team workflows (RBAC, multi-device correlation), and direct outreach to MSSP and enterprise IR teams. |
| **Customer-centric** | A paying customer who processes cases is a customer who trusts the tool for real investigations -- the ultimate validation of forensic software. Revenue without usage would be a failure. |
| **Understandable** | Anyone on the team, any investor, any advisor can understand "50 paying enterprise customers" without explanation. |

### What This Metric Rejects

| Anti-Metric | Why We Reject It |
|-------------|------------------|
| **GitHub Stars** | Vanity metric. Stars measure awareness, not adoption. A tool with 10K stars and zero production users is a toy. Stars matter for community tier health as a leading indicator, but they do not drive the business. |
| **Total Downloads** | Downloads measure curiosity, not commitment. A DFIR practitioner who downloads but never runs the tool on a real case is a non-user. Too many steps removed from value delivery. |
| **Feature Count** | More features means more maintenance surface, more bugs, more documentation debt. We optimize for depth on fewer features, not breadth across many. Adding features to match a comparison table produces breadth without depth. |
| **Time Spent in Tool** | In forensic triage, less time is better. If users spend 35 seconds instead of 35 minutes, that is success. Optimizing for engagement time would be antithetical to our mission. |
| **Lines of Code** | Complexity proxy that incentivizes bloat. The best version of Katana is the smallest codebase that answers the most IR questions accurately. |

## 1.2 Input Metrics Hierarchy

The North Star decomposes into input metrics that the team can directly influence:

```
                         NORTH STAR
                 Paying Enterprise Customers
                        Target: 50
                             |
         +-------------------+-------------------+
         |                   |                   |
         v                   v                   v
   +-----------+      +-----------+      +-----------+
   | Community |      | Product   |      | Enterprise|
   | Adoption  |      | Quality   |      | Conversion|
   |           |      |           |      |           |
   | Target:   |      | Target:   |      | Target:   |
   | 500 active|      | <5% FP    |      | 15% conv  |
   | users     |      | rate      |      | rate      |
   +-----------+      +-----------+      +-----------+
```

### Input Metrics Definitions

| Metric | Definition | Target | Owner |
|--------|------------|--------|-------|
| **Community Active Users** | Unique users who run at least one triage per month (measured via opt-in telemetry or GitHub release downloads) | 500 monthly active users | Growth |
| **Triage Completion Rate** | Percentage of triage invocations that complete successfully without errors | >95% | Engineering |
| **Time-to-First-Answer (P95)** | Wall-clock time from command execution to first triage question answered in the HTML report | <35 seconds | Engineering |
| **False Positive Rate** | Percentage of triage questions that flag activity as suspicious when it is benign, measured against labeled ground-truth datasets | <5% | Engineering |
| **Enterprise Conversion Rate** | Percentage of community-tier organizations that convert to a paid enterprise seat within 90 days of first use | 15% | Sales/Growth |
| **Enterprise Retention Rate** | Percentage of paying enterprise customers who renew after the first billing period | >90% | Customer Success |
| **Monthly Recurring Revenue (MRR)** | Total monthly revenue from enterprise seat subscriptions | $50K (at 50 customers, avg 3-4 seats at ~$125/seat) | Business |
| **Ghost Record Recovery Rate** | Percentage of recoverable deleted USN records successfully recovered from $LogFile and unallocated space | >95% | Engineering |
| **Path Resolution Completeness** | Percentage of USN journal records resolved to full file paths (zero UNKNOWN target) | 100% | Engineering |

### Metrics We Track But Don't Optimize

| Metric | Why We Track | Why We Don't Optimize |
|--------|--------------|----------------------|
| GitHub Stars | Community awareness signal; leading indicator for downloads | Optimizing for stars incentivizes marketing over substance |
| Social Media Mentions | Brand health indicator | Chasing mentions leads to clickbait content, not practitioner trust |
| Conference Talk Invitations | Thought leadership proxy | Talks follow great product, not the other way around |
| Total Artifact Types Supported | Feature completeness signal | Optimizing here leads to breadth over depth -- violates our "one thing with depth" principle |
| Installation-to-First-Run Time | Developer experience signal | Useful for onboarding friction detection but not a business driver |

## 1.3 Positioning

### Positioning Statement

> **Security Ronin Katana is a precision DFIR triage tool** that delivers incident response answers from disk images in 35 seconds for forensic practitioners. Unlike monolithic suites like EnCase and Magnet AXIOM, Katana does one thing with surgical depth: NTFS journal forensics with ghost recovery, anti-forensics detection, and courtroom-defensible evidence.

### What Makes Us Different

| Dimension | Alternatives | Our Approach |
|-----------|--------------|--------------|
| **Speed** | MFTECmd requires manual pipeline assembly (export CSV, open in Timeline Explorer, correlate manually). EnCase/AXIOM process full disk images taking minutes to hours. | Single command, 35-second triage. Point at an E01, get an HTML report with answered questions. No loading screens, no GUI overhead, no waiting. |
| **Depth** | Most tools parse allocated journal entries only. Deleted records are silently dropped or marked "UNKNOWN". Ghost evidence is invisible. | Ghost recovery from unallocated space and $LogFile, QuadLink four-artifact correlation, anti-forensics detection. Evidence other tools miss entirely. |
| **Trust** | Commercial tools are closed-source binaries. Results cannot be independently verified. Expert witnesses must trust the vendor. | Apache-2.0 source code. Published precision/recall benchmarks you can verify. Reproducible results you can defend in court. |
| **Workflow** | GUI-heavy tools require clicking through menus, loading projects, configuring parsers. Each case requires manual setup. | CLI-native. One command per case. Output is a self-contained HTML report. No project files, no databases, no configuration. |
| **Economics** | Enterprise forensic suites cost $5K-15K/year per seat. Solo consultants and small MSSPs cannot justify the cost. | Free open-source core with full forensic capabilities. Enterprise tier at $99-149/seat/month for team features -- 10x cheaper than incumbents. |

### Value Proposition

| User Need | Current Pain | Our Solution |
|-----------|--------------|--------------|
| Fast triage at incident scenes | Existing tools require 15-60 minutes of setup and processing before first answers | 35-second triage from E01 to answered questions in a self-contained HTML report |
| Evidence from deleted artifacts | Most tools drop deleted USN journal records or show them as "UNKNOWN" paths | Ghost recovery carves deleted records from unallocated space and resolves paths via MFT correlation |
| Courtroom-defensible results | Closed-source tools produce results that cannot be independently verified by opposing experts | Open-source code with published precision/recall metrics. Every result is reproducible and auditable. |
| Standardized team workflows | Each analyst uses different tools and produces inconsistent results | Enterprise tier standardizes triage with RBAC, audit trails, and multi-device correlation |
| Compliance-grade audit trails | Ad-hoc tooling produces no audit trail for SOC 2 or legal requirements | Enterprise tier logs every investigator action with immutable audit records |

## 1.4 Target Users

### Primary Persona: Alex Chen -- Solo DFIR Consultant

```
"I need answers at 2 AM, not a 45-minute loading bar."

Demographics: 38, independent DFIR consultant, boutique forensic firm owner
Experience: Ex-law enforcement digital forensics, 10+ years, certified (GCFE, EnCE)
Caseload: 3-5 cases/month, mix of corporate IR and litigation support
Budget: Budget-conscious ($200-400/hr billing rate, cannot justify $5K+/year suites)

Current State:
  MFTECmd to parse USN journal, Timeline Explorer to view CSV, manual
  grep/scripting for specific questions, separate tools for path resolution.
  Total: 45-90 minutes per triage pass.

Access Barriers:
  Cannot afford enterprise forensic suites ($5K-15K/year).
  Works from a laptop at client sites with limited bandwidth.
  Works alone -- no team to hand off to or collaborate with.

Functional Jobs:
  - Triage a disk image to determine if an incident occurred
  - Identify what files were created, deleted, or renamed and when
  - Generate a report the client can understand and act on
  - Determine if anti-forensics tools were used to cover tracks
  - Reconstruct attack narrative from file system evidence

Emotional Jobs:
  - Feel confident the tool did not miss critical evidence
  - Feel fast and competent in front of clients during 2 AM incidents
  - Feel like a professional using professional-grade tools, not duct-taped scripts

Social Jobs:
  - Appear authoritative and thorough to clients paying $200-400/hour
  - Recommend tools in DFIR community forums that others respect
  - Produce reports that hold up under legal scrutiny from opposing counsel

Success Signals:
  - "I pointed it at the E01 and had my first answers before the client
     finished their coffee."
  - "The ghost recovery found the deleted installer the attacker tried to hide.
     That was the case."
  - "I recommend this tool to every solo consultant I know."
```

**Tier**: Community (free CLI)
**Revenue Role**: Evangelist. Alex discovers the tool, validates it on real cases, and recommends it to colleagues at MSSPs and enterprises. Community adoption drives enterprise pipeline.

### Secondary Persona: Sarah Okonkwo -- MSSP Senior Analyst

```
"My team handles 15-30 cases a month. I need every analyst
producing consistent results, not reinventing the wheel each time."

Demographics: 32, Senior Analyst at a Managed Security Service Provider (MSSP)
Team: 6 analysts, handling 15-30 cases/month
Experience: 7 years in SOC/IR, moved from tier-2 analyst to team lead
Budget: Departmental budget, requires ROI justification to leadership

Current State:
  Team uses a mix of Autopsy, X-Ways, and custom scripts. Inconsistent
  workflows across analysts. Senior analysts get pulled into every case
  for quality review. No audit trail for evidence chain of custody.

Access Barriers:
  Cannot adopt tools without demonstrating ROI to leadership.
  Needs features beyond what free tools offer: RBAC, multi-device
  correlation, evidence handoff, and compliance-grade audit trails.
  Integration with Velociraptor collection pipeline is mandatory.

Functional Jobs:
  - Standardize triage workflow across a team of varying skill levels
  - Correlate artifacts across multiple devices in a single investigation
  - Import evidence from Velociraptor and Binalyze collections directly
  - Maintain chain of custody and audit trail for client deliverables
  - Produce consistent, high-quality reports regardless of which analyst ran triage

Emotional Jobs:
  - Feel confident that junior analysts cannot miss critical evidence
  - Feel in control of case quality without reviewing every output personally
  - Feel that the team investment in tooling is paying off in throughput

Social Jobs:
  - Demonstrate measurable improvement in case throughput to leadership
  - Position the team as best-in-class to client organizations
  - Show SOC 2 compliance evidence to auditors without scrambling

Success Signals:
  - "My junior analysts produce the same quality triage as my seniors now."
  - "We cut our average time-to-first-answer from 45 minutes to 2 minutes
     across the team."
  - "The audit trail saved us during the SOC 2 audit. Everything was logged."
```

**Tier**: Enterprise ($99-149/seat/month, 4-8 seats)
**Revenue Role**: Primary buyer. Sarah's team represents the core enterprise customer: mid-size seat count, high case volume, strong retention, and reference potential for other MSSPs.

### Tertiary Persona: James Whitfield -- Enterprise IR Team Lead

```
"I report to the CISO. My tools need to be defensible, auditable,
and compliant. I cannot adopt a tool my security team cannot vet."

Demographics: 45, IR Team Lead at a Fortune 500 company
Team: 12-person IR team, reports directly to CISO
Experience: 20+ years in security, former Big 4 consultant
Budget: $50K+/year for forensic tooling, procurement-driven purchasing

Current State:
  Uses EnCase and Magnet AXIOM enterprise licenses ($50K+/year).
  Frustrated by slow processing, vendor lock-in, and inability to
  verify results independently. SSO and compliance are non-negotiable.

Access Barriers:
  Procurement requires SOC 2 Type II, SSO/SAML integration, and
  vendor security questionnaire completion. Budget is not the
  constraint -- compliance and risk are. Legal review of open-source
  license required before adoption.

Functional Jobs:
  - Ensure IR team has fast, reliable triage for time-critical incidents
  - Integrate forensic tooling with existing SIEM and SOAR workflows
  - Produce audit-ready evidence packages for legal and compliance teams
  - Maintain SSO and access controls aligned with corporate identity management
  - Track and report on team triage performance metrics to CISO

Emotional Jobs:
  - Feel confident the tool meets enterprise security standards
  - Feel that the open-source foundation reduces vendor lock-in risk
  - Feel that the tool will be supported and maintained long-term

Social Jobs:
  - Justify the tooling investment to the CISO with quantified time savings
  - Present audit-compliant evidence to legal counsel and regulators
  - Position the IR team as using cutting-edge, defensible technology

Success Signals:
  - "We replaced our $50K/year suite with something faster, cheaper,
     and auditable."
  - "The SOC 2 compliance was built in. My team didn't have to bolt it on."
  - "I can show the CISO exactly how much faster our triage is quarter
     over quarter."
```

**Tier**: Enterprise ($99-149/seat/month, 8-12+ seats)
**Revenue Role**: High-value account. James's team represents the premium enterprise segment: large seat count, long sales cycle, high lifetime value, and marquee reference customer for the platform.

## 1.5 Forces of Progress Analysis

Understanding the forces that drive adoption and the forces that resist it.

### Push Forces (Away from Current State)

| Force | Evidence | Strength |
|-------|----------|----------|
| Manual tool stitching wastes 30-60 minutes per case | Practitioners report using 3-5 separate tools for basic NTFS triage (MFTECmd, Timeline Explorer, grep, custom scripts) | Strong |
| Deleted evidence is invisible in current tools | Most USN journal parsers drop records with unresolvable paths. Critical evidence is silently lost. Attackers exploit this gap. | Strong |
| Closed-source tools are courtroom liabilities | Defense experts increasingly challenge forensic tool results when source code is unavailable for review. Daubert challenges are rising. | Medium |
| Enterprise suites are prohibitively expensive for small teams | EnCase/AXIOM enterprise licenses run $5K-15K/year per seat. Solo consultants and small MSSPs cannot justify the cost. | Strong |
| Inconsistent results across team members | Without standardized workflows, junior and senior analysts produce different quality triage on the same evidence. QA review becomes a bottleneck. | Medium |
| No audit trail for compliance | Ad-hoc tooling produces no chain-of-custody documentation. SOC 2 audits require scrambling to reconstruct investigator actions. | Medium |

### Pull Forces (Toward Security Ronin Katana)

| Force | Evidence | Strength |
|-------|----------|----------|
| 35-second triage is dramatically faster than alternatives | No competing tool offers sub-minute triage from E01 to answered questions. Order-of-magnitude improvement. | Strong |
| Ghost recovery finds evidence others miss | Recovering deleted USN journal records from unallocated space and $LogFile is a capability no mainstream tool offers. | Strong |
| Open-source builds trust in the forensic community | Apache-2.0 license means every practitioner can audit the parsing logic and verify results. Courtroom-defensible by design. | Strong |
| CLI-native workflow matches practitioner habits | DFIR practitioners work in terminals. No context switch required. Scriptable. Automatable. | Medium |
| Open-core model allows free evaluation before purchase | Community tier is genuinely useful, not crippleware. Enterprise features are additive (team, compliance, integrations). Practitioners adopt bottom-up. | Medium |
| 10x cheaper than incumbents | $99-149/seat/month vs $5K-15K/year per seat. Enterprise-grade features at a fraction of the cost. | Strong |

### Anxiety of Change

| Concern | User Verbalization | Mitigation |
|---------|-------------------|------------|
| Reliability for real cases | "I can't use a hobby project for a case that might go to court." | Published precision/recall benchmarks against labeled datasets. Apache-2.0 source is auditable. Reproducible results. Security Ronin is a business, not a side project. |
| Long-term maintenance | "I've been burned by open-source tools that get abandoned after six months." | Enterprise revenue funds sustained development. Public roadmap. Active development cadence with monthly releases. |
| Workflow disruption | "We're mid-case on three investigations. I can't retrain everyone right now." | Zero-config CLI. Drop-in addition to existing workflow -- does not replace existing tools, adds a faster triage step. |
| Compliance requirements | "My auditor will ask about SOC 2 and data handling." | Enterprise tier includes SOC 2 compliance, immutable audit logging, SSO/SAML, and role-based access controls. |
| Evidence integrity | "How do I know the tool doesn't modify or corrupt evidence?" | Read-only access to disk images. Hash verification on all parsed artifacts. Deterministic output: same input always produces same report. |

### Habit of the Present

| Habit | Why It Persists | How We Break It |
|-------|-----------------|-----------------|
| "I already know MFTECmd / EnCase / AXIOM" | Tool familiarity reduces perceived risk. Practitioners have years of muscle memory. | Katana is not a replacement -- it is a faster first step. Use Katana for triage, then deep-dive with existing tools if needed. Additive, not substitutive. |
| "My team has established workflows" | Changing workflows mid-engagement is risky. Process change requires management approval. | Katana integrates into existing workflows. Import from Velociraptor/Binalyze. Export to Timeline Explorer-compatible formats. Slot in, don't rip out. |
| "We've already paid for our forensic suite" | Sunk cost fallacy. Enterprise licenses are annual commitments. | Position as complementary triage layer. $99-149/seat/month vs $5K-15K/year per seat. ROI is immediate in time saved per case. |
| "Our scripts already do this" | Custom scripts represent invested effort and institutional knowledge. | Custom scripts do not do ghost recovery, QuadLink correlation, or anti-forensics detection. Katana handles the hard parts; scripts can consume Katana output. |

---

# Part 2: Scope Definition

## 2.1 Phase Boundaries

### Phase 0: Community Foundation (Current)

**Theme**: "Ship the Sharpest Blade"

**Objective**: Release v1.0 of the community edition on GitHub and establish usnjrnl-forensic as the fastest, most accurate NTFS journal triage tool available.

**In Scope**:

| Feature | Acceptance Criteria | Why Essential |
|---------|---------------------|---------------|
| E01 image parsing | Parse E01 disk images and extract $UsnJrnl, $MFT, and $LogFile | Core input format for forensic investigations |
| USN journal triage | 21 triage questions answered with evidence citations | Triage questions are the primary value proposition -- turning raw artifacts into answers |
| Ghost record recovery | Recover deleted USN journal records from unallocated space and $LogFile | Key differentiator. No other tool does this. |
| HTML report generation | Self-contained HTML report with interactive tables, timelines, and triage answers | The report is the user-facing output. Must be polished and comprehensive. |
| CLI interface | Single command (`--image` + `--report`) produces complete triage | Speed-to-answers requires zero-config workflow |
| 7 output formats | CSV, JSONL, SQLite, Body, TLN, XML, HTML | Practitioners have existing workflows. Output must plug into them without conversion. |
| Precision/recall benchmarks | Published P/R metrics against labeled ground-truth datasets | Trust requires transparency. Benchmarks prove accuracy claims. |
| Custom rule engine | YAML-based pattern matching for user-defined detections | Extensibility without code changes. Practitioners define their own detection logic. |

**Out of Scope for Phase 0**:

| Feature | Why Deferred |
|---------|--------------|
| Multi-device correlation | Requires team infrastructure. Single-device triage must be best-in-class first. |
| RBAC and access controls | Enterprise feature. Community tier is single-user. |
| Velociraptor/Binalyze import | Integration requires stable API contracts. Ship core value first. |
| PCAP/NetFlow analysis | Network artifacts are Phase 2 scope. Focus on NTFS mastery. |
| Live triage | Requires different I/O architecture. Disk image triage is the foundation. |

**Phase 0 Success Criteria**:

| Metric | Target | Kill Threshold |
|--------|--------|----------------|
| Triage completion rate | >95% | <80% (tool is unreliable) |
| Time-to-first-answer (P95) | <35 seconds | >60 seconds (not meaningfully faster than alternatives) |
| False positive rate | <5% | >15% (practitioners lose trust) |
| GitHub stars | 200+ in first 90 days | <50 (no community interest) |
| Monthly active users | 100+ by month 6 | <25 (tool is not solving a real problem) |

### Phase 1: Enterprise MVP

**Theme**: "Teams, Trust, and Integrations"

**Objective**: Launch the paid enterprise tier with RBAC, multi-device correlation, Velociraptor/Binalyze import, and live triage capabilities to acquire the first 10 paying enterprise customers.

**Unlocked By**: Phase 0 success criteria met (>95% completion rate, <35s triage, <5% FP rate, 200+ stars)

**In Scope**:

| Feature | Acceptance Criteria | Why Now |
|---------|---------------------|---------|
| RBAC and access controls | Role-based permissions (admin, analyst, viewer) with SSO/SAML integration | Enterprise customers require identity management. James cannot adopt without SSO. |
| Multi-device correlation | Correlate USN journal artifacts across 2+ devices in a single investigation view | MSSPs handle multi-endpoint cases. Single-device triage is insufficient for Sarah's team. |
| Velociraptor import | Import Velociraptor collection results (USN journal, MFT, LogFile artifacts) directly | Velociraptor is the dominant open-source collection tool. Integration is table stakes for enterprise. |
| Binalyze import | Import Binalyze AIR collection packages | Binalyze is growing fast in the MSSP market. Removes friction for Sarah's persona. |
| Live triage | Triage a running system without creating a full disk image | Critical for IR where imaging takes too long. Time-to-first-answer drops from "imaging + 35 seconds" to "35 seconds". |
| Audit logging | Immutable audit trail of all investigator actions for SOC 2 compliance | James cannot adopt without compliance-grade logging. |
| Seat-based licensing | Per-investigator subscription at $99-149/month, self-service and sales-assisted | Revenue model. Must be operational before measuring enterprise customer count. |

**Phase 1 Success Criteria**:

| Metric | Target | Kill Threshold |
|--------|--------|----------------|
| Paying enterprise customers | 10 within 6 months of launch | <3 (value proposition is wrong) |
| Enterprise retention rate | >90% after first billing period | <70% (product is not sticky) |
| MRR | $10K within 6 months | <$3K (pricing or market is wrong) |
| Community active users | 500+ (maintained or growing) | <200 (enterprise pivot killed community) |

### Phase 2: Enterprise Expansion

**Theme**: "Network Meets Disk, Investigations at Scale"

**Objective**: Expand artifact coverage to network forensics (PCAP/NetFlow) and add collaborative investigation workflows to grow to 30 enterprise customers.

**Unlocked By**: Phase 1 success criteria met (10+ enterprise customers, >90% retention)

**In Scope**:

| Feature | Acceptance Criteria | Why Now |
|---------|---------------------|---------|
| PCAP/NetFlow analysis | Parse packet captures and flow data, correlate with NTFS timeline | Enterprise investigations span disk and network. Cross-artifact correlation is the next depth frontier. |
| Collaborative investigation | Multiple investigators on the same case with conflict resolution and real-time sync | Large enterprise teams need collaboration, not file-passing. |
| Advanced reporting | Customizable report templates, executive summary generation, evidence export packages | Enterprise customers need reports tailored to stakeholders (legal, CISO, auditors). |
| API access | RESTful API for integration with SIEM, SOAR, and ticketing systems | Enterprise workflows require programmatic access, not just CLI. |

**Phase 2 Success Criteria**:

| Metric | Target | Kill Threshold |
|--------|--------|----------------|
| Paying enterprise customers | 30 | <15 (expansion is not driving growth) |
| Average seats per customer | 5+ | <2 (not penetrating teams) |
| MRR | $30K | <$15K (unit economics are wrong) |

### Phase 3: Enterprise Platform

**Theme**: "Collection to Conclusion"

**Objective**: Ship a targeted collection agent that enables Security Ronin Katana to manage the full forensic triage lifecycle from evidence collection to report delivery, reaching 50 enterprise customers.

**Unlocked By**: Phase 2 success criteria met (30+ enterprise customers, 5+ avg seats)

**In Scope**:

| Feature | Acceptance Criteria | Why Now |
|---------|---------------------|---------|
| Targeted collection agent | Lightweight agent that collects specific NTFS artifacts from endpoints on demand | Enterprises need evidence collection without full imaging. Reduces time and storage. |
| Collection orchestration | Schedule and manage collections across endpoint fleets | Large enterprises have thousands of endpoints. Manual collection does not scale. |
| Evidence pipeline | End-to-end workflow from collection trigger to triage report delivery | Platform value: the investigator never leaves Katana. |

**Phase 3 Success Criteria**:

| Metric | Target | Kill Threshold |
|--------|--------|----------------|
| Paying enterprise customers | 50 | <30 (platform strategy is not working) |
| MRR | $50K+ | <$25K (insufficient revenue to sustain platform development) |
| Enterprise NPS | >50 | <30 (customers tolerate but do not love the product) |

## 2.2 Explicit Kill List (Never Build)

These features are explicitly out of scope regardless of phase. They represent scope creep, premature optimization, or strategic misalignment with our core beliefs.

### Community Tier Kill List

| Feature | Rationale for Rejection | Revisit When |
|---------|------------------------|--------------|
| **GUI-first application** | Primary users live in terminals. GUI overhead slows iteration, increases maintenance surface, and adds zero value for CLI-native practitioners. The HTML report IS the visual interface. | When paying enterprise customers explicitly request and fund it. |
| **Plugin/extension system** | Plugin architectures introduce untested code paths, security surface, and support burden. Ship one sharp tool, not a platform for other people's code. | Never for community tier. Enterprise tier may offer controlled integrations. |
| **Cloud processing** | Forensic evidence must stay on the investigator's machine. Uploading disk images to cloud servers is a chain-of-custody violation and a security risk. | Never. All processing is local. Enterprise tier may offer on-premise server deployment but never SaaS. |
| **AI/ML classification** | ML models are black boxes. Forensic tools must produce deterministic, reproducible results. "The AI said so" is not admissible in court. | When explainable AI can produce courtroom-defensible reasoning with published accuracy metrics. |
| **Database-first architecture** | Databases add deployment complexity, state management, and migration burden. Forensic triage is a stateless pipeline: evidence in, report out. | Never for community tier. Enterprise tier uses databases for multi-user state. |
| **Memory forensics** | Memory analysis is a separate discipline with separate tools (Volatility). Adding it would dilute focus on NTFS journal forensics. | When NTFS journal triage is best-in-class AND generating enterprise revenue AND a clear product path exists. |
| **Real-time monitoring** | We are a triage tool, not an EDR. Real-time monitoring is a different product category with different architecture requirements. | Never. This is not our market. |
| **Case management** | Case management is a workflow feature, not a forensic feature. Existing tools (TheHive, DFIR-IRIS) do this well. Integration, not replacement. | When enterprise customers demonstrate that integration with existing case management tools is insufficient. |

### Enterprise Tier Kill List

| Feature | Rationale for Rejection | Revisit When |
|---------|------------------------|--------------|
| **Replacing Velociraptor entirely** | Velociraptor is the dominant open-source collection platform. We integrate with it, we do not compete with it. Fighting Velociraptor is fighting our distribution channel. | Never. Partnership over competition. |
| **Full NDR platform** | Network Detection and Response is a separate product category. PCAP/NetFlow analysis in Phase 2 is for investigation correlation, not continuous monitoring. | Never. We correlate network artifacts with disk artifacts. We do not replace Zeek/Suricata. |
| **SaaS/cloud-hosted deployment** | Forensic evidence in cloud environments creates chain-of-custody complications, data sovereignty issues, and compliance complexity. Enterprise deployment is on-premise or customer-controlled infrastructure. | When industry standards for cloud forensic evidence handling are established and adopted by courts. |

## 2.3 Licensing & Ethics

### License Choice

**License**: Apache-2.0

**Rationale**: Apache-2.0 is the gold standard for forensic tools that must be courtroom-defensible. It allows commercial use (enabling our enterprise tier), provides patent protection, requires attribution (brand awareness), and permits modification (community contribution). The license explicitly communicates: "This tool has nothing to hide."

**Iron rule**: No forensic analysis capability is ever gated behind a paid tier. If it affects the accuracy or completeness of forensic findings, it belongs in the open-source core. Enterprise tiers add workflow, integration, and collaboration features.

### Ethical Constraints

| Constraint Type | Specification |
|-----------------|---------------|
| **Prohibited Uses** | Security Ronin Katana must never be marketed or positioned for surveillance, employee monitoring without consent, or any use that bypasses legal authorization for evidence collection. Forensic tools investigate incidents; they do not enable them. |
| **Required Behaviors** | All forensic processing must be deterministic and reproducible. Given the same input, the tool must produce the same output. No randomness, no non-deterministic ML, no "probabilistic" results without explicit confidence intervals. |
| **Data Principles** | Evidence never leaves the investigator's machine unless the investigator explicitly exports it. No telemetry on case content. Opt-in usage analytics only (command frequency, not evidence data). Enterprise audit logs stay on customer infrastructure. |
| **Transparency** | Published precision/recall benchmarks for every release. Known limitations documented. False positive and false negative rates are part of the release notes, not hidden. |
| **Evidence Integrity** | The tool operates in read-only mode on all evidence sources. No modification, no write-back, no side effects on forensic images or artifacts. |

---

# Part 3: Success Measurement

## 3.1 Metrics Dashboard

### North Star (Weekly Review)

```
+---------------------------------------------------------------------+
|  NORTH STAR: Paying Enterprise Customers                            |
|                                                                     |
|  Current: [][][][][][]                 0    Target: 50    Phase: 0  |
|                                                                     |
|  Enterprise tier not yet launched. Tracking community health        |
|  as leading indicator for enterprise readiness.                     |
+---------------------------------------------------------------------+
```

### Input Metrics (Daily Review)

| Metric | Current | Target | Status |
|--------|---------|--------|--------|
| Triage Completion Rate | ~95% | >95% | On Track |
| Time-to-First-Answer (P95) | ~35s | <35s | On Track |
| False Positive Rate | ~5% | <5% | On Track |
| Community Active Users | Pre-launch | 500 | Pre-launch |
| Ghost Recovery Rate | >95% | >95% | On Track |
| Path Resolution | 100% | 100% (zero UNKNOWN) | On Track |

### Health Metrics (Weekly Review)

| Metric | Current | Threshold | Status |
|--------|---------|-----------|--------|
| CLI Error Rate | -- | <2% | Pre-launch |
| Report Generation P95 Latency | -- | <5s | Pre-launch |
| CI Build Pass Rate | >98% | >95% | Healthy |
| Test Suite Pass Rate | 100% | 100% | Healthy |
| Open Critical Bugs (P0/P1) | <5 | <10 | Healthy |
| Triage Precision | 92.3%* | >90% | On Track |
| Triage Recall | 99.7%* | >95% | On Track |

*Benchmarked against Szechuan Sauce CTF dataset.

## 3.2 Validation Gates

Before committing significant resources, validate assumptions:

| Gate | Question | Evidence Required | Decision |
|------|----------|-------------------|----------|
| **Problem** | Do DFIR practitioners actually waste 30-60 min on triage setup? | 10+ practitioner interviews. Conference hallway validation. Community forum analysis showing multi-tool friction. | Proceed (validated) |
| **Solution** | Does 35-second triage actually change practitioner workflows? | Beta users report measurable time savings. Before/after case studies. | Proceed / Pivot |
| **Community** | Will practitioners adopt and recommend an open-source triage tool? | 200+ GitHub stars, 100+ monthly active users within 6 months of launch | Proceed / Pivot |
| **Enterprise** | Will MSSP and enterprise IR teams pay $99-149/seat/month for team features? | 10+ enterprise customers within 6 months of enterprise tier launch | Proceed / Pivot |
| **Scale** | Can we grow beyond early adopters to mainstream enterprise? | 50 enterprise customers, >90% retention, positive unit economics | Proceed / Pivot |

## 3.3 Course Correction Triggers

| Signal | Threshold | Observation Period | Response |
|--------|-----------|-------------------|----------|
| Triage completion rate drops | <80% | 2 consecutive weeks | Stop feature development. Fix reliability. Every failed triage is a practitioner who will not return. |
| False positive rate spikes | >15% on any release | Any release | Hotfix release within 48 hours. FP rate above 15% means practitioners cannot trust the output. |
| Community active users stall | <25 at month 6 | 6 months post-launch | Fundamental problem validation needed. Interview 10 practitioners. Re-evaluate whether we are solving a real problem. |
| Enterprise customers below threshold | <3 at month 6 of enterprise tier | 6 months post-enterprise launch | Re-evaluate enterprise value proposition, pricing, and feature set. Consider pivoting to services model. |
| Enterprise retention drops | <70% | First 2 billing periods | Exit interviews with churned customers. Fix top 3 churn reasons before acquiring more. |
| Performance regression | P95 triage time >45s | Any release | Block release. Bisect CI benchmarks. Revert or fix within 48 hours. |
| Community sentiment shifts negative | Sustained negative feedback | 2 consecutive weeks | Public post-mortem. Root cause fix. Trust repair takes priority over new features. |
| Safety or ethics incident | Any | Immediate | Pause all development. Investigate root cause. Publish post-mortem. Legal review. |

---

# Part 4: MVP Architecture Summary

## 4.1 Agent Topology

> **Note**: Full implementation details are in `ARCHITECTURE_BLUEPRINT.md`. This section provides strategic context. usnjrnl-forensic is a deterministic processing pipeline, not an agent-based system.

```
E01 DISK IMAGE
     |
     v
+------------------+
| Image Parser     |  <- Extracts $UsnJrnl, $MFT, $LogFile from E01
| (EWF decompress, |     MBR/GPT detect, NTFS auto-discover
|  partition detect)|
+------------------+
     |
     +--------+--------+--------+
     |        |        |        |
     v        v        v        v
  USN      MFT     LogFile  Unalloc    <- Parallel artifact parsing
  Parser   Parser  Parser   Carver
     |        |        |        |
     +--------+--------+--------+
              |
              v
+------------------+
| Rewind Engine    |  <- Reverse-chronological path resolution
+------------------+
              |
              v
+------------------+
| QuadLink         |  <- Cross-artifact correlation engine
| Correlator       |     $UsnJrnl + $MFT + $LogFile + $MFTMirr
+------------------+
     |
     v
+------------------+
| Triage Engine    |  <- 21 questions answered with evidence citations
| + Rule Engine    |     YAML-based custom detections
+------------------+
     |
     v
+------------------+
| Output Writers   |  <- CSV, JSONL, SQLite, Body, TLN, XML, HTML
+------------------+
     |
     v
HTML REPORT + STRUCTURED OUTPUT
```

### Agent Specifications (MVP)

| Module | Technology | Timeout | Responsibility |
|--------|-----------|---------|----------------|
| Image Parser | Rust (ewf-rs / libewf FFI) | 10s | Extract NTFS artifacts from E01 container, handle MBR/GPT/NTFS detection |
| USN Journal Parser | Rust (streaming) | 5s | Parse $UsnJrnl:$J records, handle V2/V3/V4 formats, parallel chunk processing |
| MFT Parser | Rust | 5s | Parse $MFT for path resolution, entry/sequence matching, file metadata |
| LogFile Parser | Rust | 3s | Parse $LogFile for transaction correlation and ghost record extraction |
| Unallocated Carver | Rust | 8s | Carve USN journal records and MFT entries from unallocated space |
| Rewind Engine | Rust | 3s | Reverse-chronological path resolution (CyberCX algorithm), zero UNKNOWN paths |
| QuadLink Correlator | Rust | 3s | Cross-reference four artifact sources, timeline merge, ghost detection |
| Triage Engine | Rust | 2s | Evaluate 21 triage questions across 4 tiers against correlated evidence |
| Rule Engine | Rust + YAML | 1s | Apply user-defined YAML detection rules to parsed records |
| Output Writers | Rust + HTML/JS | 2s | Generate all 7 output formats including self-contained interactive HTML report |

### Latency Budget

- **Total**: <35s P95 end-to-end on a standard 40GB E01 image (847K records)
- **Image Parsing + Extraction**: <10s (EWF decompression, NTFS discovery)
- **Artifact Parsing**: <10s (parallelized across 4 parsers via rayon)
- **Path Resolution + Correlation**: <5s (Rewind + QuadLink)
- **Triage + Rules + Output**: <5s
- **Overhead (I/O, memory mapping)**: <5s

## 4.2 Technology Stack (MVP)

| Layer | Choice | Rationale |
|-------|--------|-----------|
| **Language** | Rust (2021 edition) | Memory safety without GC pauses. Zero-cost abstractions for parser performance. Cross-platform compilation. Single static binary distribution. |
| **CLI Framework** | clap v4 (derive) | Industry standard for Rust CLIs. Typed argument parsing, auto-generated help, shell completions. |
| **Image Format** | ewf-rs / libewf (FFI, optional feature) | E01 is the dominant forensic image format. Optional feature flag keeps the core dependency-free. |
| **Parallelism** | rayon | Work-stealing parallel iterators for chunk-based USN parsing. Automatic CPU core utilization. |
| **Serialization** | serde, serde_json, quick-xml | Unified serialization framework across all 7 output formats. |
| **Database** | rusqlite (SQLite) | Embedded database for indexed output. No server dependency. Portable single-file output. |
| **Testing** | Rust built-in + integration tests | Unit tests per module. Integration tests against pinned forensic images. Precision/recall benchmarks per release. |
| **Distribution** | GitHub Releases (binary) + crates.io + Homebrew | Binary releases for practitioners. crates.io for Rust ecosystem. Homebrew for macOS convenience. |

### Deferred Technology (Phase 1+)

| Technology | Phase | Why Deferred |
|------------|-------|--------------|
| PostgreSQL / SQLite (server) | Phase 1 | Multi-user state management for enterprise tier. Not needed for single-user CLI. |
| SSO/SAML (Keycloak or Auth0) | Phase 1 | Enterprise identity management. Not needed for community tier. |
| REST API framework (Axum) | Phase 2 | Programmatic access for SIEM/SOAR integration. CLI-first in Phase 0. |
| PCAP parsing (pcap-rs) | Phase 2 | Network artifact analysis. NTFS mastery comes first. |
| Collection agent | Phase 3 | Targeted endpoint collection. Requires established enterprise customer base. |

## 4.3 Technology Constraints

| Constraint | Specification | Rationale |
|------------|---------------|-----------|
| **No network calls during triage** | CLI must function entirely offline. Zero network dependencies during evidence processing. | Forensic workstations are often air-gapped or in restricted networks at incident scenes. |
| **Memory-mapped I/O** | Use mmap for large file parsing. Do not load entire E01 images into RAM. | Investigators use laptops with 16-32GB RAM. A 256GB E01 must parse without OOM. |
| **Deterministic output** | Same input always produces byte-identical output. No timestamps, randomness, or non-deterministic ordering in reports. | Courtroom defensibility requires reproducibility. Two experts running the same evidence must get the same report. |
| **Single binary distribution** | Community CLI ships as a single static binary. No runtime dependencies, no installers, no package managers required. | DFIR practitioners need to drop a tool on a forensic workstation and run it immediately. |
| **Cross-platform** | Must build and pass tests on Linux, macOS, and Windows. All three are first-class targets. | Practitioners work across all three platforms. No platform can be second-class. |
| **Read-only evidence access** | Tool never writes to or modifies evidence sources. All I/O is read-only. | Forensic integrity. Evidence must be provably unmodified after analysis. |

---

# Part 5: Operations

## 5.1 Launch Plan

### Phase 0 Launch (Community Edition)

**Launch Type**: Open Source GA (General Availability)

**Target Users**: 200 DFIR practitioners sourced from conference attendees, DFIR community forums (r/computerforensics, DFIR Discord), and direct practitioner outreach.

**Launch Sequence**:

| Week | Action |
|------|--------|
| -4 | Finalize v1.0 feature set. Complete precision/recall benchmarks. Write documentation. |
| -2 | Create demo case walkthrough video (Szechuan Sauce CTF). Prepare conference talk abstract. Seed discussions in DFIR communities. |
| -1 | Publish benchmark results. Open GitHub repository. Pre-announce on social media and DFIR channels. |
| 0 | **Launch**: GitHub release with binaries for Linux, macOS, Windows. Blog post: "35-Second Forensic Triage: How Security Ronin Katana Answers 21 IR Questions." |
| +1 | Monitor GitHub issues. Respond to every issue within 24 hours. Track download and star metrics daily. |
| +2 | Publish first case study (anonymized real-world use). Engage community contributors. |
| +4 | Review Phase 0 metrics against success criteria. First community retrospective. |
| +8 | Conference circuit begins: SANS DFIR Summit, OSDFCon, BSides. Live demos and hallway conversations. |
| +12 | Phase 0 success criteria evaluation. Go/no-go decision for Phase 1 (Enterprise MVP). |

### Phase 1 Launch (Enterprise Tier)

**Launch Type**: Closed Beta with 5 design partner organizations, then GA

**Target Users**: 10 MSSP and enterprise IR teams recruited from community power users and conference contacts.

**Launch Sequence**:

| Week | Action |
|------|--------|
| -4 | Recruit 5 design partner organizations (MSSPs and enterprise IR teams). Define enterprise feature requirements. |
| -2 | Deploy enterprise features to design partners. Collect feedback on RBAC, multi-device, import workflows. |
| 0 | **Enterprise GA**: Pricing page live. Self-service signup. Sales-assisted onboarding for large teams. |
| +4 | First enterprise customer retention check. Iterate on top 3 friction points. |
| +12 | Phase 1 success criteria evaluation (10 customers, >90% retention, $10K MRR). |
| +24 | Go/no-go for Phase 2. |

## 5.2 Risk Monitoring

### Safety Risks

| Risk | Monitoring | Threshold | Action |
|------|------------|-----------|--------|
| False positives cause wrongful accusations | Precision/recall benchmarks on every release. Community-reported FP tracking. | Any FP rate >10% on triage questions | Hotfix release. Publish corrected benchmarks. Notify users who ran affected version. |
| Evidence integrity compromise | Hash verification on all parsed artifacts. Read-only access enforcement. Checksums in report output. | Any case where output cannot be reproduced from same input | Immediate investigation. Security advisory if tool modified evidence. |
| Misuse for unauthorized surveillance | License terms prohibit unauthorized use. Community reporting mechanism. | Any reported case of misuse | Legal review. Update license terms if needed. Public statement on intended use. |

### Technical Risks

| Risk | Monitoring | Threshold | Action |
|------|------------|-----------|--------|
| Performance regression | CI/CD benchmark suite on every commit against reference datasets | P95 triage time >45s (28% regression) | Block release. Profile and fix before merging. |
| Parsing accuracy regression | CI/CD precision/recall suite against labeled ground-truth | Any P/R metric drops >2% from previous release | Block release. Root cause analysis. Fix before merging. |
| Cross-platform compatibility | CI builds and tests on Linux, macOS, Windows | Any platform fails tests | Fix before release. All three platforms are first-class. |
| Memory safety | Rust's borrow checker + cargo-fuzz on all parsers | Any crash or undefined behavior | Critical severity. Fix immediately. |
| E01 format incompatibility | Expanding integration test corpus from FTK, EnCase, X-Ways, dc3dd | User report of image that fails to open | Add to test corpus. Fix parser. Regression test. |
| Open-source sustainability | Development velocity and contributor engagement | <1 release/month for 3 consecutive months | Evaluate resource allocation. Enterprise revenue should fund sustained development. |

---

# Part 6: Document Hierarchy

This document sits at the top of the strategic document hierarchy for Security Ronin Katana:

```
NORTHSTAR.md (this document)
     |
     +-- BRAND_GUIDELINES.md          <- Brand identity, voice, beliefs, kill list
     |     Must be consistent with positioning in Section 1.3.
     |
     +-- COMPETITIVE_LANDSCAPE.md     <- Market positioning and competitor analysis
     |     Must validate differentiation claims in Section 1.3.
     |
     +-- NORTHSTAR_EXTRACT.md         <- Axioms and constraints derived from this document
     |     Distilled design rules from North Star metric, personas, and phases.
     |
     +-- ARCHITECTURE_BLUEPRINT.md    <- System architecture implementing this spec
     |     Details the processing pipeline from Section 4.1.
     |     Tech stack decisions must align with constraints in Section 4.3.
     |
     +-- AGENT_PROMPTS.md             <- Module specifications for each component
     |     Maps to the 10 modules defined in Section 4.1.
     |
     +-- SECURITY_ARCHITECTURE.md     <- Threat model and security controls
           Must enforce ethical constraints from Section 2.3.
```

### Document Update Protocol

| Trigger | Action |
|---------|--------|
| Phase boundary crossed | Review all documents for consistency. Update phase status. |
| Kill list item revisited | Update Section 2.2. Cross-reference BRAND_GUIDELINES kill list. |
| New triage question added | Update triage question list. Add precision/recall benchmark. |
| Metric target changed | Update Sections 1.1, 1.2, and 3.1. Document rationale in ADR. |
| Pricing change | Update Section 2.3. Verify iron rule compliance. |
| Persona insight discovered | Update Section 1.4. Propagate to AGENT_PROMPTS for relevant modules. |

**Governance**: This document is reviewed monthly and updated when strategic decisions change. All Tier 2 and Tier 3 documents must align with the decisions recorded here. When a feature request or design choice conflicts with this document, this document wins.

---

## Appendix A: Glossary

| Term | Definition |
|------|------------|
| **E01** | Expert Witness Format. The standard forensic disk image container format, supporting compression and integrity verification. |
| **$UsnJrnl** | NTFS Update Sequence Number Journal. Records file system changes (creates, deletes, renames, modifications). |
| **$MFT** | NTFS Master File Table. Contains metadata for every file and directory on the volume. |
| **$LogFile** | NTFS transaction log. Records file system transactions for crash recovery. Contains embedded USN records. |
| **$MFTMirr** | Mirror copy of the first 4 MFT entries. Used for integrity checking to detect MFT tampering. |
| **Ghost Recovery** | Security Ronin Katana's technique for recovering deleted USN journal records from unallocated space and $LogFile transaction data. |
| **Rewind Algorithm** | Path reconstruction technique (originated by CyberCX) that processes USN records in reverse chronological order to resolve file paths even when MFT entries have been reallocated. |
| **QuadLink Correlation** | Cross-referencing four artifact sources ($UsnJrnl + $MFT + $LogFile + $MFTMirr) to build the most complete forensic timeline. |
| **Triage Questions** | The 21 investigative questions that Katana answers automatically from parsed evidence, organized into 4 tiers matching incident commander priorities. |
| **FP Rate** | False Positive Rate. The percentage of triage answers that incorrectly flag benign activity as suspicious. |
| **MSSP** | Managed Security Service Provider. A company that provides outsourced security operations to clients. |
| **RBAC** | Role-Based Access Control. Restricting system access based on user roles (admin, analyst, viewer). |
| **SOC 2** | Service Organization Control Type 2. A compliance framework covering security, availability, and confidentiality. |
| **Open Core** | Business model where core forensic functionality is open-source (Apache-2.0) and enterprise features (team, compliance, integrations) are paid. |
| **SOAR** | Security Orchestration, Automation, and Response. Platforms that automate incident response workflows. |
| **DFIR** | Digital Forensics and Incident Response. The discipline combining forensic analysis with incident response operations. |
| **Timestomping** | Anti-forensic technique where timestamps are modified to hide evidence. Detected by comparing $STANDARD_INFORMATION and $FILE_NAME timestamps. |

---

**End of North Star Specification**

*This document should be reviewed monthly and updated when strategic decisions change.*

*Generated by North Star Advisor v1.6.0 | Security Ronin*
