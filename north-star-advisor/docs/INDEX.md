# Documentation Index: usnjrnl-forensic

> 35-second NTFS forensic triage -- from disk image to incident response answers.

**Version:** 1.0
**Date:** 2026-03-08
**Status:** Active
**Phase:** 13 of 13 (Final)

---

## How to Use This Documentation

This index is the master reference for all usnjrnl-forensic strategic and implementation documentation. The 22 documents are organized into three tiers by function.

**Start here:**

1. **[ai-context.yml](../ai-context.yml)** -- Progressive strategic context file. This is the single source of truth that accumulates decisions from every generation phase. Read this first to understand the project's current state.
2. **[research/summary.md](../research/summary.md)** -- Research findings that informed strategic decisions.
3. **This index** -- Then navigate to specific documents below.

---

## Document Hierarchy

```
usnjrnl-forensic/north-star-advisor/
│
├── ai-context.yml                          ← START HERE
├── research/summary.md                     ← Research findings
│
├── docs/
│   │
│   │── TIER 1: STRATEGIC AUTHORITY
│   │   ├── BRAND_GUIDELINES.md             ← Brand identity & voice
│   │   ├── NORTHSTAR.md                    ← North Star metric & personas
│   │   ├── COMPETITIVE_LANDSCAPE.md        ← Market positioning
│   │   ├── NORTHSTAR_EXTRACT.md            ← Axioms & constraints
│   │   ├── STRATEGIC_RECOMMENDATION.md     ← Go-to-market strategy
│   │   └── ACTION_ROADMAP.md               ← 30/60/90-day execution plan
│   │
│   │── TIER 2: IMPLEMENTATION
│   │   ├── ARCHITECTURE_BLUEPRINT.md       ← System architecture overview
│   │   ├── architecture/
│   │   │   ├── AGENT_PROMPTS.md            ← 11 module specifications
│   │   │   ├── PIPELINE_ORCHESTRATION.md   ← 9-stage pipeline
│   │   │   ├── RESILIENCE_PATTERNS.md      ← Error recovery
│   │   │   ├── IMPLEMENTATION_SCAFFOLD.md  ← Project structure
│   │   │   ├── OBSERVABILITY.md            ← Logging & benchmarks
│   │   │   ├── TESTING_STRATEGY.md         ← Test pyramid & fuzz testing
│   │   │   └── HANDOFF_PROTOCOL.md         ← Data contracts
│   │   ├── SECURITY_ARCHITECTURE.md        ← STRIDE threat model
│   │   ├── ADR.md                          ← Architecture decisions
│   │   └── POST_DEPLOYMENT.md              ← Release & distribution
│   │
│   │── TIER 3: SUPPORTING
│   │   ├── design/
│   │   │   ├── USER_JOURNEYS.md            ← 5 CLI user journeys
│   │   │   ├── UI_DESIGN_SYSTEM.md         ← CLI + HTML design system
│   │   │   ├── ACCESSIBILITY.md            ← WCAG AA & CLI accessibility
│   │   │   └── WIREFRAMES.md               ← ASCII wireframes
│   │
│   └── INDEX.md                            ← YOU ARE HERE
```

---

## Quick Reference

| # | Document | Tier | Purpose | When to Use |
|---|----------|------|---------|-------------|
| 1 | [BRAND_GUIDELINES.md](./BRAND_GUIDELINES.md) | 1 | Brand identity, voice, 5 beliefs, kill list, 3 pillars | Writing copy, making product naming decisions, evaluating feature requests against brand values |
| 2 | [NORTHSTAR.md](./NORTHSTAR.md) | 1 | North Star metric (Weekly Active Cases Triaged), personas, success phases | Prioritizing features, measuring progress, understanding target users |
| 3 | [COMPETITIVE_LANDSCAPE.md](./COMPETITIVE_LANDSCAPE.md) | 1 | 5 direct competitors, positioning matrix, market shifts | Evaluating differentiation, identifying gaps, competitive positioning |
| 4 | [NORTHSTAR_EXTRACT.md](./NORTHSTAR_EXTRACT.md) | 1 | 5 axioms, non-goals, constraints, design patterns | Resolving design debates, checking alignment with core principles |
| 5 | [STRATEGIC_RECOMMENDATION.md](./STRATEGIC_RECOMMENDATION.md) | 1 | 3 strategic paths, recommendation: Conference Circuit Community Builder | Go-to-market decisions, resource allocation, partnership strategy |
| 6 | [ACTION_ROADMAP.md](./ACTION_ROADMAP.md) | 1 | 30/60/90-day plan, focus areas, avoid list | Sprint planning, tracking milestones, deciding what to build next |
| 7 | [ARCHITECTURE_BLUEPRINT.md](./ARCHITECTURE_BLUEPRINT.md) | 2 | Memory-Mapped I/O Pipeline, 14 modules, 35s performance budget | Understanding system design, onboarding new contributors |
| 8 | [architecture/AGENT_PROMPTS.md](./architecture/AGENT_PROMPTS.md) | 2 | 11 pipeline module specifications with input/output contracts | Implementing or modifying individual pipeline modules |
| 9 | [architecture/PIPELINE_ORCHESTRATION.md](./architecture/PIPELINE_ORCHESTRATION.md) | 2 | 9-stage pipeline execution, degradation model | Understanding data flow, debugging pipeline failures |
| 10 | [architecture/RESILIENCE_PATTERNS.md](./architecture/RESILIENCE_PATTERNS.md) | 2 | Error recovery, fallback chains, graceful degradation | Handling edge cases, improving reliability |
| 11 | [architecture/IMPLEMENTATION_SCAFFOLD.md](./architecture/IMPLEMENTATION_SCAFFOLD.md) | 2 | Project structure, build guide, module layout | Setting up development environment, adding new modules |
| 12 | [architecture/OBSERVABILITY.md](./architecture/OBSERVABILITY.md) | 2 | Logging, audit trail, performance benchmarks | Adding instrumentation, debugging performance issues |
| 13 | [architecture/TESTING_STRATEGY.md](./architecture/TESTING_STRATEGY.md) | 2 | Test pyramid, fuzz testing, golden datasets | Writing tests, setting up CI, validating correctness |
| 14 | [architecture/HANDOFF_PROTOCOL.md](./architecture/HANDOFF_PROTOCOL.md) | 2 | Internal and external data contracts between modules | Defining module boundaries, API design |
| 15 | [SECURITY_ARCHITECTURE.md](./SECURITY_ARCHITECTURE.md) | 2 | STRIDE threat model, 4 trust boundaries, Daubert compliance | Security review, evidence handling, legal compliance |
| 16 | [ADR.md](./ADR.md) | 2 | 10 architecture decision records with context and rationale | Understanding why decisions were made, revisiting past choices |
| 17 | [POST_DEPLOYMENT.md](./POST_DEPLOYMENT.md) | 2 | Release process, versioning, distribution, community support | Preparing releases, setting up distribution channels |
| 18 | [design/USER_JOURNEYS.md](./design/USER_JOURNEYS.md) | 3 | 5 CLI-centric user journeys from install to report | UX decisions, identifying friction points, writing tutorials |
| 19 | [design/UI_DESIGN_SYSTEM.md](./design/UI_DESIGN_SYSTEM.md) | 3 | CLI output formatting + HTML triage report design system | Implementing CLI output, styling HTML reports |
| 20 | [design/ACCESSIBILITY.md](./design/ACCESSIBILITY.md) | 3 | WCAG AA compliance, CLI accessibility, screen reader support | Ensuring inclusive design, accessibility audits |
| 21 | [design/WIREFRAMES.md](./design/WIREFRAMES.md) | 3 | ASCII wireframes for CLI interface and HTML report layout | Visual reference during implementation |
| 22 | [INDEX.md](./INDEX.md) | -- | This document: master index and navigation guide | Finding any document, understanding documentation structure |

---

## Current State

All documents were generated during the North Star Advisor process on 2026-03-08.

| # | Document | Status | Last Updated | Phase |
|---|----------|--------|--------------|-------|
| 1 | BRAND_GUIDELINES.md | Active | 2026-03-08 | Phase 1 |
| 2 | NORTHSTAR.md | Active | 2026-03-08 | Phase 2 |
| 3 | COMPETITIVE_LANDSCAPE.md | Active | 2026-03-08 | Phase 3 |
| 4 | NORTHSTAR_EXTRACT.md | Active | 2026-03-08 | Phase 4 |
| 5 | STRATEGIC_RECOMMENDATION.md | Active | 2026-03-08 | Phase 11 |
| 6 | ACTION_ROADMAP.md | Active | 2026-03-08 | Phase 12 |
| 7 | ARCHITECTURE_BLUEPRINT.md | Active | 2026-03-08 | Phase 6 |
| 8 | architecture/AGENT_PROMPTS.md | Active | 2026-03-08 | Phase 7 |
| 9 | architecture/PIPELINE_ORCHESTRATION.md | Active | 2026-03-08 | Phase 7d |
| 10 | architecture/RESILIENCE_PATTERNS.md | Active | 2026-03-08 | Phase 7d |
| 11 | architecture/IMPLEMENTATION_SCAFFOLD.md | Active | 2026-03-08 | Phase 7d |
| 12 | architecture/OBSERVABILITY.md | Active | 2026-03-08 | Phase 7d |
| 13 | architecture/TESTING_STRATEGY.md | Active | 2026-03-08 | Phase 7d |
| 14 | architecture/HANDOFF_PROTOCOL.md | Active | 2026-03-08 | Phase 7d |
| 15 | SECURITY_ARCHITECTURE.md | Active | 2026-03-08 | Phase 8 |
| 16 | ADR.md | Active | 2026-03-08 | Phase 9 |
| 17 | POST_DEPLOYMENT.md | Active | 2026-03-08 | Phase 10 |
| 18 | design/USER_JOURNEYS.md | Active | 2026-03-08 | Phase 5a |
| 19 | design/UI_DESIGN_SYSTEM.md | Active | 2026-03-08 | Phase 5b |
| 20 | design/ACCESSIBILITY.md | Active | 2026-03-08 | Phase 5c |
| 21 | design/WIREFRAMES.md | Active | 2026-03-08 | Phase 5d |
| 22 | INDEX.md | Active | 2026-03-08 | Phase 13 |

---

## Document Dependencies

The generation dependency tree shows how documents build on each other. Later documents cross-reference earlier ones.

```
Phase 1:  BRAND_GUIDELINES.md
              │
Phase 2:  NORTHSTAR.md
              │
Phase 3:  COMPETITIVE_LANDSCAPE.md
              │
Phase 4:  NORTHSTAR_EXTRACT.md
              │
          ┌───┴───────────────────────────────┐
Phase 5:  │ design/                           │
          │   ├── USER_JOURNEYS.md      (5a)  │
          │   ├── UI_DESIGN_SYSTEM.md   (5b)  │
          │   ├── ACCESSIBILITY.md      (5c)  │
          │   └── WIREFRAMES.md         (5d)  │
          └───┬───────────────────────────────┘
              │
Phase 6:  ARCHITECTURE_BLUEPRINT.md
              │
          ┌───┴───────────────────────────────────────┐
Phase 7:  │ architecture/                              │
          │   ├── AGENT_PROMPTS.md              (7)    │
          │   ├── PIPELINE_ORCHESTRATION.md     (7d)   │
          │   ├── RESILIENCE_PATTERNS.md        (7d)   │
          │   ├── IMPLEMENTATION_SCAFFOLD.md    (7d)   │
          │   ├── OBSERVABILITY.md              (7d)   │
          │   ├── TESTING_STRATEGY.md           (7d)   │
          │   └── HANDOFF_PROTOCOL.md           (7d)   │
          └───┬───────────────────────────────────────┘
              │
Phase 8:  SECURITY_ARCHITECTURE.md
              │
Phase 9:  ADR.md
              │
Phase 10: POST_DEPLOYMENT.md
              │
Phase 11: STRATEGIC_RECOMMENDATION.md
              │
Phase 12: ACTION_ROADMAP.md
              │
Phase 13: INDEX.md  ← YOU ARE HERE
```

### Cross-Reference Matrix

Documents frequently reference each other. Key cross-reference relationships:

| Document | References |
|----------|------------|
| NORTHSTAR.md | BRAND_GUIDELINES.md |
| COMPETITIVE_LANDSCAPE.md | BRAND_GUIDELINES.md, NORTHSTAR.md |
| NORTHSTAR_EXTRACT.md | NORTHSTAR.md, BRAND_GUIDELINES.md |
| ARCHITECTURE_BLUEPRINT.md | NORTHSTAR.md, NORTHSTAR_EXTRACT.md, design/* |
| architecture/* | ARCHITECTURE_BLUEPRINT.md, NORTHSTAR_EXTRACT.md |
| SECURITY_ARCHITECTURE.md | ARCHITECTURE_BLUEPRINT.md, architecture/* |
| ADR.md | All Tier 1 and Tier 2 documents |
| POST_DEPLOYMENT.md | ARCHITECTURE_BLUEPRINT.md, TESTING_STRATEGY.md |
| STRATEGIC_RECOMMENDATION.md | COMPETITIVE_LANDSCAPE.md, NORTHSTAR.md, BRAND_GUIDELINES.md |
| ACTION_ROADMAP.md | STRATEGIC_RECOMMENDATION.md, POST_DEPLOYMENT.md |

---

## Tier Descriptions

### Tier 1: Strategic Authority

These documents define **what** usnjrnl-forensic is, **who** it serves, and **why** it exists. They are the source of truth for all product decisions. When a feature request or design choice conflicts with Tier 1 documents, Tier 1 wins.

- **BRAND_GUIDELINES.md** -- The identity foundation. Defines the product name, positioning statement, 5 core beliefs, the kill list (what we will never build), voice and tone, and the three pillars: Speed, Depth, Trust.
- **NORTHSTAR.md** -- The measurement framework. Defines "Weekly Active Cases Triaged" as the single metric that matters, three target personas (Solo DFIR Consultant, MSSP Analyst, Enterprise IR Lead), and progressive success phases.
- **COMPETITIVE_LANDSCAPE.md** -- The market context. Maps 5 direct competitors (MFTECmd, X-Ways, EnCase, Autopsy, Magnet AXIOM), identifies positioning gaps, and tracks market shifts.
- **NORTHSTAR_EXTRACT.md** -- The design constitution. Distills 5 axioms, explicit non-goals, resource constraints, and design patterns that govern implementation decisions.
- **STRATEGIC_RECOMMENDATION.md** -- The go-to-market decision. Evaluates 3 strategic paths and recommends "Conference Circuit Community Builder" based on weighted scoring across market fit, resource requirements, and risk.
- **ACTION_ROADMAP.md** -- The execution plan. Translates strategy into a concrete 30/60/90-day plan with specific deliverables, focus areas, and an explicit avoid list.

### Tier 2: Implementation

These documents define **how** usnjrnl-forensic is built. They translate strategic decisions into technical specifications.

- **ARCHITECTURE_BLUEPRINT.md** -- The system overview. Defines the Memory-Mapped I/O Pipeline architecture with 14 modules operating within a 35-second performance budget.
- **architecture/** -- Seven deep-dive specifications covering module contracts, pipeline execution, error recovery, project structure, observability, testing, and data handoff protocols.
- **SECURITY_ARCHITECTURE.md** -- The trust framework. STRIDE threat model across 4 trust boundaries, evidence integrity guarantees, and Daubert compliance requirements.
- **ADR.md** -- The decision log. 10 architecture decision records capturing the context, options considered, and rationale for key technical choices.
- **POST_DEPLOYMENT.md** -- The release playbook. Versioning strategy, distribution channels (crates.io, GitHub releases, Homebrew), and community support model.

### Tier 3: Supporting

These documents define the **experience** layer -- how users interact with usnjrnl-forensic.

- **design/USER_JOURNEYS.md** -- 5 end-to-end CLI user journeys from installation through report generation.
- **design/UI_DESIGN_SYSTEM.md** -- Design system for both CLI terminal output and the HTML triage report.
- **design/ACCESSIBILITY.md** -- WCAG AA compliance plan, CLI accessibility patterns, screen reader compatibility.
- **design/WIREFRAMES.md** -- ASCII wireframes for CLI interface layouts and HTML report structure.

---

## Context Files

Beyond the 22 documents, two additional files provide essential context:

| File | Purpose |
|------|---------|
| [ai-context.yml](../ai-context.yml) | Progressive strategic context that accumulates decisions from all 13 generation phases. This is the single-file summary of the entire documentation set. Start here for a quick overview. |
| [research/summary.md](../research/summary.md) | Research findings on the DFIR tooling market, practitioner workflows, and competitive dynamics that informed strategic decisions. |

---

## Maintenance

- **Review cycle:** Documents should be reviewed when the product reaches a new success phase (as defined in NORTHSTAR.md).
- **Update process:** When updating a Tier 1 document, review all Tier 2 documents that cross-reference it for consistency.
- **ai-context.yml:** Must be updated whenever any document changes to keep the progressive context current.
- **This index:** Update the Current State table whenever documents are modified.
