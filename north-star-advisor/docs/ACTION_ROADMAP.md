# usnjrnl-forensic: Action Roadmap

> **Tier**: 1 -- Strategic Authority
> **Parent**: [STRATEGIC_RECOMMENDATION.md](STRATEGIC_RECOMMENDATION.md)
> **Created**: 2026-03-09
> **Status**: Active
> **Generation Step**: 12 of 13 -- Requires STRATEGIC_RECOMMENDATION (Step 11)

## Document Purpose

This document converts the strategic recommendation into a sequenced, time-bound execution plan for the solo founder. Every action has a specific deliverable, a due date relative to Day 1, and a measurable outcome. The roadmap covers the first 90 days of executing the "Conference Circuit Community Builder" strategy.

**Day 1 Definition**: The day you start executing this roadmap. Write the date here when you begin: ___________

---

# Part 1: Strategic Context

## North Star Reminder

| Element | Value |
|---------|-------|
| **North Star Metric** | Weekly Active Cases Triaged |
| **Definition** | Unique forensic cases where usnjrnl-forensic answered at least one triage question in the past 7 days |
| **Current Phase** | Phase 1 -- Rapid Triage (MVP) |
| **Success Target** | First 50 paying customers generating $5,000 MRR |
| **Timeline** | 12-18 months |
| **Strategic Path** | Conference Circuit Community Builder (score: 71/100) |

## Strategic Moves (Ranked by Impact)

1. **KAPE Module publication** -- Get usnjrnl-forensic into the hands of 500+ KAPE users in the first quarter by publishing an official module to the KapeFiles repository.
2. **Benchmark suite publication** -- Establish credibility by publishing reproducible precision/recall benchmarks within 3 months. No other NTFS triage tool publishes Daubert-compliant accuracy metrics.
3. **Conference circuit debut** -- Submit CFPs and present at 2-3 DFIR conferences within 6 months. This is how practitioners discover tools.
4. **DFIR community presence** -- Become a known, helpful presence in DFIR Discord and Slack channels. Answer questions. Share technical insights. Build trust before selling.
5. **Enterprise feature MVP** -- Ship the paid tier ($99/month) by month 6. First 10 paying customers by month 9.

## Current Product State

- v0.6.0, Apache-2.0 licensed, Rust CLI
- 12 IR triage questions, 7 output formats (CSV, JSON, SQLite, XML, TLN, Body, HTML)
- QuadLink correlation, Rewind path reconstruction, ghost record recovery
- HTML report with Story and Explore tabs
- 35-second E01-to-answers pipeline proven on Szechuan Sauce CTF (55,809 records)
- Zero revenue, zero paying customers

## Guiding Axioms

These resolve every priority conflict during execution:

1. **Forensic Integrity > Feature Velocity** -- Never ship a feature that compromises evidence accuracy.
2. **Speed-to-Answers > Breadth of Artifacts** -- The 35-second ceiling is sacred.
3. **Deleted Evidence > Convenience** -- Ghost recovery and unallocated carving are the differentiator.
4. **CLI Composability > Integrated Experience** -- Pipes and scripts beat dashboards.
5. **Open Source Trust > Competitive Moat** -- Apache-2.0 is non-negotiable. Trust drives adoption.

---

# Part 2: The Next 30 Days

**Theme: "Establish Presence, Prove Value"**

The first 30 days are about making usnjrnl-forensic visible and credible in the DFIR community. No enterprise features. No monetization. Pure presence and proof.

## Focus Area 1: KAPE Module and Integration Pipeline

**Goal**: Get usnjrnl-forensic running inside KAPE workflows so existing DFIR practitioners can adopt it with zero friction.

| Action | Owner | Due | Deliverable | Success Metric |
|--------|-------|-----|-------------|----------------|
| Draft KAPE Module YAML configuration | Solo founder | Day 1-3 | `KapeFiles/Modules/usnjrnl-forensic.mkape` | Valid YAML that runs usnjrnl-forensic on KAPE-collected `$UsnJrnl:$J` and `$MFT` |
| Test KAPE Module against 3 reference images | Solo founder | Day 4-7 | Test results document | Module produces correct HTML report and CSV output for all 3 images |
| Submit KAPE Module PR to KapeFiles repository | Solo founder | Day 7-10 | Open PR on GitHub | PR passes KapeFiles CI and receives maintainer review |
| Draft Velociraptor VQL artifact (collection + analysis) | Solo founder | Day 14-21 | `usnjrnl-forensic.vql` artifact | Artifact collects `$UsnJrnl:$J`, `$MFT`, runs usnjrnl-forensic, returns triage JSON |
| Create installation script for KAPE/Velociraptor users | Solo founder | Day 7-10 | `install.sh` / `install.ps1` | One-command install that downloads correct binary for platform |

**Why this matters**: KAPE has thousands of active users. Getting into the KapeFiles repository is the single highest-leverage action for adoption. Velociraptor extends reach to enterprise SOCs.

## Focus Area 2: Benchmark Suite and Credibility

**Goal**: Publish reproducible accuracy benchmarks that no competitor can match. This is the foundation for conference talks and enterprise sales.

| Action | Owner | Due | Deliverable | Success Metric |
|--------|-------|-----|-------------|----------------|
| Define benchmark methodology (precision, recall, F1 against ground truth) | Solo founder | Day 1-5 | `docs/BENCHMARK_METHODOLOGY.md` on GitHub | Methodology is Daubert-compliant and references NIST/CFTT standards |
| Select 3-5 reference forensic images with known ground truth | Solo founder | Day 5-10 | List of images with download links and expected results | At least 3 publicly available images with documented file activity |
| Run usnjrnl-forensic against all reference images, record results | Solo founder | Day 10-15 | `benchmarks/` directory with results per image | Results include precision, recall, F1 for each triage question |
| Compare results against MFTECmd + manual analysis baseline | Solo founder | Day 15-20 | Comparison table in benchmark doc | Quantified delta showing usnjrnl-forensic advantages (speed, ghost recovery, automation) |
| Publish benchmark methodology and initial results to GitHub | Solo founder | Day 20-25 | Public repository content | Published and linked from README |

**Why this matters**: DFIR practitioners trust numbers, not marketing. Publishing benchmarks first establishes usnjrnl-forensic as the tool that proves its claims. No competitor currently publishes precision/recall metrics.

## Focus Area 3: Community Presence and First Content

**Goal**: Become a recognized, helpful presence in the DFIR community. Start with giving, not selling.

| Action | Owner | Due | Deliverable | Success Metric |
|--------|-------|-----|-------------|----------------|
| Join DFIR Discord server and introduce yourself with technical post | Solo founder | Day 1-2 | Introduction post with Szechuan Sauce CTF walkthrough | Post receives engagement (replies, reactions) |
| Join relevant DFIR Slack workspaces (SANS DFIR, Magnet User Forum, etc.) | Solo founder | Day 1-3 | Active membership in 2-3 workspaces | Profile set up, lurking to understand conversation patterns |
| Write first technical blog post: "Ghost Records -- Recovering Evidence Attackers Thought They Deleted" | Solo founder | Day 7-14 | Published blog post (GitHub Pages, Medium, or personal site) | Post includes reproducible analysis with downloadable image |
| Share blog post in DFIR Discord, Twitter/X, LinkedIn, and Mastodon | Solo founder | Day 14-15 | Social media posts | Track clicks and engagement |
| Answer 5+ community questions about USN Journal analysis (genuinely helpful, not promotional) | Solo founder | Day 1-30 | Community contributions | Establish reputation as subject matter expert |
| Submit CFP to next available DFIR conference (BSides, SANS DFIR Summit, OSDFCon, etc.) | Solo founder | Day 14-21 | Submitted CFP abstract | Abstract focuses on ghost record recovery technique, not tool promotion |
| Create a short (2-3 min) demo video showing E01-to-answers pipeline | Solo founder | Day 21-28 | Published video (YouTube, linked from README) | Video shows real analysis, not slideware |

**Why this matters**: The DFIR community is small and trust-driven. Practitioners recommend tools they've seen demonstrated by someone who understands their work. Helping first, promoting second.

---

# Part 3: What to Avoid (Next 30 Days)

| Avoid | Rationale |
|-------|-----------|
| **Building a GUI** | HTML report already serves as the visual interface. A GUI would consume months of solo developer time for marginal adoption gain. CLI-first is a deliberate brand choice that resonates with DFIR practitioners. |
| **Adding memory forensics** | Out of scope for the NTFS triage niche. Integration with Volatility output is a future option, but reimplementation is a trap. |
| **Enterprise feature development** | Premature. No paying customers to validate feature requirements. Building enterprise features now means guessing what to charge for. |
| **Pursuing law enforcement market** | Government procurement cycles are 12-18 months. Compliance requirements (FedRAMP, CJIS) consume enormous solo developer time. Start with consultants and MSSPs. |
| **Chasing GitHub stars** | Vanity metric. A tool with 50 stars and 50 paying customers beats a tool with 5,000 stars and zero revenue. Focus on cases triaged, not stars collected. |
| **Optimizing the 35-second pipeline further** | 35 seconds is already excellent. Shaving it to 20 seconds yields no meaningful adoption difference. Spend engineering time on accuracy and integrations instead. |
| **Building SOAR integrations** | Enterprise feature. Wait until paying customers request specific SOAR platforms. Building Splunk SOAR, Cortex XSOAR, and Tines integrations now is speculative engineering. |
| **Writing extensive documentation** | README, --help output, and the HTML report are sufficient for early adopters. Over-documenting signals a product that needs explaining. If the tool needs a manual, the UX is wrong. |

---

# Part 4: 30-Day Success Criteria

These are the measurable outcomes that determine whether the first 30 days achieved the "Establish Presence, Prove Value" objective.

| Metric | Target | How to Measure |
|--------|--------|----------------|
| KAPE Module PR submitted | 1 PR open or merged | GitHub PR status |
| Benchmark methodology published | Live on GitHub | `docs/BENCHMARK_METHODOLOGY.md` exists with initial results |
| Blog post published | 1 technical post live | URL exists and is shareable |
| DFIR Discord presence | Active member, 5+ helpful replies | Post history |
| CFP submitted | 1 CFP to a DFIR conference | Submission confirmation |
| Demo video published | 1 video live | YouTube/Vimeo URL |
| GitHub traffic | 100+ unique visitors in month 1 | GitHub Insights |
| Tool downloads | 50+ binary downloads or `cargo install` | GitHub Releases + crates.io stats |
| Community mentions | 3+ organic mentions by others | Search monitoring |

**30-Day Gate Decision**: If fewer than 3 of these 9 metrics are met, re-evaluate the community-first strategy before proceeding to Phase 2.

---

# Part 5: Days 31-60

**Theme: "Build Community, Ship Integrations"**

The second month shifts from establishing presence to building momentum. The KAPE module should be merged or close to it. The benchmark suite provides ammunition for conference talks. Community engagement deepens.

## Focus Areas

### 5.1 Integration Completion

| Action | Owner | Due | Deliverable |
|--------|-------|-----|-------------|
| Follow up on KAPE Module PR, address review feedback | Solo founder | Day 31-40 | Merged PR or clear path to merge |
| Submit Velociraptor VQL artifact to official artifact exchange | Solo founder | Day 35-45 | Open PR on Velociraptor artifact repo |
| Test usnjrnl-forensic in Autopsy pipeline (manual integration) | Solo founder | Day 40-50 | Documentation for Autopsy users |
| Publish Windows binary via GitHub Releases with checksums | Solo founder | Day 31-35 | Signed release with SHA256 verification |

### 5.2 Content Cadence

| Action | Owner | Due | Deliverable |
|--------|-------|-----|-------------|
| Publish second blog post: "35 Seconds from E01 to IR Answers -- How usnjrnl-forensic Works" | Solo founder | Day 35-42 | Published post with architecture walkthrough |
| Publish benchmark results for 3+ reference images | Solo founder | Day 40-50 | Benchmark comparison page on GitHub |
| Record conference talk dry-run and publish as YouTube video | Solo founder | Day 50-60 | 20-30 minute technical presentation |

### 5.3 Community Deepening

| Action | Owner | Due | Deliverable |
|--------|-------|-----|-------------|
| Respond to all GitHub issues within 48 hours | Solo founder | Ongoing | Issue response rate tracking |
| Engage in 2+ DFIR Twitter/X threads per week with technical insight | Solo founder | Ongoing | Social presence |
| Identify 3-5 potential beta testers for enterprise features | Solo founder | Day 45-60 | List of interested practitioners with use cases |
| Start collecting feature requests from community interactions | Solo founder | Ongoing | Feature request tracking (GitHub Discussions or Issues) |

### 5.4 Enterprise Preparation (Research Only)

| Action | Owner | Due | Deliverable |
|--------|-------|-----|-------------|
| Survey community contacts: "What would you pay for?" | Solo founder | Day 45-55 | Survey results with 10+ responses |
| Draft enterprise feature tier spec based on community feedback | Solo founder | Day 55-60 | Internal spec document (not public) |
| Research licensing/payment infrastructure (Stripe, Gumroad, or similar) | Solo founder | Day 50-60 | Decision on payment platform |

## 60-Day Milestones

| Milestone | Target |
|-----------|--------|
| KAPE Module merged or in active review | Yes/No |
| Velociraptor artifact submitted | Yes/No |
| Blog posts published | 2 total |
| GitHub unique visitors (month 2) | 200+ |
| Tool downloads (cumulative) | 150+ |
| Community contacts identified for enterprise beta | 5+ |
| Conference talk accepted or waitlisted | 1+ |

## 60-Day Decision

**Proceed** if KAPE module is merged and community engagement is growing (GitHub visitors, Discord activity, blog post shares).

**Iterate** if KAPE module is blocked -- investigate alternative distribution channels (direct download page, Chocolatey/Homebrew packages, Docker image).

---

# Part 6: Days 61-90

**Theme: "Monetize and Measure"**

The third month begins the transition from pure community building to revenue generation. Enterprise feature development starts only after validating demand through 30-60 day community interactions.

## Focus Areas

### 6.1 Enterprise Feature MVP

| Action | Owner | Due | Deliverable |
|--------|-------|-----|-------------|
| Build batch processing (multiple images in one run) | Solo founder | Day 61-75 | `--batch` flag that processes a directory of E01 files |
| Build audit logging (who ran what, when, with what flags) | Solo founder | Day 70-80 | `--audit-log` flag that writes tamper-evident JSON log |
| Build custom triage rule support (user-defined patterns) | Solo founder | Day 75-85 | `--rules` flag that loads YAML rule definitions |
| Create enterprise landing page on GitHub Pages | Solo founder | Day 80-85 | Public page explaining paid tier, pricing, and features |
| Set up payment infrastructure (Stripe or Gumroad) | Solo founder | Day 80-90 | Working payment flow for $99/month or $999/year |

### 6.2 Conference Execution

| Action | Owner | Due | Deliverable |
|--------|-------|-----|-------------|
| Deliver first conference talk (or meetup/webinar if conference not yet scheduled) | Solo founder | Day 61-90 | Presented to live audience |
| Collect business cards / contact info from talk attendees | Solo founder | At event | Follow-up list |
| Post talk recording and slides publicly | Solo founder | Within 1 week of talk | YouTube + SlideShare/GitHub |

### 6.3 Measurement Infrastructure

| Action | Owner | Due | Deliverable |
|--------|-------|-----|-------------|
| Implement opt-in anonymous usage telemetry (cases triaged count only) | Solo founder | Day 65-75 | `--telemetry` flag (off by default, privacy-first) |
| Set up Weekly Active Cases Triaged dashboard | Solo founder | Day 75-85 | Simple tracking of North Star metric |
| Track conversion funnel: download -> use -> repeat use -> paid | Solo founder | Day 80-90 | Funnel metrics documented |

## 90-Day Milestones

| Milestone | Target |
|-----------|--------|
| Enterprise features shipped (batch, audit, rules) | 3 features live |
| Payment infrastructure live | Yes/No |
| First paying customer | 1+ (stretch goal: 5) |
| Conference talk delivered | 1+ |
| Weekly Active Cases Triaged (measured) | 10+ per week |
| GitHub unique visitors (month 3) | 300+ |
| Cumulative downloads | 300+ |
| KAPE module active users | 50+ |
| Blog posts published | 4 total |

## 90-Day Phase Gate

| Outcome | Signal | Action |
|---------|--------|--------|
| **Proceed to Scale** | 1+ paying customer, 300+ downloads, KAPE module merged, conference talk delivered | Continue Conference Circuit strategy. Increase content cadence. Pursue 50-customer target. |
| **Iterate** | Downloads growing but zero paying customers | Re-examine pricing. Consider freemium model. Survey users on willingness to pay. Adjust enterprise feature set. |
| **Pivot to Direct Enterprise** | Strong enterprise interest but community adoption flat | Shift to direct MSSP outreach. Offer 90-day pilot programs. De-prioritize community content. |
| **Pivot to Platform Integration** | KAPE/Velociraptor adoption strong but no independent demand | Double down on being a component. Explore OEM licensing with KAPE/Velociraptor vendors. |

---

# Part 7: Risk and Contingency

## Top 5 Risks

### Risk 1: MFTECmd Adds Automated Triage Questions

| Attribute | Detail |
|-----------|--------|
| **Probability** | Medium (30-40%) |
| **Impact** | High -- Eliminates primary differentiation for casual users |
| **Early Warning** | Eric Zimmerman announces triage features, MFTECmd changelog shows IR question output |
| **Mitigation** | Accelerate ghost record recovery differentiation. MFTECmd cannot match unallocated carving and `$LogFile` ghost recovery without fundamental architecture changes. Publish benchmark comparisons showing recovery rate delta. |
| **Contingency** | If MFTECmd ships triage features, pivot messaging to "we find what MFTECmd misses" and double down on deleted evidence recovery. |

### Risk 2: Zero Paying Customers After 12 Months

| Attribute | Detail |
|-----------|--------|
| **Probability** | Medium (40-50%) |
| **Impact** | Critical -- Open-core model collapses, sustainability path unclear |
| **Early Warning** | Zero enterprise feature interest by month 6. Survey responses show unwillingness to pay. |
| **Mitigation** | Validate pricing with 5 practitioners before building payment infrastructure. Offer annual discount ($999/year vs $99/month). Consider one-time license as alternative to subscription. |
| **Contingency** | If zero revenue at 12 months, explore: (a) consulting/training revenue using usnjrnl-forensic, (b) sponsored development by an MSSP, (c) donation model (GitHub Sponsors). |

### Risk 3: Conference CFPs Rejected

| Attribute | Detail |
|-----------|--------|
| **Probability** | Medium-High (50%) for tier-1 conferences |
| **Impact** | Medium -- Delays visibility but does not block community building |
| **Early Warning** | First 2 CFP submissions rejected. |
| **Mitigation** | Start with regional BSides events and local DFIR meetups (higher acceptance rates). Build a track record. Record and publish talks independently on YouTube. Apply to SANS DFIR Summit, OSDFCon, and DFRWS after establishing speaking history. |
| **Contingency** | If all CFPs rejected after 6 months, host own webinar series. Partner with DFIR content creators for guest appearances. |

### Risk 4: KAPE Module PR Rejected or Stalled

| Attribute | Detail |
|-----------|--------|
| **Probability** | Low-Medium (20-30%) |
| **Impact** | High -- Blocks the highest-leverage distribution channel |
| **Early Warning** | PR open for 30+ days with no maintainer response. |
| **Mitigation** | Study existing KapeFiles modules for format compliance before submitting. Engage with KapeFiles maintainers on Discord before PR. Include thorough documentation and test results. |
| **Contingency** | If PR is rejected, publish module independently with installation instructions. Create a "KAPE Integration Guide" in the README. Explore Velociraptor as primary distribution channel instead. |

### Risk 5: Solo Developer Burnout

| Attribute | Detail |
|-----------|--------|
| **Probability** | High (60-70%) without deliberate pacing |
| **Impact** | Critical -- All progress stops |
| **Early Warning** | Skipping weekly check-ins. Falling behind on content cadence. Avoiding community engagement. |
| **Mitigation** | Time-box community and marketing work to 30% of available hours. Batch social media engagement to specific times. Accept that "good enough" content ships; perfect content doesn't. |
| **Contingency** | If burnout symptoms appear, cut scope to product development only for 2 weeks. Drop content cadence to monthly. Focus on the single highest-impact action. |

---

# Part 8: Resource Allocation

## Solo Developer Time Budget

The following allocation assumes 20 productive hours per week (accounting for a day job, life, etc.). Adjust proportionally if more or fewer hours are available.

### Days 1-30: "Establish Presence, Prove Value"

| Activity | Allocation | Hours/Week | Examples |
|----------|------------|------------|----------|
| Product Development | 40% | 8 hrs | KAPE module, Velociraptor artifact, install scripts |
| Content Creation | 30% | 6 hrs | Blog post, demo video, benchmark methodology |
| Community Engagement | 20% | 4 hrs | Discord, Slack, Twitter/X, answering questions |
| Strategy and Planning | 10% | 2 hrs | CFP writing, conference research, metric tracking |

### Days 31-60: "Build Community, Ship Integrations"

| Activity | Allocation | Hours/Week | Examples |
|----------|------------|------------|----------|
| Product Development | 35% | 7 hrs | Integration follow-up, Windows binary releases, bug fixes |
| Content Creation | 30% | 6 hrs | Second blog post, benchmark results, talk dry-run |
| Community Engagement | 25% | 5 hrs | Deeper Discord engagement, beta tester recruitment |
| Enterprise Research | 10% | 2 hrs | Pricing validation, feature surveys, payment infrastructure research |

### Days 61-90: "Monetize and Measure"

| Activity | Allocation | Hours/Week | Examples |
|----------|------------|------------|----------|
| Product Development | 45% | 9 hrs | Enterprise features (batch, audit, rules), telemetry |
| Community Engagement | 20% | 4 hrs | Ongoing presence, conference networking |
| Content Creation | 15% | 3 hrs | Blog posts, talk recordings, benchmarks updates |
| Go-to-Market | 20% | 4 hrs | Landing page, payment setup, pricing page, first sales conversations |

## Non-Negotiable Time Blocks

| Block | Frequency | Duration | Purpose |
|-------|-----------|----------|---------|
| Weekly metric check | Every Sunday | 30 min | Review GitHub traffic, downloads, community mentions |
| Community scan | Daily | 15 min | Check Discord/Slack for questions, monitor competitor activity |
| Deep work (coding) | 3x per week | 2-3 hrs each | Uninterrupted product development |
| Content day | 1x per week | 3 hrs | Blog writing, video recording, benchmark work |

---

# Part 9: Review Protocol

## Weekly Check-in (Every Sunday, 30 Minutes)

Answer these five questions in a personal log:

1. **What shipped this week?** (List concrete deliverables: PRs, posts, modules, features)
2. **What's the single most important thing to do next week?** (Force-rank to one item)
3. **Am I spending time on something in the Avoid list?** (If yes, stop immediately)
4. **What did the community say?** (Summarize Discord/Slack/GitHub interactions)
5. **Am I on track for the 30-day success criteria?** (Check each metric)

## 30-Day Review (Day 30, 2 Hours)

### Review Agenda

1. **Score each 30-day success criterion** (Met / Partially Met / Not Met)
2. **Count organic community mentions** -- Are people talking about usnjrnl-forensic without prompting?
3. **Review GitHub Insights** -- Unique visitors, clones, traffic sources, referring sites
4. **Evaluate time allocation** -- Did the planned percentages hold? Where did time leak?
5. **Check review triggers**:
   - Has MFTECmd added triage features? If yes, reassess differentiation strategy.
   - Has a major vendor acquired a niche NTFS tool? If yes, accelerate enterprise features.
6. **Decision**: Proceed to Phase 2 as planned, or adjust scope/priorities?

### Output

A brief written summary (half page) with:
- 3 things that worked
- 3 things that didn't
- Adjusted priorities for days 31-60 (if needed)

## 90-Day Review (Day 90, 3 Hours)

### Review Agenda

1. **Phase Gate evaluation** -- Which outcome from the 90-Day Phase Gate table applies?
2. **North Star Metric baseline** -- What is the measured Weekly Active Cases Triaged? (Even if estimated)
3. **Revenue status** -- Any paying customers? Pipeline of interested buyers?
4. **Community health** -- GitHub contributors, Discord members, blog post engagement
5. **Assumption validation**:
   - Market need exists (85% confidence) -- Confirmed or revised?
   - Product ready (90% confidence) -- Any critical gaps discovered?
   - Community GTM works (80% confidence) -- Is community adoption happening?
   - Consultants will pay (55% confidence) -- Any paying or willing-to-pay signals?
   - 50 customers in 18 months (50% confidence) -- On track or unrealistic?
6. **Review trigger check** -- Has any trigger fired that requires strategy change?

### Output

A one-page written document with:
- Phase Gate decision (Proceed / Iterate / Pivot) with rationale
- Updated confidence levels for each assumption
- Next 90-day roadmap (if proceeding) or pivot plan (if changing strategy)
- Updated resource allocation percentages

---

# Appendix: Quick Reference Calendar

## Week 1 (Days 1-7)

- [ ] Join DFIR Discord, post introduction with Szechuan Sauce walkthrough
- [ ] Join 2-3 DFIR Slack workspaces
- [ ] Draft KAPE Module YAML
- [ ] Begin benchmark methodology document
- [ ] Test KAPE Module against 3 reference images
- [ ] Start answering community questions

## Week 2 (Days 8-14)

- [ ] Submit KAPE Module PR to KapeFiles repository
- [ ] Create installation scripts
- [ ] Write first blog post (ghost record recovery)
- [ ] Select reference forensic images for benchmarks
- [ ] Submit CFP to next available DFIR conference

## Week 3 (Days 15-21)

- [ ] Share blog post across social channels
- [ ] Begin Velociraptor VQL artifact development
- [ ] Run benchmark suite against reference images
- [ ] Compare results against MFTECmd baseline
- [ ] Continue community engagement (5+ helpful replies target)

## Week 4 (Days 22-30)

- [ ] Publish benchmark methodology and initial results
- [ ] Record and publish demo video (2-3 min)
- [ ] Complete Velociraptor VQL artifact draft
- [ ] Conduct 30-day review
- [ ] Log weekly metric check results for weeks 1-4

---

*This roadmap is a living document. Update it at each review checkpoint. The goal is not to follow it rigidly but to maintain momentum and direction while adapting to what the community and market reveal.*
