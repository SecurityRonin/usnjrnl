# Security Ronin Katana: User Journey Maps

> **Product**: Security Ronin Katana -- Precision DFIR triage from disk image to incident response answers in 35 seconds
> **North Star Metric**: Number of Paying Enterprise Customers
> **Date**: 2026-03-10
> **Version**: 1.0

---

## Document Purpose

This document maps the end-to-end user experience for Security Ronin Katana across both the community (CLI-only, open source) and enterprise (CLI + web API, proprietary) tiers. Each journey maps touchpoints, emotional states, friction points, and measurable KPIs specific to a CLI-first forensic triage tool -- not a web application.

**Key distinction**: Katana's user journeys are fundamentally different from SaaS products. There is no landing page, no signup flow, no onboarding modal. Discovery happens through GitHub, forensic conferences, peer recommendations, and blog posts. The "first experience" is running a command and getting answers.

**Cross-references**:
- Personas: [NORTHSTAR.md](../NORTHSTAR.md) -- Alex Chen, Sarah Okonkwo, James Whitfield
- Brand voice: [BRAND_GUIDELINES.md](../BRAND_GUIDELINES.md) -- Precise, technical, no-nonsense
- Axioms: [NORTHSTAR_EXTRACT.md](../NORTHSTAR_EXTRACT.md) -- Forensic Integrity > Feature Velocity

---

## 1. First-Time Community User Journey

### 1.1 Journey Overview

```
+------------------------------------------------------------------------------+
|                    FIRST-TIME COMMUNITY USER JOURNEY                         |
+------------------------------------------------------------------------------+
|                                                                              |
|  DISCOVERY        INSTALL          FIRST TRIAGE       REVIEW         SHARE   |
|      |               |                |                |              |      |
|      v               v                v                v              v      |
|  +--------+     +----------+     +----------+     +----------+  +--------+  |
|  | GitHub  |---->| cargo    |---->| katana   |---->| HTML     |->| Blog / |  |
|  | README  |    | install  |    | triage   |    | report   | | Slack  |  |
|  | / Talk  |    | / binary |    | image.e01|    | Story +  | | post   |  |
|  +--------+     +----------+     +----------+     | Explore  |  +--------+  |
|                                                    +----------+              |
|  EMOTION:        EMOTION:         EMOTION:         EMOTION:     EMOTION:    |
|  Skeptical/      Pragmatic/       Anxious/         Impressed/   Evangelist/ |
|  Curious         Efficient        Hopeful          Delighted    Confident   |
|                                                                              |
+------------------------------------------------------------------------------+
```

### 1.2 Detailed Journey Map

| Phase | User Action | Emotional State | System Response | Friction Points | Mitigation |
|-------|-------------|-----------------|-----------------|-----------------|------------|
| **Discovery** | Sees Katana mentioned at DFIR conference, Slack channel, or Twitter/X post | Skeptical -- "another USN tool?" | N/A (organic discovery) | Unclear differentiation from MFTECmd or other free tools | README leads with "35 seconds, ghost recovery, 12 IR questions" -- concrete numbers, not adjectives |
| **Evaluation** | Reads GitHub README, checks star count, scans feature list | Cautiously interested | README with reproducible benchmarks, sample output screenshots | "Is this maintained? Is it stable?" | Show CI badges, version number (v0.6.0), recent commit dates, Apache-2.0 license |
| **Install** | Runs `cargo install katana` or downloads pre-built binary from Releases | Pragmatic -- wants to test quickly | Binary downloads in <30 seconds; cargo install completes with progress bar | Rust toolchain required for cargo install; binary not available for their OS | Provide pre-built binaries for Linux x86_64, macOS arm64/x86_64, Windows x86_64; document minimum Rust version |
| **First Run** | Runs `katana triage suspect-workstation.e01` | Anxious -- "will it work with my image?" | Progress output: `[1/4] Mounting EWF image... [2/4] Parsing USN Journal... [3/4] Ghost recovery + carving... [4/4] Running 12 triage questions...` | No output for several seconds creates uncertainty | Streaming progress with phase labels and elapsed time; sub-35-second total |
| **Processing** | Watches terminal output | Invested -- tracking progress | Real-time line counts: `Parsed 847,293 USN records (2.1s)... Recovered 12,847 ghost entries (4.3s)... Resolved 99.8% paths (1.2s)` | Unclear whether ghost recovery found anything meaningful | Show ghost recovery count inline; highlight if count is significant |
| **Results** | Opens HTML report, sees Story tab with narrative timeline and Explore tab with filterable data | Impressed -- "it found deleted evidence I missed" | HTML report with two views: Story (analyst-friendly narrative) and Explore (searchable, filterable raw data) | Report opens in browser but user expected terminal output | Default to terminal summary with `--html` flag generating report; print report path at end |
| **Validation** | Cross-references Katana findings against manual analysis or other tools | Trust-building -- verifying accuracy | Deterministic output -- same input always produces same output; SHA-256 hash of output for court defensibility | Results differ from existing tool (false positive concern) | Include confidence indicators; document methodology in report appendix; provide `--verify` flag for hash validation |
| **Sharing** | Posts results comparison on forensic Slack/Discord, writes blog post, tells colleagues | Evangelist -- "you need to try this" | N/A (organic sharing) | No easy way to share a summary | Provide `katana triage --format summary` for a shareable text block; include comparison-friendly output |

### 1.3 Emotional Arc Visualization

```
CONFIDENCE
    ^
    |                                                          *----* EVANGELIST
    |                                                         /
    |                                                    *---*
    |                                                   / DELIGHTED
    |                                              *---*  (ghost recovery
    |                                             /    found evidence)
    |                           *---*            /
    |                          / WATCHING       *
    |                    *----*  PROGRESS      (validation
    |                   / PRAGMATIC             confirms accuracy)
    |              *---*
    |             / INSTALL
    |        *---*
    |       / CAUTIOUS
    |  *---*
    |  SKEPTICAL
    |
----+---------------------------------------------------------------> TIME
    |  README  Install  First   Progress  Results  Validate  Share
    |                   Run
    v
ANXIETY
```

**Critical Moments:**
1. **README scan (first 30 seconds)**: Must overcome "yet another tool" skepticism with concrete performance numbers and ghost recovery differentiation -- not marketing language
2. **First run progress (35 seconds)**: Highest anxiety -- did it mount correctly? Is it hanging? Streaming progress with record counts is essential
3. **Ghost recovery reveal**: The "holy shit" moment -- finding evidence that other tools missed. This is the single biggest driver of evangelism
4. **Validation against known tools**: Trust is earned here. Deterministic, reproducible output matters more than flashy features

---

## 2. Returning Community User Journey

### 2.1 Journey Overview

```
+------------------------------------------------------------------------------+
|                     RETURNING COMMUNITY USER JOURNEY                         |
+------------------------------------------------------------------------------+
|                                                                              |
|  NEW CASE         TRIAGE           REVIEW            EXPORT        ITERATE   |
|      |               |                |                |              |      |
|      v               v                v                v              v      |
|  +--------+     +----------+     +----------+     +----------+  +--------+  |
|  | New E01 |---->| katana   |---->| HTML     |---->| Export   |->| Custom |  |
|  | arrives |    | triage   |    | report   |    | to Plaso |  | flags  |  |
|  | on desk |    | image.e01|    | review   |    | / TLN    |  | batch  |  |
|  +--------+     +----------+     +----------+     +----------+  +--------+  |
|                                                                              |
|  EMOTION:        EMOTION:         EMOTION:         EMOTION:     EMOTION:    |
|  Purpose-        Confident/       Efficient/       Integrated/  Power-user/ |
|  driven          Routine          Focused          Streamlined  Mastery     |
|                                                                              |
+------------------------------------------------------------------------------+
```

### 2.2 Detailed Journey Map

| Phase | User Action | Emotional State | System Response | Friction Points | Mitigation |
|-------|-------------|-----------------|-----------------|-----------------|------------|
| **New Case** | Receives E01/raw image from client or collection | Purpose-driven -- active investigation | N/A | Image may be in unexpected format or location | Support both E01 and raw image formats; accept paths with spaces |
| **Triage** | Runs `katana triage /cases/2024-03-10/workstation.e01` | Confident -- knows what to expect | Same reliable progress output; completes in <35 seconds | Remembering exact flags from last time | `katana triage --help` with concise, grouped options; shell completion support |
| **Review** | Opens HTML report, goes directly to Explore tab to filter by time range or file pattern | Efficient -- knows the UI layout | Explore tab with pre-filtered views based on triage question hits | Switching between Story and Explore for different aspects | Keyboard shortcuts in HTML report; URL fragments for direct section links |
| **Export** | Runs `katana triage image.e01 --format tln` or `--format csv` for timeline tools | Integrated -- fitting into existing workflow | Output in Plaso/Timesketch-compatible TLN format, or CSV/JSONL/XML/body file for other tools | Output format doesn't match exact schema of target tool | Document exact schema for each format; provide format examples in `--help` |
| **Batch** | Runs `katana triage /cases/*.e01` or scripts multiple runs | Power-user mastery | Parallel processing of multiple images; summary across all results | No built-in batch mode; must shell-script it | Support glob patterns natively; provide `--output-dir` for organized batch output |

### 2.3 Power User Patterns

```
ACTIONS/MINUTE
    ^
    |                                   *----*----*----* POWER USER
    |                              *---*                 (batch, custom formats,
    |                         *---*                       piping to Plaso)
    |                    *---*
    |               *---*
    |          *---*
    |     *---*
    | *--* FIRST-TIME USER
    |
----+-----------------------------------------------------------> SESSIONS
    |    1    2    3    4    5    6    7    8    9   10
```

**Power User Optimization Opportunities:**
- Shell aliases: `alias kt='katana triage'` -- document in README
- Batch processing: `katana triage /evidence/*.e01 --output-dir /reports/`
- Pipeline integration: `katana triage image.e01 --format jsonl | jq '.[] | select(.triage_hit == true)'`
- Custom output: `katana triage image.e01 --format csv --fields timestamp,path,reason,usn_reason`
- Automation: CI/CD integration for automated triage on evidence ingestion

---

## 3. Enterprise Upgrade Journey

### 3.1 Journey Overview

> This section maps the community-to-enterprise upgrade path -- the primary revenue conversion funnel for the open-core business model.

```
+------------------------------------------------------------------------------+
|                      COMMUNITY -> ENTERPRISE UPGRADE JOURNEY                 |
+------------------------------------------------------------------------------+
|                                                                              |
|  INDIVIDUAL       TEAM FRICTION     EVALUATE          TRIAL       PURCHASE   |
|  DELIGHT             |              ENTERPRISE           |            |      |
|      |               |                |                  |            |      |
|      v               v                v                  v            v      |
|  +--------+     +----------+     +----------+     +----------+  +--------+  |
|  | Alex   |---->| "We all  |---->| Enterprise|---->| 30-day  |->| Org    |  |
|  | loves  |    | need     |    | feature  |    | trial   | | signs  |  |
|  | Katana |    | this"    |    | comparison|    | (free)  | | deal   |  |
|  +--------+     +----------+     +----------+     +----------+  +--------+  |
|                                                                              |
|  EMOTION:        EMOTION:         EMOTION:         EMOTION:     EMOTION:    |
|  Individual      Frustrated/      Analytical/      Validating/  Committed/  |
|  satisfaction    Advocating       Comparing        Proving ROI  Confident   |
|                                                                              |
+------------------------------------------------------------------------------+
```

### 3.2 Upgrade Trigger Mapping

| Trigger | Who Experiences It | Mindset | Signal to Katana | Conversion Strategy |
|---------|-------------------|---------|------------------|---------------------|
| Solo consultant recommends to MSSP team lead | Alex Chen -> Sarah Okonkwo | "My team needs what I have" | Community user mentions team in forum/support | Provide "recommend to your team" one-pager with ROI numbers |
| Team needs multi-device examination | Sarah Okonkwo | "We can't run 6 separate instances" | Multiple community downloads from same org IP range | Enterprise page shows multi-device correlation features |
| Audit trail required for compliance | James Whitfield | "We need chain of custody" | Questions about audit logging in GitHub issues | Documentation shows enterprise audit trail capabilities |
| Velociraptor integration needed | Sarah Okonkwo | "Manual evidence collection doesn't scale" | Integration questions in community channels | Highlight Velociraptor agent integration in enterprise tier |
| RBAC for analyst access control | James Whitfield | "Not everyone should see everything" | Team structure questions | Show role-based access control in enterprise demo |

### 3.3 Upgrade Decision Journey

| Phase | User Action | Emotional State | System Response | Friction Points | Mitigation |
|-------|-------------|-----------------|-----------------|-----------------|------------|
| **Individual Delight** | Solo analyst uses community Katana, saves 30+ min/case | Satisfied, becoming advocate | Consistent <35s performance, ghost recovery wins cases | No friction -- this is the honeymoon | Ensure community version is genuinely excellent; never cripple it |
| **Team Advocacy** | Recommends Katana to team lead; multiple team members install independently | Frustrated -- "we're all doing this separately" | N/A (organic team discovery) | No shared case management, no way to assign devices, duplicate work | Include `katana --enterprise-info` flag that prints upgrade benefits |
| **Evaluation Request** | Team lead visits enterprise documentation, requests pricing | Analytical -- comparing against EnCase/Magnet AXIOM enterprise | Clear feature comparison table: community vs. enterprise; transparent pricing ($99-149/seat/month) | Enterprise page is marketing-heavy, not technical enough | Lead with technical capabilities, not sales language; include CLI examples for enterprise features |
| **Trial Activation** | Team signs up for 30-day enterprise trial | Validating -- needs to prove ROI to budget holder | Immediate access, no sales call required; enterprise binary + API key delivered within minutes | Trial requires sales call or demo booking | Self-serve trial signup; API key delivered by email; `katana enterprise activate --key <key>` |
| **Trial Evaluation** | Team runs multi-device examinations, tests RBAC, generates audit reports | Proving ROI -- documenting time savings and coverage improvements | Full enterprise functionality; usage dashboard showing team metrics | 30 days isn't enough for a real IR case cycle | Extend trial to 45 days on request; provide sample enterprise datasets |
| **Purchase Decision** | Team lead presents ROI analysis to management; budget approved | Decisive -- has evidence that Katana saves time and finds more evidence | Clear procurement process; PO/invoice support; SOC 2 compliance documentation | Procurement process is complex for government/large enterprise | Support PO-based purchasing; provide security questionnaire answers; offer annual billing discount |
| **Team Onboarding** | Enterprise deployed; analyst accounts created; first team case processed | Committed -- invested in the platform | Onboarding documentation; `katana enterprise setup --org <org>` wizard | Learning curve for enterprise-specific features | Migration guide from community workflow; enterprise CLI commands mirror community patterns |

### 3.4 Upgrade Emotional Arc

```
SATISFACTION
    ^
    |  *---*                                                    *----* TEAM
    | / INDIVIDUAL                                             /       ADOPTION
    |*  DELIGHT                                          *---*
    |                                                   / TRIAL
    |                                              *---*  VALIDATES
    |                                             /
    |                        *---*---*           *
    |                       /         \         / EVALUATION
    |                  *---*           *---*---*  (analytical,
    |                 /  TEAM FRICTION             comparing)
    |            *---*   ("we need
    |           /         this for
    |      *---*          everyone")
    |
----+---------------------------------------------------------------> TIME
    |  Solo    Recommend  Team     Evaluate  Trial    Purchase  Deploy
    |  use     to team    friction enterprise
    v
FRUSTRATION
```

**Critical conversion moments:**
1. **Team friction peak**: The moment when multiple team members are running community Katana independently and realize they need shared case management. This frustration must be channeled toward enterprise evaluation, not toward abandoning Katana.
2. **Feature comparison**: Must demonstrate that enterprise adds team capabilities without degrading the CLI experience they already trust.
3. **Trial success**: First multi-device examination in the trial period must deliver the same <35s performance per device that they trusted in community.

---

## 4. Enterprise Daily Workflow Journey

### 4.1 Journey Overview

```
+------------------------------------------------------------------------------+
|                     ENTERPRISE DAILY WORKFLOW JOURNEY                         |
+------------------------------------------------------------------------------+
|                                                                              |
|  ALERT          COLLECT         TRIAGE          COLLABORATE     REPORT       |
|    |               |               |                |              |         |
|    v               v               v                v              v         |
|  +--------+   +----------+   +----------+     +----------+   +----------+   |
|  | SOC    |-->| Veloci-  |-->| katana   |---->| Team     |-->| Court-   |   |
|  | alert  |  | raptor   |  | triage   |    | review   |  | ready   |   |
|  | fires  |  | collects |  | --multi  |    | + assign |  | report  |   |
|  +--------+   +----------+   +----------+     +----------+   +----------+   |
|                                                                              |
|  EMOTION:      EMOTION:       EMOTION:         EMOTION:       EMOTION:      |
|  Urgent/       Methodical/    Focused/         Coordinated/   Confident/    |
|  Alert         Systematic     Efficient        Collaborative  Authoritative |
|                                                                              |
+------------------------------------------------------------------------------+
```

### 4.2 Detailed Journey Map

| Phase | User Action | Emotional State | System Response | Friction Points | Mitigation |
|-------|-------------|-----------------|-----------------|-----------------|------------|
| **Alert Received** | SOC analyst escalates alert to IR team; case created in ticketing system | Urgent -- clock is ticking on containment | N/A (external trigger) | IR team needs to context-switch from current work | Push notification to on-call analyst; case priority assignment |
| **Evidence Collection** | Analyst deploys Velociraptor collection agent to affected endpoints | Methodical -- following IR playbook | Enterprise Katana integrates with Velociraptor; collection jobs tracked in Katana dashboard | Collection agent fails on some endpoints; partial evidence | Retry logic with clear status per endpoint; proceed with available evidence |
| **Multi-Device Triage** | Lead analyst runs `katana triage --case IR-2024-0847 --devices /evidence/endpoints/*.e01` | Focused -- needs answers fast | Parallel triage across all devices; results correlated by timeline; per-device and cross-device views | 12 devices at 35s each = 7 minutes; feels slow for urgent IR | Show per-device progress; deliver results as each device completes (streaming); cross-device correlation starts immediately |
| **Triage Review** | Analyst reviews correlated timeline across all devices; identifies lateral movement pattern | Analytical -- piecing together the attack narrative | Cross-device timeline with lateral movement visualization; common IOCs highlighted across devices | Too much data across 12 devices; information overload | Pre-filtered "cross-device anomalies" view; triage question answers aggregated across devices |
| **Case Assignment** | Team lead assigns specific devices to individual analysts for deep dive | Coordinated -- distributing workload | RBAC-enforced assignment; analyst sees only assigned devices; audit trail logged | Analyst needs context from other devices they can't access | "Related findings" panel showing relevant cross-device context without full access |
| **Collaborative Analysis** | Multiple analysts work their assigned devices; share findings via case notes | Collaborative -- building shared understanding | Real-time case notes; finding annotations; shared IOC list | Conflicting interpretations; no version control on shared notes | Threaded discussion per finding; analyst attribution; conflict detection |
| **Report Generation** | Lead analyst generates court-ready report covering all devices and findings | Confident -- comprehensive evidence documented | `katana report --case IR-2024-0847 --format pdf --court-ready` with chain-of-custody metadata, SHA-256 hashes, methodology documentation | Report doesn't include manual analyst annotations | Merge automated findings with analyst notes; include methodology section; hash verification appendix |
| **Case Closure** | Report delivered to client/legal; case archived with full audit trail | Authoritative -- defensible documentation | Case archive with immutable audit log; evidence chain maintained | Retention policy compliance; data disposal requirements | Configurable retention policies; secure case archival; disposal certification |

### 4.3 Multi-Analyst Coordination

```
TIME -->
              0min        5min        10min       15min       20min
LEAD ANALYST  |--COLLECT--|--TRIAGE---|--ASSIGN---|--REVIEW---|--REPORT-->
ANALYST 2     |           |           |--DEVICE A-|--FINDINGS-|
ANALYST 3     |           |           |--DEVICE B-|--FINDINGS-|
ANALYST 4     |           |           |--DEVICE C-|--FINDINGS-|

              ^           ^           ^           ^           ^
              Alert       Evidence    Triage      Deep dive   Collaborative
              received    collected   complete    assigned    report
```

---

## 5. Error Recovery Journey

### 5.1 Journey Overview

```
+------------------------------------------------------------------------------+
|                         ERROR RECOVERY JOURNEY                               |
+------------------------------------------------------------------------------+
|                                                                              |
|  ERROR OCCURS      RECOGNITION       RECOVERY PATH      RESOLUTION          |
|       |                |                  |                  |               |
|       v                v                  v                  v               |
|  +----------+     +----------+       +----------+       +----------+        |
|  | Command  |---->| Clear    |------>| Guided   |------>| Back on  |        |
|  | fails    |     | stderr   |       | next     |       | track    |        |
|  |          |     | message  |       | step     |       |          |        |
|  +----------+     +----------+       +----------+       +----------+        |
|                                                                              |
|  EMOTION:          EMOTION:          EMOTION:           EMOTION:            |
|  Frustrated/       Understanding/    Hopeful/           Relieved/           |
|  Concerned         Informed          Active             Confident           |
|                                                                              |
+------------------------------------------------------------------------------+
```

### 5.2 Error Type Mapping

| Error Type | Example | Severity | User Message | Recovery Action | Emotional Design |
|------------|---------|----------|--------------|-----------------|------------------|
| **Corrupt E01 image** | EWF header checksum mismatch on segment 3/7 | Warning | `WARNING: E01 segment 3 corrupt (checksum mismatch). Processing 6/7 valid segments. Partial results flagged.` | Proceed with partial recovery; flag affected time ranges in report | Calm -- "we recovered what we could"; never blame the image source |
| **Unsupported filesystem** | ReFS, ext4, or APFS image provided | Blocking | `ERROR: Filesystem detected: ReFS. Katana supports NTFS only. See https://katana.security-ronin.com/formats for supported formats.` | Exit with code 2; link to supported format documentation | Informative -- acknowledge the limitation; suggest alternatives (Autopsy for non-NTFS) |
| **Missing USN Journal** | $UsnJrnl:$J not present in NTFS image | Warning | `WARNING: USN Journal ($UsnJrnl:$J) not found. Running ghost recovery from unallocated space. Results will be limited to carved entries.` | Fall back to unallocated carving only; adjust confidence levels in report | Reassuring -- "we have a fallback"; ghost recovery may still find evidence |
| **Permission denied** | Image file not readable by current user | Blocking | `ERROR: Cannot read '/evidence/case.e01' -- permission denied. Run with appropriate permissions or check file ownership.` | Exit with code 1; suggest `chmod` or running with correct user | Direct -- state the problem and solution; no jargon |
| **Disk space exhausted** | Output directory filesystem full during report generation | Blocking | `ERROR: Insufficient disk space in /output/ (need ~500MB, have 12MB). Triage data preserved in memory. Specify alternate output: katana triage image.e01 --output-dir /other/path` | Preserve in-memory state; allow retry with different output path | Protective -- "your work isn't lost"; provide immediate next step |
| **Network timeout (enterprise)** | Velociraptor collection agent unreachable | Warning | `WARNING: Collection timeout on endpoint DESKTOP-A7B3. 4/5 endpoints collected successfully. Retry: katana collect --retry DESKTOP-A7B3` | Proceed with available evidence; provide retry command | Pragmatic -- partial success is still success; retry is easy |
| **Malformed image** | File is not a valid E01 or raw disk image | Blocking | `ERROR: '/data/file.zip' is not a recognized disk image format (expected E01 or raw). Supported: .E01, .e01, .raw, .dd, .img` | Exit with code 2; list supported formats | Helpful -- maybe they passed the wrong file; list what works |

### 5.3 Error Recovery Emotional Design

```
TRUST IMPACT BY ERROR HANDLING QUALITY

TRUST LEVEL
    ^
    | *----*----*----*----* EXCELLENT RECOVERY
    |     \                 (clear message, actionable fix,
    |      \                 state preserved)
    |       *----*----* GOOD RECOVERY
    |        \          (clear message, manual fix needed)
    |         \
    |          *----* POOR RECOVERY
    |           \     (unclear message, user must guess)
    |            \
    |             *-* NO RECOVERY (crash, no message)
    |
----+-----------------------------------------------------------> TIME
    | ERROR  +1min  +5min  +1h   +1d
    | OCCURS
```

**Recovery Quality Standards (non-negotiable):**
1. **Speed to understanding**: User knows what happened within 1 line of stderr output
2. **Actionable next step**: Every error message includes what to do next
3. **State preservation**: Never lose partial results; never corrupt the input evidence
4. **No blame**: Error messages describe the situation, never imply user fault
5. **Exit codes**: Consistent exit codes (0=success, 1=runtime error, 2=input error) for scripting

---

## 6. Persona-Specific Journey Variations

### 6.1 Alex Chen -- Solo DFIR Consultant (Community Tier)

| Dimension | Alex's Pattern |
|-----------|---------------|
| **Entry point** | GitHub search for "USN journal forensic tool", DFIR Slack recommendation, or SANS conference talk |
| **Install preference** | Pre-built binary download (not cargo install -- doesn't maintain Rust toolchain) |
| **First action** | `katana triage` on a case he already analyzed with MFTECmd, to compare results |
| **Success metric** | Finds evidence MFTECmd missed (ghost recovery), completes in <35 seconds |
| **Power user behavior** | Shell alias `kt`, output to JSONL for piping to `jq`, exports to Plaso TLN for Timesketch |
| **Pain points** | Needs to remember flags; wants defaults that match his workflow; needs output compatible with his existing timeline tools |
| **Emotional journey** | Skeptical (seen many tools) -> Impressed (ghost recovery) -> Loyal (reliable results) -> Evangelist (recommends to Sarah's team) |
| **Upgrade trigger** | Does not upgrade personally; recommends to enterprise clients who need multi-device and RBAC |
| **Revenue role** | Evangelist -- discovers, validates, recommends to enterprise buyers |
| **KPIs** | Time-to-first-answer <35s; ghost recovery finds evidence missed by prior analysis; return usage within 30 days |

### 6.2 Sarah Okonkwo -- MSSP Senior Analyst (Enterprise Tier)

| Dimension | Sarah's Pattern |
|-----------|----------------|
| **Entry point** | Alex Chen (or similar solo consultant) recommends Katana to her team lead; she evaluates after hearing about it from trusted peer |
| **Install preference** | Enterprise deployment -- managed install across 6 analyst workstations; API key provisioned by team lead |
| **First action** | Runs community version on a known case to validate results; then pushes for enterprise trial |
| **Success metric** | Team processes 15-30 cases/month with consistent results; Velociraptor integration eliminates manual evidence collection |
| **Power user behavior** | Multi-device triage across client endpoints; batch processing; automated collection via Velociraptor agent; standardized report templates |
| **Pain points** | Needs standardized workflows across 6 analysts; needs audit trails for client reporting; needs Velociraptor integration for evidence collection at scale |
| **Emotional journey** | Curious (peer recommendation) -> Validated (community version works) -> Frustrated (can't scale to team) -> Relieved (enterprise trial) -> Committed (team adoption) |
| **Upgrade trigger** | "We're all running Katana independently -- we need shared case management, RBAC, and audit trails" |
| **Revenue role** | Primary buyer -- 4-8 seats, high volume, strong retention; $99-149/seat/month |
| **KPIs** | Team triage consistency >95%; average case turnaround time reduced; Velociraptor collection success rate; analyst utilization across cases |

### 6.3 James Whitfield -- Enterprise IR Team Lead (Enterprise Tier)

| Dimension | James's Pattern |
|-----------|----------------|
| **Entry point** | Sarah Okonkwo's MSSP (or similar) uses Katana for his company's IR engagement; he sees the results and wants it in-house |
| **Install preference** | Enterprise on-premise deployment; IT/security team handles installation; procurement through vendor management process |
| **First action** | Requests demo/trial for his 12-person IR team; evaluates against EnCase and Magnet AXIOM enterprise licenses |
| **Success metric** | IR team reduces mean-time-to-triage by 60%; court-ready reports accepted by legal without revision; full audit trail for compliance |
| **Power user behavior** | Delegates triage to analysts; reviews cross-device correlation reports; manages case assignments; generates executive summary reports |
| **Pain points** | Procurement process is complex (SOC 2 questionnaire, vendor risk assessment, legal review); needs enterprise support SLA; requires on-premise deployment option |
| **Emotional journey** | Impressed (saw MSSP results) -> Cautious (enterprise procurement) -> Analytical (comparing EnCase/AXIOM) -> Decisive (ROI is clear) -> Authoritative (team deployed, cases flowing) |
| **Upgrade trigger** | "Our MSSP uses this; I want my internal team to have the same capability without relying on external consultants" |
| **Revenue role** | High-value account -- 8-12+ seats, marquee reference customer; Fortune 500 credibility |
| **KPIs** | Mean-time-to-triage reduction; report acceptance rate by legal; analyst case throughput; compliance audit pass rate |

---

## 7. Journey Metrics

### 7.1 Key Performance Indicators

| Journey Phase | Metric | Target | Measurement Method |
|---------------|--------|--------|--------------------|
| **Discovery -> Install** | Install conversion rate | >40% of README visitors | GitHub analytics: unique visitors vs. release downloads + cargo install counts |
| **Install -> First Triage** | Activation rate | >80% within 24 hours | Opt-in telemetry: first `katana triage` execution timestamp vs. install timestamp |
| **First Triage -> Repeat** | 7-day retention rate | >60% | Opt-in telemetry: second triage within 7 days of first |
| **Community -> Enterprise Trial** | Trial request rate | >5% of active community users (annual) | Enterprise trial signups with community usage history |
| **Enterprise Trial -> Purchase** | Trial conversion rate | >30% | Trial activations vs. signed contracts |
| **Error -> Recovery** | Error recovery rate | >90% | Successful retry within 5 minutes of error |
| **Triage -> Complete** | Triage completion rate | >95% | Triage commands that exit with code 0 |
| **Performance** | P95 time-to-first-answer | <35 seconds | Triage execution time distribution |

### 7.2 Emotional Measurement

| Touchpoint | Measurement Method | Signal |
|------------|-------------------|--------|
| Post-first-triage | GitHub star (organic) | Initial satisfaction -- stars within 24h of first install |
| Post-ghost-recovery | Community mention (Slack/Twitter/blog) | "Found evidence other tools missed" -- highest advocacy signal |
| Post-error | Retry rate within 5 minutes | Error message was clear and actionable |
| Post-enterprise-trial | Trial-to-purchase conversion | Enterprise value proposition validated |
| 30-day community retention | Monthly active triage commands | Sustained utility beyond initial curiosity |
| NPS (enterprise only) | Quarterly survey to enterprise customers | Overall satisfaction and likelihood to recommend |

### 7.3 Funnel Metrics by Tier

```
COMMUNITY FUNNEL                    ENTERPRISE FUNNEL

GitHub visitor     (100%)           Community user referral  (100%)
       |                                    |
       v                                    v
README reader      (60%)            Enterprise page visit    (40%)
       |                                    |
       v                                    v
Download/install   (25%)            Trial request            (20%)
       |                                    |
       v                                    v
First triage       (20%)            Trial activation         (15%)
       |                                    |
       v                                    v
Repeat user (7d)   (12%)            Multi-device triage      (10%)
       |                                    |
       v                                    v
Monthly active     (8%)             Purchase decision        (6%)
       |                                    |
       v                                    v
Evangelist         (2%)             Team deployment          (5%)
```

---

## 8. Implementation Priorities

### 8.1 Critical Path Items

| Priority | Journey Element | Implementation Reference | Status |
|----------|-----------------|-------------------------|--------|
| **P0** | First-run progress output (streaming phases with record counts) | CLI output module | Planned |
| **P0** | Error messages with actionable recovery steps | Error handling module | Planned |
| **P0** | HTML report with Story + Explore tabs | Report generator | Built |
| **P0** | <35 second triage performance budget | Core triage pipeline | Built |
| **P1** | Multiple output formats (TLN, CSV, JSONL, XML, body, SQLite) | Output formatters | Built |
| **P1** | Ghost recovery with inline count reporting | USN ghost recovery module | Built |
| **P1** | Shell completion support (bash, zsh, fish) | CLI framework | Planned |
| **P2** | Batch processing with glob support | CLI argument parsing | Planned |
| **P2** | `--enterprise-info` flag with upgrade information | CLI help system | Planned |
| **P2** | Enterprise multi-device correlation view | Enterprise tier | Planned |
| **P3** | Velociraptor collection integration | Enterprise tier | Planned |
| **P3** | RBAC and case assignment | Enterprise tier | Planned |

### 8.2 CLI-Specific Accessibility Considerations

| Journey Phase | Concern | Design Response |
|---------------|---------|-----------------|
| **All phases** | Screen reader compatibility with terminal output | Use structured output (no ANSI art for critical info); provide `--no-color` and `--plain` flags |
| **All phases** | High-contrast terminal output | Respect `NO_COLOR` environment variable; test with light and dark terminal themes |
| **Progress output** | Non-visual progress indication | Include percentage and elapsed time in plain text, not just progress bars |
| **Error messages** | Clear screen reader announcements | Errors on stderr with consistent prefix `ERROR:` or `WARNING:`; no emoji in error output |
| **HTML report** | WCAG 2.1 AA compliance | Semantic HTML; keyboard navigation; skip links; alt text for visualizations; high-contrast mode |
| **HTML report** | Screen reader navigation | ARIA landmarks; heading hierarchy; table captions; focus management on tab switch |
| **Documentation** | Accessible README and docs | Clear heading structure; code blocks with language labels; alt text for diagrams |

---

## Validation Checklist

- [x] First-time user journey mapped with 7 phases and emotional states
- [x] Returning user journey with power user patterns documented
- [x] Enterprise upgrade journey with trigger mapping and emotional arc
- [x] Enterprise daily workflow with multi-analyst coordination
- [x] Error recovery journey with 7 error types and recovery actions
- [x] 3 persona-specific variations (Alex, Sarah, James)
- [x] 8 KPIs defined with targets and measurement methods
- [x] Emotional measurement touchpoints mapped
- [x] Implementation priorities with P0-P3 ranking
- [x] CLI-specific accessibility considerations (not web-centric)
- [x] All journeys aligned with CLI-first, offline-capable architecture
- [x] No placeholder text or TODO markers
- [x] Cross-references to NORTHSTAR.md, BRAND_GUIDELINES.md, NORTHSTAR_EXTRACT.md
