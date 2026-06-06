# usnjrnl-forensic: Wireframes

> **Version:** 1.0
> **Last updated:** 2026-03-09
> **Surfaces:** CLI terminal, HTML report
> **Cross-references:** USER_JOURNEYS.md (5a), DESIGN_SYSTEM.md (5b), ACCESSIBILITY.md (5c)

## Document Purpose

This document provides **visual wireframe specifications** for the two output surfaces of usnjrnl-forensic:

1. **CLI terminal output** -- the interactive experience during processing
2. **HTML triage report** -- the self-contained, single-file forensic report

Since usnjrnl-forensic is a CLI tool with HTML report output (not a web/mobile application), "wireframes" here means ASCII art layouts of terminal output structure and HTML report sections.

**Relationship to Other Documents:**
- **USER_JOURNEYS.md** defines the emotional arc (skepticism to confidence) we design for
- **DESIGN_SYSTEM.md** provides CSS tokens and component specifications
- **ACCESSIBILITY.md** provides WCAG AA requirements per component
- **BRAND_GUIDELINES.md** provides voice validation criteria
- **This document** translates those strategies into concrete visual layouts

---

## 1. Overview

### 1.1 Output Surfaces

| Surface | Technology | User Context |
|---------|-----------|--------------|
| CLI terminal (stderr) | Rust + indicatif | Forensic examiner running triage at the console |
| HTML report (file) | Self-contained HTML/CSS/JS | Examiner reviewing findings in browser; printed for court exhibits |

### 1.2 Design Token References

All specifications reference tokens from the design system:

- **Colors**: `#0d1117` (bg-primary), `#161b22` (bg-surface), `#e6edf3` (text-primary), `#7d8590` (text-secondary), `#58a6ff` (accent), `#f85149` (critical), `#d29922` (warning), `#3fb950` (success), `#bc8cff` (recovered)
- **Typography**: `ui-monospace, SFMono-Regular, Menlo, Consolas, monospace` at 13px base
- **Spacing**: 4px increment grid; 12px gap between stat cards; 24px container padding
- **Components**: stat-card, triage-card, triage-badge, tab-bar, evidence-table, search-input, source-pill

### 1.3 Triage Category Map

The 12 triage questions are organized into 5 categories that drive the Story tab layout:

| Category | Questions | IDs |
|----------|-----------|-----|
| What Happened (1-3) | How was the system compromised? / What malware or tools are on the system? / What programs did the attacker run? | `initial_access`, `malware_deployed`, `execution_evidence` |
| Business Impact (4-6) | Was sensitive data accessed? / Was data staged for theft? / Were credentials compromised? | `sensitive_data`, `data_staging`, `credential_access` |
| Ongoing Risk (7-8) | Do backdoors or persistence mechanisms remain? / Did the attacker move to other systems? | `persistence`, `lateral_movement` |
| Cover-Up (9-11) | Did the attacker destroy evidence? / Were file timestamps manipulated? / Were files disguised or hidden? | `evidence_destruction`, `timestomping`, `file_disguise` |
| Recovery (12) | What did we recover that the attacker deleted? | `recovered_evidence` |

---

## 2. CLI Terminal Output Wireframes

### 2.1 Startup Banner

Displayed immediately when the tool launches. Shows version, input source, and enabled features.

```
┌──────────────────────────────────────────────────────────────────────┐
│                                                                      │
│  usnjrnl-forensic v0.5.0                                             │
│  ──────────────────────────────────────────────────────────          │
│  Image:     DESKTOP-SDN1RPT.E01                                      │
│  Features:  rewind | triage | carve-unallocated | timestomping        │
│  Output:    triage.html                                              │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

**Specifications:**
- Rendered to **stderr** so stdout remains clean for piped data output
- Tool name in bold (ANSI `\x1b[1m`) when TTY detected
- Feature list derived from CLI flags: `--image` enables rewind, `--carve-unallocated` enables carving, `--detect-timestomping` enables timestomping
- Suppressed entirely when `stderr` is not a TTY (piped/redirected)
- Respects `NO_COLOR` environment variable per no-color.org convention

**Accessibility:**
- Non-TTY fallback: plain `[INFO]` prefixed lines, no box drawing characters
- Screen reader compatible: no overwriting lines, consistent prefix structure

### 2.2 Progress Display

Multi-phase progress bars shown during processing. Uses the `indicatif` crate.

```
┌──────────────────────────────────────────────────────────────────────┐
│                                                                      │
│  [1/5] Extracting artifacts from E01...                              │
│        [=================>                    ] 67%  34.2 MB/s       │
│                                                                      │
│  [2/5] Parsing $UsnJrnl:$J...                                        │
│        [========================================] 100%  142,847 recs │
│                                                                      │
│  [3/5] Building rewind tree from $MFT...                             │
│        [=============================>         ] 78%  1.2M entries   │
│                                                                      │
│  [4/5] Resolving full paths...                                       │
│        [===>                                   ] 12%  17,441 done    │
│                                                                      │
│  [5/5] Running triage queries...                                     │
│        [========================================] 100%  12/12 done   │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

**Specifications:**
- Phase counter `[N/5]` provides clear progress through the pipeline
- Each bar shows: percentage, throughput or record count
- Bars are rendered on stderr; stdout is reserved for data output formats
- Phase count adapts: 5 phases with `--image`, 3 phases with `--journal` only
- Colors: phase label in white bold, bar fill in `#58a6ff` (accent), percentage in `#7d8590` (secondary)

**Accessibility (non-TTY degradation):**
```
[INFO] [1/5] Extracting artifacts from E01...
[INFO] [1/5] Extraction: 25% complete
[INFO] [1/5] Extraction: 50% complete
[INFO] [1/5] Extraction: 75% complete
[INFO] [1/5] Extraction: 100% complete
[INFO] [2/5] Parsing $UsnJrnl:$J...
[INFO] [2/5] Parsing: 142,847 records parsed
```

### 2.3 Completion Summary

Displayed after all processing completes. Provides the key numbers an examiner needs at a glance.

```
┌──────────────────────────────────────────────────────────────────────┐
│                                                                      │
│  ── Results ────────────────────────────────────────────────          │
│                                                                      │
│  Records parsed:     142,847                                         │
│    Active (MFT):     118,203                                         │
│    Entry-carved:      23,441                                         │
│    Ghost ($LogFile):   1,203                                         │
│                                                                      │
│  Path resolution:    142,847 / 142,847 (100.0%)                      │
│  Triage hits:        1,247 across 9 of 12 questions                  │
│  Timestomping:       3 suspicious files flagged                      │
│                                                                      │
│  Time elapsed:       34.7s                                           │
│                                                                      │
│  ── Output Files ───────────────────────────────────────────          │
│                                                                      │
│  Report:   triage.html                                               │
│  CSV:      output.csv                                                │
│  SQLite:   output.sqlite                                             │
│                                                                      │
│  [*] Open triage.html in your browser to review findings             │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

**Specifications:**
- Record counts use comma-separated formatting for readability
- Path resolution shows fraction and percentage -- 100% is the expected result with rewind
- Triage hits show total match count and how many of the 12 questions had findings
- Output file paths are relative to CWD for easy copy-paste
- Final hint line uses `[*]` prefix and suggests opening the report
- Colors: labels in `#7d8590`, values in `#e6edf3`, hint line in `#58a6ff`

**Accessibility (non-TTY):**
```
[INFO] Records parsed: 142,847
[INFO]   Active (MFT): 118,203
[INFO]   Entry-carved: 23,441
[INFO]   Ghost ($LogFile): 1,203
[INFO] Path resolution: 142,847 / 142,847 (100.0%)
[INFO] Triage hits: 1,247 across 9 of 12 questions
[INFO] Timestomping: 3 suspicious files flagged
[INFO] Time elapsed: 34.7s
[INFO] Report written to: triage.html
```

### 2.4 Error Output

Structured error messages with context and recovery suggestions.

```
┌──────────────────────────────────────────────────────────────────────┐
│                                                                      │
│  [ERROR] Failed to open disk image                                   │
│                                                                      │
│  Path:   /evidence/DESKTOP-SDN1RPT.E01                               │
│  Reason: Permission denied (os error 13)                             │
│                                                                      │
│  Try:                                                                │
│    - Run with elevated privileges: sudo usnjrnl-forensic ...         │
│    - Check file permissions: ls -la /evidence/DESKTOP-SDN1RPT.E01    │
│    - Verify the file is not locked by another process                │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

**Error Types and Recovery Guidance:**

| Error | Context Shown | Recovery Suggestion |
|-------|--------------|---------------------|
| Image open failed | Path, OS error | Check permissions, run with sudo |
| No NTFS partition found | Image path, partitions found | Verify image contains NTFS, try `--output-dir` to inspect |
| Journal not found | Extraction path | Provide raw `--journal` path, check volume is NTFS |
| MFT parse error | Offset, expected vs actual | File may be corrupt; try `--carve-unallocated` |
| Output write failed | Output path, OS error | Check disk space, check directory exists |

**Specifications:**
- `[ERROR]` prefix in `#f85149` (critical red) when TTY, plain text otherwise
- Path and reason on separate labeled lines for easy parsing
- Recovery suggestions are actionable commands the user can copy-paste
- Errors go to stderr; exit code is non-zero
- `[WARN]` prefix in `#d29922` for non-fatal issues (e.g., "MFT entry reallocated, using rewind path")

---

## 3. HTML Report Layout Wireframes

### 3.1 Full Page Layout

The HTML report is a single self-contained file (no external dependencies) with this overall structure:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ ┌──────────────────────────────────────────────────────────────────────────┐ │
│ │                           HEADER                                        │ │
│ │  usnjrnl-forensic   RAPID TRIAGE REPORT                                │ │
│ │  Image: DESKTOP-SDN1RPT.E01 | Generated: 2026-03-09 14:23:07 UTC      │ │
│ └──────────────────────────────────────────────────────────────────────────┘ │
│ ┌──────────────────────────────────────────────────────────────────────────┐ │
│ │                         STAT BAR                                        │ │
│ │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐     │ │
│ │  │  TOTAL   │ │  ACTIVE  │ │  CARVED  │ │  GHOST   │ │  TRIAGE  │     │ │
│ │  │ 142,847  │ │ 118,203  │ │  23,441  │ │   1,203  │ │   1,247  │     │ │
│ │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘     │ │
│ └──────────────────────────────────────────────────────────────────────────┘ │
│ ┌──────────────────────────────────────────────────────────────────────────┐ │
│ │  [ Story ]  [ Explore ]                              TAB BAR           │ │
│ └──────────────────────────────────────────────────────────────────────────┘ │
│ ┌──────────────────────────────────────────────────────────────────────────┐ │
│ │                                                                          │ │
│ │                       TAB CONTENT AREA                                   │ │
│ │                    (Story or Explore tab)                                │ │
│ │                                                                          │ │
│ │                        ~80vh height                                      │ │
│ │                                                                          │ │
│ └──────────────────────────────────────────────────────────────────────────┘ │
│ ┌──────────────────────────────────────────────────────────────────────────┐ │
│ │  Generated by usnjrnl-forensic v0.5.0           FOOTER                 │ │
│ └──────────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────────┘
```

**Specifications:**
- Max width: 1400px, centered with `margin: 0 auto`
- Container padding: 24px horizontal
- Background: `#0d1117` (bg-primary)
- All content, CSS, and JS in a single `.html` file -- no external requests
- Semantic landmarks: `<header role="banner">`, `<main role="main">`, `<footer role="contentinfo">`
- Skip link: `<a class="skip-link" href="#triage-results">Skip to triage results</a>`

### 3.2 Header

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│  usnjrnl-forensic          RAPID TRIAGE REPORT                              │
│  ──────────────────────────────────────────────────────────────────          │
│  Image: DESKTOP-SDN1RPT.E01 | Generated: 2026-03-09 14:23:07 UTC           │
│  142,847 records | Rewind: 100% resolved | Triage: 9/12 questions hit       │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

**Specifications:**
- Tool name: 14px, `#7d8590` (secondary), 0.5px letter spacing
- Report title: 22px bold, `#e6edf3` (primary), 1px letter spacing
- Subtitle line: 12px, `#7d8590` with data values in `#58a6ff` (accent)
- Bottom border: 1px solid `#30363d`
- ARIA: `<header role="banner">` with `<h1>` containing tool name and report title

### 3.3 Stat Bar

Five stat cards in a horizontal grid showing key metrics at a glance.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐
│  │ TOTAL RECS  │  │   ACTIVE    │  │   CARVED    │  │    GHOST    │  │  TRIAGE    │
│  │             │  │             │  │             │  │             │  │   HITS     │
│  │  142,847    │  │  118,203    │  │   23,441    │  │    1,203    │  │   1,247    │
│  │  (blue)     │  │  (cyan)     │  │  (purple)   │  │   (red)     │  │  (green)   │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘  └────────────┘
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

**Specifications:**
- Grid: `grid-template-columns: repeat(5, 1fr)` with 12px gap (adapting from the 4-column existing layout to include triage hits)
- Card background: `#161b22` (bg-surface), border: 1px solid `#30363d`, border-radius: 8px
- Label: 11px uppercase, `#7d8590`, 0.8px letter spacing
- Value: 28px bold, color varies by card:
  - Total Records: `#58a6ff` (blue)
  - Active: `#79c0ff` (cyan)
  - Carved: `#bc8cff` (purple)
  - Ghost: `#f85149` (red)
  - Triage Hits: `#3fb950` (green)
- Hover: border transitions to `#484f58`
- ARIA: `role="group" aria-label="Key metrics"`, each card has `aria-label="Label: Value"`
- Responsive: collapses to 2 columns at 768px, single column at 480px

### 3.4 Tab Bar

Two tabs controlling the main content area: Story (default) and Explore.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│  ┌─────────────────┐  ┌─────────────────┐                                   │
│  │     Story        │  │    Explore       │                                  │
│  │  (active: blue   │  │  (inactive:      │                                  │
│  │   bg, dark text) │  │   dark bg,       │                                  │
│  │                  │  │   gray border)   │                                  │
│  └─────────────────┘  └─────────────────┘                                   │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

**Specifications:**
- Active tab: background `#58a6ff`, text `#0d1117`, border-color `#58a6ff`
- Inactive tab: background `#21262d`, text `#7d8590`, border 1px solid `#30363d`
- Tab button: 12px uppercase, 600 weight, 10px 20px padding, 6px border-radius
- Hover (inactive): text `#e6edf3`, border-color `#484f58`
- ARIA: `role="tablist"` wrapper, each button has `role="tab"`, `aria-selected`, `aria-controls`
- Keyboard: Tab focuses tablist, Arrow Left/Right switches tabs, Enter/Space activates
- Tab panels: `role="tabpanel"` with `aria-labelledby` pointing to tab button

### 3.5 Story Tab -- Triage Question Cards

The Story tab displays 12 triage questions organized in 5 category sections. Each question is a card with a badge, evidence summary, and expandable evidence table.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│  ── What Happened ──────────────────────────────────────────────────────     │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  Q1: How was the system compromised?                        [YES]     │  │
│  │  ──────────────────────────────────────────────────────────────────    │  │
│  │  47 records matched | Downloads, Temp, AppData                        │  │
│  │                                                                        │  │
│  │  ┌─────────────┬──────────────────────────┬──────────┬────────────┐   │  │
│  │  │  Timestamp  │  File Path               │  Reason  │  Source    │   │  │
│  │  ├─────────────┼──────────────────────────┼──────────┼────────────┤   │  │
│  │  │  2026-01-15 │  Users\admin\Downloads\  │  CREATE  │ ALLOCATED  │   │  │
│  │  │  09:14:23   │  payload.exe             │          │            │   │  │
│  │  ├─────────────┼──────────────────────────┼──────────┼────────────┤   │  │
│  │  │  2026-01-15 │  Users\admin\AppData\    │  RENAME  │ ALLOCATED  │   │  │
│  │  │  09:14:25   │  Local\Temp\dropper.dll  │          │            │   │  │
│  │  └─────────────┴──────────────────────────┴──────────┴────────────┘   │  │
│  │                                                                        │  │
│  │  [View all 47 records in Explore tab ->]                              │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  Q2: What malware or tools are on the system?               [YES]     │  │
│  │  ──────────────────────────────────────────────────────────────────    │  │
│  │  23 records matched | System32, Temp, ProgramData                     │  │
│  │  ...                                                                   │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  Q3: What programs did the attacker run?                    [YES]     │  │
│  │  ...                                                                   │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ── Business Impact ────────────────────────────────────────────────────     │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  Q4: Was sensitive data accessed?                           [YES]     │  │
│  │  ...                                                                   │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  Q5: Was data staged for theft?                              [NO]     │  │
│  │  ──────────────────────────────────────────────────────────────────    │  │
│  │  0 records matched                                                     │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  Q6: Were credentials compromised?                          [YES]     │  │
│  │  ...                                                                   │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ── Ongoing Risk ───────────────────────────────────────────────────────     │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  Q7: Do backdoors or persistence mechanisms remain?         [YES]     │  │
│  │  ...                                                                   │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  Q8: Did the attacker move to other systems?                 [NO]     │  │
│  │  ...                                                                   │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ── Cover-Up ───────────────────────────────────────────────────────────     │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  Q9: Did the attacker destroy evidence?                     [YES]     │  │
│  │  ...                                                                   │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  Q10: Were file timestamps manipulated?                     [YES]     │  │
│  │  ...                                                                   │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  Q11: Were files disguised or hidden?                       [YES]     │  │
│  │  ...                                                                   │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ── Recovery ───────────────────────────────────────────────────────────     │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  Q12: What did we recover that the attacker deleted?        [INFO]    │  │
│  │  ──────────────────────────────────────────────────────────────────    │  │
│  │  24,644 carved + ghost records recovered                               │  │
│  │  ...                                                                   │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

**Triage Card Anatomy:**

```
┌──────────────────────────────────────────────────────────────────────┐
│                                                                      │
│   Question text (h3)                                  [BADGE]        │
│   ─────────────────────────────────────────────                      │
│   N records matched | path context summary                           │
│                                                                      │
│   ┌────────────┬────────────────────────┬─────────┬──────────┐      │
│   │ Timestamp  │ File Path              │ Reason  │ Source   │      │
│   ├────────────┼────────────────────────┼─────────┼──────────┤      │
│   │ ...        │ ...                    │ ...     │ ...      │      │
│   └────────────┴────────────────────────┴─────────┴──────────┘      │
│                                                                      │
│   [View all N records in Explore tab ->]                             │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

**Badge Variants:**

| Badge | Background | Text Color | Meaning |
|-------|-----------|------------|---------|
| `YES` | `rgba(248,81,73,0.15)` | `#f85149` | Records matched -- findings exist |
| `NO` | `rgba(63,185,80,0.15)` | `#3fb950` | No records matched -- clean |
| `INFO` | `rgba(88,166,255,0.15)` | `#58a6ff` | Informational (used for Q12 recovery) |

**Specifications:**
- Card background: `#161b22`, border: 1px solid `#30363d`, border-radius: 8px, padding: 16px
- Question text: 14px bold, `#e6edf3`
- Match summary: 12px, `#7d8590`
- Evidence table: shows top 5 records; "View all in Explore" link for full list
- Source column uses pill badges: `ALLOCATED` (default), `ENTRY-CARVED` (purple `#bc8cff`), `GHOST` (red `#f85149`)
- Cards with `YES` badge show evidence table expanded by default
- Cards with `NO` badge are collapsed (summary only)
- ARIA: `role="article"`, `aria-label` with question text, `aria-expanded` for expand/collapse
- Badge: `role="status"`, `aria-label="Answer: Yes"` (or No/Info)

### 3.6 Explore Tab -- Full Evidence Table

The Explore tab provides a complete timeline workbench with search, filtering, and sorting.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│  ┌───────────────┐  ┌──────────────────────────────────────────────────────┐│
│  │               │  │                                                      ││
│  │   SIDEBAR     │  │                  MAIN TABLE                          ││
│  │               │  │                                                      ││
│  │  ┌─────────┐  │  │  ┌──────────────────────────────────────────────┐   ││
│  │  │ Search  │  │  │  │  Showing 1,247 of 142,847 records           │   ││
│  │  │ [     ] │  │  │  └──────────────────────────────────────────────┘   ││
│  │  └─────────┘  │  │                                                      ││
│  │               │  │  ┌──────────────────────────────────────────────┐   ││
│  │  REASON FLAGS │  │  │ Timestamp | File     | Path   | Reason | Src │   ││
│  │  ┌─────────┐  │  │  ├──────────┼──────────┼────────┼────────┼─────┤   ││
│  │  │☑ CREATE │  │  │  │ 01-15    │ payload  │ Users\ │ CREATE │ ALO │   ││
│  │  │☑ DELETE │  │  │  │ 09:14:23 │ .exe     │ admin\ │        │ CTD │   ││
│  │  │☑ RENAME │  │  │  ├──────────┼──────────┼────────┼────────┼─────┤   ││
│  │  │☑ DATA   │  │  │  │ 01-15    │ dropper  │ Temp\  │ RENAME │ ALO │   ││
│  │  │☑ SEC    │  │  │  │ 09:14:25 │ .dll     │        │        │ CTD │   ││
│  │  │☑ INFO   │  │  │  ├──────────┼──────────┼────────┼────────┼─────┤   ││
│  │  │☑ ADS    │  │  │  │ ...      │ ...      │ ...    │ ...    │ ... │   ││
│  │  └─────────┘  │  │  └──────────┴──────────┴────────┴────────┴─────┘   ││
│  │               │  │                                                      ││
│  │  SOURCE       │  │  ┌──────────────────────────────────────────────┐   ││
│  │  ┌─────────┐  │  │  │  < Page 1 of 57 >   25 per page            │   ││
│  │  │☑ Active │  │  │  └──────────────────────────────────────────────┘   ││
│  │  │☑ Carved │  │  │                                                      ││
│  │  │☑ Ghost  │  │  └──────────────────────────────────────────────────────┘│
│  │  └─────────┘  │                                                          │
│  │               │                                                          │
│  │  SPARKLINE    │                                                          │
│  │  ┌─────────┐  │                                                          │
│  │  │ ▁▂▃█▅▁▁ │  │                                                          │
│  │  │ 00  12  │  │                                                          │
│  │  └─────────┘  │                                                          │
│  │               │                                                          │
│  └───────────────┘                                                          │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

**Specifications:**

**Layout:**
- Grid: `grid-template-columns: 240px 1fr` with 16px gap
- Sidebar: fixed 240px, `#161b22` background, 1px solid `#30363d` border, 8px border-radius

**Search Input:**
- Full width within sidebar, `#0d1117` background, 1px solid `#30363d` border
- Placeholder: "Search filenames, paths..." in `#484f58`
- Focus: border transitions to `#58a6ff`
- ARIA: `<label>` element, `aria-describedby` for hints, results announced via `aria-live="polite"` region

**Reason Flag Filters:**
- Checkbox list: CREATE, DELETE, RENAME, DATA_CHANGE, SECURITY_CHANGE, BASIC_INFO_CHANGE, NAMED_DATA (ADS)
- Each checkbox toggles a reason flag filter
- ARIA: `aria-label` on each filter, changes announced via live region

**Source Filters:**
- Checkbox list: Active (allocated MFT), Carved (entry-carved from unallocated), Ghost ($LogFile recovered)
- Source pills in table use colored backgrounds:
  - `ALLOCATED`: default dark background
  - `ENTRY-CARVED`: `#bc8cff` purple background at 15% opacity, purple text
  - `GHOST`: `#f85149` red background at 15% opacity, red text

**Sparkline:**
- 24-hour activity histogram using Unicode block characters
- ARIA: `role="img"` with `aria-label` describing peak activity time and count
- Example label: "Activity peak at 14:23 with 847 events"

**Data Table:**
- Columns: Timestamp, Filename, Full Path, Reason Flags, Source, USN (record number)
- Sortable columns: click header to sort, `aria-sort` attribute updates
- Row hover: background transitions to `#1c2129`
- Table headers: `<th scope="col">` for screen reader association
- Pagination: 25 records per page, page navigation at bottom

**Status Bar:**
- Shows "Showing N of M records" -- updates live as filters change
- ARIA: `aria-live="polite"` so screen readers announce filter result changes

### 3.7 Print View (Court Exhibits)

When printed or `@media print` activates, the report switches to a light theme optimized for paper and photocopies.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│  usnjrnl-forensic -- Rapid Triage Report                 [LIGHT THEME]      │
│  ═══════════════════════════════════════                                     │
│  Image: DESKTOP-SDN1RPT.E01                                                 │
│  Generated: 2026-03-09 14:23:07 UTC                                         │
│  Tool version: v0.5.0                                                        │
│                                                                              │
│  ── Evidence Summary ───────────────────────────────────────────────         │
│                                                                              │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐               │
│  │ Total      │ │ Active     │ │ Carved     │ │ Ghost      │               │
│  │ 142,847    │ │ 118,203    │ │ 23,441     │ │ 1,203      │               │
│  │ [#f5f5f5]  │ │ [#f5f5f5]  │ │ [#f5f5f5]  │ │ [#f5f5f5]  │               │
│  └────────────┘ └────────────┘ └────────────┘ └────────────┘               │
│                                                                              │
│  ── What Happened ──────────────────────────────────────────────            │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────┐           │
│  │ Q1: How was the system compromised?              [YES]       │           │
│  │                                                               │           │
│  │ 47 records matched                                            │           │
│  │                                                               │           │
│  │ Timestamp        | File Path            | Reason | Source     │           │
│  │ ─────────────────┼──────────────────────┼────────┼─────────  │           │
│  │ 2026-01-15 09:14 | Downloads\payload... | CREATE | ALLOCATED │           │
│  │ ...                                                           │           │
│  └──────────────────────────────────────────────────────────────┘           │
│                                                         [page break]         │
│  ── Business Impact ────────────────────────────────────────────            │
│  ...                                                                         │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

**Specifications:**
- Background: `#ffffff`, text: `#1a1a1a`, font-size: 10pt
- Stat cards: `#f5f5f5` background, 1px solid `#333333` border
- Triage cards: white background, 1px solid `#333333` border, `break-inside: avoid`
- Badges: 2px solid `#1a1a1a` border, bold text; YES gets `#e6f4ea` background, NO gets `#f5f5f5`, CRITICAL gets `#fce8e6`
- Links: underlined with href printed inline `a::after { content: " (" attr(href) ")" }`
- **Hidden elements**: tab buttons, Explore tab, search bar, filter bar (`display: none`)
- **Forced visible**: Story tab content with all cards expanded
- **Page breaks**: `break-inside: avoid` on triage cards, `break-after: avoid` on h2 headings
- **Court exhibit requirements**: case identifier and tool version repeat in page header; all timestamps include timezone; all data legible in grayscale photocopy

---

## 4. Screen States

### 4.1 Loading / Processing States

**CLI: Image extraction in progress**
```
  [1/5] Extracting artifacts from E01...
        [=================>                    ] 67%  34.2 MB/s
```

**HTML Report: No loading states** -- the report is pre-rendered static HTML. All data is embedded at generation time. No async loading, no spinners, no skeleton screens.

### 4.2 Empty States

**CLI: No triage hits**
```
  ── Results ────────────────────────────────────────────────
  Records parsed:     142,847
  Triage hits:        0 across 0 of 12 questions

  [*] No triage findings -- this may indicate a clean system
      or that the attack used techniques not covered by
      the built-in queries.
```

**HTML Report: Empty triage card (no matches)**
```
┌──────────────────────────────────────────────────────────────────────┐
│                                                                      │
│  Q5: Was data staged for theft?                              [NO]    │
│  ──────────────────────────────────────────────────────────          │
│  0 records matched                                                   │
│                                                                      │
│  No archive files (zip, 7z, rar, tar, gz, cab) were created          │
│  or renamed in user-accessible directories.                          │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

**HTML Report: Empty Explore tab (all records filtered out)**
```
┌──────────────────────────────────────────────────────────────────────┐
│                                                                      │
│  Showing 0 of 142,847 records                                        │
│                                                                      │
│  No records match the current filters.                               │
│  Try adjusting search terms or enabling more reason flags.           │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

### 4.3 Error States

**HTML Report: No errors possible** -- the report is a static file. If generation fails, the CLI error output (section 2.4) handles it. There are no runtime errors in the HTML report itself.

---

## 5. Component Quick Reference

### 5.1 Stat Cards

```
┌─────────────────┐
│  LABEL           │   11px uppercase, #7d8590, 0.8px letter-spacing
│  VALUE           │   28px bold, color varies by card type
│                  │   Background: #161b22, Border: 1px #30363d
│                  │   Border-radius: 8px, Padding: 16px
└─────────────────┘
```

### 5.2 Triage Cards

```
┌──────────────────────────────────────────┐
│  Question (h3, 14px bold)     [BADGE]    │   Background: #161b22
│  ────────────────────────────            │   Border: 1px #30363d
│  N records matched (12px, #7d8590)       │   Border-radius: 8px
│                                           │   Padding: 16px
│  Evidence table (top 5 rows)             │
│  [View all in Explore ->]                │
└──────────────────────────────────────────┘
```

### 5.3 Source Pills

```
  ┌───────────┐   Default: dark bg, #e6edf3 text
  │ ALLOCATED │
  └───────────┘

  ┌───────────────┐   Purple: rgba(188,140,255,0.15), #bc8cff text
  │ ENTRY-CARVED  │
  └───────────────┘

  ┌───────────┐   Red: rgba(248,81,73,0.15), #f85149 text
  │   GHOST   │
  └───────────┘
```

### 5.4 Tab Buttons

```
  ┌──────────┐ ┌──────────┐
  │  Active  │ │ Inactive │
  │ #58a6ff  │ │ #21262d  │
  │ bg, dark │ │ bg, gray │
  │ text     │ │ text     │
  └──────────┘ └──────────┘
  12px uppercase, 600 weight, 10px/20px padding, 6px radius
```

### 5.5 Evidence Tables

```
  ┌────────────┬──────────────┬──────────┬──────────┐
  │ Timestamp  │ File Path    │ Reason   │ Source   │   Headers: 11px uppercase
  ├────────────┼──────────────┼──────────┼──────────┤   #7d8590, sticky top
  │ data       │ data         │ data     │ pill     │   Cells: 13px, #e6edf3
  │ data       │ data         │ data     │ pill     │   Row hover: #1c2129
  └────────────┴──────────────┴──────────┴──────────┘   Border: 1px #30363d
```

---

## 6. Brand Voice Validation Checklist

### 6.1 Per-Surface Validation

| Surface | Voice Check | Pass Criteria |
|---------|------------|---------------|
| CLI startup banner | Professional, no fluff | Tool name + version + facts only, no marketing language |
| CLI progress | Informative, precise | Phase counter + metric (records, bytes), no vague "working..." |
| CLI completion | Actionable summary | Key numbers labeled, next-step hint, no "congratulations" |
| CLI errors | Direct, helpful | What failed + why + what to do, no blame, no apology |
| HTML header | Authoritative, concise | Tool name + report title + case metadata, no decoration |
| HTML stat cards | Data-first | Label + number, no adjectives, no color without text |
| HTML triage cards | Evidence-driven | Question + answer + evidence, no speculation |
| HTML Explore tab | Power-user ready | Search + filter + sort, no tutorials, no hand-holding |
| HTML print view | Court-ready | All data legible, case ID on every page, timestamps with timezone |

### 6.2 Banned Elements (Kill List)

These elements must NOT appear in any output surface:

- Decorative ASCII art or logos (the tool name IS the brand)
- Marketing language ("revolutionary", "powerful", "industry-leading")
- Animated transitions or fade effects in the HTML report
- Loading spinners in the static HTML (it is pre-rendered)
- Tooltips that hide critical information
- Modal dialogs or popups
- External resource requests (fonts, analytics, CDNs)
- Emoji in any output (CLI or HTML)
- "AI-powered" or "intelligent" language
- Rounded avatar or mascot elements
- Gradient backgrounds or glass-morphism effects

---

## 7. Implementation Priority

### P0 -- MVP (Blocks Release)

- [ ] CLI startup banner with version, image path, features
- [ ] CLI multi-phase progress bars (indicatif)
- [ ] CLI completion summary with record counts and output paths
- [ ] CLI structured error messages with recovery suggestions
- [ ] HTML report header with case metadata
- [ ] HTML stat bar with 5 metric cards
- [ ] HTML Story tab with 12 triage question cards in 5 categories
- [ ] HTML Explore tab with full evidence table, search, and pagination
- [ ] HTML tab switching (Story / Explore)
- [ ] Source pills (ALLOCATED / ENTRY-CARVED / GHOST) in all tables

### P1 -- Core Experience (Next Release)

- [ ] HTML reason flag filter checkboxes in Explore sidebar
- [ ] HTML source filter checkboxes in Explore sidebar
- [ ] HTML sparkline activity histogram
- [ ] HTML column sorting with `aria-sort` indicators
- [ ] HTML `@media print` light theme for court exhibits
- [ ] CLI non-TTY fallback (plain `[INFO]` lines, no ANSI)
- [ ] CLI `NO_COLOR` environment variable support
- [ ] Keyboard navigation: Arrow keys for tabs, `j`/`k` for triage cards, `/` for search

### P2 -- Polish (Future)

- [ ] HTML `@media (prefers-reduced-motion: reduce)` support
- [ ] HTML `@media (forced-colors: active)` high contrast mode
- [ ] HTML responsive breakpoints for mobile/tablet viewing
- [ ] CLI `TERM=dumb` degradation to simplest output
- [ ] "View all in Explore" links from triage cards pre-filter the Explore tab

---

## Validation Schema

```yaml
inputs_required:
  # From USER_JOURNEYS (5a)
  - journeys.first_time_triage: phases, emotional_states, friction_points
  - journeys.repeat_triage: power_user_patterns
  - journeys.error_recovery: error_type_mapping

  # From UI_DESIGN_SYSTEM (5b)
  - design.colors: semantic_palette
  - design.typography: font_family, sizes
  - design.components: stat_card, triage_card, tab_bar, evidence_table, source_pill

  # From ACCESSIBILITY (5c)
  - a11y.wcag_aa: color_contrast_pairs
  - a11y.screen_reader: landmark_structure, aria_patterns
  - a11y.keyboard: tab_navigation, focus_indicators
  - a11y.print: court_exhibit_theme
  - a11y.cli: tty_detection, no_color, non_tty_fallback

  # From BRAND_GUIDELINES (1)
  - brand.voice: professional, evidence_driven, no_fluff
  - brand.kill_list: banned_elements

outputs_produced:
  - wireframes.cli_screens: startup_banner, progress_display, completion_summary, error_output
  - wireframes.html_sections: header, stat_bar, tab_bar, story_tab, explore_tab, print_view
  - wireframes.component_specs: stat_card, triage_card, source_pill, tab_button, evidence_table
  - wireframes.screen_states: loading, empty, error
  - wireframes.brand_validation: per_surface_checklist, banned_elements
  - wireframes.implementation_priority: p0_p1_p2

validation_gate:
  required_sections:
    - "Overview"
    - "CLI Terminal Output Wireframes"
    - "HTML Report Layout Wireframes"
    - "Screen States"
    - "Component Quick Reference"
    - "Brand Voice Validation Checklist"
    - "Implementation Priority"

  minimum_content:
    cli_screens: 4
    html_sections: 6
    component_specs: 5
    accessibility_items_per_screen: 3
    banned_elements: 5

cross_references:
  - triage_questions: must_match: queries.rs 12 builtin questions
  - color_tokens: must_match: design_system colors
  - aria_patterns: must_match: accessibility component requirements
  - print_theme: must_match: accessibility court exhibit spec
  - emotional_arc: must_align_with: user_journeys phases
```
