# Enterprise DFIR Tier Splitting Research

**Date:** 2026-03-09
**Purpose:** Research common features and UX patterns for enterprise DFIR tools, specifically for Security Ronin Katana's community/enterprise tier split.

---

## 1. Open-Core Tier Splitting in Security Tools

### Successful Patterns

#### Velociraptor (Fully Open Source)
- **Model:** 100% open source (no paid tier), maintained by Rapid7
- **Monetization:** Rapid7 monetizes via its broader platform; Velociraptor drives adoption
- **Lesson:** Pure open source builds massive community trust; monetization happens at the platform/services layer
- Source: [Rapid7 Velociraptor](https://www.rapid7.com/products/velociraptor/)

#### Elastic Security (Tiered Open-Core)
- **Free tier:** Core search, basic SIEM detection engine, RBAC, basic case management, CSPM, Kibana Lens
- **Gold (~$114/mo):** Advanced reporting, third-party incident response workflows, document-level security
- **Platinum (~$131/mo):** ML anomaly detection, prebuilt SIEM jobs, 24x7 support
- **Enterprise (~$184/mo):** Searchable snapshots, host response actions, cloud workload protection, AI insights
- **Pattern:** Core detection is free; ML, automation, and advanced response actions are paid
- Source: [Elastic Subscriptions](https://www.elastic.co/subscriptions), [Elastic Pricing](https://www.elastic.co/pricing)

#### Snyk (Per-Developer Open-Core)
- **Free:** Limited tests per product, basic scanning, individual developers
- **Team ($25/dev/mo):** Up to 10 licenses, more test volume
- **Enterprise (custom, ~$676-698/dev/yr):** SSO, custom roles, security policy management, Rich API, reports, on-prem registries, asset discovery
- **Pattern:** Free gets individuals hooked; enterprise gates SSO, RBAC, compliance features
- Source: [Snyk Plans](https://snyk.io/plans/), [Snyk Pricing Analysis](https://www.vendr.com/marketplace/snyk)

#### GitLab (Buyer-Based Open Core)
- **Free (self-managed):** Full CE features, unlimited users
- **Free (SaaS):** 5-user limit per namespace
- **Premium ($29/user/mo):** Merge request approvals, code owners, priority support
- **Ultimate ($99/user/mo):** SAST, DAST, container scanning, security dashboards, compliance
- **Pattern:** Security/compliance features gated to highest tier
- Source: [GitLab Pricing](https://about.gitlab.com/pricing/), [GitLab Free Tier FAQ](https://about.gitlab.com/pricing/faq-efficient-free-tier/)

### What Causes Community Backlash

| Trigger | Example | Outcome |
|---------|---------|---------|
| License change to restrict competitors | Elastic SSPL (2021) | AWS forked to OpenSearch; trust shattered |
| Removing previously free features | HashiCorp BSL (2023) | Community forked to OpenTofu |
| Tightening free tier limits | GitLab 5-user SaaS limit | Developer anger; perception of bait-and-switch |
| Gating essential security behind top tier | GitLab Ultimate-only SAST/DAST | Smaller teams feel forced into expensive plans |
| Tone-deaf communication | Elastic's Kendrick Lamar announcement | Community mockery and deeper distrust |

**Key Lesson for Security Ronin Katana:** Never move a feature from free to paid. Gate *new* capabilities behind enterprise. Keep the core analysis engine permanently free and open. Communicate transparently about what stays free forever.

Sources:
- [Socket.dev: Elasticsearch License Backlash](https://socket.dev/blog/developers-burned-by-elasticsearch-license-change-arent-going-back)
- [InfoQ: Elastic Returns to Open Source](https://www.infoq.com/news/2024/09/elastic-open-source-agpl/)
- [The New Stack: GitLab Free Tier Tightening](https://thenewstack.io/gitlabs-free-tier-belt-tightening-continues/)
- [Wikipedia: Open-core model](https://en.wikipedia.org/wiki/Open-core_model)
- [The New Stack: RIP Open Core](https://thenewstack.io/rip-open-core-long-live-open-source/)

---

## 2. Enterprise DFIR Workflow Features

### Case Management

| Feature | Tool Example | Description |
|---------|-------------|-------------|
| Centralized dashboard | Magnet Nexus | Single pane for all cases, real-time status |
| Case templates | Detego Case Manager | Pre-configured workflows per case type |
| Evidence intake tracking | DFIR-IRIS | Structured intake with alert correlation |
| Multi-case management | Magnet Nexus | 15-30 concurrent cases with assignment |
| Kanban task tracking | Detego Case Manager | Visual task boards with automation |

Sources:
- [Magnet Forensics: Enterprise Forensics](https://www.magnetforensics.com/blog/enterprise-forensics-why-scalable-solutions-matter/)
- [DFIR-IRIS](https://www.dfir-iris.org/)
- [Detego Case Manager Launch](https://www.forensicfocus.com/news/detego-global-launches-purpose-built-case-management-platform-for-digital-forensics-and-incident-response-teams/)

### RBAC Models in Forensic Tools

| Role | Permissions | Used By |
|------|------------|---------|
| **Examiner** | Analyze evidence, add annotations, run queries | All tools |
| **Reviewer** | Read-only access, approve/reject findings | Magnet Nexus, Detego |
| **Case Manager** | Assign cases, manage team workload, set priorities | Magnet Nexus, Detego |
| **Admin** | User management, system config, audit log access | All enterprise tools |
| **Legal/Compliance** | Read-only case reports, chain of custody docs | Magnet Nexus |

Sources:
- [Magnet AXIOM Features](https://www.magnetforensics.com/products/magnet-axiom/)
- [Detego Case Manager](https://hackread.com/detego-global-launches-case-management-platform-for-digital-forensics-and-incident-response-teams/)

### Evidence Chain of Custody

Essential requirements:
- **Timestamped action logging:** Every access, transfer, and analysis step recorded
- **Unique evidence identifiers:** Hash-based IDs for each evidence item
- **Access restriction:** Only authorized personnel can access evidence
- **Tamper-proof audit trail:** Immutable logs that can't be modified
- **Export-ready reports:** Court-admissible chain of custody documentation

Tools implementing this:
- **OpenText Endpoint Forensics:** Audit-ready reporting, tamper-proof collection
- **Detego Case Manager:** Timestamped notes, full audit trails, unbroken chain of custody
- **DFIR-IRIS Activities Module:** Full audit trail with millisecond timestamps, username, case association

Sources:
- [OpenText DFIR](https://solutions.opentext.com/cybersecurity/dfir/)
- [DFIR-IRIS Activities Module](https://certbar.com/technical-blogs/navigating-dfir-iris-part-2)

### Multi-Analyst Workflows

| Workflow Step | Description | Tool Example |
|--------------|-------------|--------------|
| Case assignment | Manager assigns case to examiner(s) | Magnet Nexus |
| Evidence distribution | Split data sources across analysts | Autopsy Multi-User |
| Concurrent analysis | Multiple analysts work same case | Autopsy (PostgreSQL), Timesketch |
| Annotation & tagging | Shared tags, comments, bookmarks | Timesketch |
| Peer review | Reviewer validates examiner findings | Detego Case Manager |
| Report approval | Manager/legal signs off on final report | Magnet Nexus |

Sources:
- [Autopsy Collaborative](https://www.autopsy.com/collaborative-autopsy-how-it-works/)
- [Timesketch](https://github.com/google/timesketch)

### Audit Logging Requirements

- Every user action logged with timestamp, username, and affected case
- Evidence access tracked (who viewed/exported what, when)
- Query/search history preserved for reproducibility
- Login/logout and session tracking
- Configuration changes logged
- Immutable logs (append-only, no deletion)

Source: [DFIR-IRIS Activities Module](https://certbar.com/technical-blogs/navigating-dfir-iris-part-2)

---

## 3. Collection Agent UX (Velociraptor Model)

### Remote Artifact Collection Workflows

1. **Online Collection (Client-Server):**
   - Agent (client) deployed as service on endpoints
   - Persistent connection back to server
   - Investigator tasks agents in real-time via web UI
   - Results streamed back and indexed
   - Source: [Velociraptor Overview](https://docs.velociraptor.app/docs/overview/)

2. **Offline Collection:**
   - Pre-configured binary with "baked in" instructions
   - No server connection required
   - Writes results to local encrypted collection container
   - Optional auto-upload to cloud storage
   - Useful for IR consultants without persistent agent access
   - Source: [Velociraptor Offline Collections](https://docs.velociraptor.app/docs/deployment/offline_collections/)

3. **Adaptive Collection (2025):**
   - Parses forensic artifacts on-endpoint
   - Locates and collects referenced files
   - More expensive but more thorough
   - Source: [Velociraptor Adaptive Collections](https://docs.velociraptor.app/blog/2025/2025-09-28-adaptive-collections/)

### Hunt Management

| Feature | Description |
|---------|-------------|
| Multi-endpoint hunts | Same artifact collected from many endpoints simultaneously |
| Label-based targeting | Dynamically assign hosts to hunts via labels |
| Offline endpoint scheduling | Hunts wait for endpoints to come online |
| Deduplication | Tracks which endpoints already collected |
| Hunt notebooks | VQL-powered analysis notebooks per hunt |
| Progress tracking | Real-time visibility into collection status |

Source: [Velociraptor Hunting](https://docs.velociraptor.app/docs/hunting/)

### Agent UX Expectations for IR Teams

- **One-click deployment:** Single binary, minimal configuration
- **Low resource footprint:** Minimal CPU/RAM impact on endpoints
- **Encrypted transport:** All evidence encrypted in transit
- **Platform coverage:** Windows, macOS, Linux at minimum
- **VQL (custom queries):** Extensible query language for custom artifacts
- **Integration with EDR:** Can complement or replace EDR collection

Sources:
- [CISA Velociraptor](https://www.cisa.gov/resources-tools/services/velociraptor)
- [Rapid7 Velociraptor](https://www.rapid7.com/products/velociraptor/)
- [Cyber Triage + Velociraptor Integration](https://docs.cybertriage.com/en/latest/chapters/integrations/velociraptor_collect.html)

---

## 4. Multi-Device Examination UX

### Timeline Merging Across Devices

| Approach | Description | Tool |
|----------|-------------|------|
| Unified timeline | All sources normalized into single chronological view | Timesketch, AXIOM |
| Source-tagged events | Each event tagged with origin device/source | Timesketch |
| Plaso/log2timeline | Parse multiple sources into single Plaso storage file | Plaso -> Timesketch |
| Cross-device filtering | Filter unified timeline by device, artifact type, time range | AXIOM, Oxygen |

### Cross-Device Correlation Patterns

- **Forensic Feature Extraction (FFE):** Extract features (emails, IPs, hashes) across all sources
- **Cross-Drive Analysis (CDA):** Statistical correlation across multiple disk images
- **Social graph construction:** Map relationships between entities across devices
- **Deletion detection:** Identify data deleted on one device but present on another
- **Location correlation:** Map geolocation data across devices and time

Sources:
- [ResearchGate: Cross-Drive Analysis](https://www.researchgate.net/publication/264543999_The_Potential_for_Cross-Drive_Analysis_Using_Automated_Digital_Forensic_Timelines)
- [Kroll: Mobile Forensics](https://www.kroll.com/en/publications/forensic-data-analysis-of-mobile-devices)
- [SANS FOR585](https://www.sans.org/cyber-security-courses/advanced-smartphone-mobile-device-forensics)

### Evidence Source Management UI Patterns

| Pattern | Description |
|---------|-------------|
| Source tree/sidebar | Hierarchical view of all evidence sources |
| Source badges | Color-coded indicators per source on timeline events |
| Evidence dashboard | Overview of all sources with status, hash, size, date added |
| Import wizard | Step-by-step evidence ingestion with format detection |
| Source comparison view | Side-by-side timeline comparison across sources |

### Tools Leading Multi-Device UX

| Tool | Strength |
|------|----------|
| **Magnet AXIOM** | Best-in-class multi-device correlation (computer + phone) |
| **Oxygen Forensic Detective** | Cloud + IoT + mobile aggregation, social graphing |
| **Cellebrite** | Fast mobile processing, clear reporting |
| **Timesketch** | Open-source collaborative timeline merging |

Sources:
- [Magnet AXIOM](https://www.magnetforensics.com/products/magnet-axiom/)
- [Timesketch](https://timesketch.org/)

---

## 5. PCAP/NetFlow Analysis UX in Forensic Context

### Arkime (formerly Moloch) Session Viewer

| Feature | Description |
|---------|-------------|
| Full packet capture at scale | Tens of Gbps, indexed in Elasticsearch |
| Session search | Query by IP, port, protocol, time range, country |
| Timeline scrubbing | Click-drag timeline to filter sessions by time |
| GeoIP enrichment | Country/ASN overlay on session data |
| TLS fingerprinting | JA3/JA3S/HASSH for client identification |
| PCAP/CSV export | Export filtered results for external analysis |
| Session detail view | Drill into individual session packets |

Source: [Arkime](https://arkime.com/), [GitHub: Arkime](https://github.com/arkime/arkime)

### NetworkMiner Evidence Presentation

| Feature | Description |
|---------|-------------|
| Passive host profiling | OS detection, open ports, hostnames from PCAP |
| File extraction | Reassemble transmitted files from packet data |
| Certificate extraction | Pull TLS certificates from traffic |
| Host-centric view | Organize network data by host, not by packet |
| Offline analysis | Parse PCAP files without live capture |

Source: [NetworkMiner](https://www.netresec.com/?page=Blog&tag=pcap)

### Zeek Log Integration Patterns

| Feature | Description |
|---------|-------------|
| Structured metadata logs | conn.log, http.log, dns.log, ssl.log, files.log |
| Connection UIDs | Unique IDs for correlating across log types |
| Community ID | Standard flow hash for cross-tool correlation |
| Scriptable analysis | Custom Zeek scripts for detection logic |
| Storage efficient | Metadata-only (no full packet storage needed) |

### Malcolm (CISA) - Unified Integration

Malcolm integrates Arkime + Zeek + Suricata into a single platform:
- Browser-based upload for PCAP and Zeek logs
- Automatic normalization, enrichment, correlation
- OpenSearch Dashboards with prebuilt views
- Arkime session viewer alongside Zeek metadata
- Cross-tool correlation via Community ID and Zeek UIDs

Source: [Malcolm (CISA)](https://github.com/cisagov/Malcolm), [Malcolm + Arkime](https://malcolm.fyi/docs/arkime.html)

### Host + Network Evidence Correlation UX

| Pattern | Description |
|---------|-------------|
| Unified timeline | Network events interleaved with host events |
| Pivot from host to network | Click a process -> see its network connections |
| Pivot from network to host | Click a session -> see which process/user initiated it |
| Beaconing detection | Identify periodic C2 communication patterns |
| Data exfiltration view | Correlate large outbound transfers with file access |

---

## 6. Pricing Models for Forensic Tools

### Pricing Comparison

| Tool | Model | Price Range | Notes |
|------|-------|-------------|-------|
| **Velociraptor** | Free (open source) | $0 | Monetized via Rapid7 platform |
| **X-Ways Forensics** | Per-license, subscription | ~$850/yr single user | Volume discounts at 2+, 5+, 10+, 25+, 50+ |
| **X-Ways Investigator** | Per-license | ~$425/yr | Simplified UI, half price of Forensics |
| **Magnet AXIOM** | Custom quote | ~$2,995+/yr per user (est.) | Not publicly listed; contact sales |
| **Magnet Nexus** | Custom quote | Enterprise pricing | Case management add-on |
| **Binalyze AIR** | Per-endpoint, annual | ~$2,000-5,000/yr per tier | Essentials vs Pro tiers |
| **Cyber Triage** | Per-investigator | Custom pricing | Lite version free; Standard/Team paid |
| **EnCase Forensic** | Per-license | ~$3,594+/yr | Enterprise pricing |
| **Autopsy** | Free (open source) | $0 | Commercial support available |
| **Timesketch** | Free (open source) | $0 | No commercial offering |

Sources:
- [X-Ways Order Page](https://www.x-ways.net/order.html)
- [Cyber Triage Pricing](https://www.cybertriage.com/pricing/)
- [Magnet AXIOM Pricing Analysis](https://www.cyberforensicacademy.com/blog/magnet-axiom-features-pricing-real-investigation-use-cases)
- [Binalyze AIR](https://www.binalyze.com/air)
- [Computer Forensic Tools Comparison 2026](https://www.cybertriage.com/blog/computer-forensic-tools-comparison-2026/)

### MSSP Pricing Models

| Model | Description | Pros | Cons |
|-------|-------------|------|------|
| **Per-endpoint** | Flat fee per monitored device | Predictable, scales with fleet | Penalizes large deployments |
| **Per-investigator/seat** | Licensed by analyst count | Simple, team-size based | Doesn't scale with case volume |
| **Per-case** | Charge per investigation | Aligns cost with value delivered | Unpredictable revenue |
| **Retainer** | Annual fee for guaranteed availability | Steady revenue, client loyalty | Must deliver value even in quiet periods |
| **Tiered packages** | Bronze/Silver/Gold bundles | Clear value ladder | Feature allocation can frustrate |
| **Outcome-based** | Price tied to SLAs (e.g., detection time) | Aligns incentives | Hard to measure fairly |

**MSSP pricing benchmarks (2025):**
- Basic MSSP services: avg $45/endpoint/month (top earners: $200/endpoint/month)
- MDR services: starting ~$11/device/month
- DFIR retainers: typically annual, custom pricing

Sources:
- [MSSP Pricing Guide](https://pricinglink.com/knowledge-base/managed-security-service-provider/how-to-price-mssp-services/)
- [MSSP Alert Pricing Report](https://www.msspalert.com/native/mssp-pricing-report-maps-path-for-2025)
- [Binalyze for MSSPs](https://www.binalyze.com/solutions-mssp)

---

## 7. Recommended Tier Split for Security Ronin Katana

### Community Tier (Free Forever)

Target: Solo DFIR consultants, 3-5 cases/month

| Feature | Rationale |
|---------|-----------|
| CLI parsing of USN Journal from E01 images | Core value proposition; must stay free |
| HTML report with Story/Explore tabs | Current product; never remove |
| Single-device analysis | Solo consultants typically examine one device |
| Basic timeline visualization | Essential triage capability |
| Offline collector mode | Solo consultants need offline capability |
| Local-only processing | No server dependency |
| Community support (GitHub Issues) | Standard open-source model |
| Export to CSV/JSON | Basic interoperability |
| Basic artifact scoring/triage | Core differentiator |

### Enterprise Tier (Paid)

Target: MSSP analysts and enterprise IR teams, 15-30 cases/month

| Feature Category | Features | Justification |
|-----------------|----------|---------------|
| **Case Management** | Multi-case dashboard, case templates, assignment, status tracking | MSSPs juggle 15-30 cases; need organization |
| **Collaboration** | Multi-analyst concurrent analysis, shared annotations, comments, tags | Enterprise teams have 3-10 analysts |
| **RBAC** | Examiner, Reviewer, Case Manager, Admin roles | Compliance requirement for enterprises |
| **Audit Logging** | Immutable action logs, evidence access tracking, session logging | Legal/compliance requirement |
| **Chain of Custody** | Timestamped evidence tracking, tamper-proof audit trail, export-ready reports | Court admissibility requirement |
| **Multi-Device** | Timeline merging across devices, cross-device correlation, source management | Enterprise cases involve multiple endpoints |
| **Collection Agent** | Remote artifact collection from endpoints, hunt management | Scale beyond disk images to live endpoints |
| **Network Evidence** | PCAP/NetFlow integration, host+network correlation | Complete investigation picture |
| **Reporting** | Custom report templates, branded reports, executive summaries | Client-facing deliverables |
| **Integrations** | SIEM/SOAR export, Timesketch integration, Velociraptor import | Enterprise tool ecosystem |
| **SSO/SAML** | Enterprise identity provider integration | Enterprise IT requirement |
| **Priority Support** | SLA-backed response times, dedicated support channel | Enterprise expectation |

### Pricing Recommendation

| Model | Recommendation | Rationale |
|-------|---------------|-----------|
| **Primary model** | Per-investigator/seat, annual subscription | Aligns with Cyber Triage, simpler than per-endpoint for tool-focused product |
| **Suggested price point** | $99-149/investigator/month ($1,188-1,788/yr) | Below AXIOM (~$2,995/yr), above X-Ways (~$850/yr); sweet spot for MSSP analysts |
| **Volume discounts** | 5+ seats: 15% off; 10+ seats: 25% off | Follow X-Ways volume discount pattern |
| **MSSP tier** | Custom pricing with multi-tenant support | MSSPs need tenant isolation per client |
| **Free trial** | 30-day full enterprise trial | Standard enterprise software practice |

### Anti-Backlash Principles

1. **Never move features from free to paid** - Only gate *new* capabilities behind enterprise
2. **Keep the CLI core permanently open source** - The parser, triage engine, and report generation stay free
3. **Publish a clear "Free Forever" commitment** - Document exactly what will never be paywalled
4. **Enterprise features are *additive*** - Collaboration, RBAC, multi-device, collection are new capabilities layered on top
5. **Communicate transparently** - Blog post explaining the rationale before any tier change
6. **Maintain a generous free tier** - Solo consultants should be fully productive without paying

---

## Sources Index

### Open-Core / Tier Splitting
- [Elastic Subscriptions](https://www.elastic.co/subscriptions)
- [Elastic Pricing](https://www.elastic.co/pricing)
- [Snyk Plans](https://snyk.io/plans/)
- [GitLab Pricing](https://about.gitlab.com/pricing/)
- [GitLab Free Tier FAQ](https://about.gitlab.com/pricing/faq-efficient-free-tier/)
- [Wikipedia: Open-core model](https://en.wikipedia.org/wiki/Open-core_model)
- [Socket.dev: Elasticsearch License Backlash](https://socket.dev/blog/developers-burned-by-elasticsearch-license-change-arent-going-back)
- [InfoQ: Elastic Returns to Open Source](https://www.infoq.com/news/2024/09/elastic-open-source-agpl/)
- [The New Stack: GitLab Free Tier Tightening](https://thenewstack.io/gitlabs-free-tier-belt-tightening-continues/)
- [The New Stack: RIP Open Core](https://thenewstack.io/rip-open-core-long-live-open-source/)
- [Snyk Pricing Analysis (Vendr)](https://www.vendr.com/marketplace/snyk)
- [Snyk Pricing Analysis (Spendflo)](https://www.spendflo.com/blog/snyk-pricing-plans-features)

### Enterprise DFIR Features
- [Magnet Forensics: Enterprise Forensics](https://www.magnetforensics.com/blog/enterprise-forensics-why-scalable-solutions-matter/)
- [DFIR-IRIS Platform](https://www.dfir-iris.org/)
- [DFIR-IRIS Activities Module Guide](https://certbar.com/technical-blogs/navigating-dfir-iris-part-2)
- [Detego Case Manager Launch](https://www.forensicfocus.com/news/detego-global-launches-purpose-built-case-management-platform-for-digital-forensics-and-incident-response-teams/)
- [Detego Case Manager (Hackread)](https://hackread.com/detego-global-launches-case-management-platform-for-digital-forensics-and-incident-response-teams/)
- [OpenText DFIR](https://solutions.opentext.com/cybersecurity/dfir/)
- [Fortinet: What is DFIR](https://www.fortinet.com/resources/cyberglossary/dfir)
- [Autopsy Collaborative](https://www.autopsy.com/collaborative-autopsy-how-it-works/)
- [Autopsy Official](https://www.autopsy.com/)
- [Timesketch (GitHub)](https://github.com/google/timesketch)
- [Timesketch Official](https://timesketch.org/)
- [Timesketch (CISA)](https://www.cisa.gov/resources-tools/services/timesketch)

### Collection Agent UX
- [Velociraptor Overview](https://docs.velociraptor.app/docs/overview/)
- [Velociraptor Hunting](https://docs.velociraptor.app/docs/hunting/)
- [Velociraptor Offline Collections](https://docs.velociraptor.app/docs/deployment/offline_collections/)
- [Velociraptor Adaptive Collections](https://docs.velociraptor.app/blog/2025/2025-09-28-adaptive-collections/)
- [Rapid7 Velociraptor](https://www.rapid7.com/products/velociraptor/)
- [CISA Velociraptor](https://www.cisa.gov/resources-tools/services/velociraptor)
- [Cyber Triage + Velociraptor](https://docs.cybertriage.com/en/latest/chapters/integrations/velociraptor_collect.html)
- [Pen Test Partners: Velociraptor at Scale](https://www.pentestpartners.com/security-blog/using-velociraptor-for-large-scale-endpoint-visibility-and-rapid-threat-hunting/)

### Multi-Device Examination
- [ResearchGate: Cross-Drive Analysis](https://www.researchgate.net/publication/264543999_The_Potential_for_Cross-Drive_Analysis_Using_Automated_Digital_Forensic_Timelines)
- [Kroll: Mobile Device Forensics](https://www.kroll.com/en/publications/forensic-data-analysis-of-mobile-devices)
- [SANS FOR585](https://www.sans.org/cyber-security-courses/advanced-smartphone-mobile-device-forensics)
- [Magnet AXIOM](https://www.magnetforensics.com/products/magnet-axiom/)

### PCAP/NetFlow Analysis
- [Arkime](https://arkime.com/)
- [Arkime (GitHub)](https://github.com/arkime/arkime)
- [Malcolm (CISA GitHub)](https://github.com/cisagov/Malcolm)
- [Malcolm + Arkime Docs](https://malcolm.fyi/docs/arkime.html)
- [Cyber Forensics Academy: Network Forensic Tools](https://www.cyberforensicacademy.com/blog/best-network-forensic-tools-for-packet-log-analysis)
- [SANS ISC: PCAP Analysis](https://isc.sans.edu/diary/The+easy+way+to+analyze+huge+amounts+of+PCAP+data/22876)
- [NETRESEC Blog](https://www.netresec.com/?page=Blog&tag=pcap)

### Pricing
- [X-Ways Order Page](https://www.x-ways.net/order.html)
- [X-Ways Pricing (TrustRadius)](https://www.trustradius.com/products/x-ways-forensics/pricing)
- [Cyber Triage Pricing](https://www.cybertriage.com/pricing/)
- [Magnet AXIOM Pricing Analysis](https://www.cyberforensicacademy.com/blog/magnet-axiom-features-pricing-real-investigation-use-cases)
- [Magnet AXIOM (Capterra)](https://www.capterra.com/p/230793/Magnet-AXIOM/)
- [Binalyze AIR](https://www.binalyze.com/air)
- [Binalyze AIR for MSSPs](https://www.binalyze.com/solutions-mssp)
- [Binalyze AIR (G2)](https://www.g2.com/products/binalyze-air/reviews)
- [Computer Forensic Tools Comparison 2026](https://www.cybertriage.com/blog/computer-forensic-tools-comparison-2026/)
- [MSSP Pricing Guide](https://pricinglink.com/knowledge-base/managed-security-service-provider/how-to-price-mssp-services/)
- [MSSP Alert Pricing Report](https://www.msspalert.com/native/mssp-pricing-report-maps-path-for-2025)
- [MDR Pricing](https://underdefense.com/mdr-pricing/)
- [Gartner DFIR Market Guide (Group-IB)](https://www.group-ib.com/resources/research-hub/dfir-guide-2025/)
- [Remote Forensic Collection Tools 2025](https://www.cybertriage.com/blog/remote-forensic-collection-tools-2025/)
