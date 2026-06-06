# Security Ronin Katana: Post-Deployment Operations

> Operational runbook for a solo-developer forensic triage product spanning community CLI and enterprise server deployments.

**Product:** Security Ronin Katana (usnjrnl-forensic)
**Company:** Security Ronin
**Version:** 1.0
**Date:** 2026-03-10
**Status:** Active
**Cross-references:** [ARCHITECTURE_BLUEPRINT.md](./ARCHITECTURE_BLUEPRINT.md) | [SECURITY_ARCHITECTURE.md](./SECURITY_ARCHITECTURE.md) | [NORTHSTAR.md](./NORTHSTAR.md)

---

## Document Purpose

This document defines post-deployment operations for both deployment models of Security Ronin Katana:

- **Community Tier (`katana` CLI):** Static binary distributed via GitHub Releases, `cargo install`, and Docker. Runs entirely on the user's machine with no server infrastructure. Operations focus on release management, binary signing, and community support.
- **Enterprise Tier (`katana-pro`):** Axum API server with PostgreSQL, collection agents deployed to customer endpoints, and multi-tenant MSSP support. Operations focus on server uptime, agent fleet management, database maintenance, and SLA compliance.

The solo-developer constraint shapes every operational decision: automate aggressively, prefer free-tier tooling, and design for asynchronous incident response rather than on-call rotation.

---

## 1. Monitoring Dashboard

### 1.1 North Star Metric (Weekly Review)

| Metric | Definition | Current | Target | Trend |
|--------|-----------|---------|--------|-------|
| **Paying Enterprise Customers** | Organizations with active paid seat + case processed in trailing 30 days | -- | 50 (12mo post-launch) | -- |

**Input Metrics:**

| Input Metric | Measurement | Current | Target | Review Cadence |
|-------------|-------------|---------|--------|----------------|
| Community Adoption | Active `katana` users (GitHub clones + cargo installs + Docker pulls, 30-day trailing) | -- | 500 active | Weekly |
| Product Quality | False positive rate across 12 triage questions on reference corpus | -- | <5% FP rate | Per release |
| Enterprise Conversion | Community users who convert to enterprise trial or paid | -- | 15% conversion | Monthly |
| Time to First Answer | P95 seconds from `katana triage` invocation to first question answered | -- | <35 seconds | Per release |
| Ghost Recovery Rate | Percentage of deleted files recovered from reference corpus | -- | >90% | Per release |

**Where to check:**
- Community: GitHub Insights (clones, stars, forks), crates.io download stats, Docker Hub pull counts
- Enterprise: License management database (`SELECT count(*) FROM tenants WHERE last_case_at > now() - interval '30 days' AND subscription_status = 'active'`)

### 1.2 Community Tier Metrics (Weekly Review)

| Metric | Source | Healthy | Degraded | Action |
|--------|--------|---------|----------|--------|
| GitHub stars growth | GitHub API | >5/week | <2/week | Review community engagement |
| Issue response time | GitHub Issues | <48h first response | >72h | Prioritize triage |
| Binary download count | GitHub Releases API | Growing MoM | Declining | Investigate, blog post |
| Cargo install failures | crates.io + issue reports | <1% | >5% | Hotfix release |
| Docker pull count | Docker Hub API | Growing MoM | Declining | Check image size, docs |
| Reference corpus pass rate | CI (GitHub Actions) | 100% | <100% | Block release |

### 1.3 Enterprise Tier Metrics (Daily Review)

| Metric | Current | SLO | Status |
|--------|---------|-----|--------|
| **API Latency P50** | -- | <200ms | -- |
| **API Latency P95** | -- | <500ms | -- |
| **API Latency P99** | -- | <1000ms | -- |
| **API Error Rate** | -- | <1% | -- |
| **API Availability** | -- | >99.5% | -- |
| **Triage Latency P95** | -- | <35s (1GB E01) | -- |
| **Agent Connection Success** | -- | >99% | -- |
| **Agent Cold Start** | -- | <50ms | -- |
| **Database Query P95** | -- | <100ms | -- |
| **gRPC Stream Throughput** | -- | >10MB/s | -- |

**Observability Stack (Enterprise):**
- **Metrics:** Prometheus (self-hosted, free) with Grafana dashboards
- **Logs:** Structured JSON logs (tracing crate) shipped to Grafana Loki
- **Traces:** OpenTelemetry with Jaeger (self-hosted) for request tracing
- **Alerts:** Grafana Alerting to email + PagerDuty (free tier, 1 user)

### 1.4 Pipeline Stage Metrics (Enterprise)

| Pipeline Stage | Crate | P95 Budget | Error Rate SLO | Fallback Strategy |
|---------------|-------|------------|----------------|-------------------|
| EWF Parser | katana-ewf | 2s | <0.1% | Partial processing + warning |
| NTFS Volume | katana-ntfs | 1s | <0.1% | Error with actionable message |
| USN Journal Parser | katana-core | 5s | <0.5% | MFT-only fallback |
| MFT Parser | katana-core | 5s | <0.5% | USN-only mode |
| Ghost Recovery | katana-core | 3s | <1% | Skip, note in report |
| Unallocated Carving | katana-core | 5s | <1% | Skip, note in report |
| QuadLink Correlator | katana-core | 3s | <0.5% | Single-artifact mode |
| Triage Engine | katana-core | 5s | <0.1% | Partial answers |
| Output Formatter | katana-formats | 3s | <0.1% | JSON fallback |

---

## 2. Release Management

### 2.1 Community Release Process

Forensic tools demand deterministic, verifiable builds. Every release must be reproducible and signed.

**Release Checklist:**

```
Pre-Release:
  [ ] All CI checks pass (GitHub Actions)
  [ ] Reference corpus: 100% pass rate on all 12 triage questions
  [ ] Precision/recall metrics computed and documented
  [ ] P95 triage time on 1GB E01 reference image < 35 seconds
  [ ] Ghost recovery rate > 90% on reference corpus
  [ ] CHANGELOG.md updated with user-facing changes
  [ ] Version bumped (semantic versioning: major.minor.patch)
  [ ] cargo clippy --all-targets -- -D warnings passes
  [ ] cargo audit shows no critical vulnerabilities
  [ ] SPDX license headers present on all source files

Build:
  [ ] Deterministic build (same source + same toolchain = same binary hash)
  [ ] Pin Rust toolchain version in rust-toolchain.toml
  [ ] Cross-compile targets: x86_64-linux-gnu, x86_64-apple-darwin, aarch64-apple-darwin, x86_64-windows-msvc
  [ ] Binary size within expected range per target
  [ ] Ed25519 sign all release binaries
  [ ] Generate SHA-256 checksums for all artifacts
  [ ] Build and tag Docker image (multi-arch: amd64, arm64)

Release:
  [ ] Create GitHub Release with signed tag (git tag -s)
  [ ] Upload binaries + checksums + signatures
  [ ] Publish to crates.io (cargo publish)
  [ ] Push Docker image to Docker Hub / GitHub Container Registry
  [ ] Update Homebrew tap formula (if applicable)
  [ ] Publish release blog post / changelog

Post-Release:
  [ ] Verify binary checksums match CI artifacts
  [ ] Test cargo install katana from crates.io
  [ ] Test Docker image pull and basic triage
  [ ] Monitor GitHub Issues for regression reports (48h window)
  [ ] Update Daubert packet if precision/recall changed
```

**Semantic Versioning Rules for Forensic Tools:**

| Change Type | Version Bump | Example |
|------------|-------------|---------|
| New triage question added | Minor | 0.3.0 -> 0.4.0 |
| Triage answer format change | Major | 0.4.0 -> 1.0.0 |
| Parser accuracy improvement | Minor | 0.4.0 -> 0.5.0 |
| Bug fix (no output change) | Patch | 0.4.1 -> 0.4.2 |
| Output format breaking change | Major | 1.0.0 -> 2.0.0 |
| New output format option | Minor | 1.0.0 -> 1.1.0 |
| Performance improvement only | Patch | 1.0.1 -> 1.0.2 |

**Deterministic Build Verification:**

```bash
# Build twice, compare hashes (CI job)
cargo build --release --target x86_64-unknown-linux-gnu
sha256sum target/x86_64-unknown-linux-gnu/release/katana > build1.sha256
cargo clean && cargo build --release --target x86_64-unknown-linux-gnu
sha256sum target/x86_64-unknown-linux-gnu/release/katana > build2.sha256
diff build1.sha256 build2.sha256  # Must be identical
```

**Binary Signing:**

```bash
# Sign release binary with Ed25519 (minisign)
minisign -Sm katana-x86_64-linux -s ~/.minisign/katana-release.key

# Users verify:
minisign -Vm katana-x86_64-linux -p katana-release.pub
```

### 2.2 Enterprise Release Process

Enterprise releases follow the same quality gates as community, plus:

```
Additional Enterprise Pre-Release:
  [ ] Enterprise integration tests pass (katana-pro CI)
  [ ] Agent-server compatibility matrix verified
  [ ] Database migration tested (up and down)
  [ ] Multi-tenant isolation tests pass
  [ ] RBAC permission tests pass for all 5 roles
  [ ] mTLS certificate rotation tested
  [ ] Load test: 10 concurrent triage operations
  [ ] Agent update mechanism tested (staged rollout)

Enterprise Release:
  [ ] Tag katana-pro release (private repo)
  [ ] Build and sign agent binaries (all platforms)
  [ ] Build server Docker image
  [ ] Run database migrations in staging
  [ ] Deploy to staging, run smoke tests
  [ ] Deploy to production (blue-green)
  [ ] Staged agent rollout: canary (5%) -> 25% -> 100%
  [ ] Notify enterprise customers via changelog email
```

**Agent-Server Compatibility Matrix:**

| Agent Version | Server Version | Status |
|--------------|---------------|--------|
| Current (N) | Current (N) | Supported |
| Previous (N-1) | Current (N) | Supported (backward compat) |
| Current (N) | Previous (N-1) | Not supported |
| Older (N-2) | Current (N) | Deprecated, forced update |

---

## 3. Agent Fleet Management (Enterprise)

### 3.1 Agent Lifecycle

```
Enrollment -> Active -> Update -> Active -> ... -> Decommission
    |                     |
    v                     v
  Failed              Quarantine
```

**Enrollment Procedure:**

```bash
# 1. Generate single-use enrollment token (server)
curl -X POST https://api.katana.example/admin/agents/enroll \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{"hostname": "endpoint-001", "tenant_id": "tenant-abc"}' \
  # Returns: { "token": "enroll-xyz", "expires_at": "2026-03-11T..." }

# 2. Install and enroll agent (endpoint)
katana-agent enroll \
  --server https://api.katana.example \
  --token enroll-xyz
  # Agent generates CSR, server issues X.509 cert (90-day validity)

# 3. Verify enrollment (server)
curl https://api.katana.example/admin/agents \
  -H "Authorization: Bearer $ADMIN_JWT" \
  | jq '.agents[] | select(.hostname == "endpoint-001")'
```

### 3.2 Agent Health Monitoring

| Health Signal | Check Method | Healthy | Degraded | Critical |
|--------------|-------------|---------|----------|----------|
| Heartbeat | gRPC keepalive | <30s interval | 30-60s gap | >60s gap |
| Certificate expiry | Cert CN check | >30 days | 7-30 days | <7 days |
| Version currency | Agent metadata | Current (N) or N-1 | N-2 | N-3+ |
| Resource usage | Agent telemetry | CPU <15%, mem <256MB | CPU <30%, mem <512MB | Exceeds limits |
| Collection queue | gRPC status | <10 pending | 10-50 pending | >50 pending |
| Last successful upload | Server records | <1h ago | 1-4h ago | >4h ago |

**Automated Health Alerts (Grafana):**

```yaml
- alert: AgentHeartbeatMissing
  expr: time() - agent_last_heartbeat_timestamp > 120
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Agent {{ $labels.hostname }} heartbeat missing >2 minutes"

- alert: AgentCertExpiringSoon
  expr: agent_cert_expiry_days < 14
  for: 0s
  labels:
    severity: warning
  annotations:
    summary: "Agent {{ $labels.hostname }} cert expires in {{ $value }} days"
    action: "Run: katana-admin cert rotate --agent {{ $labels.hostname }}"

- alert: AgentCertExpiryCritical
  expr: agent_cert_expiry_days < 3
  for: 0s
  labels:
    severity: critical
  annotations:
    summary: "CRITICAL: Agent {{ $labels.hostname }} cert expires in {{ $value }} days"
```

### 3.3 Agent Update Procedure

```bash
# Staged rollout process

# Step 1: Upload new agent binary to update server
katana-admin agent-release upload \
  --version 1.2.0 \
  --binary ./katana-agent-1.2.0-linux-amd64 \
  --signature ./katana-agent-1.2.0-linux-amd64.sig

# Step 2: Canary (5% of fleet)
katana-admin agent-release rollout \
  --version 1.2.0 \
  --percentage 5 \
  --monitor-duration 1h

# Step 3: Expand to 25%
katana-admin agent-release rollout \
  --version 1.2.0 \
  --percentage 25 \
  --monitor-duration 2h

# Step 4: Full fleet
katana-admin agent-release rollout \
  --version 1.2.0 \
  --percentage 100

# Emergency rollback
katana-admin agent-release rollback \
  --to-version 1.1.0 \
  --reason "elevated error rate post-update"
```

**Agent self-update mechanism:**
- Agent checks for updates on heartbeat interval (every 60s)
- Downloads new binary from server (signed URL, Ed25519 verified)
- Verifies Ed25519 signature before replacing binary
- Keeps previous version alongside for instant rollback
- Restarts with new binary, reports version in next heartbeat

### 3.4 Certificate Rotation

```bash
# Routine rotation (automated, runs via cron or server scheduler)
# Certificates have 90-day validity, rotation triggers at 30 days remaining

# Manual rotation for single agent
katana-admin cert rotate --agent endpoint-001

# Fleet-wide rotation (staggered over 24h to avoid thundering herd)
katana-admin cert rotate --all --stagger 24h

# Emergency revocation (compromised agent)
katana-admin cert revoke --agent endpoint-001 --reason "potential compromise"
# Adds cert to CRL, all servers reject immediately
```

---

## 4. Database Operations (Enterprise)

### 4.1 PostgreSQL Maintenance

**Backup Strategy:**

| Backup Type | Frequency | Retention | Method | Storage |
|------------|-----------|-----------|--------|---------|
| Full (pg_basebackup) | Daily (02:00 UTC) | 30 days | Streaming replication snapshot | S3-compatible (Backblaze B2) |
| WAL archiving | Continuous | 7 days | pg_receivewal | Local + S3 |
| Logical (pg_dump) | Weekly (Sunday 03:00 UTC) | 90 days | Per-tenant dump | S3 |
| Point-in-time recovery | N/A | 7 days | WAL replay | From WAL archive |

**Backup Automation:**

```bash
#!/bin/bash
# daily-backup.sh -- runs via cron at 02:00 UTC
set -euo pipefail

BACKUP_DATE=$(date +%Y-%m-%d)
BACKUP_DIR="/backups/postgres/${BACKUP_DATE}"
S3_BUCKET="s3://katana-backups/postgres"

mkdir -p "${BACKUP_DIR}"

# Full backup
pg_basebackup -h localhost -U katana_backup -D "${BACKUP_DIR}/base" \
  --wal-method=stream --checkpoint=fast --progress

# Compress
tar czf "${BACKUP_DIR}/base.tar.gz" -C "${BACKUP_DIR}" base
rm -rf "${BACKUP_DIR}/base"

# Upload to S3 (Backblaze B2 via rclone)
rclone copy "${BACKUP_DIR}/base.tar.gz" "${S3_BUCKET}/${BACKUP_DATE}/"

# Cleanup local backups older than 7 days
find /backups/postgres -maxdepth 1 -type d -mtime +7 -exec rm -rf {} +

printf '%s\n' "Backup completed: ${BACKUP_DATE}"
```

**Restore Procedure:**

```bash
# Stop server
systemctl stop katana-server

# Restore from backup
pg_restore --clean --if-exists -d katana /backups/postgres/2026-03-10/base.tar.gz

# Apply WAL logs for point-in-time recovery
# (configure recovery.conf with recovery_target_time)

# Verify data integrity
katana-admin db verify --check-hash-chains

# Restart server
systemctl start katana-server
```

**Routine Maintenance:**

```bash
# Weekly: analyze and vacuum (automated via pg_cron or system cron)
psql -U katana -d katana -c "VACUUM ANALYZE;"

# Monthly: check for bloat
psql -U katana -d katana -c "
  SELECT schemaname, tablename,
    pg_size_pretty(pg_total_relation_size(schemaname || '.' || tablename)) as total_size
  FROM pg_tables
  WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
  ORDER BY pg_total_relation_size(schemaname || '.' || tablename) DESC
  LIMIT 20;
"

# Check connection pool health
psql -U katana -d katana -c "
  SELECT state, count(*) FROM pg_stat_activity
  WHERE datname = 'katana'
  GROUP BY state;
"
```

### 4.2 Tantivy Search Index Maintenance

Katana uses tantivy (Rust-native full-text search) instead of OpenSearch to avoid JVM overhead.

**Index Lifecycle:**

| Index Type | Retention | Merge Policy | Max Segment Size |
|-----------|-----------|-------------|-----------------|
| Evidence metadata | Case lifetime + 1 year | Log merge | 500MB |
| Triage results | Case lifetime + 1 year | Log merge | 200MB |
| Audit logs | 7 years (compliance) | Log merge | 1GB |
| Agent telemetry | 90 days | Time-based | 200MB |

**Index Maintenance:**

```bash
# Force merge (reduce segment count, reclaim space)
katana-admin search optimize --index evidence_metadata

# Rebuild index from PostgreSQL (disaster recovery)
katana-admin search reindex --source postgres --index evidence_metadata

# Check index health
katana-admin search status
# Output: index_name, doc_count, segment_count, disk_size, last_commit
```

### 4.3 Audit Log Management

Audit logs are forensic evidence themselves and require the same integrity standards as case evidence.

**Hash-Chain Verification:**

```bash
# Daily automated check (runs via cron or scheduled task)
katana-admin audit verify --chain-integrity
# Verifies: each entry's SHA-256 hash matches hash of (previous_hash + current_entry)
# Exit code 0 = intact, exit code 1 = broken chain (SEV-1 incident)

# Export audit trail for legal proceedings
katana-admin audit export \
  --case-id CASE-2026-001 \
  --format pdf \
  --include-chain-verification \
  --output /exports/CASE-2026-001-audit.pdf
```

**Audit Log Retention:**

| Log Type | Retention | Archival | Deletion |
|---------|-----------|---------|----------|
| Evidence access logs | 7 years | Yearly to cold storage (S3 Glacier) | Automated after retention |
| Authentication events | 3 years | Yearly to cold storage | Automated |
| Admin actions | 7 years | Yearly to cold storage | Automated |
| Agent telemetry | 90 days | None | Automated |
| API request logs | 1 year | None | Automated |

---

## 5. Feedback Loops

### 5.1 Community Feedback Collection

| Channel | Type | Response SLA | Triage Process |
|---------|------|-------------|----------------|
| GitHub Issues | Bug reports, feature requests | First response <48h | Label, prioritize, assign to milestone |
| GitHub Discussions | Q&A, use cases, feedback | Best effort <72h | Pin FAQs, extract feature signals |
| Release download stats | Implicit signal | Weekly review | Track adoption trends |
| Cargo install errors | Error reports via issues | <48h | Hotfix if widespread |

**Feedback Processing (Solo Developer Workflow):**

1. **Monday morning:** Review all new GitHub Issues and Discussions from past week
2. **Triage labels:** `bug`, `enhancement`, `question`, `forensic-accuracy` (high priority), `performance`, `wontfix`
3. **Priority matrix:** Forensic accuracy issues > correctness bugs > performance > features
4. **Community contributions:** Review PRs within 72h, provide actionable feedback

### 5.2 Enterprise Feedback Collection

| Channel | Type | Response SLA | Triage Process |
|---------|------|-------------|----------------|
| Support email | Bug reports, incidents | Per SLA tier | Ticket creation, severity assignment |
| Quarterly business review | Strategic feedback | Scheduled | Document action items, update roadmap |
| Usage analytics | Implicit signals | Weekly review | Feature adoption tracking |
| Agent telemetry | Operational feedback | Real-time alerts | Automated escalation |

### 5.3 Precision/Recall Feedback Loop

Because forensic accuracy is the product's foundation, every release includes a precision/recall cycle:

```
Reference Corpus --> katana triage --> Compare to Ground Truth
        |                                      |
        v                                      v
  Update corpus with            Compute per-question P/R
  new edge cases                       |
        ^                              v
        |                    P/R meets threshold?
        |                    Yes: release    No: fix
        +------------------------------------------+
```

**Thresholds for release:**
- Precision: >95% per triage question
- Recall: >90% per triage question
- Ghost recovery: >90% on reference corpus
- Zero regressions on previously passing test cases

---

## 6. Incident Response

### 6.1 Solo Developer Incident Model

Traditional on-call rotation is impossible for a solo developer. The incident model is designed around automation, severity-gated response times, and async communication.

**Response Philosophy:**
- SEV-1 and SEV-2 get PagerDuty alerts (phone notification)
- SEV-3 and SEV-4 get email notifications, handled during business hours
- Automation handles containment for most scenarios
- Kill switches provide immediate mitigation without human intervention

### 6.2 Severity Levels

| Severity | Response Time | Examples | Notification |
|----------|-------------|----------|-------------|
| **SEV-1** | 15 minutes | Hash chain broken, evidence tampering detected, agent fleet compromise, data breach | PagerDuty (phone call) |
| **SEV-2** | 1 hour | RBAC bypass, cross-tenant data access, unauthorized agent deployment, server down | PagerDuty (push notification) |
| **SEV-3** | 4 hours | Single agent offline, elevated error rates, degraded performance, failed backup | Email alert |
| **SEV-4** | 24 hours | Non-critical bug, cosmetic issue, single user report, documentation gap | Email digest |

### 6.3 Kill Switches

Pre-configured automated responses that can be triggered without debugging:

```bash
# Kill entire agent fleet (all agents stop collecting)
katana-admin kill-switch activate agent_fleet_kill \
  --reason "suspected fleet compromise"

# Kill single agent (revoke certificate via CRL)
katana-admin kill-switch activate single_agent_kill \
  --agent endpoint-001 \
  --reason "anomalous behavior detected"

# Lock out entire tenant (suspend all users and agents)
katana-admin kill-switch activate tenant_lockout \
  --tenant tenant-abc \
  --reason "potential data breach"

# Quarantine evidence (read-only lock, no modifications)
katana-admin kill-switch activate evidence_quarantine \
  --case CASE-2026-001 \
  --reason "chain of custody dispute"

# Emergency full shutdown (graceful)
katana-admin kill-switch activate emergency_shutdown \
  --reason "active exploitation detected"
```

### 6.4 Incident Response Procedures

**SEV-1: Evidence Tampering / Hash Chain Break**

```
1. CONTAIN (automated)
   - Kill switch: evidence_quarantine on affected case
   - Alert: PagerDuty SEV-1

2. PRESERVE (within 15 minutes)
   - Snapshot current database state
   - Export audit logs for affected case
   - Capture server logs (last 24h)

3. INVESTIGATE
   - katana-admin audit verify --chain-integrity --verbose
   - Identify break point in hash chain
   - Check audit logs for unauthorized access patterns
   - Review agent telemetry for anomalies

4. REMEDIATE
   - If agent compromise: revoke agent cert, re-enroll clean agent
   - If server compromise: rotate all secrets, rebuild from known-good image
   - If data tampering: restore from last verified backup

5. COMMUNICATE
   - Notify affected customer(s) within 24 hours
   - File incident report
   - Update Daubert packet if integrity was compromised
```

**SEV-1: Agent Fleet Compromise**

```
1. CONTAIN (immediate)
   - katana-admin kill-switch activate agent_fleet_kill
   - All agents stop collecting and uploading

2. PRESERVE (within 15 minutes)
   - Snapshot server state
   - Export all agent enrollment records
   - Capture network logs

3. INVESTIGATE
   - Identify compromised agent(s)
   - Check for lateral movement indicators
   - Verify server integrity (agent cannot escalate to server by design)
   - Review CRL and enrollment audit trail

4. REMEDIATE
   - Revoke compromised agent certificates
   - Issue new certificates to verified-clean agents
   - Update agent binary if vulnerability found
   - Staged re-enrollment of fleet

5. COMMUNICATE
   - Notify affected tenants
   - Publish security advisory if CVE warranted
```

**SEV-2: Server Outage**

```
1. DETECT (automated)
   - Grafana alert: API availability < 99.5% for 5 minutes
   - PagerDuty push notification

2. DIAGNOSE (within 1 hour)
   - Check: systemctl status katana-server
   - Check: PostgreSQL connectivity
   - Check: disk space, memory, CPU
   - Check: recent deployments (was there a rollback-worthy change?)

3. MITIGATE
   - If deployment-related: rollback to previous version
   - If database: check connection pool, restart if needed
   - If infrastructure: restart service, scale if needed

4. RESTORE
   - Verify all health checks pass
   - Confirm agent reconnection
   - Check no data loss during outage
```

### 6.5 Post-Incident Review Template

```markdown
## Incident Report: [INCIDENT-YYYY-NNN]

**Severity:** SEV-[1/2/3/4]
**Duration:** [Start time] to [End time] ([total duration])
**Impact:** [Number of affected customers/agents/cases]
**On-call:** [Solo developer -- response time from notification]

### Timeline
- [HH:MM UTC] Detection: [How was it detected?]
- [HH:MM UTC] Response: [First action taken]
- [HH:MM UTC] Containment: [What stopped the bleeding?]
- [HH:MM UTC] Resolution: [Root cause addressed]

### Root Cause
[What actually broke and why]

### What Went Well
- [Automated detection worked / kill switch effective / etc.]

### What Needs Improvement
- [Detection gap / missing automation / missing runbook]

### Action Items
- [ ] [Specific improvement with owner and deadline]
- [ ] [Update runbook with new procedure]
- [ ] [Add monitoring for gap]
```

---

## 7. Security and Compliance Operations

### 7.1 Security Review Cadence

| Review Type | Frequency | Scope | Method |
|-------------|-----------|-------|--------|
| Dependency audit | Weekly (automated) | cargo audit + cargo deny | GitHub Actions (Dependabot + cargo-audit) |
| Binary signing verification | Per release | All release artifacts | CI job (minisign verify) |
| mTLS certificate inventory | Monthly | All agent + server certs | katana-admin cert list |
| RBAC permission audit | Quarterly | All roles and permissions | Manual review against spec |
| Penetration test | Annually | Enterprise server + API | Third-party (budget permitting) |
| Forensic accuracy audit | Per release | Reference corpus | Automated CI (precision/recall) |
| Daubert packet review | Quarterly | Methodology documentation | Manual review |

### 7.2 Compliance Checklist

| Requirement | Status | Applicability | Last Verified | Next Review |
|-------------|--------|---------------|---------------|-------------|
| Daubert standard compliance | Active | All tiers | Per release | Per release |
| NIST SP 800-86 alignment | Active | All tiers | Quarterly | Quarterly |
| ISO 27037 (digital evidence) | Active | All tiers | Quarterly | Quarterly |
| SOC 2 Type I readiness | Planning | Enterprise | -- | Phase 3 milestone |
| SOC 2 Type II | Future | Enterprise | -- | Post 25 customers |
| CJIS compliance | Future | Government customers | -- | On demand |
| FedRAMP | Not planned | -- | -- | -- |
| Data retention policy | Active | Enterprise | Monthly | Monthly |
| Incident disclosure SLA | Active | Enterprise | Per incident | Per incident |

### 7.3 Supply Chain Security

```bash
# Automated in CI (GitHub Actions, runs on every PR and release)

# Check for known vulnerabilities in dependencies
cargo audit

# Enforce dependency policies (license, source, advisory)
cargo deny check

# Verify no new unsafe blocks without justification
cargo geiger --output-format json | jq '.unsafety'

# SBOM generation (per release)
cargo cyclonedx --output-file sbom.json
```

### 7.4 Privacy Operations (Enterprise)

**Data Subject Requests (MSSP tenant data):**

| Request Type | SLA | Process |
|-------------|-----|---------|
| Data access (DSAR) | 30 days | Export all tenant data via katana-admin tenant export |
| Data deletion | 30 days | katana-admin tenant purge --tenant-id (schema drop + file deletion + S3 cleanup) |
| Data correction | 30 days | Manual update + audit log entry |
| Data portability | 30 days | Export in open format (JSON + E01 originals) |

**Tenant Data Isolation Verification:**

```bash
# Monthly automated test: attempt cross-tenant access
katana-admin security test-isolation \
  --tenant-a tenant-001 \
  --tenant-b tenant-002
# Verifies: no query from tenant-a can access tenant-b data
# Covers: PostgreSQL schema isolation, file system paths, search index
```

---

## 8. Cost and Resource Tracking

### 8.1 Monthly Cost Review

| Cost Category | Target (Solo Dev) | Notes |
|--------------|-------------------|-------|
| **Infrastructure (VPS)** | $50-100/mo | Single server (Hetzner/OVH), scale when needed |
| **Database (PostgreSQL)** | $0 (self-hosted) | Runs on same VPS |
| **Search (tantivy)** | $0 (embedded) | No separate service |
| **Backups (S3)** | $5-10/mo | Backblaze B2 ($0.006/GB) |
| **Monitoring (Grafana)** | $0 (self-hosted) | Prometheus + Grafana + Loki on same VPS |
| **Alerting (PagerDuty)** | $0 | Free tier (1 user) |
| **CI/CD (GitHub Actions)** | $0 | Free tier for open-source repo |
| **Docker Registry** | $0 | GitHub Container Registry (free for public) |
| **Domain + SSL** | $15/year | Let's Encrypt for SSL |
| **Code signing** | $0 | minisign (Ed25519, free) |
| **Total Community** | ~$0/mo | Zero infrastructure cost |
| **Total Enterprise** | ~$60-120/mo | Minimal VPS + backups |

### 8.2 Scaling Triggers

| Signal | Threshold | Action |
|--------|-----------|--------|
| CPU sustained | >70% for 1 hour | Upgrade VPS or add worker |
| Memory usage | >80% | Increase VPS RAM |
| Disk usage | >80% | Add volume or archive old data |
| API latency P95 | >1000ms sustained | Profile, optimize, or scale |
| Concurrent triage operations | >10 simultaneous | Add processing worker |
| Agent fleet size | >100 agents | Evaluate dedicated gRPC server |
| Database size | >100GB | Evaluate read replica |
| Monthly revenue | >$10K MRR | Budget for managed services |

### 8.3 Cost Optimization Principles

- **Self-host everything possible.** PostgreSQL, Grafana, Prometheus, tantivy all run on one VPS until revenue justifies managed services.
- **Free tiers first.** PagerDuty free, GitHub Actions free (open source), Let's Encrypt, Backblaze B2.
- **Scale vertically before horizontally.** One beefy VPS is simpler than orchestrating multiple small ones for a solo developer.
- **No Kubernetes until >$50K MRR.** Docker Compose on a single server is the right tool for the current scale.
- **Monitor costs monthly.** Set billing alerts at $100/mo and $200/mo.

---

## 9. Iteration Planning

### 9.1 Quarterly Strategy Review

Every quarter, review against the North Star (50 Paying Enterprise Customers) and input metrics:

```
Quarterly Review Agenda (2 hours, solo):
  1. North Star progress (enterprise customer count vs target)
  2. Input metrics review (community adoption, product quality, conversion)
  3. Re-evaluation trigger check (any thresholds breached?)
  4. Competitive landscape scan (any market shifts?)
  5. Kill list review (anything to add or remove?)
  6. Roadmap adjustment (shift priorities based on data)
  7. Cost review (on track with budget?)
```

**Re-evaluation Triggers (from North Star Extract):**

| Signal | Threshold | Action |
|--------|-----------|--------|
| Enterprise customers stall | <10 after 6 months | Reassess enterprise value prop |
| Community adoption plateau | <200 stars after 90 days | Increase content marketing |
| Triage completion rate drop | <90% for 3 releases | Focus on parser reliability |
| False positive rate climb | >10% for 4 weeks | Halt features, fix accuracy |
| P95 triage time regression | >45s for 2 releases | Performance sprint |
| Ghost recovery rate drop | <90% on reference corpus | Parser investigation |

**External Triggers:**
- CrowdStrike ships native NTFS triage
- Microsoft adds forensic triage to Defender
- Velociraptor adds built-in triage questions
- Court rejects open-source tool output
- NTFS specification changes

### 9.2 Kill List Maintenance

Items that will never be built (review quarterly to confirm):

- GUI-first application
- Plugin/extension system
- Cloud-based processing
- AI/ML-based triage classification
- Memory forensics
- Real-time monitoring
- Mobile forensics
- SaaS/cloud-hosted platform
- Multi-language codebase
- VC funding

**Kill list review question:** Has any signal emerged that makes a killed item strategically necessary? If not, it stays killed. If yes, write an ADR documenting the reversal.

### 9.3 Roadmap Update Process

```
Signal detected (feedback, metrics, competitive move)
    |
    v
Does it align with North Star?
    |          |
   Yes         No --> Kill list or backlog
    |
    v
Does it conflict with any Axiom?
    |          |
   No         Yes --> Which axiom? Can we resolve without violating?
    |                    |           |
    |                   Yes         No --> Reject
    |                    |
    v                    v
Prioritize by impact on input metrics
    |
    v
Add to next milestone, update roadmap doc
```

---

## 10. Runbook Quick Reference

### Daily Checklist (Enterprise, 15 minutes)

- [ ] Check Grafana dashboard: API availability, error rates, agent fleet health
- [ ] Review overnight PagerDuty alerts (if any)
- [ ] Verify daily PostgreSQL backup completed successfully
- [ ] Check audit log hash-chain integrity (automated, review results)

### Weekly Checklist (Both Tiers, 1 hour)

- [ ] Review GitHub Issues and Discussions (community)
- [ ] Triage new bug reports, respond within SLA
- [ ] Check cargo audit for new vulnerabilities
- [ ] Review community adoption metrics (stars, downloads, Docker pulls)
- [ ] Check enterprise metrics (customer activity, agent fleet health)
- [ ] Review disk usage and cost tracking

### Monthly Checklist (Both Tiers, 2 hours)

- [ ] PostgreSQL VACUUM ANALYZE (enterprise)
- [ ] Certificate inventory review (enterprise)
- [ ] Tenant isolation test (enterprise)
- [ ] Cost review against budget
- [ ] Dependency update cycle (minor versions)
- [ ] Update Daubert packet if any accuracy changes

### Quarterly Checklist (Both Tiers, half day)

- [ ] Full strategy review against North Star
- [ ] Re-evaluation trigger check
- [ ] Kill list review
- [ ] RBAC permission audit (enterprise)
- [ ] Competitive landscape scan
- [ ] Roadmap update
- [ ] Daubert packet full review
- [ ] NIST/ISO alignment check

### Release Day Checklist

- [ ] Reference corpus: 100% pass
- [ ] Precision: >95%, Recall: >90% per question
- [ ] P95 < 35s on 1GB E01
- [ ] Ghost recovery > 90%
- [ ] Deterministic build verified
- [ ] Binaries signed (Ed25519)
- [ ] SHA-256 checksums generated
- [ ] GitHub Release created (signed tag)
- [ ] crates.io published
- [ ] Docker image pushed
- [ ] Changelog published
- [ ] Monitor issues for 48h post-release

---

## 11. Contacts and Escalation

| Role | Contact | Method | Response Time |
|------|---------|--------|---------------|
| Solo Developer / Founder | @4n6h4x0r | PagerDuty (SEV-1/2), Email (SEV-3/4) | Per severity level |
| Community Support | GitHub Issues | github.com/h4x0r/katana/issues | <48h first response |
| Enterprise Support | Support email | support@securityronin.com | Per SLA tier |
| Security Reports | Security email | security@securityronin.com | <24h acknowledgment |

**Enterprise SLA Tiers:**

| Tier | Monthly | SEV-1 Response | SEV-2 Response | Support Hours |
|------|---------|---------------|---------------|---------------|
| Standard | $99-149/seat | 4 hours | 8 hours | Business hours (M-F) |
| Premium | Custom | 1 hour | 4 hours | Extended (M-Sat) |

**Escalation Path (Solo Developer):**
1. Automated detection and containment (kill switches, alerts)
2. PagerDuty notification (SEV-1/2 only)
3. Investigate and remediate
4. If beyond solo capability: engage contract security consultant (pre-identified, retainer agreement)
5. Customer communication within SLA

---

*This document is a living operational guide. Update it after every incident, every release process improvement, and every quarterly review. An outdated runbook is worse than no runbook -- keep it current or delete the stale sections.*
