# Security Ronin Katana: Security Architecture

> **Version**: 1.0
> **Date**: 2026-03-10
> **Status**: Draft
> **Owner**: Security Ronin
> **Classification**: Internal

## Executive Summary

Security Ronin Katana is a precision DFIR triage tool that processes forensic evidence (E01/raw disk images, USN journals, MFT records) to answer 12 incident response questions in 35 seconds. Its security architecture must protect three critical concerns that differ from typical application security:

1. **Forensic Evidence Integrity** -- Every output must be deterministic, hash-verifiable, and court-admissible under the Daubert standard. A single non-deterministic result can invalidate an entire investigation.
2. **Collection Agent as Attack Vector** -- The enterprise collection agent runs with elevated privileges on endpoints. As Velociraptor's weaponization by Storm-2603 demonstrated in 2025, a legitimate DFIR tool can become a ransomware C2 channel. The agent is designed with assume-breach architecture.
3. **Enterprise Multi-Tenancy** -- MSSP customers sharing infrastructure creates cross-contamination risk where one customer's evidence could leak to another, destroying chain of custody for both.

This document covers the two-tier trust model (community and enterprise), forensic-specific threat scenarios, collection agent hardening, authentication and authorization patterns, hash-chain audit trails, and Daubert compliance controls.

---

## 1. Threat Model

### 1.1 Attack Surface Analysis

```
+--------------------------------------------------------------------------+
|              SECURITY RONIN KATANA ATTACK SURFACE MAP                    |
+--------------------------------------------------------------------------+
|                                                                          |
|  EXTERNAL THREATS                      INTERNAL THREATS                  |
|  ================                      =================                |
|                                                                          |
|  +---------------+                     +------------------+              |
|  | Evidence       |                     | Insider Analyst  |             |
|  | Tampering      | ---- Pre-analysis   | Tampering        |             |
|  | (modified E01) |      injection ---> | (altered results)|             |
|  +---------------+                     +------------------+              |
|         |                                      |                         |
|         v                                      v                         |
|  +---------------+                     +------------------+              |
|  | Agent          |                     | Supply Chain     |             |
|  | Weaponization  | <-- Compromised     | Attack           |             |
|  | (C2 channel)   |     endpoint        | (cargo crate)    |             |
|  +---------------+                     +------------------+              |
|         |                                      |                         |
|         v                                      v                         |
|  +---------------+                     +------------------+              |
|  | Multi-Tenant   |                     | Privilege        |             |
|  | Data Leak      | --- Cross-tenant    | Escalation       |             |
|  | (MSSP breach)  |     access -------> | (role bypass)    |             |
|  +---------------+                     +------------------+              |
|                                                                          |
+--------------------------------------------------------------------------+
```

### 1.2 Forensic Tool Threat Classification (FTTC)

This project replaces the OWASP Agentic AI Top 10 mapping with a forensic-specific threat classification, since Security Ronin Katana is a DFIR tool, not an AI/LLM system.

| ID | Threat Category | Description | Severity |
|----|----------------|-------------|----------|
| FT-01 | Evidence Tampering | Modification of E01/raw images before or during analysis | Critical |
| FT-02 | Agent Weaponization | Collection agent repurposed as C2, lateral movement tool | Critical |
| FT-03 | Non-Deterministic Output | Same input producing different results across runs/versions | Critical |
| FT-04 | Supply Chain Compromise | Malicious cargo crate injecting backdoor into parser | High |
| FT-05 | Insider Result Manipulation | Analyst modifying findings before court submission | High |
| FT-06 | Multi-Tenant Data Leak | MSSP customer A accessing customer B's evidence | Critical |
| FT-07 | Chain of Custody Break | Unaudited access to evidence destroying legal admissibility | High |
| FT-08 | Privilege Escalation | Examiner gaining Admin or cross-case access | Medium |
| FT-09 | Agent Credential Theft | Extraction of mTLS certificates or tokens from agent binary | High |
| FT-10 | Audit Trail Tampering | Deletion or modification of forensic audit logs | Critical |

### 1.3 Trust Boundaries

```
+======================================================================+
|                        TRUST BOUNDARY MAP                            |
+======================================================================+
|                                                                      |
|  COMMUNITY TIER (fully offline, no auth)                             |
|  ========================================                            |
|  +----------------------------------------------------------------+  |
|  |  Local Machine (single user, single process)                   |  |
|  |                                                                |  |
|  |  [E01/Raw Image] --> [katana-cli] --> [Output Files]           |  |
|  |       |                   |                |                   |  |
|  |   SHA-256 hash       Deterministic     SHA-256 hash            |  |
|  |   verified on        processing        written to              |  |
|  |   input              (no network)      output manifest         |  |
|  |                                                                |  |
|  |  Trust: User is responsible for chain of custody.              |  |
|  |  No authentication. No telemetry. No network access.           |  |
|  +----------------------------------------------------------------+  |
|                                                                      |
|  ENTERPRISE TIER (networked, authenticated)                          |
|  ==========================================                          |
|                                                                      |
|  +------------------+     mTLS + cert     +-------------------+      |
|  |  Collection Agent | ---- pinning ----> |  Katana Server    |      |
|  |  (katana-agent)   |     gRPC/HTTP2     |  (katana-server)  |      |
|  |                   |                    |                   |      |
|  |  Trust boundary:  |                    |  Trust boundary:  |      |
|  |  Assume-breach.   |                    |  Authenticated    |      |
|  |  Agent compromise  |                    |  zone. RBAC       |      |
|  |  must not yield   |                    |  enforced via     |      |
|  |  server access.   |                    |  Tower middleware. |      |
|  +------------------+                    +-------------------+      |
|                                                   |                  |
|                                              JWT auth                |
|                                                   |                  |
|                                          +--------v--------+        |
|                                          |  Web API Users   |        |
|                                          |  (Examiner,      |        |
|                                          |   Reviewer,      |        |
|                                          |   Admin)         |        |
|                                          +-----------------+        |
|                                                                      |
|  MSSP MULTI-TENANCY BOUNDARY                                        |
|  ============================                                        |
|  +-------------------+  +-------------------+                        |
|  |  Tenant A Schema  |  |  Tenant B Schema  |  Schema-per-tenant    |
|  |  (isolated data)  |  |  (isolated data)  |  isolation in DuckDB  |
|  +-------------------+  +-------------------+                        |
|  Tenant ID embedded in every query via Tower middleware.              |
|  Cross-tenant queries are architecturally impossible.                |
+======================================================================+
```

### 1.4 Threat Scenarios

#### Scenario 1: Evidence Tampering Before Analysis (FT-01)

**Attacker Goal**: Modify an E01 disk image to remove incriminating artifacts before the DFIR analyst processes it.
**Attack Vector**: Attacker with access to evidence storage modifies the E01 file directly, altering USN journal entries or MFT records. The analyst then processes the tampered image, producing results that omit critical evidence.
**Example**: An insider threat actor with access to the evidence locker edits a raw disk image to remove file deletion records from the USN journal before the forensic examiner runs Katana.
**Impact**: Incorrect triage results presented in court. If undetected, the omitted evidence could change the outcome of a criminal case. Detected post-testimony, it destroys the examiner's credibility and the tool's reputation.
**Mitigation**: SHA-256 hash verification of all input evidence at ingestion time. Hash is recorded in the audit trail and compared against the hash documented in the chain of custody form. Any mismatch halts processing and alerts the examiner.

#### Scenario 2: Collection Agent Weaponization (FT-02)

**Attacker Goal**: Repurpose the collection agent as a persistent access and command-and-control channel, as demonstrated by Storm-2603's weaponization of Velociraptor in 2025.
**Attack Vector**: Attacker gains initial access to an endpoint (via phishing, WSUS exploitation, or web shell), then deploys the Katana collection agent MSI or uses an already-installed agent to exfiltrate data or deploy ransomware. The agent's elevated privileges and legitimate network traffic provide cover.
**Example**: Storm-2603 deployed Velociraptor on compromised hosts via `msiexec` on Cloudflare Workers domains, used it to tunnel Visual Studio Code for persistent remote access, and deployed Warlock, LockBit, and Babuk ransomware against VMware ESXi and Windows servers.
**Impact**: The DFIR tool becomes the attack tool. Customer endpoints are compromised through the very agent designed to protect them. Catastrophic reputational damage.
**Mitigation**: mTLS with certificate pinning (agent cannot talk to rogue servers), code-signed binaries (unsigned agents refuse to execute), resource throttling (agent cannot consume excessive CPU/memory/IO), collection scoping with allowlists (agent only collects requested artifacts), network isolation (agent communicates only with designated server). See Section 2.2 for full agent hardening architecture.

#### Scenario 3: Insider Analyst Tampers with Findings (FT-05)

**Attacker Goal**: An analyst modifies triage results before they are presented in court, either to frame a suspect or to exonerate one.
**Attack Vector**: The analyst exports results, modifies specific entries (e.g., removes a file deletion record or changes a timestamp), and submits the altered report.
**Impact**: Falsified evidence presented under oath. If the hash-chain audit trail detects the tampering, the analyst faces criminal charges. If undetected, a miscarriage of justice.
**Mitigation**: Hash-chain audit trail (Section 4.2) makes every analyst action immutable and tamper-evident. All output files include SHA-256 manifests. Reviewer role provides independent verification. Export operations are audit-logged with before/after hashes.

#### Scenario 4: Supply Chain Compromise via Cargo Crate (FT-04)

**Attacker Goal**: Inject a backdoor into Katana through a compromised upstream dependency (cargo crate).
**Attack Vector**: An attacker compromises a maintainer account for a crate in Katana's dependency tree (e.g., an NTFS parsing library or EWF reader), publishes a malicious update that exfiltrates evidence data or introduces non-deterministic parsing.
**Example**: The `xz-utils` backdoor (CVE-2024-3094) demonstrated how a patient, years-long social engineering campaign can compromise critical infrastructure dependencies.
**Impact**: Every Katana installation using the compromised version becomes a data exfiltration tool or produces unreliable results, destroying Daubert compliance.
**Mitigation**: `cargo-vet` for supply chain auditing, `cargo-deny` for license and advisory checking, pinned dependency versions in `Cargo.lock`, minimal dependency philosophy (prefer Rust standard library over third-party crates), binary reproducibility verification, and SBOM generation for enterprise customers.

#### Scenario 5: Multi-Tenant Evidence Leak (FT-06)

**Attacker Goal**: MSSP customer A gains access to customer B's forensic evidence stored on the same Katana server instance.
**Attack Vector**: A vulnerability in tenant isolation (e.g., a query that omits the tenant ID filter, a shared temp directory, or a race condition in schema switching) allows cross-tenant data access.
**Example**: An examiner working for MSSP client Acme Corp runs a timeline query that, due to a missing tenant filter in a newly added API endpoint, returns evidence from competitor BetaCo's active investigation.
**Impact**: Chain of custody destroyed for both investigations. Legal liability for the MSSP. Potential evidence spoliation claims. Loss of all MSSP customers.
**Mitigation**: Schema-per-tenant isolation in DuckDB, tenant ID embedded in every query via Tower middleware (not optional per-endpoint), integration tests that verify cross-tenant isolation on every API endpoint, and tenant-scoped file storage paths.

---

## 2. Authentication Architecture

### 2.1 Two-Tier Identity Model

Security Ronin Katana operates with fundamentally different identity models for its two tiers:

**Community Tier: No Identity**

The community tier is a local CLI tool with zero network access. There are no user accounts, no authentication, no sessions, and no telemetry. The user is a single practitioner running `katana-cli` on their own machine. Identity is irrelevant -- the user is whoever is logged into the OS. Chain of custody responsibility lies entirely with the practitioner and their organization's procedures.

**Enterprise Tier: Three Identity Types**

```
+-------------------------------------------------------------------+
|                ENTERPRISE IDENTITY MODEL                          |
+-------------------------------------------------------------------+
|                                                                   |
|  HUMAN USERS                      COLLECTION AGENTS               |
|  ============                     ==================              |
|  +-------------------+            +-------------------+           |
|  |  User Identity    |            |  Agent Identity   |           |
|  |  - user_id (UUID) |            |  - agent_id (UUID)|           |
|  |  - email          |            |  - hostname       |           |
|  |  - role (RBAC)    |            |  - mTLS cert CN   |           |
|  |  - tenant_id      |            |  - tenant_id      |           |
|  |  - JWT token      |            |  - capabilities[] |           |
|  +-------------------+            +-------------------+           |
|                                                                   |
|  SERVICE IDENTITY (internal)                                      |
|  ===========================                                      |
|  +-------------------+                                            |
|  |  Service Identity |  Internal crate-to-crate calls.            |
|  |  - service_name   |  No network boundary. Compile-time         |
|  |  - version        |  trust via Rust type system.               |
|  +-------------------+                                            |
+-------------------------------------------------------------------+
```

### 2.2 Collection Agent Authentication (Assume-Breach Architecture)

The collection agent (`katana-agent`) runs on customer endpoints with elevated privileges. It is the highest-risk component and is designed with the assumption that some agents will be compromised.

**Authentication Chain:**

```
Agent Enrollment (one-time):
  1. Admin generates enrollment token (single-use, 24h TTL)
  2. Agent contacts server with enrollment token over TLS
  3. Server issues client certificate (X.509, 90-day validity)
  4. Agent pins server certificate fingerprint locally
  5. Enrollment token is invalidated

Agent Communication (ongoing):
  1. Agent connects via gRPC/HTTP2 with mTLS
  2. Server verifies client certificate against enrollment record
  3. Server checks certificate revocation list (CRL)
  4. Agent verifies server certificate against pinned fingerprint
  5. Tenant ID extracted from certificate CN
  6. Capabilities scoped per agent enrollment profile
```

**Hardening Controls:**

| Control | Implementation | Rationale |
|---------|---------------|-----------|
| **mTLS** | tonic + rustls, no OpenSSL | Mutual authentication; agent cannot talk to rogue servers |
| **Certificate Pinning** | Server cert fingerprint stored in agent config | Prevents MITM even if CA is compromised |
| **Code Signing** | Ed25519 signatures on agent binaries | Unsigned/tampered binaries refuse to execute |
| **No Static Credentials** | Certificate-based auth only, no API keys or passwords | Nothing to extract from binary or memory |
| **Resource Throttling** | Configurable CPU/memory/IO limits per-agent | Prevents weaponized agent from DoS on endpoint |
| **Collection Scoping** | Allowlist of collectible artifact types | Agent cannot be repurposed for arbitrary data exfiltration |
| **Network Isolation** | Agent communicates only with enrolled server | Blocks agent-to-agent lateral movement |
| **Tamper Protection** | OS-level service protection, integrity monitoring | Alerts on agent modification or unauthorized uninstallation |
| **Revocation** | Server-side CRL checked on every connection | Compromised agent certificates are immediately revoked |

**Blast Radius Containment:**

A compromised agent can:
- Send collected artifacts to the server (normal behavior)
- Consume local resources within throttle limits

A compromised agent cannot:
- Authenticate to other agents (no agent-to-agent communication)
- Escalate to server-side admin access (agent role has no admin capabilities)
- Access other tenants' data (tenant ID bound to certificate)
- Execute arbitrary commands from the server (agent only accepts collection tasks, not shell commands)
- Survive certificate revocation (CRL check on every connection)

### 2.3 User Authentication (Enterprise Tier)

**Primary Method: JWT with SSO/SAML**

```
Authentication Flow:
  1. User authenticates via SSO provider (WorkOS/Scalekit integration)
  2. IdP returns SAML assertion to Katana server
  3. Katana server validates assertion, extracts user attributes
  4. Server issues JWT (RS256, 1h expiry, refresh token 7d)
  5. JWT contains: user_id, tenant_id, role, permissions[]
  6. Every API request includes JWT in Authorization header
  7. Tower middleware validates JWT before routing to handler

Token Structure:
  {
    "sub": "user_id (UUID)",
    "tid": "tenant_id (UUID)",
    "role": "examiner",
    "perms": ["case.view", "evidence.ingest", "triage.run"],
    "iat": 1710028800,
    "exp": 1710032400,
    "iss": "katana-server"
  }
```

**SSO Implementation:**

- Use WorkOS or Scalekit as SSO middleware (buy, not build)
- Supports SAML 2.0, OIDC, and SCIM for directory sync
- Each enterprise customer configures their own IdP connection
- Avoids the SAML certificate rotation nightmare by delegating to the SSO provider
- Avoids the Auth0 MAU pricing trap by using flat-rate SSO providers

**Local Authentication Fallback:**

- Argon2id password hashing for customers without SSO
- TOTP-based 2FA mandatory for local accounts
- Rate-limited login attempts (5 attempts, 15-minute lockout)

---

## 3. Authorization Matrix

### 3.1 Role-Based Access Control (RBAC)

| Role | Description | Case Permissions | Evidence Permissions | System Permissions |
|------|-------------|-----------------|---------------------|-------------------|
| **Admin** | System administrator | Create, view, manage, close all cases | Full access to all evidence | User management, system config, audit view |
| **Case Manager** | Investigation lead | Create, view, manage, close assigned cases | Full access within assigned cases | Assign examiners, review reports |
| **Examiner** | DFIR analyst | View assigned cases | Ingest, view, annotate, run triage, generate reports | None |
| **Reviewer** | Quality control | View assigned cases (read-only) | View evidence, approve/reject findings | None |
| **Auditor** | Compliance officer | Read-only access to all cases | Read-only access to all evidence | Full audit trail access |

### 3.2 Permission Model (Case-Level + Evidence-Level)

```rust
// Dual-granularity permission enforcement
pub enum Permission {
    // Case-level permissions
    CaseCreate,
    CaseView(CaseId),
    CaseManage(CaseId),
    CaseClose(CaseId),

    // Evidence-level permissions
    EvidenceIngest(CaseId),
    EvidenceView(CaseId, EvidenceId),
    EvidenceAnnotate(CaseId, EvidenceId),
    EvidenceExport(CaseId, EvidenceId),
    EvidenceDelete(CaseId, EvidenceId),  // Admin only, audit-logged

    // Analysis permissions
    TimelineView(CaseId),
    TimelineAnnotate(CaseId),
    TriageRun(CaseId),
    ReportGenerate(CaseId),

    // System permissions
    UserManage,
    SystemConfig,
    AuditView,
}
```

**Enforcement Point:** All permissions are checked in Tower middleware before the request reaches the Axum handler. There is no permission check in the handler itself -- if the request reaches the handler, it is authorized.

### 3.3 Collection Agent Authorization

| Capability | Description | Default |
|-----------|-------------|---------|
| `collect:usn` | Collect USN journal data | Enabled |
| `collect:mft` | Collect MFT records | Enabled |
| `collect:evtx` | Collect Windows Event Logs | Enabled |
| `collect:prefetch` | Collect Prefetch files | Enabled |
| `collect:registry` | Collect Registry hives | Disabled |
| `upload:evidence` | Upload collected artifacts to server | Enabled |
| `status:report` | Report agent health and status | Enabled |

Agents cannot request capabilities beyond their enrollment profile. The server rejects any task request for a capability not in the agent's profile.

### 3.4 Multi-Tenancy Data Access Controls

**Schema-per-tenant isolation using DuckDB:**

```sql
-- Each tenant gets a dedicated schema
CREATE SCHEMA tenant_acme;
CREATE SCHEMA tenant_betaco;

-- All tables scoped to tenant schema
CREATE TABLE tenant_acme.cases (...);
CREATE TABLE tenant_acme.evidence (...);
CREATE TABLE tenant_acme.audit_log (...);

-- Tower middleware injects tenant context
-- Every query is prefixed with SET SCHEMA = 'tenant_{id}';
-- Cross-schema joins are architecturally impossible in this model
```

**File Storage Isolation:**

```
/data/tenants/
  {tenant_id}/
    cases/
      {case_id}/
        evidence/
          {evidence_id}.e01
          {evidence_id}.e01.sha256
        outputs/
          {run_id}/
            triage_results.jsonl
            triage_results.jsonl.sha256
```

OS-level directory permissions enforce that the Katana server process accesses tenant directories only through the tenant-scoped middleware path. Direct filesystem access bypassing the application layer requires OS-level compromise.

---

## 4. Audit System

### 4.1 Forensic Audit Requirements

Unlike typical application audit logging, Katana's audit system must itself be forensically sound. The audit trail is evidence about evidence -- it must be immutable, tamper-evident, and legally admissible.

**Design Principles:**
- Append-only storage (no UPDATE or DELETE operations on audit tables)
- Hash-chain linking (each entry contains the hash of the previous entry)
- Tamper detection via hash-chain verification
- Cryptographic timestamping for non-repudiation

### 4.2 Hash-Chain Audit Trail

```
+-------------------------------------------------------------------+
|                  HASH-CHAIN AUDIT TRAIL                           |
+-------------------------------------------------------------------+
|                                                                   |
|  Entry N-1           Entry N             Entry N+1                |
|  +---------------+   +---------------+   +---------------+       |
|  | event_id      |   | event_id      |   | event_id      |       |
|  | timestamp     |   | timestamp     |   | timestamp     |       |
|  | actor_id      |   | actor_id      |   | actor_id      |       |
|  | action        |   | action        |   | action        |       |
|  | target        |   | target        |   | target        |       |
|  | details       |   | details       |   | details       |       |
|  | prev_hash ----+--->| prev_hash ----+--->| prev_hash     |       |
|  | entry_hash    |   | entry_hash    |   | entry_hash    |       |
|  +---------------+   +---------------+   +---------------+       |
|                                                                   |
|  entry_hash = SHA-256(event_id + timestamp + actor_id + action    |
|               + target + details + prev_hash)                     |
|                                                                   |
|  Tampering with any entry breaks the hash chain from that         |
|  point forward, making modification immediately detectable.       |
+-------------------------------------------------------------------+
```

### 4.3 Audit Event Types

| Category | Event | Severity | Details Captured |
|----------|-------|----------|-----------------|
| **Evidence** | `evidence.ingested` | Info | Source hash, file size, format, case_id |
| **Evidence** | `evidence.accessed` | Info | User, case_id, evidence_id, access type |
| **Evidence** | `evidence.exported` | Warning | User, case_id, export format, output hash |
| **Evidence** | `evidence.deleted` | Critical | User, case_id, evidence_id, justification |
| **Analysis** | `triage.started` | Info | Case_id, evidence_id, katana version, config hash |
| **Analysis** | `triage.completed` | Info | Case_id, output hash, record count, duration |
| **Analysis** | `report.generated` | Info | Case_id, report hash, format |
| **Auth** | `user.login` | Info | User, IP, auth method, success/failure |
| **Auth** | `user.login_failed` | Warning | User, IP, failure reason, attempt count |
| **Auth** | `agent.enrolled` | Info | Agent_id, hostname, tenant_id, cert fingerprint |
| **Auth** | `agent.revoked` | Warning | Agent_id, reason, revoked_by |
| **RBAC** | `role.assigned` | Warning | User, role, assigned_by, case_scope |
| **RBAC** | `permission.denied` | Warning | User, attempted action, reason |
| **System** | `config.changed` | Warning | Setting, old value, new value, changed_by |
| **System** | `chain.verification` | Info | Verification result, entries checked, first broken entry |

### 4.4 Audit Log Schema

```sql
CREATE TABLE audit_log (
    event_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp    TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_type   VARCHAR NOT NULL,           -- 'user', 'agent', 'system'
    actor_id     UUID NOT NULL,
    action       VARCHAR NOT NULL,           -- 'evidence.ingested', etc.
    target_type  VARCHAR,                    -- 'case', 'evidence', 'user'
    target_id    UUID,
    details      JSONB NOT NULL DEFAULT '{}',
    severity     VARCHAR NOT NULL,           -- 'info', 'warning', 'critical'
    prev_hash    VARCHAR(64) NOT NULL,       -- SHA-256 of previous entry
    entry_hash   VARCHAR(64) NOT NULL,       -- SHA-256 of this entry
    -- No UPDATE or DELETE triggers allowed on this table
    -- Enforced via database-level policy
    CONSTRAINT audit_append_only CHECK (true)  -- placeholder for trigger
);

-- Index for chain verification
CREATE INDEX idx_audit_chain ON audit_log (timestamp ASC);
-- Index for actor queries
CREATE INDEX idx_audit_actor ON audit_log (actor_id, timestamp DESC);
-- Index for target queries
CREATE INDEX idx_audit_target ON audit_log (target_id, timestamp DESC);
```

### 4.5 Audit Query Interface

```
# Verify chain integrity (detect tampering)
GET /api/v1/audit/verify?from={timestamp}&to={timestamp}
Response: { "valid": true, "entries_checked": 15847, "chain_intact": true }

# Query audit trail for a case
GET /api/v1/audit/case/{case_id}?from={timestamp}&to={timestamp}
Response: [ { "event_id": "...", "action": "evidence.ingested", ... }, ... ]

# Export audit trail for legal proceedings
GET /api/v1/audit/export/{case_id}?format=pdf
Response: PDF document with hash-chain verification attestation
```

---

## 5. Daubert Standard Compliance

This section documents how Security Ronin Katana satisfies each prong of the Daubert standard for forensic tool admissibility.

### 5.1 Testability

| Requirement | Implementation |
|-------------|---------------|
| Methodology can be tested | Open-source code (Apache-2.0) allows any party to inspect and test the parsing logic |
| Methodology has been tested | Public test corpus with known-good inputs and expected outputs |
| Test results are reproducible | Deterministic processing -- identical input always produces byte-identical output |
| Test framework exists | `cargo test` suite with forensic validation tests, CI/CD verification on every commit |

**Public Test Corpus:**

```
katana/tests/corpus/
  usn/
    known_good_01.bin      # Known USN journal with documented entries
    known_good_01.expected # Expected parse output (hash-verified)
  mft/
    known_good_01.bin      # Known MFT with documented records
    known_good_01.expected # Expected parse output (hash-verified)
  e01/
    sample_image.e01       # Sample E01 with known content
    sample_image.expected  # Expected triage output (hash-verified)
```

### 5.2 Peer Review

| Requirement | Implementation |
|-------------|---------------|
| Subjected to peer review | Open-source repository accepts public scrutiny and contributions |
| Publication | Methodology documented in ARCHITECTURE_BLUEPRINT.md and academic-style validation papers |
| Community validation | Public issue tracker for bug reports; every reported parsing error is a peer review data point |

### 5.3 Known Error Rate

| Requirement | Implementation |
|-------------|---------------|
| Error rate is known | Precision/recall analysis published at `docs/performance/precision_recall.html` |
| Error rate is documented | False positive and false negative rates for each of the 12 triage questions |
| Error rate is acceptable | Current: >95% precision, >90% recall across triage questions |
| Error rate is tracked over time | CI/CD runs precision/recall suite on every release; results are versioned |

**Precision/Recall Pipeline:**

```
For each release:
  1. Run triage against test corpus (N known-good images)
  2. Compare output against ground truth
  3. Calculate per-question precision and recall
  4. Generate ROC curves for threshold-dependent questions
  5. Publish results to docs/performance/
  6. Fail release if any question drops below threshold
```

### 5.4 Standards Controlling Operation

| Requirement | Implementation |
|-------------|---------------|
| Standards exist | NIST SP 800-86 (Guide to Integrating Forensic Techniques), ISO 27037 (Digital Evidence) |
| Tool follows standards | SHA-256 hashing per NIST guidelines, evidence handling per ISO 27037 |
| Deviation documented | Any deviation from standards is documented in the ARCHITECTURE_BLUEPRINT.md with rationale |

### 5.5 General Acceptance

| Requirement | Implementation |
|-------------|---------------|
| Accepted in scientific community | USN journal parsing methodology is well-established in DFIR literature |
| Tool uses accepted methods | MFT parsing, USN journal analysis, and timeline reconstruction are standard DFIR techniques |
| No novel/unproven methods | All analysis methods have existing implementations in peer-reviewed tools (e.g., Zimmerman's MFTECmd, SANS tools) |

### 5.6 Daubert Packet

A "Daubert Packet" is maintained at `docs/daubert/` containing:

1. **Tool Methodology Document** -- How Katana parses USN journals, MFT records, and answers triage questions
2. **Validation Report** -- Test corpus results with precision/recall metrics
3. **Error Rate History** -- Version-by-version error rate tracking
4. **Source Code Reference** -- Pointer to the open-source repository for inspection
5. **Expert Witness Template** -- Template testimony for forensic examiners using Katana in court

---

## 6. Resilience Safeguards

### 6.1 Collection Agent Safeguards

| Control | Trigger | Action |
|---------|---------|--------|
| **CPU Throttle** | Agent CPU usage > 15% sustained | Reduce collection rate, yield to user workload |
| **Memory Limit** | Agent memory > 256 MB | Pause collection, flush buffers, resume at lower rate |
| **IO Throttle** | Agent disk IO > 50 MB/s | Throttle read operations to prevent disk contention |
| **Network Limit** | Upload bandwidth > 10 MB/s | Queue uploads, transmit during low-activity windows |
| **Watchdog Timer** | Collection task running > 30 min | Kill task, report timeout, alert server |
| **Heartbeat** | No server contact > 5 min | Cache collected data locally, retry with exponential backoff |

### 6.2 Server-Side Safeguards

| Control | Trigger | Action |
|---------|---------|--------|
| **Rate Limiting** | > 100 API requests/min per user | Return 429, log warning |
| **Evidence Size Limit** | Single evidence file > 500 GB | Reject upload, require chunked ingestion |
| **Concurrent Analysis Limit** | > 10 simultaneous triage runs | Queue additional requests |
| **Circuit Breaker** | > 5 consecutive failures on external service | Open circuit, stop requests, retry after 60s |
| **Disk Space Monitor** | Storage > 90% capacity | Alert admin, reject new evidence ingestion |

### 6.3 Kill Switches

| Switch | Scope | Activation | Effect |
|--------|-------|------------|--------|
| **Agent Fleet Kill** | All agents | Admin API call | All agents stop collection, enter standby mode |
| **Single Agent Kill** | One agent | Admin API call + CRL update | Target agent certificate revoked, connection refused |
| **Tenant Lockout** | One tenant | Admin API call | All users and agents for tenant suspended |
| **Evidence Quarantine** | One evidence item | Examiner or Admin | Evidence marked read-only, analysis results preserved but flagged |
| **Emergency Shutdown** | Entire server | Admin API call | Graceful shutdown of all services, audit trail finalized |

---

## 7. Human Escalation Rules

### 7.1 Automatic Escalation Triggers

| Trigger | Escalation Target | Response Time |
|---------|-------------------|---------------|
| Hash mismatch on evidence input | Case Manager + Examiner | Immediate (block processing) |
| Audit chain integrity failure | Admin + Auditor | 15 minutes |
| Agent certificate revocation (non-admin initiated) | Admin | 15 minutes |
| Cross-tenant query detected in logs | Admin | Immediate |
| Failed login attempts > 10 in 5 minutes | Admin | 30 minutes |
| Evidence deletion requested | Case Manager (approval required) | Manual review |
| Agent deployed on unexpected host | Admin + Case Manager | 1 hour |
| Triage results differ from previous run on same evidence | Examiner + Reviewer | Next business day |

### 7.2 Escalation Flow

```
Trigger Detected
       |
       v
  Is it a chain-of-custody event?
       |
  +----+----+
  |         |
  Yes       No
  |         |
  v         v
 BLOCK     Is it a security event?
 processing     |
 immediately +--+--+
  |          |     |
  v          Yes   No
 Alert       |     |
 Case Mgr   v     v
 + Examiner  Alert  Log and
             Admin  continue
             |
             v
         Assess severity
             |
      +------+------+
      |      |      |
    SEV-1  SEV-2  SEV-3/4
      |      |      |
      v      v      v
    15min  1hr   4hr/24hr
    response  response  response
```

### 7.3 Chain-of-Custody Escalation

Any event that could break the chain of custody triggers an immediate halt-and-escalate:

1. **Hash mismatch** -- Evidence hash does not match chain of custody documentation
2. **Unauthorized access** -- User accesses evidence outside their assigned cases
3. **Audit gap** -- Missing audit entries detected during chain verification
4. **Concurrent modification** -- Two analysts modifying the same evidence simultaneously
5. **Export without authorization** -- Evidence exported by user without export permission

---

## 8. Incident Response Playbook

### 8.1 Severity Levels (Forensic-Adapted)

| Level | Description | Response Time | Forensic Examples |
|-------|-------------|---------------|-------------------|
| **SEV-1** | Evidence integrity compromised | 15 min | Hash chain broken, evidence tampering detected, agent fleet compromise |
| **SEV-2** | Security control bypassed | 1 hour | RBAC bypass, cross-tenant access, unauthorized agent deployment |
| **SEV-3** | Suspicious activity detected | 4 hours | Repeated failed logins, unusual agent behavior, large evidence export |
| **SEV-4** | Policy violation | 24 hours | Missing audit entry, configuration drift, expired certificate not rotated |

### 8.2 Response Procedures

#### SEV-1: Evidence Integrity Compromised

1. **Immediate Actions** (0-15 min)
   - Activate incident commander (Admin)
   - Quarantine affected evidence (read-only lock)
   - Suspend all triage runs against affected evidence
   - Preserve audit trail (export hash-chain for affected period)
   - Notify Case Manager and all assigned Examiners

2. **Containment** (15-60 min)
   - Identify scope: which cases, evidence items, and triage results are affected
   - Verify hash-chain integrity across entire audit trail
   - If agent compromise: revoke agent certificate immediately
   - If insider threat: suspend user account, preserve session logs

3. **Assessment** (1-4 hours)
   - Determine root cause (tampering, software bug, or hardware failure)
   - Assess legal impact: which court cases use affected evidence
   - Contact legal counsel if evidence was already submitted to court
   - Generate incident report with full audit trail export

4. **Recovery** (4-24 hours)
   - Re-ingest evidence from original source if available
   - Re-run triage with verified input
   - Compare results against original output
   - Document all recovery actions in audit trail

5. **Post-Incident** (24-72 hours)
   - Root cause analysis document
   - Update threat model if new attack vector identified
   - Implement preventive controls
   - Notify affected customers (MSSP tenants)

#### SEV-2: Collection Agent Compromise

1. **Immediate Actions** (0-15 min)
   - Revoke compromised agent certificate via CRL update
   - Activate agent fleet kill switch if scope is unclear
   - Quarantine all evidence collected by compromised agent

2. **Containment** (15-60 min)
   - Identify all endpoints with the compromised agent
   - Check for lateral movement indicators
   - Verify other agents' certificate integrity
   - Review agent communication logs for anomalous patterns

3. **Eradication** (1-4 hours)
   - Remove compromised agent from affected endpoints
   - Rotate server-side certificates if server compromise suspected
   - Re-deploy agents with fresh certificates
   - Scan affected endpoints for residual compromise

4. **Recovery** (4-24 hours)
   - Re-collect evidence from affected endpoints using fresh agents
   - Verify re-collected evidence against original hashes (if available)
   - Restore normal agent fleet operations
   - Enhanced monitoring for 30 days

### 8.3 Communication Templates

#### Evidence Integrity Incident Notification

```markdown
INCIDENT NOTIFICATION -- EVIDENCE INTEGRITY

Severity: SEV-1
Status: [Investigating | Contained | Resolved]
Incident ID: [UUID]
Affected Cases: [Case IDs]
Affected Evidence: [Evidence IDs]

Timeline:
  [Timestamp] -- Incident detected
  [Timestamp] -- Evidence quarantined
  [Timestamp] -- Scope assessed
  [Timestamp] -- Current status

Impact: [Description of impact to investigations and court proceedings]

Actions Taken:
  - [List of containment and remediation actions]

Required Actions:
  - [Any required actions from case managers, examiners, or legal counsel]

Audit Trail Export: [Link to hash-chain verified audit export for affected period]
```

---

## 9. Security Checklist

### Pre-Launch Checklist

#### Authentication and Authorization
- [ ] mTLS configured for agent-server communication
- [ ] Certificate pinning implemented in agent binary
- [ ] Agent enrollment flow tested (enrollment token, cert issuance, revocation)
- [ ] JWT authentication configured for web API
- [ ] SSO/SAML integration tested with at least 2 IdPs
- [ ] RBAC roles defined and enforced in Tower middleware
- [ ] Permission checks prevent cross-case and cross-tenant access
- [ ] Rate limiting configured on all API endpoints
- [ ] Login attempt throttling implemented
- [ ] 2FA mandatory for local (non-SSO) accounts

#### Data Protection
- [ ] SHA-256 hash verification on all evidence ingestion
- [ ] Hash manifest generated for all triage outputs
- [ ] Schema-per-tenant isolation verified (cross-tenant query test)
- [ ] Tenant-scoped file storage paths enforced
- [ ] Evidence at rest encrypted (AES-256)
- [ ] Evidence in transit encrypted (TLS 1.3 / mTLS)
- [ ] No evidence data in application logs (only hashes and IDs)

#### Forensic Integrity
- [ ] Deterministic output verified (same input = byte-identical output across runs)
- [ ] Version-locked output format with format version in every output file
- [ ] Public test corpus with expected output hashes
- [ ] Precision/recall metrics published and meeting thresholds
- [ ] Daubert packet assembled and reviewed by legal counsel
- [ ] Chain of custody form template available

#### Threat Mitigation
- [ ] Agent code signing configured and verified
- [ ] Agent resource throttling tested under load
- [ ] Agent kill switch (single and fleet) tested
- [ ] Evidence quarantine mechanism tested
- [ ] `cargo-vet` supply chain auditing enabled
- [ ] `cargo-deny` license and advisory checking enabled
- [ ] Dependency versions pinned in Cargo.lock
- [ ] SBOM generation configured for enterprise releases

#### Monitoring and Response
- [ ] Hash-chain audit trail operational
- [ ] Audit chain verification job scheduled (daily)
- [ ] Escalation triggers configured and tested
- [ ] Kill switches accessible and tested
- [ ] Incident response playbook reviewed by team
- [ ] Evidence integrity monitoring active

### Post-Launch Monitoring

- [ ] Daily: Audit chain integrity verification
- [ ] Weekly: Review failed login attempts and permission denials
- [ ] Weekly: Review agent fleet health (disconnected agents, certificate expiry)
- [ ] Monthly: Rotate service credentials
- [ ] Quarterly: Review RBAC role assignments
- [ ] Quarterly: Dependency audit (`cargo-vet` + `cargo-deny`)
- [ ] Annually: Full security architecture review
- [ ] Annually: Penetration test (focus on cross-tenant isolation and agent hardening)

---

## 10. Security Architecture Summary

### Defense in Depth

```
+--------------------------------------------------------------------------+
|                    SECURITY RONIN KATANA DEFENSE IN DEPTH                 |
+--------------------------------------------------------------------------+
|                                                                          |
|  Layer 1: EVIDENCE INTEGRITY                                             |
|  +--------------------------------------------------------------------+  |
|  |  SHA-256 hash on input | Deterministic processing | Hash manifest  |  |
|  |  on output | Version-locked format | Daubert compliance             |  |
|  +--------------------------------------------------------------------+  |
|                                                                          |
|  Layer 2: AGENT HARDENING                                                |
|  +--------------------------------------------------------------------+  |
|  |  mTLS + cert pinning | Code signing | Resource throttling |         |  |
|  |  Collection scoping | Network isolation | Assume-breach design      |  |
|  +--------------------------------------------------------------------+  |
|                                                                          |
|  Layer 3: AUTHENTICATION                                                 |
|  +--------------------------------------------------------------------+  |
|  |  JWT + SSO/SAML (users) | mTLS certs (agents) | No static creds   |  |
|  +--------------------------------------------------------------------+  |
|                                                                          |
|  Layer 4: AUTHORIZATION                                                  |
|  +--------------------------------------------------------------------+  |
|  |  RBAC (5 roles) | Case-level + evidence-level perms | Tower        |  |
|  |  middleware enforcement | Schema-per-tenant isolation               |  |
|  +--------------------------------------------------------------------+  |
|                                                                          |
|  Layer 5: AUDIT & CHAIN OF CUSTODY                                       |
|  +--------------------------------------------------------------------+  |
|  |  Hash-chain audit trail | Append-only storage | Tamper detection   |  |
|  |  Cryptographic timestamps | Legal-grade export                     |  |
|  +--------------------------------------------------------------------+  |
|                                                                          |
|  Layer 6: RESILIENCE                                                     |
|  +--------------------------------------------------------------------+  |
|  |  Agent kill switches | Evidence quarantine | Circuit breakers      |  |
|  |  Rate limiting | Resource throttling | Graceful degradation        |  |
|  +--------------------------------------------------------------------+  |
|                                                                          |
|  Layer 7: INCIDENT RESPONSE                                              |
|  +--------------------------------------------------------------------+  |
|  |  SEV-1 to SEV-4 classification | Forensic-adapted playbooks       |  |
|  |  Evidence preservation first | Legal counsel notification          |  |
|  +--------------------------------------------------------------------+  |
|                                                                          |
+--------------------------------------------------------------------------+
```

### Key Security Principles

1. **Forensic Integrity Above All** -- Axiom 1 (Forensic Integrity > Feature Velocity) governs every security decision. A feature that introduces non-determinism is rejected regardless of user demand.
2. **Assume Breach** -- Axiom 5 (Assume Breach > Assume Safety) means the collection agent is designed for the case where it is compromised. Agent compromise must not mean server compromise.
3. **Two-Tier Trust** -- Community tier has zero attack surface (no network, no auth, no accounts). Enterprise tier has defense in depth across all seven layers.
4. **Evidence is Immutable** -- Once ingested, evidence is never modified. Analysis produces new artifacts, never modifies the source. Hash verification at every boundary.
5. **Audit Trail is Evidence** -- The audit trail is itself forensic evidence. It must meet the same integrity standards as the evidence it records.
6. **Buy Auth, Build Forensics** -- Authentication (SSO/SAML) is purchased (WorkOS/Scalekit). Forensic integrity controls are built in-house because they are the core differentiator.
7. **Blast Radius Containment** -- Every component is designed so that its compromise does not cascade. Agent to server, tenant to tenant, user to admin -- each boundary contains the blast.
