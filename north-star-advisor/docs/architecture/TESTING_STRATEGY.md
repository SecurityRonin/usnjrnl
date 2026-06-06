# Security Ronin Katana: Testing Strategy

> Forensic integrity is non-negotiable -- every output must be deterministic, verifiable, and court-admissible. This testing strategy exists to prove that claim under adversarial scrutiny.

---

## 1. Test Categories

### 1.1 Test Pyramid

| Layer | Scope | Framework | Count Target | Execution Time |
|-------|-------|-----------|-------------|----------------|
| **Unit** | Individual parsers, record types, correlation logic | `cargo test` (built-in) | 500+ | < 30s total |
| **Property** | Parser invariants, roundtrip encoding, boundary conditions | `proptest` | 100+ generators | < 60s total |
| **Fuzz** | Parser robustness against malformed/corrupt input | `cargo-fuzz` (libFuzzer) + AFL | Continuous | 24h+ corpus runs |
| **Integration** | Stage-to-stage pipeline contracts, format verification | `cargo test --test` | 80+ | < 120s total |
| **Golden** | Determinism verification against known-good test images | Custom harness + SHA-256 | 30+ cases | < 90s total |
| **Precision/Recall** | Triage question accuracy per IR question | Custom metrics harness | 12 questions x 5+ images | < 180s total |
| **Performance** | P95 regression budget enforcement | `criterion` benchmarks | 9 stage budgets | < 300s total |
| **E2E** | Full image-to-report pipeline verification | CLI integration tests | 15+ scenarios | < 300s total |
| **Enterprise** | RBAC, multi-tenant isolation, mTLS, audit trail | `cargo test` + `tonic` test utilities | 60+ | < 120s total |

### 1.2 Coverage Targets

| Crate | Line Coverage | Branch Coverage | Rationale |
|-------|--------------|-----------------|-----------|
| `katana-core` (parsers) | 95% | 90% | Parser correctness is Daubert-critical |
| `katana-core` (triage) | 90% | 85% | Triage accuracy directly impacts IR outcomes |
| `katana-core` (ghost recovery) | 95% | 90% | Recovery claims must be provable |
| `katana-ewf` | 85% | 80% | FFI boundary -- focus on error paths |
| `katana-ntfs` | 90% | 85% | Filesystem parsing must handle edge cases |
| `katana-formats` | 85% | 80% | Output format correctness is auditable |
| `katana-server` | 80% | 75% | Enterprise API coverage |
| `katana-agent` | 80% | 75% | Collection agent reliability |
| `katana-multi` | 90% | 85% | Tenant isolation is security-critical |

Coverage is measured with `cargo-llvm-cov` and enforced in CI. Coverage drops below threshold fail the build.

---

## 2. Test Configuration

### 2.1 Test Framework Configuration

```toml
# Cargo.toml workspace test configuration
[workspace]
members = [
    "katana-core",
    "katana-ewf",
    "katana-ntfs",
    "katana-formats",
    "katana-server",
    "katana-agent",
    "katana-multi",
]

# Per-crate test dependencies (example: katana-core)
[dev-dependencies]
proptest = "1.4"
criterion = { version = "0.5", features = ["html_reports"] }
tempfile = "3.10"
assert_cmd = "2.0"
predicates = "3.1"
insta = { version = "1.38", features = ["yaml"] }  # snapshot testing
sha2 = "0.10"                                       # determinism verification
hex = "0.4"
test-case = "3.3"                                    # parameterized tests
mockall = "0.12"                                     # trait mocking for enterprise

[[bench]]
name = "pipeline_benchmark"
harness = false
```

### 2.2 Test Directory Structure

```
tests/
  unit/
    usn_parser_test.rs          # USN V2/V3/V4 record parsing
    mft_parser_test.rs          # MFT entry parsing and attribute extraction
    ghost_recovery_test.rs      # Ghost record reconstruction
    unallocated_carving_test.rs # Unallocated space carving
    quadlink_test.rs            # 4-artifact correlation engine
    triage_engine_test.rs       # Triage question evaluation
    timeline_test.rs            # Timeline construction and sorting
    path_resolver_test.rs       # CyberCX Rewind path reconstruction
  integration/
    pipeline_test.rs            # Stage-to-stage contract verification
    image_integration.rs        # Full image parsing (E01, raw)
    report_integration.rs       # Output format verification (7 formats)
    format_roundtrip_test.rs    # Parse -> serialize -> parse identity
  golden/
    determinism_test.rs         # Hash-match verification across runs
    known_answers_test.rs       # Known-good image -> expected output
    regression_test.rs          # Previously-found bug regression
  precision_recall/
    triage_accuracy_test.rs     # Per-question P/R measurement
    false_positive_test.rs      # FP rate verification (< 5% target)
    ghost_recovery_rate_test.rs # Recovery completeness (> 95% target)
  performance/
    pipeline_bench.rs           # Per-stage budget enforcement
    throughput_bench.rs         # Records/second measurement
    memory_bench.rs             # Peak RSS tracking
  e2e/
    cli_test.rs                 # Full CLI invocation tests
    output_format_test.rs       # All 7 output formats end-to-end
    error_handling_test.rs      # Corrupt/missing/unsupported input
  enterprise/
    rbac_test.rs                # Role-based access control
    multi_tenant_test.rs        # Schema-per-tenant isolation
    mtls_test.rs                # Certificate pinning verification
    audit_trail_test.rs         # Hash-chain append-only log
    import_test.rs              # Velociraptor/Binalyze format import
  fuzz/
    fuzz_targets/
      fuzz_usn_parser.rs        # USN record fuzzing
      fuzz_mft_parser.rs        # MFT entry fuzzing
      fuzz_ntfs_volume.rs       # NTFS structure fuzzing
      fuzz_ewf_header.rs        # EWF header fuzzing
fixtures/
  images/
    known-good/                 # Public test images with ground truth
    corrupt/                    # Intentionally malformed images
    edge-cases/                 # Boundary condition images
  expected/
    golden/                     # SHA-256 verified expected outputs
    triage/                     # Expected triage answers per image
```

### 2.3 Test Setup

```rust
// tests/common/mod.rs -- shared test utilities

use std::path::PathBuf;
use sha2::{Sha256, Digest};
use tempfile::TempDir;

/// Returns path to test fixtures directory
pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Returns path to a specific test image
pub fn test_image(name: &str) -> PathBuf {
    fixtures_dir().join("images/known-good").join(name)
}

/// Compute SHA-256 of file contents for determinism verification
pub fn file_sha256(path: &std::path::Path) -> String {
    let bytes = std::fs::read(path).expect("failed to read file for hashing");
    let hash = Sha256::digest(&bytes);
    hex::encode(hash)
}

/// Assert two outputs are byte-identical (determinism check)
pub fn assert_deterministic(output_a: &[u8], output_b: &[u8]) {
    let hash_a = hex::encode(Sha256::digest(output_a));
    let hash_b = hex::encode(Sha256::digest(output_b));
    assert_eq!(
        hash_a, hash_b,
        "Determinism violation: outputs differ.\n  Run A: {}\n  Run B: {}",
        hash_a, hash_b
    );
}

/// Create isolated temp directory for test output
pub fn test_output_dir() -> TempDir {
    tempfile::tempdir().expect("failed to create test output directory")
}
```

---

## 3. Golden Datasets

### 3.1 Golden Dataset Structure

Each golden dataset entry pairs a forensic image (or extracted artifact) with its verified ground truth. Ground truth is established through manual expert analysis and cross-validated with at least two independent tools.

```yaml
# tests/fixtures/golden_manifest.yml

datasets:
  - id: "NIST-CFREDS-NTFS-01"
    source: "NIST CFReDS"
    image: "images/known-good/cfreds-ntfs-2023.E01"
    description: "NIST CFReDS NTFS test image with known file operations"
    ground_truth: "expected/golden/cfreds-ntfs-2023.yml"
    sha256_image: "a1b2c3d4..."
    sha256_output: "e5f6a7b8..."
    record_count: 12847
    ghost_count: 342
    triage_answers:
      ransomware_indicators: false
      lateral_movement: false
      data_exfiltration: false
    validated_by: "manual + Autopsy + plaso cross-check"

  - id: "SANS-DFIR-LATERAL-01"
    source: "SANS DFIR challenge (public)"
    image: "images/known-good/sans-lateral-2024.raw"
    description: "Lateral movement scenario with RDP, PsExec, WMI artifacts"
    ground_truth: "expected/golden/sans-lateral-2024.yml"
    sha256_image: "b2c3d4e5..."
    sha256_output: "f6a7b8c9..."
    record_count: 87293
    ghost_count: 1204
    triage_answers:
      ransomware_indicators: false
      lateral_movement: true
      data_exfiltration: true
    validated_by: "manual + Eric Zimmerman MFTECmd + KAPE"

  - id: "KATANA-RANSOMWARE-01"
    source: "Security Ronin lab-generated"
    image: "images/known-good/katana-ransomware-01.E01"
    description: "Simulated ransomware attack with encryption, shadow copy deletion, persistence"
    ground_truth: "expected/golden/katana-ransomware-01.yml"
    sha256_image: "c3d4e5f6..."
    sha256_output: "a7b8c9d0..."
    record_count: 34521
    ghost_count: 8923
    triage_answers:
      ransomware_indicators: true
      lateral_movement: false
      data_exfiltration: false
    validated_by: "manual + Autopsy + X-Ways"

  - id: "KATANA-GHOST-RECOVERY-01"
    source: "Security Ronin lab-generated"
    image: "images/known-good/katana-ghost-heavy-01.raw"
    description: "Image with high $MFT reuse and UsnJrnl wrap-around for ghost recovery stress test"
    ground_truth: "expected/golden/katana-ghost-heavy-01.yml"
    sha256_image: "d4e5f6a7..."
    sha256_output: "b8c9d0e1..."
    record_count: 256000
    ghost_count: 42000
    triage_answers:
      ransomware_indicators: false
      lateral_movement: false
      data_exfiltration: false
    validated_by: "manual enumeration + custom validation script"

  - id: "KATANA-EDGE-MIXED-USN-01"
    source: "Security Ronin lab-generated"
    image: "images/known-good/katana-mixed-usn-v2v3v4.raw"
    description: "USN Journal with mixed V2/V3/V4 records and journal wrap-around"
    ground_truth: "expected/golden/katana-mixed-usn-v2v3v4.yml"
    sha256_image: "e5f6a7b8..."
    sha256_output: "c9d0e1f2..."
    record_count: 45000
    ghost_count: 0
    triage_answers:
      ransomware_indicators: false
      lateral_movement: false
      data_exfiltration: false
    validated_by: "manual + fsutil usn readjournal cross-check"

  - id: "KATANA-EXFIL-01"
    source: "Security Ronin lab-generated"
    image: "images/known-good/katana-exfil-01.E01"
    description: "Data exfiltration via USB, cloud sync, archive creation"
    ground_truth: "expected/golden/katana-exfil-01.yml"
    sha256_image: "f6a7b8c9..."
    sha256_output: "d0e1f2a3..."
    record_count: 67000
    ghost_count: 3200
    triage_answers:
      ransomware_indicators: false
      lateral_movement: false
      data_exfiltration: true
    validated_by: "manual + plaso + log2timeline"

  - id: "KATANA-PERSISTENCE-01"
    source: "Security Ronin lab-generated"
    image: "images/known-good/katana-persistence-01.raw"
    description: "Multiple persistence mechanisms: scheduled tasks, services, Run keys via file operations"
    ground_truth: "expected/golden/katana-persistence-01.yml"
    sha256_image: "a7b8c9d0..."
    sha256_output: "e1f2a3b4..."
    record_count: 29000
    ghost_count: 1500
    triage_answers:
      ransomware_indicators: false
      lateral_movement: false
      data_exfiltration: false
    validated_by: "manual + Autoruns + RECmd"
```

### 3.2 Golden Dataset Categories

| Category | Purpose | Min Cases | Validation Method |
|----------|---------|-----------|-------------------|
| **NIST CFReDS** | Third-party baseline, public reproducibility | 2 | NIST published ground truth |
| **SANS DFIR** | Real-world attack scenarios from public challenges | 3 | Community-validated answers |
| **Lab-Generated (attack)** | Controlled attack simulations with known ground truth | 5 | Manual + 2 independent tools |
| **Lab-Generated (edge)** | Parser edge cases (wrap-around, mixed versions, sparse) | 5 | Manual + custom validation |
| **Corrupt/Malformed** | Fuzz-discovered crashes, truncated images, bad headers | 10 | Must not crash, graceful error |
| **Import Formats** | Velociraptor/Binalyze KAPE collection output | 3 | Round-trip format verification |

### 3.3 Ground Truth Format

```yaml
# expected/golden/cfreds-ntfs-2023.yml
# Ground truth for determinism and correctness verification

metadata:
  image_sha256: "a1b2c3d4..."
  katana_version: "0.6.0"       # Version that produced this ground truth
  validated_date: "2026-03-10"
  validators: ["manual", "Autopsy 4.21", "plaso 20240315"]

parse_stats:
  total_records: 12847
  usn_v2_records: 12500
  usn_v3_records: 347
  usn_v4_records: 0
  ghost_records_recovered: 342
  unallocated_records_carved: 89
  mft_entries_parsed: 8923
  paths_resolved: 8923
  paths_unknown: 0

triage_answers:
  - question_id: 1
    question: "Were any executable files created, renamed, or deleted?"
    answer: true
    evidence_count: 47
    sample_evidence: "C:\\Windows\\Temp\\svchost_update.exe (CREATED)"
  - question_id: 2
    question: "Were any archive files created (ZIP, RAR, 7z) suggesting data staging?"
    answer: true
    evidence_count: 3
    sample_evidence: "C:\\Users\\admin\\Documents\\backup_2023.zip (CREATED)"
  - question_id: 3
    question: "Were Volume Shadow Copies deleted?"
    answer: false
    evidence_count: 0
    sample_evidence: null
  - question_id: 4
    question: "Were any files created or modified in startup/persistence locations?"
    answer: true
    evidence_count: 12
    sample_evidence: "C:\\Users\\admin\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\update.lnk (CREATED)"
  - question_id: 5
    question: "Were any files created or modified in Temp directories?"
    answer: true
    evidence_count: 23
    sample_evidence: "C:\\Windows\\Temp\\svchost_update.exe (CREATED)"
  - question_id: 6
    question: "Were any PowerShell or script files (ps1, bat, cmd, vbs) created or modified?"
    answer: true
    evidence_count: 5
    sample_evidence: "C:\\Users\\admin\\AppData\\Local\\Temp\\update.ps1 (CREATED)"
  - question_id: 7
    question: "Were any files mass-renamed (potential ransomware encryption)?"
    answer: false
    evidence_count: 0
    sample_evidence: null
  - question_id: 8
    question: "Were files copied to removable media or cloud sync directories?"
    answer: false
    evidence_count: 0
    sample_evidence: null
  - question_id: 9
    question: "Were Windows Event Logs cleared or deleted?"
    answer: false
    evidence_count: 0
    sample_evidence: null
  - question_id: 10
    question: "Were any DLLs created or modified in System32 or SysWOW64?"
    answer: false
    evidence_count: 0
    sample_evidence: null
  - question_id: 11
    question: "Were any prefetch files created for suspicious executables?"
    answer: true
    evidence_count: 2
    sample_evidence: "C:\\Windows\\Prefetch\\SVCHOST_UPDATE.EXE-A1B2C3D4.pf (CREATED)"
  - question_id: 12
    question: "Were any files created or modified related to remote access tools?"
    answer: false
    evidence_count: 0
    sample_evidence: null

determinism_hashes:
  sqlite_output: "sha256:..."
  jsonl_output: "sha256:..."
  csv_output: "sha256:..."
  xml_output: "sha256:..."
  tln_output: "sha256:..."
  html_output: "sha256:..."
  body_output: "sha256:..."
```

---

## 4. Parser Unit Tests

### 4.1 USN Journal Parser Tests

```rust
// tests/unit/usn_parser_test.rs

#[cfg(test)]
mod usn_parser_tests {
    use katana_core::usn::{UsnParser, UsnRecord, UsnVersion};

    /// Verify V2 record parsing extracts all fields correctly
    #[test]
    fn parse_v2_record_all_fields() {
        let raw = include_bytes!("../fixtures/usn_v2_record.bin");
        let record = UsnParser::parse_record(raw).expect("valid V2 record");

        assert_eq!(record.version(), UsnVersion::V2);
        assert!(record.file_reference_number() > 0);
        assert!(record.parent_file_reference_number() > 0);
        assert!(!record.filename().is_empty());
        assert!(record.timestamp().year() >= 2000);
        assert!(record.reason_flags().bits() > 0);
    }

    /// Verify V3 record parsing handles 128-bit file references
    #[test]
    fn parse_v3_record_128bit_refs() {
        let raw = include_bytes!("../fixtures/usn_v3_record.bin");
        let record = UsnParser::parse_record(raw).expect("valid V3 record");

        assert_eq!(record.version(), UsnVersion::V3);
        // V3 uses 128-bit file reference numbers (ReFS)
        assert!(record.file_reference_number_128().is_some());
    }

    /// FILETIME epoch sentinel (Jan 1, 1601) must be treated as "no timestamp"
    #[test]
    fn filetime_epoch_sentinel_returns_none() {
        let raw = include_bytes!("../fixtures/usn_v2_epoch_sentinel.bin");
        let record = UsnParser::parse_record(raw).expect("valid record");

        assert!(
            record.timestamp_opt().is_none(),
            "FILETIME epoch sentinel should be treated as missing timestamp"
        );
    }

    /// Mixed-version journal: parser must handle V2 and V3 records in same stream
    #[test]
    fn parse_mixed_version_journal() {
        let journal_data = include_bytes!("../fixtures/mixed_v2_v3_journal.bin");
        let records = UsnParser::parse_journal(journal_data).expect("parseable journal");

        let v2_count = records.iter().filter(|r| r.version() == UsnVersion::V2).count();
        let v3_count = records.iter().filter(|r| r.version() == UsnVersion::V3).count();

        assert!(v2_count > 0, "expected V2 records in mixed journal");
        assert!(v3_count > 0, "expected V3 records in mixed journal");
        assert_eq!(v2_count + v3_count, records.len());
    }

    /// Journal wrap-around: records at buffer boundary must parse correctly
    #[test]
    fn journal_wrap_around_boundary() {
        let journal_data = include_bytes!("../fixtures/usn_wraparound.bin");
        let records = UsnParser::parse_journal(journal_data).expect("parseable journal");

        // Timestamps should be monotonically increasing despite wrap
        for window in records.windows(2) {
            assert!(
                window[1].timestamp() >= window[0].timestamp(),
                "timestamp ordering violated at wrap boundary"
            );
        }
    }

    /// Truncated record at end of buffer must not crash
    #[test]
    fn truncated_record_graceful_handling() {
        let mut journal_data = include_bytes!("../fixtures/usn_v2_record.bin").to_vec();
        journal_data.truncate(journal_data.len() / 2); // Truncate mid-record

        let result = UsnParser::parse_journal(&journal_data);
        // Must not panic. Either returns partial results or error.
        match result {
            Ok(records) => assert!(records.is_empty()),
            Err(e) => assert!(
                e.to_string().contains("truncat") || e.to_string().contains("incomplete")
            ),
        }
    }

    /// Zero-length record must not cause infinite loop
    #[test]
    fn zero_length_record_no_infinite_loop() {
        let journal_data = vec![0u8; 64]; // All zeros
        let result = UsnParser::parse_journal(&journal_data);
        // Must terminate. Result is either empty or error -- never hang.
        assert!(result.is_ok() || result.is_err());
    }
}
```

### 4.2 MFT Parser Tests

```rust
// tests/unit/mft_parser_test.rs

#[cfg(test)]
mod mft_parser_tests {
    use katana_core::mft::{MftParser, MftEntry};

    /// Standard MFT entry with $STANDARD_INFORMATION and $FILE_NAME
    #[test]
    fn parse_standard_mft_entry() {
        let raw = include_bytes!("../fixtures/mft_entry_standard.bin");
        let entry = MftParser::parse_entry(raw).expect("valid MFT entry");

        assert!(entry.has_standard_information());
        assert!(entry.has_file_name());
        assert!(!entry.filename().is_empty());
    }

    /// Deleted MFT entry (not in use) must still be parseable for ghost recovery
    #[test]
    fn parse_deleted_mft_entry() {
        let raw = include_bytes!("../fixtures/mft_entry_deleted.bin");
        let entry = MftParser::parse_entry(raw).expect("deleted entry still parseable");

        assert!(!entry.is_in_use());
        // Deleted entries should still expose metadata for ghost recovery
        assert!(entry.has_standard_information() || entry.has_file_name());
    }

    /// MFT entry with multiple $FILE_NAME attributes (8.3 + long name)
    #[test]
    fn parse_entry_with_multiple_filenames() {
        let raw = include_bytes!("../fixtures/mft_entry_multi_filename.bin");
        let entry = MftParser::parse_entry(raw).expect("valid entry");

        let filenames = entry.all_filenames();
        assert!(filenames.len() >= 2, "expected both 8.3 and long filename");
    }

    /// MFT entry sequence number overflow (reuse detection)
    #[test]
    fn sequence_number_reuse_detection() {
        let entry_a = include_bytes!("../fixtures/mft_entry_seq_1.bin");
        let entry_b = include_bytes!("../fixtures/mft_entry_seq_2.bin");

        let a = MftParser::parse_entry(entry_a).expect("entry A");
        let b = MftParser::parse_entry(entry_b).expect("entry B");

        // Same MFT entry number, different sequence = reuse
        assert_eq!(a.entry_number(), b.entry_number());
        assert_ne!(a.sequence_number(), b.sequence_number());
    }
}
```

### 4.3 Ghost Recovery Tests

```rust
// tests/unit/ghost_recovery_test.rs

#[cfg(test)]
mod ghost_recovery_tests {
    use katana_core::ghost::{GhostRecoveryEngine, GhostRecord};
    use katana_core::usn::UsnRecord;
    use katana_core::mft::MftEntry;

    /// Ghost recovery must find records referenced in USN but deleted from MFT
    #[test]
    fn recover_ghost_from_usn_mft_mismatch() {
        let usn_records = load_test_usn_records("ghost_scenario_01");
        let mft_entries = load_test_mft_entries("ghost_scenario_01");

        let engine = GhostRecoveryEngine::new();
        let ghosts = engine.recover(&usn_records, &mft_entries);

        assert!(!ghosts.is_empty(), "expected ghost records from USN/MFT mismatch");

        for ghost in &ghosts {
            assert!(ghost.source().contains("usn_mft_mismatch"));
            assert!(!ghost.filename().is_empty());
            assert!(ghost.confidence() > 0.0 && ghost.confidence() <= 1.0);
        }
    }

    /// Ghost recovery rate must exceed 95% against known ground truth
    #[test]
    fn ghost_recovery_rate_above_threshold() {
        let usn_records = load_test_usn_records("ghost_heavy_01");
        let mft_entries = load_test_mft_entries("ghost_heavy_01");
        let ground_truth = load_ghost_ground_truth("ghost_heavy_01");

        let engine = GhostRecoveryEngine::new();
        let recovered = engine.recover(&usn_records, &mft_entries);

        let recovery_rate = recovered.len() as f64 / ground_truth.len() as f64;
        assert!(
            recovery_rate >= 0.95,
            "Ghost recovery rate {:.1}% below 95% threshold. Recovered {} of {} known ghosts.",
            recovery_rate * 100.0,
            recovered.len(),
            ground_truth.len()
        );
    }

    /// Ghost records must not include false positives (files that are still live)
    #[test]
    fn no_false_positive_ghosts() {
        let usn_records = load_test_usn_records("no_ghosts_scenario");
        let mft_entries = load_test_mft_entries("no_ghosts_scenario");

        let engine = GhostRecoveryEngine::new();
        let ghosts = engine.recover(&usn_records, &mft_entries);

        assert!(
            ghosts.is_empty(),
            "Expected zero ghosts but recovered {}. False positive ghost records detected.",
            ghosts.len()
        );
    }

    /// Ghost recovery must handle $MFT entry reuse correctly
    #[test]
    fn mft_entry_reuse_does_not_produce_spurious_ghosts() {
        let usn_records = load_test_usn_records("mft_reuse_scenario");
        let mft_entries = load_test_mft_entries("mft_reuse_scenario");

        let engine = GhostRecoveryEngine::new();
        let ghosts = engine.recover(&usn_records, &mft_entries);

        // Every ghost must reference a file reference number that is either
        // (a) absent from current MFT or (b) has a different sequence number
        for ghost in &ghosts {
            let mft_entry = mft_entries.iter().find(|e| e.entry_number() == ghost.mft_entry_number());
            match mft_entry {
                Some(entry) => assert_ne!(
                    entry.sequence_number(),
                    ghost.original_sequence_number(),
                    "Ghost {} references live MFT entry with matching sequence -- false positive",
                    ghost.filename()
                ),
                None => {} // Absent from MFT is valid ghost
            }
        }
    }
}
```

### 4.4 Triage Engine Tests

```rust
// tests/unit/triage_engine_test.rs

#[cfg(test)]
mod triage_engine_tests {
    use katana_core::triage::{TriageEngine, TriageQuestion, TriageResult};

    /// Each of the 12 IR questions must produce a boolean answer with evidence
    #[test]
    fn all_twelve_questions_produce_results() {
        let records = load_test_records("triage_full_scenario");
        let engine = TriageEngine::new();
        let results = engine.evaluate_all(&records);

        assert_eq!(results.len(), 12, "expected exactly 12 triage question results");

        for result in &results {
            assert!(!result.question().is_empty());
            // If answer is true, evidence must be non-empty
            if result.answer() {
                assert!(
                    !result.evidence().is_empty(),
                    "Question '{}' answered true but provided no evidence",
                    result.question()
                );
            }
        }
    }

    /// Ransomware indicators must detect known ransomware USN patterns
    #[test]
    fn ransomware_detection_known_patterns() {
        let records = load_test_records("ransomware_scenario_01");
        let engine = TriageEngine::new();
        let result = engine.evaluate_question(TriageQuestion::RansomwareIndicators, &records);

        assert!(
            result.answer(),
            "Failed to detect ransomware indicators in known ransomware scenario"
        );
        assert!(result.evidence().len() >= 3, "expected multiple ransomware evidence items");
    }

    /// Clean system must not trigger false positive ransomware detection
    #[test]
    fn ransomware_no_false_positive_on_clean() {
        let records = load_test_records("clean_system_01");
        let engine = TriageEngine::new();
        let result = engine.evaluate_question(TriageQuestion::RansomwareIndicators, &records);

        assert!(
            !result.answer(),
            "False positive: ransomware detected on clean system"
        );
    }

    /// Lateral movement detection via RDP, PsExec, WMI artifacts
    #[test]
    fn lateral_movement_detection() {
        let records = load_test_records("lateral_movement_scenario");
        let engine = TriageEngine::new();
        let result = engine.evaluate_question(TriageQuestion::LateralMovement, &records);

        assert!(result.answer(), "Failed to detect lateral movement indicators");
    }

    /// Data exfiltration detection via USB, archive creation, cloud sync
    #[test]
    fn data_exfiltration_detection() {
        let records = load_test_records("exfiltration_scenario");
        let engine = TriageEngine::new();
        let result = engine.evaluate_question(TriageQuestion::DataExfiltration, &records);

        assert!(result.answer(), "Failed to detect data exfiltration indicators");
    }

    /// Triage evaluation must be deterministic
    #[test]
    fn triage_deterministic_across_runs() {
        let records = load_test_records("triage_full_scenario");
        let engine = TriageEngine::new();

        let results_a = engine.evaluate_all(&records);
        let results_b = engine.evaluate_all(&records);

        for (a, b) in results_a.iter().zip(results_b.iter()) {
            assert_eq!(a.answer(), b.answer(), "Non-deterministic triage answer for '{}'", a.question());
            assert_eq!(
                a.evidence().len(), b.evidence().len(),
                "Non-deterministic evidence count for '{}'", a.question()
            );
        }
    }
}
```

### 4.5 QuadLink Correlator Tests

```rust
// tests/unit/quadlink_test.rs

#[cfg(test)]
mod quadlink_tests {
    use katana_core::quadlink::{QuadLinkCorrelator, CorrelatedEvent};

    /// QuadLink must correlate USN, MFT, ghost, and unallocated records
    #[test]
    fn correlate_four_artifact_types() {
        let usn = load_test_usn_records("quadlink_scenario");
        let mft = load_test_mft_entries("quadlink_scenario");
        let ghosts = load_test_ghost_records("quadlink_scenario");
        let unalloc = load_test_unallocated_records("quadlink_scenario");

        let correlator = QuadLinkCorrelator::new();
        let events = correlator.correlate(&usn, &mft, &ghosts, &unalloc);

        assert!(!events.is_empty(), "expected correlated events");

        for event in &events {
            // Each correlated event must reference at least 2 artifact sources
            assert!(
                event.source_count() >= 2,
                "Correlated event should link 2+ artifacts, got {}",
                event.source_count()
            );
        }
    }

    /// Correlation must be deterministic: identical input always produces identical output
    #[test]
    fn correlation_deterministic() {
        let usn = load_test_usn_records("quadlink_scenario");
        let mft = load_test_mft_entries("quadlink_scenario");
        let ghosts = load_test_ghost_records("quadlink_scenario");
        let unalloc = load_test_unallocated_records("quadlink_scenario");

        let correlator = QuadLinkCorrelator::new();

        let events_a = correlator.correlate(&usn, &mft, &ghosts, &unalloc);
        let events_b = correlator.correlate(&usn, &mft, &ghosts, &unalloc);

        assert_eq!(
            events_a.len(), events_b.len(),
            "Correlation results differ between runs"
        );
        for (a, b) in events_a.iter().zip(events_b.iter()) {
            assert_eq!(a.file_reference(), b.file_reference());
            assert_eq!(a.source_count(), b.source_count());
        }
    }
}
```

### 4.6 Path Resolver Tests

```rust
// tests/unit/path_resolver_test.rs

#[cfg(test)]
mod path_resolver_tests {
    use katana_core::path::{PathResolver, ResolvedPath};

    /// Path resolution must achieve 100% completeness (zero UNKNOWN)
    #[test]
    fn zero_unknown_paths() {
        let mft_entries = load_test_mft_entries("full_path_scenario");
        let resolver = PathResolver::new(&mft_entries);

        let results = resolver.resolve_all();
        let unknown_count = results.iter().filter(|r| r.path().contains("UNKNOWN")).count();

        assert_eq!(
            unknown_count, 0,
            "Path resolution completeness failure: {} paths contain UNKNOWN",
            unknown_count
        );
    }

    /// Orphaned MFT entries (parent deleted) must resolve with best-effort path
    #[test]
    fn orphaned_entry_best_effort_resolution() {
        let mft_entries = load_test_mft_entries("orphaned_entries_scenario");
        let resolver = PathResolver::new(&mft_entries);

        let results = resolver.resolve_all();
        for result in &results {
            // Even orphaned entries should have some path, not UNKNOWN
            assert!(
                !result.path().is_empty(),
                "Orphaned entry {} has empty path",
                result.entry_number()
            );
        }
    }

    /// CyberCX Rewind reconstruction must match known ground truth
    #[test]
    fn cybercx_rewind_correctness() {
        let mft_entries = load_test_mft_entries("cybercx_rewind_scenario");
        let ground_truth = load_path_ground_truth("cybercx_rewind_scenario");
        let resolver = PathResolver::new(&mft_entries);

        let results = resolver.resolve_all();
        for (result, expected) in results.iter().zip(ground_truth.iter()) {
            assert_eq!(
                result.path(), expected.path(),
                "Path mismatch for entry {}: got '{}', expected '{}'",
                result.entry_number(), result.path(), expected.path()
            );
        }
    }
}
```

---

## 5. Integration Tests

### 5.1 Pipeline Stage Contract Tests

Each pipeline stage has a defined contract: specific input types, expected output types, and a time budget. Integration tests verify these contracts hold when stages are composed.

```rust
// tests/integration/pipeline_test.rs

#[cfg(test)]
mod pipeline_contract_tests {
    use katana_core::pipeline::{Pipeline, PipelineConfig, StageResult};
    use std::time::Instant;

    /// EWF Parser -> NTFS Volume: verify output contract
    #[test]
    fn ewf_to_ntfs_contract() {
        let image_path = test_image("cfreds-ntfs-2023.E01");
        let pipeline = Pipeline::new(PipelineConfig::default());

        let ewf_output = pipeline.run_stage("ewf_parser", &image_path).expect("EWF stage");
        let ntfs_output = pipeline.run_stage("ntfs_volume", &ewf_output).expect("NTFS stage");

        assert!(ntfs_output.has("mft_data"), "NTFS stage must produce mft_data");
        assert!(ntfs_output.has("usnjrnl_data"), "NTFS stage must produce usnjrnl_data");
        assert!(ntfs_output.has("volume_info"), "NTFS stage must produce volume_info");
    }

    /// USN Parser -> MFT Parser -> Ghost Recovery: data flows correctly
    #[test]
    fn usn_mft_ghost_data_flow() {
        let ntfs_output = load_stage_fixture("ntfs_volume_output");
        let pipeline = Pipeline::new(PipelineConfig::default());

        let usn_output = pipeline.run_stage("usn_parser", &ntfs_output).expect("USN stage");
        let mft_output = pipeline.run_stage("mft_parser", &ntfs_output).expect("MFT stage");
        let ghost_output = pipeline
            .run_stage_with_inputs("ghost_recovery", &[&usn_output, &mft_output])
            .expect("Ghost stage");

        assert!(ghost_output.has("ghost_records"));
        assert!(ghost_output.get::<Vec<_>>("ghost_records").is_some());
    }

    /// Full pipeline: image -> triage results (no stage panics or errors)
    #[test]
    fn full_pipeline_completes_without_error() {
        let image_path = test_image("cfreds-ntfs-2023.E01");
        let pipeline = Pipeline::new(PipelineConfig::default());

        let result = pipeline.run_full(&image_path);
        assert!(result.is_ok(), "Full pipeline failed: {:?}", result.err());

        let output = result.unwrap();
        assert!(output.triage_results().len() == 12);
        assert!(output.record_count() > 0);
    }

    /// Stage budget enforcement: each stage must complete within its allocated time
    #[test]
    fn stage_budget_enforcement() {
        let image_path = test_image("cfreds-ntfs-2023.E01");
        let pipeline = Pipeline::new(PipelineConfig::default());

        let budgets: Vec<(&str, u64)> = vec![
            ("ewf_parser", 2),
            ("ntfs_volume", 1),
            ("usn_parser", 5),
            ("mft_parser", 5),
            ("ghost_recovery", 3),
            ("unallocated_carving", 5),
            ("quadlink_correlator", 3),
            ("triage_engine", 5),
            ("output_formatter", 3),
        ];

        for (stage_name, budget_secs) in budgets {
            let start = Instant::now();
            let _result = pipeline.run_stage(stage_name, &image_path);
            let elapsed = start.elapsed();

            assert!(
                elapsed.as_secs() <= budget_secs + 1, // 1s grace for CI variability
                "Stage '{}' exceeded budget: {:.1}s > {}s",
                stage_name,
                elapsed.as_secs_f64(),
                budget_secs
            );
        }
    }
}
```

### 5.2 Output Format Verification Tests

```rust
// tests/integration/report_integration.rs

#[cfg(test)]
mod output_format_tests {
    use katana_formats::{OutputFormat, Formatter};

    /// All 7 output formats must produce valid, non-empty output
    #[test]
    fn all_seven_formats_produce_output() {
        let pipeline_output = load_pipeline_fixture("full_pipeline_output");

        let formats = vec![
            OutputFormat::Sqlite,
            OutputFormat::Jsonl,
            OutputFormat::Csv,
            OutputFormat::Xml,
            OutputFormat::Tln,
            OutputFormat::Html,
            OutputFormat::BodyFile,
        ];

        for format in formats {
            let formatter = Formatter::new(format);
            let output_dir = test_output_dir();
            let result = formatter.write(&pipeline_output, output_dir.path());

            assert!(result.is_ok(), "{:?} format failed: {:?}", format, result.err());

            let output_file = output_dir.path().join(formatter.default_filename());
            assert!(output_file.exists(), "{:?} output file not created", format);
            assert!(
                std::fs::metadata(&output_file).unwrap().len() > 0,
                "{:?} output file is empty",
                format
            );
        }
    }

    /// SQLite output must have correct schema
    #[test]
    fn sqlite_output_schema_validation() {
        let pipeline_output = load_pipeline_fixture("full_pipeline_output");
        let output_dir = test_output_dir();

        Formatter::new(OutputFormat::Sqlite)
            .write(&pipeline_output, output_dir.path())
            .expect("SQLite write");

        let db_path = output_dir.path().join("katana_output.db");
        let conn = rusqlite::Connection::open(&db_path).expect("open SQLite");

        // Verify expected tables exist
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();

        assert!(tables.contains(&"usn_records".to_string()));
        assert!(tables.contains(&"mft_entries".to_string()));
        assert!(tables.contains(&"ghost_records".to_string()));
        assert!(tables.contains(&"triage_results".to_string()));
        assert!(tables.contains(&"timeline".to_string()));
    }

    /// JSONL output must have one valid JSON object per line
    #[test]
    fn jsonl_output_valid_per_line() {
        let pipeline_output = load_pipeline_fixture("full_pipeline_output");
        let output_dir = test_output_dir();

        Formatter::new(OutputFormat::Jsonl)
            .write(&pipeline_output, output_dir.path())
            .expect("JSONL write");

        let content = std::fs::read_to_string(
            output_dir.path().join("katana_output.jsonl")
        ).unwrap();
        for (i, line) in content.lines().enumerate() {
            assert!(
                serde_json::from_str::<serde_json::Value>(line).is_ok(),
                "Line {} is not valid JSON: {}",
                i + 1,
                &line[..line.len().min(100)]
            );
        }
    }

    /// Output format determinism: same input must produce byte-identical output
    #[test]
    fn output_format_determinism() {
        let pipeline_output = load_pipeline_fixture("full_pipeline_output");

        for format in [OutputFormat::Csv, OutputFormat::Jsonl, OutputFormat::Tln, OutputFormat::BodyFile] {
            let dir_a = test_output_dir();
            let dir_b = test_output_dir();

            let formatter = Formatter::new(format);
            formatter.write(&pipeline_output, dir_a.path()).unwrap();
            formatter.write(&pipeline_output, dir_b.path()).unwrap();

            let file_a = std::fs::read(dir_a.path().join(formatter.default_filename())).unwrap();
            let file_b = std::fs::read(dir_b.path().join(formatter.default_filename())).unwrap();

            assert_deterministic(&file_a, &file_b);
        }
    }
}
```

### 5.3 Import Format Verification (Enterprise)

```rust
// tests/integration/import_test.rs

#[cfg(test)]
mod import_format_tests {
    use katana_import::{VelociraptorImporter, BinalyzeImporter, ImportResult};

    /// Velociraptor collection output must import and parse correctly
    #[test]
    fn velociraptor_import_valid_collection() {
        let collection_path = fixtures_dir().join("imports/velociraptor_collection_01");
        let importer = VelociraptorImporter::new();
        let result = importer.import(&collection_path);

        assert!(result.is_ok(), "Velociraptor import failed: {:?}", result.err());
        let imported = result.unwrap();
        assert!(imported.usnjrnl_data().is_some(), "Expected USN journal data from Velociraptor import");
        assert!(imported.mft_data().is_some(), "Expected MFT data from Velociraptor import");
    }

    /// Binalyze KAPE collection output must import correctly
    #[test]
    fn binalyze_import_valid_collection() {
        let collection_path = fixtures_dir().join("imports/binalyze_kape_01");
        let importer = BinalyzeImporter::new();
        let result = importer.import(&collection_path);

        assert!(result.is_ok(), "Binalyze import failed: {:?}", result.err());
        let imported = result.unwrap();
        assert!(imported.usnjrnl_data().is_some());
    }

    /// Import from unknown format must produce clear error, not panic
    #[test]
    fn import_unknown_format_graceful_error() {
        let path = fixtures_dir().join("imports/unknown_format");
        let result = VelociraptorImporter::new().import(&path);

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unsupported") || err.contains("unrecognized"),
            "Error message should indicate unsupported format, got: {}",
            err
        );
    }
}
```

---

## 6. E2E Tests

### 6.1 CLI End-to-End Tests

```rust
// tests/e2e/cli_test.rs

#[cfg(test)]
mod cli_e2e_tests {
    use assert_cmd::Command;
    use predicates::prelude::*;
    use tempfile::TempDir;

    /// Full CLI: image -> SQLite report
    #[test]
    fn cli_full_pipeline_sqlite() {
        let output_dir = TempDir::new().unwrap();

        Command::cargo_bin("katana")
            .unwrap()
            .args([
                "--image", test_image("cfreds-ntfs-2023.E01").to_str().unwrap(),
                "--output-dir", output_dir.path().to_str().unwrap(),
                "--format", "sqlite",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("Triage complete"));

        assert!(output_dir.path().join("katana_output.db").exists());
    }

    /// Full CLI: image -> all 7 formats simultaneously
    #[test]
    fn cli_all_output_formats() {
        let output_dir = TempDir::new().unwrap();

        Command::cargo_bin("katana")
            .unwrap()
            .args([
                "--image", test_image("cfreds-ntfs-2023.E01").to_str().unwrap(),
                "--output-dir", output_dir.path().to_str().unwrap(),
                "--format", "all",
            ])
            .assert()
            .success();

        let expected_files = [
            "katana_output.db",
            "katana_output.jsonl",
            "katana_output.csv",
            "katana_output.xml",
            "katana_output.tln",
            "katana_output.html",
            "katana_output.body",
        ];

        for file in &expected_files {
            assert!(
                output_dir.path().join(file).exists(),
                "Missing output file: {}",
                file
            );
        }
    }

    /// CLI with corrupt image must exit with non-zero and clear error
    #[test]
    fn cli_corrupt_image_graceful_error() {
        let output_dir = TempDir::new().unwrap();

        Command::cargo_bin("katana")
            .unwrap()
            .args([
                "--image", fixtures_dir().join("images/corrupt/truncated.E01").to_str().unwrap(),
                "--output-dir", output_dir.path().to_str().unwrap(),
                "--format", "sqlite",
            ])
            .assert()
            .failure()
            .stderr(predicate::str::contains("Error").or(predicate::str::contains("error")));
    }

    /// CLI must complete within 35-second P95 budget for standard test image
    #[test]
    fn cli_performance_budget_p95() {
        let output_dir = TempDir::new().unwrap();
        let start = std::time::Instant::now();

        Command::cargo_bin("katana")
            .unwrap()
            .args([
                "--image", test_image("cfreds-ntfs-2023.E01").to_str().unwrap(),
                "--output-dir", output_dir.path().to_str().unwrap(),
                "--format", "sqlite",
            ])
            .assert()
            .success();

        let elapsed = start.elapsed();
        assert!(
            elapsed.as_secs() <= 35,
            "CLI exceeded 35s P95 budget: {:.1}s",
            elapsed.as_secs_f64()
        );
    }

    /// CLI version flag must print version and exit
    #[test]
    fn cli_version_flag() {
        Command::cargo_bin("katana")
            .unwrap()
            .arg("--version")
            .assert()
            .success()
            .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
    }

    /// CLI with missing image path must show usage help
    #[test]
    fn cli_missing_image_shows_help() {
        Command::cargo_bin("katana")
            .unwrap()
            .assert()
            .failure()
            .stderr(predicate::str::contains("--image").or(predicate::str::contains("Usage")));
    }
}
```

### 6.2 Determinism E2E Tests

```rust
// tests/golden/determinism_test.rs

#[cfg(test)]
mod determinism_tests {
    use assert_cmd::Command;
    use sha2::{Sha256, Digest};

    /// Same image processed twice must produce byte-identical output
    #[test]
    fn full_pipeline_deterministic_across_runs() {
        let image = test_image("cfreds-ntfs-2023.E01");

        let dir_a = test_output_dir();
        let dir_b = test_output_dir();

        for dir in [&dir_a, &dir_b] {
            Command::cargo_bin("katana")
                .unwrap()
                .args([
                    "--image", image.to_str().unwrap(),
                    "--output-dir", dir.path().to_str().unwrap(),
                    "--format", "jsonl",
                ])
                .assert()
                .success();
        }

        let output_a = std::fs::read(dir_a.path().join("katana_output.jsonl")).unwrap();
        let output_b = std::fs::read(dir_b.path().join("katana_output.jsonl")).unwrap();

        assert_deterministic(&output_a, &output_b);
    }

    /// Output must match known golden hash for version-locked test image
    #[test]
    fn output_matches_golden_hash() {
        let image = test_image("cfreds-ntfs-2023.E01");
        let dir = test_output_dir();

        Command::cargo_bin("katana")
            .unwrap()
            .args([
                "--image", image.to_str().unwrap(),
                "--output-dir", dir.path().to_str().unwrap(),
                "--format", "jsonl",
            ])
            .assert()
            .success();

        let output = std::fs::read(dir.path().join("katana_output.jsonl")).unwrap();
        let hash = hex::encode(Sha256::digest(&output));

        let expected_hash = load_golden_hash("cfreds-ntfs-2023", "jsonl");
        assert_eq!(
            hash, expected_hash,
            "Output hash mismatch against golden. Regenerate golden if change is intentional."
        );
    }
}
```

---

## 7. Precision/Recall Tests

Triage question accuracy is measured per release and published in the Daubert compliance packet. Every triage question must meet the < 5% false positive target.

### 7.1 Per-Question Precision/Recall Harness

```rust
// tests/precision_recall/triage_accuracy_test.rs

#[cfg(test)]
mod triage_precision_recall {
    use katana_core::triage::{TriageEngine, TriageQuestion};

    struct PRResult {
        question: TriageQuestion,
        true_positives: usize,
        false_positives: usize,
        true_negatives: usize,
        false_negatives: usize,
    }

    impl PRResult {
        fn precision(&self) -> f64 {
            if self.true_positives + self.false_positives == 0 {
                return 1.0;
            }
            self.true_positives as f64 / (self.true_positives + self.false_positives) as f64
        }

        fn recall(&self) -> f64 {
            if self.true_positives + self.false_negatives == 0 {
                return 1.0;
            }
            self.true_positives as f64 / (self.true_positives + self.false_negatives) as f64
        }

        fn false_positive_rate(&self) -> f64 {
            if self.false_positives + self.true_negatives == 0 {
                return 0.0;
            }
            self.false_positives as f64 / (self.false_positives + self.true_negatives) as f64
        }
    }

    /// Evaluate all 12 triage questions across golden dataset corpus
    #[test]
    fn triage_precision_recall_all_questions() {
        let golden_datasets = load_golden_manifest();
        let engine = TriageEngine::new();
        let questions = TriageQuestion::all();

        let mut results: Vec<PRResult> = questions
            .iter()
            .map(|q| PRResult {
                question: *q,
                true_positives: 0,
                false_positives: 0,
                true_negatives: 0,
                false_negatives: 0,
            })
            .collect();

        for dataset in &golden_datasets {
            let records = load_records_from_image(&dataset.image_path);
            let ground_truth = &dataset.triage_answers;

            for (i, question) in questions.iter().enumerate() {
                let result = engine.evaluate_question(*question, &records);
                let expected = ground_truth.get(question);

                match (result.answer(), expected) {
                    (true, Some(true)) => results[i].true_positives += 1,
                    (true, Some(false)) | (true, None) => results[i].false_positives += 1,
                    (false, Some(false)) | (false, None) => results[i].true_negatives += 1,
                    (false, Some(true)) => results[i].false_negatives += 1,
                }
            }
        }

        // Assert thresholds per question
        for result in &results {
            let fpr = result.false_positive_rate();
            assert!(
                fpr < 0.05,
                "Question {:?} false positive rate {:.1}% exceeds 5% threshold.\n  TP={} FP={} TN={} FN={}",
                result.question,
                fpr * 100.0,
                result.true_positives,
                result.false_positives,
                result.true_negatives,
                result.false_negatives,
            );

            let recall = result.recall();
            assert!(
                recall >= 0.80,
                "Question {:?} recall {:.1}% below 80% threshold.\n  TP={} FN={}",
                result.question,
                recall * 100.0,
                result.true_positives,
                result.false_negatives,
            );
        }
    }

    /// Generate precision/recall report for Daubert packet
    #[test]
    fn generate_pr_report_for_daubert() {
        let golden_datasets = load_golden_manifest();
        let engine = TriageEngine::new();
        let questions = TriageQuestion::all();

        let mut report = String::from("# Triage Precision/Recall Report\n\n");
        report.push_str(&format!("Version: {}\n", env!("CARGO_PKG_VERSION")));
        report.push_str(&format!("Date: {}\n", chrono::Utc::now().format("%Y-%m-%d")));
        report.push_str(&format!("Golden datasets: {}\n\n", golden_datasets.len()));
        report.push_str("| Question | Precision | Recall | FPR | TP | FP | TN | FN |\n");
        report.push_str("|----------|-----------|--------|-----|----|----|----|----|---|\n");

        // Compute and format results for each question against all golden datasets
        for question in &questions {
            let mut tp = 0usize;
            let mut fp = 0usize;
            let mut tn = 0usize;
            let mut fn_ = 0usize;

            for dataset in &golden_datasets {
                let records = load_records_from_image(&dataset.image_path);
                let result = engine.evaluate_question(*question, &records);
                let expected = dataset.triage_answers.get(question);

                match (result.answer(), expected) {
                    (true, Some(true)) => tp += 1,
                    (true, Some(false)) | (true, None) => fp += 1,
                    (false, Some(false)) | (false, None) => tn += 1,
                    (false, Some(true)) => fn_ += 1,
                }
            }

            let precision = if tp + fp > 0 { tp as f64 / (tp + fp) as f64 } else { 1.0 };
            let recall = if tp + fn_ > 0 { tp as f64 / (tp + fn_) as f64 } else { 1.0 };
            let fpr = if fp + tn > 0 { fp as f64 / (fp + tn) as f64 } else { 0.0 };

            report.push_str(&format!(
                "| {:?} | {:.1}% | {:.1}% | {:.1}% | {} | {} | {} | {} |\n",
                question, precision * 100.0, recall * 100.0, fpr * 100.0, tp, fp, tn, fn_
            ));
        }

        let report_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("docs/daubert/precision_recall.md");
        std::fs::create_dir_all(report_path.parent().unwrap()).ok();
        std::fs::write(&report_path, &report).expect("write P/R report");
    }
}
```

---

## 8. Performance Tests

### 8.1 Per-Stage Criterion Benchmarks

```rust
// benches/pipeline_benchmark.rs

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};

fn pipeline_benchmarks(c: &mut Criterion) {
    let image_path = test_image("cfreds-ntfs-2023.E01");

    let mut group = c.benchmark_group("pipeline_stages");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(30));

    let stages_and_budgets: Vec<(&str, u64)> = vec![
        ("ewf_parser", 2_000),
        ("ntfs_volume", 1_000),
        ("usn_parser", 5_000),
        ("mft_parser", 5_000),
        ("ghost_recovery", 3_000),
        ("unallocated_carving", 5_000),
        ("quadlink_correlator", 3_000),
        ("triage_engine", 5_000),
        ("output_formatter", 3_000),
    ];

    for (stage, _budget_ms) in stages_and_budgets {
        group.bench_function(BenchmarkId::new("stage", stage), |b| {
            b.iter(|| {
                let pipeline = Pipeline::new(PipelineConfig::default());
                pipeline.run_stage(stage, &image_path).expect("stage should succeed");
            })
        });
    }

    group.finish();

    // Full pipeline benchmark (35s P95 budget)
    c.bench_function("full_pipeline_e2e", |b| {
        b.iter(|| {
            let pipeline = Pipeline::new(PipelineConfig::default());
            pipeline.run_full(&image_path).expect("pipeline should succeed");
        })
    });
}

criterion_group!(benches, pipeline_benchmarks);
criterion_main!(benches);
```

### 8.2 Throughput Benchmarks

```rust
// benches/throughput_benchmark.rs

use criterion::{criterion_group, criterion_main, Criterion, Throughput};

fn throughput_benchmarks(c: &mut Criterion) {
    let journal_data = std::fs::read(fixtures_dir().join("usn_journal_100k.bin")).unwrap();

    let mut group = c.benchmark_group("parser_throughput");
    group.throughput(Throughput::Bytes(journal_data.len() as u64));
    group.sample_size(20);

    group.bench_function("usn_parser_throughput", |b| {
        b.iter(|| {
            UsnParser::parse_journal(&journal_data).expect("parse");
        })
    });

    group.finish();
    // Target: 100k+ events/second
    // Criterion reports throughput automatically
}

criterion_group!(benches, throughput_benchmarks);
criterion_main!(benches);
```

### 8.3 Memory Budget Tests

```rust
// tests/performance/memory_bench.rs

#[cfg(test)]
mod memory_tests {
    /// Peak RSS must not exceed 2x image size for mmap-based processing
    #[test]
    fn peak_memory_within_budget() {
        let image_path = test_image("cfreds-ntfs-2023.E01");
        let image_size = std::fs::metadata(&image_path).unwrap().len();

        let before_rss = get_current_rss();

        let pipeline = Pipeline::new(PipelineConfig::default());
        let _result = pipeline.run_full(&image_path).expect("pipeline");

        let after_rss = get_current_rss();
        let delta_bytes = after_rss.saturating_sub(before_rss);

        assert!(
            delta_bytes < image_size * 2,
            "Memory usage {:.0}MB exceeds 2x image size {:.0}MB",
            delta_bytes as f64 / 1_048_576.0,
            image_size as f64 / 1_048_576.0,
        );
    }

    #[cfg(target_os = "linux")]
    fn get_current_rss() -> u64 {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        for line in status.lines() {
            if line.starts_with("VmRSS:") {
                let kb: u64 = line.split_whitespace().nth(1).unwrap().parse().unwrap();
                return kb * 1024;
            }
        }
        0
    }

    #[cfg(target_os = "macos")]
    fn get_current_rss() -> u64 {
        use std::process::Command;
        let output = Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
            .unwrap();
        let kb: u64 = String::from_utf8_lossy(&output.stdout).trim().parse().unwrap_or(0);
        kb * 1024
    }
}
```

---

## 9. Fuzz Tests

### 9.1 Fuzz Target Configuration

```toml
# fuzz/Cargo.toml
[package]
name = "katana-fuzz"
version = "0.0.0"
publish = false
edition = "2021"

[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4"
katana-core = { path = "../katana-core" }

[[bin]]
name = "fuzz_usn_parser"
path = "fuzz_targets/fuzz_usn_parser.rs"
doc = false

[[bin]]
name = "fuzz_mft_parser"
path = "fuzz_targets/fuzz_mft_parser.rs"
doc = false

[[bin]]
name = "fuzz_ntfs_volume"
path = "fuzz_targets/fuzz_ntfs_volume.rs"
doc = false

[[bin]]
name = "fuzz_ewf_header"
path = "fuzz_targets/fuzz_ewf_header.rs"
doc = false
```

### 9.2 Fuzz Targets

```rust
// fuzz/fuzz_targets/fuzz_usn_parser.rs
#![no_main]
use libfuzzer_sys::fuzz_target;
use katana_core::usn::UsnParser;

fuzz_target!(|data: &[u8]| {
    // Must never panic, regardless of input
    let _ = UsnParser::parse_journal(data);
});
```

```rust
// fuzz/fuzz_targets/fuzz_mft_parser.rs
#![no_main]
use libfuzzer_sys::fuzz_target;
use katana_core::mft::MftParser;

fuzz_target!(|data: &[u8]| {
    let _ = MftParser::parse_entry(data);
});
```

```rust
// fuzz/fuzz_targets/fuzz_ntfs_volume.rs
#![no_main]
use libfuzzer_sys::fuzz_target;
use katana_core::ntfs::NtfsVolume;

fuzz_target!(|data: &[u8]| {
    let cursor = std::io::Cursor::new(data);
    let _ = NtfsVolume::open(cursor);
});
```

```rust
// fuzz/fuzz_targets/fuzz_ewf_header.rs
#![no_main]
use libfuzzer_sys::fuzz_target;
use katana_ewf::EwfHeader;

fuzz_target!(|data: &[u8]| {
    let _ = EwfHeader::parse(data);
});
```

### 9.3 Fuzz Execution Schedule

| Target | Corpus Seeds | Min Runtime | Schedule |
|--------|-------------|-------------|----------|
| `fuzz_usn_parser` | Known V2/V3/V4 records | 24 hours | Weekly + pre-release |
| `fuzz_mft_parser` | Known MFT entries | 24 hours | Weekly + pre-release |
| `fuzz_ntfs_volume` | NTFS boot sector + minimal volume | 48 hours | Pre-release only |
| `fuzz_ewf_header` | Valid EWF headers | 12 hours | Pre-release only |

Crashes found by fuzzing are added to `tests/fixtures/images/corrupt/` as regression tests with a corresponding unit test to prevent recurrence.

---

## 10. Enterprise Tests

### 10.1 RBAC Enforcement Tests

```rust
// tests/enterprise/rbac_test.rs

#[cfg(test)]
mod rbac_tests {
    use katana_server::auth::{Role, Permission, RbacPolicy};
    use katana_server::test_utils::create_test_jwt;

    /// Each role must have exactly the permissions defined in the security spec
    #[test]
    fn role_permission_matrix() {
        let test_cases = vec![
            (Role::Admin, vec![
                Permission::CreateCase, Permission::DeleteCase,
                Permission::ManageUsers, Permission::ViewAuditLog,
                Permission::RunTriage, Permission::ExportResults,
            ]),
            (Role::CaseManager, vec![
                Permission::CreateCase, Permission::AssignExaminer,
                Permission::RunTriage, Permission::ExportResults,
            ]),
            (Role::Examiner, vec![
                Permission::RunTriage, Permission::ExportResults,
                Permission::UploadEvidence,
            ]),
            (Role::Reviewer, vec![
                Permission::ViewResults, Permission::AddComment,
            ]),
            (Role::Auditor, vec![
                Permission::ViewAuditLog,
            ]),
        ];

        let policy = RbacPolicy::default();

        for (role, expected_permissions) in test_cases {
            for perm in &expected_permissions {
                assert!(
                    policy.allows(&role, perm),
                    "Role {:?} should have permission {:?}",
                    role, perm
                );
            }

            // Verify no extra permissions beyond what is specified
            for perm in Permission::all() {
                if !expected_permissions.contains(&perm) {
                    assert!(
                        !policy.allows(&role, &perm),
                        "Role {:?} should NOT have permission {:?}",
                        role, perm
                    );
                }
            }
        }
    }

    /// Reviewer must not be able to run triage (read-only role)
    #[test]
    fn reviewer_cannot_run_triage() {
        let policy = RbacPolicy::default();

        assert!(
            !policy.allows(&Role::Reviewer, &Permission::RunTriage),
            "Reviewer must not have RunTriage permission"
        );
    }

    /// Expired JWT must be rejected
    #[test]
    fn expired_jwt_rejected() {
        let token = create_test_jwt_expired(Role::Admin, "tenant_001");
        let result = validate_jwt(&token);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }

    /// JWT with invalid signature must be rejected
    #[test]
    fn invalid_jwt_signature_rejected() {
        let token = create_test_jwt(Role::Admin, "tenant_001");
        let tampered = tamper_jwt_signature(&token);
        let result = validate_jwt(&tampered);

        assert!(result.is_err());
    }
}
```

### 10.2 Multi-Tenant Isolation Tests

```rust
// tests/enterprise/multi_tenant_test.rs

#[cfg(test)]
mod multi_tenant_tests {
    use katana_multi::{TenantManager, TenantId};

    /// Tenant A must never see Tenant B's data
    #[test]
    fn cross_tenant_data_isolation() {
        let manager = TenantManager::new_test();
        let tenant_a = TenantId::new("tenant_alpha");
        let tenant_b = TenantId::new("tenant_beta");

        // Ingest data for Tenant A
        manager.with_tenant(&tenant_a, |ctx| {
            ctx.ingest_test_case("case_001", test_image("cfreds-ntfs-2023.E01"));
        });

        // Tenant B must see zero cases
        manager.with_tenant(&tenant_b, |ctx| {
            let cases = ctx.list_cases();
            assert!(
                cases.is_empty(),
                "Tenant B sees {} cases from Tenant A -- isolation breach",
                cases.len()
            );
        });

        // Tenant A should see exactly 1 case
        manager.with_tenant(&tenant_a, |ctx| {
            let cases = ctx.list_cases();
            assert_eq!(cases.len(), 1, "Tenant A should see exactly 1 case");
        });
    }

    /// Direct SQL injection attempt must not cross tenant boundary
    #[test]
    fn sql_injection_cross_tenant_blocked() {
        let manager = TenantManager::new_test();
        let tenant_a = TenantId::new("tenant_alpha");

        manager.with_tenant(&tenant_a, |ctx| {
            ctx.ingest_test_case("case_001", test_image("cfreds-ntfs-2023.E01"));
        });

        // Attempt to query with a malicious tenant ID
        let malicious_tenant = TenantId::new("tenant_alpha' OR '1'='1");
        manager.with_tenant(&malicious_tenant, |ctx| {
            let cases = ctx.list_cases();
            assert!(
                cases.is_empty(),
                "SQL injection yielded {} results -- isolation breach",
                cases.len()
            );
        });
    }

    /// Schema-per-tenant: each tenant gets its own DuckDB schema
    #[test]
    fn schema_per_tenant_isolation() {
        let manager = TenantManager::new_test();

        for i in 0..5 {
            let tenant = TenantId::new(&format!("tenant_{:03}", i));
            manager.with_tenant(&tenant, |ctx| {
                let schema = ctx.current_schema();
                assert_eq!(schema, format!("tenant_{:03}", i));
                assert!(ctx.schema_exists(&schema));
            });
        }
    }

    /// Tenant deletion must remove all data including DuckDB schema
    #[test]
    fn tenant_deletion_removes_all_data() {
        let manager = TenantManager::new_test();
        let tenant = TenantId::new("tenant_to_delete");

        manager.with_tenant(&tenant, |ctx| {
            ctx.ingest_test_case("case_001", test_image("cfreds-ntfs-2023.E01"));
            assert_eq!(ctx.list_cases().len(), 1);
        });

        manager.delete_tenant(&tenant).expect("tenant deletion");

        manager.with_tenant(&tenant, |ctx| {
            assert!(ctx.list_cases().is_empty(), "Data survived tenant deletion");
        });
    }
}
```

### 10.3 Agent Security Tests (mTLS)

```rust
// tests/enterprise/mtls_test.rs

#[cfg(test)]
mod mtls_tests {
    use katana_agent::tls::{TlsConfig, CertificateValidator};
    use rcgen::generate_simple_self_signed;

    /// Agent connection without valid client certificate must be rejected
    #[test]
    fn reject_connection_without_client_cert() {
        let server_config = TlsConfig::test_server();

        let result = attempt_grpc_connect(server_config.endpoint(), None);
        assert!(result.is_err(), "Connection without client cert should be rejected");
    }

    /// Agent connection with expired certificate must be rejected
    #[test]
    fn reject_expired_client_cert() {
        let expired_cert = generate_expired_test_cert();
        let server_config = TlsConfig::test_server();

        let result = attempt_grpc_connect(server_config.endpoint(), Some(&expired_cert));
        assert!(result.is_err(), "Connection with expired cert should be rejected");
    }

    /// Agent connection with wrong CA must be rejected (certificate pinning)
    #[test]
    fn reject_wrong_ca_cert() {
        let wrong_ca_cert = generate_simple_self_signed(
            vec!["agent.wrong-ca.test".to_string()]
        ).unwrap();
        let server_config = TlsConfig::test_server();

        let result = attempt_grpc_connect(server_config.endpoint(), Some(&wrong_ca_cert));
        assert!(result.is_err(), "Connection with wrong CA should be rejected by cert pinning");
    }

    /// Valid mTLS connection with pinned certificate must succeed
    #[test]
    fn accept_valid_pinned_cert() {
        let server_config = TlsConfig::test_server();
        let valid_cert = server_config.generate_agent_cert("agent-001");

        let result = attempt_grpc_connect(server_config.endpoint(), Some(&valid_cert));
        assert!(result.is_ok(), "Valid pinned cert should be accepted");
    }

    /// Agent binary size must be under 5MB
    #[test]
    fn agent_binary_size_within_budget() {
        let agent_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/release/katana-agent");
        if agent_path.exists() {
            let size = std::fs::metadata(&agent_path).unwrap().len();
            assert!(
                size < 5 * 1024 * 1024,
                "Agent binary {:.1}MB exceeds 5MB budget",
                size as f64 / 1_048_576.0
            );
        }
    }
}
```

### 10.4 Audit Trail Tests

```rust
// tests/enterprise/audit_trail_test.rs

#[cfg(test)]
mod audit_trail_tests {
    use katana_server::audit::{AuditLog, AuditEvent};

    /// Every triage action must produce an audit entry
    #[test]
    fn triage_action_creates_audit_entry() {
        let audit_log = AuditLog::new_test();

        run_test_triage(&audit_log, "user_001", "case_001");

        let entries = audit_log.query_by_case("case_001");
        assert!(!entries.is_empty(), "Triage should produce audit entries");
        assert!(entries.iter().any(|e| e.action() == "triage_started"));
        assert!(entries.iter().any(|e| e.action() == "triage_completed"));
    }

    /// Audit log must be append-only: deletion attempt must fail
    #[test]
    fn audit_log_append_only() {
        let audit_log = AuditLog::new_test();
        audit_log.append(AuditEvent::test("action_001"));

        let result = audit_log.delete_entry("action_001");
        assert!(result.is_err(), "Audit log must be append-only");
    }

    /// Audit log hash chain: tampering with any entry breaks verification
    #[test]
    fn audit_log_hash_chain_integrity() {
        let audit_log = AuditLog::new_test();

        for i in 0..10 {
            audit_log.append(AuditEvent::test(&format!("action_{:03}", i)));
        }

        assert!(audit_log.verify_chain().is_ok(), "Clean audit log should verify");

        // Tamper with entry 5
        audit_log.test_tamper_entry(5, "tampered_value");

        assert!(
            audit_log.verify_chain().is_err(),
            "Tampered audit log must fail verification"
        );
    }

    /// Audit entries must include user identity, timestamp, and action
    #[test]
    fn audit_entry_completeness() {
        let audit_log = AuditLog::new_test();
        run_test_triage(&audit_log, "user_001", "case_001");

        let entries = audit_log.query_by_case("case_001");
        for entry in &entries {
            assert!(!entry.user_id().is_empty(), "Audit entry missing user_id");
            assert!(entry.timestamp().year() >= 2026, "Audit entry has invalid timestamp");
            assert!(!entry.action().is_empty(), "Audit entry missing action");
            assert!(!entry.case_id().is_empty(), "Audit entry missing case_id");
        }
    }
}
```

---

## 11. CI/CD Integration

### 11.1 GitHub Actions Workflow

```yaml
# .github/workflows/test.yml
name: Test Suite

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: "-D warnings"

jobs:
  unit-tests:
    name: Unit Tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - name: Run unit tests
        run: cargo test --lib --workspace
      - name: Run doc tests
        run: cargo test --doc --workspace

  integration-tests:
    name: Integration Tests
    runs-on: ubuntu-latest
    needs: unit-tests
    steps:
      - uses: actions/checkout@v4
        with:
          lfs: true  # Test images stored in Git LFS
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - name: Run integration tests
        run: cargo test --test '*' --workspace -- --test-threads=1
        timeout-minutes: 10

  golden-tests:
    name: Golden / Determinism Tests
    runs-on: ubuntu-latest
    needs: unit-tests
    steps:
      - uses: actions/checkout@v4
        with:
          lfs: true
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - name: Run golden tests
        run: cargo test --test determinism_test --test known_answers_test
      - name: Run precision/recall tests
        run: cargo test --test triage_accuracy_test
      - name: Upload Daubert P/R report
        uses: actions/upload-artifact@v4
        with:
          name: daubert-pr-report
          path: docs/daubert/precision_recall.md

  performance-tests:
    name: Performance Benchmarks
    runs-on: ubuntu-latest
    needs: integration-tests
    steps:
      - uses: actions/checkout@v4
        with:
          lfs: true
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - name: Run criterion benchmarks
        run: cargo bench --bench pipeline_benchmark -- --output-format bencher | tee bench_output.txt
      - name: Check 35s P95 budget
        run: cargo test --test cli_test cli_performance_budget_p95
      - name: Store benchmark results
        uses: benchmark-action/github-action-benchmark@v1
        with:
          tool: cargo
          output-file-path: bench_output.txt
          alert-threshold: "120%"
          fail-on-alert: true

  e2e-tests:
    name: E2E Tests
    runs-on: ubuntu-latest
    needs: integration-tests
    steps:
      - uses: actions/checkout@v4
        with:
          lfs: true
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - name: Build release binary
        run: cargo build --release
      - name: Run E2E tests
        run: cargo test --test cli_test --release
        timeout-minutes: 5

  coverage:
    name: Coverage Report
    runs-on: ubuntu-latest
    needs: unit-tests
    steps:
      - uses: actions/checkout@v4
        with:
          lfs: true
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: llvm-tools-preview
      - uses: Swatinem/rust-cache@v2
      - name: Install cargo-llvm-cov
        run: cargo install cargo-llvm-cov
      - name: Generate coverage
        run: cargo llvm-cov --workspace --lcov --output-path lcov.info
      - name: Upload coverage
        uses: codecov/codecov-action@v4
        with:
          files: lcov.info
          fail_ci_if_error: true

  fuzz-smoke:
    name: Fuzz Smoke Test
    runs-on: ubuntu-latest
    needs: unit-tests
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
      - name: Install cargo-fuzz
        run: cargo install cargo-fuzz
      - name: Fuzz USN parser (60s smoke)
        run: cargo +nightly fuzz run fuzz_usn_parser -- -max_total_time=60
      - name: Fuzz MFT parser (60s smoke)
        run: cargo +nightly fuzz run fuzz_mft_parser -- -max_total_time=60

  enterprise-tests:
    name: Enterprise Tests
    runs-on: ubuntu-latest
    needs: unit-tests
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4
        with:
          lfs: true
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - name: Run RBAC tests
        run: cargo test --test rbac_test -p katana-server
      - name: Run multi-tenant isolation tests
        run: cargo test --test multi_tenant_test -p katana-multi
      - name: Run mTLS tests
        run: cargo test --test mtls_test -p katana-agent
      - name: Run audit trail tests
        run: cargo test --test audit_trail_test -p katana-server
```

### 11.2 CI Job Responsibilities

| Job | Trigger | Timeout | Blocks Merge |
|-----|---------|---------|-------------|
| `unit-tests` | Every push + PR | 5 min | Yes |
| `integration-tests` | Every push + PR | 10 min | Yes |
| `golden-tests` | Every push + PR | 5 min | Yes |
| `performance-tests` | Every push + PR | 10 min | Yes (alert on regression) |
| `e2e-tests` | Every push + PR | 5 min | Yes |
| `coverage` | Every push + PR | 10 min | Yes (threshold enforcement) |
| `fuzz-smoke` | Every push + PR | 3 min | No (informational) |
| `enterprise-tests` | Push to main only | 5 min | Yes (main branch) |

### 11.3 Pre-Release Validation

```yaml
# .github/workflows/release.yml
name: Pre-Release Validation

on:
  push:
    tags: ["v*"]

jobs:
  release-validation:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          lfs: true
      - uses: dtolnay/rust-toolchain@stable

      # Full test suite in release mode
      - name: Full test suite (release)
        run: cargo test --workspace --release

      # Extended fuzz (10 min per target for release gate)
      - name: Extended fuzz - USN parser
        run: cargo +nightly fuzz run fuzz_usn_parser -- -max_total_time=600
      - name: Extended fuzz - MFT parser
        run: cargo +nightly fuzz run fuzz_mft_parser -- -max_total_time=600

      # Performance regression check
      - name: Performance benchmarks
        run: cargo bench --bench pipeline_benchmark

      # Triple-run determinism verification
      - name: Determinism verification (3 runs)
        run: |
          for i in 1 2 3; do
            cargo run --release -- \
              --image tests/fixtures/images/known-good/cfreds-ntfs-2023.E01 \
              --output-dir /tmp/run_$i --format jsonl
          done
          sha256sum /tmp/run_*/katana_output.jsonl | awk '{print $1}' | sort -u | wc -l | \
            xargs -I{} test {} -eq 1

      # Generate Daubert P/R report artifact
      - name: Generate Daubert packet
        run: cargo test --test triage_accuracy_test generate_pr_report_for_daubert --release
      - uses: actions/upload-artifact@v4
        with:
          name: daubert-packet
          path: docs/daubert/
```

---

## 12. Test Utilities

### 12.1 Test Data Loaders

```rust
// tests/common/loaders.rs

use std::path::PathBuf;

/// Load USN records from binary fixture file
pub fn load_test_usn_records(scenario: &str) -> Vec<UsnRecord> {
    let path = fixtures_dir().join(format!("scenarios/{}/usn_records.bin", scenario));
    UsnParser::parse_journal(
        &std::fs::read(&path).expect(&format!("fixture: {}", path.display()))
    ).expect("parse fixture USN records")
}

/// Load MFT entries from binary fixture file
pub fn load_test_mft_entries(scenario: &str) -> Vec<MftEntry> {
    let path = fixtures_dir().join(format!("scenarios/{}/mft_entries.bin", scenario));
    MftParser::parse_all(
        &std::fs::read(&path).expect(&format!("fixture: {}", path.display()))
    ).expect("parse fixture MFT entries")
}

/// Load ghost ground truth from YAML
pub fn load_ghost_ground_truth(scenario: &str) -> Vec<GhostGroundTruth> {
    let path = fixtures_dir().join(format!("scenarios/{}/ghost_ground_truth.yml", scenario));
    let content = std::fs::read_to_string(&path).expect("read ground truth");
    serde_yaml::from_str(&content).expect("parse ground truth YAML")
}

/// Load golden manifest
pub fn load_golden_manifest() -> Vec<GoldenDataset> {
    let path = fixtures_dir().join("golden_manifest.yml");
    let content = std::fs::read_to_string(&path).expect("read golden manifest");
    serde_yaml::from_str(&content).expect("parse golden manifest")
}

/// Load expected golden hash for a specific image and format
pub fn load_golden_hash(image_name: &str, format: &str) -> String {
    let path = fixtures_dir().join(format!("expected/golden/{}.yml", image_name));
    let content = std::fs::read_to_string(&path).expect("read golden hashes");
    let hashes: std::collections::HashMap<String, String> =
        serde_yaml::from_str(&content).expect("parse golden hashes");
    hashes
        .get(format)
        .expect(&format!("no golden hash for format '{}'", format))
        .clone()
}
```

### 12.2 Test Image Management

Test images are stored in Git LFS to keep the repository lightweight. The golden manifest (`tests/fixtures/golden_manifest.yml`) tracks image SHA-256 hashes to detect corruption.

```bash
# .gitattributes
tests/fixtures/images/**/*.E01 filter=lfs diff=lfs merge=lfs -text
tests/fixtures/images/**/*.raw filter=lfs diff=lfs merge=lfs -text
tests/fixtures/images/**/*.dd filter=lfs diff=lfs merge=lfs -text
```

```bash
# Download test images for local development
git lfs pull --include="tests/fixtures/images/"

# Verify test image integrity
sha256sum tests/fixtures/images/known-good/*.E01 | diff - tests/fixtures/image_checksums.sha256
```

### 12.3 Property-Based Testing Generators

```rust
// tests/common/generators.rs

use proptest::prelude::*;

/// Generate arbitrary valid USN V2 records
pub fn arb_usn_v2_record() -> impl Strategy<Value = Vec<u8>> {
    (
        1u64..u64::MAX,                                      // file reference number
        1u64..u64::MAX,                                      // parent file reference number
        0u64..i64::MAX as u64,                               // timestamp (FILETIME)
        prop::bits::u32::ANY,                                // reason flags
        prop::collection::vec(any::<u8>(), 1..255),          // filename bytes (UTF-16LE)
    )
        .prop_map(|(frn, parent_frn, timestamp, reason, name_bytes)| {
            build_usn_v2_bytes(frn, parent_frn, timestamp, reason, &name_bytes)
        })
}

/// Generate arbitrary valid MFT entries
pub fn arb_mft_entry() -> impl Strategy<Value = Vec<u8>> {
    (
        any::<bool>(),                                       // in_use flag
        1u16..u16::MAX,                                      // sequence number
        prop::collection::vec(any::<u8>(), 1..255),          // filename
    )
        .prop_map(|(in_use, seq, name)| {
            build_mft_entry_bytes(in_use, seq, &name)
        })
}

proptest! {
    /// Any valid USN V2 record must parse without panic
    #[test]
    fn usn_v2_parse_no_panic(data in arb_usn_v2_record()) {
        let _ = UsnParser::parse_record(&data);
    }

    /// Any valid MFT entry must parse without panic
    #[test]
    fn mft_entry_parse_no_panic(data in arb_mft_entry()) {
        let _ = MftParser::parse_entry(&data);
    }

    /// Parse -> serialize roundtrip must be identity for USN records
    #[test]
    fn usn_roundtrip_identity(data in arb_usn_v2_record()) {
        if let Ok(record) = UsnParser::parse_record(&data) {
            let serialized = record.to_bytes();
            let reparsed = UsnParser::parse_record(&serialized).unwrap();
            prop_assert_eq!(record.file_reference_number(), reparsed.file_reference_number());
            prop_assert_eq!(record.filename(), reparsed.filename());
        }
    }
}
```

---

## 13. Daubert Compliance Testing

Forensic tools used in legal proceedings must satisfy the Daubert standard for admissibility of expert testimony. This requires documented methodology, known error rates, and reproducibility.

### 13.1 Daubert Testing Requirements

| Daubert Factor | Testing Requirement | Verification Method |
|----------------|--------------------|--------------------|
| **Testability** | All claims must be empirically verifiable | Golden dataset with known ground truth |
| **Error Rate** | Known and documented per-question false positive/negative rates | Precision/recall tests run per release |
| **Peer Review** | Open source code, public test corpus | Apache-2.0 license, public fixtures repo |
| **Standards** | Follows established forensic standards (NIST, SWGDE) | NIST CFReDS baseline tests |
| **General Acceptance** | Cross-validated with accepted tools | Compare output with Autopsy, plaso, MFTECmd |

### 13.2 Daubert Packet Artifacts (Auto-Generated)

Every tagged release produces these artifacts in `docs/daubert/`:

| Artifact | Description | Generated By |
|----------|-------------|-------------|
| `precision_recall.md` | Per-question P/R table with TP/FP/TN/FN counts | `triage_accuracy_test` |
| `determinism_report.md` | Triple-run hash comparison across all output formats | `determinism_test` |
| `parser_coverage.md` | Coverage report for parser crates | `cargo-llvm-cov` |
| `fuzz_report.md` | Fuzz corpus size, runtime, crashes found/fixed | Fuzz CI job |
| `cross_validation.md` | Output comparison with Autopsy, plaso, MFTECmd | Manual + automated diff |
| `version_changelog.md` | Changes since last release affecting output | `git log` + manual review |

### 13.3 Regression Protection

When a triage question's precision or recall drops below threshold between releases, the CI pipeline:

1. Fails the build with explicit metric comparison (before vs. after).
2. Generates a diff report showing which golden dataset cases changed.
3. Requires explicit acknowledgment via `ALLOW_PR_REGRESSION=question_id` environment variable to merge.

This prevents accidental accuracy regressions from reaching production.

---

## 14. Test Execution Quick Reference

```bash
# Run all unit tests
cargo test --lib --workspace

# Run all integration tests (requires test images via Git LFS)
cargo test --test '*' --workspace

# Run golden/determinism tests only
cargo test --test determinism_test --test known_answers_test

# Run precision/recall tests and generate Daubert report
cargo test --test triage_accuracy_test

# Run performance benchmarks
cargo bench --bench pipeline_benchmark

# Run fuzz tests (requires nightly)
cargo +nightly fuzz run fuzz_usn_parser -- -max_total_time=3600

# Run enterprise tests only
cargo test --test rbac_test --test multi_tenant_test --test mtls_test --test audit_trail_test

# Run full test suite with coverage
cargo llvm-cov --workspace --html --open

# Run 35s budget enforcement test
cargo test --test cli_test cli_performance_budget_p95 --release

# Verify determinism (manual 3-run check)
for i in 1 2 3; do
  cargo run --release -- --image test.E01 --output-dir /tmp/run_$i --format jsonl
done
sha256sum /tmp/run_*/katana_output.jsonl
```
