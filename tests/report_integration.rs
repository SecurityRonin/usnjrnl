//! End-to-end integration tests for the triage report pipeline.
//!
//! These tests verify the full flow from resolved records through triage
//! to HTML report generation, using synthetic data (no forensic images needed).

use chrono::DateTime;
use usnjrnl_forensic::analysis::JournalClearingResult;
use usnjrnl_forensic::correlation::GhostRecord;
use usnjrnl_forensic::output::report::{build_report_data, export_report, ReportInput};
use usnjrnl_forensic::rewind::{RecordSource, ResolvedRecord};
use usnjrnl_forensic::triage::queries::builtin_questions;
use usnjrnl_forensic::triage::run_triage;
use usnjrnl_forensic::usn::{FileAttributes, UsnReason, UsnRecord};

fn make_record(
    mft_entry: u64,
    usn: i64,
    filename: &str,
    full_path: &str,
    reason: UsnReason,
    source: RecordSource,
) -> ResolvedRecord {
    ResolvedRecord {
        record: UsnRecord {
            mft_entry,
            mft_sequence: 1,
            parent_mft_entry: 5,
            parent_mft_sequence: 5,
            usn,
            timestamp: DateTime::from_timestamp(1_700_000_000 + usn, 0).unwrap(),
            reason,
            filename: filename.to_string(),
            file_attributes: FileAttributes::ARCHIVE,
            source_info: 0,
            security_id: 0,
            major_version: 2,
        },
        full_path: full_path.to_string(),
        parent_path: ".".to_string(),
        source,
    }
}

/// Full pipeline: mixed sources -> triage -> report HTML contains all expected data.
#[test]
fn e2e_report_with_mixed_sources() {
    let resolved = vec![
        // Allocated: malware dropped in System32
        make_record(
            100,
            1000,
            "evil.exe",
            r".\Windows\System32\evil.exe",
            UsnReason::FILE_CREATE,
            RecordSource::Allocated,
        ),
        // Allocated: prefetch proves execution
        make_record(
            101,
            1001,
            "EVIL.EXE-AABB1234.pf",
            r".\Windows\Prefetch\EVIL.EXE-AABB1234.pf",
            UsnReason::FILE_CREATE,
            RecordSource::Allocated,
        ),
        // Carved: deleted archive in user dir (data staging)
        make_record(
            102,
            1002,
            "exfil.zip",
            r".\Users\admin\Desktop\exfil.zip",
            UsnReason::FILE_CREATE,
            RecordSource::Carved,
        ),
        // Ghost: event log deletion recovered from LogFile
        make_record(
            103,
            1003,
            "Security.evtx",
            r".\Windows\System32\winevt\Logs\Security.evtx",
            UsnReason::FILE_DELETE,
            RecordSource::Ghost,
        ),
        // Allocated: ADS operation (file disguise)
        make_record(
            104,
            1004,
            "document.docx",
            r".\Users\admin\document.docx",
            UsnReason::NAMED_DATA_EXTEND,
            RecordSource::Allocated,
        ),
    ];

    let ghosts = vec![GhostRecord {
        record: UsnRecord {
            mft_entry: 103,
            mft_sequence: 1,
            parent_mft_entry: 5,
            parent_mft_sequence: 5,
            usn: 1003,
            timestamp: DateTime::from_timestamp(1_700_001_003, 0).unwrap(),
            reason: UsnReason::FILE_DELETE,
            filename: "Security.evtx".to_string(),
            file_attributes: FileAttributes::ARCHIVE,
            source_info: 0,
            security_id: 0,
            major_version: 2,
        },
        lsn: 55555,
    }];

    let clearing = JournalClearingResult {
        clearing_detected: false,
        first_usn: Some(1000),
        timestamp_gaps: vec![],
        confidence: 0.0,
    };

    // Run triage
    let questions = builtin_questions();
    let triage_results = run_triage(&questions, &resolved);

    // Verify triage findings
    let malware = triage_results
        .iter()
        .find(|r| r.id == "malware_deployed")
        .unwrap();
    assert!(
        malware.has_hits,
        "malware_deployed should detect evil.exe in System32"
    );

    let execution = triage_results
        .iter()
        .find(|r| r.id == "execution_evidence")
        .unwrap();
    assert!(
        execution.has_hits,
        "execution_evidence should detect prefetch creation"
    );

    let staging = triage_results
        .iter()
        .find(|r| r.id == "data_staging")
        .unwrap();
    assert!(staging.has_hits, "data_staging should detect exfil.zip");

    let destruction = triage_results
        .iter()
        .find(|r| r.id == "evidence_destruction")
        .unwrap();
    assert!(
        destruction.has_hits,
        "evidence_destruction should detect evtx deletion"
    );

    let disguise = triage_results
        .iter()
        .find(|r| r.id == "file_disguise")
        .unwrap();
    assert!(
        disguise.has_hits,
        "file_disguise should detect ADS operation"
    );

    let recovered = triage_results
        .iter()
        .find(|r| r.id == "recovered_evidence")
        .unwrap();
    assert!(
        recovered.has_hits,
        "recovered_evidence should match carved + ghost records"
    );
    assert_eq!(
        recovered.hit_count, 2,
        "carved zip + ghost evtx should match"
    );

    // Build report
    let input = ReportInput {
        image_name: "e2e_test.E01",
        resolved: &resolved,
        mft_data: None,
        timestomping: &[],
        secure_deletion: &[],
        ransomware: &[],
        journal_clearing: &clearing,
        ghost_records: &ghosts,
        carved_usn_count: 1,
        carved_mft_count: 0,
        carving_bytes_scanned: 1024,
        carving_chunks: 1,
        carving_usn_dupes: 0,
        carving_mft_dupes: 0,
    };
    let data = build_report_data(&input, &questions);

    // Verify report data
    assert_eq!(data.meta.record_count, 5);
    assert_eq!(data.records.len(), 5);
    assert_eq!(data.ghost_records.len(), 1);

    // Verify source fields in report records
    assert_eq!(data.records[0].source, "allocated");
    assert_eq!(data.records[2].source, "entry-carved");
    assert_eq!(data.records[3].source, "ghost");

    // Verify triage is embedded in report
    let triage_recovered = data
        .triage
        .iter()
        .find(|t| t.id == "recovered_evidence")
        .unwrap();
    assert!(triage_recovered.has_hits);
    assert_eq!(triage_recovered.hit_count, 2);

    // Export to HTML and verify
    let mut buf = Vec::new();
    export_report(&data, &mut buf).unwrap();
    let html = String::from_utf8(buf).unwrap();

    assert!(html.contains("<!DOCTYPE html>"), "valid HTML document");
    assert!(html.contains("e2e_test.E01"), "image name in report");
    assert!(html.contains("evil.exe"), "malware filename in report");
    assert!(html.contains("exfil.zip"), "carved filename in report");
    assert!(html.contains("Security.evtx"), "ghost filename in report");
    assert!(html.contains("carved"), "source 'carved' in report data");
    assert!(html.contains("ghost"), "source 'ghost' in report data");
    assert!(
        html.contains("allocated"),
        "source 'allocated' in report data"
    );
    assert!(
        html.contains("recovered_evidence"),
        "triage question ID in report"
    );
    assert!(html.contains("What Happened"), "triage category in report");
    assert!(html.contains("Recovery"), "recovery category in report");
}

/// Verify that triage questions are independent -- each question evaluates all records.
#[test]
fn e2e_triage_all_12_questions_evaluated() {
    let records = vec![make_record(
        100,
        1,
        "test.exe",
        r".\test.exe",
        UsnReason::FILE_CREATE,
        RecordSource::Allocated,
    )];
    let questions = builtin_questions();
    let results = run_triage(&questions, &records);
    assert_eq!(
        results.len(),
        12,
        "all 12 builtin questions should produce results"
    );

    // Verify each result has the correct metadata
    for (q, r) in questions.iter().zip(results.iter()) {
        assert_eq!(q.id, r.id, "result ID should match question ID");
        assert_eq!(q.category, r.category, "result category should match");
        assert_eq!(q.question, r.question, "result question should match");
    }
}

/// Verify empty input produces a valid report with no hits.
#[test]
fn e2e_empty_report() {
    let clearing = JournalClearingResult {
        clearing_detected: false,
        first_usn: None,
        timestamp_gaps: vec![],
        confidence: 0.0,
    };
    let input = ReportInput {
        image_name: "empty.E01",
        resolved: &[],
        mft_data: None,
        timestomping: &[],
        secure_deletion: &[],
        ransomware: &[],
        journal_clearing: &clearing,
        ghost_records: &[],
        carved_usn_count: 0,
        carved_mft_count: 0,
        carving_bytes_scanned: 0,
        carving_chunks: 0,
        carving_usn_dupes: 0,
        carving_mft_dupes: 0,
    };
    let questions = builtin_questions();
    let data = build_report_data(&input, &questions);

    assert_eq!(data.meta.record_count, 0);
    assert!(data.records.is_empty());
    assert_eq!(data.triage.len(), 12);
    for t in &data.triage {
        assert!(
            !t.has_hits,
            "question '{}' should have no hits on empty data",
            t.id
        );
    }

    // Should still produce valid HTML
    let mut buf = Vec::new();
    export_report(&data, &mut buf).unwrap();
    let html = String::from_utf8(buf).unwrap();
    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("empty.E01"));
}

/// Generate a test report with records at known timestamps for browser testing.
///
/// Creates tests/output/time_filter_test.html with three distinct time groups:
///   Group A: 5 records at ~2024-03-15 14:00-14:05 UTC
///   Group B: 3 records at ~2024-03-15 16:00-16:10 UTC  (2 hours later)
///   Group C: 2 records at ~2024-03-16 10:00-10:05 UTC  (next day)
///
/// This enables Playwright tests to verify time filtering precision.
#[test]
fn generate_time_filter_test_report() {
    use std::fs;
    use std::path::Path;

    // Base: 2024-03-15 14:00:00 UTC = 1710511200
    let base: i64 = 1_710_511_200;

    let records = vec![
        // Group A: 14:00-14:05 (5 records, 1 min apart)
        make_record(200, 2000, "groupA_00.log", r".\logs\groupA_00.log",
            UsnReason::FILE_CREATE, RecordSource::Allocated),
        make_record(201, 2001, "groupA_01.log", r".\logs\groupA_01.log",
            UsnReason::DATA_EXTEND, RecordSource::Allocated),
        make_record(202, 2002, "groupA_02.log", r".\logs\groupA_02.log",
            UsnReason::FILE_CREATE, RecordSource::Allocated),
        make_record(203, 2003, "groupA_03.log", r".\logs\groupA_03.log",
            UsnReason::DATA_EXTEND, RecordSource::Allocated),
        make_record(204, 2004, "groupA_04.log", r".\logs\groupA_04.log",
            UsnReason::FILE_CREATE, RecordSource::Allocated),
        // Group B: 16:00-16:10 (3 records, 5 min apart, 2h after group A)
        make_record(210, 2010, "groupB_00.dat", r".\data\groupB_00.dat",
            UsnReason::FILE_CREATE, RecordSource::Allocated),
        make_record(211, 2011, "groupB_01.dat", r".\data\groupB_01.dat",
            UsnReason::DATA_EXTEND, RecordSource::Carved),
        make_record(212, 2012, "groupB_02.dat", r".\data\groupB_02.dat",
            UsnReason::FILE_CREATE, RecordSource::Allocated),
        // Group C: next day 10:00-10:05 (2 records, 20h after group B)
        make_record(220, 2020, "groupC_00.txt", r".\docs\groupC_00.txt",
            UsnReason::FILE_CREATE, RecordSource::Allocated),
        make_record(221, 2021, "groupC_01.txt", r".\docs\groupC_01.txt",
            UsnReason::FILE_DELETE, RecordSource::Ghost),
    ];

    // Override timestamps: use make_record then patch, since make_record uses usn-based ts
    let mut resolved: Vec<ResolvedRecord> = records;
    let offsets: &[i64] = &[
        0, 60, 120, 180, 300,          // Group A: +0m, +1m, +2m, +3m, +5m
        7200, 7500, 7800,              // Group B: +2h, +2h5m, +2h10m
        72000, 72300,                  // Group C: +20h, +20h5m
    ];
    for (r, &offset) in resolved.iter_mut().zip(offsets.iter()) {
        r.record.timestamp = DateTime::from_timestamp(base + offset, 0).unwrap();
    }

    let ghosts = vec![GhostRecord {
        record: UsnRecord {
            mft_entry: 221,
            mft_sequence: 1,
            parent_mft_entry: 5,
            parent_mft_sequence: 5,
            usn: 2021,
            timestamp: DateTime::from_timestamp(base + 72300, 0).unwrap(),
            reason: UsnReason::FILE_DELETE,
            filename: "groupC_01.txt".to_string(),
            file_attributes: FileAttributes::ARCHIVE,
            source_info: 0,
            security_id: 0,
            major_version: 2,
        },
        lsn: 99999,
    }];

    let clearing = JournalClearingResult {
        clearing_detected: false,
        first_usn: Some(2000),
        timestamp_gaps: vec![],
        confidence: 0.0,
    };

    let questions = builtin_questions();
    let input = ReportInput {
        image_name: "time_filter_test.E01",
        resolved: &resolved,
        mft_data: None,
        timestomping: &[],
        secure_deletion: &[],
        ransomware: &[],
        journal_clearing: &clearing,
        ghost_records: &ghosts,
        carved_usn_count: 1,
        carved_mft_count: 0,
        carving_bytes_scanned: 2048,
        carving_chunks: 2,
        carving_usn_dupes: 0,
        carving_mft_dupes: 0,
    };
    let data = build_report_data(&input, &questions);

    // Verify data structure
    assert_eq!(data.records.len(), 10, "should have 10 records total");

    // Export to HTML file for Playwright testing
    let out_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/output");
    fs::create_dir_all(&out_dir).unwrap();
    let out_path = out_dir.join("time_filter_test.html");
    let mut file = fs::File::create(&out_path).unwrap();
    export_report(&data, &mut file).unwrap();

    // Verify file was written
    let meta = fs::metadata(&out_path).unwrap();
    assert!(meta.len() > 1000, "report HTML should have content");
    eprintln!("Test report written to: {}", out_path.display());
}
