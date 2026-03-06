//! Integration tests for E01 disk image extraction.
//!
//! These tests require the `image` feature and real forensic test images.
//! They are gated with `#[ignore]` and only run when explicitly requested:
//!
//!   cargo test --features image --test image_integration -- --ignored

#![cfg(feature = "image")]

use std::collections::HashSet;
use std::path::Path;
use usnjrnl_forensic::image::extract_artifacts;
use usnjrnl_forensic::image::unallocated::scan_for_unallocated;

/// Test E01 extraction against the Szechuan Sauce CTF desktop image.
/// Image: 20200918_0417_DESKTOP-SDN1RPT.E01 (from DESKTOP-E01.zip)
#[test]
#[ignore]
fn extract_artifacts_from_szechuan_sauce_e01() {
    let image_path = Path::new("tests/data/20200918_0417_DESKTOP-SDN1RPT.E01");
    if !image_path.exists() {
        panic!(
            "Test image not found at {}. Download DESKTOP-E01.zip from dfirmadness.com.",
            image_path.display()
        );
    }

    let output_dir = tempfile::tempdir().unwrap();
    let result = extract_artifacts(image_path, output_dir.path());

    match &result {
        Ok(artifacts) => {
            // $MFT must exist and be non-empty
            assert!(artifacts.mft.exists(), "$MFT not extracted");
            assert!(
                std::fs::metadata(&artifacts.mft).unwrap().len() > 0,
                "$MFT is empty"
            );

            // $MFTMirr must exist and be non-empty
            assert!(artifacts.mftmirr.exists(), "$MFTMirr not extracted");
            assert!(
                std::fs::metadata(&artifacts.mftmirr).unwrap().len() > 0,
                "$MFTMirr is empty"
            );

            // $LogFile must exist and be non-empty
            assert!(artifacts.logfile.exists(), "$LogFile not extracted");
            assert!(
                std::fs::metadata(&artifacts.logfile).unwrap().len() > 0,
                "$LogFile is empty"
            );

            // $UsnJrnl:$J must exist and be non-empty
            assert!(artifacts.usnjrnl.exists(), "$UsnJrnl:$J not extracted");
            assert!(
                std::fs::metadata(&artifacts.usnjrnl).unwrap().len() > 0,
                "$UsnJrnl:$J is empty"
            );

            // Print sizes for forensic validation
            eprintln!("Extracted artifacts:");
            eprintln!(
                "  $MFT:        {} bytes",
                std::fs::metadata(&artifacts.mft).unwrap().len()
            );
            eprintln!(
                "  $MFTMirr:    {} bytes",
                std::fs::metadata(&artifacts.mftmirr).unwrap().len()
            );
            eprintln!(
                "  $LogFile:    {} bytes",
                std::fs::metadata(&artifacts.logfile).unwrap().len()
            );
            eprintln!(
                "  $UsnJrnl:$J: {} bytes",
                std::fs::metadata(&artifacts.usnjrnl).unwrap().len()
            );
        }
        Err(e) => {
            panic!("extract_artifacts failed: {:#}", e);
        }
    }
}

/// End-to-end: extract from E01 then parse with usnjrnl-forensic's own parser.
#[test]
#[ignore]
fn extracted_artifacts_are_valid_for_parsing() {
    let image_path = Path::new("tests/data/20200918_0417_DESKTOP-SDN1RPT.E01");
    if !image_path.exists() {
        return; // Skip if test image not available
    }

    let output_dir = tempfile::tempdir().unwrap();
    let artifacts = extract_artifacts(image_path, output_dir.path())
        .expect("Failed to extract artifacts from E01");

    // Parse the extracted $UsnJrnl:$J
    let journal_data = std::fs::read(&artifacts.usnjrnl).unwrap();
    let records = usnjrnl_forensic::usn::parse_usn_journal(&journal_data)
        .expect("Failed to parse extracted $UsnJrnl:$J");
    assert!(
        !records.is_empty(),
        "No USN records parsed from extracted $UsnJrnl:$J"
    );
    eprintln!(
        "Parsed {} USN records from extracted $UsnJrnl:$J",
        records.len()
    );

    // Parse the extracted $MFT
    let mft_data = usnjrnl_forensic::mft::MftData::parse(&std::fs::read(&artifacts.mft).unwrap())
        .expect("Failed to parse extracted $MFT");
    eprintln!("Parsed MFT from extracted $MFT successfully");

    // Parse the extracted $LogFile
    let logfile_data = std::fs::read(&artifacts.logfile).unwrap();
    let logfile_summary = usnjrnl_forensic::logfile::parse_logfile(&logfile_data)
        .expect("Failed to parse extracted $LogFile");
    eprintln!(
        "Parsed LogFile: {} restart areas from extracted $LogFile",
        logfile_summary.restart_areas.len()
    );

    // Do full rewind path resolution
    let mut engine = mft_data.seed_rewind();
    let resolved_records = engine.rewind(&records);
    let with_path = resolved_records
        .iter()
        .filter(|r| !r.full_path.is_empty())
        .count();
    eprintln!(
        "Path resolution: {}/{} ({:.1}%)",
        with_path,
        resolved_records.len(),
        100.0 * with_path as f64 / resolved_records.len().max(1) as f64
    );
    assert!(
        with_path > 0,
        "Rewind algorithm resolved 0 paths from extracted artifacts"
    );
}

// ─── Unallocated carving E2E tests ──────────────────────────────────────────

/// Helper: run unallocated carving against an E01 image and return stats.
/// Extracts allocated artifacts first, builds dedup sets, then scans.
fn run_carving_e2e(image_path: &Path) {
    let output_dir = tempfile::tempdir().unwrap();
    let artifacts =
        extract_artifacts(image_path, output_dir.path()).expect("Failed to extract artifacts");

    // Parse allocated $UsnJrnl to build known USN offset set
    let journal_data = std::fs::read(&artifacts.usnjrnl).unwrap();
    let records =
        usnjrnl_forensic::usn::parse_usn_journal(&journal_data).expect("Failed to parse $UsnJrnl");
    let known_usn: HashSet<i64> = records.iter().map(|r| r.usn).collect();

    // Parse allocated $MFT to build known (entry, seq) set
    let mft_raw = std::fs::read(&artifacts.mft).unwrap();
    let mft_data = usnjrnl_forensic::mft::MftData::parse(&mft_raw).expect("Failed to parse $MFT");
    let known_mft: HashSet<(u64, u16)> = mft_data
        .entries
        .iter()
        .map(|e| (e.entry_number, e.sequence_number))
        .collect();

    // Find NTFS partition for scanning
    let mut reader = ewf::EwfReader::open(image_path).expect("Failed to open EWF image");
    let partition = usnjrnl_forensic::image::find_ntfs_partition(&mut reader)
        .expect("Failed to find NTFS partition");

    eprintln!(
        "Image: {} | Partition: offset={}, size={:.1} MB",
        image_path.display(),
        partition.offset,
        partition.size as f64 / 1_048_576.0
    );
    eprintln!(
        "  Allocated: {} USN records, {} MFT entries",
        known_usn.len(),
        known_mft.len()
    );

    // Scan for carved records
    let result = scan_for_unallocated(
        &mut reader,
        partition.offset,
        partition.size,
        &known_usn,
        &known_mft,
        0, // default chunk size
    )
    .expect("Unallocated scan failed");

    eprintln!(
        "  Carved: {} USN records, {} MFT entries",
        result.usn_records.len(),
        result.mft_entries.len()
    );
    eprintln!(
        "  Deduped: {} USN, {} MFT removed as already in allocated artifacts",
        result.stats.usn_duplicates_removed, result.stats.mft_duplicates_removed
    );
    eprintln!(
        "  Scanned: {:.1} MB in {} chunks",
        result.stats.bytes_scanned as f64 / 1_048_576.0,
        result.stats.chunks_processed
    );

    // Validate carved records have sane fields
    for rec in &result.usn_records {
        assert!(
            !rec.record.filename.is_empty(),
            "Carved USN record has empty filename"
        );
    }
    for entry in &result.mft_entries {
        assert!(
            !entry.filename.is_empty(),
            "Carved MFT entry has empty filename"
        );
        assert!(
            entry.sequence_number > 0,
            "Carved MFT entry has zero sequence"
        );
    }
}

#[test]
#[ignore]
fn carve_unallocated_szechuan_sauce() {
    let path = Path::new("tests/data/20200918_0417_DESKTOP-SDN1RPT.E01");
    if !path.exists() {
        return;
    }
    run_carving_e2e(path);
}

#[test]
#[ignore]
fn carve_unallocated_pc_mus() {
    let path = Path::new("tests/data/PC-MUS-001.E01");
    if !path.exists() {
        return;
    }
    run_carving_e2e(path);
}

#[test]
#[ignore]
fn carve_unallocated_max_powers() {
    let path = Path::new("tests/data/MaxPowersCDrive.E01");
    if !path.exists() {
        return;
    }
    run_carving_e2e(path);
}
