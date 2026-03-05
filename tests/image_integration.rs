//! Integration tests for E01 disk image extraction.
//!
//! These tests require the `image` feature and real forensic test images.
//! They are gated with `#[ignore]` and only run when explicitly requested:
//!
//!   cargo test --features image --test image_integration -- --ignored

#![cfg(feature = "image")]

use std::path::Path;
use usnjrnl_forensic::image::extract_artifacts;

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
