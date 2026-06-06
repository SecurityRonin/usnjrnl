//! Parity gate: `extract_artifacts` (now backed by ntfs-forensic) must produce
//! the same bytes as TSK on a real image.
//!
//! ```bash
//! icat -o <ntfs_lba> disk.E01 1 > mftmirr.icat        # $MFTMirr = record 1
//! NTFS_FORENSIC_E01=disk.E01 NTFS_FORENSIC_MFTMIRR=mftmirr.icat \
//!   cargo test --features image --test extract_parity -- --ignored --nocapture
//! ```
#![cfg(feature = "image")]

use std::path::Path;

#[test]
#[ignore = "requires NTFS_FORENSIC_E01 + NTFS_FORENSIC_MFTMIRR (icat oracle)"]
fn extract_artifacts_match_icat() {
    let (Ok(e01), Ok(mftmirr_ref)) = (
        std::env::var("NTFS_FORENSIC_E01"),
        std::env::var("NTFS_FORENSIC_MFTMIRR"),
    ) else {
        return;
    };

    let tmp = tempfile::tempdir().expect("tempdir");
    let arts = usnjrnl_forensic::image::extract_artifacts(Path::new(&e01), tmp.path())
        .expect("extract_artifacts");

    let mftmirr = std::fs::read(&arts.mftmirr).expect("read extracted $MFTMirr");
    let expected = std::fs::read(&mftmirr_ref).expect("read icat oracle");
    println!(
        "$MFTMirr: ntfs-forensic {} bytes, icat {} bytes",
        mftmirr.len(),
        expected.len()
    );
    assert_eq!(mftmirr, expected, "$MFTMirr bytes differ from TSK icat");

    // The whole point of this crate: the USN journal lives in $UsnJrnl:$J (a
    // named stream), which ntfs-forensic's read_named_stream now extracts.
    let usn = std::fs::read(&arts.usnjrnl).expect("read extracted $UsnJrnl");
    assert!(!usn.is_empty(), "$UsnJrnl:$J must not be empty");
    println!("$UsnJrnl:$J extracted: {} bytes", usn.len());

    assert!(arts.mft.exists() && arts.logfile.exists());
}
