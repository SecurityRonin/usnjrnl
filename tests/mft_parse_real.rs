//! Doer-checker gate: parse a REAL $MFT through `MftData::parse` and sanity-check
//! the wrapper logic (entry counts, well-known system records, path resolution)
//! that the synthetic fixtures cannot exercise. The underlying record/attribute
//! parser is independently cross-validated in ntfs-forensic's parity_mft.rs.
//!
//! ```bash
//! icat <e01-or-raw $MFT> > real_mft.raw
//! NTFS_FORENSIC_MFT=/tmp/real_mft.raw \
//!   cargo test --test mft_parse_real -- --ignored --nocapture
//! ```
use usnjrnl_forensic::mft::MftData;

#[test]
#[ignore = "requires NTFS_FORENSIC_MFT (raw $MFT bytes)"]
fn parse_real_mft_sanity() {
    let Ok(path) = std::env::var("NTFS_FORENSIC_MFT") else {
        return;
    };
    let data = std::fs::read(&path).expect("read $MFT");
    let mft = MftData::parse(&data).expect("parse real $MFT");

    println!("parsed {} entries from {} bytes", mft.entries.len(), data.len());
    assert!(mft.entries.len() > 10_000, "real $MFT should yield many entries");

    // Well-known NTFS metafiles must be present with their canonical names.
    let mft0 = mft.get_by_entry(0).expect("$MFT (entry 0) present");
    assert_eq!(mft0.filename, "$MFT", "entry 0 is $MFT");
    assert!(mft0.is_in_use);
    assert_eq!(mft.get_by_entry(5).map(|e| e.filename.as_str()), Some("."), "entry 5 is root '.'");

    // Path resolution: every in-use entry's full_path must start with the root prefix.
    let bad = mft
        .entries
        .iter()
        .filter(|e| e.is_in_use)
        .find(|e| !e.full_path.starts_with(".\\"));
    assert!(bad.is_none(), "full_path must be rooted: {:?}", bad.map(|e| &e.full_path));

    // Directories vs files both appear.
    let dirs = mft.entries.iter().filter(|e| e.is_directory).count();
    let files = mft.entries.iter().filter(|e| !e.is_directory).count();
    println!("directories: {dirs}, files: {files}");
    assert!(dirs > 0 && files > 0);
}
