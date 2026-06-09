//! USN Journal extraction built on `ntfs_core`'s parser core.
//!
//! The on-disk record format (`USN_RECORD_V2`/`V3`/`V4`, reason/attribute flag
//! sets), the `Read + Seek` reader, and the unallocated-space carver all live
//! in [`ntfs_core::usn`] — `$UsnJrnl:$J` records are an NTFS metadata artifact.
//! This module re-exports that core so existing `crate::usn::…` and downstream
//! `usnjrnl_forensic::usn::…` paths keep resolving, and adds the only journal
//! layer that stays local: the rayon-backed parallel scanner.

pub mod parallel;

// Parser/reader/carver core re-exported from ntfs_core so existing
// `crate::usn::…` paths and downstream `usnjrnl_forensic::usn::…` imports keep
// resolving unchanged.
pub use ntfs_core::usn::{
    carve_usn_records, parse_usn_journal, parse_usn_record_v2, parse_usn_record_v3, CarvedRecord,
    CarvingStats, FileAttributes, UsnJournalReader, UsnReason, UsnRecord,
};

pub use parallel::parse_usn_journal_parallel;
