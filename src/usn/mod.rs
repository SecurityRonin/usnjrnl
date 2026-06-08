//! USN Journal extraction built on `ntfs_core`'s parser core.
//!
//! The on-disk record format (`USN_RECORD_V2`/`V3`/`V4`, reason/attribute flag
//! sets) now lives in [`ntfs_core::usn`] — `$UsnJrnl:$J` records are an NTFS
//! metadata artifact. This module re-exports that core and adds the
//! higher-level layers that operate over journal data: a `Read + Seek` reader,
//! an unallocated-space carver, and a parallel scanner.

pub mod carver;
pub mod parallel;
mod reader;

// Parser core re-exported from ntfs_core so existing `crate::usn::…` paths and
// downstream `usnjrnl_forensic::usn::…` imports keep resolving unchanged.
pub use ntfs_core::usn::{
    parse_usn_journal, parse_usn_record_v2, parse_usn_record_v3, FileAttributes, UsnReason,
    UsnRecord,
};

pub use carver::{carve_usn_records, CarvedRecord, CarvingStats};
pub use parallel::parse_usn_journal_parallel;
pub use reader::UsnJournalReader;
