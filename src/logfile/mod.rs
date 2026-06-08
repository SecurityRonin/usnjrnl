//! $LogFile parsing — re-exported from [`ntfs_core::logfile`].
//!
//! The $LogFile parser and the embedded-USN extractor moved into ntfs-core
//! (they decode NTFS metadata); these shims keep `crate::logfile::…` and
//! `crate::logfile::usn_extractor::…` paths resolving unchanged.

pub use ntfs_core::logfile::{
    detect_journal_clearing, parse_logfile, LogFileSummary, RestartArea,
};

/// Re-export so `crate::logfile::usn_extractor::…` paths keep resolving.
pub mod usn_extractor {
    pub use ntfs_core::logfile::usn_extractor::{
        extract_usn_from_logfile, LogFileRecordSource, LogFileUsnRecord,
    };
}
