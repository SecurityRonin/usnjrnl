//! $MFTMirr comparison — re-exported from [`ntfs_core::mftmirr`].
//!
//! The parser/comparison primitive moved into ntfs-core (it decodes NTFS
//! metadata); this shim keeps `crate::mftmirr::…` paths resolving. Tamper
//! findings are layered on top by the analyzer.

pub use ntfs_core::mftmirr::{compare_mft_mirror, MirrorComparison};
