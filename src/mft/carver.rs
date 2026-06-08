//! MFT entry carving — re-exported from [`ntfs_core::carve`].
//!
//! The carver moved into ntfs-core (it decodes raw NTFS MFT records); this shim
//! keeps `crate::mft::carver::…` paths resolving for the rewind/correlation
//! layers that consume it.

pub use ntfs_core::carve::{carve_mft_entries, CarvedMftEntry, MftCarvingStats};
