#![no_main]
//! $MFT parsing (fixup + attribute walking via ntfs-core) over arbitrary
//! bytes — record headers and attribute chains are attacker-controlled.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ntfs_core::mft::MftData::parse(data);
});
