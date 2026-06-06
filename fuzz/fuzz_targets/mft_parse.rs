#![no_main]
//! $MFT parsing (fixup + attribute walking via ntfs-forensic) over arbitrary
//! bytes — record headers and attribute chains are attacker-controlled.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = usnjrnl_forensic::mft::MftData::parse(data);
});
