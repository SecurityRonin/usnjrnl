#![no_main]
//! $MFT vs $MFTMirr byte comparison — both inputs are attacker-controlled.
//! The first byte selects a split point so the fuzzer can size each side.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (split, rest) = match data.split_first() {
        Some((s, r)) => (*s as usize % (r.len() + 1), r),
        None => return,
    };
    let (mft, mftmirr) = rest.split_at(split);
    let _ = ntfs_core::mftmirr::compare_mft_mirror(mft, mftmirr);
});
