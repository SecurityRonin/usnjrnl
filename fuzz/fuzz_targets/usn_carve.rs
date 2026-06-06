#![no_main]
//! USN record carving over arbitrary unallocated/disk bytes — signature
//! scanning + per-candidate validation must stay panic-free.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = usnjrnl_forensic::usn::carve_usn_records(data);
});
