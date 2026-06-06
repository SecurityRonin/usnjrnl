#![no_main]
//! MFT entry carving over arbitrary bytes — FILE-signature scanning plus
//! resident $FILE_NAME attribute decoding must stay panic-free.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = usnjrnl_forensic::mft::carver::carve_mft_entries(data);
});
