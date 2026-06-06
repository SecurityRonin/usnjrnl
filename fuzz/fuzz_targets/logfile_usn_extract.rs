#![no_main]
//! Extracting USN records embedded in $LogFile RCRD redo/undo/slack areas —
//! nested length fields are attacker-controlled, so this must never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = usnjrnl_forensic::logfile::usn_extractor::extract_usn_from_logfile(data);
});
