#![no_main]
//! $LogFile restart-area / record-page scanning over arbitrary bytes.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = usnjrnl_forensic::logfile::parse_logfile(data);
});
