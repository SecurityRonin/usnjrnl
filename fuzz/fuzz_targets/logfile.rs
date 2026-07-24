#![no_main]
//! $LogFile restart-area / record-page scanning over arbitrary bytes.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ntfs_core::logfile::parse_logfile(data);
});
