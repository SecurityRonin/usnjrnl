#![no_main]
//! $UsnJrnl:$J is fully attacker-controlled — record parsing must never panic.
//! Exercises the bulk journal parser plus the V2/V3 single-record parsers.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = usnjrnl_forensic::usn::parse_usn_journal(data);
    let _ = usnjrnl_forensic::usn::parse_usn_record_v2(data);
    let _ = usnjrnl_forensic::usn::parse_usn_record_v3(data);
});
