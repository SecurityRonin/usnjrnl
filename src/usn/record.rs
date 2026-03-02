use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use log::debug;

use super::reason::UsnReason;
use super::attributes::FileAttributes;

// ─── Constants ───────────────────────────────────────────────────────────────

/// Minimum valid USN_RECORD_V2 size (without filename).
const USN_V2_MIN_SIZE: usize = 0x3C; // 60 bytes

/// Minimum valid USN_RECORD_V3 size (128-bit file refs, without filename).
const USN_V3_MIN_SIZE: usize = 0x4C; // 76 bytes

/// Minimum valid USN_RECORD_V4 size.
const USN_V4_MIN_SIZE: usize = 0x38; // 56 bytes

/// Maximum valid record size (sanity check).
const USN_MAX_RECORD_SIZE: usize = 65536;

// ─── UsnRecord ───────────────────────────────────────────────────────────────

/// A parsed USN record from the $UsnJrnl:$J (V2 or V3).
#[derive(Debug, Clone)]
pub struct UsnRecord {
    /// MFT entry number for this file/folder.
    pub mft_entry: u64,
    /// MFT sequence number for this file/folder.
    pub mft_sequence: u16,
    /// Parent folder's MFT entry number.
    pub parent_mft_entry: u64,
    /// Parent folder's MFT sequence number.
    pub parent_mft_sequence: u16,
    /// Update Sequence Number (byte offset in the journal).
    pub usn: i64,
    /// Timestamp of this journal event.
    pub timestamp: DateTime<Utc>,
    /// Reason flags (what changed).
    pub reason: UsnReason,
    /// Filename (not the full path).
    pub filename: String,
    /// File attributes at time of event.
    pub file_attributes: FileAttributes,
    /// Source information flags.
    pub source_info: u32,
    /// Security descriptor ID.
    pub security_id: u32,
    /// USN record major version (2 or 3).
    pub major_version: u16,
}

// ─── Binary helpers ──────────────────────────────────────────────────────────

fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn read_i64_le(data: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

fn read_u128_le(data: &[u8], offset: usize) -> u128 {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&data[offset..offset + 16]);
    u128::from_le_bytes(bytes)
}

/// Convert Windows FILETIME (100-ns intervals since 1601-01-01) to UTC DateTime.
fn filetime_to_datetime(filetime: i64) -> Option<DateTime<Utc>> {
    if filetime <= 0 {
        return None;
    }
    // Windows epoch is 1601-01-01, Unix epoch is 1970-01-01.
    // Difference = 11644473600 seconds = 116444736000000000 in 100-ns ticks.
    const EPOCH_DIFF: i64 = 116_444_736_000_000_000;
    let unix_100ns = filetime - EPOCH_DIFF;
    if unix_100ns < 0 {
        return None;
    }
    let secs = unix_100ns / 10_000_000;
    let nanos = ((unix_100ns % 10_000_000) * 100) as u32;
    DateTime::from_timestamp(secs, nanos)
}

// ─── V2 parser ───────────────────────────────────────────────────────────────

/// Parse a single USN_RECORD_V2 at the given offset in `data`.
pub fn parse_usn_record_v2(data: &[u8]) -> Result<UsnRecord> {
    if data.len() < USN_V2_MIN_SIZE {
        bail!("Data too short for USN_RECORD_V2: {} < {}", data.len(), USN_V2_MIN_SIZE);
    }

    let record_len = read_u32_le(data, 0x00) as usize;
    if record_len < USN_V2_MIN_SIZE || record_len > USN_MAX_RECORD_SIZE {
        bail!("Invalid V2 record length: {}", record_len);
    }
    if record_len > data.len() {
        bail!("V2 record length {} exceeds available data {}", record_len, data.len());
    }

    // File reference: 6 bytes entry + 2 bytes sequence
    let file_ref = read_u64_le(data, 0x08);
    let mft_entry = file_ref & 0x0000_FFFF_FFFF_FFFF;
    let mft_sequence = ((file_ref >> 48) & 0xFFFF) as u16;

    let parent_ref = read_u64_le(data, 0x10);
    let parent_mft_entry = parent_ref & 0x0000_FFFF_FFFF_FFFF;
    let parent_mft_sequence = ((parent_ref >> 48) & 0xFFFF) as u16;

    let usn = read_i64_le(data, 0x18);
    let timestamp_raw = read_i64_le(data, 0x20);
    let reason_bits = read_u32_le(data, 0x28);
    let source_info = read_u32_le(data, 0x2C);
    let security_id = read_u32_le(data, 0x30);
    let file_attr_bits = read_u32_le(data, 0x34);
    let filename_length = read_u16_le(data, 0x38) as usize;
    let filename_offset = read_u16_le(data, 0x3A) as usize;

    let timestamp = filetime_to_datetime(timestamp_raw)
        .unwrap_or_else(|| DateTime::from_timestamp(0, 0).unwrap());

    // Parse UTF-16LE filename
    let filename = if filename_offset + filename_length <= data.len() && filename_length >= 2 {
        let name_bytes = &data[filename_offset..filename_offset + filename_length];
        let u16_chars: Vec<u16> = name_bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&u16_chars)
    } else {
        String::new()
    };

    Ok(UsnRecord {
        mft_entry,
        mft_sequence,
        parent_mft_entry,
        parent_mft_sequence,
        usn,
        timestamp,
        reason: UsnReason::from_bits_retain(reason_bits),
        filename,
        file_attributes: FileAttributes::from_bits_retain(file_attr_bits),
        source_info,
        security_id,
        major_version: 2,
    })
}

// ─── V3 parser ───────────────────────────────────────────────────────────────

/// Parse a single USN_RECORD_V3 at the given offset in `data`.
/// V3 uses 128-bit file references (ReFS).
pub fn parse_usn_record_v3(data: &[u8]) -> Result<UsnRecord> {
    if data.len() < USN_V3_MIN_SIZE {
        bail!("Data too short for USN_RECORD_V3: {} < {}", data.len(), USN_V3_MIN_SIZE);
    }

    let record_len = read_u32_le(data, 0x00) as usize;
    if record_len < USN_V3_MIN_SIZE || record_len > USN_MAX_RECORD_SIZE {
        bail!("Invalid V3 record length: {}", record_len);
    }

    // 128-bit file reference at offset 0x08
    let file_ref_128 = read_u128_le(data, 0x08);
    let mft_entry = (file_ref_128 & 0xFFFF_FFFF_FFFF) as u64;
    let mft_sequence = 0u16; // V3 doesn't use traditional sequence numbers

    // 128-bit parent reference at offset 0x18
    let parent_ref_128 = read_u128_le(data, 0x18);
    let parent_mft_entry = (parent_ref_128 & 0xFFFF_FFFF_FFFF) as u64;
    let parent_mft_sequence = 0u16;

    let usn = read_i64_le(data, 0x28);
    let timestamp_raw = read_i64_le(data, 0x30);
    let reason_bits = read_u32_le(data, 0x38);
    let source_info = read_u32_le(data, 0x3C);
    let security_id = read_u32_le(data, 0x40);
    let file_attr_bits = read_u32_le(data, 0x44);
    let filename_length = read_u16_le(data, 0x48) as usize;
    let filename_offset = read_u16_le(data, 0x4A) as usize;

    let timestamp = filetime_to_datetime(timestamp_raw)
        .unwrap_or_else(|| DateTime::from_timestamp(0, 0).unwrap());

    let filename = if filename_offset + filename_length <= data.len() && filename_length >= 2 {
        let name_bytes = &data[filename_offset..filename_offset + filename_length];
        let u16_chars: Vec<u16> = name_bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&u16_chars)
    } else {
        String::new()
    };

    Ok(UsnRecord {
        mft_entry,
        mft_sequence,
        parent_mft_entry,
        parent_mft_sequence,
        usn,
        timestamp,
        reason: UsnReason::from_bits_retain(reason_bits),
        filename,
        file_attributes: FileAttributes::from_bits_retain(file_attr_bits),
        source_info,
        security_id,
        major_version: 3,
    })
}

// ─── Bulk parser ─────────────────────────────────────────────────────────────

/// Parse all USN records from raw $UsnJrnl:$J data.
///
/// Handles V2, V3 records. V4 records are skipped (range-tracking only).
/// Skips zero-filled regions and corrupt records gracefully.
pub fn parse_usn_journal(data: &[u8]) -> Result<Vec<UsnRecord>> {
    let mut records = Vec::new();
    let mut offset = 0;
    let len = data.len();

    while offset + 8 <= len {
        // Skip zero-filled regions (sparse journal pages)
        if data[offset..offset + 4] == [0, 0, 0, 0] {
            // Scan forward in 8-byte chunks for non-zero data
            let mut found = false;
            while offset + 8 <= len {
                if data[offset..offset + 8] != [0, 0, 0, 0, 0, 0, 0, 0] {
                    found = true;
                    break;
                }
                offset += 8;
            }
            if !found {
                break;
            }
        }

        if offset + 8 > len {
            break;
        }

        let record_len = read_u32_le(data, offset) as usize;

        // Validate record length
        if record_len < USN_V4_MIN_SIZE || record_len > USN_MAX_RECORD_SIZE {
            debug!("Invalid record length {} at offset 0x{:x}, scanning forward", record_len, offset);
            offset += 8;
            continue;
        }

        if offset + record_len > len {
            debug!("Record at 0x{:x} extends past end of data", offset);
            break;
        }

        // Check version
        let major_version = read_u16_le(data, offset + 4);

        match major_version {
            2 => {
                if record_len < USN_V2_MIN_SIZE {
                    offset += 8;
                    continue;
                }
                match parse_usn_record_v2(&data[offset..offset + record_len]) {
                    Ok(record) => {
                        // Skip close-only records (forensically insignificant noise)
                        if record.reason != UsnReason::CLOSE {
                            records.push(record);
                        }
                    }
                    Err(e) => {
                        debug!("Failed to parse V2 at 0x{:x}: {}", offset, e);
                    }
                }
            }
            3 => {
                if record_len < USN_V3_MIN_SIZE {
                    offset += 8;
                    continue;
                }
                match parse_usn_record_v3(&data[offset..offset + record_len]) {
                    Ok(record) => {
                        if record.reason != UsnReason::CLOSE {
                            records.push(record);
                        }
                    }
                    Err(e) => {
                        debug!("Failed to parse V3 at 0x{:x}: {}", offset, e);
                    }
                }
            }
            4 => {
                // V4 records contain range-tracking data only (no timestamps/filenames).
                // Skip them for timeline purposes.
                debug!("Skipping V4 record at 0x{:x}", offset);
            }
            _ => {
                debug!("Unknown USN version {} at 0x{:x}", major_version, offset);
                offset += 8;
                continue;
            }
        }

        // Advance by record length, aligned to 8 bytes
        let aligned = (record_len + 7) & !7;
        offset += aligned;
    }

    Ok(records)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn build_v2_record(
        entry: u64,
        seq: u16,
        parent_entry: u64,
        parent_seq: u16,
        reason: u32,
        filename: &str,
    ) -> Vec<u8> {
        let name_utf16: Vec<u16> = filename.encode_utf16().collect();
        let name_bytes_len = name_utf16.len() * 2;
        let record_len = 0x3C + name_bytes_len;
        let aligned_len = (record_len + 7) & !7;
        let mut buf = vec![0u8; aligned_len];

        // Record length
        buf[0..4].copy_from_slice(&(record_len as u32).to_le_bytes());
        // Major version = 2
        buf[4..6].copy_from_slice(&2u16.to_le_bytes());
        // Minor version = 0
        buf[6..8].copy_from_slice(&0u16.to_le_bytes());
        // File reference
        let file_ref = entry | ((seq as u64) << 48);
        buf[0x08..0x10].copy_from_slice(&file_ref.to_le_bytes());
        // Parent reference
        let parent_ref = parent_entry | ((parent_seq as u64) << 48);
        buf[0x10..0x18].copy_from_slice(&parent_ref.to_le_bytes());
        // USN
        buf[0x18..0x20].copy_from_slice(&100i64.to_le_bytes());
        // Timestamp: 2024-01-15 12:00:00 UTC
        let ts: i64 = 133500480000000000;
        buf[0x20..0x28].copy_from_slice(&ts.to_le_bytes());
        // Reason
        buf[0x28..0x2C].copy_from_slice(&reason.to_le_bytes());
        // Source info
        buf[0x2C..0x30].copy_from_slice(&0u32.to_le_bytes());
        // Security ID
        buf[0x30..0x34].copy_from_slice(&0u32.to_le_bytes());
        // File attributes (ARCHIVE)
        buf[0x34..0x38].copy_from_slice(&0x20u32.to_le_bytes());
        // Filename length
        buf[0x38..0x3A].copy_from_slice(&(name_bytes_len as u16).to_le_bytes());
        // Filename offset
        buf[0x3A..0x3C].copy_from_slice(&0x3Cu16.to_le_bytes());
        // Filename UTF-16LE
        for (i, &ch) in name_utf16.iter().enumerate() {
            let off = 0x3C + i * 2;
            buf[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }

        buf
    }

    #[test]
    fn test_parse_v2_record() {
        let data = build_v2_record(100, 3, 5, 5, 0x100, "test.txt");
        let record = parse_usn_record_v2(&data).unwrap();

        assert_eq!(record.mft_entry, 100);
        assert_eq!(record.mft_sequence, 3);
        assert_eq!(record.parent_mft_entry, 5);
        assert_eq!(record.parent_mft_sequence, 5);
        assert_eq!(record.filename, "test.txt");
        assert!(record.reason.contains(UsnReason::FILE_CREATE));
        assert_eq!(record.major_version, 2);
    }

    #[test]
    fn test_parse_v2_unicode_filename() {
        let data = build_v2_record(200, 1, 5, 5, 0x100, "日本語.txt");
        let record = parse_usn_record_v2(&data).unwrap();
        assert_eq!(record.filename, "日本語.txt");
    }

    #[test]
    fn test_parse_journal_skips_zero_regions() {
        let mut data = vec![0u8; 4096]; // Zero-filled region
        let record = build_v2_record(100, 1, 5, 5, 0x100, "after_gap.txt");
        data.extend_from_slice(&record);

        let records = parse_usn_journal(&data).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].filename, "after_gap.txt");
    }

    #[test]
    fn test_parse_journal_multiple_records() {
        let r1 = build_v2_record(100, 1, 5, 5, 0x100, "file1.txt");
        let r2 = build_v2_record(200, 1, 100, 1, 0x200, "file2.txt");
        let mut data = Vec::new();
        data.extend_from_slice(&r1);
        data.extend_from_slice(&r2);

        let records = parse_usn_journal(&data).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].filename, "file1.txt");
        assert_eq!(records[1].filename, "file2.txt");
    }

    #[test]
    fn test_parse_journal_skips_close_only() {
        let r = build_v2_record(100, 1, 5, 5, 0x8000_0000, "closed.txt");
        let records = parse_usn_journal(&r).unwrap();
        assert_eq!(records.len(), 0);
    }

    #[test]
    fn test_file_reference_extraction() {
        // Entry 12345, sequence 7
        let data = build_v2_record(12345, 7, 5, 5, 0x100, "x.txt");
        let record = parse_usn_record_v2(&data).unwrap();
        assert_eq!(record.mft_entry, 12345);
        assert_eq!(record.mft_sequence, 7);
    }

    #[test]
    fn test_parent_reference_extraction() {
        let data = build_v2_record(100, 1, 983, 4, 0x100, "data.txt");
        let record = parse_usn_record_v2(&data).unwrap();
        assert_eq!(record.parent_mft_entry, 983);
        assert_eq!(record.parent_mft_sequence, 4);
    }

    #[test]
    fn test_reason_flags_preserved() {
        let reason = 0x0000_0100 | 0x8000_0000; // FILE_CREATE | CLOSE
        let data = build_v2_record(100, 1, 5, 5, reason, "x.txt");
        let record = parse_usn_record_v2(&data).unwrap();
        assert!(record.reason.contains(UsnReason::FILE_CREATE));
        assert!(record.reason.contains(UsnReason::CLOSE));
    }

    #[test]
    fn test_too_short_data_fails() {
        let data = vec![0u8; 10];
        assert!(parse_usn_record_v2(&data).is_err());
    }

    // ─── V3 parser tests ────────────────────────────────────────────────

    fn build_v3_record(
        entry: u64,
        parent_entry: u64,
        reason: u32,
        filename: &str,
    ) -> Vec<u8> {
        let name_utf16: Vec<u16> = filename.encode_utf16().collect();
        let name_bytes_len = name_utf16.len() * 2;
        let record_len = 0x4C + name_bytes_len;
        let aligned_len = (record_len + 7) & !7;
        let mut buf = vec![0u8; aligned_len];

        // Record length
        buf[0..4].copy_from_slice(&(record_len as u32).to_le_bytes());
        // Major version = 3
        buf[4..6].copy_from_slice(&3u16.to_le_bytes());
        // Minor version = 0
        buf[6..8].copy_from_slice(&0u16.to_le_bytes());
        // 128-bit file reference at 0x08
        let file_ref_128: u128 = entry as u128;
        buf[0x08..0x18].copy_from_slice(&file_ref_128.to_le_bytes());
        // 128-bit parent reference at 0x18
        let parent_ref_128: u128 = parent_entry as u128;
        buf[0x18..0x28].copy_from_slice(&parent_ref_128.to_le_bytes());
        // USN
        buf[0x28..0x30].copy_from_slice(&200i64.to_le_bytes());
        // Timestamp: 2024-01-15 12:00:00 UTC
        let ts: i64 = 133500480000000000;
        buf[0x30..0x38].copy_from_slice(&ts.to_le_bytes());
        // Reason
        buf[0x38..0x3C].copy_from_slice(&reason.to_le_bytes());
        // Source info
        buf[0x3C..0x40].copy_from_slice(&0u32.to_le_bytes());
        // Security ID
        buf[0x40..0x44].copy_from_slice(&0u32.to_le_bytes());
        // File attributes (ARCHIVE)
        buf[0x44..0x48].copy_from_slice(&0x20u32.to_le_bytes());
        // Filename length
        buf[0x48..0x4A].copy_from_slice(&(name_bytes_len as u16).to_le_bytes());
        // Filename offset
        buf[0x4A..0x4C].copy_from_slice(&0x4Cu16.to_le_bytes());
        // Filename UTF-16LE
        for (i, &ch) in name_utf16.iter().enumerate() {
            let off = 0x4C + i * 2;
            buf[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }

        buf
    }

    #[test]
    fn test_parse_v3_record_basic() {
        let data = build_v3_record(100, 5, 0x100, "v3_test.txt");
        let record = parse_usn_record_v3(&data).unwrap();

        assert_eq!(record.mft_entry, 100);
        assert_eq!(record.mft_sequence, 0); // V3 doesn't use seq
        assert_eq!(record.parent_mft_entry, 5);
        assert_eq!(record.parent_mft_sequence, 0);
        assert_eq!(record.filename, "v3_test.txt");
        assert!(record.reason.contains(UsnReason::FILE_CREATE));
        assert_eq!(record.major_version, 3);
    }

    #[test]
    fn test_parse_v3_record_unicode() {
        let data = build_v3_record(200, 5, 0x100, "日本語ファイル.txt");
        let record = parse_usn_record_v3(&data).unwrap();
        assert_eq!(record.filename, "日本語ファイル.txt");
        assert_eq!(record.major_version, 3);
    }

    #[test]
    fn test_parse_v3_too_short() {
        let data = vec![0u8; 0x4B]; // Less than USN_V3_MIN_SIZE
        assert!(parse_usn_record_v3(&data).is_err());
    }

    #[test]
    fn test_parse_v3_invalid_record_length_too_small() {
        let mut data = vec![0u8; 0x60];
        // record_len smaller than min
        data[0..4].copy_from_slice(&(0x30u32).to_le_bytes());
        data[4..6].copy_from_slice(&3u16.to_le_bytes());
        assert!(parse_usn_record_v3(&data).is_err());
    }

    #[test]
    fn test_parse_v3_invalid_record_length_too_large() {
        let mut data = vec![0u8; 0x60];
        // record_len larger than max
        data[0..4].copy_from_slice(&(70000u32).to_le_bytes());
        data[4..6].copy_from_slice(&3u16.to_le_bytes());
        assert!(parse_usn_record_v3(&data).is_err());
    }

    #[test]
    fn test_parse_v3_zero_filename() {
        // V3 record with zero-length filename
        let mut data = vec![0u8; 0x60];
        let record_len = 0x4Cu32;
        data[0..4].copy_from_slice(&record_len.to_le_bytes());
        data[4..6].copy_from_slice(&3u16.to_le_bytes());
        // 128-bit file reference
        data[0x08..0x18].copy_from_slice(&100u128.to_le_bytes());
        data[0x18..0x28].copy_from_slice(&5u128.to_le_bytes());
        data[0x28..0x30].copy_from_slice(&100i64.to_le_bytes());
        let ts: i64 = 133500480000000000;
        data[0x30..0x38].copy_from_slice(&ts.to_le_bytes());
        data[0x38..0x3C].copy_from_slice(&0x100u32.to_le_bytes());
        // filename_length = 0
        data[0x48..0x4A].copy_from_slice(&0u16.to_le_bytes());
        data[0x4A..0x4C].copy_from_slice(&0x4Cu16.to_le_bytes());

        let record = parse_usn_record_v3(&data).unwrap();
        assert_eq!(record.filename, "");
    }

    // ─── V2 edge case tests ─────────────────────────────────────────────

    #[test]
    fn test_parse_v2_invalid_record_length_too_small() {
        let mut data = vec![0u8; 0x60];
        // record_len below min
        data[0..4].copy_from_slice(&(0x30u32).to_le_bytes());
        data[4..6].copy_from_slice(&2u16.to_le_bytes());
        assert!(parse_usn_record_v2(&data).is_err());
    }

    #[test]
    fn test_parse_v2_invalid_record_length_too_large() {
        let mut data = vec![0u8; 0x60];
        // record_len exceeds max
        data[0..4].copy_from_slice(&(70000u32).to_le_bytes());
        data[4..6].copy_from_slice(&2u16.to_le_bytes());
        assert!(parse_usn_record_v2(&data).is_err());
    }

    #[test]
    fn test_parse_v2_record_length_exceeds_data() {
        let mut data = vec![0u8; 0x40];
        // record_len says 0x100 but we only have 0x40 bytes
        data[0..4].copy_from_slice(&(0x100u32).to_le_bytes());
        data[4..6].copy_from_slice(&2u16.to_le_bytes());
        assert!(parse_usn_record_v2(&data).is_err());
    }

    #[test]
    fn test_parse_v2_zero_filename() {
        let mut data = vec![0u8; 0x40];
        let record_len = 0x3Cu32;
        data[0..4].copy_from_slice(&record_len.to_le_bytes());
        data[4..6].copy_from_slice(&2u16.to_le_bytes());
        let file_ref = 100u64 | (3u64 << 48);
        data[0x08..0x10].copy_from_slice(&file_ref.to_le_bytes());
        let parent_ref = 5u64 | (5u64 << 48);
        data[0x10..0x18].copy_from_slice(&parent_ref.to_le_bytes());
        data[0x18..0x20].copy_from_slice(&100i64.to_le_bytes());
        let ts: i64 = 133500480000000000;
        data[0x20..0x28].copy_from_slice(&ts.to_le_bytes());
        data[0x28..0x2C].copy_from_slice(&0x100u32.to_le_bytes());
        data[0x34..0x38].copy_from_slice(&0x20u32.to_le_bytes());
        // filename_length = 0
        data[0x38..0x3A].copy_from_slice(&0u16.to_le_bytes());
        data[0x3A..0x3C].copy_from_slice(&0x3Cu16.to_le_bytes());

        let record = parse_usn_record_v2(&data).unwrap();
        assert_eq!(record.filename, "");
    }

    #[test]
    fn test_parse_v2_zero_timestamp() {
        // A record with timestamp = 0 should use epoch fallback
        let mut data = build_v2_record(100, 1, 5, 5, 0x100, "t.txt");
        // Set timestamp to 0
        data[0x20..0x28].copy_from_slice(&0i64.to_le_bytes());

        let record = parse_usn_record_v2(&data).unwrap();
        assert_eq!(record.timestamp.timestamp(), 0);
    }

    #[test]
    fn test_parse_v2_negative_timestamp() {
        // A record with negative timestamp should use epoch fallback
        let mut data = build_v2_record(100, 1, 5, 5, 0x100, "t.txt");
        data[0x20..0x28].copy_from_slice(&(-1i64).to_le_bytes());

        let record = parse_usn_record_v2(&data).unwrap();
        assert_eq!(record.timestamp.timestamp(), 0);
    }

    #[test]
    fn test_parse_v2_pre_epoch_timestamp() {
        // A timestamp before Unix epoch but valid Windows FILETIME
        let mut data = build_v2_record(100, 1, 5, 5, 0x100, "old.txt");
        // A FILETIME value between 1601 and 1970 (positive but < EPOCH_DIFF)
        let ts: i64 = 100_000_000_000_000_000; // ~1917
        data[0x20..0x28].copy_from_slice(&ts.to_le_bytes());

        let record = parse_usn_record_v2(&data).unwrap();
        // Should fall back to epoch 0
        assert_eq!(record.timestamp.timestamp(), 0);
    }

    #[test]
    fn test_parse_v2_filename_out_of_bounds() {
        // Filename offset + length exceeds data length
        let mut data = build_v2_record(100, 1, 5, 5, 0x100, "ok.txt");
        // Set filename_length to something huge
        data[0x38..0x3A].copy_from_slice(&(5000u16).to_le_bytes());

        let record = parse_usn_record_v2(&data).unwrap();
        assert_eq!(record.filename, ""); // Should get empty string fallback
    }

    #[test]
    fn test_parse_v2_filename_length_one_byte() {
        // Filename length of 1 is < 2, so should produce empty string
        let mut data = build_v2_record(100, 1, 5, 5, 0x100, "x.txt");
        data[0x38..0x3A].copy_from_slice(&1u16.to_le_bytes());

        let record = parse_usn_record_v2(&data).unwrap();
        assert_eq!(record.filename, "");
    }

    // ─── Bulk parser edge cases ─────────────────────────────────────────

    #[test]
    fn test_parse_journal_v3_records() {
        let r = build_v3_record(100, 5, 0x100, "v3file.txt");
        let records = parse_usn_journal(&r).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].filename, "v3file.txt");
        assert_eq!(records[0].major_version, 3);
    }

    #[test]
    fn test_parse_journal_mixed_v2_v3() {
        let mut data = Vec::new();
        data.extend_from_slice(&build_v2_record(100, 1, 5, 5, 0x100, "v2.txt"));
        data.extend_from_slice(&build_v3_record(200, 5, 0x200, "v3.txt"));

        let records = parse_usn_journal(&data).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].major_version, 2);
        assert_eq!(records[1].major_version, 3);
    }

    #[test]
    fn test_parse_journal_v4_record_skipped() {
        // Build a fake V4 record - it should be skipped
        let record_len = 0x38u32; // USN_V4_MIN_SIZE
        let aligned_len = ((record_len as usize) + 7) & !7;
        let mut data = vec![0u8; aligned_len];
        data[0..4].copy_from_slice(&record_len.to_le_bytes());
        data[4..6].copy_from_slice(&4u16.to_le_bytes()); // version 4

        let records = parse_usn_journal(&data).unwrap();
        assert_eq!(records.len(), 0);
    }

    #[test]
    fn test_parse_journal_unknown_version_skipped() {
        let record_len = 0x40u32;
        let aligned_len = ((record_len as usize) + 7) & !7;
        let mut data = vec![0u8; aligned_len];
        data[0..4].copy_from_slice(&record_len.to_le_bytes());
        data[4..6].copy_from_slice(&99u16.to_le_bytes()); // unknown version

        let records = parse_usn_journal(&data).unwrap();
        assert_eq!(records.len(), 0);
    }

    #[test]
    fn test_parse_journal_invalid_record_length_scan_forward() {
        // Invalid record length should cause scanning forward
        let mut data = vec![0u8; 16];
        data[0..4].copy_from_slice(&3u32.to_le_bytes()); // too small
        data[4..6].copy_from_slice(&2u16.to_le_bytes());
        // Fill rest with zeros (will end loop)

        let records = parse_usn_journal(&data).unwrap();
        assert_eq!(records.len(), 0);
    }

    #[test]
    fn test_parse_journal_record_extends_past_end() {
        // Record claims to be 0x1000 bytes, but data is only 0x100
        let mut data = vec![0u8; 0x100];
        data[0..4].copy_from_slice(&(0x1000u32).to_le_bytes());
        data[4..6].copy_from_slice(&2u16.to_le_bytes());

        let records = parse_usn_journal(&data).unwrap();
        assert_eq!(records.len(), 0);
    }

    #[test]
    fn test_parse_journal_empty_data() {
        let records = parse_usn_journal(&[]).unwrap();
        assert_eq!(records.len(), 0);
    }

    #[test]
    fn test_parse_journal_all_zeros() {
        let data = vec![0u8; 4096];
        let records = parse_usn_journal(&data).unwrap();
        assert_eq!(records.len(), 0);
    }

    #[test]
    fn test_parse_journal_v2_too_small_for_v2_but_valid_len() {
        // record_len >= V4_MIN but < V2_MIN, version=2 -> skip
        let mut data = vec![0u8; 0x40];
        data[0..4].copy_from_slice(&(0x3Au32).to_le_bytes()); // < V2_MIN (0x3C)
        data[4..6].copy_from_slice(&2u16.to_le_bytes());

        let records = parse_usn_journal(&data).unwrap();
        assert_eq!(records.len(), 0);
    }

    #[test]
    fn test_parse_journal_v3_too_small_for_v3_but_valid_len() {
        // record_len >= V4_MIN but < V3_MIN, version=3 -> skip
        let mut data = vec![0u8; 0x50];
        data[0..4].copy_from_slice(&(0x40u32).to_le_bytes()); // < V3_MIN (0x4C)
        data[4..6].copy_from_slice(&3u16.to_le_bytes());

        let records = parse_usn_journal(&data).unwrap();
        assert_eq!(records.len(), 0);
    }

    #[test]
    fn test_parse_journal_v3_close_only_skipped() {
        let r = build_v3_record(100, 5, 0x8000_0000, "closed.txt");
        let records = parse_usn_journal(&r).unwrap();
        assert_eq!(records.len(), 0); // CLOSE-only filtered out
    }

    #[test]
    fn test_parse_journal_8byte_alignment() {
        // Verify that records are properly aligned to 8-byte boundaries
        let r1 = build_v2_record(100, 1, 5, 5, 0x100, "a.txt");
        assert_eq!(r1.len() % 8, 0); // Should be 8-byte aligned already
        let r2 = build_v2_record(200, 1, 5, 5, 0x200, "b.txt");
        let mut data = Vec::new();
        data.extend_from_slice(&r1);
        data.extend_from_slice(&r2);

        let records = parse_usn_journal(&data).unwrap();
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn test_filetime_to_datetime_zero() {
        assert!(filetime_to_datetime(0).is_none());
    }

    #[test]
    fn test_filetime_to_datetime_negative() {
        assert!(filetime_to_datetime(-100).is_none());
    }

    #[test]
    fn test_filetime_to_datetime_pre_unix_epoch() {
        // FILETIME before Unix epoch but after Windows epoch
        let pre_unix: i64 = 100_000_000_000_000_000;
        assert!(filetime_to_datetime(pre_unix).is_none());
    }

    #[test]
    fn test_filetime_to_datetime_valid() {
        let ts: i64 = 133500480000000000;
        let dt = filetime_to_datetime(ts);
        assert!(dt.is_some());
        let dt = dt.unwrap();
        // Verify it produces a date in January 2024
        assert_eq!(dt.format("%Y").to_string(), "2024");
    }

    #[test]
    fn test_read_u128_le() {
        let mut data = [0u8; 16];
        let val: u128 = 0x0102030405060708090A0B0C0D0E0F10;
        data.copy_from_slice(&val.to_le_bytes());
        assert_eq!(read_u128_le(&data, 0), val);
    }

    #[test]
    fn test_read_u64_le() {
        let mut data = [0u8; 8];
        let val: u64 = 0x0102030405060708;
        data.copy_from_slice(&val.to_le_bytes());
        assert_eq!(read_u64_le(&data, 0), val);
    }

    #[test]
    fn test_read_i64_le() {
        let mut data = [0u8; 8];
        let val: i64 = -12345;
        data.copy_from_slice(&val.to_le_bytes());
        assert_eq!(read_i64_le(&data, 0), val);
    }

    #[test]
    fn test_read_u32_le() {
        let mut data = [0u8; 4];
        data.copy_from_slice(&42u32.to_le_bytes());
        assert_eq!(read_u32_le(&data, 0), 42);
    }

    #[test]
    fn test_read_u16_le() {
        let mut data = [0u8; 2];
        data.copy_from_slice(&1234u16.to_le_bytes());
        assert_eq!(read_u16_le(&data, 0), 1234);
    }
}
