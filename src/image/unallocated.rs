//! Unallocated space scanning for carved USN records and MFT entries.
//!
//! Reads a partition in overlapping chunks, runs both the USN carver and
//! MFT carver on each chunk, and deduplicates results against known
//! allocated records.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom};

use anyhow::Result;
use log::info;

use crate::mft::carver::{carve_mft_entries, CarvedMftEntry, MftCarvingStats};
use crate::usn::carver::{carve_usn_records, CarvedRecord, CarvingStats};

// ─── Constants ───────────────────────────────────────────────────────────────

/// Default chunk size for reading partition data (4 MB).
const DEFAULT_CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// Overlap between chunks to catch USN records at boundaries.
/// Must be >= max USN record size (64 KB).
const CHUNK_OVERLAP: usize = 65536;

// ─── Result types ────────────────────────────────────────────────────────────

/// Results from scanning a partition for carved records.
#[derive(Debug)]
pub struct UnallocatedScanResults {
    /// USN records carved from unallocated/slack space (not in allocated $J).
    pub usn_records: Vec<CarvedRecord>,
    /// MFT entries carved from unallocated/slack space (not in allocated $MFT).
    pub mft_entries: Vec<CarvedMftEntry>,
    /// Scanning statistics.
    pub stats: UnallocatedScanStats,
}

/// Statistics from scanning unallocated space.
#[derive(Debug, Clone, Default)]
pub struct UnallocatedScanStats {
    /// Total bytes scanned.
    pub bytes_scanned: u64,
    /// Number of chunks processed.
    pub chunks_processed: u64,
    /// USN records found before deduplication.
    pub usn_records_found: usize,
    /// MFT entries found before deduplication.
    pub mft_entries_found: usize,
    /// USN records removed as duplicates of allocated records.
    pub usn_duplicates_removed: usize,
    /// MFT entries removed as duplicates of allocated records.
    pub mft_duplicates_removed: usize,
    /// Aggregate USN carving stats.
    pub usn_carving: CarvingStats,
    /// Aggregate MFT carving stats.
    pub mft_carving: MftCarvingStats,
}

// ─── Scanner ─────────────────────────────────────────────────────────────────

/// Scan a partition for carved USN records and MFT entries.
///
/// Reads the partition in overlapping chunks, carves both USN records and
/// MFT entries from each chunk, and deduplicates against known allocated
/// records.
///
/// # Arguments
/// * `reader` - A seekable reader positioned at the start of the partition
/// * `partition_offset` - Byte offset of the partition within the image
/// * `partition_size` - Size of the partition in bytes
/// * `known_usn_offsets` - USN offset values from the allocated $J (for dedup)
/// * `known_mft_keys` - (entry_number, sequence_number) pairs from allocated $MFT
/// * `chunk_size` - Size of each read chunk (use 0 for default 4MB)
pub fn scan_for_unallocated<R: Read + Seek>(
    reader: &mut R,
    partition_offset: u64,
    partition_size: u64,
    known_usn_offsets: &HashSet<i64>,
    known_mft_keys: &HashSet<(u64, u16)>,
    chunk_size: usize,
) -> Result<UnallocatedScanResults> {
    let chunk_size = if chunk_size == 0 {
        DEFAULT_CHUNK_SIZE
    } else {
        chunk_size.max(CHUNK_OVERLAP * 2) // must be larger than overlap
    };
    let advance = chunk_size - CHUNK_OVERLAP;

    let mut all_usn: HashMap<u64, CarvedRecord> = HashMap::new();
    let mut all_mft: HashMap<u64, CarvedMftEntry> = HashMap::new();
    let mut stats = UnallocatedScanStats::default();

    let mut pos: u64 = 0;
    let mut buf = vec![0u8; chunk_size];

    while pos < partition_size {
        reader.seek(SeekFrom::Start(partition_offset + pos))?;
        let to_read = chunk_size.min((partition_size - pos) as usize);
        let n = read_full(reader, &mut buf[..to_read])?;
        if n == 0 {
            break;
        }

        let chunk = &buf[..n];

        // Carve USN records
        let (usn_records, usn_stats) = carve_usn_records(chunk);
        stats.usn_carving.candidates_examined += usn_stats.candidates_examined;
        stats.usn_carving.rejected_timestamp += usn_stats.rejected_timestamp;
        stats.usn_carving.rejected_structure += usn_stats.rejected_structure;

        for rec in usn_records {
            let abs_offset = pos + rec.offset as u64;
            stats.usn_records_found += 1;
            if known_usn_offsets.contains(&rec.record.usn) {
                stats.usn_duplicates_removed += 1;
            } else {
                all_usn.entry(abs_offset).or_insert(rec);
            }
        }

        // Carve MFT entries
        let (mft_entries, mft_stats) = carve_mft_entries(chunk);
        stats.mft_carving.candidates_examined += mft_stats.candidates_examined;
        stats.mft_carving.rejected += mft_stats.rejected;

        for entry in mft_entries {
            let abs_offset = pos + entry.offset as u64;
            stats.mft_entries_found += 1;
            let key = (entry.entry_number, entry.sequence_number);
            if known_mft_keys.contains(&key) {
                stats.mft_duplicates_removed += 1;
            } else {
                all_mft.entry(abs_offset).or_insert(entry);
            }
        }

        stats.bytes_scanned += n as u64;
        stats.chunks_processed += 1;

        if n < chunk_size {
            break; // reached end of partition
        }
        pos += advance as u64;
    }

    stats.usn_carving.bytes_scanned = stats.bytes_scanned as usize;
    stats.usn_carving.records_carved = all_usn.len();
    stats.mft_carving.bytes_scanned = stats.bytes_scanned as usize;
    stats.mft_carving.entries_carved = all_mft.len();

    info!(
        "Unallocated scan: {} USN records, {} MFT entries ({} chunks, {:.1} MB)",
        all_usn.len(),
        all_mft.len(),
        stats.chunks_processed,
        stats.bytes_scanned as f64 / 1_048_576.0,
    );

    Ok(UnallocatedScanResults {
        usn_records: all_usn.into_values().collect(),
        mft_entries: all_mft.into_values().collect(),
        stats,
    })
}

/// Read as many bytes as possible, handling partial reads.
fn read_full<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..])? {
            0 => break,
            n => total += n,
        }
    }
    Ok(total)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // Re-use test helpers from the carver modules for building records.

    /// Build a valid USN V2 record (same logic as usn::carver::tests).
    fn build_usn_v2_record(
        entry: u64,
        seq: u16,
        parent_entry: u64,
        parent_seq: u16,
        usn_offset: i64,
        reason: u32,
        filename: &str,
    ) -> Vec<u8> {
        let name_utf16: Vec<u16> = filename.encode_utf16().collect();
        let name_bytes_len = name_utf16.len() * 2;
        let record_len = 0x3C + name_bytes_len;
        let aligned_len = (record_len + 7) & !7;
        let mut buf = vec![0u8; aligned_len];

        buf[0..4].copy_from_slice(&(record_len as u32).to_le_bytes());
        buf[4..6].copy_from_slice(&2u16.to_le_bytes());
        buf[6..8].copy_from_slice(&0u16.to_le_bytes());
        let file_ref = entry | ((seq as u64) << 48);
        buf[0x08..0x10].copy_from_slice(&file_ref.to_le_bytes());
        let parent_ref = parent_entry | ((parent_seq as u64) << 48);
        buf[0x10..0x18].copy_from_slice(&parent_ref.to_le_bytes());
        buf[0x18..0x20].copy_from_slice(&usn_offset.to_le_bytes());
        let ts: i64 = 133_500_480_000_000_000; // 2024-01-15
        buf[0x20..0x28].copy_from_slice(&ts.to_le_bytes());
        buf[0x28..0x2C].copy_from_slice(&reason.to_le_bytes());
        buf[0x30..0x34].copy_from_slice(&0u32.to_le_bytes());
        buf[0x34..0x38].copy_from_slice(&0x20u32.to_le_bytes());
        buf[0x38..0x3A].copy_from_slice(&(name_bytes_len as u16).to_le_bytes());
        buf[0x3A..0x3C].copy_from_slice(&0x3Cu16.to_le_bytes());
        for (i, &ch) in name_utf16.iter().enumerate() {
            let off = 0x3C + i * 2;
            buf[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }
        buf
    }

    /// Build a valid MFT entry (same logic as mft::carver::tests).
    fn build_mft_entry(
        entry_number: u32,
        sequence: u16,
        parent_entry: u64,
        parent_seq: u16,
        filename: &str,
        flags: u16,
    ) -> Vec<u8> {
        let mut buf = vec![0u8; 1024];

        buf[0..4].copy_from_slice(b"FILE");
        buf[4..6].copy_from_slice(&48u16.to_le_bytes());
        buf[6..8].copy_from_slice(&3u16.to_le_bytes());
        buf[8..16].copy_from_slice(&1u64.to_le_bytes());
        buf[16..18].copy_from_slice(&sequence.to_le_bytes());
        buf[18..20].copy_from_slice(&1u16.to_le_bytes());
        let first_attr: u16 = 56;
        buf[20..22].copy_from_slice(&first_attr.to_le_bytes());
        buf[22..24].copy_from_slice(&flags.to_le_bytes());
        buf[24..28].copy_from_slice(&512u32.to_le_bytes());
        buf[28..32].copy_from_slice(&1024u32.to_le_bytes());
        buf[44..48].copy_from_slice(&entry_number.to_le_bytes());
        buf[48..50].copy_from_slice(&0x0001u16.to_le_bytes());

        // FILE_NAME attribute
        let name_utf16: Vec<u16> = filename.encode_utf16().collect();
        let name_bytes_len = name_utf16.len() * 2;
        let fn_content_size = 66 + name_bytes_len;
        let content_offset: u16 = 24;
        let attr_size = (content_offset as usize + fn_content_size + 7) & !7;
        let attr_start = first_attr as usize;

        buf[attr_start..attr_start + 4].copy_from_slice(&0x30u32.to_le_bytes());
        buf[attr_start + 4..attr_start + 8].copy_from_slice(&(attr_size as u32).to_le_bytes());
        buf[attr_start + 8] = 0;
        buf[attr_start + 16..attr_start + 20]
            .copy_from_slice(&(fn_content_size as u32).to_le_bytes());
        buf[attr_start + 20..attr_start + 22].copy_from_slice(&content_offset.to_le_bytes());

        let fn_start = attr_start + content_offset as usize;
        let parent_ref = parent_entry | ((parent_seq as u64) << 48);
        buf[fn_start..fn_start + 8].copy_from_slice(&parent_ref.to_le_bytes());
        let ts: i64 = 133_500_480_000_000_000;
        for i in 0..4 {
            let off = fn_start + 8 + i * 8;
            buf[off..off + 8].copy_from_slice(&ts.to_le_bytes());
        }
        buf[fn_start + 64] = name_utf16.len() as u8;
        buf[fn_start + 65] = 3; // Win32+DOS
        for (i, &ch) in name_utf16.iter().enumerate() {
            let off = fn_start + 66 + i * 2;
            buf[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }
        let end_offset = attr_start + attr_size;
        buf[end_offset..end_offset + 4].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());

        buf
    }

    /// Build partition data with embedded records surrounded by zeroed space.
    /// Returns (data, usn_partition_offsets, mft_partition_offsets).
    fn build_partition_with_records() -> (Vec<u8>, Vec<u64>, Vec<u64>) {
        // Use a small partition: 256 KB
        let part_size = 256 * 1024;
        let mut data = vec![0u8; part_size];

        let mut usn_offsets = Vec::new();
        let mut mft_offsets = Vec::new();

        // Place an MFT entry at offset 0 (1024-byte aligned)
        let mft1 = build_mft_entry(42, 3, 5, 1, "carved_mft.txt", 0x01);
        data[0..1024].copy_from_slice(&mft1);
        mft_offsets.push(0u64);

        // Place a USN record at offset 2048 (8-byte aligned)
        let usn1 = build_usn_v2_record(100, 1, 5, 1, 1000, 0x100, "carved_usn.txt");
        let usn1_len = usn1.len();
        data[2048..2048 + usn1_len].copy_from_slice(&usn1);
        usn_offsets.push(2048u64);

        // Place another MFT entry at offset 4096
        let mft2 = build_mft_entry(99, 1, 5, 1, "another_mft.doc", 0x01);
        data[4096..4096 + 1024].copy_from_slice(&mft2);
        mft_offsets.push(4096u64);

        // Place another USN record at offset 8192
        let usn2 = build_usn_v2_record(200, 2, 100, 1, 2000, 0x200, "second_usn.doc");
        let usn2_len = usn2.len();
        data[8192..8192 + usn2_len].copy_from_slice(&usn2);
        usn_offsets.push(8192u64);

        (data, usn_offsets, mft_offsets)
    }

    // ─── Tests ───────────────────────────────────────────────────────────────

    #[test]
    fn test_scan_empty_partition() {
        let data = vec![0u8; 4096];
        let mut cursor = Cursor::new(data);
        let result =
            scan_for_unallocated(&mut cursor, 0, 4096, &HashSet::new(), &HashSet::new(), 4096)
                .unwrap();

        assert_eq!(result.usn_records.len(), 0);
        assert_eq!(result.mft_entries.len(), 0);
    }

    #[test]
    fn test_scan_finds_usn_records() {
        let (data, _, _) = build_partition_with_records();
        let part_size = data.len() as u64;
        let mut cursor = Cursor::new(data);

        let result = scan_for_unallocated(
            &mut cursor,
            0,
            part_size,
            &HashSet::new(), // no known records → nothing deduped
            &HashSet::new(),
            part_size as usize, // single chunk
        )
        .unwrap();

        assert!(
            result.usn_records.len() >= 2,
            "Should find at least 2 USN records, found {}",
            result.usn_records.len()
        );
    }

    #[test]
    fn test_scan_finds_mft_entries() {
        let (data, _, _) = build_partition_with_records();
        let part_size = data.len() as u64;
        let mut cursor = Cursor::new(data);

        let result = scan_for_unallocated(
            &mut cursor,
            0,
            part_size,
            &HashSet::new(),
            &HashSet::new(),
            part_size as usize,
        )
        .unwrap();

        assert!(
            result.mft_entries.len() >= 2,
            "Should find at least 2 MFT entries, found {}",
            result.mft_entries.len()
        );
    }

    #[test]
    fn test_scan_deduplicates_usn_by_usn_offset() {
        let (data, _, _) = build_partition_with_records();
        let part_size = data.len() as u64;
        let mut cursor = Cursor::new(data);

        // Mark USN offset 1000 as known → that record should be removed
        let mut known_usn = HashSet::new();
        known_usn.insert(1000i64);

        let result = scan_for_unallocated(
            &mut cursor,
            0,
            part_size,
            &known_usn,
            &HashSet::new(),
            part_size as usize,
        )
        .unwrap();

        // Only the record with USN offset 2000 should remain
        assert_eq!(result.usn_records.len(), 1);
        assert_eq!(result.usn_records[0].record.usn, 2000);
        assert_eq!(result.stats.usn_duplicates_removed, 1);
    }

    #[test]
    fn test_scan_deduplicates_mft_by_entry_and_sequence() {
        let (data, _, _) = build_partition_with_records();
        let part_size = data.len() as u64;
        let mut cursor = Cursor::new(data);

        // Mark (42, 3) as known → that entry should be removed
        let mut known_mft = HashSet::new();
        known_mft.insert((42u64, 3u16));

        let result = scan_for_unallocated(
            &mut cursor,
            0,
            part_size,
            &HashSet::new(),
            &known_mft,
            part_size as usize,
        )
        .unwrap();

        // Only entry_number=99 should remain
        assert_eq!(result.mft_entries.len(), 1);
        assert_eq!(result.mft_entries[0].entry_number, 99);
        assert_eq!(result.stats.mft_duplicates_removed, 1);
    }

    #[test]
    fn test_scan_with_partition_offset() {
        // Simulate a partition starting at offset 1MB in the image
        let prefix = vec![0u8; 1024 * 1024]; // 1MB of zeros before partition
        let (part_data, _, _) = build_partition_with_records();
        let part_size = part_data.len() as u64;
        let partition_offset = prefix.len() as u64;

        let mut image_data = prefix;
        image_data.extend_from_slice(&part_data);

        let mut cursor = Cursor::new(image_data);

        let result = scan_for_unallocated(
            &mut cursor,
            partition_offset,
            part_size,
            &HashSet::new(),
            &HashSet::new(),
            part_size as usize,
        )
        .unwrap();

        assert!(result.usn_records.len() >= 2);
        assert!(result.mft_entries.len() >= 2);
    }

    #[test]
    fn test_scan_chunked_finds_all_records() {
        let (data, _, _) = build_partition_with_records();
        let part_size = data.len() as u64;
        let mut cursor = Cursor::new(data);

        // Use a very small chunk size to force multiple chunks
        // Records are at offsets 0, 2048, 4096, 8192
        // With chunk_size = 131072 + 65536 overlap, we should still find all
        let chunk_size = CHUNK_OVERLAP * 2 + 1024; // just over minimum

        let result = scan_for_unallocated(
            &mut cursor,
            0,
            part_size,
            &HashSet::new(),
            &HashSet::new(),
            chunk_size,
        )
        .unwrap();

        assert!(
            result.usn_records.len() >= 2,
            "Chunked scan should find USN records, found {}",
            result.usn_records.len()
        );
        assert!(
            result.mft_entries.len() >= 2,
            "Chunked scan should find MFT entries, found {}",
            result.mft_entries.len()
        );
        assert!(result.stats.chunks_processed >= 2);
    }

    #[test]
    fn test_scan_stats_tracking() {
        let (data, _, _) = build_partition_with_records();
        let part_size = data.len() as u64;
        let mut cursor = Cursor::new(data);

        let mut known_usn = HashSet::new();
        known_usn.insert(1000i64);
        let mut known_mft = HashSet::new();
        known_mft.insert((42u64, 3u16));

        let result = scan_for_unallocated(
            &mut cursor,
            0,
            part_size,
            &known_usn,
            &known_mft,
            part_size as usize,
        )
        .unwrap();

        assert!(result.stats.bytes_scanned > 0);
        assert!(result.stats.chunks_processed >= 1);
        assert_eq!(result.stats.usn_records_found, 2); // found 2 before dedup
        assert_eq!(result.stats.mft_entries_found, 2);
        assert_eq!(result.stats.usn_duplicates_removed, 1);
        assert_eq!(result.stats.mft_duplicates_removed, 1);
    }

    #[test]
    fn test_scan_keeps_different_sequence_mft_entries() {
        // An MFT entry with same entry_number but different sequence is a
        // historical version and should NOT be deduplicated.
        let mut data = vec![0u8; 4096];
        let entry = build_mft_entry(42, 5, 5, 1, "reused.txt", 0x01);
        data[0..1024].copy_from_slice(&entry);

        let mut cursor = Cursor::new(data);

        // Known MFT has (42, 3) — different sequence from carved (42, 5)
        let mut known_mft = HashSet::new();
        known_mft.insert((42u64, 3u16));

        let result =
            scan_for_unallocated(&mut cursor, 0, 4096, &HashSet::new(), &known_mft, 4096).unwrap();

        assert_eq!(
            result.mft_entries.len(),
            1,
            "Historical MFT entry (different sequence) should be kept"
        );
        assert_eq!(result.mft_entries[0].sequence_number, 5);
        assert_eq!(result.stats.mft_duplicates_removed, 0);
    }
}
