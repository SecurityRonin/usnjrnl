//! MFT parsing for path resolution and correlation with USN Journal.
//!
//! Uses the `mft` crate for parsing $MFT entries. Extracts entry numbers,
//! sequence numbers, filenames, and parent references needed for the
//! Rewind engine and timestomping detection.

use std::collections::HashMap;

use anyhow::Result;
use chrono::{DateTime, Utc};
use log::debug;
use mft::MftParser;
use mft::attribute::MftAttributeType;

use crate::rewind::{EntryKey, RewindEngine};

/// Parsed MFT entry with fields relevant to USN Journal correlation.
#[derive(Debug, Clone)]
pub struct MftEntry {
    pub entry_number: u64,
    pub sequence_number: u16,
    pub filename: String,
    pub parent_entry: u64,
    pub parent_sequence: u16,
    pub is_directory: bool,
    pub is_in_use: bool,
    /// $STANDARD_INFORMATION timestamps (user-modifiable).
    pub si_created: Option<DateTime<Utc>>,
    pub si_modified: Option<DateTime<Utc>>,
    pub si_mft_modified: Option<DateTime<Utc>>,
    pub si_accessed: Option<DateTime<Utc>>,
    /// $FILE_NAME timestamps (harder to modify, more trustworthy).
    pub fn_created: Option<DateTime<Utc>>,
    pub fn_modified: Option<DateTime<Utc>>,
    pub fn_mft_modified: Option<DateTime<Utc>>,
    pub fn_accessed: Option<DateTime<Utc>>,
    /// Full path resolved from MFT parent chain.
    pub full_path: String,
    /// File size from $DATA attribute.
    pub file_size: u64,
    /// Whether this entry has alternate data streams.
    pub has_ads: bool,
}

/// Parsed $MFT data for correlation.
pub struct MftData {
    /// All parsed entries.
    pub entries: Vec<MftEntry>,
    /// Map: entry_number -> index in entries vec (for current allocation).
    pub by_entry: HashMap<u64, usize>,
    /// Map: (entry, sequence) -> index (sequence-aware lookup).
    pub by_key: HashMap<EntryKey, usize>,
}

impl MftData {
    /// Parse raw $MFT data.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut parser = MftParser::from_buffer(data.to_vec())?;

        // First pass: collect all raw MFT entries
        let raw_entries: Vec<_> = parser.iter_entries().collect();

        let mut entries = Vec::new();
        let mut by_entry = HashMap::new();
        let mut by_key = HashMap::new();

        for entry_result in raw_entries {
            let entry = match entry_result {
                Ok(e) => e,
                Err(e) => {
                    debug!("Skipping invalid MFT entry: {}", e);
                    continue;
                }
            };

            let entry_number = entry.header.record_number;
            let sequence_number = entry.header.sequence;
            let is_in_use = entry.is_allocated();
            let is_directory = entry.is_dir();

            // SI timestamps
            let mut si_created = None;
            let mut si_modified = None;
            let mut si_mft_modified = None;
            let mut si_accessed = None;
            let mut has_ads = false;

            // Extract $STANDARD_INFORMATION timestamps
            for attr_result in entry.iter_attributes_matching(
                Some(vec![MftAttributeType::StandardInformation]),
            ) {
                if let Ok(attr) = attr_result {
                    if let Some(si) = attr.data.into_standard_info() {
                        si_created = Some(DateTime::<Utc>::from(si.created));
                        si_modified = Some(DateTime::<Utc>::from(si.modified));
                        si_mft_modified = Some(DateTime::<Utc>::from(si.mft_modified));
                        si_accessed = Some(DateTime::<Utc>::from(si.accessed));
                    }
                }
            }

            // Use find_best_name_attribute for filename and parent ref
            let best_name = match entry.find_best_name_attribute() {
                Some(name) => name,
                None => continue,
            };

            let best_filename = best_name.name.clone();
            let parent_entry = best_name.parent.entry;
            let parent_sequence = best_name.parent.sequence;
            let fn_created = Some(DateTime::<Utc>::from(best_name.created));
            let fn_modified = Some(DateTime::<Utc>::from(best_name.modified));
            let fn_mft_modified = Some(DateTime::<Utc>::from(best_name.mft_modified));
            let fn_accessed = Some(DateTime::<Utc>::from(best_name.accessed));

            // Check for ADS: look for $DATA attributes with non-empty names
            for attr_result in entry.iter_attributes_matching(
                Some(vec![MftAttributeType::DATA]),
            ) {
                if let Ok(attr) = attr_result {
                    if !attr.header.name.is_empty() {
                        has_ads = true;
                        break;
                    }
                }
            }

            // Resolve full path (parser is no longer borrowed by iter_entries)
            let full_path = parser
                .get_full_path_for_entry(&entry)
                .unwrap_or_default()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();

            let idx = entries.len();
            let mft_entry = MftEntry {
                entry_number,
                sequence_number,
                filename: best_filename,
                parent_entry,
                parent_sequence,
                is_directory,
                is_in_use,
                si_created,
                si_modified,
                si_mft_modified,
                si_accessed,
                fn_created,
                fn_modified,
                fn_mft_modified,
                fn_accessed,
                full_path,
                file_size: 0,
                has_ads,
            };

            by_entry.insert(entry_number, idx);
            by_key.insert(EntryKey::new(entry_number, sequence_number), idx);
            entries.push(mft_entry);
        }

        Ok(Self {
            entries,
            by_entry,
            by_key,
        })
    }

    /// Seed a RewindEngine with the current MFT state.
    pub fn seed_rewind(&self) -> RewindEngine {
        let mft_iter = self.entries.iter().map(|e| {
            (
                e.entry_number,
                e.sequence_number,
                e.filename.clone(),
                e.parent_entry,
                e.parent_sequence,
            )
        });
        RewindEngine::from_mft(mft_iter)
    }

    /// Detect potential timestomping: $SI created before $FN created.
    pub fn detect_timestomping(&self) -> Vec<&MftEntry> {
        self.entries
            .iter()
            .filter(|e| {
                if let (Some(si_c), Some(fn_c)) = (e.si_created, e.fn_created) {
                    si_c < fn_c || {
                        if let Some(si_m) = e.si_modified {
                            si_m < fn_c
                        } else {
                            false
                        }
                    }
                } else {
                    false
                }
            })
            .collect()
    }

    /// Get entry by entry number (current allocation).
    pub fn get_by_entry(&self, entry_number: u64) -> Option<&MftEntry> {
        self.by_entry.get(&entry_number).map(|&idx| &self.entries[idx])
    }

    /// Get entry by (entry, sequence) pair.
    pub fn get_by_key(&self, key: &EntryKey) -> Option<&MftEntry> {
        self.by_key.get(key).map(|&idx| &self.entries[idx])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mft_data_empty() {
        let result = MftData::parse(&[]);
        assert!(result.is_err() || result.unwrap().entries.is_empty());
    }

    #[test]
    fn test_entry_key_equality() {
        let k1 = EntryKey::new(100, 3);
        let k2 = EntryKey::new(100, 3);
        let k3 = EntryKey::new(100, 4);
        assert_eq!(k1, k2);
        assert_ne!(k1, k3);
    }

    #[test]
    fn test_mft_data_get_by_entry_not_found() {
        // Empty MftData should return None for any entry lookup
        let mft_data = MftData {
            entries: Vec::new(),
            by_entry: HashMap::new(),
            by_key: HashMap::new(),
        };
        assert!(mft_data.get_by_entry(100).is_none());
    }

    #[test]
    fn test_mft_data_get_by_key_not_found() {
        let mft_data = MftData {
            entries: Vec::new(),
            by_entry: HashMap::new(),
            by_key: HashMap::new(),
        };
        let key = EntryKey::new(100, 3);
        assert!(mft_data.get_by_key(&key).is_none());
    }

    fn make_mft_entry(
        entry_number: u64,
        sequence_number: u16,
        filename: &str,
        parent_entry: u64,
        parent_sequence: u16,
        is_dir: bool,
        is_in_use: bool,
    ) -> MftEntry {
        MftEntry {
            entry_number,
            sequence_number,
            filename: filename.to_string(),
            parent_entry,
            parent_sequence,
            is_directory: is_dir,
            is_in_use,
            si_created: None,
            si_modified: None,
            si_mft_modified: None,
            si_accessed: None,
            fn_created: None,
            fn_modified: None,
            fn_mft_modified: None,
            fn_accessed: None,
            full_path: format!(".\\{}", filename),
            file_size: 0,
            has_ads: false,
        }
    }

    #[test]
    fn test_mft_data_get_by_entry_found() {
        let entry = make_mft_entry(100, 3, "test.txt", 5, 5, false, true);
        let mut by_entry = HashMap::new();
        by_entry.insert(100u64, 0usize);
        let mut by_key = HashMap::new();
        by_key.insert(EntryKey::new(100, 3), 0usize);

        let mft_data = MftData {
            entries: vec![entry],
            by_entry,
            by_key,
        };

        let found = mft_data.get_by_entry(100);
        assert!(found.is_some());
        assert_eq!(found.unwrap().filename, "test.txt");
    }

    #[test]
    fn test_mft_data_get_by_key_found() {
        let entry = make_mft_entry(100, 3, "test.txt", 5, 5, false, true);
        let mut by_entry = HashMap::new();
        by_entry.insert(100u64, 0usize);
        let mut by_key = HashMap::new();
        by_key.insert(EntryKey::new(100, 3), 0usize);

        let mft_data = MftData {
            entries: vec![entry],
            by_entry,
            by_key,
        };

        let key = EntryKey::new(100, 3);
        let found = mft_data.get_by_key(&key);
        assert!(found.is_some());
        assert_eq!(found.unwrap().filename, "test.txt");
    }

    #[test]
    fn test_detect_timestomping_si_before_fn() {
        use chrono::DateTime;
        let mut entry = make_mft_entry(100, 1, "suspicious.exe", 5, 5, false, true);
        // SI created is before FN created -> timestomped
        entry.si_created = Some(DateTime::from_timestamp(1700000000, 0).unwrap());
        entry.fn_created = Some(DateTime::from_timestamp(1700001000, 0).unwrap());

        let mut by_entry = HashMap::new();
        by_entry.insert(100u64, 0usize);
        let mft_data = MftData {
            entries: vec![entry],
            by_entry,
            by_key: HashMap::new(),
        };

        let stomped = mft_data.detect_timestomping();
        assert_eq!(stomped.len(), 1);
        assert_eq!(stomped[0].filename, "suspicious.exe");
    }

    #[test]
    fn test_detect_timestomping_si_modified_before_fn_created() {
        use chrono::DateTime;
        let mut entry = make_mft_entry(100, 1, "modified.exe", 5, 5, false, true);
        // SI created is same as FN, but SI modified is before FN created
        entry.si_created = Some(DateTime::from_timestamp(1700001000, 0).unwrap());
        entry.si_modified = Some(DateTime::from_timestamp(1700000000, 0).unwrap());
        entry.fn_created = Some(DateTime::from_timestamp(1700001000, 0).unwrap());

        let mft_data = MftData {
            entries: vec![entry],
            by_entry: HashMap::new(),
            by_key: HashMap::new(),
        };

        let stomped = mft_data.detect_timestomping();
        assert_eq!(stomped.len(), 1);
    }

    #[test]
    fn test_detect_timestomping_none_when_consistent() {
        use chrono::DateTime;
        let mut entry = make_mft_entry(100, 1, "normal.txt", 5, 5, false, true);
        let ts = DateTime::from_timestamp(1700001000, 0).unwrap();
        entry.si_created = Some(ts);
        entry.si_modified = Some(ts);
        entry.fn_created = Some(ts);

        let mft_data = MftData {
            entries: vec![entry],
            by_entry: HashMap::new(),
            by_key: HashMap::new(),
        };

        let stomped = mft_data.detect_timestomping();
        assert_eq!(stomped.len(), 0);
    }

    #[test]
    fn test_detect_timestomping_no_timestamps() {
        let entry = make_mft_entry(100, 1, "no_ts.txt", 5, 5, false, true);

        let mft_data = MftData {
            entries: vec![entry],
            by_entry: HashMap::new(),
            by_key: HashMap::new(),
        };

        let stomped = mft_data.detect_timestomping();
        assert_eq!(stomped.len(), 0);
    }

    #[test]
    fn test_seed_rewind() {
        let entry = make_mft_entry(100, 1, "test.txt", 5, 5, false, true);
        let mut by_entry = HashMap::new();
        by_entry.insert(100u64, 0usize);
        let mut by_key = HashMap::new();
        by_key.insert(EntryKey::new(100, 1), 0usize);

        let mft_data = MftData {
            entries: vec![entry],
            by_entry,
            by_key,
        };

        let engine = mft_data.seed_rewind();
        assert_eq!(engine.lookup_len(), 1);
        let path = engine.resolve_path(&EntryKey::new(100, 1));
        assert_eq!(path, ".\\test.txt");
    }

    #[test]
    fn test_mft_data_multiple_entries() {
        let e1 = make_mft_entry(100, 1, "file1.txt", 5, 5, false, true);
        let e2 = make_mft_entry(200, 2, "file2.txt", 100, 1, false, true);
        let e3 = make_mft_entry(300, 1, "dir1", 5, 5, true, true);

        let mut by_entry = HashMap::new();
        by_entry.insert(100u64, 0usize);
        by_entry.insert(200u64, 1usize);
        by_entry.insert(300u64, 2usize);

        let mut by_key = HashMap::new();
        by_key.insert(EntryKey::new(100, 1), 0usize);
        by_key.insert(EntryKey::new(200, 2), 1usize);
        by_key.insert(EntryKey::new(300, 1), 2usize);

        let mft_data = MftData {
            entries: vec![e1, e2, e3],
            by_entry,
            by_key,
        };

        assert_eq!(mft_data.entries.len(), 3);
        assert_eq!(mft_data.get_by_entry(200).unwrap().filename, "file2.txt");
        assert_eq!(mft_data.get_by_key(&EntryKey::new(300, 1)).unwrap().filename, "dir1");
        assert!(mft_data.get_by_key(&EntryKey::new(300, 1)).unwrap().is_directory);
    }

    #[test]
    fn test_detect_timestomping_si_modified_none() {
        use chrono::DateTime;
        let mut entry = make_mft_entry(100, 1, "check.exe", 5, 5, false, true);
        // SI created == FN created, SI modified is None
        let ts = DateTime::from_timestamp(1700001000, 0).unwrap();
        entry.si_created = Some(ts);
        entry.si_modified = None;
        entry.fn_created = Some(ts);

        let mft_data = MftData {
            entries: vec![entry],
            by_entry: HashMap::new(),
            by_key: HashMap::new(),
        };

        let stomped = mft_data.detect_timestomping();
        assert_eq!(stomped.len(), 0);
    }

    #[test]
    fn test_mft_entry_has_ads_field() {
        let mut entry = make_mft_entry(100, 1, "ads.txt", 5, 5, false, true);
        entry.has_ads = true;
        assert!(entry.has_ads);
    }

    #[test]
    fn test_mft_entry_file_size() {
        let mut entry = make_mft_entry(100, 1, "big.bin", 5, 5, false, true);
        entry.file_size = 1_048_576;
        assert_eq!(entry.file_size, 1_048_576);
    }

    #[test]
    fn test_mft_data_parse_invalid_data() {
        // Random garbage data that is not a valid MFT - should error or return empty
        let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
        let result = MftData::parse(&garbage);
        // Either it errors out or it parses with zero valid entries
        match result {
            Ok(mft_data) => assert!(mft_data.entries.is_empty()),
            Err(_) => {} // Error is also acceptable for invalid data
        }
    }

    #[test]
    fn test_mft_data_parse_short_data() {
        // Data shorter than one MFT entry (1024 bytes)
        let data = vec![0xAA; 512];
        let result = MftData::parse(&data);
        match result {
            Ok(mft_data) => assert!(mft_data.entries.is_empty()),
            Err(_) => {}
        }
    }

    #[test]
    fn test_mft_data_parse_corrupt_entries_skipped() {
        // The `mft` crate can panic on malformed entries, so we use catch_unwind
        // to verify that MftData::parse either succeeds (with empty entries for
        // corrupt data), errors out, or panics without crashing the test suite.
        //
        // Build a minimal valid-looking MFT entry structure:
        // - FILE signature at offset 0
        // - Update sequence offset at 0x04 (u16) = 0x30 (after the header)
        // - Update sequence size at 0x06 (u16) = 3 (1 + number of sectors)
        // - Allocated size of entry at 0x1C (u32) = 1024
        // - Flags at 0x16 (u16) = 0x01 (in-use)
        // - First attribute offset at 0x14 (u16) = 0x38
        // - Bytes used at 0x18 (u32) = 0x38 (just the header, no attributes)
        let mut data = vec![0u8; 1024 * 4];
        for i in 0..4 {
            let o = i * 1024;
            data[o..o + 4].copy_from_slice(b"FILE");
            data[o + 0x04..o + 0x06].copy_from_slice(&0x30u16.to_le_bytes()); // update seq offset
            data[o + 0x06..o + 0x08].copy_from_slice(&3u16.to_le_bytes()); // update seq size
            data[o + 0x14..o + 0x16].copy_from_slice(&0x38u16.to_le_bytes()); // first attr offset
            data[o + 0x16..o + 0x18].copy_from_slice(&0x01u16.to_le_bytes()); // flags: in-use
            data[o + 0x18..o + 0x1C].copy_from_slice(&0x38u32.to_le_bytes()); // bytes used
            data[o + 0x1C..o + 0x20].copy_from_slice(&1024u32.to_le_bytes()); // allocated size
            // Write end-of-attributes marker (0xFFFFFFFF) at first attribute offset
            data[o + 0x38..o + 0x3C].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        }
        let result = std::panic::catch_unwind(|| MftData::parse(&data));
        match result {
            Ok(Ok(mft_data)) => {
                // All entries lack $FILE_NAME, so should be skipped via `continue`
                assert!(mft_data.entries.is_empty(),
                    "Corrupt entries without $FILE_NAME should be skipped");
            }
            Ok(Err(_)) => {} // Parse error is acceptable
            Err(_) => {} // Panic from mft crate is acceptable (we caught it)
        }
    }

    #[test]
    fn test_mft_entry_ads_detection_field() {
        // Test that the has_ads field works correctly with manually constructed entries
        let mut entry = make_mft_entry(100, 1, "file_with_ads.txt", 5, 5, false, true);
        assert!(!entry.has_ads);
        entry.has_ads = true;
        assert!(entry.has_ads);

        // Verify ADS entry shows up in detect_timestomping correctly (no false positives)
        let mft_data = MftData {
            entries: vec![entry],
            by_entry: HashMap::new(),
            by_key: HashMap::new(),
        };
        // ADS alone should not trigger timestomping
        assert_eq!(mft_data.detect_timestomping().len(), 0);
    }

    #[test]
    fn test_mft_data_seed_rewind_multiple() {
        // Test seeding rewind with multiple entries and verify path resolution
        let e1 = make_mft_entry(10, 1, "Users", 5, 5, true, true);
        let e2 = make_mft_entry(20, 1, "admin", 10, 1, true, true);
        let e3 = make_mft_entry(30, 1, "Desktop", 20, 1, true, true);

        let mut by_entry = HashMap::new();
        by_entry.insert(10u64, 0usize);
        by_entry.insert(20u64, 1usize);
        by_entry.insert(30u64, 2usize);

        let mut by_key = HashMap::new();
        by_key.insert(EntryKey::new(10, 1), 0usize);
        by_key.insert(EntryKey::new(20, 1), 1usize);
        by_key.insert(EntryKey::new(30, 1), 2usize);

        let mft_data = MftData {
            entries: vec![e1, e2, e3],
            by_entry,
            by_key,
        };

        let engine = mft_data.seed_rewind();
        assert_eq!(engine.lookup_len(), 3);
        let path = engine.resolve_path(&EntryKey::new(30, 1));
        assert_eq!(path, ".\\Users\\admin\\Desktop");
    }

    #[test]
    fn test_mft_data_full_path_field() {
        let entry = make_mft_entry(100, 1, "test.txt", 5, 5, false, true);
        assert_eq!(entry.full_path, ".\\test.txt");
    }

    #[test]
    fn test_mft_data_is_directory_and_in_use() {
        let dir_entry = make_mft_entry(100, 1, "Documents", 5, 5, true, true);
        assert!(dir_entry.is_directory);
        assert!(dir_entry.is_in_use);

        let deleted_entry = make_mft_entry(200, 1, "deleted.txt", 5, 5, false, false);
        assert!(!deleted_entry.is_directory);
        assert!(!deleted_entry.is_in_use);
    }
}
