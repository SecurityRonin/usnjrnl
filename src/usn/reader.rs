use std::io::{Read, Seek, SeekFrom};

use anyhow::Result;

use super::record::{UsnRecord, parse_usn_record_v2, parse_usn_record_v3};
use super::reason::UsnReason;

const BUF_SIZE: usize = 64 * 1024; // 64KB read buffer

/// Streaming iterator over USN records from a reader.
///
/// For multi-GB journals where loading everything into memory is impractical.
pub struct UsnJournalReader<R: Read + Seek> {
    reader: R,
    buf: Vec<u8>,
    buf_len: usize,
    buf_offset: usize,
    stream_pos: u64,
    total_size: u64,
    done: bool,
}

impl<R: Read + Seek> UsnJournalReader<R> {
    pub fn new(mut reader: R) -> Result<Self> {
        let total_size = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(0))?;

        Ok(Self {
            reader,
            buf: vec![0u8; BUF_SIZE],
            buf_len: 0,
            buf_offset: 0,
            stream_pos: 0,
            total_size,
            done: false,
        })
    }

    fn fill_buffer(&mut self) -> Result<bool> {
        if self.stream_pos >= self.total_size {
            self.done = true;
            return Ok(false);
        }

        // Move unconsumed data to front
        if self.buf_offset > 0 && self.buf_offset < self.buf_len {
            let remaining = self.buf_len - self.buf_offset;
            self.buf.copy_within(self.buf_offset..self.buf_len, 0);
            self.buf_len = remaining;
        } else {
            self.buf_len = 0;
        }
        self.buf_offset = 0;

        // Read more data
        let space = BUF_SIZE - self.buf_len;
        if space > 0 {
            let n = self.reader.read(&mut self.buf[self.buf_len..self.buf_len + space])?;
            if n == 0 {
                self.done = true;
                return Ok(self.buf_len > 0);
            }
            self.buf_len += n;
            self.stream_pos += n as u64;
        }

        Ok(true)
    }

    fn skip_zeros(&mut self) -> Result<bool> {
        loop {
            while self.buf_offset + 8 <= self.buf_len {
                let chunk = &self.buf[self.buf_offset..self.buf_offset + 8];
                if chunk != [0, 0, 0, 0, 0, 0, 0, 0] {
                    return Ok(true);
                }
                self.buf_offset += 8;
            }
            if !self.fill_buffer()? {
                return Ok(false);
            }
            if self.buf_len == 0 {
                return Ok(false);
            }
        }
    }
}

impl<R: Read + Seek> Iterator for UsnJournalReader<R> {
    type Item = Result<UsnRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        // Ensure we have data
        if self.buf_offset >= self.buf_len {
            match self.fill_buffer() {
                Ok(true) => {}
                Ok(false) => return None,
                Err(e) => return Some(Err(e)),
            }
        }

        // Skip zero-filled regions
        match self.skip_zeros() {
            Ok(true) => {}
            Ok(false) => return None,
            Err(e) => return Some(Err(e)),
        }

        // Need at least 8 bytes for record length + version
        if self.buf_offset + 8 > self.buf_len {
            match self.fill_buffer() {
                Ok(true) if self.buf_offset + 8 <= self.buf_len => {}
                _ => return None,
            }
        }

        let record_len = u32::from_le_bytes([
            self.buf[self.buf_offset],
            self.buf[self.buf_offset + 1],
            self.buf[self.buf_offset + 2],
            self.buf[self.buf_offset + 3],
        ]) as usize;

        if record_len < 8 || record_len > 65536 {
            self.buf_offset += 8;
            return self.next();
        }

        // Ensure we have the full record in buffer
        if self.buf_offset + record_len > self.buf_len {
            match self.fill_buffer() {
                Ok(true) if self.buf_offset + record_len <= self.buf_len => {}
                _ => {
                    self.buf_offset += 8;
                    return self.next();
                }
            }
        }

        let version = u16::from_le_bytes([
            self.buf[self.buf_offset + 4],
            self.buf[self.buf_offset + 5],
        ]);

        let record_data = &self.buf[self.buf_offset..self.buf_offset + record_len];
        let aligned = (record_len + 7) & !7;
        self.buf_offset += aligned;

        match version {
            2 => {
                match parse_usn_record_v2(record_data) {
                    Ok(r) if r.reason == UsnReason::CLOSE => self.next(),
                    Ok(r) => Some(Ok(r)),
                    Err(_) => self.next(),
                }
            }
            3 => {
                match parse_usn_record_v3(record_data) {
                    Ok(r) if r.reason == UsnReason::CLOSE => self.next(),
                    Ok(r) => Some(Ok(r)),
                    Err(_) => self.next(),
                }
            }
            _ => self.next(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn build_v2_record_bytes(entry: u64, seq: u16, parent: u64, parent_seq: u16, reason: u32, name: &str) -> Vec<u8> {
        let name_utf16: Vec<u16> = name.encode_utf16().collect();
        let name_bytes_len = name_utf16.len() * 2;
        let record_len = 0x3C + name_bytes_len;
        let aligned_len = (record_len + 7) & !7;
        let mut buf = vec![0u8; aligned_len];
        buf[0..4].copy_from_slice(&(record_len as u32).to_le_bytes());
        buf[4..6].copy_from_slice(&2u16.to_le_bytes());
        let file_ref = entry | ((seq as u64) << 48);
        buf[0x08..0x10].copy_from_slice(&file_ref.to_le_bytes());
        let parent_ref = parent | ((parent_seq as u64) << 48);
        buf[0x10..0x18].copy_from_slice(&parent_ref.to_le_bytes());
        buf[0x18..0x20].copy_from_slice(&100i64.to_le_bytes());
        let ts: i64 = 133500480000000000;
        buf[0x20..0x28].copy_from_slice(&ts.to_le_bytes());
        buf[0x28..0x2C].copy_from_slice(&reason.to_le_bytes());
        buf[0x34..0x38].copy_from_slice(&0x20u32.to_le_bytes());
        buf[0x38..0x3A].copy_from_slice(&(name_bytes_len as u16).to_le_bytes());
        buf[0x3A..0x3C].copy_from_slice(&0x3Cu16.to_le_bytes());
        for (i, &ch) in name_utf16.iter().enumerate() {
            let off = 0x3C + i * 2;
            buf[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }
        buf
    }

    #[test]
    fn test_streaming_reader_basic() {
        let r = build_v2_record_bytes(100, 1, 5, 5, 0x100, "test.txt");
        let cursor = Cursor::new(r);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(|r| r.ok()).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].filename, "test.txt");
    }

    #[test]
    fn test_streaming_reader_skips_zeros() {
        let mut data = vec![0u8; 4096];
        data.extend_from_slice(&build_v2_record_bytes(100, 1, 5, 5, 0x100, "found.txt"));
        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(|r| r.ok()).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].filename, "found.txt");
    }

    #[test]
    fn test_streaming_reader_multiple() {
        let mut data = Vec::new();
        data.extend_from_slice(&build_v2_record_bytes(100, 1, 5, 5, 0x100, "a.txt"));
        data.extend_from_slice(&build_v2_record_bytes(200, 1, 100, 1, 0x200, "b.txt"));
        data.extend_from_slice(&build_v2_record_bytes(300, 1, 100, 1, 0x100, "c.txt"));
        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(|r| r.ok()).collect();
        assert_eq!(records.len(), 3);
    }

    #[test]
    fn test_streaming_reader_empty_data() {
        let cursor = Cursor::new(Vec::<u8>::new());
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(|r| r.ok()).collect();
        assert_eq!(records.len(), 0);
    }

    #[test]
    fn test_streaming_reader_all_zeros() {
        let data = vec![0u8; 4096];
        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(|r| r.ok()).collect();
        assert_eq!(records.len(), 0);
    }

    #[test]
    fn test_streaming_reader_skips_close_only() {
        let data = build_v2_record_bytes(100, 1, 5, 5, 0x8000_0000, "closed.txt");
        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(|r| r.ok()).collect();
        assert_eq!(records.len(), 0);
    }

    #[test]
    fn test_streaming_reader_invalid_record_length() {
        // Record with invalid length (too small) should be skipped
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&3u32.to_le_bytes()); // length < 8
        data[4..6].copy_from_slice(&2u16.to_le_bytes());
        // Rest is zeros, reader will skip

        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(|r| r.ok()).collect();
        assert_eq!(records.len(), 0);
    }

    #[test]
    fn test_streaming_reader_invalid_then_valid() {
        let mut data = vec![0u8; 16]; // some garbage that looks non-zero
        data[0..4].copy_from_slice(&5u32.to_le_bytes()); // invalid length
        data[4..6].copy_from_slice(&99u16.to_le_bytes()); // invalid version
        // Pad to 8-byte boundary for skipping
        data.resize(16, 0);
        // Now add zeros then a valid record
        data.extend_from_slice(&vec![0u8; 64]);
        data.extend_from_slice(&build_v2_record_bytes(100, 1, 5, 5, 0x100, "valid.txt"));

        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(|r| r.ok()).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].filename, "valid.txt");
    }

    #[test]
    fn test_streaming_reader_unknown_version() {
        // Record with valid length but unknown version
        let mut data = vec![0u8; 0x40];
        data[0..4].copy_from_slice(&(0x40u32).to_le_bytes());
        data[4..6].copy_from_slice(&99u16.to_le_bytes()); // version 99

        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(|r| r.ok()).collect();
        assert_eq!(records.len(), 0);
    }

    fn build_v3_record_bytes(entry: u64, parent: u64, reason: u32, name: &str) -> Vec<u8> {
        let name_utf16: Vec<u16> = name.encode_utf16().collect();
        let name_bytes_len = name_utf16.len() * 2;
        let record_len = 0x4C + name_bytes_len;
        let aligned_len = (record_len + 7) & !7;
        let mut buf = vec![0u8; aligned_len];

        buf[0..4].copy_from_slice(&(record_len as u32).to_le_bytes());
        buf[4..6].copy_from_slice(&3u16.to_le_bytes());
        buf[6..8].copy_from_slice(&0u16.to_le_bytes());
        buf[0x08..0x18].copy_from_slice(&(entry as u128).to_le_bytes());
        buf[0x18..0x28].copy_from_slice(&(parent as u128).to_le_bytes());
        buf[0x28..0x30].copy_from_slice(&200i64.to_le_bytes());
        let ts: i64 = 133500480000000000;
        buf[0x30..0x38].copy_from_slice(&ts.to_le_bytes());
        buf[0x38..0x3C].copy_from_slice(&reason.to_le_bytes());
        buf[0x44..0x48].copy_from_slice(&0x20u32.to_le_bytes());
        buf[0x48..0x4A].copy_from_slice(&(name_bytes_len as u16).to_le_bytes());
        buf[0x4A..0x4C].copy_from_slice(&0x4Cu16.to_le_bytes());
        for (i, &ch) in name_utf16.iter().enumerate() {
            let off = 0x4C + i * 2;
            buf[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }
        buf
    }

    #[test]
    fn test_streaming_reader_v3_record() {
        let data = build_v3_record_bytes(100, 5, 0x100, "v3file.txt");
        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(|r| r.ok()).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].filename, "v3file.txt");
        assert_eq!(records[0].major_version, 3);
    }

    #[test]
    fn test_streaming_reader_v3_close_only_skipped() {
        let data = build_v3_record_bytes(100, 5, 0x8000_0000, "closed_v3.txt");
        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(|r| r.ok()).collect();
        assert_eq!(records.len(), 0);
    }

    #[test]
    fn test_streaming_reader_large_zero_gap() {
        // Large zero region followed by a valid record
        let mut data = vec![0u8; 128 * 1024]; // 128KB of zeros (larger than buffer)
        data.extend_from_slice(&build_v2_record_bytes(100, 1, 5, 5, 0x100, "deep.txt"));

        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(|r| r.ok()).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].filename, "deep.txt");
    }

    #[test]
    fn test_streaming_reader_record_larger_than_initial_buffer_fill() {
        // Record at offset 0 where the buffer needs to be filled
        let record = build_v2_record_bytes(42, 3, 5, 5, 0x100, "buffer_test.txt");
        let cursor = Cursor::new(record);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(|r| r.ok()).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].mft_entry, 42);
        assert_eq!(records[0].mft_sequence, 3);
    }

    #[test]
    fn test_streaming_reader_record_too_large() {
        // A record that claims to be 65537 bytes (> 65536 max) should be skipped
        let mut data = vec![0u8; 128];
        data[0..4].copy_from_slice(&(65537u32).to_le_bytes());
        data[4..6].copy_from_slice(&2u16.to_le_bytes());

        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(|r| r.ok()).collect();
        assert_eq!(records.len(), 0);
    }

    #[test]
    fn test_streaming_reader_mixed_v2_v3() {
        let mut data = Vec::new();
        data.extend_from_slice(&build_v2_record_bytes(100, 1, 5, 5, 0x100, "v2.txt"));
        data.extend_from_slice(&build_v3_record_bytes(200, 5, 0x200, "v3.txt"));
        data.extend_from_slice(&build_v2_record_bytes(300, 1, 5, 5, 0x100, "v2b.txt"));

        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(|r| r.ok()).collect();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].major_version, 2);
        assert_eq!(records[1].major_version, 3);
        assert_eq!(records[2].major_version, 2);
    }

    #[test]
    fn test_streaming_reader_fill_buffer_with_unconsumed_data() {
        // Create data that spans multiple buffer fills.
        // First, fill most of the 64KB buffer with valid records, then add
        // a record that straddles the buffer boundary.
        // This triggers the fill_buffer path where buf_offset > 0 && buf_offset < buf_len,
        // meaning unconsumed data needs to be moved to front of buffer.
        let mut data = Vec::new();
        let record_size;
        {
            let sample = build_v2_record_bytes(1, 1, 5, 5, 0x100, "sample.txt");
            record_size = sample.len();
        }

        // Fill just under 64KB with records, then add zeros, then another record
        // that will require a buffer refill with leftover data
        let num_records_to_fill = (BUF_SIZE - record_size) / record_size;
        for i in 0..num_records_to_fill {
            data.extend_from_slice(&build_v2_record_bytes(
                (i + 1) as u64, 1, 5, 5, 0x100,
                &format!("f{:04}.txt", i),
            ));
        }

        // Add a few zeros to push the next record across the buffer boundary
        let remaining = BUF_SIZE - (num_records_to_fill * record_size);
        if remaining > 0 && remaining < record_size {
            data.extend_from_slice(&vec![0u8; remaining]);
        }

        // Add more records after the boundary
        for i in 0..5 {
            data.extend_from_slice(&build_v2_record_bytes(
                (num_records_to_fill + i + 1) as u64, 1, 5, 5, 0x100,
                &format!("after{}.txt", i),
            ));
        }

        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(|r| r.ok()).collect();
        // Should find all records from both sides of the buffer boundary
        assert!(records.len() >= num_records_to_fill + 5,
            "Expected at least {} records, got {}", num_records_to_fill + 5, records.len());
    }

    #[test]
    fn test_streaming_reader_record_at_exact_buffer_boundary() {
        // Place records such that one record ends exactly at the buffer boundary
        // and the next starts exactly at the next fill.
        let sample = build_v2_record_bytes(1, 1, 5, 5, 0x100, "sample.txt");
        let record_size = sample.len();

        let mut data = Vec::new();
        // Calculate how many records fit exactly in the buffer
        let records_per_buffer = BUF_SIZE / record_size;
        let exact_fill = records_per_buffer * record_size;

        // Fill exactly to the buffer size
        for i in 0..records_per_buffer {
            data.extend_from_slice(&build_v2_record_bytes(
                (i + 1) as u64, 1, 5, 5, 0x100, "exact.txt",
            ));
        }

        // Pad to exactly BUF_SIZE if needed
        if exact_fill < BUF_SIZE {
            data.extend_from_slice(&vec![0u8; BUF_SIZE - exact_fill]);
        }

        // Add one more record that starts at the exact boundary
        data.extend_from_slice(&build_v2_record_bytes(
            (records_per_buffer + 1) as u64, 1, 5, 5, 0x100, "boundary.txt",
        ));

        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(|r| r.ok()).collect();
        // The last record "boundary.txt" should be found
        assert!(records.iter().any(|r| r.filename == "boundary.txt"),
            "Should find the record at the buffer boundary");
    }

    #[test]
    fn test_streaming_reader_record_straddles_buffer() {
        // Create data where a record starts in one buffer fill and extends
        // into the next fill. This tests the refill path where
        // buf_offset + record_len > buf_len triggers fill_buffer.
        let sample = build_v2_record_bytes(1, 1, 5, 5, 0x100, "sample.txt");
        let record_size = sample.len();

        let mut data = Vec::new();
        // Fill most of the buffer
        let records_to_fill = (BUF_SIZE / record_size) - 1;
        for i in 0..records_to_fill {
            data.extend_from_slice(&build_v2_record_bytes(
                (i + 1) as u64, 1, 5, 5, 0x100, "fill.txt",
            ));
        }

        let current_len = data.len();
        // Add zeros to position us near the end of the buffer
        // Leave less than record_size bytes before the boundary
        let padding = BUF_SIZE - current_len - (record_size / 2);
        if padding > 0 {
            data.extend_from_slice(&vec![0u8; padding]);
        }

        // Now add a record that will straddle the buffer boundary
        data.extend_from_slice(&build_v2_record_bytes(
            999, 1, 5, 5, 0x100, "straddle.txt",
        ));

        // Add trailing data
        data.extend_from_slice(&vec![0u8; 256]);

        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(|r| r.ok()).collect();
        // The straddling record should be found
        assert!(records.iter().any(|r| r.filename == "straddle.txt"),
            "Should find the record that straddles the buffer boundary");
    }

    #[test]
    fn test_streaming_reader_data_larger_than_buffer() {
        // Create data significantly larger than the 64KB buffer to ensure
        // multiple fill_buffer cycles work correctly
        let mut data = Vec::new();
        let total_records = 2000; // Each ~80 bytes = ~160KB > 64KB buffer
        for i in 0..total_records {
            data.extend_from_slice(&build_v2_record_bytes(
                (i + 1) as u64, 1, 5, 5, 0x100,
                &format!("r{:04}.txt", i),
            ));
        }

        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(|r| r.ok()).collect();
        assert_eq!(records.len(), total_records,
            "Should parse all {} records across multiple buffer fills", total_records);
    }
}
