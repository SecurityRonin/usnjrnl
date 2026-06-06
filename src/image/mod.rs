//! Disk image format detection and NTFS artifact extraction.
//!
//! Supports opening E01 (Expert Witness Format) disk images and extracting
//! NTFS forensic artifacts: $MFT, $UsnJrnl:$J, $LogFile, and $MFTMirr.

pub mod unallocated;

use anyhow::{bail, Result};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

#[allow(unused_imports)]
use log::info;

/// Supported disk image formats.
#[derive(Debug, PartialEq, Clone)]
pub enum ImageFormat {
    /// Expert Witness Format (E01/EWF)
    Ewf,
    /// Raw disk image (dd)
    Raw,
}

/// EWF file signature: "EVF\x09\x0d\x0a\xff\x00"
const EWF_SIGNATURE: [u8; 8] = [0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00];

/// MBR boot signature at offset 510-511.
const MBR_SIGNATURE: [u8; 2] = [0x55, 0xAA];

/// NTFS OEM ID at VBR offset 3.
const NTFS_OEM_ID: &[u8; 8] = b"NTFS    ";

/// MBR partition type for NTFS / HPFS / exFAT.
const PARTITION_TYPE_NTFS: u8 = 0x07;

/// MBR partition type for GPT protective MBR.
const PARTITION_TYPE_GPT: u8 = 0xEE;

/// GPT header signature.
const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";

/// Microsoft Basic Data partition type GUID (mixed-endian bytes).
const GUID_BASIC_DATA: [u8; 16] = [
    0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7,
];

/// Sector size in bytes.
const SECTOR_SIZE: u64 = 512;

/// A discovered partition on disk.
#[derive(Debug, Clone, PartialEq)]
pub struct PartitionEntry {
    /// Partition type byte (MBR) or 0x07 for NTFS-detected GPT partitions.
    pub partition_type: u8,
    /// Byte offset of partition start on disk.
    pub offset: u64,
    /// Size of partition in bytes.
    pub size: u64,
}

/// Paths to extracted NTFS artifacts.
#[derive(Debug)]
pub struct ExtractedArtifacts {
    pub mft: PathBuf,
    pub usnjrnl: PathBuf,
    pub logfile: PathBuf,
    pub mftmirr: PathBuf,
}

impl ImageFormat {
    /// Detect the disk image format by reading magic bytes from the file.
    pub fn detect(path: &Path) -> Result<Self> {
        let mut file = File::open(path)?;
        let mut buf = [0u8; 8];
        file.read_exact(&mut buf)?;

        if buf == EWF_SIGNATURE {
            Ok(ImageFormat::Ewf)
        } else {
            Ok(ImageFormat::Raw)
        }
    }
}

/// Parse MBR partition table entries from the first 512 bytes.
/// Returns all partitions with type != 0 (empty).
pub fn parse_mbr_partitions<R: Read + Seek>(reader: &mut R) -> Result<Vec<PartitionEntry>> {
    reader.seek(SeekFrom::Start(0))?;
    let mut mbr = [0u8; 512];
    reader.read_exact(&mut mbr)?;

    // Verify MBR signature
    if mbr[510] != MBR_SIGNATURE[0] || mbr[511] != MBR_SIGNATURE[1] {
        bail!("Invalid MBR signature");
    }

    let mut partitions = Vec::new();

    // Four 16-byte partition entries starting at offset 446
    for i in 0..4 {
        let base = 446 + i * 16;
        let ptype = mbr[base + 4];
        if ptype == 0 {
            continue;
        }

        let start_lba =
            u32::from_le_bytes([mbr[base + 8], mbr[base + 9], mbr[base + 10], mbr[base + 11]]);
        let size_sectors = u32::from_le_bytes([
            mbr[base + 12],
            mbr[base + 13],
            mbr[base + 14],
            mbr[base + 15],
        ]);

        partitions.push(PartitionEntry {
            partition_type: ptype,
            offset: start_lba as u64 * SECTOR_SIZE,
            size: size_sectors as u64 * SECTOR_SIZE,
        });
    }

    Ok(partitions)
}

/// Parse GPT partition table entries.
/// Reads the GPT header at LBA 1, then reads all partition entries.
pub fn parse_gpt_partitions<R: Read + Seek>(reader: &mut R) -> Result<Vec<PartitionEntry>> {
    // Read GPT header at LBA 1 (offset 512)
    reader.seek(SeekFrom::Start(512))?;
    let mut header = [0u8; 92];
    reader.read_exact(&mut header)?;

    // Verify GPT signature
    if &header[0..8] != GPT_SIGNATURE {
        bail!("Invalid GPT signature");
    }

    let entry_start_lba = u64::from_le_bytes(header[72..80].try_into().unwrap());
    let num_entries = u32::from_le_bytes(header[80..84].try_into().unwrap());
    let entry_size = u32::from_le_bytes(header[84..88].try_into().unwrap());

    if entry_size < 128 || num_entries > 1024 {
        bail!("Invalid GPT entry parameters: size={entry_size}, count={num_entries}");
    }

    // Read all partition entries
    let entries_offset = entry_start_lba * SECTOR_SIZE;
    reader.seek(SeekFrom::Start(entries_offset))?;

    let mut partitions = Vec::new();

    for _ in 0..num_entries {
        let mut entry = vec![0u8; entry_size as usize];
        reader.read_exact(&mut entry)?;

        // Skip empty entries (type GUID all zeros)
        if entry[0..16].iter().all(|&b| b == 0) {
            continue;
        }

        let start_lba = u64::from_le_bytes(entry[32..40].try_into().unwrap());
        let end_lba = u64::from_le_bytes(entry[40..48].try_into().unwrap());

        if end_lba < start_lba {
            continue;
        }

        let size = (end_lba - start_lba + 1) * SECTOR_SIZE;

        // Map GPT type GUID to MBR-style type byte for compatibility
        let partition_type = if entry[0..16] == GUID_BASIC_DATA {
            PARTITION_TYPE_NTFS // Could be NTFS or exFAT; we'll verify with OEM ID
        } else {
            0xFF // Unknown GPT type
        };

        partitions.push(PartitionEntry {
            partition_type,
            offset: start_lba * SECTOR_SIZE,
            size,
        });
    }

    Ok(partitions)
}

/// Check if an NTFS volume boot record starts at the given offset.
pub fn is_ntfs_at<R: Read + Seek>(reader: &mut R, offset: u64) -> Result<bool> {
    reader.seek(SeekFrom::Start(offset + 3))?;
    let mut oem_id = [0u8; 8];
    reader.read_exact(&mut oem_id)?;
    Ok(&oem_id == NTFS_OEM_ID)
}

/// Find the byte offset and size of the first NTFS partition.
/// Tries: direct NTFS at offset 0, then GPT, then MBR.
pub fn find_ntfs_partition<R: Read + Seek>(reader: &mut R) -> Result<PartitionEntry> {
    // Try direct NTFS at offset 0 (partition image, no partition table)
    if is_ntfs_at(reader, 0).unwrap_or(false) {
        let size = reader.seek(SeekFrom::End(0))?;
        return Ok(PartitionEntry {
            partition_type: PARTITION_TYPE_NTFS,
            offset: 0,
            size,
        });
    }

    // Check if MBR has GPT protective entry (type 0xEE)
    if let Ok(mbr_parts) = parse_mbr_partitions(reader) {
        let is_gpt = mbr_parts
            .iter()
            .any(|p| p.partition_type == PARTITION_TYPE_GPT);

        if is_gpt {
            // Parse GPT and find NTFS partition
            if let Ok(gpt_parts) = parse_gpt_partitions(reader) {
                // First pass: check Basic Data partitions for NTFS OEM ID
                for part in &gpt_parts {
                    if is_ntfs_at(reader, part.offset).unwrap_or(false) {
                        return Ok(PartitionEntry {
                            partition_type: PARTITION_TYPE_NTFS,
                            offset: part.offset,
                            size: part.size,
                        });
                    }
                }
            }
        } else {
            // Pure MBR: check type 0x07 partitions first
            for part in &mbr_parts {
                if part.partition_type == PARTITION_TYPE_NTFS
                    && is_ntfs_at(reader, part.offset).unwrap_or(false)
                {
                    return Ok(part.clone());
                }
            }
            // Fallback: check all partitions for NTFS signature
            for part in &mbr_parts {
                if is_ntfs_at(reader, part.offset).unwrap_or(false) {
                    return Ok(PartitionEntry {
                        partition_type: PARTITION_TYPE_NTFS,
                        offset: part.offset,
                        size: part.size,
                    });
                }
            }
        }
    }

    bail!("No NTFS partition found in disk image")
}

/// Extract NTFS artifacts ($MFT, $MFTMirr, $LogFile, $UsnJrnl:$J) from an EWF
/// disk image into `output_dir`, via the self-owned ntfs-forensic reader.
#[cfg(feature = "image")]
pub fn extract_artifacts(image_path: &Path, output_dir: &Path) -> Result<ExtractedArtifacts> {
    info!("Opening disk image: {}", image_path.display());
    let reader = ewf::EwfReader::open(image_path)
        .map_err(|e| anyhow::anyhow!("Failed to open EWF image: {e}"))?;
    extract_artifacts_from_reader(reader, output_dir)
}

/// Extract the artifacts from any `Read + Seek` disk image — the testable core.
#[cfg(feature = "image")]
pub fn extract_artifacts_from_reader<R: Read + Seek>(
    mut reader: R,
    output_dir: &Path,
) -> Result<ExtractedArtifacts> {
    use std::io::Write;

    std::fs::create_dir_all(output_dir)?;

    let partition = find_ntfs_partition(&mut reader)?;
    info!(
        "NTFS partition at offset {} ({:.1} MB)",
        partition.offset,
        partition.size as f64 / 1_048_576.0
    );

    // Re-base the volume to offset 0 (bounded to the partition) and open it.
    let part = ntfs_forensic::OffsetReader::new(reader, partition.offset, partition.size)
        .map_err(|e| anyhow::anyhow!("partition window: {e}"))?;
    let mut fs =
        ntfs_forensic::NtfsFs::open(part).map_err(|e| anyhow::anyhow!("open NTFS volume: {e}"))?;

    let write_artifact = |name: &str, bytes: &[u8]| -> Result<PathBuf> {
        let path = output_dir.join(name);
        File::create(&path)?.write_all(bytes)?;
        info!("Extracted {name} ({} bytes)", bytes.len());
        Ok(path)
    };

    let mft = write_artifact(
        "$MFT",
        &fs.read_file(r"\$MFT")
            .map_err(|e| anyhow::anyhow!("read $MFT: {e}"))?,
    )?;
    let mftmirr = write_artifact(
        "$MFTMirr",
        &fs.read_file(r"\$MFTMirr")
            .map_err(|e| anyhow::anyhow!("read $MFTMirr: {e}"))?,
    )?;
    let logfile = write_artifact(
        "$LogFile",
        &fs.read_file(r"\$LogFile")
            .map_err(|e| anyhow::anyhow!("read $LogFile: {e}"))?,
    )?;
    // The USN change journal is the named $DATA stream $UsnJrnl:$J.
    let usnjrnl = write_artifact(
        "$UsnJrnl_$J",
        &fs.read_named_stream(r"\$Extend\$UsnJrnl", "$J")
            .map_err(|e| anyhow::anyhow!("read $UsnJrnl:$J: {e}"))?,
    )?;

    Ok(ExtractedArtifacts {
        mft,
        mftmirr,
        logfile,
        usnjrnl,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use tempfile::NamedTempFile;

    // --- Format detection tests ---

    #[test]
    fn detect_ewf_format_from_magic_bytes() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&EWF_SIGNATURE).unwrap();
        file.flush().unwrap();

        let format = ImageFormat::detect(file.path()).unwrap();
        assert_eq!(format, ImageFormat::Ewf);
    }

    #[test]
    fn detect_raw_format_for_non_ewf_files() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&[0x00; 512]).unwrap();
        file.flush().unwrap();

        let format = ImageFormat::detect(file.path()).unwrap();
        assert_eq!(format, ImageFormat::Raw);
    }

    #[test]
    fn detect_format_returns_error_for_nonexistent_file() {
        let result = ImageFormat::detect(Path::new("/nonexistent/file.E01"));
        assert!(result.is_err());
    }

    // --- MBR partition parsing tests ---

    fn build_mbr_with_ntfs_partition(start_lba: u32, size_sectors: u32) -> Vec<u8> {
        let mut mbr = vec![0u8; 512];
        mbr[446] = 0x80; // Active
        mbr[446 + 4] = PARTITION_TYPE_NTFS;
        mbr[446 + 8..446 + 12].copy_from_slice(&start_lba.to_le_bytes());
        mbr[446 + 12..446 + 16].copy_from_slice(&size_sectors.to_le_bytes());
        mbr[510] = 0x55;
        mbr[511] = 0xAA;
        mbr
    }

    #[test]
    fn parse_mbr_finds_ntfs_partition() {
        let mbr = build_mbr_with_ntfs_partition(2048, 1_048_576);
        let mut cursor = Cursor::new(mbr);

        let partitions = parse_mbr_partitions(&mut cursor).unwrap();
        assert_eq!(partitions.len(), 1);
        assert_eq!(partitions[0].partition_type, PARTITION_TYPE_NTFS);
        assert_eq!(partitions[0].offset, 2048 * 512);
        assert_eq!(partitions[0].size, 1_048_576 * 512);
    }

    #[test]
    fn parse_mbr_skips_empty_entries() {
        let mut mbr = vec![0u8; 512];
        mbr[510] = 0x55;
        mbr[511] = 0xAA;
        let mut cursor = Cursor::new(mbr);

        let partitions = parse_mbr_partitions(&mut cursor).unwrap();
        assert_eq!(partitions.len(), 0);
    }

    #[test]
    fn parse_mbr_rejects_invalid_signature() {
        let mbr = vec![0u8; 512];
        let mut cursor = Cursor::new(mbr);

        let result = parse_mbr_partitions(&mut cursor);
        assert!(result.is_err());
    }

    #[test]
    fn parse_mbr_finds_multiple_partitions() {
        let mut mbr = vec![0u8; 512];
        mbr[446 + 4] = PARTITION_TYPE_NTFS;
        mbr[446 + 8..446 + 12].copy_from_slice(&2048u32.to_le_bytes());
        mbr[446 + 12..446 + 16].copy_from_slice(&500_000u32.to_le_bytes());
        mbr[462 + 4] = 0x0C; // FAT32
        mbr[462 + 8..462 + 12].copy_from_slice(&502_048u32.to_le_bytes());
        mbr[462 + 12..462 + 16].copy_from_slice(&200_000u32.to_le_bytes());
        mbr[510] = 0x55;
        mbr[511] = 0xAA;
        let mut cursor = Cursor::new(mbr);

        let partitions = parse_mbr_partitions(&mut cursor).unwrap();
        assert_eq!(partitions.len(), 2);
        assert_eq!(partitions[0].partition_type, PARTITION_TYPE_NTFS);
        assert_eq!(partitions[1].partition_type, 0x0C);
    }

    // --- GPT partition parsing tests ---

    /// Build a synthetic GPT disk image with one Basic Data partition.
    fn build_gpt_disk(ntfs_start_lba: u64, ntfs_end_lba: u64) -> Vec<u8> {
        // Need enough space: MBR + GPT header + entries + partition start + NTFS VBR
        let total_size = ((ntfs_start_lba + 1) * SECTOR_SIZE + 512) as usize;
        let mut disk = vec![0u8; total_size];

        // Protective MBR at LBA 0
        disk[446 + 4] = PARTITION_TYPE_GPT; // 0xEE
        disk[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes()); // start LBA 1
        disk[446 + 12..446 + 16].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        disk[510] = 0x55;
        disk[511] = 0xAA;

        // GPT header at LBA 1 (offset 512)
        let gpt_offset = 512;
        disk[gpt_offset..gpt_offset + 8].copy_from_slice(GPT_SIGNATURE);
        // Partition entries at LBA 2
        disk[gpt_offset + 72..gpt_offset + 80].copy_from_slice(&2u64.to_le_bytes());
        // 1 partition entry
        disk[gpt_offset + 80..gpt_offset + 84].copy_from_slice(&1u32.to_le_bytes());
        // Entry size 128
        disk[gpt_offset + 84..gpt_offset + 88].copy_from_slice(&128u32.to_le_bytes());

        // GPT partition entry at LBA 2 (offset 1024)
        let entry_offset = 1024;
        // Type GUID: Microsoft Basic Data
        disk[entry_offset..entry_offset + 16].copy_from_slice(&GUID_BASIC_DATA);
        // Start LBA
        disk[entry_offset + 32..entry_offset + 40].copy_from_slice(&ntfs_start_lba.to_le_bytes());
        // End LBA
        disk[entry_offset + 40..entry_offset + 48].copy_from_slice(&ntfs_end_lba.to_le_bytes());

        // NTFS OEM ID at partition start
        let part_byte_offset = (ntfs_start_lba * SECTOR_SIZE) as usize;
        if part_byte_offset + 11 < disk.len() {
            disk[part_byte_offset + 3..part_byte_offset + 11].copy_from_slice(NTFS_OEM_ID);
        }

        disk
    }

    #[test]
    fn parse_gpt_finds_basic_data_partition() {
        let disk = build_gpt_disk(2048, 1_000_000);
        let mut cursor = Cursor::new(disk);

        let partitions = parse_gpt_partitions(&mut cursor).unwrap();
        assert_eq!(partitions.len(), 1);
        assert_eq!(partitions[0].offset, 2048 * SECTOR_SIZE);
        assert_eq!(partitions[0].size, (1_000_000 - 2048 + 1) * SECTOR_SIZE);
    }

    #[test]
    fn parse_gpt_rejects_invalid_signature() {
        let disk = vec![0u8; 2048];
        // No "EFI PART" at offset 512
        let mut cursor = Cursor::new(disk);

        let result = parse_gpt_partitions(&mut cursor);
        assert!(result.is_err());
    }

    #[test]
    fn find_ntfs_partition_via_gpt() {
        let disk = build_gpt_disk(2048, 1_000_000);
        let mut cursor = Cursor::new(disk);

        let part = find_ntfs_partition(&mut cursor).unwrap();
        assert_eq!(part.offset, 2048 * SECTOR_SIZE);
        assert_eq!(part.partition_type, PARTITION_TYPE_NTFS);
    }

    #[test]
    fn parse_gpt_rejects_bad_entry_params() {
        // entry_size < 128 must be rejected.
        let mut disk = build_gpt_disk(2048, 1_000_000);
        disk[512 + 84..512 + 88].copy_from_slice(&64u32.to_le_bytes());
        let mut cursor = Cursor::new(disk);
        assert!(parse_gpt_partitions(&mut cursor).is_err());
    }

    /// Build a GPT disk with three entries: empty, end<start, and unknown-type.
    fn build_gpt_disk_three_entries() -> Vec<u8> {
        let entry_size = 128usize;
        let gpt_offset = 512usize;
        let entries_lba = 2u64;
        let mut disk = vec![0u8; 8192];
        // Protective MBR
        disk[446 + 4] = PARTITION_TYPE_GPT;
        disk[510] = 0x55;
        disk[511] = 0xAA;
        // GPT header
        disk[gpt_offset..gpt_offset + 8].copy_from_slice(GPT_SIGNATURE);
        disk[gpt_offset + 72..gpt_offset + 80].copy_from_slice(&entries_lba.to_le_bytes());
        disk[gpt_offset + 80..gpt_offset + 84].copy_from_slice(&3u32.to_le_bytes());
        disk[gpt_offset + 84..gpt_offset + 88].copy_from_slice(&(entry_size as u32).to_le_bytes());
        let eoff = (entries_lba as usize) * 512;
        // entry 0: all-zero GUID -> skipped
        // entry 1: non-zero GUID, end_lba < start_lba -> skipped
        let e1 = eoff + entry_size;
        disk[e1] = 0x11;
        disk[e1 + 32..e1 + 40].copy_from_slice(&100u64.to_le_bytes());
        disk[e1 + 40..e1 + 48].copy_from_slice(&50u64.to_le_bytes());
        // entry 2: non-zero, non-Basic-Data GUID -> type 0xFF
        let e2 = eoff + 2 * entry_size;
        disk[e2] = 0x22;
        disk[e2 + 32..e2 + 40].copy_from_slice(&10u64.to_le_bytes());
        disk[e2 + 40..e2 + 48].copy_from_slice(&20u64.to_le_bytes());
        disk
    }

    #[test]
    fn parse_gpt_skips_empty_and_invalid_entries() {
        let mut cursor = Cursor::new(build_gpt_disk_three_entries());
        let parts = parse_gpt_partitions(&mut cursor).unwrap();
        // entry 0 (empty) and entry 1 (end<start) skipped; entry 2 -> unknown type.
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].partition_type, 0xFF);
    }

    #[test]
    fn find_ntfs_gpt_no_ntfs_partition_bails() {
        // GPT partition present but its boot record lacks the NTFS OEM id, so the
        // is_ntfs_at check is false (loop falls through) and the search bails.
        let mut disk = build_gpt_disk(2048, 1_000_000);
        let off = (2048 * SECTOR_SIZE) as usize;
        disk[off + 3..off + 11].copy_from_slice(&[0u8; 8]);
        let mut cursor = Cursor::new(disk);
        assert!(find_ntfs_partition(&mut cursor).is_err());
    }

    #[test]
    fn find_ntfs_via_mbr_type_07() {
        // Pure MBR with a type-0x07 partition whose boot record has the NTFS OEM.
        let start_lba = 4u32;
        let mut disk = build_mbr_with_ntfs_partition(start_lba, 1000);
        let off = start_lba as usize * 512;
        disk.resize(off + 512, 0);
        disk[off + 3..off + 11].copy_from_slice(NTFS_OEM_ID);
        let mut cursor = Cursor::new(disk);
        let part = find_ntfs_partition(&mut cursor).unwrap();
        assert_eq!(part.offset, off as u64);
    }

    #[test]
    fn find_ntfs_via_mbr_fallback_non_07_type() {
        // MBR partition tagged FAT32 (0x0C) but holding an NTFS volume: the
        // type-0x07 pass misses it and the fallback signature scan finds it.
        let start_lba = 4u32;
        let off = start_lba as usize * 512;
        let mut disk = vec![0u8; off + 512];
        disk[446 + 4] = 0x0C;
        disk[446 + 8..446 + 12].copy_from_slice(&start_lba.to_le_bytes());
        disk[446 + 12..446 + 16].copy_from_slice(&1000u32.to_le_bytes());
        disk[510] = 0x55;
        disk[511] = 0xAA;
        disk[off + 3..off + 11].copy_from_slice(NTFS_OEM_ID);
        let mut cursor = Cursor::new(disk);
        let part = find_ntfs_partition(&mut cursor).unwrap();
        assert_eq!(part.offset, off as u64);
    }

    #[test]
    fn find_ntfs_pure_mbr_no_ntfs_bails() {
        // A non-NTFS MBR partition with no NTFS OEM anywhere: both MBR passes fall
        // through and the search bails.
        let mut disk = vec![0u8; 4096];
        disk[446 + 4] = 0x0C; // FAT32
        disk[446 + 8..446 + 12].copy_from_slice(&4u32.to_le_bytes());
        disk[446 + 12..446 + 16].copy_from_slice(&1u32.to_le_bytes());
        disk[510] = 0x55;
        disk[511] = 0xAA;
        let mut cursor = Cursor::new(disk);
        assert!(find_ntfs_partition(&mut cursor).is_err());
    }

    #[test]
    fn find_ntfs_gpt_protective_but_invalid_gpt_bails() {
        // Protective MBR (0xEE) but no valid GPT header: parse_gpt errors, the
        // if-let-Ok falls through, and the search bails.
        let mut disk = vec![0u8; 4096];
        disk[446 + 4] = PARTITION_TYPE_GPT;
        disk[510] = 0x55;
        disk[511] = 0xAA;
        let mut cursor = Cursor::new(disk);
        assert!(find_ntfs_partition(&mut cursor).is_err());
    }

    // --- NTFS detection tests ---

    #[test]
    fn is_ntfs_at_detects_ntfs_boot_sector() {
        let mut data = vec![0u8; 512];
        data[3..11].copy_from_slice(NTFS_OEM_ID);
        let mut cursor = Cursor::new(data);

        assert!(is_ntfs_at(&mut cursor, 0).unwrap());
    }

    #[test]
    fn is_ntfs_at_rejects_non_ntfs() {
        let data = vec![0u8; 512];
        let mut cursor = Cursor::new(data);

        assert!(!is_ntfs_at(&mut cursor, 0).unwrap());
    }

    #[test]
    fn is_ntfs_at_checks_correct_offset() {
        let partition_offset: u64 = 1_048_576;
        let total_size = partition_offset + 512;
        let mut data = vec![0u8; total_size as usize];
        data[(partition_offset + 3) as usize..(partition_offset + 11) as usize]
            .copy_from_slice(NTFS_OEM_ID);
        let mut cursor = Cursor::new(data);

        assert!(!is_ntfs_at(&mut cursor, 0).unwrap());
        assert!(is_ntfs_at(&mut cursor, partition_offset).unwrap());
    }

    // --- find_ntfs_partition tests ---

    #[test]
    fn find_ntfs_partition_direct_ntfs_image() {
        let mut data = vec![0u8; 4096];
        data[3..11].copy_from_slice(NTFS_OEM_ID);
        let mut cursor = Cursor::new(data);

        let part = find_ntfs_partition(&mut cursor).unwrap();
        assert_eq!(part.offset, 0);
        assert_eq!(part.size, 4096);
    }

    #[test]
    fn find_ntfs_partition_via_mbr() {
        let start_lba: u32 = 2048;
        let size_sectors: u32 = 100_000;
        let partition_offset = start_lba as u64 * SECTOR_SIZE;

        let total = partition_offset + 512;
        let mut data = vec![0u8; total as usize];

        let mbr = build_mbr_with_ntfs_partition(start_lba, size_sectors);
        data[..512].copy_from_slice(&mbr);
        data[(partition_offset + 3) as usize..(partition_offset + 11) as usize]
            .copy_from_slice(NTFS_OEM_ID);

        let mut cursor = Cursor::new(data);
        let part = find_ntfs_partition(&mut cursor).unwrap();
        assert_eq!(part.offset, partition_offset);
        assert_eq!(part.size, size_sectors as u64 * SECTOR_SIZE);
    }

    #[test]
    fn find_ntfs_partition_fails_when_no_ntfs() {
        let mut data = vec![0u8; 512];
        data[510] = 0x55;
        data[511] = 0xAA;
        let mut cursor = Cursor::new(data);

        let result = find_ntfs_partition(&mut cursor);
        assert!(result.is_err());
    }
}
