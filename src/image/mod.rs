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

/// A `Read + Seek` wrapper that presents a sub-range of an inner reader as a
/// standalone stream. Seeks are offset by `base` and clamped to `size`.
#[cfg(feature = "image")]
struct PartitionReader<R> {
    inner: R,
    base: u64,
    size: u64,
    pos: u64,
}

#[cfg(feature = "image")]
impl<R: Read + Seek> PartitionReader<R> {
    fn new(mut inner: R, base: u64, size: u64) -> std::io::Result<Self> {
        inner.seek(SeekFrom::Start(base))?;
        Ok(Self {
            inner,
            base,
            size,
            pos: 0,
        })
    }
}

#[cfg(feature = "image")]
impl<R: Read + Seek> Read for PartitionReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self.size.saturating_sub(self.pos) as usize;
        if remaining == 0 {
            return Ok(0);
        }
        let to_read = buf.len().min(remaining);
        let n = self.inner.read(&mut buf[..to_read])?;
        self.pos += n as u64;
        Ok(n)
    }
}

#[cfg(feature = "image")]
impl<R: Read + Seek> Seek for PartitionReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(p) => p as i64,
            SeekFrom::End(p) => self.size as i64 + p,
            SeekFrom::Current(p) => self.pos as i64 + p,
        };
        if new_pos < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek to negative position",
            ));
        }
        let new_pos = (new_pos as u64).min(self.size);
        self.inner.seek(SeekFrom::Start(self.base + new_pos))?;
        self.pos = new_pos;
        Ok(self.pos)
    }
}

/// Extract NTFS artifacts ($MFT, $UsnJrnl:$J, $LogFile, $MFTMirr) from a disk image.
#[cfg(feature = "image")]
pub fn extract_artifacts(image_path: &Path, output_dir: &Path) -> Result<ExtractedArtifacts> {
    use anyhow::Context;
    use ntfs::Ntfs;

    std::fs::create_dir_all(output_dir)?;

    info!("Opening disk image: {}", image_path.display());
    let mut reader = ewf::EwfReader::open(image_path)
        .map_err(|e| anyhow::anyhow!("Failed to open EWF image: {}", e))?;
    info!(
        "EWF image: {:.2} GB, {} chunks",
        reader.total_size() as f64 / 1_073_741_824.0,
        reader.chunk_count(),
    );

    // Find NTFS partition
    let partition = find_ntfs_partition(&mut reader)?;
    info!(
        "Found NTFS partition at offset {} ({:.1} MB, {:.1} GB)",
        partition.offset,
        partition.offset as f64 / 1_048_576.0,
        partition.size as f64 / 1_073_741_824.0,
    );

    // Create a reader scoped to the NTFS partition
    let mut partition_reader = PartitionReader::new(reader, partition.offset, partition.size)?;

    // Initialize NTFS filesystem
    let mut ntfs = Ntfs::new(&mut partition_reader)?;
    ntfs.read_upcase_table(&mut partition_reader)?;
    info!(
        "NTFS filesystem initialized (cluster size: {})",
        ntfs.cluster_size()
    );

    // Extract $MFT (file record 0)
    let mft_path = output_dir.join("$MFT");
    extract_file_by_record(&ntfs, &mut partition_reader, 0, &mft_path)
        .context("Failed to extract $MFT")?;
    info!(
        "Extracted $MFT ({} bytes)",
        std::fs::metadata(&mft_path)?.len()
    );

    // Extract $MFTMirr (file record 1)
    let mftmirr_path = output_dir.join("$MFTMirr");
    extract_file_by_record(&ntfs, &mut partition_reader, 1, &mftmirr_path)
        .context("Failed to extract $MFTMirr")?;
    info!(
        "Extracted $MFTMirr ({} bytes)",
        std::fs::metadata(&mftmirr_path)?.len()
    );

    // Extract $LogFile (file record 2)
    let logfile_path = output_dir.join("$LogFile");
    extract_file_by_record(&ntfs, &mut partition_reader, 2, &logfile_path)
        .context("Failed to extract $LogFile")?;
    info!(
        "Extracted $LogFile ({} bytes)",
        std::fs::metadata(&logfile_path)?.len()
    );

    // Extract $UsnJrnl:$J (inside $Extend directory)
    let usnjrnl_path = output_dir.join("$UsnJrnl_$J");
    extract_usnjrnl(&ntfs, &mut partition_reader, &usnjrnl_path)
        .context("Failed to extract $UsnJrnl:$J")?;
    info!(
        "Extracted $UsnJrnl:$J ({} bytes)",
        std::fs::metadata(&usnjrnl_path)?.len()
    );

    Ok(ExtractedArtifacts {
        mft: mft_path,
        mftmirr: mftmirr_path,
        logfile: logfile_path,
        usnjrnl: usnjrnl_path,
    })
}

/// Extract a file's default $DATA stream by its MFT record number.
#[cfg(feature = "image")]
fn extract_file_by_record<T: Read + Seek>(
    ntfs: &ntfs::Ntfs,
    fs: &mut T,
    record_number: u64,
    output_path: &Path,
) -> Result<()> {
    use ntfs::NtfsReadSeek;
    use std::io::Write;

    let file = ntfs.file(fs, record_number)?;
    let data_item = file
        .data(fs, "")
        .ok_or_else(|| anyhow::anyhow!("No $DATA attribute on record {}", record_number))??;
    let data_attr = data_item.to_attribute()?;
    let mut data_value = data_attr.value(fs)?;

    let mut output = File::create(output_path)?;
    let mut buf = [0u8; 65536];
    loop {
        let n = data_value.read(fs, &mut buf)?;
        if n == 0 {
            break;
        }
        output.write_all(&buf[..n])?;
    }

    Ok(())
}

/// Extract $UsnJrnl:$J by navigating root -> $Extend -> $UsnJrnl -> :$J stream.
#[cfg(feature = "image")]
fn extract_usnjrnl<T: Read + Seek>(
    ntfs: &ntfs::Ntfs,
    fs: &mut T,
    output_path: &Path,
) -> Result<()> {
    use ntfs::indexes::NtfsFileNameIndex;
    use ntfs::NtfsReadSeek;
    use std::io::Write;

    // $Extend is MFT record 11
    let extend_file = ntfs.file(fs, 11)?;
    let extend_index = extend_file.directory_index(fs)?;
    let mut finder = extend_index.finder();

    // Find $UsnJrnl in $Extend directory
    let usnjrnl_entry = NtfsFileNameIndex::find(&mut finder, ntfs, fs, "$UsnJrnl")
        .ok_or_else(|| anyhow::anyhow!("$UsnJrnl not found in $Extend directory"))??;

    let usnjrnl_file = usnjrnl_entry.to_file(ntfs, fs)?;

    // Get the :$J alternate data stream
    let data_item = usnjrnl_file
        .data(fs, "$J")
        .ok_or_else(|| anyhow::anyhow!("No $J data stream on $UsnJrnl"))??;
    let data_attr = data_item.to_attribute()?;
    let mut data_value = data_attr.value(fs)?;

    let mut output = File::create(output_path)?;
    let mut buf = [0u8; 65536];
    loop {
        let n = data_value.read(fs, &mut buf)?;
        if n == 0 {
            break;
        }
        output.write_all(&buf[..n])?;
    }

    Ok(())
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
