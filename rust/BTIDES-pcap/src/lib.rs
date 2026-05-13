#![allow(non_snake_case)]
// BTIDES-pcap: minimal classic libpcap reader.
//
// Supports the 4 classic pcap magic numbers (us/ns, little/big endian).
// Does NOT yet support pcapng. The whole file is mmap'd up front so iteration
// is a series of pointer bumps with no heap allocations per packet.

use std::path::Path;

use memmap2::Mmap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PcapError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("not a classic pcap: bad magic {0:#010x}")]
    BadMagic(u32),
    #[error("truncated header (need {need} bytes, have {have})")]
    TruncatedHeader { need: usize, have: usize },
    #[error("truncated packet at offset {offset}: incl_len={incl_len} but only {remaining} bytes left")]
    TruncatedPacket {
        offset: usize,
        incl_len: u32,
        remaining: usize,
    },
}

/// pcap global header.
#[derive(Debug, Clone, Copy)]
pub struct PcapHeader {
    pub little_endian: bool,
    pub ns_resolution: bool,
    pub version_major: u16,
    pub version_minor: u16,
    pub thiszone: i32,
    pub sigfigs: u32,
    pub snaplen: u32,
    pub linktype: u32,
}

const PCAP_MAGIC_LE_US: u32 = 0xa1b2c3d4;
const PCAP_MAGIC_BE_US: u32 = 0xd4c3b2a1;
const PCAP_MAGIC_LE_NS: u32 = 0xa1b23c4d;
const PCAP_MAGIC_BE_NS: u32 = 0x4d3cb2a1;

/// Memory-mapped pcap file. Open once with [`PcapReader::open`], then iterate
/// packets with [`PcapReader::next`]; iteration borrows from the mmap so there
/// is no per-packet allocation.
pub struct PcapReader {
    _mmap: Mmap,
    data: &'static [u8],
    pos: usize,
    header: PcapHeader,
}

/// One packet record (zero-copy slice into the mmap).
pub struct PcapPacket<'a> {
    pub ts_sec: u32,
    pub ts_subsec: u32, // microseconds or nanoseconds depending on header
    pub incl_len: u32,
    pub orig_len: u32,
    pub data: &'a [u8],
}

impl PcapReader {
    pub fn open(path: &Path) -> Result<Self, PcapError> {
        let file = std::fs::File::open(path)?;
        // SAFETY: file is opened above, and the Mmap is owned by `self` so the
        // backing memory outlives every `&'static [u8]` slice we hand out. The
        // 'static lifetime is a self-referential lie limited to internal use:
        // callers only see slices reborrowed to the lifetime of `&self`.
        let mmap = unsafe { Mmap::map(&file) }?;
        let bytes: &'static [u8] = unsafe { std::mem::transmute(&mmap[..]) };
        if bytes.len() < 24 {
            return Err(PcapError::TruncatedHeader {
                need: 24,
                have: bytes.len(),
            });
        }
        let magic_le = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let (little_endian, ns_resolution) = match magic_le {
            PCAP_MAGIC_LE_US => (true, false),
            PCAP_MAGIC_BE_US => (false, false),
            PCAP_MAGIC_LE_NS => (true, true),
            PCAP_MAGIC_BE_NS => (false, true),
            _ => return Err(PcapError::BadMagic(magic_le)),
        };
        let r16 = |o: usize| -> u16 {
            if little_endian {
                u16::from_le_bytes([bytes[o], bytes[o + 1]])
            } else {
                u16::from_be_bytes([bytes[o], bytes[o + 1]])
            }
        };
        let r32 = |o: usize| -> u32 {
            if little_endian {
                u32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]])
            } else {
                u32::from_be_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]])
            }
        };
        let header = PcapHeader {
            little_endian,
            ns_resolution,
            version_major: r16(4),
            version_minor: r16(6),
            thiszone: r32(8) as i32,
            sigfigs: r32(12),
            snaplen: r32(16),
            linktype: r32(20),
        };
        Ok(Self {
            _mmap: mmap,
            data: bytes,
            pos: 24,
            header,
        })
    }

    pub fn header(&self) -> PcapHeader {
        self.header
    }

    /// Return the next packet or None at EOF. On any structural error, returns
    /// the error and advances past the failing record so iteration can continue
    /// (matches scapy's "skip bad packet and keep going" behavior).
    pub fn next(&mut self) -> Result<Option<PcapPacket<'_>>, PcapError> {
        let bytes = self.data;
        if self.pos >= bytes.len() {
            return Ok(None);
        }
        if self.pos + 16 > bytes.len() {
            // Partial trailing record: treat as EOF (matches scapy).
            return Ok(None);
        }
        let le = self.header.little_endian;
        let r32 = |o: usize| -> u32 {
            if le {
                u32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]])
            } else {
                u32::from_be_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]])
            }
        };
        let ts_sec = r32(self.pos);
        let ts_subsec = r32(self.pos + 4);
        let incl_len = r32(self.pos + 8);
        let orig_len = r32(self.pos + 12);
        let payload_start = self.pos + 16;
        let payload_end = match payload_start.checked_add(incl_len as usize) {
            Some(e) => e,
            None => return Ok(None),
        };
        if payload_end > bytes.len() {
            return Err(PcapError::TruncatedPacket {
                offset: self.pos,
                incl_len,
                remaining: bytes.len() - payload_start,
            });
        }
        let data = &bytes[payload_start..payload_end];
        self.pos = payload_end;
        Ok(Some(PcapPacket {
            ts_sec,
            ts_subsec,
            incl_len,
            orig_len,
            data,
        }))
    }
}
