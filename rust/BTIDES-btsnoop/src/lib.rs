#![allow(non_snake_case)]
// BTIDES-btsnoop: minimal mmap'd BTSnoop file reader.
//
// Supports the two BTSnoop sub-formats we care about, matching the upstream
// btsnoop Python module (bluez/src/shared/btsnoop.h):
//   - BTSNOOP_FORMAT_UART     = 1002  (classic H4 — H4 type byte prefixed
//                                      to the data; flags hold direction)
//   - BTSNOOP_FORMAT_MONITOR  = 2001  (btmon — flags hold a BTSnoopOpcode,
//                                      data is the raw HCI packet body)
//
// File layout:
//   header (16B): magic "btsnoop\0" (8B) + version (4B BE) + data_link_type (4B BE)
//   per-record (24B header): orig_len(4 BE), inc_len(4 BE), flags(4 BE),
//                            drops(4 BE), ts(8 BE microseconds since 0 AD)
//   followed by inc_len bytes of packet data.

use std::path::Path;

use memmap2::Mmap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BtsnoopError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("not a btsnoop file (magic mismatch)")]
    BadMagic,
    #[error("unsupported btsnoop data link type {0}; expected 1002 (UART/H4) or 2001 (MONITOR)")]
    UnsupportedType(u32),
    #[error("truncated header (have {0} bytes)")]
    TruncatedHeader(usize),
}

pub const FORMAT_UART: u32 = 1002;
pub const FORMAT_MONITOR: u32 = 2001;

#[allow(non_camel_case_types)]
pub mod monitor_op {
    pub const NEW_INDEX: u16 = 0;
    pub const DEL_INDEX: u16 = 1;
    pub const COMMAND_PKT: u16 = 2;
    pub const EVENT_PKT: u16 = 3;
    pub const ACL_TX_PKT: u16 = 4;
    pub const ACL_RX_PKT: u16 = 5;
    pub const SCO_TX_PKT: u16 = 6;
    pub const SCO_RX_PKT: u16 = 7;
}

/// H4 packet type values (the byte that prefixes an H4-framed HCI packet).
pub mod h4 {
    pub const CMD: u8 = 0x01;
    pub const ACL: u8 = 0x02;
    pub const SCO: u8 = 0x03;
    pub const EVT: u8 = 0x04;
}

/// One parsed btsnoop record, normalized for downstream consumers.
/// `uart_type` is the synthesized H4 type byte (1=CMD, 2=ACL, 3=SCO, 4=EVT).
/// `direction` is 0 for h2c (host->controller) or 1 for c2h (controller->host).
/// `data` is the HCI packet *body* with the H4 type byte stripped if present.
#[derive(Debug, Clone)]
pub struct Record<'a> {
    pub uart_type: u8,
    pub direction: u8,
    pub data: &'a [u8],
}

pub struct BtsnoopReader {
    _mmap: Mmap,
    bytes: &'static [u8],
    pos: usize,
    pub format: u32,
}

impl BtsnoopReader {
    pub fn open(path: &Path) -> Result<Self, BtsnoopError> {
        let file = std::fs::File::open(path)?;
        // SAFETY: the Mmap is owned by self for the lifetime of the reader.
        let mmap = unsafe { Mmap::map(&file) }?;
        let bytes: &'static [u8] = unsafe { std::mem::transmute(&mmap[..]) };
        if bytes.len() < 16 {
            return Err(BtsnoopError::TruncatedHeader(bytes.len()));
        }
        if &bytes[..8] != b"btsnoop\0" {
            return Err(BtsnoopError::BadMagic);
        }
        let _version = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let dlt = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        if dlt != FORMAT_UART && dlt != FORMAT_MONITOR {
            return Err(BtsnoopError::UnsupportedType(dlt));
        }
        Ok(Self {
            _mmap: mmap,
            bytes,
            pos: 16,
            format: dlt,
        })
    }

    pub fn next_record(&mut self) -> Option<Record<'_>> {
        loop {
            if self.pos + 24 > self.bytes.len() {
                return None;
            }
            let inc_len = u32::from_be_bytes([
                self.bytes[self.pos + 4],
                self.bytes[self.pos + 5],
                self.bytes[self.pos + 6],
                self.bytes[self.pos + 7],
            ]);
            let flags = u32::from_be_bytes([
                self.bytes[self.pos + 8],
                self.bytes[self.pos + 9],
                self.bytes[self.pos + 10],
                self.bytes[self.pos + 11],
            ]);
            let payload_start = self.pos + 24;
            let payload_end = match payload_start.checked_add(inc_len as usize) {
                Some(e) => e,
                None => return None,
            };
            if payload_end > self.bytes.len() {
                return None;
            }
            self.pos = payload_end;
            if inc_len == 0 {
                continue;
            }
            match self.format {
                FORMAT_UART => {
                    // UART data starts with the H4 type byte; strip it and
                    // use the flags to determine direction.
                    let f = (flags & 0xff) as u8;
                    let direction = match f {
                        0 | 2 => 0u8, // h2c
                        1 | 3 => 1u8, // c2h
                        _ => continue,
                    };
                    let payload = &self.bytes[payload_start..payload_end];
                    if payload.is_empty() {
                        continue;
                    }
                    let uart_type = payload[0];
                    if !matches!(uart_type, h4::CMD | h4::ACL | h4::EVT | h4::SCO) {
                        continue;
                    }
                    return Some(Record {
                        uart_type,
                        direction,
                        data: &payload[1..],
                    });
                }
                FORMAT_MONITOR => {
                    let op = (flags & 0xffff) as u16;
                    let (uart_type, direction) = match op {
                        monitor_op::COMMAND_PKT => (h4::CMD, 0u8),
                        monitor_op::EVENT_PKT => (h4::EVT, 1u8),
                        monitor_op::ACL_TX_PKT => (h4::ACL, 0u8),
                        monitor_op::ACL_RX_PKT => (h4::ACL, 1u8),
                        monitor_op::SCO_TX_PKT => (h4::SCO, 0u8),
                        monitor_op::SCO_RX_PKT => (h4::SCO, 1u8),
                        _ => continue,
                    };
                    let payload = &self.bytes[payload_start..payload_end];
                    return Some(Record {
                        uart_type,
                        direction,
                        data: payload,
                    });
                }
                _ => return None,
            }
        }
    }
}
