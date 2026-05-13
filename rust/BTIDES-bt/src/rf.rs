// BTLE_RF pseudo-header (Sniffle/TI style) — 10 bytes of capture-time metadata
// prepended to the on-air BTLE PDU inside DLT_BLUETOOTH_LE_LL_WITH_PHDR pcaps.

use crate::types::{DIR_C2P, DIR_P2C};

/// Parsed BTLE_RF header + the slice positioned at the start of the air PDU
/// (i.e., the access address).
#[derive(Debug, Clone, Copy)]
pub struct RfHeader {
    pub rf_channel: u8,
    pub signal: i8,
    pub noise: i8,
    pub aa_offenses: u8,
    pub ref_aa: u32,
    pub flags: u16,
}

impl RfHeader {
    /// 3-bit `type` enum from the BTLE_RF flags field. Values per scapy:
    /// 0 = ADV_OR_DATA_UNKNOWN_DIR, 1 = AUX_ADV, 2 = DATA_C_TO_P, 3 = DATA_P_TO_C,
    /// 4 = CONN_ISO_C_TO_P, 5 = CONN_ISO_P_TO_C, 6 = BROADCAST_ISO.
    pub fn rf_type(&self) -> u8 {
        ((self.flags >> 7) & 0x7) as u8
    }

    /// Map BTLE_RF type to a BTIDES `direction` value (0 = C2P, 1 = P2C).
    /// Anything that isn't an unambiguous DATA direction falls back to C2P (0)
    /// to match scapy's default field value for adv-channel packets.
    pub fn direction(&self) -> u8 {
        match self.rf_type() {
            3 | 5 => DIR_P2C,
            _ => DIR_C2P,
        }
    }
}

/// Try to parse a 10-byte BTLE_RF header from the front of `bytes`.
/// Returns the parsed header and a slice pointing past it (i.e. at the on-air
/// PDU starting with the access address).
pub fn parse_rf(bytes: &[u8]) -> Option<(RfHeader, &[u8])> {
    if bytes.len() < 10 {
        return None;
    }
    let h = RfHeader {
        rf_channel: bytes[0],
        signal: bytes[1] as i8,
        noise: bytes[2] as i8,
        aa_offenses: bytes[3],
        ref_aa: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        flags: u16::from_le_bytes([bytes[8], bytes[9]]),
    };
    Some((h, &bytes[10..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_scan_req_header() {
        // First packet from the reference sniffle pcap.
        let raw = [
            0x00u8, 0xb1, 0x80, 0x00, 0xd6, 0xbe, 0x89, 0x8e, 0x13, 0x0c,
        ];
        let (h, rest) = parse_rf(&raw).unwrap();
        assert_eq!(h.rf_channel, 0);
        assert_eq!(h.signal, -79);
        assert_eq!(h.noise, -128);
        assert_eq!(h.ref_aa, 0x8e89bed6);
        // type bits should be 0 (ADV_OR_DATA_UNKNOWN_DIR).
        assert_eq!(h.rf_type(), 0);
        assert_eq!(rest.len(), 0);
    }
}
