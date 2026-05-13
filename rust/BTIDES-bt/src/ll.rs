// BTLE link-layer header parsing for both adv-channel and data-channel PDUs.
// On-air layout (post-BTLE_RF): access address (4 LE) + LL header (2 bytes) +
// payload (length bytes) + CRC (3 bytes).

use crate::types::BLE_ADV_ACCESS_ADDRESS;

/// Splits an on-air PDU slice into (access_addr, llheader[2], payload, crc[3]).
/// Returns None if the slice is too short for the indicated length.
pub fn parse_air_pdu(bytes: &[u8]) -> Option<(u32, [u8; 2], &[u8], &[u8])> {
    if bytes.len() < 4 + 2 + 3 {
        return None;
    }
    let aa = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let ll_hdr = [bytes[4], bytes[5]];
    let length = bytes[5] as usize;
    let total = 4 + 2 + length + 3;
    if bytes.len() < total {
        return None;
    }
    let payload = &bytes[6..6 + length];
    let crc = &bytes[6 + length..6 + length + 3];
    Some((aa, ll_hdr, payload, crc))
}

pub fn is_adv_aa(aa: u32) -> bool {
    aa == BLE_ADV_ACCESS_ADDRESS
}

/// Parse the first byte of an advertising-channel LL header.
/// Per BT spec (and confirmed against scapy.BTLE_ADV which uses MSB-first bit
/// fields): bit7=RxAdd, bit6=TxAdd, bit5=ChSel, bit4=RFU/CTEInfo,
/// bits3..0=PDU_Type.
#[derive(Debug, Clone, Copy)]
pub struct AdvLlHeader {
    pub pdu_type: u8,
    pub rfu_or_cte: bool,
    pub ch_sel: bool,
    pub tx_add: bool,
    pub rx_add: bool,
}

pub fn parse_adv_ll_header(b: u8) -> AdvLlHeader {
    AdvLlHeader {
        pdu_type: b & 0x0f,
        rfu_or_cte: (b & 0x10) != 0,
        ch_sel: (b & 0x20) != 0,
        tx_add: (b & 0x40) != 0,
        rx_add: (b & 0x80) != 0,
    }
}

/// Parse the first byte of a data-channel LL header.
/// Layout (MSB-first per scapy.BTLE_DATA): bit7..5=RFU(3), bit4=MD,
/// bit3=SN, bit2=NESN, bits1..0=LLID.
#[derive(Debug, Clone, Copy)]
pub struct DataLlHeader {
    pub llid: u8,
    pub nesn: bool,
    pub sn: bool,
    pub md: bool,
}

pub fn parse_data_ll_header(b: u8) -> DataLlHeader {
    DataLlHeader {
        llid: b & 0x03,
        nesn: (b & 0x04) != 0,
        sn: (b & 0x08) != 0,
        md: (b & 0x10) != 0,
    }
}

/// LLID values (2-bit field). 0b01 is also used for empty PDUs.
pub const LLID_RESERVED: u8 = 0;
pub const LLID_CONTINUATION: u8 = 1;
pub const LLID_START: u8 = 2;
pub const LLID_CONTROL: u8 = 3;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adv_header_decode() {
        // First reference packet: 0xc3 = SCAN_REQ with both addrs random.
        let h = parse_adv_ll_header(0xc3);
        assert_eq!(h.pdu_type, 3);
        assert!(h.tx_add);
        assert!(h.rx_add);
        assert!(!h.ch_sel);
    }
}
