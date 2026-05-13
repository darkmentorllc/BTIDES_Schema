// Advertising-channel PDU dispatch.

use BTIDES_model::{bdaddr_from_le_bytes, hex_lower, Btides};
use serde_json::{Map, Value};

use crate::adv_data;
use crate::conn::ConnectionTable;
use crate::ll::AdvLlHeader;
use crate::types::{
    ADV_PDU_ADV_DIRECT_IND, ADV_PDU_ADV_IND, ADV_PDU_ADV_NONCONN_IND, ADV_PDU_ADV_SCAN_IND,
    ADV_PDU_CONNECT_IND, ADV_PDU_SCAN_RSP, BTIDES_ADV_DIRECT_IND, BTIDES_ADV_IND,
    BTIDES_ADV_NONCONN_IND, BTIDES_ADV_SCAN_IND, BTIDES_SCAN_RSP,
};

/// Dispatch a single advertising-channel PDU. `payload` is the LL payload AFTER
/// the 2-byte LL header (so it starts with the first address field). The PDU
/// type and add bits come from the LL header byte.
pub fn handle_adv_pdu(
    bt: &mut Btides,
    conns: &mut ConnectionTable,
    hdr: AdvLlHeader,
    payload: &[u8],
) {
    match hdr.pdu_type {
        ADV_PDU_ADV_IND => {
            // Python skips ADV_IND with no AdvData (payload length 6 = just AdvA).
            if payload.len() <= 6 {
                return;
            }
            handle_adv_with_data(bt, hdr, payload, BTIDES_ADV_IND, "ADV_IND");
        }
        ADV_PDU_ADV_NONCONN_IND => handle_adv_with_data(
            bt,
            hdr,
            payload,
            BTIDES_ADV_NONCONN_IND,
            "ADV_NONCONN_IND",
        ),
        ADV_PDU_ADV_SCAN_IND => {
            // Python: "if adv_hdr.Length <= 9: continue" — Length is the
            // total payload count (AdvA(6) + TLVs). My `payload` is that same
            // byte count, so the equivalent threshold is <= 9.
            if payload.len() <= 9 {
                return;
            }
            handle_adv_with_data(bt, hdr, payload, BTIDES_ADV_SCAN_IND, "ADV_SCAN_IND");
        }
        ADV_PDU_SCAN_RSP => {
            // Python skips SCAN_RSP entirely when the AdvData portion is empty.
            if payload.len() < 6 {
                return;
            }
            if payload.len() == 6 {
                return;
            }
            let _ = (ADV_PDU_SCAN_RSP, &bdaddr_from_le_bytes);
            handle_adv_with_data(bt, hdr, payload, BTIDES_SCAN_RSP, "SCAN_RSP");
        }
        ADV_PDU_ADV_DIRECT_IND => {
            let _ = BTIDES_ADV_DIRECT_IND;
        }
        ADV_PDU_CONNECT_IND => handle_connect_ind(bt, conns, hdr, payload),
        _ => {}
    }
}

fn handle_adv_with_data(
    bt: &mut Btides,
    hdr: AdvLlHeader,
    payload: &[u8],
    btides_type: u8,
    btides_type_str: &str,
) {
    if payload.len() < 6 {
        return;
    }
    let bdaddr = bdaddr_from_le_bytes(&payload[0..6]);
    let advdata = &payload[6..];
    let rand = if hdr.tx_add { 1 } else { 0 };

    // For ADV_IND/SCAN_RSP/etc., if no TLV produces output (e.g. malformed
    // adv_data), Python falls through without exporting. We still need an
    // AdvChanData wrapper for every successful TLV; adv_data::export_all
    // handles per-TLV emission via Btides.insert_single_t2.
    adv_data::export_all_tlvs(bt, &bdaddr, rand, btides_type, btides_type_str, advdata);
}

fn handle_connect_ind(
    bt: &mut Btides,
    conns: &mut ConnectionTable,
    hdr: AdvLlHeader,
    payload: &[u8],
) {
    // Layout: InitA(6) AdvA(6) LLData(22) = 34 bytes
    if payload.len() < 34 {
        return;
    }
    let central_bdaddr = bdaddr_from_le_bytes(&payload[0..6]);
    let peripheral_bdaddr = bdaddr_from_le_bytes(&payload[6..12]);
    let ll = &payload[12..34];
    // Wire byte order in scapy is little-endian for the multi-byte fields, but
    // BTIDES wants the spec-canonical byte order. PCAP_to_BTIDES.py does:
    //   access_address = int.from_bytes(AA.to_bytes(4,'little'),'big')
    //   channel_map_hex_str = bytes(chM.to_bytes(5,'little')).hex()
    //   crc_init_hex_str    = bytes(crc_init.to_bytes(3,'little')).hex()
    // Working from the on-wire bytes directly, the AA on the wire IS already
    // little-endian, so reading as LE then re-serializing as BE gives us the
    // spec value: u32::from_le_bytes(...).
    let aa = u32::from_le_bytes([ll[0], ll[1], ll[2], ll[3]]);
    let crc_init_hex = hex_lower(&ll[4..7]);
    let win_size = ll[7] as i64;
    let win_offset = u16::from_le_bytes([ll[8], ll[9]]) as i64;
    let interval = u16::from_le_bytes([ll[10], ll[11]]) as i64;
    let latency = u16::from_le_bytes([ll[12], ll[13]]) as i64;
    let timeout = u16::from_le_bytes([ll[14], ll[15]]) as i64;
    let channel_map_hex = hex_lower(&ll[16..21]);
    let hop_sca = ll[21];
    let hop = (hop_sca & 0x1f) as i64;
    let sca = ((hop_sca >> 5) & 0x07) as i64;

    let mut ci = Map::new();
    ci.insert(
        "central_bdaddr".to_string(),
        Value::String(central_bdaddr),
    );
    ci.insert(
        "central_bdaddr_rand".to_string(),
        Value::from(if hdr.tx_add { 1 } else { 0 }),
    );
    ci.insert(
        "peripheral_bdaddr".to_string(),
        Value::String(peripheral_bdaddr),
    );
    ci.insert(
        "peripheral_bdaddr_rand".to_string(),
        Value::from(if hdr.rx_add { 1 } else { 0 }),
    );
    ci.insert("access_address".to_string(), Value::from(aa as i64));
    ci.insert("crc_init_hex_str".to_string(), Value::String(crc_init_hex));
    ci.insert("win_size".to_string(), Value::from(win_size));
    ci.insert("win_offset".to_string(), Value::from(win_offset));
    ci.insert("interval".to_string(), Value::from(interval));
    ci.insert("latency".to_string(), Value::from(latency));
    ci.insert("timeout".to_string(), Value::from(timeout));
    ci.insert(
        "channel_map_hex_str".to_string(),
        Value::String(channel_map_hex),
    );
    ci.insert("hop".to_string(), Value::from(hop));
    ci.insert("SCA".to_string(), Value::from(sca));

    let ci_value = Value::Object(ci);

    // Store for later cross-reference by access address.
    let st = conns.by_aa.entry(aa).or_default();
    st.connect_ind = Some(ci_value.clone());

    bt.insert_dual_zero(ci_value);
}
