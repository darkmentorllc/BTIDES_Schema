#![allow(non_snake_case)]
// BTIDES-hci: HCI command/event/ACL parsers feeding BTIDES records.
//
// Mirrors Analysis/HCI_to_BTIDES.py. Each btsnoop record is dispatched here
// based on its H4 uart_type. ACL data fragments are reassembled per
// (handle, direction) before being handed to the L2CAP/ATT/SMP parsers in
// BTIDES-bt.

use std::collections::HashMap;

use BTIDES_bt::conn::ConnectionTable;
use BTIDES_bt::types::*;
use BTIDES_model::{bdaddr_from_le_bytes, hex_lower, Btides};
use serde_json::{Map, Value};

/// Per-handle state for the HCI converter. Stores the connection-handle →
/// (peer_bdaddr, addr_type) mapping populated by Connection_Complete events
/// (mirrors HCI_to_BTIDES.py::g_last_handle_to_bdaddr) and per-handle ACL
/// reassembly buffers.
#[derive(Default)]
pub struct HciState {
    pub handle_to_peer: HashMap<u16, (String, u8)>,
    pub acl_reassembly: HashMap<(u16, u8), Vec<u8>>,
}

/// Top-level dispatcher. `uart_type` and `direction` come from BTIDES-btsnoop.
/// `data` is the HCI packet body (no H4 type byte).
pub fn handle_packet(
    bt: &mut Btides,
    conns: &mut ConnectionTable,
    hci: &mut HciState,
    uart_type: u8,
    direction: u8,
    data: &[u8],
) {
    match uart_type {
        0x04 => handle_event(bt, conns, hci, direction, data),
        0x02 => handle_acl(bt, conns, hci, direction, data),
        _ => {}
    }
}

// =====================================================================
// HCI Events
// =====================================================================

fn handle_event(
    bt: &mut Btides,
    conns: &mut ConnectionTable,
    hci: &mut HciState,
    _direction: u8,
    data: &[u8],
) {
    if data.len() < 2 {
        return;
    }
    let event_code = data[0];
    let param_len = data[1] as usize;
    if data.len() < 2 + param_len {
        return;
    }
    let params = &data[2..2 + param_len];

    match event_code {
        0x02 => handle_inquiry_result(bt, params),
        0x03 => handle_connection_complete(hci, params),
        0x07 => handle_remote_name_request_complete(bt, params),
        0x0B => handle_read_remote_supported_features_complete(bt, hci, params),
        0x22 => handle_inquiry_result_with_rssi(bt, params),
        0x23 => handle_read_remote_extended_features_complete(bt, hci, params),
        0x2F => handle_extended_inquiry_result(bt, params),
        0x33 => handle_remote_host_supported_features_notification(bt, params),
        0x3E => handle_le_meta(bt, conns, hci, params),
        _ => {}
    }
}

/// Bluetooth LMP feature constants we need:
///   type_LMP_FEATURES_RES = 40
///   type_LMP_ESCAPE_127   = 127
///   type_ext_opcode_LMP_FEATURES_RES_EXT = 4
const LMP_FEATURES_RES: u8 = 40;
const LMP_ESCAPE_127: u8 = 127;
const LMP_EXT_FEATURES_RES_EXT: u8 = 4;
const LL_FEATURE_RSP: u8 = 9;

fn handle_connection_complete(hci: &mut HciState, p: &[u8]) {
    // Classic Connection_Complete: status(1) handle(2 LE) bdaddr(6 LE) link_type(1) enc(1).
    if p.len() < 11 {
        return;
    }
    let status = p[0];
    if status != 0 {
        return;
    }
    let handle = u16::from_le_bytes([p[1], p[2]]) & 0x0fff;
    let bdaddr = bdaddr_from_le_bytes(&p[3..9]);
    hci.handle_to_peer.insert(handle, (bdaddr, 0));
}

fn handle_remote_name_request_complete(bt: &mut Btides, p: &[u8]) {
    // status(1) bdaddr(6 LE) remote_name(248).
    if p.len() < 7 + 248 {
        return;
    }
    let status = p[0];
    if status != 0 {
        return;
    }
    let bdaddr = bdaddr_from_le_bytes(&p[1..7]);
    let name_bytes = &p[7..7 + 248];
    // Match Python: decode utf-8 with errors=ignore, rstrip nulls. We just
    // serialize the trimmed bytes as hex (the BTIDES schema field is hex_str).
    let trimmed_end = name_bytes.iter().rposition(|&b| b != 0).map(|i| i + 1).unwrap_or(0);
    let trimmed = &name_bytes[..trimmed_end];
    if trimmed.is_empty() {
        return;
    }
    // Python's export_Remote_Name_Request_Complete emits an HCIArray entry
    // with `event_code: 7`, `status: 0`, and `remote_name_hex_str: hex_str`.
    // (The schema requires those three fields; event_code is a const 7.)
    let mut obj = Map::new();
    obj.insert("event_code".to_string(), Value::from(7));
    obj.insert("status".to_string(), Value::from(0));
    obj.insert(
        "remote_name_hex_str".to_string(),
        Value::String(hex_lower(trimmed)),
    );
    bt.insert_single_t1(&bdaddr, 0, Value::Object(obj), "HCIArray");
}

fn handle_inquiry_result(bt: &mut Btides, p: &[u8]) {
    // num_response(1), then per-response 14 bytes:
    //   bd_addr(6) page_scan_repetition_mode(1) reserved(2) device_class(3) clock_offset(2)
    if p.is_empty() {
        return;
    }
    let n = p[0] as usize;
    if n != 1 {
        return;
    }
    // Just emit the CoD and page_scan_repetition_mode for the (only) response.
    if p.len() < 1 + 14 {
        return;
    }
    let bd_addr = bdaddr_from_le_bytes(&p[1..7]);
    let psrm = p[7];
    let cod = &p[10..13];
    emit_psrm_and_cod(bt, &bd_addr, psrm, cod);
}

fn handle_inquiry_result_with_rssi(bt: &mut Btides, p: &[u8]) {
    if p.is_empty() {
        return;
    }
    let n = p[0] as usize;
    if n != 1 {
        return;
    }
    // num_resp(1) + per-response 14 bytes:
    //   bd_addr(6) psrm(1) reserved(1) cod(3) clock_offset(2) rssi(1)
    if p.len() < 1 + 14 {
        return;
    }
    let bd_addr = bdaddr_from_le_bytes(&p[1..7]);
    let psrm = p[7];
    let cod = &p[9..12];
    emit_psrm_and_cod(bt, &bd_addr, psrm, cod);
}

fn handle_extended_inquiry_result(bt: &mut Btides, p: &[u8]) {
    // Per BT Core Spec HCI_Extended_Inquiry_Result event:
    //   num_response(1) + per-response (14): bd_addr(6) psrm(1) reserved(1)
    //   device_class(3) clock_offset(2) rssi(1), then EIR data.
    // EIR starts at byte index 15 (1 num_response + 14 per-response fixed).
    if p.is_empty() {
        return;
    }
    let n = p[0] as usize;
    if n != 1 {
        return;
    }
    if p.len() < 15 {
        return;
    }
    let bd_addr = bdaddr_from_le_bytes(&p[1..7]);
    let psrm = p[7];
    let cod = &p[9..12];
    emit_psrm_and_cod(bt, &bd_addr, psrm, cod);
    let eir_offset = 15;
    if p.len() > eir_offset {
        let eir = &p[eir_offset..];
        BTIDES_bt::adv_data::export_all_tlvs(bt, &bd_addr, 0, 50, "EIR", eir);
    }
}

fn emit_psrm_and_cod(bt: &mut Btides, bd_addr: &str, psrm: u8, cod: &[u8]) {
    // Python emits two EIRArray entries: type=1 PSRM and type=2 ClassOfDevice.
    let mut psrm_entry = Map::new();
    psrm_entry.insert("type".to_string(), Value::from(1));
    psrm_entry.insert("page_scan_repetition_mode".to_string(), Value::from(psrm as i64));
    bt.insert_single_t1(bd_addr, 0, Value::Object(psrm_entry), "EIRArray");

    let cod_hex = format!("{:02x}{:02x}{:02x}", cod[2], cod[1], cod[0]);
    let mut cod_entry = Map::new();
    cod_entry.insert("type".to_string(), Value::from(2));
    cod_entry.insert("CoD_hex_str".to_string(), Value::String(cod_hex));
    bt.insert_single_t1(bd_addr, 0, Value::Object(cod_entry), "EIRArray");
}

fn handle_read_remote_supported_features_complete(
    bt: &mut Btides,
    hci: &HciState,
    p: &[u8],
) {
    // status(1) handle(2 LE) lmp_features(8 LE).
    if p.len() < 1 + 2 + 8 {
        return;
    }
    if p[0] != 0 {
        return;
    }
    let handle = u16::from_le_bytes([p[1], p[2]]) & 0x0fff;
    let Some((bdaddr, _)) = hci.handle_to_peer.get(&handle) else {
        return;
    };
    let features = u64::from_le_bytes([p[3], p[4], p[5], p[6], p[7], p[8], p[9], p[10]]);
    let mut obj = Map::new();
    obj.insert("opcode".to_string(), Value::from(LMP_FEATURES_RES));
    obj.insert(
        "lmp_features_hex_str".to_string(),
        Value::String(format!("{:016x}", features)),
    );
    if bt.verbose_btides {
        obj.insert(
            "opcode_str".to_string(),
            Value::String("LMP_FEATURES_RES".to_string()),
        );
    }
    let bd = bdaddr.clone();
    bt.insert_single_t1(&bd, 0, Value::Object(obj), "LMPArray");
}

fn handle_read_remote_extended_features_complete(
    bt: &mut Btides,
    hci: &HciState,
    p: &[u8],
) {
    // status(1) handle(2 LE) page(1) max_page(1) extended_features(8 LE).
    if p.len() < 1 + 2 + 1 + 1 + 8 {
        return;
    }
    if p[0] != 0 {
        return;
    }
    let handle = u16::from_le_bytes([p[1], p[2]]) & 0x0fff;
    let page = p[3] as i64;
    let max_page = p[4] as i64;
    let Some((bdaddr, _)) = hci.handle_to_peer.get(&handle) else {
        return;
    };
    let features = u64::from_le_bytes([p[5], p[6], p[7], p[8], p[9], p[10], p[11], p[12]]);
    let mut obj = Map::new();
    obj.insert("escape_127".to_string(), Value::from(LMP_ESCAPE_127));
    obj.insert(
        "extended_opcode".to_string(),
        Value::from(LMP_EXT_FEATURES_RES_EXT),
    );
    obj.insert("page".to_string(), Value::from(page));
    obj.insert("max_page".to_string(), Value::from(max_page));
    obj.insert(
        "lmp_features_hex_str".to_string(),
        Value::String(format!("{:016x}", features)),
    );
    if bt.verbose_btides {
        obj.insert(
            "opcode_str".to_string(),
            Value::String("LMP_FEATURES_RES_EXT".to_string()),
        );
    }
    let bd = bdaddr.clone();
    bt.insert_single_t1(&bd, 0, Value::Object(obj), "LMPArray");
}

fn handle_remote_host_supported_features_notification(bt: &mut Btides, p: &[u8]) {
    // bd_addr(6 LE) lmp_features(8 LE).
    if p.len() < 6 + 8 {
        return;
    }
    let bdaddr = bdaddr_from_le_bytes(&p[..6]);
    let features = u64::from_le_bytes([p[6], p[7], p[8], p[9], p[10], p[11], p[12], p[13]]);
    let mut obj = Map::new();
    obj.insert("opcode".to_string(), Value::from(LMP_FEATURES_RES));
    obj.insert(
        "lmp_features_hex_str".to_string(),
        Value::String(format!("{:016x}", features)),
    );
    if bt.verbose_btides {
        obj.insert(
            "opcode_str".to_string(),
            Value::String("LMP_FEATURES_RES".to_string()),
        );
    }
    bt.insert_single_t1(&bdaddr, 0, Value::Object(obj), "LMPArray");
}

// =====================================================================
// LE Meta events
// =====================================================================

fn handle_le_meta(
    bt: &mut Btides,
    _conns: &mut ConnectionTable,
    hci: &mut HciState,
    params: &[u8],
) {
    if params.is_empty() {
        return;
    }
    let sub = params[0];
    let body = &params[1..];
    match sub {
        0x01 => handle_le_connection_complete(hci, body),
        0x02 => handle_le_adv_reports(bt, body),
        0x04 => handle_le_read_remote_features_complete(bt, hci, body),
        0x0A => handle_le_enhanced_connection_complete(hci, body),
        0x0D => handle_le_extended_adv_reports(bt, body),
        _ => {}
    }
}

fn handle_le_connection_complete(hci: &mut HciState, b: &[u8]) {
    // status(1) handle(2 LE) role(1) paddr_type(1) paddr(6 LE) ...
    if b.len() < 11 {
        return;
    }
    let status = b[0];
    if status != 0 {
        return;
    }
    let handle = u16::from_le_bytes([b[1], b[2]]) & 0x0fff;
    let paddr_type = b[4];
    let paddr = bdaddr_from_le_bytes(&b[5..11]);
    hci.handle_to_peer.insert(handle, (paddr, paddr_type));
}

fn handle_le_enhanced_connection_complete(hci: &mut HciState, b: &[u8]) {
    // status(1) handle(2 LE) role(1) paddr_type(1) paddr(6 LE) lrpa(6) prpa(6) ...
    if b.len() < 11 {
        return;
    }
    let status = b[0];
    if status != 0 {
        return;
    }
    let handle = u16::from_le_bytes([b[1], b[2]]) & 0x0fff;
    let paddr_type = b[4];
    let paddr = bdaddr_from_le_bytes(&b[5..11]);
    hci.handle_to_peer.insert(handle, (paddr, paddr_type));
}

fn handle_le_read_remote_features_complete(
    bt: &mut Btides,
    hci: &HciState,
    b: &[u8],
) {
    // status(1) handle(2 LE) le_features(8 LE). Python emits an LLArray entry
    // with LL_FEATURE_RSP shape, direction P2C, keyed by the bdaddr resolved
    // via handle_to_peer.
    if b.len() < 1 + 2 + 8 {
        return;
    }
    if b[0] != 0 {
        return;
    }
    let handle = u16::from_le_bytes([b[1], b[2]]) & 0x0fff;
    let Some((bdaddr, addr_type)) = hci.handle_to_peer.get(&handle).cloned() else {
        return;
    };
    let features = u64::from_le_bytes([b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10]]);
    let mut obj = Map::new();
    obj.insert("direction".to_string(), Value::from(1)); // P2C
    obj.insert("opcode".to_string(), Value::from(LL_FEATURE_RSP));
    obj.insert(
        "le_features_hex_str".to_string(),
        Value::String(format!("{:016x}", features)),
    );
    if bt.verbose_btides {
        obj.insert(
            "opcode_str".to_string(),
            Value::String("LL_FEATURE_RSP".to_string()),
        );
    }
    bt.insert_single_t1(&bdaddr, addr_type as i64, Value::Object(obj), "LLArray");
}

/// LE_Advertising_Reports subevent (0x02). Each report's bdaddr/atype/data is
/// emitted independently.
///
/// NOTE: Python's HCI_to_BTIDES.process_advertisements has a subtle bug — it
/// uses `packet.getlayer(HCI_LE_Meta_Advertising_Report)` (singular) inside
/// export_AdvChannelData, which always returns the *first* report regardless
/// of which iteration the for-loop is on, then `return True`s after the first
/// emission. So Python emits at most one record per event, using report 1's
/// data even when subsequent reports have different addresses. We process all
/// reports correctly — losing nominal byte-parity on multi-report events but
/// not losing data that's actually in the capture.
fn handle_le_adv_reports(bt: &mut Btides, b: &[u8]) {
    if b.is_empty() {
        return;
    }
    let num_reports = b[0] as usize;
    let mut off = 1;
    for _ in 0..num_reports {
        if off + 10 > b.len() {
            return;
        }
        let event_type = b[off];
        let addr_type = b[off + 1];
        let addr = bdaddr_from_le_bytes(&b[off + 2..off + 8]);
        let data_len = b[off + 8] as usize;
        let data_start = off + 9;
        if data_start + data_len + 1 > b.len() {
            return;
        }
        let adv_data = &b[data_start..data_start + data_len];
        let mapped = match event_type {
            0x00 => Some((BTIDES_ADV_IND, "ADV_IND")),
            0x01 => Some((BTIDES_ADV_DIRECT_IND, "ADV_DIRECT_IND")),
            0x02 => Some((BTIDES_ADV_SCAN_IND, "ADV_SCAN_IND")),
            0x03 => Some((BTIDES_ADV_NONCONN_IND, "ADV_NONCONN_IND")),
            0x04 => Some((BTIDES_SCAN_RSP, "SCAN_RSP")),
            _ => None,
        };
        if let Some((btides_type, btides_type_str)) = mapped {
            BTIDES_bt::adv_data::export_all_tlvs(
                bt,
                &addr,
                addr_type as i64,
                btides_type,
                btides_type_str,
                adv_data,
            );
        }
        off = data_start + data_len + 1;
    }
}

/// LE_Extended_Advertising_Reports subevent (0x0D). Each report is emitted
/// using its OWN bdaddr/atype/data — full coverage of the on-wire data.
///
/// NOTE: Python's HCI_to_BTIDES.process_advertisements would emit with the
/// FIRST report's bdaddr/data on every iteration because of a `getlayer()`
/// quirk; that's a bug. We do the right thing instead, which means we'll
/// emit additional records on multi-report events where the first report
/// and subsequent reports have different addresses.
fn handle_le_extended_adv_reports(bt: &mut Btides, b: &[u8]) {
    if b.is_empty() {
        return;
    }
    let num_reports = b[0] as usize;
    let mut off = 1;
    for _ in 0..num_reports {
        if off + 24 > b.len() {
            break;
        }
        let ev = u16::from_le_bytes([b[off], b[off + 1]]);
        let addr_type = b[off + 2];
        let addr = bdaddr_from_le_bytes(&b[off + 3..off + 9]);
        let data_len = b[off + 23] as usize;
        let data_start = off + 24;
        let advance = 24 + data_len;
        if data_start + data_len > b.len() {
            break;
        }
        let adv_data = &b[data_start..data_start + data_len];

        let connectable = (ev & 0b0001) != 0;
        let scannable = (ev & 0b0010) != 0;
        let directed = (ev & 0b0100) != 0;
        let scan_rsp = (ev & 0b1000) != 0;
        let mapped: Option<(u8, &'static str)> = if !scan_rsp && !directed && !scannable && !connectable {
            Some((BTIDES_ADV_NONCONN_IND, "ADV_NONCONN_IND"))
        } else if !scan_rsp && !directed && scannable && !connectable {
            Some((BTIDES_ADV_SCAN_IND, "ADV_SCAN_IND"))
        } else if !scan_rsp && !directed && scannable && connectable {
            Some((BTIDES_ADV_IND, "ADV_IND"))
        } else if !scan_rsp && directed && !scannable && connectable {
            Some((BTIDES_ADV_DIRECT_IND, "ADV_DIRECT_IND"))
        } else if scan_rsp && !directed && scannable {
            Some((BTIDES_SCAN_RSP, "SCAN_RSP"))
        } else {
            None
        };
        if let Some((btides_type, btides_type_str)) = mapped {
            BTIDES_bt::adv_data::export_all_tlvs(
                bt,
                &addr,
                addr_type as i64,
                btides_type,
                btides_type_str,
                adv_data,
            );
        }
        off += advance;
    }
}

// =====================================================================
// HCI ACL data → L2CAP reassembly → ATT / SMP / signal dispatch
// =====================================================================

fn handle_acl(
    bt: &mut Btides,
    conns: &mut ConnectionTable,
    hci: &mut HciState,
    direction: u8,
    data: &[u8],
) {
    if data.len() < 4 {
        return;
    }
    let hdr = u16::from_le_bytes([data[0], data[1]]);
    let handle = hdr & 0x0fff;
    let pb = ((hdr >> 12) & 0x3) as u8;
    let data_len = u16::from_le_bytes([data[2], data[3]]) as usize;
    if data.len() < 4 + data_len {
        return;
    }
    let acl_payload = &data[4..4 + data_len];

    // Python's HCI_to_BTIDES.py doesn't reassemble across ACL packets — it
    // hands each ACL to scapy, which parses one L2CAP frame per packet and
    // creates whatever sub-layers fit in the available bytes. Match that:
    // dispatch per-ACL for the "start"/"complete" PB values; drop continuations
    // (Python would parse them as some other layer or skip them — either way
    // it never emits BTIDES records from a pure continuation fragment).
    if pb == 0b01 {
        // BLE continuation / BR-EDR continuation. Append to any prior buffer
        // so a START followed by CONTINUATION still works as a single big
        // frame; but only run dispatch on START/COMPLETE — matching scapy's
        // per-packet semantics where the START already produced the layer.
        let key = (handle, direction);
        let buf = hci.acl_reassembly.entry(key).or_default();
        buf.extend_from_slice(acl_payload);
        return;
    }
    if !matches!(pb, 0b00 | 0b10 | 0b11) {
        return;
    }

    // For START / COMPLETE: refresh the buffer, dispatch using whatever bytes
    // arrived in this ACL. We do NOT wait for the L2CAP "length" field to be
    // satisfied — Python emits BTIDES records based on per-packet parsing,
    // even when the L2CAP length field is bogus.
    let key = (handle, direction);
    if let Some(buf) = hci.acl_reassembly.get_mut(&key) {
        buf.clear();
        buf.extend_from_slice(acl_payload);
    } else {
        hci.acl_reassembly.insert(key, acl_payload.to_vec());
    }

    if acl_payload.len() < 4 {
        return;
    }
    let cid = u16::from_le_bytes([acl_payload[2], acl_payload[3]]);
    let l2cap_body: Vec<u8> = acl_payload[4..].to_vec();

    let aa = handle as u32;
    let connect_ind = build_connect_ind_for_handle(hci, handle);
    conns.by_aa.entry(aa).or_default().connect_ind = Some(connect_ind);

    let l2cap_len = u16::from_le_bytes([acl_payload[0], acl_payload[1]]);
    let is_sdp_cid = conns
        .by_aa
        .get(&aa)
        .map(|s| s.sdp_cids.contains(&cid))
        .unwrap_or(false);
    match cid {
        CID_ATT => BTIDES_bt::att::handle_att(bt, conns, aa, direction, &l2cap_body),
        CID_SMP => BTIDES_bt::smp::handle_smp(bt, conns, aa, direction, &l2cap_body),
        CID_LE_SIGNALING | CID_BR_EDR_SIGNALING => {
            BTIDES_bt::l2cap::handle_signal_pdu(bt, conns, aa, direction, &l2cap_body)
        }
        _ if is_sdp_cid => {
            BTIDES_bt::sdp::handle_sdp(bt, conns, aa, direction, l2cap_len, cid, &l2cap_body)
        }
        _ => {}
    }
}

fn build_connect_ind_for_handle(hci: &HciState, handle: u16) -> Value {
    // Match Python's ff_CONNECT_IND(peripheral_bdaddr=..., peripheral_bdaddr_rand=...)
    // for handles we know, and ff_CONNECT_IND_placeholder() otherwise.
    let (peripheral_bdaddr, peripheral_bdaddr_rand) = match hci.handle_to_peer.get(&handle) {
        Some((bd, t)) => (bd.clone(), *t as i64),
        None => ("00:00:00:00:00:00".to_string(), 0),
    };
    let mut m = Map::new();
    m.insert(
        "central_bdaddr".to_string(),
        Value::String("00:00:00:00:00:00".to_string()),
    );
    m.insert("central_bdaddr_rand".to_string(), Value::from(0));
    m.insert(
        "peripheral_bdaddr".to_string(),
        Value::String(peripheral_bdaddr),
    );
    m.insert(
        "peripheral_bdaddr_rand".to_string(),
        Value::from(peripheral_bdaddr_rand),
    );
    m.insert("access_address".to_string(), Value::from(0));
    m.insert(
        "crc_init_hex_str".to_string(),
        Value::String("112233".to_string()),
    );
    m.insert("win_size".to_string(), Value::from(0));
    m.insert("win_offset".to_string(), Value::from(0));
    m.insert("interval".to_string(), Value::from(0));
    m.insert("latency".to_string(), Value::from(0));
    m.insert("timeout".to_string(), Value::from(0));
    m.insert(
        "channel_map_hex_str".to_string(),
        Value::String("FFFFFFFF1F".to_string()),
    );
    m.insert("hop".to_string(), Value::from(0));
    m.insert("SCA".to_string(), Value::from(0));
    Value::Object(m)
}
