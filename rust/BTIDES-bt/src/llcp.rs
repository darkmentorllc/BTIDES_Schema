// LL Control PDU parsing — payload of a data-channel PDU with LLID = 0b11.
// Layout: 1 byte opcode + opcode-specific body.

use BTIDES_model::{hex_lower, Btides};
use serde_json::{Map, Value};

use crate::conn::ConnectionTable;
use crate::types::*;

pub fn handle_llcp(
    bt: &mut Btides,
    conns: &mut ConnectionTable,
    aa: u32,
    direction: u8,
    payload: &[u8],
) {
    if payload.is_empty() {
        return;
    }

    // Encryption gating mirrors PCAP_to_BTIDES.export_BTLE_CTRL: once we've
    // seen LL_ENC_RSP or LL_START_ENC_REQ for this connection, subsequent
    // packets are encrypted garbage. We still allow LL_START_ENC_RSP through
    // (treating it as evidence of a decrypted capture).
    let opcode = payload[0];
    {
        let st = conns.by_aa.entry(aa).or_default();
        if st.encrypted {
            match opcode {
                LL_START_ENC_REQ => { /* pass through */ }
                LL_START_ENC_RSP => {
                    st.encrypted = false;
                }
                _ => return,
            }
        }
        if matches!(opcode, LL_ENC_RSP | LL_START_ENC_REQ) {
            st.encrypted = true;
        }
    }

    let body = &payload[1..];
    let data = match opcode {
        LL_CONNECTION_UPDATE_IND => ff_connection_update_ind(bt.verbose_btides, direction, body),
        LL_CHANNEL_MAP_IND => ff_channel_map_ind(bt.verbose_btides, direction, body),
        LL_TERMINATE_IND => ff_terminate_ind(bt.verbose_btides, direction, body),
        LL_ENC_REQ => ff_enc_req(bt.verbose_btides, direction, body),
        LL_ENC_RSP => ff_enc_rsp(bt.verbose_btides, direction, body),
        LL_START_ENC_REQ => ff_simple_no_body(bt.verbose_btides, direction, LL_START_ENC_REQ, "LL_START_ENC_REQ"),
        LL_START_ENC_RSP => ff_simple_no_body(bt.verbose_btides, direction, LL_START_ENC_RSP, "LL_START_ENC_RSP"),
        LL_UNKNOWN_RSP => ff_unknown_rsp(bt.verbose_btides, direction, body),
        LL_FEATURE_REQ => ff_features(bt.verbose_btides, direction, LL_FEATURE_REQ, "LL_FEATURE_REQ", body),
        LL_FEATURE_RSP => ff_features(bt.verbose_btides, direction, LL_FEATURE_RSP, "LL_FEATURE_RSP", body),
        LL_PERIPHERAL_FEATURE_REQ => ff_features(bt.verbose_btides, direction, LL_PERIPHERAL_FEATURE_REQ, "LL_PERIPHERAL_FEATURE_REQ", body),
        LL_VERSION_IND => ff_version_ind(bt.verbose_btides, direction, body),
        LL_REJECT_IND => ff_reject_ind(bt.verbose_btides, direction, body),
        LL_CONNECTION_PARAM_REQ => ff_conn_param(bt.verbose_btides, direction, LL_CONNECTION_PARAM_REQ, "LL_CONNECTION_PARAM_REQ", body),
        LL_CONNECTION_PARAM_RSP => ff_conn_param(bt.verbose_btides, direction, LL_CONNECTION_PARAM_RSP, "LL_CONNECTION_PARAM_RSP", body),
        LL_REJECT_EXT_IND => ff_reject_ext_ind(bt.verbose_btides, direction, body),
        LL_PING_REQ => ff_simple_no_body(bt.verbose_btides, direction, LL_PING_REQ, "LL_PING_REQ"),
        LL_PING_RSP => ff_simple_no_body(bt.verbose_btides, direction, LL_PING_RSP, "LL_PING_RSP"),
        LL_LENGTH_REQ => ff_length(bt.verbose_btides, direction, LL_LENGTH_REQ, "LL_LENGTH_REQ", body),
        LL_LENGTH_RSP => ff_length(bt.verbose_btides, direction, LL_LENGTH_RSP, "LL_LENGTH_RSP", body),
        LL_PHY_REQ => ff_phy(bt.verbose_btides, direction, LL_PHY_REQ, "LL_PHY_REQ", body),
        LL_PHY_RSP => ff_phy(bt.verbose_btides, direction, LL_PHY_RSP, "LL_PHY_RSP", body),
        LL_PHY_UPDATE_IND => ff_phy_update_ind(bt.verbose_btides, direction, body),
        LL_POWER_CONTROL_REQ | LL_POWER_CONTROL_RSP => {
            // PCAP_to_BTIDES.py explicitly skips these.
            return;
        }
        LL_UNKNOWN_CUSTOM => ff_unknown_custom(bt.verbose_btides, direction, payload),
        _ => return,
    };

    let Some(data) = data else { return };
    // Insert under the DualBDADDR (CONNECT_IND) if we have one; otherwise
    // under a placeholder CONNECT_IND so the records still anchor to the AA.
    let ci = conns
        .by_aa
        .entry(aa)
        .or_default()
        .connect_ind
        .clone()
        .unwrap_or_else(crate::conn::ConnectionState::placeholder_connect_ind);
    bt.insert_dual_t1(&ci, data, "LLArray");
}

fn ff_connection_update_ind(verbose: bool, dir: u8, body: &[u8]) -> Option<Value> {
    if body.len() < 11 {
        return None;
    }
    let win_size = body[0] as i64;
    let win_offset = u16::from_le_bytes([body[1], body[2]]) as i64;
    let interval = u16::from_le_bytes([body[3], body[4]]) as i64;
    let latency = u16::from_le_bytes([body[5], body[6]]) as i64;
    let timeout = u16::from_le_bytes([body[7], body[8]]) as i64;
    let instant = u16::from_le_bytes([body[9], body[10]]) as i64;
    let mut m = Map::new();
    m.insert("direction".to_string(), Value::from(dir));
    m.insert("opcode".to_string(), Value::from(LL_CONNECTION_UPDATE_IND));
    m.insert("win_size".to_string(), Value::from(win_size));
    m.insert("win_offset".to_string(), Value::from(win_offset));
    m.insert("interval".to_string(), Value::from(interval));
    m.insert("latency".to_string(), Value::from(latency));
    m.insert("timeout".to_string(), Value::from(timeout));
    m.insert("instant".to_string(), Value::from(instant));
    if verbose {
        m.insert(
            "opcode_str".to_string(),
            Value::String("LL_CONNECTION_UPDATE_IND".into()),
        );
    }
    Some(Value::Object(m))
}

fn ff_channel_map_ind(verbose: bool, dir: u8, body: &[u8]) -> Option<Value> {
    if body.len() < 7 {
        return None;
    }
    let chm = &body[0..5];
    let instant = u16::from_le_bytes([body[5], body[6]]) as i64;
    // Python pads to 10 hex chars (5 bytes), MSB-first formatted by writing the
    // raw integer with `:010x`. Easiest equivalent: little-endian-bytes →
    // big-endian integer → hex.
    let mut be = [0u8; 5];
    for i in 0..5 {
        be[i] = chm[4 - i];
    }
    let hex_str = format!(
        "{:010x}",
        u64::from_be_bytes([0, 0, 0, be[0], be[1], be[2], be[3], be[4]])
    );
    let mut m = Map::new();
    m.insert("direction".to_string(), Value::from(dir));
    m.insert("opcode".to_string(), Value::from(LL_CHANNEL_MAP_IND));
    m.insert(
        "channel_map_hex_str".to_string(),
        Value::String(hex_str),
    );
    m.insert("instant".to_string(), Value::from(instant));
    if verbose {
        m.insert(
            "opcode_str".to_string(),
            Value::String("LL_CHANNEL_MAP_IND".into()),
        );
    }
    Some(Value::Object(m))
}

fn ff_terminate_ind(verbose: bool, dir: u8, body: &[u8]) -> Option<Value> {
    if body.is_empty() {
        return None;
    }
    let mut m = Map::new();
    m.insert("direction".to_string(), Value::from(dir));
    m.insert("opcode".to_string(), Value::from(LL_TERMINATE_IND));
    m.insert("error_code".to_string(), Value::from(body[0] as i64));
    if verbose {
        m.insert(
            "opcode_str".to_string(),
            Value::String("LL_TERMINATE_IND".into()),
        );
    }
    Some(Value::Object(m))
}

fn ff_enc_req(verbose: bool, dir: u8, body: &[u8]) -> Option<Value> {
    if body.len() < 22 {
        return None;
    }
    let rand = u64::from_le_bytes([
        body[0], body[1], body[2], body[3], body[4], body[5], body[6], body[7],
    ]);
    let ediv = u16::from_le_bytes([body[8], body[9]]);
    let skd_c = u64::from_le_bytes([
        body[10], body[11], body[12], body[13], body[14], body[15], body[16], body[17],
    ]);
    let iv_c = u32::from_le_bytes([body[18], body[19], body[20], body[21]]);
    let mut m = Map::new();
    m.insert("direction".to_string(), Value::from(dir));
    m.insert("opcode".to_string(), Value::from(LL_ENC_REQ));
    m.insert("rand".to_string(), Value::from(rand));
    m.insert("ediv".to_string(), Value::from(ediv as i64));
    m.insert("skd_c".to_string(), Value::from(skd_c));
    m.insert("iv_c".to_string(), Value::from(iv_c as i64));
    if verbose {
        m.insert("opcode_str".to_string(), Value::String("LL_ENC_REQ".into()));
    }
    Some(Value::Object(m))
}

fn ff_enc_rsp(verbose: bool, dir: u8, body: &[u8]) -> Option<Value> {
    if body.len() < 12 {
        return None;
    }
    let skd_p = u64::from_le_bytes([
        body[0], body[1], body[2], body[3], body[4], body[5], body[6], body[7],
    ]);
    let iv_p = u32::from_le_bytes([body[8], body[9], body[10], body[11]]);
    let mut m = Map::new();
    m.insert("direction".to_string(), Value::from(dir));
    m.insert("opcode".to_string(), Value::from(LL_ENC_RSP));
    m.insert("skd_p".to_string(), Value::from(skd_p));
    m.insert("iv_p".to_string(), Value::from(iv_p as i64));
    if verbose {
        m.insert("opcode_str".to_string(), Value::String("LL_ENC_RSP".into()));
    }
    Some(Value::Object(m))
}

fn ff_simple_no_body(verbose: bool, dir: u8, op: u8, name: &str) -> Option<Value> {
    let mut m = Map::new();
    m.insert("direction".to_string(), Value::from(dir));
    m.insert("opcode".to_string(), Value::from(op));
    if verbose {
        m.insert("opcode_str".to_string(), Value::String(name.into()));
    }
    Some(Value::Object(m))
}

fn ff_unknown_rsp(verbose: bool, dir: u8, body: &[u8]) -> Option<Value> {
    if body.is_empty() {
        return None;
    }
    let mut m = Map::new();
    m.insert("direction".to_string(), Value::from(dir));
    m.insert("opcode".to_string(), Value::from(LL_UNKNOWN_RSP));
    m.insert("unknown_type".to_string(), Value::from(body[0] as i64));
    if verbose {
        m.insert(
            "opcode_str".to_string(),
            Value::String("LL_UNKNOWN_RSP".into()),
        );
    }
    Some(Value::Object(m))
}

fn ff_features(verbose: bool, dir: u8, op: u8, name: &str, body: &[u8]) -> Option<Value> {
    if body.len() < 8 {
        return None;
    }
    // Python `f"{features:016x}"` where features is the little-endian uint64
    // read from the wire bytes. Format: hex of LE-as-integer = bytes
    // little-endian, but printed in MSB-first nibble order.
    let features = u64::from_le_bytes([
        body[0], body[1], body[2], body[3], body[4], body[5], body[6], body[7],
    ]);
    let mut m = Map::new();
    m.insert("direction".to_string(), Value::from(dir));
    m.insert("opcode".to_string(), Value::from(op));
    m.insert(
        "le_features_hex_str".to_string(),
        Value::String(format!("{:016x}", features)),
    );
    if verbose {
        m.insert("opcode_str".to_string(), Value::String(name.into()));
    }
    Some(Value::Object(m))
}

fn ff_version_ind(verbose: bool, dir: u8, body: &[u8]) -> Option<Value> {
    if body.len() < 5 {
        return None;
    }
    let version = body[0] as i64;
    let company_id = u16::from_le_bytes([body[1], body[2]]) as i64;
    let subversion = u16::from_le_bytes([body[3], body[4]]) as i64;
    let mut m = Map::new();
    m.insert("direction".to_string(), Value::from(dir));
    m.insert("opcode".to_string(), Value::from(LL_VERSION_IND));
    m.insert("version".to_string(), Value::from(version));
    m.insert("company_id".to_string(), Value::from(company_id));
    m.insert("subversion".to_string(), Value::from(subversion));
    if verbose {
        m.insert(
            "opcode_str".to_string(),
            Value::String("LL_VERSION_IND".into()),
        );
    }
    Some(Value::Object(m))
}

fn ff_reject_ind(verbose: bool, dir: u8, body: &[u8]) -> Option<Value> {
    if body.is_empty() {
        return None;
    }
    let mut m = Map::new();
    m.insert("direction".to_string(), Value::from(dir));
    m.insert("opcode".to_string(), Value::from(LL_REJECT_IND));
    m.insert("error_code".to_string(), Value::from(body[0] as i64));
    if verbose {
        m.insert(
            "opcode_str".to_string(),
            Value::String("LL_REJECT_IND".into()),
        );
    }
    Some(Value::Object(m))
}

fn ff_conn_param(verbose: bool, dir: u8, op: u8, name: &str, body: &[u8]) -> Option<Value> {
    if body.len() < 23 {
        return None;
    }
    let interval_min = u16::from_le_bytes([body[0], body[1]]) as i64;
    let interval_max = u16::from_le_bytes([body[2], body[3]]) as i64;
    let latency = u16::from_le_bytes([body[4], body[5]]) as i64;
    let timeout = u16::from_le_bytes([body[6], body[7]]) as i64;
    let preferred_periodicity = body[8] as i64;
    let ref_conn_event_count = u16::from_le_bytes([body[9], body[10]]) as i64;
    let offsets = [
        u16::from_le_bytes([body[11], body[12]]) as i64,
        u16::from_le_bytes([body[13], body[14]]) as i64,
        u16::from_le_bytes([body[15], body[16]]) as i64,
        u16::from_le_bytes([body[17], body[18]]) as i64,
        u16::from_le_bytes([body[19], body[20]]) as i64,
        u16::from_le_bytes([body[21], body[22]]) as i64,
    ];
    let mut m = Map::new();
    m.insert("direction".to_string(), Value::from(dir));
    m.insert("opcode".to_string(), Value::from(op));
    m.insert("interval_min".to_string(), Value::from(interval_min));
    m.insert("interval_max".to_string(), Value::from(interval_max));
    m.insert("latency".to_string(), Value::from(latency));
    m.insert("timeout".to_string(), Value::from(timeout));
    m.insert(
        "preferred_periodicity".to_string(),
        Value::from(preferred_periodicity),
    );
    m.insert(
        "reference_conneventcount".to_string(),
        Value::from(ref_conn_event_count),
    );
    for (i, v) in offsets.iter().enumerate() {
        m.insert(format!("offset{i}"), Value::from(*v));
    }
    if verbose {
        m.insert("opcode_str".to_string(), Value::String(name.into()));
    }
    Some(Value::Object(m))
}

fn ff_reject_ext_ind(verbose: bool, dir: u8, body: &[u8]) -> Option<Value> {
    if body.len() < 2 {
        return None;
    }
    let mut m = Map::new();
    m.insert("direction".to_string(), Value::from(dir));
    m.insert("opcode".to_string(), Value::from(LL_REJECT_EXT_IND));
    m.insert("reject_opcode".to_string(), Value::from(body[0] as i64));
    m.insert("error_code".to_string(), Value::from(body[1] as i64));
    if verbose {
        m.insert(
            "opcode_str".to_string(),
            Value::String("LL_REJECT_EXT_IND".into()),
        );
    }
    Some(Value::Object(m))
}

fn ff_length(verbose: bool, dir: u8, op: u8, name: &str, body: &[u8]) -> Option<Value> {
    if body.len() < 8 {
        return None;
    }
    let max_rx_octets = u16::from_le_bytes([body[0], body[1]]) as i64;
    let max_rx_time = u16::from_le_bytes([body[2], body[3]]) as i64;
    let max_tx_octets = u16::from_le_bytes([body[4], body[5]]) as i64;
    let max_tx_time = u16::from_le_bytes([body[6], body[7]]) as i64;
    let mut m = Map::new();
    m.insert("direction".to_string(), Value::from(dir));
    m.insert("opcode".to_string(), Value::from(op));
    m.insert("max_rx_octets".to_string(), Value::from(max_rx_octets));
    m.insert("max_rx_time".to_string(), Value::from(max_rx_time));
    m.insert("max_tx_octets".to_string(), Value::from(max_tx_octets));
    m.insert("max_tx_time".to_string(), Value::from(max_tx_time));
    if verbose {
        m.insert("opcode_str".to_string(), Value::String(name.into()));
    }
    Some(Value::Object(m))
}

fn ff_phy(verbose: bool, dir: u8, op: u8, name: &str, body: &[u8]) -> Option<Value> {
    if body.len() < 2 {
        return None;
    }
    let mut m = Map::new();
    m.insert("direction".to_string(), Value::from(dir));
    m.insert("opcode".to_string(), Value::from(op));
    m.insert("TX_PHYS".to_string(), Value::from(body[0] as i64));
    m.insert("RX_PHYS".to_string(), Value::from(body[1] as i64));
    if verbose {
        m.insert("opcode_str".to_string(), Value::String(name.into()));
    }
    Some(Value::Object(m))
}

fn ff_phy_update_ind(verbose: bool, dir: u8, body: &[u8]) -> Option<Value> {
    if body.len() < 4 {
        return None;
    }
    let mut m = Map::new();
    m.insert("direction".to_string(), Value::from(dir));
    m.insert("opcode".to_string(), Value::from(LL_PHY_UPDATE_IND));
    m.insert("phy_c_to_p".to_string(), Value::from(body[0] as i64));
    m.insert("phy_p_to_c".to_string(), Value::from(body[1] as i64));
    m.insert(
        "instant".to_string(),
        Value::from(u16::from_le_bytes([body[2], body[3]]) as i64),
    );
    if verbose {
        m.insert(
            "opcode_str".to_string(),
            Value::String("LL_PHY_UPDATE_IND".into()),
        );
    }
    Some(Value::Object(m))
}

fn ff_unknown_custom(verbose: bool, dir: u8, full: &[u8]) -> Option<Value> {
    let mut m = Map::new();
    m.insert("direction".to_string(), Value::from(dir));
    m.insert("opcode".to_string(), Value::from(LL_UNKNOWN_CUSTOM));
    m.insert(
        "full_pkt_hex_str".to_string(),
        Value::String(hex_lower(full)),
    );
    if verbose {
        m.insert(
            "opcode_str".to_string(),
            Value::String("LL_UNKNOWN_CUSTOM".into()),
        );
    }
    Some(Value::Object(m))
}
