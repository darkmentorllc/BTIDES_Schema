// L2CAP framing and signal-channel handlers.
//
// An LL data PDU with LLID = 0b10 starts a new L2CAP frame; subsequent LLID =
// 0b01 PDUs carry continuation fragments. The frame header is:
//     length (2 LE) + cid (2 LE) + payload[length]
// CID 0x0004 = ATT, 0x0005 = LE signaling, 0x0006 = SMP.

use BTIDES_model::Btides;
use serde_json::{Map, Value};

use crate::att;
use crate::conn::ConnectionTable;
use crate::smp;
use crate::types::*;

/// Feed a data-PDU payload (after the LL header) into the per-direction
/// reassembly buffer. If a complete L2CAP frame is now available, dispatch it
/// to the correct CID handler.
pub fn handle_data_pdu(
    bt: &mut Btides,
    conns: &mut ConnectionTable,
    aa: u32,
    direction: u8,
    llid: u8,
    payload: &[u8],
) {
    let dir_idx = (direction & 1) as usize;

    // Reassemble (scoped borrow so we can re-borrow `conns` later for dispatch).
    let mut completed: Vec<Vec<u8>> = Vec::new();
    {
        let st = conns.by_aa.entry(aa).or_default();
        match llid {
            crate::ll::LLID_START => {
                if payload.len() < 4 {
                    return;
                }
                let length = u16::from_le_bytes([payload[0], payload[1]]) as usize;
                let expected = 4 + length;
                st.reassembly[dir_idx].buf.clear();
                st.reassembly[dir_idx].buf.extend_from_slice(payload);
                st.reassembly[dir_idx].expected = expected;
            }
            crate::ll::LLID_CONTINUATION => {
                if st.reassembly[dir_idx].expected == 0 {
                    return;
                }
                st.reassembly[dir_idx].buf.extend_from_slice(payload);
            }
            _ => return,
        }
        while st.reassembly[dir_idx].expected > 0
            && st.reassembly[dir_idx].buf.len() >= st.reassembly[dir_idx].expected
        {
            let exp = st.reassembly[dir_idx].expected;
            let frame: Vec<u8> = st.reassembly[dir_idx].buf.drain(..exp).collect();
            st.reassembly[dir_idx].expected = 0;
            completed.push(frame);
        }
    }

    for frame in completed {
        if frame.len() < 4 {
            continue;
        }
        let cid = u16::from_le_bytes([frame[2], frame[3]]);
        let l2cap_payload = &frame[4..];
        match cid {
            CID_ATT => att::handle_att(bt, conns, aa, direction, l2cap_payload),
            CID_SMP => smp::handle_smp(bt, conns, aa, direction, l2cap_payload),
            CID_LE_SIGNALING | CID_BR_EDR_SIGNALING => {
                handle_signal(bt, conns, aa, direction, l2cap_payload)
            }
            _ => {}
        }
    }
}

/// Public entry for L2CAP signaling PDUs that have already been reassembled
/// out-of-band (e.g. via HCI ACL reassembly). The BTIDES-pcap path calls the
/// private `handle_signal` inside `handle_data_pdu`; this is the version
/// BTIDES-hci uses after it's done its own L2CAP frame reassembly.
pub fn handle_signal_pdu(
    bt: &mut Btides,
    conns: &mut ConnectionTable,
    aa: u32,
    direction: u8,
    bytes: &[u8],
) {
    handle_signal(bt, conns, aa, direction, bytes)
}

fn handle_signal(
    bt: &mut Btides,
    conns: &mut ConnectionTable,
    aa: u32,
    direction: u8,
    bytes: &[u8],
) {
    // Signal-channel format: code(1) + id(1) + data_len(2 LE) + data[data_len].
    // We do NOT require `data_len` to match the actual remaining body length —
    // scapy emits the BTIDES record even when the on-wire data_len is bogus
    // (we've seen Android logs with data_len in the 1000s but only a few real
    // body bytes). Each per-cmd handler does its own minimum-body check.
    if bytes.len() < 4 {
        return;
    }
    let code = bytes[0];
    let id = bytes[1] as i64;
    let data_len = u16::from_le_bytes([bytes[2], bytes[3]]) as i64;
    let body = &bytes[4..];

    // Side-effect: track SDP-channel CIDs so the SDP payload dispatcher knows
    // which L2CAP data PDUs to parse as SDP.
    if let Some((psm, scid, maybe_dcid)) = parse_conn_psm_cids(code, body) {
        let st = conns.by_aa.entry(aa).or_default();
        if code == L2CAP_CONNECTION_REQ && psm == 0x0001 {
            st.sdp_cids.insert(scid);
        } else if code == L2CAP_CONNECTION_RSP {
            // If the source_cid was previously registered as SDP (from REQ),
            // the destination_cid is the other end of the SDP channel.
            if st.sdp_cids.contains(&scid) {
                if let Some(d) = maybe_dcid {
                    st.sdp_cids.insert(d);
                }
            }
        }
    }

    let entry = match code {
        L2CAP_CONNECTION_REQ => signal_conn_req(bt.verbose_btides, direction, id, data_len, body),
        L2CAP_CONNECTION_RSP => signal_conn_rsp(bt.verbose_btides, direction, id, data_len, body),
        L2CAP_CONFIGURATION_REQ => signal_config_req(bt.verbose_btides, direction, id, data_len, body),
        L2CAP_CONFIGURATION_RSP => signal_config_rsp(bt.verbose_btides, direction, id, data_len, body),
        L2CAP_DISCONNECTION_REQ => signal_disc_req(bt.verbose_btides, direction, id, data_len, body),
        L2CAP_DISCONNECTION_RSP => signal_disc_rsp(bt.verbose_btides, direction, id, data_len, body),
        L2CAP_INFORMATION_REQ => signal_info_req(bt.verbose_btides, direction, id, data_len, body),
        L2CAP_INFORMATION_RSP => signal_info_rsp(bt.verbose_btides, direction, id, data_len, body),
        L2CAP_CONNECTION_PARAMETER_UPDATE_REQ => {
            signal_cpu_req(bt.verbose_btides, direction, id, data_len, body)
        }
        L2CAP_CONNECTION_PARAMETER_UPDATE_RSP => {
            signal_cpu_rsp(bt.verbose_btides, direction, id, data_len, body)
        }
        _ => None,
    };
    let Some(entry) = entry else { return };
    let ci = conns
        .by_aa
        .entry(aa)
        .or_default()
        .connect_ind
        .clone()
        .unwrap_or_else(crate::conn::ConnectionState::placeholder_connect_ind);
    bt.insert_dual_t1(&ci, entry, "L2CAPArray");
}

fn base(dir: u8, code: u8, id: i64, data_len: i64) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("direction".to_string(), Value::from(dir));
    m.insert("code".to_string(), Value::from(code));
    m.insert("id".to_string(), Value::from(id));
    m.insert("data_len".to_string(), Value::from(data_len));
    m
}

fn maybe_code_str(m: &mut Map<String, Value>, verbose: bool, s: &str) {
    if verbose {
        m.insert("code_str".to_string(), Value::String(s.into()));
    }
}

fn signal_conn_req(v: bool, dir: u8, id: i64, dl: i64, body: &[u8]) -> Option<Value> {
    if body.len() < 4 {
        return None;
    }
    let psm = u16::from_le_bytes([body[0], body[1]]) as i64;
    let source_cid = u16::from_le_bytes([body[2], body[3]]) as i64;
    let mut m = base(dir, L2CAP_CONNECTION_REQ, id, dl);
    m.insert("psm".to_string(), Value::from(psm));
    m.insert("source_cid".to_string(), Value::from(source_cid));
    maybe_code_str(&mut m, v, "L2CAP_CONNECTION_REQ");
    Some(Value::Object(m))
}

/// Pull L2CAP_CONNECTION_REQ source_cid / psm or CONNECTION_RSP CIDs out of an
/// already-parsed L2CAP signaling frame body so the caller (in handle_signal)
/// can update the per-connection SDP-CID set when PSM=0x0001 connections are
/// negotiated. Returns (psm, source_cid, destination_cid) where destination is
/// only set for CONNECTION_RSP.
fn parse_conn_psm_cids(code: u8, body: &[u8]) -> Option<(u16, u16, Option<u16>)> {
    match code {
        L2CAP_CONNECTION_REQ if body.len() >= 4 => {
            let psm = u16::from_le_bytes([body[0], body[1]]);
            let scid = u16::from_le_bytes([body[2], body[3]]);
            Some((psm, scid, None))
        }
        L2CAP_CONNECTION_RSP if body.len() >= 8 => {
            let dcid = u16::from_le_bytes([body[0], body[1]]);
            let scid = u16::from_le_bytes([body[2], body[3]]);
            // PSM isn't in the response; we only learn the d/s cid pair.
            // Caller knows the connection-level set already.
            Some((0, scid, Some(dcid)))
        }
        _ => None,
    }
}

fn signal_conn_rsp(v: bool, dir: u8, id: i64, dl: i64, body: &[u8]) -> Option<Value> {
    if body.len() < 8 {
        return None;
    }
    let dst = u16::from_le_bytes([body[0], body[1]]) as i64;
    let src = u16::from_le_bytes([body[2], body[3]]) as i64;
    let result = u16::from_le_bytes([body[4], body[5]]) as i64;
    let status = u16::from_le_bytes([body[6], body[7]]) as i64;
    let mut m = base(dir, L2CAP_CONNECTION_RSP, id, dl);
    m.insert("destination_cid".to_string(), Value::from(dst));
    m.insert("source_cid".to_string(), Value::from(src));
    m.insert("result".to_string(), Value::from(result));
    m.insert("status".to_string(), Value::from(status));
    maybe_code_str(&mut m, v, "L2CAP_CONNECTION_RSP");
    Some(Value::Object(m))
}

fn signal_config_req(v: bool, dir: u8, id: i64, dl: i64, body: &[u8]) -> Option<Value> {
    if body.len() < 4 {
        return None;
    }
    let dst = u16::from_le_bytes([body[0], body[1]]) as i64;
    let flags = u16::from_le_bytes([body[2], body[3]]) as i64;
    let opts = &body[4..];
    let mut m = base(dir, L2CAP_CONFIGURATION_REQ, id, dl);
    m.insert("destination_cid".to_string(), Value::from(dst));
    m.insert("flags".to_string(), Value::from(flags));
    if !opts.is_empty() {
        m.insert(
            "config_options_hex_str".to_string(),
            Value::String(BTIDES_model::hex_lower(opts)),
        );
    }
    maybe_code_str(&mut m, v, "L2CAP_CONFIGURATION_REQ");
    Some(Value::Object(m))
}

fn signal_config_rsp(v: bool, dir: u8, id: i64, dl: i64, body: &[u8]) -> Option<Value> {
    if body.len() < 6 {
        return None;
    }
    let src = u16::from_le_bytes([body[0], body[1]]) as i64;
    let flags = u16::from_le_bytes([body[2], body[3]]) as i64;
    let result = u16::from_le_bytes([body[4], body[5]]) as i64;
    let opts = &body[6..];
    let mut m = base(dir, L2CAP_CONFIGURATION_RSP, id, dl);
    m.insert("source_cid".to_string(), Value::from(src));
    m.insert("flags".to_string(), Value::from(flags));
    m.insert("result".to_string(), Value::from(result));
    if !opts.is_empty() {
        m.insert(
            "config_options_hex_str".to_string(),
            Value::String(BTIDES_model::hex_lower(opts)),
        );
    }
    maybe_code_str(&mut m, v, "L2CAP_CONFIGURATION_RSP");
    Some(Value::Object(m))
}

fn signal_disc_req(v: bool, dir: u8, id: i64, dl: i64, body: &[u8]) -> Option<Value> {
    if body.len() < 4 {
        return None;
    }
    let dst = u16::from_le_bytes([body[0], body[1]]) as i64;
    let src = u16::from_le_bytes([body[2], body[3]]) as i64;
    let mut m = base(dir, L2CAP_DISCONNECTION_REQ, id, dl);
    m.insert("destination_cid".to_string(), Value::from(dst));
    m.insert("source_cid".to_string(), Value::from(src));
    maybe_code_str(&mut m, v, "L2CAP_DISCONNECTION_REQ");
    Some(Value::Object(m))
}

fn signal_disc_rsp(v: bool, dir: u8, id: i64, dl: i64, body: &[u8]) -> Option<Value> {
    if body.len() < 4 {
        return None;
    }
    let dst = u16::from_le_bytes([body[0], body[1]]) as i64;
    let src = u16::from_le_bytes([body[2], body[3]]) as i64;
    let mut m = base(dir, L2CAP_DISCONNECTION_RSP, id, dl);
    m.insert("destination_cid".to_string(), Value::from(dst));
    m.insert("source_cid".to_string(), Value::from(src));
    maybe_code_str(&mut m, v, "L2CAP_DISCONNECTION_RSP");
    Some(Value::Object(m))
}

fn signal_info_req(v: bool, dir: u8, id: i64, dl: i64, body: &[u8]) -> Option<Value> {
    if body.len() < 2 {
        return None;
    }
    let info_type = u16::from_le_bytes([body[0], body[1]]) as i64;
    let mut m = base(dir, L2CAP_INFORMATION_REQ, id, dl);
    m.insert("info_type".to_string(), Value::from(info_type));
    maybe_code_str(&mut m, v, "L2CAP_INFORMATION_REQ");
    Some(Value::Object(m))
}

fn signal_info_rsp(v: bool, dir: u8, id: i64, dl: i64, body: &[u8]) -> Option<Value> {
    if body.len() < 4 {
        return None;
    }
    let info_type = u16::from_le_bytes([body[0], body[1]]) as i64;
    let result = u16::from_le_bytes([body[2], body[3]]) as i64;
    let info = &body[4..];
    let mut m = base(dir, L2CAP_INFORMATION_RSP, id, dl);
    m.insert("info_type".to_string(), Value::from(info_type));
    m.insert("result".to_string(), Value::from(result));
    if !info.is_empty() {
        m.insert(
            "info_hex_str".to_string(),
            Value::String(BTIDES_model::hex_lower(info)),
        );
    }
    maybe_code_str(&mut m, v, "L2CAP_INFORMATION_RSP");
    Some(Value::Object(m))
}

fn signal_cpu_req(v: bool, dir: u8, id: i64, dl: i64, body: &[u8]) -> Option<Value> {
    if body.len() < 8 {
        return None;
    }
    let interval_min = u16::from_le_bytes([body[0], body[1]]) as i64;
    let interval_max = u16::from_le_bytes([body[2], body[3]]) as i64;
    let latency = u16::from_le_bytes([body[4], body[5]]) as i64;
    let timeout = u16::from_le_bytes([body[6], body[7]]) as i64;
    let mut m = base(dir, L2CAP_CONNECTION_PARAMETER_UPDATE_REQ, id, dl);
    m.insert("interval_min".to_string(), Value::from(interval_min));
    m.insert("interval_max".to_string(), Value::from(interval_max));
    m.insert("latency".to_string(), Value::from(latency));
    m.insert("timeout".to_string(), Value::from(timeout));
    maybe_code_str(&mut m, v, "L2CAP_CONNECTION_PARAMETER_UPDATE_REQ");
    Some(Value::Object(m))
}

fn signal_cpu_rsp(v: bool, dir: u8, id: i64, dl: i64, body: &[u8]) -> Option<Value> {
    if body.len() < 2 {
        return None;
    }
    let result = u16::from_le_bytes([body[0], body[1]]) as i64;
    let mut m = base(dir, L2CAP_CONNECTION_PARAMETER_UPDATE_RSP, id, dl);
    m.insert("result".to_string(), Value::from(result));
    maybe_code_str(&mut m, v, "L2CAP_CONNECTION_PARAMETER_UPDATE_RSP");
    Some(Value::Object(m))
}
