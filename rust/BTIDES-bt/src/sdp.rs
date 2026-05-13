// SDP packet handler. Called when L2CAP data arrives on a CID that's been
// registered as carrying SDP (PSM=0x0001) on this connection.

use BTIDES_model::{hex_lower, Btides};
use serde_json::{Map, Value};

use crate::conn::ConnectionTable;

pub const SDP_ERROR_RSP: u8 = 0x01;
pub const SDP_SERVICE_SEARCH_REQ: u8 = 0x02;
pub const SDP_SERVICE_SEARCH_RSP: u8 = 0x03;
pub const SDP_SERVICE_ATTR_REQ: u8 = 0x04;
pub const SDP_SERVICE_ATTR_RSP: u8 = 0x05;
pub const SDP_SERVICE_SEARCH_ATTR_REQ: u8 = 0x06;
pub const SDP_SERVICE_SEARCH_ATTR_RSP: u8 = 0x07;

/// Parse an SDP PDU from the given L2CAP body and emit one SDPArray record.
///
/// SDP PDU wire layout:
///   pdu_id (1 byte) + transaction_id (2 BE) + parameter_length (2 BE) + body.
///
/// Python's export_SDP_ERROR_RSP emits {pdu_id, transaction_id,
/// parameter_length, error_code} (error_code is the first 2 bytes of body).
/// All the other PDU IDs go through export_SDP_Common which emits
/// {pdu_id, transaction_id, parameter_length, raw_data_hex_str} where
/// raw_data_hex_str is the post-header body (sdp_hdr.load in scapy) as hex.
pub fn handle_sdp(
    bt: &mut Btides,
    conns: &mut ConnectionTable,
    aa: u32,
    direction: u8,
    l2cap_len: u16,
    l2cap_cid: u16,
    bytes: &[u8],
) {
    if bytes.len() < 5 {
        return;
    }
    let pdu_id = bytes[0];
    let transaction_id = u16::from_be_bytes([bytes[1], bytes[2]]) as i64;
    let param_len = u16::from_be_bytes([bytes[3], bytes[4]]) as i64;
    let body = &bytes[5..];

    let mut obj = Map::new();
    obj.insert("direction".to_string(), Value::from(direction));
    obj.insert("l2cap_len".to_string(), Value::from(l2cap_len as i64));
    obj.insert("l2cap_cid".to_string(), Value::from(l2cap_cid as i64));
    obj.insert("pdu_id".to_string(), Value::from(pdu_id));
    obj.insert("transaction_id".to_string(), Value::from(transaction_id));
    obj.insert("param_len".to_string(), Value::from(param_len));

    match pdu_id {
        SDP_ERROR_RSP => {
            if body.len() < 2 {
                return;
            }
            let error_code = u16::from_be_bytes([body[0], body[1]]) as i64;
            obj.insert("error_code".to_string(), Value::from(error_code));
            if bt.verbose_btides {
                obj.insert(
                    "pdu_id_str".to_string(),
                    Value::String("SDP_ERROR_RSP".to_string()),
                );
            }
        }
        SDP_SERVICE_SEARCH_REQ
        | SDP_SERVICE_SEARCH_RSP
        | SDP_SERVICE_ATTR_REQ
        | SDP_SERVICE_ATTR_RSP
        | SDP_SERVICE_SEARCH_ATTR_REQ
        | SDP_SERVICE_SEARCH_ATTR_RSP => {
            obj.insert(
                "raw_data_hex_str".to_string(),
                Value::String(hex_lower(body)),
            );
            if bt.verbose_btides {
                let name = match pdu_id {
                    SDP_SERVICE_SEARCH_REQ => "SDP_SERVICE_SEARCH_REQ",
                    SDP_SERVICE_SEARCH_RSP => "SDP_SERVICE_SEARCH_RSP",
                    SDP_SERVICE_ATTR_REQ => "SDP_SERVICE_ATTR_REQ",
                    SDP_SERVICE_ATTR_RSP => "SDP_SERVICE_ATTR_RSP",
                    SDP_SERVICE_SEARCH_ATTR_REQ => "SDP_SERVICE_SEARCH_ATTR_REQ",
                    SDP_SERVICE_SEARCH_ATTR_RSP => "SDP_SERVICE_SEARCH_ATTR_RSP",
                    _ => unreachable!(),
                };
                obj.insert("pdu_id_str".to_string(), Value::String(name.to_string()));
            }
        }
        _ => return,
    }

    let ci = conns
        .by_aa
        .entry(aa)
        .or_default()
        .connect_ind
        .clone()
        .unwrap_or_else(crate::conn::ConnectionState::placeholder_connect_ind);
    bt.insert_dual_t1(&ci, Value::Object(obj), "SDPArray");
}
