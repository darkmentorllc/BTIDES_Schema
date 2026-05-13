// SMP packet handlers.

use BTIDES_model::{hex_lower, Btides};
use serde_json::{Map, Value};

use crate::conn::ConnectionTable;
use crate::types::*;

pub fn handle_smp(
    bt: &mut Btides,
    conns: &mut ConnectionTable,
    aa: u32,
    direction: u8,
    bytes: &[u8],
) {
    if bytes.is_empty() {
        return;
    }
    let op = bytes[0];
    let body = &bytes[1..];
    let entry = match op {
        SMP_PAIRING_REQUEST | SMP_PAIRING_RESPONSE => pairing_req_rsp(bt.verbose_btides, direction, op, body),
        SMP_PAIRING_CONFIRM => fixed_value(bt.verbose_btides, direction, op, "Pairing Confirm", body, 16, "value_hex_str"),
        SMP_PAIRING_RANDOM => fixed_value(bt.verbose_btides, direction, op, "Pairing Random", body, 16, "value_hex_str"),
        SMP_PAIRING_FAILED => pairing_failed(bt.verbose_btides, direction, body),
        SMP_SECURITY_REQUEST => security_request(bt.verbose_btides, direction, body),
        SMP_PAIRING_PUBLIC_KEY => {
            // Python's export_SMP_Pairing_Public_Key is commented out (see
            // PCAP_to_BTIDES.export_to_SMPArray) — scapy doesn't reassemble
            // the 64-byte key across data PDUs, so the recorded value would
            // be wrong. Match Python: skip emission.
            let _ = public_key;
            None
        }
        SMP_PAIRING_DHKEY_CHECK => fixed_value(bt.verbose_btides, direction, op, "Pairing DHKey Check", body, 16, "value_hex_str"),
        SMP_PAIRING_KEYPRESS_NOTIFICATION => keypress(bt.verbose_btides, direction, body),
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
    bt.insert_dual_t1(&ci, entry, "SMPArray");
}

fn pairing_req_rsp(verbose: bool, dir: u8, op: u8, body: &[u8]) -> Option<Value> {
    if body.len() < 6 {
        return None;
    }
    let mut m = Map::new();
    m.insert("direction".to_string(), Value::from(dir));
    m.insert("opcode".to_string(), Value::from(op));
    m.insert("io_cap".to_string(), Value::from(body[0] as i64));
    m.insert("oob_data".to_string(), Value::from(body[1] as i64));
    m.insert("auth_req".to_string(), Value::from(body[2] as i64));
    m.insert("max_key_size".to_string(), Value::from(body[3] as i64));
    m.insert("initiator_key_dist".to_string(), Value::from(body[4] as i64));
    m.insert("responder_key_dist".to_string(), Value::from(body[5] as i64));
    if verbose {
        m.insert(
            "opcode_str".to_string(),
            Value::String(if op == SMP_PAIRING_REQUEST {
                "Pairing Request".to_string()
            } else {
                "Pairing Response".to_string()
            }),
        );
    }
    Some(Value::Object(m))
}

fn fixed_value(
    verbose: bool,
    dir: u8,
    op: u8,
    label: &str,
    body: &[u8],
    expected_len: usize,
    field: &str,
) -> Option<Value> {
    if body.len() < expected_len {
        return None;
    }
    let mut m = Map::new();
    m.insert("direction".to_string(), Value::from(dir));
    m.insert("opcode".to_string(), Value::from(op));
    m.insert(field.to_string(), Value::String(hex_lower(&body[..expected_len])));
    if verbose {
        m.insert("opcode_str".to_string(), Value::String(label.into()));
    }
    Some(Value::Object(m))
}

fn pairing_failed(verbose: bool, dir: u8, body: &[u8]) -> Option<Value> {
    if body.is_empty() {
        return None;
    }
    let mut m = Map::new();
    m.insert("direction".to_string(), Value::from(dir));
    m.insert("opcode".to_string(), Value::from(SMP_PAIRING_FAILED));
    m.insert("reason".to_string(), Value::from(body[0] as i64));
    if verbose {
        m.insert("opcode_str".to_string(), Value::String("Pairing Failed".into()));
    }
    Some(Value::Object(m))
}

fn security_request(verbose: bool, dir: u8, body: &[u8]) -> Option<Value> {
    if body.is_empty() {
        return None;
    }
    let mut m = Map::new();
    m.insert("direction".to_string(), Value::from(dir));
    m.insert("opcode".to_string(), Value::from(SMP_SECURITY_REQUEST));
    m.insert("auth_req".to_string(), Value::from(body[0] as i64));
    if verbose {
        m.insert("opcode_str".to_string(), Value::String("Security Request".into()));
    }
    Some(Value::Object(m))
}

fn public_key(verbose: bool, dir: u8, body: &[u8]) -> Option<Value> {
    if body.len() < 64 {
        return None;
    }
    let mut m = Map::new();
    m.insert("direction".to_string(), Value::from(dir));
    m.insert("opcode".to_string(), Value::from(SMP_PAIRING_PUBLIC_KEY));
    m.insert(
        "pub_key_x_hex_str".to_string(),
        Value::String(hex_lower(&body[0..32])),
    );
    m.insert(
        "pub_key_y_hex_str".to_string(),
        Value::String(hex_lower(&body[32..64])),
    );
    if verbose {
        m.insert(
            "opcode_str".to_string(),
            Value::String("Pairing Public Key".into()),
        );
    }
    Some(Value::Object(m))
}

fn keypress(verbose: bool, dir: u8, body: &[u8]) -> Option<Value> {
    if body.is_empty() {
        return None;
    }
    let mut m = Map::new();
    m.insert("direction".to_string(), Value::from(dir));
    m.insert(
        "opcode".to_string(),
        Value::from(SMP_PAIRING_KEYPRESS_NOTIFICATION),
    );
    m.insert(
        "notification_type".to_string(),
        Value::from(body[0] as i64),
    );
    if verbose {
        m.insert(
            "opcode_str".to_string(),
            Value::String("Pairing Keypress Notification".into()),
        );
    }
    Some(Value::Object(m))
}
