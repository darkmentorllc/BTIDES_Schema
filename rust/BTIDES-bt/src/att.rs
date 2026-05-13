// ATT packet handlers.

use BTIDES_model::{convert_uuid128_to_uuid16_if_possible, hex_lower, Btides};
use serde_json::{Map, Value};

use crate::conn::ConnectionTable;
use crate::types::*;

pub fn handle_att(
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

    // Stash per-connection request context BEFORE handling so the matching
    // RSP knows what to do.
    match op {
        ATT_READ_BY_GROUP_TYPE_REQ => {
            if body.len() >= 6 {
                let gt = uuid_from_le(&body[4..]).unwrap_or_default();
                conns.by_aa.entry(aa).or_default().last_group_type = gt;
            }
        }
        ATT_READ_BY_TYPE_REQ => {
            if body.len() >= 6 {
                let u = uuid_from_le(&body[4..]).unwrap_or_default();
                conns.by_aa.entry(aa).or_default().last_read_by_type_uuid = u;
            }
        }
        ATT_READ_REQ => {
            if body.len() >= 2 {
                let h = u16::from_le_bytes([body[0], body[1]]) as i64;
                conns.by_aa.entry(aa).or_default().last_read_handle = Some(h);
            }
        }
        _ => {}
    }

    let entry = match op {
        ATT_ERROR_RSP => att_error_rsp(bt.verbose_btides, direction, body),
        ATT_EXCHANGE_MTU_REQ => att_mtu_req(bt.verbose_btides, direction, body),
        ATT_EXCHANGE_MTU_RSP => att_mtu_rsp(bt.verbose_btides, direction, body),
        ATT_FIND_INFORMATION_REQ => att_find_info_req(bt.verbose_btides, direction, body),
        ATT_FIND_INFORMATION_RSP => att_find_info_rsp(bt.verbose_btides, direction, body),
        ATT_READ_BY_TYPE_REQ => att_read_by_type_req(bt.verbose_btides, direction, body),
        ATT_READ_BY_TYPE_RSP => att_read_by_type_rsp(bt.verbose_btides, direction, body),
        ATT_READ_REQ => att_read_req(bt.verbose_btides, direction, body),
        ATT_READ_RSP => att_read_rsp(bt.verbose_btides, direction, body),
        ATT_READ_BY_GROUP_TYPE_REQ => att_rbgt_req(bt.verbose_btides, direction, body),
        ATT_READ_BY_GROUP_TYPE_RSP => att_rbgt_rsp(bt.verbose_btides, direction, body),
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

    // Side-effects: RSP-typed packets that also produce GATT/handle-enum records.
    // Run BEFORE inserting the ATT record so we don't move `entry` first.
    match op {
        ATT_FIND_INFORMATION_RSP => {
            if let Some(info_list) = entry.as_object().and_then(|m| m.get("information_data")).and_then(|v| v.as_array()) {
                // Cache handle→UUID under the direction-dependent bdaddr, in the
                // process-global table — so later ATT_READ_RSP handlers can
                // classify handles even across connection turnover (Python's
                // g_bdaddr_to_list_of_ff_ATT_FIND_INFORMATION_RSP_information_data
                // persists for the lifetime of the Python process and is
                // bdaddr-keyed, not connection-keyed).
                let sender = crate::conn::ConnectionTable::direction_bdaddr(&ci, direction);
                if let Some(bd) = sender {
                    let cache = conns
                        .handle_to_uuid_by_bdaddr
                        .entry(bd)
                        .or_default();
                    for h_entry in info_list.iter() {
                        if let Some(o) = h_entry.as_object() {
                            let handle = o.get("handle").and_then(|v| v.as_i64());
                            let uuid = o.get("UUID").and_then(|v| v.as_str());
                            if let (Some(h), Some(u)) = (handle, uuid) {
                                cache.insert(h, u.to_string());
                            }
                        }
                    }
                }
                // Mirror Python: information_data inside the ATT record keeps
                // the dashed UUID128 form (uses scapy UUID __str__), but the
                // ATT_handle_enumeration entries go through `ff_ATT_handle_entry`
                // which calls convert_UUID128_to_UUID16_if_possible — stripping
                // dashes. So we build a dashless variant for the enum here.
                for h_entry in info_list.iter() {
                    let Some(o) = h_entry.as_object() else { continue };
                    let handle = o.get("handle").cloned();
                    let uuid_str = o.get("UUID").and_then(|v| v.as_str()).unwrap_or("");
                    let dashless = BTIDES_model::convert_uuid128_to_uuid16_if_possible(uuid_str);
                    let mut enum_entry = serde_json::Map::new();
                    if let Some(h) = handle {
                        enum_entry.insert("handle".to_string(), h);
                    }
                    enum_entry.insert("UUID".to_string(), serde_json::Value::String(dashless));
                    let enum_value = serde_json::Value::Object(enum_entry);
                    bt.insert_dual_t2(
                        &ci,
                        serde_json::json!({"ATT_handle_enumeration": [enum_value.clone()]}),
                        "ATTArray",
                        enum_value,
                        "ATT_handle_enumeration",
                    );
                }
            }
        }
        ATT_READ_RSP => {
            // If the last ATT_READ_REQ targeted a handle whose UUID we know
            // (from a prior FIND_INFO_RSP, possibly on an earlier connection
            // to the same peripheral), and that UUID is "2803", then this
            // response's value is a Characteristic Declaration: parse and emit.
            let last_handle = conns.by_aa.entry(aa).or_default().last_read_handle;
            let sender = crate::conn::ConnectionTable::direction_bdaddr(&ci, direction);
            let uuid = match (sender, last_handle) {
                (Some(bd), Some(h)) => conns
                    .handle_to_uuid_by_bdaddr
                    .get(&bd)
                    .and_then(|m| m.get(&h).cloned()),
                _ => None,
            };
            if uuid.as_deref() == Some("2803") {
                if let Some(handle) = last_handle {
                    if let Some(val_hex) = entry
                        .as_object()
                        .and_then(|m| m.get("value_hex_str"))
                        .and_then(|v| v.as_str())
                    {
                        let raw: Vec<u8> = (0..val_hex.len())
                            .step_by(2)
                            .filter_map(|i| u8::from_str_radix(val_hex.get(i..i + 2)?, 16).ok())
                            .collect();
                        if raw.len() == 5 || raw.len() == 19 {
                            let properties = raw[0] as i64;
                            let value_handle = u16::from_le_bytes([raw[1], raw[2]]) as i64;
                            let value_uuid = if raw.len() == 5 {
                                format!("{:02x}{:02x}", raw[4], raw[3])
                            } else {
                                let mut be = [0u8; 16];
                                for i in 0..16 {
                                    be[i] = raw[3 + 15 - i];
                                }
                                BTIDES_model::hex_lower(&be)
                            };
                            let value_uuid =
                                BTIDES_model::convert_uuid128_to_uuid16_if_possible(&value_uuid);
                            let mut ch = serde_json::Map::new();
                            ch.insert("handle".to_string(), serde_json::Value::from(handle));
                            ch.insert("properties".to_string(), serde_json::Value::from(properties));
                            ch.insert(
                                "value_handle".to_string(),
                                serde_json::Value::from(value_handle),
                            );
                            ch.insert(
                                "value_uuid".to_string(),
                                serde_json::Value::String(value_uuid.clone()),
                            );
                            // Python embeds a char_value placeholder (handle = value_handle,
                            // value_uuid = value_uuid) so later read/write IO can attach to
                            // it. Mirror that.
                            ch.insert(
                                "char_value".to_string(),
                                serde_json::json!({
                                    "handle": value_handle,
                                    "value_uuid": value_uuid,
                                }),
                            );
                            if bt.verbose_btides {
                                ch.insert(
                                    "type_str".to_string(),
                                    serde_json::Value::String("Characteristic".into()),
                                );
                                ch.insert(
                                    "utype".to_string(),
                                    serde_json::Value::String("2803".into()),
                                );
                            }
                            let ch_value = serde_json::Value::Object(ch);
                            if !bt.append_characteristic_to_service(&ci, handle, ch_value.clone()) {
                                let mut svc = serde_json::Map::new();
                                svc.insert(
                                    "placeholder_entry".to_string(),
                                    serde_json::Value::Bool(true),
                                );
                                svc.insert(
                                    "utype".to_string(),
                                    serde_json::Value::String("2800".to_string()),
                                );
                                svc.insert("begin_handle".to_string(), serde_json::Value::from(1));
                                svc.insert(
                                    "end_handle".to_string(),
                                    serde_json::Value::from(0xFFFF_i64),
                                );
                                svc.insert(
                                    "UUID".to_string(),
                                    serde_json::Value::String("FFFF".to_string()),
                                );
                                svc.insert(
                                    "characteristics".to_string(),
                                    serde_json::Value::Array(vec![ch_value.clone()]),
                                );
                                if bt.verbose_btides {
                                    svc.insert(
                                        "type_str".to_string(),
                                        serde_json::Value::String("Primary Service".into()),
                                    );
                                }
                                bt.insert_dual_t2(
                                    &ci,
                                    serde_json::Value::Object(svc),
                                    "GATTArray",
                                    ch_value,
                                    "characteristics",
                                );
                            }
                            // Note: the READ_RSP-derived characteristic path
                            // does NOT emit ATT_handle_enumeration entries.
                            // Python's export_characteristic (used here) only
                            // calls BTIDES_export_GATT_Characteristic; the
                            // handle_enumeration side-effect is exclusive to
                            // the RBT_RSP-based path further down.
                        }
                    }
                }
            }
        }
        ATT_READ_BY_GROUP_TYPE_RSP => {
            let group_type = conns
                .by_aa
                .get(&aa)
                .map(|s| s.last_group_type.clone())
                .unwrap_or_else(|| "2800".to_string());
            if let Some(list) = entry.as_object().and_then(|m| m.get("attribute_data_list")).and_then(|v| v.as_array()) {
                for it in list.iter() {
                    if let Some(o) = it.as_object() {
                        let attr_handle = o.get("attribute_handle").and_then(|v| v.as_i64());
                        let end_group_handle = o.get("end_group_handle").and_then(|v| v.as_i64());
                        let uuid = o.get("UUID").and_then(|v| v.as_str()).map(|s| s.to_string());
                        if let (Some(begin), Some(end), Some(uuid)) = (attr_handle, end_group_handle, uuid) {
                            let mut gatt = serde_json::Map::new();
                            gatt.insert("utype".into(), serde_json::Value::String(group_type.clone()));
                            gatt.insert("UUID".into(), serde_json::Value::String(uuid));
                            gatt.insert("begin_handle".into(), serde_json::Value::from(begin));
                            gatt.insert("end_handle".into(), serde_json::Value::from(end));
                            if bt.verbose_btides {
                                gatt.insert(
                                    "type_str".into(),
                                    serde_json::Value::String(
                                        if group_type == "2801" {
                                            "Secondary Service".to_string()
                                        } else {
                                            "Primary Service".to_string()
                                        },
                                    ),
                                );
                            }
                            bt.insert_dual_t1(&ci, serde_json::Value::Object(gatt), "GATTArray");
                        }
                    }
                }
            }
        }
        ATT_READ_BY_TYPE_RSP => {
            // If the last READ_BY_TYPE_REQ asked for UUID 2803 ("Characteristic
            // Declaration"), each value is a 5- or 19-byte structure:
            //   properties(1) + value_handle(2 LE) + value_uuid(2 or 16 LE)
            // The attribute_handle in the response is the handle of the
            // Characteristic Declaration itself.
            let is_char_decl = conns
                .by_aa
                .get(&aa)
                .map(|s| s.last_read_by_type_uuid == "2803")
                .unwrap_or(false);
            if is_char_decl {
                if let Some(list) = entry
                    .as_object()
                    .and_then(|m| m.get("attribute_data_list"))
                    .and_then(|v| v.as_array())
                {
                    for it in list.iter() {
                        let Some(o) = it.as_object() else { continue };
                        let Some(handle) = o.get("attribute_handle").and_then(|v| v.as_i64()) else {
                            continue;
                        };
                        let Some(value_hex) = o.get("value_hex_str").and_then(|v| v.as_str()) else {
                            continue;
                        };
                        // value_hex is the raw bytes hex-encoded; need to decode to bytes.
                        let raw: Vec<u8> = (0..value_hex.len())
                            .step_by(2)
                            .filter_map(|i| u8::from_str_radix(value_hex.get(i..i + 2)?, 16).ok())
                            .collect();
                        if raw.len() < 5 {
                            continue;
                        }
                        let properties = raw[0] as i64;
                        let value_handle = u16::from_le_bytes([raw[1], raw[2]]) as i64;
                        let value_uuid = if raw.len() == 5 {
                            format!("{:02x}{:02x}", raw[4], raw[3])
                        } else if raw.len() == 19 {
                            let mut be = [0u8; 16];
                            for i in 0..16 {
                                be[i] = raw[3 + 15 - i];
                            }
                            BTIDES_model::hex_lower(&be)
                        } else {
                            continue;
                        };
                        let value_uuid = BTIDES_model::convert_uuid128_to_uuid16_if_possible(&value_uuid);
                        let mut ch = serde_json::Map::new();
                        ch.insert("handle".to_string(), serde_json::Value::from(handle));
                        ch.insert("properties".to_string(), serde_json::Value::from(properties));
                        ch.insert("value_handle".to_string(), serde_json::Value::from(value_handle));
                        ch.insert("value_uuid".to_string(), serde_json::Value::String(value_uuid.clone()));
                        if bt.verbose_btides {
                            ch.insert(
                                "type_str".to_string(),
                                serde_json::Value::String("Characteristic".into()),
                            );
                            ch.insert(
                                "utype".to_string(),
                                serde_json::Value::String("2803".into()),
                            );
                        }
                        let ch_value = serde_json::Value::Object(ch);
                        if !bt.append_characteristic_to_service(&ci, handle, ch_value.clone()) {
                            // No matching Service in GATTArray — Python's
                            // BTIDES_export_GATT_Characteristic builds a
                            // placeholder Primary Service covering the entire
                            // ATT handle range and embeds the characteristic
                            // inside it. The placeholder's primitive fields
                            // are all the same across invocations, so
                            // insert_dual_t2's tier1 dedup will merge new
                            // characteristics into the existing placeholder.
                            let mut svc = serde_json::Map::new();
                            svc.insert(
                                "placeholder_entry".to_string(),
                                serde_json::Value::Bool(true),
                            );
                            svc.insert(
                                "utype".to_string(),
                                serde_json::Value::String("2800".to_string()),
                            );
                            svc.insert("begin_handle".to_string(), serde_json::Value::from(1));
                            svc.insert(
                                "end_handle".to_string(),
                                serde_json::Value::from(0xFFFF_i64),
                            );
                            svc.insert(
                                "UUID".to_string(),
                                serde_json::Value::String("FFFF".to_string()),
                            );
                            svc.insert(
                                "characteristics".to_string(),
                                serde_json::Value::Array(vec![ch_value.clone()]),
                            );
                            if bt.verbose_btides {
                                svc.insert(
                                    "type_str".to_string(),
                                    serde_json::Value::String("Primary Service".into()),
                                );
                            }
                            bt.insert_dual_t2(
                                &ci,
                                serde_json::Value::Object(svc),
                                "GATTArray",
                                ch_value,
                                "characteristics",
                            );
                        }
                        // Python's export_ATT_Read_By_Type_Response (line ~720
                        // in scapy_to_BTIDES_common.py) emits two
                        // ATT_handle_enumeration entries per discovered
                        // characteristic: one tying the declaration handle to
                        // UUID "2803", and one tying the value handle to the
                        // characteristic's value_uuid (passed through
                        // ff_ATT_handle_entry which strips UUID128 dashes).
                        for (h, u) in [
                            (handle, "2803".to_string()),
                            (value_handle, value_uuid.clone()),
                        ] {
                            let mut he = serde_json::Map::new();
                            he.insert("handle".to_string(), serde_json::Value::from(h));
                            he.insert("UUID".to_string(), serde_json::Value::String(u));
                            let he_val = serde_json::Value::Object(he);
                            bt.insert_dual_t2(
                                &ci,
                                serde_json::json!({"ATT_handle_enumeration": [he_val.clone()]}),
                                "ATTArray",
                                he_val,
                                "ATT_handle_enumeration",
                            );
                        }
                    }
                }
            }
        }
        _ => {}
    }

    bt.insert_dual_t1(&ci, entry, "ATTArray");
}

fn att_error_rsp(verbose: bool, dir: u8, body: &[u8]) -> Option<Value> {
    if body.len() < 4 {
        return None;
    }
    let mut m = Map::new();
    m.insert("direction".to_string(), Value::from(dir));
    m.insert("opcode".to_string(), Value::from(ATT_ERROR_RSP));
    m.insert(
        "request_opcode_in_error".to_string(),
        Value::from(body[0] as i64),
    );
    m.insert(
        "attribute_handle_in_error".to_string(),
        Value::from(u16::from_le_bytes([body[1], body[2]]) as i64),
    );
    m.insert("error_code".to_string(), Value::from(body[3] as i64));
    if verbose {
        m.insert("opcode_str".to_string(), Value::String("ATT_ERROR_RSP".into()));
    }
    Some(Value::Object(m))
}

fn att_mtu_req(verbose: bool, dir: u8, body: &[u8]) -> Option<Value> {
    if body.len() < 2 {
        return None;
    }
    let mut m = Map::new();
    m.insert("direction".to_string(), Value::from(dir));
    m.insert("opcode".to_string(), Value::from(ATT_EXCHANGE_MTU_REQ));
    m.insert(
        "client_rx_mtu".to_string(),
        Value::from(u16::from_le_bytes([body[0], body[1]]) as i64),
    );
    if verbose {
        m.insert(
            "opcode_str".to_string(),
            Value::String("ATT_EXCHANGE_MTU_REQ".into()),
        );
    }
    Some(Value::Object(m))
}

fn att_mtu_rsp(verbose: bool, dir: u8, body: &[u8]) -> Option<Value> {
    if body.len() < 2 {
        return None;
    }
    let mut m = Map::new();
    m.insert("direction".to_string(), Value::from(dir));
    m.insert("opcode".to_string(), Value::from(ATT_EXCHANGE_MTU_RSP));
    m.insert(
        "server_rx_mtu".to_string(),
        Value::from(u16::from_le_bytes([body[0], body[1]]) as i64),
    );
    if verbose {
        m.insert(
            "opcode_str".to_string(),
            Value::String("ATT_EXCHANGE_MTU_RSP".into()),
        );
    }
    Some(Value::Object(m))
}

fn att_find_info_req(verbose: bool, dir: u8, body: &[u8]) -> Option<Value> {
    if body.len() < 4 {
        return None;
    }
    let mut m = Map::new();
    m.insert("direction".to_string(), Value::from(dir));
    m.insert("opcode".to_string(), Value::from(ATT_FIND_INFORMATION_REQ));
    m.insert(
        "start_handle".to_string(),
        Value::from(u16::from_le_bytes([body[0], body[1]]) as i64),
    );
    m.insert(
        "end_handle".to_string(),
        Value::from(u16::from_le_bytes([body[2], body[3]]) as i64),
    );
    if verbose {
        m.insert(
            "opcode_str".to_string(),
            Value::String("ATT_FIND_INFORMATION_REQ".into()),
        );
    }
    Some(Value::Object(m))
}

fn att_find_info_rsp(verbose: bool, dir: u8, body: &[u8]) -> Option<Value> {
    if body.is_empty() {
        return None;
    }
    let format = body[0];
    let entries = &body[1..];
    let item_size = match format {
        1 => 4, // handle(2) + UUID16(2)
        2 => 18, // handle(2) + UUID128(16)
        _ => return None,
    };
    let mut data = Vec::new();
    for chunk in entries.chunks_exact(item_size) {
        let handle = u16::from_le_bytes([chunk[0], chunk[1]]) as i64;
        let uuid = match format {
            // Format 1: UUID16, two LE bytes -> 4 hex chars, no dashes. Python:
            // `f"{handle_obj.value:04x}"` after passing through scapy's int decoder.
            1 => format!("{:02x}{:02x}", chunk[3], chunk[2]),
            // Format 2: UUID128. Python uses `str(handle_obj.value)` here, which
            // is scapy's UUID `__str__` -> canonical 8-4-4-4-12 dashed form. Keep
            // it dashed (do NOT pass through convert_uuid128_to_uuid16_if_possible,
            // which strips dashes).
            2 => {
                let mut be = [0u8; 16];
                for i in 0..16 {
                    be[i] = chunk[2 + 15 - i];
                }
                let hex = hex_lower(&be);
                format!(
                    "{}-{}-{}-{}-{}",
                    &hex[0..8],
                    &hex[8..12],
                    &hex[12..16],
                    &hex[16..20],
                    &hex[20..32]
                )
            }
            _ => unreachable!(),
        };
        let mut e = Map::new();
        e.insert("handle".to_string(), Value::from(handle));
        // Only collapse to UUID16 when it's actually a SIG-assigned alias (the
        // helper preserves dashes for non-aliases by short-circuiting on
        // len < 32 — our format=2 output is len 36).
        e.insert(
            "UUID".to_string(),
            Value::String(if format == 1 {
                convert_uuid128_to_uuid16_if_possible(&uuid)
            } else {
                // Python preserves dashes verbatim for UUID128 here, even when
                // the value would compress to a UUID16 (it just doesn't call
                // the compressor). Match that.
                uuid
            }),
        );
        data.push(Value::Object(e));
    }
    let mut m = Map::new();
    m.insert("direction".to_string(), Value::from(dir));
    m.insert("opcode".to_string(), Value::from(ATT_FIND_INFORMATION_RSP));
    m.insert("format".to_string(), Value::from(format as i64));
    m.insert("information_data".to_string(), Value::Array(data));
    if verbose {
        m.insert(
            "opcode_str".to_string(),
            Value::String("ATT_FIND_INFORMATION_RSP".into()),
        );
    }
    Some(Value::Object(m))
}

fn att_read_by_type_req(verbose: bool, dir: u8, body: &[u8]) -> Option<Value> {
    if body.len() < 6 {
        return None;
    }
    let start_handle = u16::from_le_bytes([body[0], body[1]]) as i64;
    let end_handle = u16::from_le_bytes([body[2], body[3]]) as i64;
    let uuid_bytes = &body[4..];
    // Python's scapy parses ATT_Read_By_Type_Request.uuid as a raw integer
    // (XLEShortField) for the UUID16 variant; that integer goes straight into
    // the BTIDES record. For the UUID128 variant scapy emits a UUID string.
    // The BTIDES schema technically says UUID16_hex_str is a string, but the
    // Python validator accepts the int — and we match Python's emission for
    // byte parity (rather than the stricter schema interpretation).
    let attr_uuid_value: Value = match uuid_bytes.len() {
        2 => Value::from(u16::from_le_bytes([uuid_bytes[0], uuid_bytes[1]]) as i64),
        16 => {
            let mut be = [0u8; 16];
            for i in 0..16 {
                be[i] = uuid_bytes[15 - i];
            }
            // For UUID128, Python uses scapy's UUID __str__ (dashed canonical).
            let hex = BTIDES_model::hex_lower(&be);
            Value::String(format!(
                "{}-{}-{}-{}-{}",
                &hex[0..8],
                &hex[8..12],
                &hex[12..16],
                &hex[16..20],
                &hex[20..32]
            ))
        }
        _ => return None,
    };
    let mut m = Map::new();
    m.insert("direction".to_string(), Value::from(dir));
    m.insert("opcode".to_string(), Value::from(ATT_READ_BY_TYPE_REQ));
    m.insert("start_handle".to_string(), Value::from(start_handle));
    m.insert("end_handle".to_string(), Value::from(end_handle));
    m.insert("attribute_uuid".to_string(), attr_uuid_value);
    if verbose {
        m.insert(
            "opcode_str".to_string(),
            Value::String("ATT_READ_BY_TYPE_REQ".into()),
        );
    }
    Some(Value::Object(m))
}

fn att_read_by_type_rsp(verbose: bool, dir: u8, body: &[u8]) -> Option<Value> {
    if body.is_empty() {
        return None;
    }
    let length = body[0] as usize;
    if length < 2 {
        return None;
    }
    let entries = &body[1..];
    let mut data = Vec::new();
    for chunk in entries.chunks_exact(length) {
        let h = u16::from_le_bytes([chunk[0], chunk[1]]) as i64;
        let val = &chunk[2..length];
        let mut e = Map::new();
        e.insert("attribute_handle".to_string(), Value::from(h));
        e.insert(
            "value_hex_str".to_string(),
            Value::String(hex_lower(val)),
        );
        data.push(Value::Object(e));
    }
    let mut m = Map::new();
    m.insert("direction".to_string(), Value::from(dir));
    m.insert("opcode".to_string(), Value::from(ATT_READ_BY_TYPE_RSP));
    m.insert("length".to_string(), Value::from(length as i64));
    m.insert("attribute_data_list".to_string(), Value::Array(data));
    if verbose {
        m.insert(
            "opcode_str".to_string(),
            Value::String("ATT_READ_BY_TYPE_RSP".into()),
        );
    }
    Some(Value::Object(m))
}

fn att_read_req(verbose: bool, dir: u8, body: &[u8]) -> Option<Value> {
    if body.len() < 2 {
        return None;
    }
    let mut m = Map::new();
    m.insert("direction".to_string(), Value::from(dir));
    m.insert("opcode".to_string(), Value::from(ATT_READ_REQ));
    m.insert(
        "handle".to_string(),
        Value::from(u16::from_le_bytes([body[0], body[1]]) as i64),
    );
    if verbose {
        m.insert("opcode_str".to_string(), Value::String("ATT_READ_REQ".into()));
    }
    Some(Value::Object(m))
}

fn att_read_rsp(verbose: bool, dir: u8, body: &[u8]) -> Option<Value> {
    // Empty payload → scapy doesn't instantiate the Read_Response sub-layer,
    // so Python's get_ATT_data() returns None and export_ATT_Read_Response
    // skips emission. Match that.
    if body.is_empty() {
        return None;
    }
    let mut m = Map::new();
    m.insert("direction".to_string(), Value::from(dir));
    m.insert("opcode".to_string(), Value::from(ATT_READ_RSP));
    m.insert(
        "value_hex_str".to_string(),
        Value::String(hex_lower(body)),
    );
    if verbose {
        m.insert("opcode_str".to_string(), Value::String("ATT_READ_RSP".into()));
    }
    Some(Value::Object(m))
}

fn att_rbgt_req(verbose: bool, dir: u8, body: &[u8]) -> Option<Value> {
    if body.len() < 6 {
        return None;
    }
    let start = u16::from_le_bytes([body[0], body[1]]) as i64;
    let end = u16::from_le_bytes([body[2], body[3]]) as i64;
    let gt = uuid_from_le(&body[4..])?;
    let mut m = Map::new();
    m.insert("direction".to_string(), Value::from(dir));
    m.insert("opcode".to_string(), Value::from(ATT_READ_BY_GROUP_TYPE_REQ));
    m.insert("start_handle".to_string(), Value::from(start));
    m.insert("end_handle".to_string(), Value::from(end));
    m.insert(
        "group_type".to_string(),
        Value::String(convert_uuid128_to_uuid16_if_possible(&gt)),
    );
    if verbose {
        m.insert(
            "opcode_str".to_string(),
            Value::String("ATT_READ_BY_GROUP_TYPE_REQ".into()),
        );
    }
    Some(Value::Object(m))
}

fn att_rbgt_rsp(verbose: bool, dir: u8, body: &[u8]) -> Option<Value> {
    if body.is_empty() {
        return None;
    }
    let length = body[0] as usize;
    if length < 4 {
        return None;
    }
    let entries = &body[1..];
    let mut data = Vec::new();
    for chunk in entries.chunks_exact(length) {
        let ah = u16::from_le_bytes([chunk[0], chunk[1]]) as i64;
        let egh = u16::from_le_bytes([chunk[2], chunk[3]]) as i64;
        let uuid_bytes = &chunk[4..length];
        let uuid = if uuid_bytes.len() == 2 {
            format!("{:02x}{:02x}", uuid_bytes[1], uuid_bytes[0])
        } else if uuid_bytes.len() == 16 {
            let mut be = [0u8; 16];
            for i in 0..16 {
                be[i] = uuid_bytes[15 - i];
            }
            hex_lower(&be)
        } else {
            continue;
        };
        let mut e = Map::new();
        e.insert("attribute_handle".to_string(), Value::from(ah));
        e.insert("end_group_handle".to_string(), Value::from(egh));
        e.insert(
            "UUID".to_string(),
            Value::String(convert_uuid128_to_uuid16_if_possible(&uuid)),
        );
        data.push(Value::Object(e));
    }
    let mut m = Map::new();
    m.insert("direction".to_string(), Value::from(dir));
    m.insert("opcode".to_string(), Value::from(ATT_READ_BY_GROUP_TYPE_RSP));
    m.insert("length".to_string(), Value::from(length as i64));
    m.insert("attribute_data_list".to_string(), Value::Array(data));
    if verbose {
        m.insert(
            "opcode_str".to_string(),
            Value::String("ATT_READ_BY_GROUP_TYPE_RSP".into()),
        );
    }
    Some(Value::Object(m))
}

fn uuid_from_le(b: &[u8]) -> Option<String> {
    if b.len() == 2 {
        Some(format!("{:02x}{:02x}", b[1], b[0]))
    } else if b.len() == 16 {
        let mut be = [0u8; 16];
        for i in 0..16 {
            be[i] = b[15 - i];
        }
        Some(hex_lower(&be))
    } else {
        None
    }
}
