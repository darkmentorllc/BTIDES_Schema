// AdvData TLV parsing. The wire format is a sequence of `[len][type][data...]`
// records where `len` covers `type + data`. Each known TLV type is converted
// into the BTIDES dict shape defined in BTIDES_Schema/BTIDES_AdvData.json and
// pushed via Btides::insert_single_t2 (wrapper AdvChanData -> AdvDataArray).

use BTIDES_model::{convert_uuid128_to_uuid16_if_possible, hex_lower, Btides};
use serde_json::{Map, Value};

use crate::types::*;

/// Walk a raw AdvData byte slice and emit a per-TLV BTIDES record for every
/// recognized type. Returns true if at least one TLV produced an export.
pub fn export_all_tlvs(
    bt: &mut Btides,
    bdaddr: &str,
    rand: i64,
    btides_type: u8,
    btides_type_str: &str,
    data: &[u8],
) -> bool {
    let mut any = false;
    let mut i = 0usize;
    while i < data.len() {
        let len = data[i] as usize;
        if len == 0 {
            break;
        }
        if i + 1 + len > data.len() {
            break;
        }
        let ad_type = data[i + 1];
        let body = &data[i + 2..i + 1 + len];
        if let Some(entry) = ff_adv_data_entry(bt.verbose_btides, ad_type, body, len as i64) {
            // Python pre-attaches AdvDataArray to the tier1 wrapper before calling
            // generic_SingleBDADDR_insertion_into_BTIDES_second_level_array so the
            // key-set equality check on the tier1 dedup succeeds against existing
            // entries (which always carry AdvDataArray). Mirror that here.
            let mut wrapper = Map::new();
            wrapper.insert("type".to_string(), Value::from(btides_type));
            if bt.verbose_btides {
                wrapper.insert(
                    "type_str".to_string(),
                    Value::String(btides_type_str.to_string()),
                );
            }
            wrapper.insert(
                "AdvDataArray".to_string(),
                Value::Array(vec![entry.clone()]),
            );
            if bt.insert_single_t2(
                bdaddr,
                rand,
                Value::Object(wrapper),
                "AdvChanArray",
                entry,
                "AdvDataArray",
            ) {
                any = true;
            }
        }
        i += 1 + len;
    }
    any
}

fn ff_adv_data_entry(verbose: bool, ad_type: u8, body: &[u8], length: i64) -> Option<Value> {
    // Python's scapy_to_BTIDES_common.py:export_AdvData computes an expected
    // length for the TLV (`1 + N*item_size`) and calls exit_on_len_mismatch.
    // If the declared TLV length doesn't match the parsed body size, Python
    // returns False and nothing is emitted. Mirror that here per-type.
    //
    // Additionally: scapy doesn't instantiate `EIR_*` sub-layers when the
    // payload is empty (`length == 1`, only type byte). So name-style TLVs
    // with body.is_empty() are silently dropped on the Python side.
    match ad_type {
        ADV_FLAGS => {
            if body.len() != 1 {
                return None;
            }
            let mut m = Map::new();
            m.insert("type".to_string(), Value::from(1));
            m.insert("length".to_string(), Value::from(length));
            m.insert(
                "flags_hex_str".to_string(),
                Value::String(format!("{:02x}", body[0])),
            );
            if verbose {
                m.insert("type_str".to_string(), Value::String("Flags".into()));
            }
            Some(Value::Object(m))
        }
        ADV_UUID16_LIST_INCOMPLETE | ADV_UUID16_LIST_COMPLETE => {
            if !body.is_empty() && body.len() % 2 != 0 {
                return None;
            }
            let list: Vec<Value> = body
                .chunks_exact(2)
                .map(|c| {
                    Value::String(format!("{:02x}{:02x}", c[1], c[0]))
                })
                .collect();
            let mut m = Map::new();
            m.insert("type".to_string(), Value::from(ad_type));
            m.insert("length".to_string(), Value::from(length));
            m.insert("UUID16List".to_string(), Value::Array(list));
            if verbose {
                m.insert(
                    "type_str".to_string(),
                    Value::String(
                        if ad_type == ADV_UUID16_LIST_INCOMPLETE {
                            "UUID16ListIncomplete".to_string()
                        } else {
                            "UUID16ListComplete".to_string()
                        },
                    ),
                );
            }
            Some(Value::Object(m))
        }
        ADV_UUID32_LIST_INCOMPLETE | ADV_UUID32_LIST_COMPLETE => {
            if !body.is_empty() && body.len() % 4 != 0 {
                return None;
            }
            let list: Vec<Value> = body
                .chunks_exact(4)
                .map(|c| Value::String(format!("{:02x}{:02x}{:02x}{:02x}", c[3], c[2], c[1], c[0])))
                .collect();
            let mut m = Map::new();
            m.insert("type".to_string(), Value::from(ad_type));
            m.insert("length".to_string(), Value::from(length));
            m.insert("UUID32List".to_string(), Value::Array(list));
            if verbose {
                m.insert(
                    "type_str".to_string(),
                    Value::String(
                        if ad_type == ADV_UUID32_LIST_INCOMPLETE {
                            "UUID32ListIncomplete".to_string()
                        } else {
                            "UUID32ListComplete".to_string()
                        },
                    ),
                );
            }
            Some(Value::Object(m))
        }
        ADV_UUID128_LIST_INCOMPLETE | ADV_UUID128_LIST_COMPLETE => {
            if !body.is_empty() && body.len() % 16 != 0 {
                return None;
            }
            // Python emits these via `str(uuid)` (scapy UUID __str__), which is
            // the canonical 8-4-4-4-12 dashed form. Match it.
            let list: Vec<Value> = body
                .chunks_exact(16)
                .map(|c| {
                    let mut be = [0u8; 16];
                    for i in 0..16 {
                        be[i] = c[15 - i];
                    }
                    let hex = hex_lower(&be);
                    Value::String(format!(
                        "{}-{}-{}-{}-{}",
                        &hex[0..8],
                        &hex[8..12],
                        &hex[12..16],
                        &hex[16..20],
                        &hex[20..32]
                    ))
                })
                .collect();
            let mut m = Map::new();
            m.insert("type".to_string(), Value::from(ad_type));
            m.insert("length".to_string(), Value::from(length));
            m.insert("UUID128List".to_string(), Value::Array(list));
            if verbose {
                m.insert(
                    "type_str".to_string(),
                    Value::String(
                        if ad_type == ADV_UUID128_LIST_INCOMPLETE {
                            "UUID128ListIncomplete".to_string()
                        } else {
                            "UUID128ListComplete".to_string()
                        },
                    ),
                );
            }
            Some(Value::Object(m))
        }
        ADV_INCOMPLETE_NAME | ADV_COMPLETE_NAME | ADV_BROADCAST_NAME => {
            // scapy doesn't produce an EIR_*LocalName sub-layer for empty
            // bodies (length == 1), so Python silently drops these TLVs.
            if body.is_empty() {
                return None;
            }
            let name_hex = hex_lower(body);
            let mut m = Map::new();
            m.insert("type".to_string(), Value::from(ad_type));
            m.insert("length".to_string(), Value::from(length));
            m.insert("name_hex_str".to_string(), Value::String(name_hex));
            if verbose {
                let label = match ad_type {
                    ADV_INCOMPLETE_NAME => "IncompleteName",
                    ADV_COMPLETE_NAME => "CompleteName",
                    _ => "BroadcastName",
                };
                m.insert("type_str".to_string(), Value::String(label.to_string()));
                if let Ok(s) = std::str::from_utf8(body) {
                    let s = s.trim_end_matches('\0');
                    if !s.is_empty() {
                        m.insert("utf8_name".to_string(), Value::String(s.to_string()));
                    }
                }
            }
            Some(Value::Object(m))
        }
        ADV_TX_POWER => {
            if body.is_empty() {
                return None;
            }
            let mut m = Map::new();
            m.insert("type".to_string(), Value::from(10));
            m.insert("length".to_string(), Value::from(length));
            m.insert("tx_power".to_string(), Value::from(body[0] as i8 as i64));
            if verbose {
                m.insert("type_str".to_string(), Value::String("TxPower".into()));
            }
            Some(Value::Object(m))
        }
        ADV_CLASS_OF_DEVICE => {
            if body.len() < 3 {
                return None;
            }
            let mut m = Map::new();
            m.insert("type".to_string(), Value::from(13));
            m.insert("length".to_string(), Value::from(length));
            m.insert(
                "CoD_hex_str".to_string(),
                Value::String(hex_lower(&body[..3])),
            );
            if verbose {
                m.insert("type_str".to_string(), Value::String("ClassOfDevice".into()));
            }
            Some(Value::Object(m))
        }
        ADV_DEVICE_ID => {
            if body.len() < 8 {
                return None;
            }
            let vid_source = u16::from_le_bytes([body[0], body[1]]) as i64;
            let vid = u16::from_le_bytes([body[2], body[3]]) as i64;
            let pid = u16::from_le_bytes([body[4], body[5]]) as i64;
            let ver = u16::from_le_bytes([body[6], body[7]]) as i64;
            let mut m = Map::new();
            m.insert("type".to_string(), Value::from(16));
            m.insert("length".to_string(), Value::from(length));
            m.insert("vendor_id_source".to_string(), Value::from(vid_source));
            m.insert("vendor_id".to_string(), Value::from(vid));
            m.insert("product_id".to_string(), Value::from(pid));
            m.insert("version".to_string(), Value::from(ver));
            if verbose {
                m.insert("type_str".to_string(), Value::String("DeviceID".into()));
            }
            Some(Value::Object(m))
        }
        ADV_PERIPHERAL_CONNECTION_INTERVAL_RANGE => {
            if body.len() < 4 {
                return None;
            }
            let min = u16::from_le_bytes([body[0], body[1]]) as i64;
            let max = u16::from_le_bytes([body[2], body[3]]) as i64;
            let mut m = Map::new();
            m.insert("type".to_string(), Value::from(18));
            m.insert("length".to_string(), Value::from(length));
            m.insert("conn_interval_min".to_string(), Value::from(min));
            m.insert("conn_interval_max".to_string(), Value::from(max));
            if verbose {
                m.insert(
                    "type_str".to_string(),
                    Value::String("PeripheralConnectionIntervalRange".into()),
                );
            }
            Some(Value::Object(m))
        }
        ADV_UUID16_LIST_SERVICE_SOLICITATION => {
            let list: Vec<Value> = body
                .chunks_exact(2)
                .map(|c| Value::String(format!("{:02x}{:02x}", c[1], c[0])))
                .collect();
            let mut m = Map::new();
            m.insert("type".to_string(), Value::from(20));
            m.insert("length".to_string(), Value::from(length));
            m.insert("UUID16List".to_string(), Value::Array(list));
            if verbose {
                m.insert(
                    "type_str".to_string(),
                    Value::String("UUID16ListServiceSolicitation".into()),
                );
            }
            Some(Value::Object(m))
        }
        ADV_UUID128_LIST_SERVICE_SOLICITATION => {
            let list: Vec<Value> = body
                .chunks_exact(16)
                .map(|c| {
                    let mut be = [0u8; 16];
                    for i in 0..16 {
                        be[i] = c[15 - i];
                    }
                    Value::String(hex_lower(&be))
                })
                .collect();
            let mut m = Map::new();
            m.insert("type".to_string(), Value::from(21));
            m.insert("length".to_string(), Value::from(length));
            m.insert("UUID128List".to_string(), Value::Array(list));
            if verbose {
                m.insert(
                    "type_str".to_string(),
                    Value::String("UUID128ListServiceSolicitation".into()),
                );
            }
            Some(Value::Object(m))
        }
        ADV_UUID16_SERVICE_DATA => {
            if body.len() < 2 {
                return None;
            }
            let uuid = format!("{:02x}{:02x}", body[1], body[0]);
            let sd = hex_lower(&body[2..]);
            let mut m = Map::new();
            m.insert("type".to_string(), Value::from(22));
            m.insert("length".to_string(), Value::from(length));
            m.insert(
                "UUID16".to_string(),
                Value::String(convert_uuid128_to_uuid16_if_possible(&uuid)),
            );
            m.insert("service_data_hex_str".to_string(), Value::String(sd));
            if verbose {
                m.insert(
                    "type_str".to_string(),
                    Value::String("UUID16ServiceData".into()),
                );
            }
            Some(Value::Object(m))
        }
        ADV_UUID32_SERVICE_DATA => {
            if body.len() < 4 {
                return None;
            }
            let uuid = format!("{:02x}{:02x}{:02x}{:02x}", body[3], body[2], body[1], body[0]);
            let sd = hex_lower(&body[4..]);
            let mut m = Map::new();
            m.insert("type".to_string(), Value::from(32));
            m.insert("length".to_string(), Value::from(length));
            m.insert("UUID32".to_string(), Value::String(uuid));
            m.insert("service_data_hex_str".to_string(), Value::String(sd));
            if verbose {
                m.insert(
                    "type_str".to_string(),
                    Value::String("UUID32ServiceData".into()),
                );
            }
            Some(Value::Object(m))
        }
        ADV_UUID128_SERVICE_DATA => {
            if body.len() < 16 {
                return None;
            }
            let mut be = [0u8; 16];
            for i in 0..16 {
                be[i] = body[15 - i];
            }
            let uuid = hex_lower(&be);
            let sd = hex_lower(&body[16..]);
            let mut m = Map::new();
            m.insert("type".to_string(), Value::from(33));
            m.insert("length".to_string(), Value::from(length));
            m.insert(
                "UUID128".to_string(),
                Value::String(convert_uuid128_to_uuid16_if_possible(&uuid)),
            );
            m.insert("service_data_hex_str".to_string(), Value::String(sd));
            if verbose {
                m.insert(
                    "type_str".to_string(),
                    Value::String("UUID128ServiceData".into()),
                );
            }
            Some(Value::Object(m))
        }
        ADV_PUBLIC_TARGET_ADDRESS => {
            if body.len() < 6 {
                return None;
            }
            let mut m = Map::new();
            m.insert("type".to_string(), Value::from(23));
            m.insert("length".to_string(), Value::from(length));
            m.insert(
                "public_bdaddr".to_string(),
                Value::String(BTIDES_model::bdaddr_from_le_bytes(&body[..6])),
            );
            if verbose {
                m.insert(
                    "type_str".to_string(),
                    Value::String("PublicTargetAddress".into()),
                );
            }
            Some(Value::Object(m))
        }
        ADV_RANDOM_TARGET_ADDRESS => {
            if body.len() < 6 {
                return None;
            }
            let mut m = Map::new();
            m.insert("type".to_string(), Value::from(24));
            m.insert("length".to_string(), Value::from(length));
            m.insert(
                "random_bdaddr".to_string(),
                Value::String(BTIDES_model::bdaddr_from_le_bytes(&body[..6])),
            );
            if verbose {
                m.insert(
                    "type_str".to_string(),
                    Value::String("RandomTargetAddress".into()),
                );
            }
            Some(Value::Object(m))
        }
        ADV_APPEARANCE => {
            if body.len() < 2 {
                return None;
            }
            let hex_str = format!("{:02x}{:02x}", body[1], body[0]);
            let mut m = Map::new();
            m.insert("type".to_string(), Value::from(25));
            m.insert("length".to_string(), Value::from(length));
            m.insert("appearance_hex_str".to_string(), Value::String(hex_str));
            if verbose {
                m.insert("type_str".to_string(), Value::String("Appearance".into()));
            }
            Some(Value::Object(m))
        }
        ADV_ADVERTISING_INTERVAL => {
            let interval: i64 = match body.len() {
                2 => u16::from_le_bytes([body[0], body[1]]) as i64,
                3 => u32::from_le_bytes([body[0], body[1], body[2], 0]) as i64,
                4 => u32::from_le_bytes([body[0], body[1], body[2], body[3]]) as i64,
                _ => return None,
            };
            let mut m = Map::new();
            m.insert("type".to_string(), Value::from(26));
            m.insert("length".to_string(), Value::from(length));
            m.insert("advertising_interval".to_string(), Value::from(interval));
            if verbose {
                m.insert(
                    "type_str".to_string(),
                    Value::String("AdvertisingInterval".into()),
                );
            }
            Some(Value::Object(m))
        }
        ADV_LE_BDADDR => {
            if body.len() < 7 {
                return None;
            }
            let bdaddr_type = body[0] as i64;
            let mut m = Map::new();
            m.insert("type".to_string(), Value::from(27));
            m.insert("length".to_string(), Value::from(length));
            m.insert("bdaddr_type".to_string(), Value::from(bdaddr_type));
            m.insert(
                "le_bdaddr".to_string(),
                Value::String(BTIDES_model::bdaddr_from_le_bytes(&body[1..7])),
            );
            if verbose {
                m.insert("type_str".to_string(), Value::String("LE_BDADDR".into()));
            }
            Some(Value::Object(m))
        }
        ADV_LE_ROLE => {
            if body.is_empty() {
                return None;
            }
            let mut m = Map::new();
            m.insert("type".to_string(), Value::from(28));
            m.insert("length".to_string(), Value::from(length));
            m.insert("role".to_string(), Value::from(body[0] as i64));
            if verbose {
                m.insert("type_str".to_string(), Value::String("LE_Role".into()));
            }
            Some(Value::Object(m))
        }
        ADV_UUID32_LIST_SERVICE_SOLICITATION => {
            let list: Vec<Value> = body
                .chunks_exact(4)
                .map(|c| Value::String(format!("{:02x}{:02x}{:02x}{:02x}", c[3], c[2], c[1], c[0])))
                .collect();
            let mut m = Map::new();
            m.insert("type".to_string(), Value::from(31));
            m.insert("length".to_string(), Value::from(length));
            m.insert("UUID32List".to_string(), Value::Array(list));
            if verbose {
                m.insert(
                    "type_str".to_string(),
                    Value::String("UUID32ListServiceSolicitation".into()),
                );
            }
            Some(Value::Object(m))
        }
        ADV_URI => {
            let mut m = Map::new();
            m.insert("type".to_string(), Value::from(36));
            m.insert("length".to_string(), Value::from(length));
            m.insert("uri_hex_str".to_string(), Value::String(hex_lower(body)));
            if verbose {
                m.insert("type_str".to_string(), Value::String("URI".into()));
            }
            Some(Value::Object(m))
        }
        ADV_LE_SUPPORTED_FEATURES => {
            // Schema wants exactly 16 hex chars; if body shorter, pad LE-style.
            let mut le = [0u8; 8];
            let n = body.len().min(8);
            le[..n].copy_from_slice(&body[..n]);
            let mut m = Map::new();
            m.insert("type".to_string(), Value::from(39));
            m.insert("length".to_string(), Value::from(length));
            m.insert(
                "le_features_hex_str".to_string(),
                Value::String(hex_lower(&le)),
            );
            if verbose {
                m.insert(
                    "type_str".to_string(),
                    Value::String("LESupportedFeatures".into()),
                );
            }
            Some(Value::Object(m))
        }
        ADV_ENCRYPTED_ADV_DATA => {
            let mut m = Map::new();
            m.insert("type".to_string(), Value::from(49));
            m.insert("length".to_string(), Value::from(length));
            m.insert(
                "enc_adv_data_hex_str".to_string(),
                Value::String(hex_lower(body)),
            );
            if verbose {
                m.insert(
                    "type_str".to_string(),
                    Value::String("EncryptedAdvertisingData".into()),
                );
            }
            Some(Value::Object(m))
        }
        ADV_3D_INFO_DATA => {
            if body.len() < 2 {
                return None;
            }
            let mut m = Map::new();
            m.insert("type".to_string(), Value::from(61));
            m.insert("length".to_string(), Value::from(length));
            m.insert("byte1".to_string(), Value::from(body[0] as i64));
            m.insert("path_loss".to_string(), Value::from(body[1] as i64));
            if verbose {
                m.insert("type_str".to_string(), Value::String("3DInfoData".into()));
            }
            Some(Value::Object(m))
        }
        ADV_MSD => {
            if body.len() < 2 {
                return None;
            }
            // Python stores company id LE: e.g. bytes 4C 00 -> "004c". Two-byte LE
            // value, then formatted as uppercase-hex MSB-first... Actually Python:
            //   company_id_hex_str = f"{bytes[0]:02X}{bytes[1]:02X}"
            // Wait actually it's `bytes_to_hex_str(packet bytes[0:2])` reversed.
            // Looking at scapy MSD parsing: the company_id is parsed as 2 bytes LE.
            // The hex string format the Python uses for MSD company_id_hex_str:
            // "First 2 bytes of the MSD, interpreted as a little-endian company ID.
            // e.g. first 2 bytes were 0x4C 0x00 it should be \"004C\" (Apple)."
            // → that means: byte[1]<<8 | byte[0] formatted as %04X.
            let cid = u16::from_le_bytes([body[0], body[1]]);
            let mut m = Map::new();
            m.insert("type".to_string(), Value::from(255));
            m.insert("length".to_string(), Value::from(length));
            m.insert(
                "company_id_hex_str".to_string(),
                Value::String(format!("{:04x}", cid)),
            );
            m.insert(
                "msd_hex_str".to_string(),
                Value::String(hex_lower(&body[2..])),
            );
            if verbose {
                m.insert(
                    "type_str".to_string(),
                    Value::String("ManufacturerSpecificData".into()),
                );
            }
            Some(Value::Object(m))
        }
        _ => None,
    }
}
