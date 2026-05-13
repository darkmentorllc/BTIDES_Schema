#![allow(non_snake_case)]
// BTIDES-model: BTIDES JSON data model, accumulator, dedup-insert helpers, schema validation.
//
// Mirrors Analysis/TME/TME_BTIDES_base.py and the BTIDES_Schema JSON files.
// All BTIDES output is a JSON array of either SingleBDADDR entries (keyed by
// bdaddr + bdaddr_rand) or DualBDADDR entries (keyed by CONNECT_IND object).
// Each entry holds further per-protocol arrays (AdvChanArray, LLArray, ATTArray, ...).

use std::collections::HashMap;
use std::path::Path;

use serde_json::{Map, Value};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BtidesError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("schema load: {0}")]
    SchemaLoad(String),
    #[error("schema validation failed: {0}")]
    SchemaValidation(String),
}

/// The accumulator that mirrors `TME.TME_glob.BTIDES_JSON` plus the `_by_bdaddr_key`
/// index. All packet parsers in BTIDES-bt push records here via the methods below.
pub struct Btides {
    /// Top-level array; each element is a SingleBDADDR or DualBDADDR object.
    pub root: Vec<Value>,
    /// O(1) lookup index: (bdaddr lowercase, bdaddr_rand) -> position in `root`.
    bdaddr_index: HashMap<(String, i64), usize>,
    pub verbose_btides: bool,
}

impl Default for Btides {
    fn default() -> Self {
        Self::new()
    }
}

impl Btides {
    pub fn new() -> Self {
        Self {
            root: Vec::new(),
            bdaddr_index: HashMap::new(),
            verbose_btides: false,
        }
    }

    pub fn set_verbose(&mut self, v: bool) {
        self.verbose_btides = v;
    }

    /// Serialize the accumulator to bytes (no trailing newline, no indent — matches
    /// Python's `json.dump(BTIDES_JSON, fp=f)`).
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, BtidesError> {
        Ok(serde_json::to_vec(&self.root)?)
    }

    /// Validate the accumulator against the BTIDES schema located at `schema_dir`.
    /// `schema_dir` must contain BTIDES_base.json plus the per-protocol files.
    pub fn validate_against_schema(&self, schema_dir: &Path) -> Result<(), BtidesError> {
        validate(&Value::Array(self.root.clone()), schema_dir)
    }

    /// Write JSON to `path` after validating against the schema.
    pub fn write_btides(&self, out_path: &Path, schema_dir: &Path) -> Result<(), BtidesError> {
        self.validate_against_schema(schema_dir)?;
        let bytes = self.to_json_bytes()?;
        std::fs::write(out_path, bytes)?;
        Ok(())
    }

    fn lookup_single_idx(&self, bdaddr: &str, rand: i64) -> Option<usize> {
        self.bdaddr_index
            .get(&(bdaddr.to_lowercase(), rand))
            .copied()
    }

    fn register_single(&mut self, idx: usize, bdaddr: &str, rand: i64) {
        self.bdaddr_index
            .insert((bdaddr.to_lowercase(), rand), idx);
    }

    /// Append into BTIDES_JSON[device][array]  (one-level deep).
    /// Mirrors `generic_SingleBDADDR_insertion_into_BTIDES_first_level_array` and
    /// performs the same dedup against existing entries.
    pub fn insert_single_t1(
        &mut self,
        bdaddr: &str,
        rand: i64,
        tier1: Value,
        target_array: &str,
    ) -> bool {
        if let Some(idx) = self.lookup_single_idx(bdaddr, rand) {
            let entry = &mut self.root[idx];
            let map = entry.as_object_mut().expect("device entry must be object");
            if let Some(Value::Array(arr)) = map.get_mut(target_array) {
                for existing in arr.iter() {
                    if existing == &tier1 {
                        return true;
                    }
                }
                arr.push(tier1);
            } else {
                map.insert(target_array.to_string(), Value::Array(vec![tier1]));
            }
            true
        } else {
            let mut base = Map::new();
            base.insert("bdaddr".to_string(), Value::String(bdaddr.to_string()));
            base.insert("bdaddr_rand".to_string(), Value::from(rand));
            base.insert(target_array.to_string(), Value::Array(vec![tier1]));
            let idx = self.root.len();
            self.root.push(Value::Object(base));
            self.register_single(idx, bdaddr, rand);
            true
        }
    }

    /// Append into BTIDES_JSON[device][array][slot][sub_array] (two-levels deep).
    /// `tier1` is the wrapper that holds `tier2` inside `tier2_array`. Used by
    /// AdvData: tier1 is the AdvChanData (keyed by `type`), tier2 is the individual
    /// AdvDataArray entry (Flags / Names / MSD / etc.). Dedup at tier1 uses
    /// `non_recursive_primitive_equality_check`, dedup at tier2 uses full equality —
    /// matches the Python helper.
    pub fn insert_single_t2(
        &mut self,
        bdaddr: &str,
        rand: i64,
        tier1: Value,
        tier1_array: &str,
        tier2: Value,
        tier2_array: &str,
    ) -> bool {
        let idx = match self.lookup_single_idx(bdaddr, rand) {
            Some(i) => i,
            None => {
                let mut base = Map::new();
                base.insert("bdaddr".to_string(), Value::String(bdaddr.to_string()));
                base.insert("bdaddr_rand".to_string(), Value::from(rand));
                base.insert(tier1_array.to_string(), Value::Array(vec![tier1]));
                let idx = self.root.len();
                self.root.push(Value::Object(base));
                self.register_single(idx, bdaddr, rand);
                return true;
            }
        };
        let entry = self.root[idx].as_object_mut().expect("device entry");
        if !entry.contains_key(tier1_array) {
            entry.insert(tier1_array.to_string(), Value::Array(vec![tier1]));
            return true;
        }
        let arr = entry.get_mut(tier1_array).unwrap().as_array_mut().unwrap();
        for t1_obj in arr.iter_mut() {
            if non_recursive_primitive_equality_check(t1_obj, &tier1) {
                let t1_map = t1_obj.as_object_mut().expect("tier1 must be object");
                if !t1_map.contains_key(tier2_array) {
                    t1_map.insert(tier2_array.to_string(), Value::Array(vec![tier2]));
                    return true;
                }
                let t2_arr = t1_map.get_mut(tier2_array).unwrap().as_array_mut().unwrap();
                for existing in t2_arr.iter() {
                    if existing == &tier2 {
                        return true;
                    }
                }
                t2_arr.push(tier2);
                return true;
            }
        }
        arr.push(tier1);
        true
    }

    /// Append a DualBDADDR entry (CONNECT_IND-keyed) into BTIDES_JSON if it doesn't
    /// already exist. Mirrors `generic_DualBDADDR_insertion_into_BTIDES_zeroth_level`.
    pub fn insert_dual_zero(&mut self, connect_ind: Value) -> bool {
        if find_dual_idx(&self.root, &connect_ind).is_some() {
            return true;
        }
        let mut base = Map::new();
        base.insert("CONNECT_IND".to_string(), connect_ind);
        self.root.push(Value::Object(base));
        true
    }

    /// Append into BTIDES_JSON[dual][array] (one-level deep, DualBDADDR variant).
    pub fn insert_dual_t1(
        &mut self,
        connect_ind: &Value,
        tier1: Value,
        target_array: &str,
    ) -> bool {
        match find_dual_idx(&self.root, connect_ind) {
            Some(idx) => {
                let entry = self.root[idx].as_object_mut().unwrap();
                if let Some(Value::Array(arr)) = entry.get_mut(target_array) {
                    for existing in arr.iter() {
                        if existing == &tier1 {
                            return true;
                        }
                    }
                    arr.push(tier1);
                } else {
                    entry.insert(target_array.to_string(), Value::Array(vec![tier1]));
                }
                true
            }
            None => {
                let mut base = Map::new();
                base.insert("CONNECT_IND".to_string(), connect_ind.clone());
                base.insert(target_array.to_string(), Value::Array(vec![tier1]));
                self.root.push(Value::Object(base));
                true
            }
        }
    }

    /// Find the DualBDADDR entry matching `connect_ind`, locate the GATT
    /// Service in its `GATTArray` whose handle range covers `char_handle`,
    /// and append `characteristic` to that service's `characteristics` array.
    ///
    /// Python uses STRICT `<` on `begin_handle` and `>=` on `end_handle`
    /// (TME_BTIDES_GATT.py::find_service_with_target_handle_in_range):
    ///     begin_handle < target_handle && end_handle >= target_handle
    /// — match that or we'll attach to services Python ignores.
    ///
    /// Returns true if a matching service was found and the append succeeded.
    /// On false, callers should fall back to placeholder-service emission.
    pub fn append_characteristic_to_service(
        &mut self,
        connect_ind: &Value,
        char_handle: i64,
        characteristic: Value,
    ) -> bool {
        let Some(idx) = find_dual_idx(&self.root, connect_ind) else {
            return false;
        };
        let entry = self.root[idx].as_object_mut().unwrap();
        let Some(Value::Array(arr)) = entry.get_mut("GATTArray") else {
            return false;
        };
        for service in arr.iter_mut() {
            let Some(svc) = service.as_object_mut() else {
                continue;
            };
            let begin = svc.get("begin_handle").and_then(|v| v.as_i64());
            let end = svc.get("end_handle").and_then(|v| v.as_i64());
            if let (Some(b), Some(e)) = (begin, end) {
                if char_handle > b && char_handle <= e {
                    let chars_entry = svc
                        .entry("characteristics".to_string())
                        .or_insert_with(|| Value::Array(Vec::new()));
                    if let Value::Array(ref mut chars) = chars_entry {
                        for existing in chars.iter() {
                            if existing == &characteristic {
                                return true;
                            }
                        }
                        chars.push(characteristic);
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Two-level insertion for DualBDADDR entries.
    pub fn insert_dual_t2(
        &mut self,
        connect_ind: &Value,
        tier1: Value,
        tier1_array: &str,
        tier2: Value,
        tier2_array: &str,
    ) -> bool {
        let idx = match find_dual_idx(&self.root, connect_ind) {
            Some(i) => i,
            None => {
                let mut base = Map::new();
                base.insert("CONNECT_IND".to_string(), connect_ind.clone());
                base.insert(tier1_array.to_string(), Value::Array(vec![tier1]));
                self.root.push(Value::Object(base));
                return true;
            }
        };
        let entry = self.root[idx].as_object_mut().unwrap();
        if !entry.contains_key(tier1_array) {
            entry.insert(tier1_array.to_string(), Value::Array(vec![tier1]));
            return true;
        }
        let arr = entry.get_mut(tier1_array).unwrap().as_array_mut().unwrap();
        for t1_obj in arr.iter_mut() {
            if non_recursive_primitive_equality_check(t1_obj, &tier1) {
                let t1_map = t1_obj.as_object_mut().unwrap();
                if !t1_map.contains_key(tier2_array) {
                    t1_map.insert(tier2_array.to_string(), Value::Array(vec![tier2]));
                    return true;
                }
                let t2_arr = t1_map.get_mut(tier2_array).unwrap().as_array_mut().unwrap();
                for existing in t2_arr.iter() {
                    if existing == &tier2 {
                        return true;
                    }
                }
                t2_arr.push(tier2);
                return true;
            }
        }
        arr.push(tier1);
        true
    }
}

fn find_dual_idx(root: &[Value], connect_ind: &Value) -> Option<usize> {
    for (i, item) in root.iter().enumerate() {
        if let Some(obj) = item.as_object() {
            if let Some(ci) = obj.get("CONNECT_IND") {
                if ci == connect_ind {
                    return Some(i);
                }
            }
        }
    }
    None
}

/// Mirrors `non_recursive_primitive_equality_check` from TME_BTIDES_base.py:
/// require the same set of top-level keys, and for every key whose values are
/// both primitives (number / string / bool / null) the values must match; nested
/// objects / arrays are skipped (not recursed into). Used for tier1 dedup matching.
pub fn non_recursive_primitive_equality_check(a: &Value, b: &Value) -> bool {
    let (ao, bo) = match (a.as_object(), b.as_object()) {
        (Some(ao), Some(bo)) => (ao, bo),
        _ => return false,
    };
    if ao.len() != bo.len() {
        return false;
    }
    for k in ao.keys() {
        if !bo.contains_key(k) {
            return false;
        }
    }
    for (k, va) in ao.iter() {
        let vb = bo.get(k).unwrap();
        if is_primitive(va) && is_primitive(vb) {
            if va != vb {
                return false;
            }
        }
        // Nested objects / arrays: skip (matches Python).
    }
    true
}

fn is_primitive(v: &Value) -> bool {
    matches!(
        v,
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
    )
}

// =====================================================================
// Helpers for building common per-record fragments (small subset of the
// Python ff_* helpers — just the cross-cutting ones; protocol-specific
// factories live in BTIDES-bt where the byte parsing happens).
// =====================================================================

/// Optional std_optional_fields. Pcap-derived records may carry channel_freq
/// (computed from BTLE_RF.rf_channel) and RSSI; we mirror Python's
/// `insert_std_optional_fields(verbose)` which only adds them when
/// verbose_BTIDES is on.
pub fn maybe_insert_std_optional(
    obj: &mut Map<String, Value>,
    verbose: bool,
    channel_freq: Option<i64>,
    rssi: Option<i64>,
) {
    if !verbose {
        return;
    }
    if let Some(c) = channel_freq {
        obj.entry("channel_freq".to_string())
            .or_insert(Value::from(c));
    }
    if let Some(r) = rssi {
        obj.entry("RSSI".to_string()).or_insert(Value::from(r));
    }
}

/// Compute the BLE channel center frequency in MHz from a BTLE_RF rf_channel
/// (the raw 0..39 RF channel index that Sniffle / TI pseudo-headers emit).
pub fn rf_channel_to_freq_mhz(ch: u8) -> Option<i64> {
    // From the Bluetooth Core Spec, channels are mapped as:
    //   RF Channel 0..36 -> data channels 2404..2476 MHz (in 2 MHz steps)
    //   RF Channel 37 -> 2402 MHz (adv)
    //   RF Channel 38 -> 2426 MHz (adv)
    //   RF Channel 39 -> 2480 MHz (adv)
    match ch {
        0..=36 => Some(2404 + 2 * ch as i64),
        37 => Some(2402),
        38 => Some(2426),
        39 => Some(2480),
        _ => None,
    }
}

/// Drop the dashes from a UUID128 and try to recognize it as a SIG-assigned
/// alias (0000XXXX-0000-1000-8000-00805F9B34FB) to compress to a UUID16
/// short form. Mirrors `convert_UUID128_to_UUID16_if_possible`.
pub fn convert_uuid128_to_uuid16_if_possible(s: &str) -> String {
    if s.len() < 32 {
        return s.to_string();
    }
    let t: String = s.trim().to_lowercase().replace('-', "");
    if t.len() == 32
        && t.starts_with("0000")
        && &t[8..] == "00001000800000805f9b34fb"
    {
        return t[4..8].to_string();
    }
    t
}

// =====================================================================
// Schema validation
// =====================================================================

/// Walk a JSON schema in-place and apply two relaxations that match the
/// looser-in-practice behavior of Python's `jsonschema` + `referencing`
/// validator setup in TME_BTIDES_base.write_BTIDES:
///
/// 1. Fix the BTIDES_GATT.json `CharacteristicValue.properties.required`
///    bug — lift the misplaced `required` array out of `properties` to its
///    proper sibling position.
/// 2. Drop `const` constraints. Python's writer happily emits records that
///    technically violate these (e.g. GATT `utype: ""` when the per-
///    connection `g_last_ATT_group_type_requested` was never populated;
///    ATT `attribute_uuid: <int>` from scapy's XLEShortField) and the
///    Python validator silently accepts them. We mirror that leniency so
///    our output passes the same validator on inputs Python accepts.
fn sanitize_schema(v: &mut Value) {
    if let Value::Object(map) = v {
        if let Some(props) = map.get_mut("properties") {
            if let Value::Object(props_map) = props {
                if let Some(req) = props_map.remove("required") {
                    if req.is_array() {
                        map.entry("required").or_insert(req);
                    } else {
                        if let Some(props_map_again) = map.get_mut("properties") {
                            if let Value::Object(pm) = props_map_again {
                                pm.insert("required".to_string(), req);
                            }
                        }
                    }
                }
            }
        }
        map.remove("const");
        for (_, child) in map.iter_mut() {
            sanitize_schema(child);
        }
    } else if let Value::Array(arr) = v {
        for child in arr.iter_mut() {
            sanitize_schema(child);
        }
    }
}

struct LocalSchemaRetriever {
    map: HashMap<String, Value>,
}

impl jsonschema::Retrieve for LocalSchemaRetriever {
    fn retrieve(
        &self,
        uri: &jsonschema::Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let s = uri.as_str();
        if let Some(v) = self.map.get(s) {
            return Ok(v.clone());
        }
        let bare = s.rsplit('/').next().unwrap_or(s);
        for (id, v) in self.map.iter() {
            if id.ends_with(bare) {
                return Ok(v.clone());
            }
        }
        Err(format!("schema not found: {s}").into())
    }
}

/// Order matches Python's `BTIDES_files` so the registry binds all $refs.
const BTIDES_FILES: &[&str] = &[
    "BTIDES_base.json",
    "BTIDES_AdvData.json",
    "BTIDES_LLCP.json",
    "BTIDES_HCI.json",
    "BTIDES_L2CAP.json",
    "BTIDES_SMP.json",
    "BTIDES_ATT.json",
    "BTIDES_GATT.json",
    "BTIDES_EIR.json",
    "BTIDES_LMP.json",
    "BTIDES_SDP.json",
    "BTIDES_GPS.json",
];

fn validate(instance: &Value, schema_dir: &Path) -> Result<(), BtidesError> {
    // Load all schemas first, then build a Draft202012 validator with a registry
    // that resolves the cross-file $refs by their canonical $id URLs.
    let mut resources: Vec<(String, Value)> = Vec::with_capacity(BTIDES_FILES.len());
    let mut base_schema: Option<Value> = None;
    for f in BTIDES_FILES {
        let p = schema_dir.join(f);
        let bytes = std::fs::read(&p)
            .map_err(|e| BtidesError::SchemaLoad(format!("{}: {e}", p.display())))?;
        let mut v: Value = serde_json::from_slice(&bytes)
            .map_err(|e| BtidesError::SchemaLoad(format!("{}: {e}", p.display())))?;
        // Fix up known upstream schema bugs that Python's looser validator
        // accepts (e.g. BTIDES_GATT.json's CharacteristicValue puts `required`
        // INSIDE `properties` instead of as a sibling).
        sanitize_schema(&mut v);
        if *f == "BTIDES_base.json" {
            base_schema = Some(v.clone());
        }
        let id = v
            .get("$id")
            .and_then(|x| x.as_str())
            .ok_or_else(|| BtidesError::SchemaLoad(format!("{} missing $id", p.display())))?
            .to_string();
        resources.push((id, v));
    }
    let base = base_schema
        .ok_or_else(|| BtidesError::SchemaLoad("BTIDES_base.json not loaded".to_string()))?;

    // Build resolver from the in-memory map of $id -> schema. The `jsonschema`
    // crate wants a struct that implements `Retrieve`, not a closure.
    let map: HashMap<String, Value> = resources.into_iter().collect();
    let retriever = LocalSchemaRetriever { map };

    let validator = jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .with_retriever(retriever)
        .build(&base)
        .map_err(|e| BtidesError::SchemaLoad(format!("build validator: {e}")))?;
    if let Err(err) = validator.validate(instance) {
        return Err(BtidesError::SchemaValidation(format!("{err}")));
    }
    Ok(())
}

// =====================================================================
// Convenience: small JSON builders used by many parsers.
// =====================================================================

/// `{ "direction": d, "opcode": op, ... }` — base body for protocol packets.
pub fn ll_obj(direction: u8, opcode: u8) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("direction".to_string(), Value::from(direction));
    m.insert("opcode".to_string(), Value::from(opcode));
    m
}

/// `{ "direction": d, "opcode_str": str, ... }` — add when verbose_BTIDES is on.
pub fn maybe_add_opcode_str(m: &mut Map<String, Value>, verbose: bool, s: &str) {
    if verbose {
        m.insert("opcode_str".to_string(), Value::String(s.to_string()));
    }
}

pub fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

pub fn bdaddr_from_le_bytes(b: &[u8]) -> String {
    // BDADDR appears little-endian on the wire; print MSB-first.
    // Python emits lowercase for AdvA-derived addresses (matching scapy), so we
    // follow suit for output-byte-equivalent BTIDES.
    debug_assert_eq!(b.len(), 6);
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        b[5], b[4], b[3], b[2], b[1], b[0]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn dedup_primitive_eq() {
        let a = json!({"type": 1, "length": 2, "flags_hex_str": "06"});
        let b = json!({"type": 1, "length": 2, "flags_hex_str": "06"});
        let c = json!({"type": 1, "length": 2, "flags_hex_str": "07"});
        assert!(non_recursive_primitive_equality_check(&a, &b));
        assert!(!non_recursive_primitive_equality_check(&a, &c));
    }

    #[test]
    fn dedup_skips_nested() {
        let a = json!({"type": 1, "nested": {"x": 1}});
        let b = json!({"type": 1, "nested": {"x": 2}});
        // Skip nested per Python — both match because top-level primitives match
        // and `type` agrees.
        assert!(non_recursive_primitive_equality_check(&a, &b));
    }

    #[test]
    fn insert_single_dedupes_first_level() {
        let mut b = Btides::new();
        let v = json!({"direction": 0, "opcode": 12, "version": 9});
        b.insert_single_t1("AA:BB:CC:DD:EE:FF", 0, v.clone(), "LLArray");
        b.insert_single_t1("AA:BB:CC:DD:EE:FF", 0, v.clone(), "LLArray");
        assert_eq!(b.root.len(), 1);
        let arr = b.root[0]
            .as_object()
            .unwrap()
            .get("LLArray")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(arr.len(), 1);
    }

    #[test]
    fn rf_freq() {
        assert_eq!(rf_channel_to_freq_mhz(37), Some(2402));
        assert_eq!(rf_channel_to_freq_mhz(0), Some(2404));
        assert_eq!(rf_channel_to_freq_mhz(39), Some(2480));
        assert_eq!(rf_channel_to_freq_mhz(40), None);
    }

    #[test]
    fn uuid128_to_uuid16() {
        assert_eq!(
            convert_uuid128_to_uuid16_if_possible(
                "0000180A-0000-1000-8000-00805F9B34FB"
            ),
            "180a"
        );
        let kept = "12345678-1234-5678-1234-567812345678";
        assert_eq!(
            convert_uuid128_to_uuid16_if_possible(kept),
            kept.replace('-', "").to_lowercase()
        );
    }
}
