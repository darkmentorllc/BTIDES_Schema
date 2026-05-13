// Per-connection state tracked across data-channel packets.
// Mirrors Analysis/PCAP_to_BTIDES.py's g_access_address_to_connect_ind_obj +
// g_stop_exporting_encrypted_packets_by_AA.

use std::collections::HashMap;

use serde_json::{Map, Value};

/// Reassembly buffer for L2CAP frames carried over LL data PDUs. A START PDU
/// arrives with LLID=10 and the L2CAP length; CONTINUATION PDUs follow with
/// LLID=01 until we've collected `length+4` bytes (length + cid + payload).
#[derive(Default)]
pub struct L2capReassembly {
    pub buf: Vec<u8>,
    pub expected: usize,
}

#[derive(Default)]
pub struct ConnectionState {
    pub connect_ind: Option<Value>,
    pub encrypted: bool,
    /// One reassembly slot per direction (C2P vs P2C). Indexed by `direction`
    /// (0 or 1) — BLE LL is half-duplex per direction but the two sides can
    /// independently have in-flight fragments.
    pub reassembly: [L2capReassembly; 2],
    /// Last group_type seen on an ATT_READ_BY_GROUP_TYPE_REQ. Used by the RSP
    /// handler to decide whether the discovered services are Primary (0x2800)
    /// or Secondary (0x2801). Default to "2800" to match Python's behavior of
    /// using the most-common case if a RSP arrives before any REQ.
    pub last_group_type: String,
    /// Last attribute_uuid seen on an ATT_READ_BY_TYPE_REQ. Drives whether the
    /// RSP entries get emitted as GATT Characteristics (when == "2803").
    pub last_read_by_type_uuid: String,
    /// Handle from the most recent ATT_READ_REQ, used to correlate with
    /// the next ATT_READ_RSP.
    pub last_read_handle: Option<i64>,
    /// Set of L2CAP CIDs known to carry SDP traffic on this connection.
    /// Populated when an L2CAP_CONNECTION_REQ for PSM 0x0001 (SDP) arrives
    /// (source_cid added) and again on the matching CONNECTION_RSP
    /// (destination_cid added). Mirrors Python's g_CIDs_used_for_SDP.
    pub sdp_cids: std::collections::HashSet<u16>,
}

impl ConnectionState {
    pub fn placeholder_connect_ind() -> Value {
        let mut m = Map::new();
        m.insert(
            "central_bdaddr".to_string(),
            Value::String("00:00:00:00:00:00".to_string()),
        );
        m.insert("central_bdaddr_rand".to_string(), Value::from(0));
        m.insert(
            "peripheral_bdaddr".to_string(),
            Value::String("00:00:00:00:00:00".to_string()),
        );
        m.insert("peripheral_bdaddr_rand".to_string(), Value::from(0));
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
}

#[derive(Default)]
pub struct ConnectionTable {
    pub by_aa: HashMap<u32, ConnectionState>,
    /// Process-global cache of handle→UUID mappings learned from
    /// ATT_FIND_INFORMATION_RSP packets, keyed by the sender's bdaddr
    /// (peripheral on P2C, central on C2P). Mirrors Python's module-level
    /// `g_bdaddr_to_list_of_ff_ATT_FIND_INFORMATION_RSP_information_data`,
    /// which persists across connections to the same device — so when the
    /// same peripheral is re-connected later in the capture, ATT_READ_RSP
    /// handlers can still classify handles based on UUIDs learned earlier.
    pub handle_to_uuid_by_bdaddr: HashMap<String, HashMap<i64, String>>,
}

impl ConnectionTable {
    pub fn get_or_placeholder(&mut self, aa: u32) -> &mut ConnectionState {
        self.by_aa.entry(aa).or_default()
    }
    pub fn lookup_connect_ind(&self, aa: u32) -> Option<&Value> {
        self.by_aa.get(&aa).and_then(|s| s.connect_ind.as_ref())
    }

    /// Direction-dependent bdaddr selection that matches the Python source's
    /// pattern: P2C ⇒ peripheral_bdaddr; C2P ⇒ central_bdaddr.
    pub fn direction_bdaddr(connect_ind: &Value, direction: u8) -> Option<String> {
        let obj = connect_ind.as_object()?;
        let key = if direction == 1 { "peripheral_bdaddr" } else { "central_bdaddr" };
        obj.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
    }
}
