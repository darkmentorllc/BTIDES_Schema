// Numeric constants for all Bluetooth protocols we emit BTIDES for.
// Mirrors Analysis/TME/BT_Data_Types.py and BTIDES_Data_Types.py.

#![allow(non_upper_case_globals)]

// AdvData (Common Data Types) — values from BT Core Spec Supplement
pub const ADV_FLAGS: u8 = 0x01;
pub const ADV_UUID16_LIST_INCOMPLETE: u8 = 0x02;
pub const ADV_UUID16_LIST_COMPLETE: u8 = 0x03;
pub const ADV_UUID32_LIST_INCOMPLETE: u8 = 0x04;
pub const ADV_UUID32_LIST_COMPLETE: u8 = 0x05;
pub const ADV_UUID128_LIST_INCOMPLETE: u8 = 0x06;
pub const ADV_UUID128_LIST_COMPLETE: u8 = 0x07;
pub const ADV_INCOMPLETE_NAME: u8 = 0x08;
pub const ADV_COMPLETE_NAME: u8 = 0x09;
pub const ADV_TX_POWER: u8 = 0x0a;
pub const ADV_CLASS_OF_DEVICE: u8 = 0x0d;
pub const ADV_DEVICE_ID: u8 = 0x10;
pub const ADV_PERIPHERAL_CONNECTION_INTERVAL_RANGE: u8 = 0x12;
pub const ADV_UUID16_LIST_SERVICE_SOLICITATION: u8 = 0x14;
pub const ADV_UUID128_LIST_SERVICE_SOLICITATION: u8 = 0x15;
pub const ADV_UUID16_SERVICE_DATA: u8 = 0x16;
pub const ADV_PUBLIC_TARGET_ADDRESS: u8 = 0x17;
pub const ADV_RANDOM_TARGET_ADDRESS: u8 = 0x18;
pub const ADV_APPEARANCE: u8 = 0x19;
pub const ADV_ADVERTISING_INTERVAL: u8 = 0x1a;
pub const ADV_LE_BDADDR: u8 = 0x1b;
pub const ADV_LE_ROLE: u8 = 0x1c;
pub const ADV_UUID32_LIST_SERVICE_SOLICITATION: u8 = 0x1f;
pub const ADV_UUID32_SERVICE_DATA: u8 = 0x20;
pub const ADV_UUID128_SERVICE_DATA: u8 = 0x21;
pub const ADV_URI: u8 = 0x24;
pub const ADV_LE_SUPPORTED_FEATURES: u8 = 0x27;
pub const ADV_BROADCAST_NAME: u8 = 0x30;
pub const ADV_ENCRYPTED_ADV_DATA: u8 = 0x31;
pub const ADV_3D_INFO_DATA: u8 = 0x3d;
pub const ADV_MSD: u8 = 0xff;

// BLE advertising channel PDU types (4-bit field in the adv header)
pub const ADV_PDU_ADV_IND: u8 = 0;
pub const ADV_PDU_ADV_DIRECT_IND: u8 = 1;
pub const ADV_PDU_ADV_NONCONN_IND: u8 = 2;
pub const ADV_PDU_SCAN_REQ: u8 = 3;
pub const ADV_PDU_SCAN_RSP: u8 = 4;
pub const ADV_PDU_CONNECT_IND: u8 = 5;
pub const ADV_PDU_ADV_SCAN_IND: u8 = 6;
pub const ADV_PDU_AUX_ADV_IND: u8 = 7;

// BTIDES adv-channel type values (separate from the wire PDU values above).
pub const BTIDES_ADV_IND: u8 = 0;
pub const BTIDES_ADV_DIRECT_IND: u8 = 1;
pub const BTIDES_ADV_NONCONN_IND: u8 = 2;
pub const BTIDES_ADV_SCAN_IND: u8 = 3;
pub const BTIDES_AUX_ADV_IND: u8 = 10;
pub const BTIDES_SCAN_RSP: u8 = 20;
pub const BTIDES_AUX_SCAN_RSP: u8 = 21;

// LL Control PDU opcodes
pub const LL_CONNECTION_UPDATE_IND: u8 = 0;
pub const LL_CHANNEL_MAP_IND: u8 = 1;
pub const LL_TERMINATE_IND: u8 = 2;
pub const LL_ENC_REQ: u8 = 3;
pub const LL_ENC_RSP: u8 = 4;
pub const LL_START_ENC_REQ: u8 = 5;
pub const LL_START_ENC_RSP: u8 = 6;
pub const LL_UNKNOWN_RSP: u8 = 7;
pub const LL_FEATURE_REQ: u8 = 8;
pub const LL_FEATURE_RSP: u8 = 9;
pub const LL_VERSION_IND: u8 = 12;
pub const LL_REJECT_IND: u8 = 13;
pub const LL_PERIPHERAL_FEATURE_REQ: u8 = 14;
pub const LL_CONNECTION_PARAM_REQ: u8 = 15;
pub const LL_CONNECTION_PARAM_RSP: u8 = 16;
pub const LL_REJECT_EXT_IND: u8 = 17;
pub const LL_PING_REQ: u8 = 18;
pub const LL_PING_RSP: u8 = 19;
pub const LL_LENGTH_REQ: u8 = 20;
pub const LL_LENGTH_RSP: u8 = 21;
pub const LL_PHY_REQ: u8 = 22;
pub const LL_PHY_RSP: u8 = 23;
pub const LL_PHY_UPDATE_IND: u8 = 24;
pub const LL_POWER_CONTROL_REQ: u8 = 35;
pub const LL_POWER_CONTROL_RSP: u8 = 36;
pub const LL_UNKNOWN_CUSTOM: u8 = 255;

// L2CAP signal-channel codes
pub const L2CAP_CONNECTION_REQ: u8 = 0x02;
pub const L2CAP_CONNECTION_RSP: u8 = 0x03;
pub const L2CAP_CONFIGURATION_REQ: u8 = 0x04;
pub const L2CAP_CONFIGURATION_RSP: u8 = 0x05;
pub const L2CAP_DISCONNECTION_REQ: u8 = 0x06;
pub const L2CAP_DISCONNECTION_RSP: u8 = 0x07;
pub const L2CAP_INFORMATION_REQ: u8 = 0x0a;
pub const L2CAP_INFORMATION_RSP: u8 = 0x0b;
pub const L2CAP_CONNECTION_PARAMETER_UPDATE_REQ: u8 = 0x12;
pub const L2CAP_CONNECTION_PARAMETER_UPDATE_RSP: u8 = 0x13;

// L2CAP fixed CIDs
pub const CID_ATT: u16 = 0x0004;
pub const CID_LE_SIGNALING: u16 = 0x0005;
pub const CID_SMP: u16 = 0x0006;
pub const CID_BR_EDR_SIGNALING: u16 = 0x0001;

// ATT opcodes
pub const ATT_ERROR_RSP: u8 = 0x01;
pub const ATT_EXCHANGE_MTU_REQ: u8 = 0x02;
pub const ATT_EXCHANGE_MTU_RSP: u8 = 0x03;
pub const ATT_FIND_INFORMATION_REQ: u8 = 0x04;
pub const ATT_FIND_INFORMATION_RSP: u8 = 0x05;
pub const ATT_FIND_BY_TYPE_VALUE_REQ: u8 = 0x06;
pub const ATT_FIND_BY_TYPE_VALUE_RSP: u8 = 0x07;
pub const ATT_READ_BY_TYPE_REQ: u8 = 0x08;
pub const ATT_READ_BY_TYPE_RSP: u8 = 0x09;
pub const ATT_READ_REQ: u8 = 0x0a;
pub const ATT_READ_RSP: u8 = 0x0b;
pub const ATT_READ_BLOB_REQ: u8 = 0x0c;
pub const ATT_READ_BLOB_RSP: u8 = 0x0d;
pub const ATT_READ_MULTIPLE_REQ: u8 = 0x0e;
pub const ATT_READ_MULTIPLE_RSP: u8 = 0x0f;
pub const ATT_READ_BY_GROUP_TYPE_REQ: u8 = 0x10;
pub const ATT_READ_BY_GROUP_TYPE_RSP: u8 = 0x11;
pub const ATT_WRITE_REQ: u8 = 0x12;
pub const ATT_WRITE_RSP: u8 = 0x13;
pub const ATT_HANDLE_VALUE_NTF: u8 = 0x1b;
pub const ATT_HANDLE_VALUE_IND: u8 = 0x1d;
pub const ATT_HANDLE_VALUE_CFM: u8 = 0x1e;
pub const ATT_WRITE_CMD: u8 = 0x52;

// SMP opcodes
pub const SMP_PAIRING_REQUEST: u8 = 1;
pub const SMP_PAIRING_RESPONSE: u8 = 2;
pub const SMP_PAIRING_CONFIRM: u8 = 3;
pub const SMP_PAIRING_RANDOM: u8 = 4;
pub const SMP_PAIRING_FAILED: u8 = 5;
pub const SMP_SECURITY_REQUEST: u8 = 11;
pub const SMP_PAIRING_PUBLIC_KEY: u8 = 12;
pub const SMP_PAIRING_DHKEY_CHECK: u8 = 13;
pub const SMP_PAIRING_KEYPRESS_NOTIFICATION: u8 = 14;

pub const BLE_ADV_ACCESS_ADDRESS: u32 = 0x8e89bed6;

/// BTIDES "direction" values.
pub const DIR_C2P: u8 = 0;
pub const DIR_P2C: u8 = 1;
