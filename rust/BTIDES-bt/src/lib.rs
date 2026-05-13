#![allow(non_snake_case)]
// BTIDES-bt: Bluetooth protocol parsers shared by all BTIDES converters
// (pcap-derived now; HCI-snoop later). Each protocol module turns raw bytes
// into the JSON shapes defined by BTIDES_Schema/*.json and pushes them
// through the `BTIDES_model::Btides` accumulator.

pub mod types;
pub mod adv;
pub mod adv_data;
pub mod att;
pub mod conn;
pub mod l2cap;
pub mod ll;
pub mod llcp;
pub mod rf;
pub mod sdp;
pub mod smp;

pub use BTIDES_model;
