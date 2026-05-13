// pcap-to-BTIDES: CLI binary that walks a libpcap file of BLUETOOTH_LE_LL_WITH_PHDR
// captures, drives the BTIDES-bt parsers, and writes a BTIDES JSON file (after
// validating against the BTIDES schema).

use std::path::PathBuf;
use std::time::Instant;

use clap::Parser;

use BTIDES_bt::adv::handle_adv_pdu;
use BTIDES_bt::conn::ConnectionTable;
use BTIDES_bt::l2cap::handle_data_pdu;
use BTIDES_bt::ll::{
    is_adv_aa, parse_adv_ll_header, parse_air_pdu, parse_data_ll_header, LLID_CONTROL,
};
use BTIDES_bt::llcp::handle_llcp;
use BTIDES_bt::rf::parse_rf;
use BTIDES_model::Btides;
use BTIDES_pcap::PcapReader;

/// Linktype for BLUETOOTH_LE_LL_WITH_PHDR (the one Sniffle / TI sniffers use).
const LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR: u32 = 256;

#[derive(Parser, Debug)]
#[command(version, about = "Convert a BLUETOOTH_LE_LL_WITH_PHDR pcap into a BTIDES JSON file.")]
struct Cli {
    /// Input pcap.
    #[arg(long)]
    input: PathBuf,
    /// Output BTIDES JSON file.
    #[arg(long)]
    output: PathBuf,
    /// Path to the BTIDES_Schema directory (must contain BTIDES_base.json + friends).
    #[arg(long)]
    schema_dir: PathBuf,
    /// Include optional verbose fields (`type_str`, `opcode_str`, `utf8_name`, etc).
    #[arg(long = "verbose-BTIDES", default_value_t = false)]
    verbose_btides: bool,
    /// Skip schema validation (useful for perf comparisons).
    #[arg(long, default_value_t = false)]
    no_validate: bool,
    /// Print phase timings.
    #[arg(long, default_value_t = false)]
    timings: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let t0 = Instant::now();
    let mut reader = PcapReader::open(&cli.input)?;
    let hdr = reader.header();
    if hdr.linktype != LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR {
        return Err(format!(
            "unsupported linktype {}, expected {}",
            hdr.linktype, LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR
        )
        .into());
    }

    let mut bt = Btides::new();
    bt.set_verbose(cli.verbose_btides);
    let mut conns = ConnectionTable::default();
    let mut count = 0u64;

    loop {
        let next = match reader.next() {
            Ok(Some(p)) => p,
            Ok(None) => break,
            Err(_) => break, // emulate Python "skip bad packet and stop"
        };
        count += 1;
        process_packet(&mut bt, &mut conns, next.data);
    }
    let t_parse = t0.elapsed();
    if cli.timings {
        eprintln!("read_pcap+parse: {:.2}s ({count} packets)", t_parse.as_secs_f64());
    }

    let t1 = Instant::now();
    if cli.no_validate {
        let bytes = bt.to_json_bytes()?;
        std::fs::write(&cli.output, bytes)?;
    } else {
        bt.write_btides(&cli.output, &cli.schema_dir)?;
    }
    let t_write = t1.elapsed();
    if cli.timings {
        eprintln!(
            "write_btides (validate={}): {:.2}s",
            !cli.no_validate,
            t_write.as_secs_f64()
        );
        eprintln!("TOTAL: {:.2}s", (t0.elapsed()).as_secs_f64());
    }

    Ok(())
}

fn process_packet(bt: &mut Btides, conns: &mut ConnectionTable, raw: &[u8]) {
    let Some((rf, after_rf)) = parse_rf(raw) else {
        return;
    };
    let direction = rf.direction();
    let Some((aa, ll_hdr, payload, _crc)) = parse_air_pdu(after_rf) else {
        return;
    };
    if is_adv_aa(aa) {
        // Match Python skip: SCAN_REQ / ADV_DIRECT_IND (PDU types) are filtered
        // by the per-handler logic in adv.rs.
        let hdr = parse_adv_ll_header(ll_hdr[0]);
        handle_adv_pdu(bt, conns, hdr, payload);
    } else {
        // Data channel: skip empty PDUs (matches Python's `len == 0` filter).
        let hdr = parse_data_ll_header(ll_hdr[0]);
        if ll_hdr[1] == 0 {
            return;
        }
        // Skip subsequent packets on encrypted connections (matches Python
        // g_stop_exporting_encrypted_packets_by_AA in read_pcap, applied before
        // dispatch). The flag is set in llcp.rs but we still need to short-circuit
        // here for non-LL_CTRL packets on the same connection.
        if let Some(st) = conns.by_aa.get(&aa) {
            if st.encrypted {
                return;
            }
        }
        if hdr.llid == LLID_CONTROL {
            handle_llcp(bt, conns, aa, direction, payload);
        } else {
            handle_data_pdu(bt, conns, aa, direction, hdr.llid, payload);
        }
    }
}
