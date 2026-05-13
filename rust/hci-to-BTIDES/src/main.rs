// hci-to-BTIDES: CLI binary that walks a BTSnoop / btmon HCI log and writes
// a BTIDES JSON file.
//
// Same workspace, same crates as pcap-to-BTIDES — we only swap the source
// (BTIDES-btsnoop instead of BTIDES-pcap) and the per-packet dispatcher
// (BTIDES-hci instead of pcap-side decoders).

use std::path::PathBuf;
use std::time::Instant;

use clap::Parser;

use BTIDES_bt::conn::ConnectionTable;
use BTIDES_btsnoop::BtsnoopReader;
use BTIDES_hci::{handle_packet, HciState};
use BTIDES_model::Btides;

#[derive(Parser, Debug)]
#[command(version, about = "Convert a BTSnoop / btmon HCI log into a BTIDES JSON file.")]
struct Cli {
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    schema_dir: PathBuf,
    #[arg(long = "verbose-BTIDES", default_value_t = false)]
    verbose_btides: bool,
    #[arg(long, default_value_t = false)]
    no_validate: bool,
    #[arg(long, default_value_t = false)]
    timings: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let t0 = Instant::now();
    let mut reader = BtsnoopReader::open(&cli.input)?;
    let mut bt = Btides::new();
    bt.set_verbose(cli.verbose_btides);
    let mut conns = ConnectionTable::default();
    let mut hci = HciState::default();
    let mut count = 0u64;
    while let Some(rec) = reader.next_record() {
        count += 1;
        handle_packet(&mut bt, &mut conns, &mut hci, rec.uart_type, rec.direction, rec.data);
    }
    let t_parse = t0.elapsed();
    if cli.timings {
        eprintln!("read_hci+parse: {:.2}s ({count} records)", t_parse.as_secs_f64());
    }
    let t1 = Instant::now();
    if cli.no_validate {
        std::fs::write(&cli.output, bt.to_json_bytes()?)?;
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
        eprintln!("TOTAL: {:.2}s", t0.elapsed().as_secs_f64());
    }
    Ok(())
}
