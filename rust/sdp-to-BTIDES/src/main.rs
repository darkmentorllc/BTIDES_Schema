// sdp-to-BTIDES: CLI binary that converts sdptool XML output (one or more
// `{BDADDR}_sdp.xml` files) into a BTIDES JSON file.
//
// Ports Analysis/SDP_to_BTIDES.py. For each input file we:
//   1. Pull out every `<record>...</record>` chunk (sdptool concatenates multiple
//      XML documents and may interleave non-XML status text).
//   2. Re-encode the parsed XML as SDP binary attribute lists per the Core Spec
//      data-element grammar.
//   3. Wrap them as a single synthetic SDP_SERVICE_SEARCH_ATTR_RSP PDU and
//      emit one SingleBDADDR entry per file containing one SDPArray record.

use std::fs;
use std::path::{Path, PathBuf};

use BTIDES_model::Btides;
use clap::Parser;
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use serde_json::{Map, Value};

const SDP_SERVICE_SEARCH_ATTR_RSP: u8 = 0x07;

// --------------------------------------------------------------------------
// SDP binary data-element encoding
// --------------------------------------------------------------------------

/// Encode a variable-length SDP element (text, url, sequence, alternate) using
/// the smallest descriptor size_code that fits — matches Python's _sdp_var_len.
fn sdp_var_len(type_id: u8, payload: &[u8]) -> Vec<u8> {
    let n = payload.len();
    let mut out = Vec::with_capacity(payload.len() + 5);
    if n <= 0xFF {
        out.push((type_id << 3) | 5);
        out.push(n as u8);
    } else if n <= 0xFFFF {
        out.push((type_id << 3) | 6);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else {
        out.push((type_id << 3) | 7);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    }
    out.extend_from_slice(payload);
    out
}

#[derive(Debug)]
struct XmlElement {
    tag: String,
    /// All attributes (e.g. {"value": "0x1234", "id": "0x0001"}).
    attrs: std::collections::HashMap<String, String>,
    children: Vec<XmlElement>,
}

/// Parse a number that may be hex ("0xff", "0XAB"), bare hex (rare), or decimal.
/// sdptool emits hex with the 0x prefix for value attributes, so this is mostly
/// `i64::from_str_radix(strip_prefix, 16)`. Returns Err on malformed input.
fn parse_int(s: &str) -> Result<i64, String> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i64::from_str_radix(rest, 16).map_err(|e| format!("parse {s}: {e}"))
    } else {
        s.parse::<i64>().map_err(|e| format!("parse {s}: {e}"))
    }
}

/// Encode one parsed XML element as a binary SDP data element. Unknown tags are
/// dropped with a warning (matches Python). Errors out for malformed attributes.
fn encode_sdp_element(el: &XmlElement) -> Result<Vec<u8>, String> {
    let value = || el.attrs.get("value").cloned().unwrap_or_default();
    match el.tag.as_str() {
        "nil" => Ok(vec![0x00]),
        "uint8" => {
            let v = parse_int(&value())? as u8;
            Ok(vec![0x08, v])
        }
        "uint16" => {
            let v = parse_int(&value())? as u16;
            let mut o = vec![0x09];
            o.extend_from_slice(&v.to_be_bytes());
            Ok(o)
        }
        "uint32" => {
            let v = parse_int(&value())? as u32;
            let mut o = vec![0x0A];
            o.extend_from_slice(&v.to_be_bytes());
            Ok(o)
        }
        "uint64" => {
            // i64 covers all positive values we'll see here; Python casts via int(s, 16).
            let v = parse_int(&value())? as u64;
            let mut o = vec![0x0B];
            o.extend_from_slice(&v.to_be_bytes());
            Ok(o)
        }
        "int8" => {
            let v = parse_int(&value())? as i8;
            Ok(vec![0x10, v as u8])
        }
        "int16" => {
            let v = parse_int(&value())? as i16;
            let mut o = vec![0x11];
            o.extend_from_slice(&v.to_be_bytes());
            Ok(o)
        }
        "int32" => {
            let v = parse_int(&value())? as i32;
            let mut o = vec![0x12];
            o.extend_from_slice(&v.to_be_bytes());
            Ok(o)
        }
        "int64" => {
            let v = parse_int(&value())?;
            let mut o = vec![0x13];
            o.extend_from_slice(&v.to_be_bytes());
            Ok(o)
        }
        "uuid" => {
            let val = value();
            if val.starts_with("0x") || val.starts_with("0X") {
                let n = u32::from_str_radix(&val[2..], 16)
                    .map_err(|e| format!("uuid {val}: {e}"))?;
                if n <= 0xFFFF {
                    let mut o = vec![0x19];
                    o.extend_from_slice(&(n as u16).to_be_bytes());
                    Ok(o)
                } else {
                    let mut o = vec![0x1A];
                    o.extend_from_slice(&n.to_be_bytes());
                    Ok(o)
                }
            } else {
                // UUID128 with dashes, e.g. "00000000-deca-fade-deca-deafdecacaff"
                let hex: String = val.chars().filter(|c| *c != '-').collect();
                let bytes = decode_hex(&hex).map_err(|e| format!("uuid128 {val}: {e}"))?;
                if bytes.len() != 16 {
                    return Err(format!("uuid128 wrong length: {val}"));
                }
                let mut o = vec![0x1C];
                o.extend_from_slice(&bytes);
                Ok(o)
            }
        }
        "text" => {
            let s = value();
            Ok(sdp_var_len(4, s.as_bytes()))
        }
        "url" => {
            let s = value();
            Ok(sdp_var_len(8, s.as_bytes()))
        }
        "boolean" => {
            let v = value().to_ascii_lowercase();
            let b = if v == "true" || v == "1" { 1u8 } else { 0u8 };
            Ok(vec![0x28, b])
        }
        "sequence" => {
            let mut inner = Vec::new();
            for c in &el.children {
                inner.extend(encode_sdp_element(c)?);
            }
            Ok(sdp_var_len(6, &inner))
        }
        "alternate" => {
            let mut inner = Vec::new();
            for c in &el.children {
                inner.extend(encode_sdp_element(c)?);
            }
            Ok(sdp_var_len(7, &inner))
        }
        other => {
            eprintln!("Warning: unknown sdptool XML element type '{other}', skipping");
            Ok(Vec::new())
        }
    }
}

/// Encode one `<record>` element as an SDP attribute list sequence (Spec §5.1.2):
/// each attribute becomes `[0x09, u16 attr_id, encoded_value]`, all wrapped in
/// one outer sequence.
fn encode_record(record: &XmlElement) -> Result<Vec<u8>, String> {
    let mut pairs = Vec::new();
    for attr in record.children.iter().filter(|c| c.tag == "attribute") {
        let id_str = attr
            .attrs
            .get("id")
            .ok_or_else(|| "<attribute> missing id".to_string())?;
        let attr_id = parse_int(id_str)? as u16;
        pairs.push(0x09);
        pairs.extend_from_slice(&attr_id.to_be_bytes());
        for child in &attr.children {
            pairs.extend(encode_sdp_element(child)?);
        }
    }
    Ok(sdp_var_len(6, &pairs))
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd length".into());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_val(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("non-hex char {:?}", c as char)),
    }
}

// --------------------------------------------------------------------------
// XML extraction
// --------------------------------------------------------------------------

/// Pull every well-formed `<record>...</record>` block out of an sdptool dump.
/// Reproduces Python's split-on-<?xml?>-then-regex strategy: sdptool concatenates
/// multiple XML documents and the file may contain trailing non-XML text like
/// "Browsing ... Service Search failed: ...".
fn extract_record_chunks(content: &str) -> Vec<&str> {
    // Split on every <?xml ...?> declaration (any chunk before the first one is
    // discarded — it's the "Browsing ..." preamble).
    let parts = split_on_xml_decl(content);
    let mut out = Vec::new();
    for part in parts {
        if let Some(rec) = find_record_block(part) {
            out.push(rec);
        }
    }
    out
}

fn split_on_xml_decl(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut last = 0usize;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 5 < bytes.len() {
        // Look for "<?xml" followed by valid XML decl characters (no '?' inside) terminated by "?>"
        if &bytes[i..i + 5] == b"<?xml" {
            // Find terminating "?>"
            let mut j = i + 5;
            let mut found = false;
            while j + 1 < bytes.len() {
                if bytes[j] == b'?' && bytes[j + 1] == b'>' {
                    // Push everything from last..i, set last = j+2
                    parts.push(&s[last..i]);
                    last = j + 2;
                    i = last;
                    found = true;
                    break;
                }
                j += 1;
            }
            if !found {
                i += 5;
            }
        } else {
            i += 1;
        }
    }
    parts.push(&s[last..]);
    parts
}

fn find_record_block(chunk: &str) -> Option<&str> {
    // Find the first `<record` followed eventually by `</record>` — Python's
    // re.search(r'<record\b.*?</record>', chunk, re.DOTALL).
    let start = chunk.find("<record")?;
    // Make sure the character right after "<record" is whitespace or > so we
    // don't match `<records>` or similar. `\b` in the regex enforces this.
    let after = chunk.as_bytes().get(start + 7)?;
    if !(after.is_ascii_whitespace() || *after == b'>') {
        return None;
    }
    let rest = &chunk[start..];
    let end = rest.find("</record>")?;
    Some(&rest[..end + "</record>".len()])
}

/// Parse one `<record>...</record>` block into an XmlElement tree.
fn parse_record(block: &str) -> Result<XmlElement, String> {
    let mut reader = Reader::from_str(block);
    reader.config_mut().trim_text(true);
    let mut stack: Vec<XmlElement> = Vec::new();
    loop {
        match reader.read_event() {
            Err(e) => return Err(format!("xml parse: {e}")),
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                stack.push(make_element(&reader, &e)?);
            }
            Ok(Event::Empty(e)) => {
                let el = make_element(&reader, &e)?;
                match stack.last_mut() {
                    Some(parent) => parent.children.push(el),
                    None => return Err("empty element at root".into()),
                }
            }
            Ok(Event::End(_)) => {
                let done = stack.pop().ok_or("unbalanced </>".to_string())?;
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(done);
                } else {
                    // Root closed; expect EOF next.
                    return Ok(done);
                }
            }
            Ok(_) => {}
        }
    }
    Err("no closing tag found".into())
}

fn make_element(
    _reader: &Reader<&[u8]>,
    e: &quick_xml::events::BytesStart,
) -> Result<XmlElement, String> {
    let tag = std::str::from_utf8(e.name().as_ref())
        .map_err(|err| format!("tag utf8: {err}"))?
        .to_string();
    let mut attrs = std::collections::HashMap::new();
    for a in e.attributes().with_checks(false) {
        let a = a.map_err(|err| format!("attr: {err}"))?;
        let key = std::str::from_utf8(a.key.as_ref())
            .map_err(|err| format!("attr key: {err}"))?
            .to_string();
        let val = a
            .unescape_value()
            .map_err(|err| format!("attr val: {err}"))?
            .into_owned();
        attrs.insert(key, val);
    }
    Ok(XmlElement {
        tag,
        attrs,
        children: Vec::new(),
    })
}

// --------------------------------------------------------------------------
// Per-file BTIDES export
// --------------------------------------------------------------------------

fn process_sdp_file(bt: &mut Btides, path: &Path) -> Result<bool, String> {
    // sdptool occasionally injects garbage high-bit-set bytes into <url> values
    // (we've seen ~3/3243 files). Python reads with errors='replace' which lets
    // the well-formed records in the same file still parse; mirror that by
    // doing a lossy UTF-8 conversion (invalid bytes become U+FFFD).
    let raw =
        fs::read(path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    let content = String::from_utf8_lossy(&raw).into_owned();

    let bdaddr = path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.replace("_sdp.xml", "").to_lowercase())
        .ok_or_else(|| format!("bad filename {}", path.display()))?;

    let chunks = extract_record_chunks(&content);
    if chunks.is_empty() {
        return Ok(false);
    }

    let mut inner = Vec::new();
    for chunk in chunks {
        match parse_record(chunk) {
            Ok(rec) => match encode_record(&rec) {
                Ok(bytes) => inner.extend(bytes),
                Err(e) => eprintln!("Warning: encode failed for {}: {e}", path.display()),
            },
            Err(e) => {
                eprintln!("Warning: XML parse error in {}: {e}", path.display());
            }
        }
    }
    if inner.is_empty() {
        return Ok(false);
    }

    let outer = sdp_var_len(6, &inner);
    // SDP_SERVICE_SEARCH_ATTR_RSP parameter bytes:
    //   AttributeListsByteCount (u16 BE) | AttributeLists | ContinuationState (1 byte 0x00)
    let mut payload = Vec::with_capacity(outer.len() + 3);
    payload.extend_from_slice(&(outer.len() as u16).to_be_bytes());
    payload.extend_from_slice(&outer);
    payload.push(0x00);

    let mut obj = Map::new();
    obj.insert("direction".into(), Value::from(1));  // type_BTIDES_direction_P2C (peripheral -> central)
    obj.insert("l2cap_len".into(), Value::from(payload.len() + 5));
    obj.insert("l2cap_cid".into(), Value::from(0x0040));
    obj.insert("pdu_id".into(), Value::from(SDP_SERVICE_SEARCH_ATTR_RSP));
    obj.insert("transaction_id".into(), Value::from(0x0001));
    obj.insert("param_len".into(), Value::from(payload.len()));
    let mut hex = String::with_capacity(payload.len() * 2);
    for b in &payload {
        hex.push_str(&format!("{:02x}", b));
    }
    obj.insert("raw_data_hex_str".into(), Value::String(hex));

    bt.insert_single_t1(&bdaddr, 0, Value::Object(obj), "SDPArray");
    Ok(true)
}

// --------------------------------------------------------------------------
// CLI
// --------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(version, about = "Convert sdptool XML output into a BTIDES JSON file.")]
struct Cli {
    /// Either a single `{BDADDR}_sdp.xml` file or a directory containing them.
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
    quiet: bool,
}

fn collect_inputs(input: &Path) -> Vec<PathBuf> {
    if input.is_dir() {
        let mut v: Vec<PathBuf> = fs::read_dir(input)
            .map(|it| {
                it.flatten()
                    .map(|e| e.path())
                    .filter(|p| {
                        p.file_name()
                            .and_then(|n| n.to_str())
                            .map(|s| s.ends_with("_sdp.xml"))
                            .unwrap_or(false)
                    })
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    } else if input.is_file() {
        vec![input.to_path_buf()]
    } else {
        Vec::new()
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let inputs = collect_inputs(&cli.input);
    if inputs.is_empty() {
        eprintln!("No *_sdp.xml files found at {}", cli.input.display());
        std::process::exit(1);
    }
    if !cli.quiet {
        println!("Processing {} sdptool XML file(s)...", inputs.len());
    }

    let mut bt = Btides::new();
    bt.set_verbose(cli.verbose_btides);
    let mut processed = 0u64;
    for path in &inputs {
        match process_sdp_file(&mut bt, path) {
            Ok(true) => processed += 1,
            Ok(false) => {}
            Err(e) => eprintln!("Error processing {}: {e}", path.display()),
        }
    }
    if !cli.quiet {
        println!("Exported SDP data for {processed} device(s).");
    }

    if cli.no_validate {
        std::fs::write(&cli.output, bt.to_json_bytes()?)?;
    } else {
        bt.write_btides(&cli.output, &cli.schema_dir)?;
    }
    if !cli.quiet {
        println!("BTIDES output written to {}", cli.output.display());
    }
    Ok(())
}
