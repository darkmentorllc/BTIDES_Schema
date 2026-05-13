# BlueTooth Information Data Exchange Schema (BTIDES!)

BTIDES is an attempt to create a schema for sharing Bluetooth data between different tools. Creating a formal schema helps with machine-enforcible sanity checking over the data structure, as well as automatic documentation.

**Why not juse use pcap/HCI logs everywhere?**

**TL;DR:** Neither of pcap nor HCI capture all the Bluetooth data we'd like captured, individually, or in unison.

First, using HCI logs everywhere is not feasible. The Host-Controller Interface (HCI) in Bluetooth is defined as being between the Host (e.g. OS like Windows/Linux/macOS) and the Controller (e.g. a chip from a silicon maker) over a local physical bus such as SPI, PCI, UART, etc. HCI is a means for the Host to tell the Controller to send some packet types. *But the host never actually sees many of the packets which go out over the air!* Therefore a HCI log is necessarily incomplete in its view of the communications between two devices.

Second, pcap is the other side of the coin of HCI - current tools which log to pcap format in the Bluetooth space (e.g. [Sniffle](https://github.com/nccgroup/Sniffle), [Ubertooth](https://github.com/greatscottgadgets/ubertooth)) are generally focused on over-the-air (OTA) Bluetooth traffic capture. Therefore by definition they will not be able to see HCI traffic, because it does not go OTA. And the pcap is therefore missing information exchanged between the Host and Controller, which can include very important data such as the keys used for traffic encryption.

Third, in Bluetooth Low Energy (BLE) the Generic Attribute Profile (GATT) defines a meaningful hierarchy of Services and Characteristics, which are one of the primary ways which BLE devices interact with each other. It is very often desirable to capture/view/analyze the GATT hierarchy for a given device. However, the hierarchy is not given in a simple form, but rather built up by applying the semantic knowlege of GATT to many underlying ATT read/write request/responses. While BTIDES captures the underlying raw ATT packets, when available from a pcap source, it also importantly *defines a data structure for directly representing the nested GATT hierarchy* with Primary Services, Secondary Services, Characteristics, and Characteristic Descriptors. All of these aspects are important, but not all of them are captured by all tools, leaving data often incomplete. The GATT hierarchy can be built up from underlying low-level data, when available, or it can be captured from tools which may only present it once it has already been organized into the higher-level form.

## Usage

The BTIDES format is currently used as the basis for crowdsourced sharing of data between [Blue2thprinting](https://github.com/darkmentorllc/Blue2thprinting) endpoints, and a cloud *BTIDALPOOL* server. Other tools that operate on BTIDES format data can submit BTIDES data to the *BTIDALPOOL* or query and retrieve data from it in BTIDES format.

Beyond just data exchange, the BTIDES format attempts to also capture common types of information that have been used in past tools such as [GATTacker](https://github.com/securing/gattacker) and [btlejuice](https://github.com/DigitalSecurity/btlejuice), which logged the ATT traffic (in JSON format, but without any schema) as they performed a MitM attack between two devices. Future tools can log traffic in BTIDES format for easy sharing and cross-tool compatibility.


## Schema

The `BTIDES_base.json` file is the enclosing schema which imports schema definitions from other protocols, profiles, and metadata like `BTIDES_AdvData.json`, `BTIDES_GATT.json`, `BTIDES_HCI.json`, `BTIDES_GPS.json`, etc. The schemas are meant to encompass both Bluetooth Classic (BR/EDR) and Low Energy (BLE). (Though the Classic data is significantly incomplete for the moment.) The purpose of these schema files is to both allow for automatic verification, and automatic documentation creation.

The [automatically generated documentation](https://darkmentor.com/BTIDES_Schema/BTIDES.html) can be generated via the below commands.

```
python3 -m venv ./venv
source ./venv/bin/activate
pip3 install json-schema-for-humans
```

Documentation using online Javascript:
`generate-schema-doc BTIDES_base.json BTIDES.html`

Documentation using offline/local Javascript:
`generate-schema-doc BTIDES_base.json --config  template_name=js_offline BTIDES.html`

Documentation using Markdown:
`generate-schema-doc BTIDES_base.json --config  template_name=md BTIDES.md`

We prefer the collapsible HTML/JS formatting, therefore the latest copy of that documentation will always be mirroed to [https://darkmentor.com/BTIDES_base/BTIDES.html](https://darkmentor.com/BTIDES_base/BTIDES.html).

### Schema verification in CLI

A JSON file meant to conform to the BTIDES schema can be validated on the command line via the following commands:

```
python3 -m venv ./venv`
source ./venv/bin/activate`
pip3 install check-jsonschema`
check-jsonschema --verbose --base-uri ./BTIDES_base.json --schemafile ./BTIDES_base.json ./example_data.btides
```

### Schema verification in Python

The below is a Python 3 example of exporting data in BTIDES format to a file, and verifying it. The data itself is in `BTIDES_JSON` a python list of dictionaries.

```python
import json
from jsonschema import validate, ValidationError
from referencing import Registry, Resource
from jsonschema import Draft202012Validator

# Same order as in BTIDES_base.json
BTIDES_files = ["BTIDES_base.json",
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
                "BTIDES_GPS.json"
                ]

def write_BTIDES(out_filename):
    # Sanity check the BTIDES data against the schema before export, to not write garbage
    # Import all the local BTIDES json schema files, so that we don't hit the website all the time
    all_schemas = []
    required_version = "0.2.1"

    def version_tuple(v):
        return tuple(map(int, (v.split("."))))

    for file in BTIDES_files:
        with open(f"./BTIDES_Schema/{file}", 'r') as f:
            s = json.load(f)
            if file == "BTIDES_base.json":
                schema_version = s.get("version", "0.2.1")
                if version_tuple(schema_version) < version_tuple(required_version):
                    raise ValueError(f"Schema version {schema_version} is less than the required version {required_version}")
            schema = Resource.from_contents(s)
            all_schemas.append((s["$id"], schema))

    registry = Registry().with_resources( all_schemas )

    # Sanity check every entry against the Schema
    try:
        Draft202012Validator(
            {"$ref": "https://darkmentor.com/BTIDES_Schema/BTIDES_base.json"},
            registry=registry,
        ).validate(instance=BTIDES_JSON)
        #print("JSON is valid according to BTIDES Schema")
    except ValidationError as e:
        print(f"JSON data is invalid per BTIDES Schema version {required_version}. Check any changes to schema or code. Error:", e.message)
        print(json.dumps(BTIDES_JSON, indent=2))
        exit(-1)

    with open(out_filename, 'w') as f:
        json.dump(BTIDES_JSON, fp=f) # For saving space
```

# Rust converters (`rust/`)

The `rust/` directory contains a Cargo workspace with three end-user binaries that read Bluetooth-adjacent data sources and emit `.btides` files validated against the schemas in this repo:

- `pcap-to-BTIDES` — convert a single libpcap/pcapng capture (Sniffle, BetterGetter, etc.) to BTIDES.
- `hci-to-BTIDES` — convert a single BTSnoop log (BlueZ `btmon`, Android `btsnoop_hci.log`) to BTIDES.
- `sdp-to-BTIDES` — convert sdptool XML output (`{BDADDR}_sdp.xml` files) into BTIDES. Re-encodes the XML as binary SDP attribute lists wrapped in a synthetic `SDP_SERVICE_SEARCH_ATTR_RSP` PDU per device.

The workspace also ships reusable library crates (`BTIDES-model`, `BTIDES-pcap`, `BTIDES-btsnoop`, `BTIDES-bt`, `BTIDES-hci`) so the same protocol parsers can be embedded in other tools.

Two further converters live in the parent [Blue2thprinting](https://github.com/darkmentorllc/Blue2thprinting) repository at `Analysis/rust/`, because they depend on Blue2thprinting-specific state that isn't part of this schema repo:

- `wigle-to-BTIDES` — needs the local `bt2`/`bttest` MySQL schema to look up `bdaddr_random` for BLE devices observed by WiGLE.
- `import-all-BTIDES` — orchestrates bulk capture-folder conversion using Blue2thprinting's directory layout.

Those binaries consume the libraries above as cross-workspace path dependencies, so they only build inside a full Blue2thprinting checkout.

## Build prerequisites

The workspace targets stable Rust and uses `jsonschema 0.30`, which requires **rustc 1.79 or newer**. On Debian/Ubuntu the apt-shipped `rustc` is often too old — use `rustup` instead.

**macOS** (with [Homebrew](https://brew.sh/) installed):

```sh
brew install rust
```

**Debian / Ubuntu**:

```sh
sudo apt-get install -y build-essential curl ca-certificates pkg-config
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal
```

## Build

From the directory containing this README:

```sh
cd rust
cargo build --release
```

The optimized binaries are produced at `rust/target/release/{pcap-to-BTIDES,hci-to-BTIDES,sdp-to-BTIDES}`.

## Usage

Each binary takes a `--schema-dir` pointing at the directory containing this README (so the schemas can be loaded for validation):

```sh
# Single PCAP
./rust/target/release/pcap-to-BTIDES \
    --input  capture.pcap \
    --output capture.btides \
    --schema-dir .

# Single HCI / BTSnoop log
./rust/target/release/hci-to-BTIDES \
    --input  btsnoop_hci.log \
    --output btsnoop_hci.btides \
    --schema-dir .

# sdptool XML directory or single file
./rust/target/release/sdp-to-BTIDES \
    --input  /path/to/sdptool/   \
    --output sdp_all.btides      \
    --schema-dir .
```

For `import-all-BTIDES` (bulk converter) and `wigle-to-BTIDES`, see the corresponding `Analysis/rust/` workspace in the parent [Blue2thprinting](https://github.com/darkmentorllc/Blue2thprinting) repository.

# Contributing

If you would like to contribute a definition of one of the protocol types not yet captured in a schema (we know there are many still), please reach out to discuss it first by contacting xeno🍥darkmentor.com.

If there is a basic error, please open an issue.
