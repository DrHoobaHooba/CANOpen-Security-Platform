# CANopen Security Platform

A modular Python framework for CANopen security research and fuzzing on Windows + PCAN hardware.

---

## ⚠️ Important Disclaimer

**This project was developed with AI assistance (GitHub Copilot/Claude) and is intended for RESEARCH AND EDUCATIONAL PURPOSES ONLY.**

### Critical Safety Warnings

- ⚠️ **NOT for production use** without extensive independent review and validation
- ⚠️ **NOT safety-certified** or suitable for safety-critical systems
- ⚠️ **AI-generated code** may contain bugs, security vulnerabilities, or logic errors
- ⚠️ **CAN bus fuzzing** can disrupt network operations and potentially damage equipment
- ⚠️ **Use only in isolated test environments** with proper supervision
- ⚠️ **Testing on live operational systems** could cause system failures, data loss, or safety hazards

### Responsible Use

- ✅ Use in isolated lab environments only
- ✅ Obtain proper authorization before testing
- ✅ Conduct thorough code review before deployment
- ✅ Test on non-critical systems first
- ✅ Have rollback/recovery procedures in place
- ✅ Comply with all applicable laws and regulations

### No Warranty

This software is provided **"AS IS"** without warranty of any kind. The authors and contributors assume **NO LIABILITY** for any damages, losses, or consequences resulting from its use.

Licensed under the **Apache License 2.0** - see [LICENSE](LICENSE) for full terms, including:
- Strong liability disclaimers (Section 7 & 8)
- Explicit patent grants (Section 3)
- Contribution terms (Section 5)

### Verification Recommended

- Independent security audit recommended before production use
- Thorough testing required on target hardware
- Compliance verification for safety-critical applications
- Professional review of AI-generated code sections

**By using this software, you acknowledge these risks and agree to use it responsibly and at your own risk.**

---

## Quick Start

```sh
# Install
pip install -e .

# Run full automated test suite (all 12 stages)
python -m canopen_security_platform.orchestrator.run_full_security_suite

# Or run individual operations
cansec --bitrate 250000 enumerate      # Discovery
cansec --bitrate 250000 fuzz-sdo 1     # Fuzz a node
```

See [ORCHESTRATOR_QUICK_GUIDE.md](ORCHESTRATOR_QUICK_GUIDE.md) for full test suite configuration and examples.

## Architecture Overview

The platform is organized into functional layers:

- **HAL**: Direct PCAN hardware interface
- **Discovery**: Passive, SDO, and LSS scanning
- **OD**: Object dictionary loading, XDD conversion, hidden scanning
- **Fuzzing**: Modular fuzzers for SDO, PDO, NMT, LSS
- **Monitoring**: Event tracking and oracle callbacks
- **Orchestrator**: Full 12-stage automated security test suite
- **CLI**: Command-line entry point with argparse
- **Utils**: Shared logging and frame utilities

## Installation & Setup

### From the project root:

```sh
pip install -e .
```

This installs `canopen-security-platform` in editable mode and registers the global `cansec` command.

### Verify installation:

```sh
cansec --help
```

### Default OD file folder (auto-discovery)

By default, the CLI looks for OD files in the project root under these folder names (in order):

1. `od_files`
2. `object_dictionary`
3. `object_dictionaries`
4. `od`
5. `eds`

Inside the first matching folder, file types are selected in this priority:

1. `.eds`
2. `.xdc`
3. `.xdd`

If a file is found, it is loaded automatically (and `.xdc`/`.xdd` are converted to `.eds` when a converter is available).

Example:

```text
CANOpen-Security-Platform/
    od_files/
        device.eds
```

---

## Full Test Suite (Orchestrator)

The platform includes a complete 12-stage automated security test suite that runs all discovery, scanning, and fuzzing operations sequentially with integrated monitoring and reporting.

### Running the Full Suite

```sh
# Run with default configuration from config.yaml
python -m canopen_security_platform.orchestrator.run_full_security_suite

# Run with custom configuration
python -m canopen_security_platform.orchestrator.run_full_security_suite --config custom.yaml
```

### The 12 Stages

| Stage | Name | Purpose |
|-------|------|---------|
| 1 | PCAN Bus Connection | Establish CAN interface connection |
| 2 | Initialize Monitoring | Set up Oracle anomaly detection |
| 3 | Passive Discovery | Listen for heartbeats, EMCY, boot-up |
| 4 | Active SDO Discovery | Probe nodes for device identity |
| 5 | LSS Discovery | Scan for unconfigured nodes |
| 6 | OD Loading | Load EDS/XDD/XDC device descriptions |
| 7 | Hidden Object Scanning | Brute-force scan for undocumented OD indices |
| 8 | SDO Fuzzing | Send 31 malformed SDO requests |
| 9 | PDO Fuzzing | Send 137 PDO mutations |
| 10 | NMT Fuzzing | Send 73 NMT state machine violations |
| 11 | Monitoring Results | Collect detected anomalies and events |
| 12 | Report Generation | Create HTML and JSON reports |

### Configuration

Edit `canopen_security_platform/orchestrator/config.yaml`:

```yaml
tests:
    fuzz_sdo: true
    fuzz_pdo: true        # ⚠ can disrupt operations on active networks
    fuzz_nmt: true

object_dictionary:
    device_descriptions_dir: "od_files"

reporting:
    output_dir: "reports"
```

### Test Results

Latest verified run (2026-03-03):
- **Duration**: 15.7 seconds
- **Stages Completed**: 12/12 (0 failures)
- **Nodes Discovered**: 1 (Node 97 via passive)
- **CAN Frames Transmitted**: 171
- **Mutations Sent**: 241 (39 SDO + 137 PDO + 73 NMT)
- **OD Objects Loaded**: 45 from EDS
- **Errors**: 0
- **Status**: ✅ Verified on lab hardware (research use)

See [WHATS_CHANGED.md](WHATS_CHANGED.md) for detailed test results and [ORCHESTRATOR_QUICK_GUIDE.md](ORCHESTRATOR_QUICK_GUIDE.md) for advanced usage.

---

## Module Reference

### HAL (bus_pcan.py) - ✅ Ready

Direct PCAN interface with context manager support.

```python
from canopen_security_platform.hal.bus_pcan import BusInterface

config = {"bitrate": 250000, "channel": "PCAN_USBBUS1"}
with BusInterface(config=config) as bus:
    msg = bus.recv(timeout=1.0)
    bus.send(msg)
```

**Methods:**
- `send(frame)`, `recv(timeout)`, `iterate(timeout)`
- `flush_tx()`, `flush_rx()`
- Context manager support

---

### Discovery (discovery/) - ✅ Ready and Enhanced

The discovery layer has been fully implemented with passive listening, active SDO
probing, and LSS scanning.  All components now include robust parsing, error
handling, retries, and metadata aggregation.

#### **passive.py** - Listen for boot-up, heartbeat, EMCY, PDOs

```python
from canopen_security_platform.discovery.passive import PassiveDiscovery
passive = PassiveDiscovery(bus)
nodes = passive.run(timeout=5.0)  # Returns Set[int]
node_info = passive.get_all_node_info()
```

*Features added:*
- Detailed COB‑ID classification (heartbeat, EMCY, TPDO/RPDO)
- NMT state tracking with transitions
- EMCY parsing and event logging
- Noise filtering via timeouts

#### **sdo_probe.py** - Active SDO discovery with retries

```python
from canopen_security_platform.discovery.sdo_probe import SDOProbe
probe = SDOProbe(network)
results = probe.scan(start=1, end=127)  # Dict[node_id, {info}]
```

*Features added:*
- Automatic querying of 0x1000, 0x1008, 0x1009, 0x100A, 0x1018
- Retry logic, timeout handling, and scan statistics
- Identity object parsing (vendor ID, product code, etc.)

#### **lss_scan.py** - Fast and reliable LSS scanning

```python
from canopen_security_platform.discovery.lss_scan import LSSScanner
lss = LSSScanner(network)
identities = lss.fast_scan()  # List[(VendorID, ProductCode, Revision, Serial)]
```

*Features added:*
- Native python-canopen support with fallback manual binary search stub
- Node ID assignment utilities and selective mode queries
- Timeout management and identification helpers

#### **enumerator.py** - Unified discovery orchestration

```python
from canopen_security_platform.discovery.enumerator import NodeEnumerator
enum = NodeEnumerator(bus=bus)
enum.discover_all()
inventory = enum.get_inventory()
```

*Features added:*
- Coordinated passive, SDO, and LSS discovery with timing metadata
- Inventory aggregation, node summaries, and error reporting
- Optional per-method control and targeted SDO probes

---

### OD Layer (od/) - ✅ Ready and Extensible

The OD layer now supports full EDS handling, XDD conversion, live OD syncing,
hidden-object scanning, and metadata reporting.

#### **eds_loader.py** - Load, validate, and cache EDS files

```python
from canopen_security_platform.od.eds_loader import EDSLoader
loader = EDSLoader(cache_dir=".cache")
od = loader.load("device.eds")
metadata = loader.get_od_metadata(od)
```

*Features added:*
- In‑memory and optional disk cache
- File existence checks and validation
- Metadata extraction and index categorization
- Error handling with informative logs

#### **xdd_converter.py** - Robust XDD/XDC to EDS conversion

```python
from canopen_security_platform.od.xdd_converter import XDDConverter
converter = XDDConverter()
eds = converter.convert("device.xdd")
```

*Features added:*
- Automatic tool discovery and availability checks
- Output validation and timeout handling
- Detailed error reporting

#### **runtime_od.py** - Live node state tracking & audit

```python
from canopen_security_platform.od.runtime_od import RuntimeObjectDictionary
runtime_od = RuntimeObjectDictionary()
runtime_od.register_node(node, sync_on_register=True)
values = runtime_od.sync_from_node(node)
```

*Features added:*
- Sync object values from remote nodes
- Modification history with source tagging
- Queryable tracked values and sync status

#### **hidden_scanner.py** - Optimized hidden object enumeration

```python
from canopen_security_platform.od.hidden_scanner import HiddenObjectScanner
scanner = HiddenObjectScanner(network, max_workers=8)
hidden = scanner.scan_node(1)
diffs = scanner.diff_with_eds(1, od)
report = scanner.export_report(1, "reports/scan1.json")
```

*Features added:*
- Priority ranges and parallel scanning
- Subindex enumeration with timeout control
- Detailed diffs (hidden/missing/subindex mismatches)
- JSON report export with statistics

---

### Fuzzing Engine (fuzzing/) - ✅ Ready

All fuzzers follow the same pattern and include multiple mutation strategies:

```python
from canopen_security_platform.fuzzing.sdo_fuzzer import SDOFuzzer

fuzzer = SDOFuzzer(bus=bus, od=od, node_id=1, oracle=oracle_callback)
fuzzer.execute()
```

#### **sdo_fuzzer.py** - Service Data Objects

*Implemented strategies:*
- Command specifier mutations
- Wrong length fields
- Overflow/underflow boundary values
- Illegal index access
- Read/write violations
- Segmentation/toggle errors

#### **pdo_fuzzer.py** - Process Data Objects

*Implemented strategies:*
- COB-ID mutation
- Mapping mutation
- Transmission type abuse
- Timing mutation and SYNC timing stress
- Data payload fuzzing

#### **nmt_fuzzer.py** - Network Management

*Implemented strategies:*
- Rapid transitions
- Illegal transitions
- Broadcast attacks
- Command field corruption

#### **lss_fuzzer.py** - Layer Setting Services

*Implemented strategies:*
- State confusion
- Bit timing fuzzing
- Device identification fuzzing
- Rapid command sequences
- Timing side-channel probing

---

### Monitoring (monitoring/) - ✅ Ready & Analytical

Monitoring now records every EMCY, heartbeat, timeout, and reboot, with
persistence, alert rules, and reporting built in.

#### **oracle.py** - Behavior tracking with persistence and alerts

```python
from canopen_security_platform.monitoring.oracle import Oracle, AlertRule

oracle = Oracle(persist_dir="./logs")
# add a simple rule that flags any EMCY event
rule = AlertRule(
    name="any_emcy",
    event_type="emcy",
    condition=lambda e: True,
    severity="warning",
)
oracle.add_alert_rule(rule)
```

*Features added:*
- Event log with optional JSONL persistence
- AlertRule system for custom detection
- Node summaries and statistics
- Exportable reports with recent events and triggered alerts

#### **event_handlers.py** - CAN callback integration

```python
from canopen_security_platform.monitoring.event_handlers import EventHandlers

handlers = EventHandlers(oracle=oracle, async_mode=True)
handlers.attach(network)
```

*Features added:*
- EMCY, heartbeat, and SYNC callbacks
- Asynchronous processing via background queue/thread
- Detailed frame parsing and error handling
- Stop method for clean shutdown

---

### CLI (cli/main.py) - ✅ Ready

```sh
cansec [--bitrate BITRATE] [--channel CHANNEL] COMMAND [ARGS]
```

**Commands:**
- `enumerate` – Run all discovery
- `od-dump <node>` – Dump OD (basic listing)
- `scan-hidden <node>` – Scan hidden objects
- `fuzz-sdo <node>` – Run SDO fuzz
- `fuzz-pdo <node>` – Run PDO fuzz
- `fuzz-nmt <node>` – Run NMT fuzz
- `fuzz-lss` – Run LSS fuzz

For OD-aware commands (`od-dump`, `scan-hidden`, `fuzz-sdo`, `fuzz-pdo`, `fuzz-nmt`, `fuzz-lss`), the CLI automatically loads a reference OD from default folders when available: `od_files`, `object_dictionary`, `object_dictionaries`, `od`, `eds`.

---

### Utils (utils/) - ✅ Ready

- **logging_utils.py** – Centralized logging
- **frame_utils.py** – CAN message helpers

---

## Implementation Status

| Component | Status | Notes |
|-----------|--------|-------|
| HAL (PCAN) | ✅ Ready | Full context manager |
| Passive Discovery | ✅ Ready | Extensive parsing, NMT & EMCY tracking |
| SDO Probe | ✅ Ready | Retries, identity queries, stats |
| LSS Scan | ✅ Ready | Fast-scan skeleton & assignment APIs |
| EDS/XDD | ✅ Ready | Caching, validation, converter wrapper |
| OD Runtime | ✅ Ready | Live syncing & modification log |
| Hidden Scanner | ✅ Ready | Parallel scan & JSON reporting |
| **SDO/PDO/NMT/LSS Fuzzers** | ✅ Ready | Full fuzzing suite with OD utilization |
| Oracle | ✅ Ready | Persistence & alert rules added |
| Event Handlers | ✅ Ready | Async CAN callbacks integrated |
| **Orchestrator** | ✅ Ready | 12-stage automated test suite |
| CLI | ✅ Ready | All commands implemented |

---

## Development Roadmap

### Current State (March 2026)
- [x] Discovery stack complete (passive, SDO, LSS)
- [x] OD pipeline complete (EDS load, XDD/XDC conversion hooks, hidden scan)
- [x] Fuzzing engines available (SDO, PDO, NMT, LSS)
- [x] Orchestrator integrated (12-stage run with JSON/HTML reporting)
- [x] Baseline unit tests present for discovery, fuzzing, HAL, OD, monitoring

### Near-Term Priorities
- [ ] Add CI coverage gate and publish coverage percentage in reports
- [ ] Expand negative-path tests for orchestrator stage failures and recovery
- [ ] Add configuration profiles for safer default fuzzing presets

### Mid-Term Priorities
- [ ] Add optional persistent event backend (SQLite/PostgreSQL)
- [ ] Introduce baseline-vs-current diff reporting between runs
- [ ] Add machine-readable risk scoring per node/device

### Long-Term Goals
- [ ] Real-time dashboard for fleet/node health and anomaly trends
- [ ] SIEM integrations for alert forwarding
- [ ] Extended protocol security checks (segmented/block transfer edge cases)

---

## Example Workflows

### Discovery

```sh
# Passive 5-second listen (default 250kbit/s)
cansec enumerate

# With explicit bitrate
cansec --bitrate 250000 enumerate

# Custom channel
cansec --bitrate 250000 --channel PCAN_USBBUS1 enumerate

# Passive-only discovery
cansec enumerate --passive-only --timeout 5

# Detect available CAN interfaces
cansec --detect
```

### Hidden Object Scan

If a default OD file is present in one of the auto-discovery folders (`od_files`, `object_dictionary`, `object_dictionaries`, `od`, `eds`), `scan-hidden` will automatically diff scan results against it.

```sh
cansec --bitrate 250000 scan-hidden 1

# Limit scan to a small index range (hex)
cansec --bitrate 250000 scan-hidden 1 --range 1000-10FF
```

### OD Dump

`od-dump` also uses the default OD auto-discovery folders (`od_files`, `object_dictionary`, `object_dictionaries`, `od`, `eds`). If live SDO OD enumeration is empty or unavailable, it falls back to the discovered reference OD.

```sh
cansec --bitrate 250000 od-dump 1
```

### SDO Fuzzing

`fuzz-sdo` loads the default discovered OD as runtime reference context when available.

```sh
cansec --bitrate 250000 fuzz-sdo 1
```

### PDO/NMT/LSS Fuzzing

`fuzz-pdo`, `fuzz-nmt`, and `fuzz-lss` also load the default discovered OD as runtime reference context when available.

```sh
cansec --bitrate 250000 fuzz-pdo 1
cansec --bitrate 250000 fuzz-nmt 1
cansec --bitrate 250000 fuzz-lss
```

### Python API

```python
from canopen_security_platform.hal.bus_pcan import BusInterface
from canopen_security_platform.discovery.enumerator import NodeEnumerator

with BusInterface(config={"bitrate": 250000}) as bus:
    enum = NodeEnumerator(bus=bus)
    enum.discover_all()
    print(enum.get_inventory())
```

---

## Known limitations

- LSS fast scan includes a simplified binary-search fallback
- `od-dump --output` is not yet implemented (prints basic listing)
- SDO probing depends on a node responding to 0x1000; some devices may restrict access

---

## Notes

- All code uses **type hints** for IDE support
- Uses **logging instead of print()**
- **No external CLI dependencies** except CANopen Editor (optional for XDD)

---

## License

This project is licensed under the **Apache License 2.0**.

See [LICENSE](LICENSE) file for the full text.

**Key Points:**
- ✅ Free to use, modify, and distribute
- ✅ Explicit patent grant from contributors
- ✅ Strong liability protection
- ✅ Commercial use allowed
- ⚠️ Must preserve copyright and license notices
- ⚠️ State changes made to files

**Copyright © 2026 CANopen Security Platform Contributors**
