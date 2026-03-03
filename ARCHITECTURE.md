# Full Security Suite - Execution Flow & Architecture

> **⚠️ DISCLAIMER**: This is AI-assisted research software. Not for production use. See [README.md](README.md) for safety warnings and disclaimer.

---

## 🔄 Complete Execution Flow

```
┌─────────────────────────────────────────────────────────────────┐
│  SecurityTestSuite.run()                                        │
│  ├─ Print header with configuration summary                    │
│  └─ Execute test stages in sequence                            │
└─────────────────┬───────────────────────────────────────────────┘
                  │
                  ├──► STAGE 1: PCAN Bus Connection
                  │    │
                  │    ├─ Create BusInterface instance
                  │    ├─ Connect to CAN interface
                  │    ├─ Test connection status
                  │    └─ Initialize canopen.Network
                  │
                  ├──► STAGE 2: Initialize Monitoring
                  │    │
                  │    ├─ Create Oracle instance
                  │    ├─ Register alert rules
                  │    └─ Setup anomaly detection
                  │
                  ├──► STAGE 3: Passive Discovery
                  │    │
                  │    ├─ Create PassiveDiscovery instance
                  │    ├─ Listen for timeout seconds
                  │    ├─ Collect boot-up/heartbeat/EMCY frames
                  │    ├─ Extract node IDs and states
                  │    └─ Update TestResults.passive_nodes
                  │
                  ├──► STAGE 4: Active SDO Discovery
                  │    │
                  │    ├─ Create SDOProbe instance
                  │    ├─ For each target node:
                  │    │   ├─ Query 0x1000 (device type)
                  │    │   ├─ Query 0x1008 (device name)
                  │    │   ├─ Query device ID/vendor/product
                  │    │   └─ Collect device details
                  │    └─ Update TestResults.active_nodes
                  │
                  ├──► STAGE 5: LSS Discovery
                  │    │
                  │    ├─ Create LSSScanner instance
                  │    ├─ Binary search on 4-part identity
                  │    └─ Update TestResults.lss_nodes
                  │
                  ├──► STAGE 6: Object Dictionary Loading
                  │    │
                  │    ├─ Scan device_descriptions/ folder
                  │    ├─ Find .eds files
                  │    ├─ Find .xdd/.xdc files
                  │    ├─ If auto-convert enabled:
                  │    │   ├─ Create XDDConverter instance
                  │    │   └─ Convert .xdd/.xdc → .eds
                  │    ├─ Load each .eds file
                  │    ├─ Cache parsed OD files
                  │    └─ Match ODs to discovered nodes
                  │
                  ├──► STAGE 7: Hidden Object Scanning
                  │    │
                  │    ├─ For each active node:
                  │    │   ├─ Create HiddenObjectScanner
                  │    │   ├─ For each scan range:
                  │    │   │   ├─ Query each index
                  │    │   │   ├─ Collect responses
                  │    │   │   └─ Classify by abort code
                  │    │   └─ Find undocumented objects
                  │    └─ Update TestResults.hidden_objects
                  │
                  ├──► STAGE 8: SDO Fuzzing
                  │    │
                  │    ├─ For each target node:
                  │    │   ├─ Create SDOFuzzer
                  │    │   ├─ For each fuzzing strategy:
                  │    │   │   ├─ Run N iterations
                  │    │   │   ├─ Mutate SDO frames
                  │    │   │   ├─ Send to device
                  │    │   │   ├─ Collect responses
                  │    │   │   └─ Detect anomalies
                  │    │   └─ Record anomaly count
                  │    └─ Update TestResults.sdo_fuzzing_results
                  │
                  ├──► STAGE 9: PDO Fuzzing
                  │    │
                  │    ├─ For each target node:
                  │    │   ├─ Create PDOFuzzer
                  │    │   ├─ For each fuzzing strategy:
                  │    │   │   ├─ Corrupt PDO config/data
                  │    │   │   ├─ Send malformed PDOs
                  │    │   │   └─ Monitor for failures
                  │    │   └─ Record results
                  │    └─ Update TestResults.pdo_fuzzing_results
                  │
                  ├──► STAGE 10: NMT Fuzzing
                  │    │
                  │    ├─ For each target node:
                  │    │   ├─ Create NMTFuzzer
                  │    │   ├─ For each fuzzing strategy:
                  │    │   │   ├─ Send invalid NMT commands
                  │    │   │   ├─ Trigger state transitions
                  │    │   │   └─ Monitor recovery
                  │    │   └─ Record results
                  │    └─ Update TestResults.nmt_fuzzing_results
                  │
                  ├──► STAGE 11: Monitoring Results
                  │    │
                  │    ├─ Query Oracle for alerts
                  │    ├─ Extract EMCY events
                  │    ├─ Extract heartbeat anomalies
                  │    ├─ Categorize by severity
                  │    └─ Update TestResults monitoring fields
                  │
                  ├──► STAGE 12: Report Generation
                  │    │
                  │    ├─ Create reports/ directory
                  │    ├─ Export JSON results
                  │    │   └─ Serialize TestResults to JSON
                  │    ├─ Generate HTML report
                  │    │   ├─ Create executive summary
                  │    │   ├─ Create discovery table
                  │    │   ├─ Create hidden objects section
                  │    │   ├─ Create fuzzing results table
                  │    │   ├─ Include event logs
                  │    │   └─ Generate styled HTML
                  │    └─ Print report locations
                  │
                  ├──► Cleanup
                  │    └─ Close bus connection
                  │
                  └──► Print Final Summary
                       ├─ Completion statistics
                       ├─ Discovery summary
                       ├─ Issues/warnings
                       └─ Error details
```

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                   SecurityTestSuite                             │
│                                                                 │
│  ┌────────────────────────────────────────────────────────┐    │
│  │ Configuration Management                               │    │
│  │ ├─ Load YAML config file                              │    │
│  │ ├─ Validate parameters                                │    │
│  │ └─ Merge with defaults                                │    │
│  └────────────────────────────────────────────────────────┘    │
│                                                                 │
│  ┌────────────────────────────────────────────────────────┐    │
│  │ Result Collection                                      │    │
│  │ ├─ TestResults dataclass (stores all findings)        │    │
│  │ ├─ Node inventory                                     │    │
│  │ ├─ Fuzzing results                                    │    │
│  │ └─ Event logs                                         │    │
│  └────────────────────────────────────────────────────────┘    │
│                                                                 │
│  ┌────────────────────────────────────────────────────────┐    │
│  │ 12 Execution Stages                                    │    │
│  │ ├─ PCAN connection                                    │    │
│  │ ├─ Oracle initialization                              │    │
│  │ ├─ Discovery (passive + active + LSS)                │    │
│  │ ├─ OD loading & conversion                            │    │
│  │ ├─ Hidden scanning                                    │    │
│  │ ├─ Fuzzing (SDO + PDO + NMT)                         │    │
│  │ ├─ Results collection                                 │    │
│  │ └─ Report generation                                  │    │
│  └────────────────────────────────────────────────────────┘    │
│                                                                 │
│  ┌────────────────────────────────────────────────────────┐    │
│  │ Error Handling                                         │    │
│  │ ├─ Try/except on each stage                          │    │
│  │ ├─ Mark stage as failed but continue                 │    │
│  │ ├─ Track all errors in TestResults                   │    │
│  │ └─ Include in final report                           │    │
│  └────────────────────────────────────────────────────────┘    │
│                                                                 │
│  ┌────────────────────────────────────────────────────────┐    │
│  │ Output Generation                                      │    │
│  │ ├─ Console (rich human-readable)                      │    │
│  │ ├─ HTML report (styled, formatted)                    │    │
│  │ ├─ JSON report (structured, scriptable)              │    │
│  │ └─ Log files (debugging)                              │    │
│  └────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📊 Data Flow Diagram

```
                        Input
                          ↓
                   config.yaml file
                          ↓
            ┌─────────────────────────┐
            │  SecurityTestSuite      │
            │ (load config)           │
            └────────┬────────────────┘
                     ↓
            ┌─────────────────────────┐
            │ CAN Hardware            │
            │ (PCAN/Virtual/...  )    │
            └────────┬────────────────┘
                     ↓
        ┌───────────────────────────────┐
        │  Discovery Modules:           │
        │  - PassiveDiscovery           │
        │  - SDOProbe                   │
        │  - LSSScanner                 │
        └───────────┬───────────────────┘
                    ↓
            ┌──────────────────┐
            │ Node Inventory   │
            └────────┬─────────┘
                     ↓
        ┌───────────────────────────────┐
        │  Object Dictionary Loading:    │
        │  - EDSLoader                  │
        │  - XDDConverter               │
        │  - RuntimeObjectDictionary    │
        └───────────┬───────────────────┘
                    ↓
            ┌──────────────────┐
            │ OD Files Loaded  │
            └────────┬─────────┘
                     ↓
        ┌───────────────────────────────┐
        │  Scanning & Fuzzing:          │
        │  - HiddenObjectScanner        │
        │  - SDOFuzzer                  │
        │  - PDOFuzzer                  │
        │  - NMTFuzzer                  │
        └───────────┬───────────────────┘
                    ↓
            ┌──────────────────┐
            │ Oracle Monitoring│
            │ (EMCY, heartbeat)│
            └────────┬─────────┘
                     ↓
            ┌──────────────────┐
            │  TestResults     │
            │  (all findings)  │
            └────────┬─────────┘
                     ↓
        ┌───────────────────────────────┐
        │  Report Generation:           │
        │  - HTML generation            │
        │  - JSON export                │
        │  - Console output             │
        └───────────┬───────────────────┘
                    ↓
                 Output
                    ├─ reports/report_*.html
                    ├─ reports/results_*.json
                    └─ Console summary
```

---

## 🎯 Class Hierarchy

```
TestResults (Dataclass)
├── Timing
│   ├─ start_time: datetime
│   └─ end_time: Optional[datetime]
│
├── Configuration
│   └─ config: Dict[str, Any]
│
├── Discovery Data
│   ├─ passive_nodes: Set[int]
│   ├─ active_nodes: Set[int]
│   ├─ lss_nodes: List[Dict]
│   └─ node_details: Dict[int, Dict]
│
├── OD Loading
│   ├─ loaded_ods: Dict[int, str]
│   └─ od_errors: List[str]
│
├── Scan Results
│   └─ hidden_objects: Dict[int, List[Dict]]
│
├── Fuzzing Results
│   ├─ sdo_fuzzing_results: Dict[int, Dict]
│   ├─ pdo_fuzzing_results: Dict[int, Dict]
│   └─ nmt_fuzzing_results: Dict[int, Dict]
│
├── Monitoring
│   ├─ emcy_events: List[Dict]
│   ├─ heartbeat_anomalies: List[Dict]
│   └─ oracle_alerts: List[Dict]
│
├── Issues
│   ├─ warnings: List[str]
│   └─ errors: List[str]
│
└── Stage Tracking
    ├─ completed_stages: List[str]
    └─ failed_stages: List[str]


SecurityTestSuite (Main Orchestrator)
├── __init__(config_path)
│   ├─ Load configuration
│   └─ Initialize TestResults
│
├── run() → TestResults
│   ├─ _print_header()
│   ├─ _stage_connect_pcan()
│   ├─ _stage_initialize_oracle()
│   ├─ _stage_passive_discovery()
│   ├─ _stage_active_discovery()
│   ├─ _stage_lss_discovery()
│   ├─ _stage_load_object_dictionaries()
│   ├─ _stage_hidden_od_scan()
│   ├─ _stage_sdo_fuzzing()
│   ├─ _stage_pdo_fuzzing()
│   ├─ _stage_nmt_fuzzing()
│   ├─ _stage_collect_oracle_results()
│   ├─ _stage_generate_reports()
│   ├─ _cleanup()
│   └─ _print_summary()
│
├── Configuration Helpers
│   ├─ _load_config()
│   └─ _default_config()
│
├── Reporting
│   ├─ _export_json()
│   ├─ _generate_html_report()
│   └─ _get_fuzzing_targets()
│
└── Display
    ├─ _print_stage_header()
    └─ _print_summary()
```

---

## 🔌 Module Integration Points

```
SecurityTestSuite
│
├──► hal/bus_pcan.py
│    └─ BusInterface
│       ├─ __init__() → Connect to PCAN
│       ├─ send()     → Send CAN frame
│       ├─ recv()     → Receive CAN frame
│       └─ close()    → Close connection
│
├──► discovery/passive.py
│    └─ PassiveDiscovery
│       ├─ __init__()     → Initialize listener
│       ├─ discover()     → Listen for frames
│       └─ get_node_state() → Get NMT state
│
├──► discovery/sdo_probe.py
│    └─ SDOProbe
│       ├─ __init__()     → Initialize probe
│       └─ probe_node()   → Query device identification
│
├──► discovery/lss_scan.py
│    └─ LSSScanner
│       ├─ __init__()     → Initialize scanner
│       └─ fastscan()     → Binary search discovery
│
├──► od/eds_loader.py
│    └─ EDSLoader
│       ├─ __init__()     → Setup loader
│       └─ load()         → Load EDS file
│
├──► od/xdd_converter.py
│    └─ XDDConverter
│       ├─ __init__()     → Find converter tool
│       ├─ is_available() → Check if available
│       └─ convert()      → XDD/XDC → EDS
│
├──► od/hidden_scanner.py
│    └─ HiddenObjectScanner
│       ├─ __init__()      → Initialize scanner
│       └─ scan_ranges()   → Brute-force scan
│
├──► fuzzing/sdo_fuzzer.py
│    └─ SDOFuzzer
│       ├─ __init__()            → Setup fuzzer
│       └─ fuzz_with_strategy()  → Fuzz with strategy
│
├──► fuzzing/pdo_fuzzer.py
│    └─ PDOFuzzer
│       ├─ __init__()            → Setup fuzzer
│       └─ fuzz_with_strategy()  → Fuzz with strategy
│
├──► fuzzing/nmt_fuzzer.py
│    └─ NMTFuzzer
│       ├─ __init__()            → Setup fuzzer
│       └─ fuzz_with_strategy()  → Fuzz with strategy
│
├──► monitoring/oracle.py
│    └─ Oracle
│       ├─ __init__()      → Initialize oracle
│       ├─ add_rule()      → Register alert rule
│       ├─ record_event()  → Log event
│       ├─ get_alerts()    → Get triggered alerts
│       └─ get_all_events() → Get event history
│
└──► utils/logging_utils.py
     └─ get_logger()
        └─ Get configured logger instance
```

---

## 🎬 Sample Execution Timeline

```
Time    Action                                  Duration  Cumulative
────────────────────────────────────────────────────────────────────
00:00   Start suite                                               0s
00:01   Stage 1 - PCAN Connect                   1s             1s
00:02   Stage 2 - Initialize Oracle              1s             2s
00:14   Stage 3 - Passive Discovery (listen)    12s            14s
00:22   Stage 4 - Active Discovery               8s            22s
00:32   Stage 5 - LSS Discovery                 10s            32s
00:37   Stage 6 - OD Loading                     5s            37s
01:37   Stage 7 - Hidden Scanning              60s            97s
02:17   Stage 8 - SDO Fuzzing                  40s           137s
02:47   Stage 9 - PDO Fuzzing                  30s           167s
03:07   Stage 10 - NMT Fuzzing                 20s           187s
03:09   Stage 11 - Monitoring Results           2s           189s
03:11   Stage 12 - Report Generation            2s           191s
03:12   Final Summary                           1s           192s
────────────────────────────────────────────────────────────────────
Total                                                        192s (~3.2 min)
```

---

## 💾 Memory & Resource Usage

```
Component              Memory      Notes
─────────────────────────────────────────────────────────────
Base Python             ~20 MB
CANopen modules         ~15 MB
CAN Bus interface       ~5 MB
Config + logging        ~2 MB
TestResults storage     ~8 MB      Per run; grows with results
                        ──────
Per 5-node network:    ~50 MB     Baseline for 5 nodes

Hidden scanning         +20 MB     During scanning phase
Fuzzing (in progress)   +30 MB     SDO/PDO/NMT combined
Peak usage:            ~100 MB     All active simultaneously

Reports in memory       ~2 MB      HTML/JSON generation
Total peak:           ~100 MB     Typical for 5 nodes
                      ~150 MB     With 10+ nodes
```

---

## 🔐 Error Recovery Strategy

```
For Each Stage:
  ┌──────────────────────┐
  │ Try Stage Execution  │
  └──────────┬───────────┘
             │
    ┌────────┴────────┐
    │                 │
    ▼ SUCCESS         ▼ ERROR
    │                 │
  Mark:          ┌────────────────────┐
  - Stage        │ Catch Exception    │
    Completed    ├────────────────────┤
  - Add to       │ Log error          │
    completed    │ Mark stage failed  │
    list         │ Add to errors list │
                 │ Continue execution │
                 └─────────┬──────────┘
                           │
                           ▼
                    (Next Stage)
```

Result: Failed stages don't stop the suite; continue testing other stages and report all issues at the end.

---

## 📈 Scalability

```
Network Size    Discovery Time   Hidden Scan   Fuzzing    Total
────────────────────────────────────────────────────────────────
1 node            5 sec           10 sec        30 sec     45 sec
5 nodes          10 sec           30 sec        90 sec    130 sec  
10 nodes         15 sec           90 sec       200 sec    305 sec
25 nodes         20 sec          200 sec       500 sec    720 sec
50 nodes         25 sec          400 sec     1000 sec    1425 sec
```

**Key factors**:
- Discovery time: Linear in node count
- Hidden scanning: Linear in node count (parallel workers help)
- Fuzzing: Linear in node count × iterations
- Can parallelize node fuzzing for large networks

---

## 🎯 Test Coverage

```
Protocol Layer              Tests Performed
─────────────────────────────────────────────
Hardware (CAN)            - Connection/status
                          - Bus state monitoring

Discovery Layer           - Passive listening
                          - Active SDO probing
                          - LSS binary search

Object Dictionary         - File format support
                          - Auto-conversion
                          - Index matching

OD Coverage               - Hidden object scanning
                          - Access right verification
                          - Undocumented objects

SDO Protocol              - CS byte corruption
                          - Wrong length fields
                          - Overflow/underflow
                          - Illegal indices
                          - Read-only writing
                          - Write-only reading
                          - Segmentation errors
                          - Timeout simulation

PDO Protocol              - COB-ID corruption
                          - Invalid PDO lengths
                          - Data mutation
                          - Burst flooding

NMT Protocol              - Invalid commands
                          - Wrong node IDs
                          - Rapid transitions
                          - Recovery monitoring

Monitoring                - EMCY detection
                          - Heartbeat timeout
                          - Anomaly detection
                          - Alert rule matching
```

---

This represents the complete architecture and execution flow of the Full Security Suite Orchestrator.
