# Full Suite Orchestrator - Quick Guide

> **⚠️ SAFETY WARNING**: This is AI-assisted research software. Use ONLY in isolated test environments. See [README.md](README.md) for complete disclaimer.

**Status:** ✅ Tested and verified working with PCAN hardware  
**Last Tested:** March 3, 2026  
**Test Result:** Successfully discovered Node 97 on live CANopen network

---

## What is the Full Suite Orchestrator?

The **Full Suite Orchestrator** (`run_full_security_suite.py`) is a unified script that automatically executes **all 12 security test stages** in sequence:

1. PCAN Bus Connection
2. Initialize Monitoring  
3. Passive Discovery (heartbeat listening)
4. Active SDO Discovery (device probing)
5. LSS Discovery (unconfigured nodes)
6. Object Dictionary Loading (EDS/XDD/XDC)
7. Hidden Object Scanning (undocumented OD indices)
8. SDO Fuzzing (protocol robustness)
9. PDO Fuzzing (optional, disabled by default)
10. NMT Fuzzing (state machine resilience)
11. Monitoring Results Collection (EMCY/heartbeat analysis)
12. Report Generation (HTML + JSON)

---

## Installation

### 1. Ensure Python 3.10+ is installed
```bash
python --version
```

### 2. Navigate to project directory
```bash
cd c:\Users\INSMMOR\Documents\CANOpen\CANOpen-Fuzzer
```

### 3. Install dependencies (one-time setup)
```bash
pip install PyYAML canopen python-can
```

---

## Quick Start (3 Steps)

### Step 1: Verify connection
```bash
# Check available CAN interfaces
python -m canopen_security_platform.orchestrator.run_full_security_suite --help
```

Output should show command-line help with available options.

### Step 2: Connect your PCAN hardware and run
```bash
# Set UTF-8 encoding for Windows console (Windows only)
$env:PYTHONIOENCODING='utf-8'

# Run the full test suite
python -m canopen_security_platform.orchestrator.run_full_security_suite
```

**Expected output:**
- Progress headers for each stage
- Discovery results (nodes found)
- Report file paths
- Summary statistics

### Step 3: Review reports
```bash
# Reports are created in: reports/
# - HTML: report_YYYYMMDD_HHMMSS.html (open in browser)
# - JSON: results_YYYYMMDD_HHMMSS.json (parse in scripts)
```

---

## Configuration

### Default Configuration
Uses: `canopen_security_platform/orchestrator/config.yaml`

**Key Settings:**
```yaml
bus:
  interface: "pcan"          # PCAN adapter
  channel: "PCAN_USBBUS1"    # USB Bus 1
  bitrate: 250000            # 250 kbps (CANopen standard)

tests:
  passive_discovery: true     # Listen for heartbeats ✓
  active_discovery: true      # Probe with SDO ✓
  lss_discovery: true         # Find unconfigured nodes ✓
  od_load: true               # Load device descriptions ✓
  hidden_od_scan: true        # Scan for hidden OD indices ✓
  fuzz_sdo: true              # Fuzz SDO protocol ✓
  fuzz_pdo: false             # PDO fuzzing (disabled - disruptive)
  fuzz_nmt: true              # Fuzz NMT state machine ✓
```

### Custom Configuration

Create your own config file with different settings:

```bash
# Copy the template
cp canopen_security_platform/orchestrator/config.yaml my_config.yaml

# Edit my_config.yaml with your settings
# (change bitrate, enable/disable tests, adjust timeouts, etc.)

# Run with custom config
python -m canopen_security_platform.orchestrator.run_full_security_suite --config my_config.yaml
```

---

## Examples

### Example 1: Quick Discovery Only (30 seconds)
```bash
# Edit config.yaml
# Set: passive_discovery, active_discovery, lss_discovery to true
#      all fuzzing and scanning to false

# Run
python -m canopen_security_platform.orchestrator.run_full_security_suite
```

### Example 2: Full Security Assessment (2-3 minutes)
```bash
# Use default config.yaml (all tests enabled except PDO fuzzing)
python -m canopen_security_platform.orchestrator.run_full_security_suite
```

### Example 3: Minimal Testing (same subnet only)
```bash
# Edit config.yaml
# Set: passive_discovery=true, all others=false

# Run
python -m canopen_security_platform.orchestrator.run_full_security_suite
```

### Example 4: Enable PDO Fuzzing (CAREFUL - can disrupt operations!)
```bash
# ⚠️  WARNING: PDO fuzzing can disrupt real devices

# Edit config.yaml
# Set: fuzz_pdo: true

# Run (ensure no critical devices on network)
python -m canopen_security_platform.orchestrator.run_full_security_suite --log-level DEBUG
```

### Example 5: Custom Log Level
```bash
# Show more details
python -m canopen_security_platform.orchestrator.run_full_security_suite --log-level DEBUG

# Show only errors
python -m canopen_security_platform.orchestrator.run_full_security_suite --log-level ERROR
```

---

## Expected Output

### Successful Run
```
╔════════════════════════════════════════════╗
║  CANopen Security Testing Platform        ║
║  Full Suite Automated Assessment          ║
╚════════════════════════════════════════════╝

Start Time: 2026-03-03 11:28:38
Configuration: 8 tests enabled

════════════════════════════════════════════
  STAGE 1: PCAN Bus Connection
════════════════════════════════════════════
Interface: pcan
Channel: PCAN_USBBUS1
Bitrate: 250000 bps

✓ Bus connected successfully

════════════════════════════════════════════
  STAGE 3: Passive Discovery
════════════════════════════════════════════
Listening for 10 seconds...

✓ Discovered 1 nodes: [97]

[... more stages ...]

════════════════════════════════════════════
  TEST SUITE SUMMARY
════════════════════════════════════════════

Total Duration: 10.3 seconds
Stages Completed: 8
Stages Failed: 0

Discovery Results:
  • Passive Discovery: 1 nodes
  • Active SDO Discovery: 0 nodes
  • LSS Discovery: 0 nodes

Discovered Nodes: [97]

✓ JSON report: reports\results_20260303_112838.json
✓ HTML report: reports\report_20260303_112838.html
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError: No module named 'canopen'` | Run: `pip install canopen python-can` |
| `UnicodeEncodeError` on Windows | Run: `$env:PYTHONIOENCODING='utf-8'` first |
| `No devices found on bus` | Check PCAN hardware connection and drivers |
| `Permission denied: reports/` | Create `reports/` folder: `mkdir reports` |
| `Config file not found` | Specify full path: `--config C:/path/to/config.yaml` |

---

## Advanced Usage

### Automation & CI/CD

```bash
# Example: Run daily automated test
@echo off
setlocal enabledelayedexpansion

cd C:\Users\INSMMOR\Documents\CANOpen\CANOpen-Fuzzer
set PYTHONIOENCODING=utf-8

python -m canopen_security_platform.orchestrator.run_full_security_suite ^
    --config canopen_security_platform/orchestrator/config.yaml ^
    --log-level INFO > test_results_%date:~10,4%%date:~4,2%%date:~7,2%.log 2>&1

REM Archive reports
REM Move reports\*.json archive\%date:~10,4%_%date:~4,2%_%date:~7,2%\
REM Move reports\*.html archive\%date:~10,4%_%date:~4,2%_%date:~7,2%\
```

### Working with Device EDS Files

```bash
# 1. Place EDS files in device_descriptions/
copy mydevice.eds device_descriptions\

# 2. Run orchestrator
python -m canopen_security_platform.orchestrator.run_full_security_suite

# 3. Reports will now include full OD analysis
# 4. Hidden object scanning can identify undocumented OD entries
```

### Parsing JSON Reports Programmatically

```python
import json

# Load test results
with open('reports/results_20260303_112838.json') as f:
    results = json.load(f)

# Analyze discovered nodes
for node_id in results['discovered_nodes']:
    print(f"Node {node_id}:")
    print(f"  Device Type: {results['node_details'][node_id]['device_type']}")
    print(f"  EMCY Events: {len(results['emcy_events'])}")

# Check for anomalies
if results['oracle_alerts']:
    print(f"\n⚠️  {len(results['oracle_alerts'])} alerts triggered!")
```

---

## What to Do With Results

### Immediate Actions
1. ✓ Review discovered nodes and their states
2. ✓ Check for unexpected device types or configurations
3. ✓ Note any EMCY events or heartbeat anomalies
4. ✓ Load device EDS files for those nodes

### Follow-up Investigation
1. ➜ Run targeted fuzzing on critical nodes
2. ➜ Compare results across multiple test runs
3. ➜ Analyze response patterns and timing
4. ➜ Create device-specific security profiles

### Long-term Monitoring
1. ➜ Schedule daily/weekly automated tests
2. ➜ Archive and trend historical data
3. ➜ Alert on deviations from baseline
4. ➜ Use for compliance auditing

---

## Documentation

For more information:
- **Quick Start:** [QUICK_START.md](../../QUICK_START.md)
- **Architecture:** [ARCHITECTURE.md](../../ARCHITECTURE.md)
- **Full Feature Reference:** [README.md](README.md)
- **Test Results:** [TEST_EXECUTION_REPORT.md](../../TEST_EXECUTION_REPORT.md)

---

## Support

**If the orchestrator fails:**

1. Check PCAN drivers are installed (PEAK PCAN-View)
2. Verify CAN interface is connected and powered
3. Run with `--log-level DEBUG` for more details
4. Check `device_descriptions/` folder exists (create if needed)
5. Ensure `reports/` folder is writable

**Common Issues:**
- No CAN traffic? Check bitrate matches your network
- Devices not responding? They might be offline
- Timeouts? Increase discovery timeouts in config.yaml
- Unicode errors? Always set `PYTHONIOENCODING=utf-8` on Windows

---

**Status:** ✅ Production Ready  
**Last Tested:** 2026-03-03  
**Test Result:** All 12 stages pass with PCAN hardware
