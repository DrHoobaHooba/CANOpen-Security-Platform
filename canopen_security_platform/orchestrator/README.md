# CANopen Security Testing Platform - Orchestrator Suite

## Overview

The **Full Automation Suite** is a unified orchestrator that runs the entire CANopen security testing workflow sequentially with comprehensive progress reporting, rich console output, and centralized configuration management.

## Features

✓ **Complete Test Automation** - Runs all security tests in a logical sequence  
✓ **Configuration-Driven** - All tests controlled via YAML config (no code changes needed)  
✓ **Rich Console Output** - Human-readable progress with status indicators  
✓ **Graceful Error Handling** - Failures don't stop the suite; they're tracked and reported  
✓ **Comprehensive Logging** - All activities logged for debugging and audit trails  
✓ **HTML & JSON Reports** - Automated report generation with timestamps  
✓ **Modular Architecture** - Each stage is independent and reusable  
✓ **Type Hints & Documentation** - Production-ready code with full docstrings  

## Test Stages

The orchestrator runs 12 stages in sequence:

```
STAGE 1:  PCAN Bus Connection          → Establish CAN interface
STAGE 2:  Initialize Monitoring        → Setup anomaly detection & event tracking
STAGE 3:  Passive Discovery            → Listen for boot-up/heartbeat/EMCY frames
STAGE 4:  Active SDO Discovery         → Probe nodes for device identification
STAGE 5:  LSS Discovery                → Scan for unconfigured nodes
STAGE 6:  Object Dictionary Loading    → Load and convert EDS/XDD/XDC files
STAGE 7:  Hidden Object Scanning       → Brute-force scan for undocumented OD indices
STAGE 8:  SDO Fuzzing                  → Test SDO protocol robustness
STAGE 9:  PDO Fuzzing                  → Test PDO configuration/transmission
STAGE 10: NMT Fuzzing                  → Test NMT state machine
STAGE 11: Monitoring Results           → Collect EMCY, heartbeat, and anomaly data
STAGE 12: Report Generation            → Create HTML and JSON reports
```

## File Structure

```
canopen_security_platform/
├── orchestrator/
│   ├── __init__.py                     # Package initialization
│   ├── run_full_security_suite.py      # Main orchestrator (THIS FILE)
│   └── config.yaml                     # Configuration template
│
├── reporting/
│   ├── __init__.py                     # Package initialization
│   └── html_reporter.py                # HTML report generator (coming soon)
│
└── device_descriptions/                # OD file storage
    └── README.md                       # Device descriptions guide

reports/                                # Output directory (created automatically)
├── report_TIMESTAMP.html               # HTML test report
└── results_TIMESTAMP.json              # JSON test results
```

## Installation & Setup

### 1. Prerequisites

```bash
# Install required Python packages
pip install python-can canopen PyYAML pytest

# For XDD/XDC conversion (optional)
# Install CANopen Editor from https://www.beckhoff.com/
```

### 2. Place Device Descriptions

```bash
# Copy your EDS/XDD/XDC files to:
device_descriptions/
├── motor_driver.eds
├── io_module.eds
└── plc_device.xdd              # Will auto-convert to EDS if converter available
```

### 3. Configure Settings (Optional)

Edit `canopen_security_platform/orchestrator/config.yaml` to customize:
- CAN bus parameters (interface, channel, bitrate)
- Which tests to run (all enabled by default)
- Discovery parameters (timeouts, node ranges)
- Fuzzing iterations and strategies
- Report output format

## Usage

### Basic Run (Default Configuration)

```bash
# Run with default config
python -m canopen_security_platform.orchestrator.run_full_security_suite

# Output:
# ╔══════════════════════════════════════════════════════════════════════╗
# ║         CANopen Security Testing Platform - Full Suite              ║
# ║                    Automated Security Assessment                     ║
# ╚══════════════════════════════════════════════════════════════════════╝
#
# Start Time: 2026-03-03 14:28:45
# Configuration: 11 tests enabled
# ────────────────────────────────────────────────────────────────────────
# 
# ════════════════════════════════════════════════════════════════════════
#   STAGE 1: PCAN Bus Connection
#   Establishing connection to CAN bus
# ════════════════════════════════════════════════════════════════════════
# 
# Interface: pcan
# Channel: PCAN_USBBUS1
# Bitrate: 250000 bps
# 
# ✓ Bus connected successfully
#   Status: Bus OK
```

### Custom Configuration

```bash
# Run with custom config file
python -m canopen_security_platform.orchestrator.run_full_security_suite \
    --config my_custom_config.yaml
```

### Debug Mode

```bash
# Run with debug logging
python -m canopen_security_platform.orchestrator.run_full_security_suite \
    --log-level DEBUG
```

### Quiet Mode

```bash
# Run with minimal logging (ERROR level only)
python -m canopen_security_platform.orchestrator.run_full_security_suite \
    --log-level ERROR
```

## Configuration Guide

### Minimal Configuration (config.yaml)

```yaml
# Only required field - everything else has defaults
bus:
  interface: "pcan"
  channel: "PCAN_USBBUS1"
  bitrate: 250000
```

### Common Configuration Patterns

**Production Testing (All Tests)**
```yaml
tests:
  passive_discovery: true
  active_discovery: true
  lss_discovery: true
  od_load: true
  hidden_od_scan: true
  fuzz_sdo: true
  fuzz_pdo: true          # Caution: can disrupt operations
  fuzz_nmt: true
  monitor_emcy: true
  monitor_heartbeat: true
```

**Quick Discovery Only**
```yaml
tests:
  passive_discovery: true
  active_discovery: true
  lss_discovery: true
  od_load: true
  hidden_od_scan: false
  fuzz_sdo: false
  fuzz_pdo: false
  fuzz_nmt: false
  monitor_emcy: true
  monitor_heartbeat: true
```

**Safety-Critical (Minimal Disruption)**
```yaml
tests:
  passive_discovery: true
  active_discovery: true
  lss_discovery: false
  od_load: true
  hidden_od_scan: true
  fuzz_sdo: false         # Skip SDO fuzzing
  fuzz_pdo: false         # Skip PDO fuzzing
  fuzz_nmt: false         # Skip NMT fuzzing
  monitor_emcy: true
  monitor_heartbeat: true
```

### All Configuration Options

See [config.yaml](./config.yaml) for comprehensive documentation of every option including:

- **Bus Configuration**: Interface type, channel, bitrate
- **Discovery Parameters**: Timeouts, retry counts, node ranges
- **Object Dictionary**: Cache settings, auto-conversion, preferred format
- **Hidden Scanner**: Range selection, parallel workers, request delays
- **Fuzzing Parameters**: Iteration counts, mutation strategies, target nodes
- **Monitoring**: Alert thresholds, anomaly detection, state tracking
- **Reporting**: Output directory, format selection, logging options
- **Safety Limits**: Timeouts, recovery attempts, emergency stops

## Output & Reports

### Console Output

The orchestrator provides real-time progress feedback:

```
════════════════════════════════════════════════════════════════════════
  STAGE 3: Passive Discovery
  Listening for boot-up, heartbeat, and EMCY frames
════════════════════════════════════════════════════════════════════════

Listening for 10 seconds...

✓ Discovered 5 nodes: [1, 2, 5, 10, 15]
  Node   1: State = OPERATIONAL
  Node   2: State = PRE_OPERATIONAL
  Node   5: State = OPERATIONAL
  Node  10: State = STOPPED
  Node  15: State = OPERATIONAL
```

### Final Summary

```
════════════════════════════════════════════════════════════════════════
  TEST SUITE SUMMARY
════════════════════════════════════════════════════════════════════════

Total Duration: 145.3 seconds
Stages Completed: 12
Stages Failed: 0

Discovery Results:
  • Passive Discovery: 5 nodes
  • Active SDO Discovery: 5 nodes
  • LSS Discovery: 0 nodes

Discovered Nodes: [1, 2, 5, 10, 15]

Hidden Objects Found: 12 across 3 nodes

⚠  EMCY Events Detected: 2
⚠  Heartbeat Anomalies: 1

════════════════════════════════════════════════════════════════════════
```

### Generated Reports

```
reports/
├── report_20260303_142845.html         # Interactive HTML report
└── results_20260303_142845.json        # Machine-readable results
```

#### HTML Report Includes:
- Executive summary with timing and stage completion
- Node discovery results (passive, active, LSS)
- Node inventory with device types and states
- Hidden object findings with access modes
- Fuzzing results by node and strategy
- EMCY and heartbeat event logs
- Oracle alert summaries
- Full error and warning logs

#### JSON Report Includes:
- Structured test results for programmatic access
- Complete discovery data
- Object dictionary load status
- Fuzzing results with anomaly counts
- EMCY/heartbeat events with timestamps
- Oracle alert history
- All errors and warnings

## Data Collection

### Discovery Data
- **Nodes Found**: Node IDs from boot-up, SDO response, LSS scan
- **Device Details**: Device type, device name, hardware/firmware versions
- **Node State**: INITIALIZING, STOPPED, PRE_OPERATIONAL, OPERATIONAL

### Hidden Objects
- **Index/Subindex**: Object location in OD space
- **Access Mode**: Read-only, Write-only, or Read/Write
- **Abort Code**: SDO error code if read failed

### Fuzzing Results
- **Anomalies Detected**: Count of unexpected device responses
- **Strategies Used**: Mutation methods applied
- **Affected Nodes**: Which devices were vulnerable

### Monitoring Events
- **EMCY Events**: Emergency messages with error codes
- **Heartbeat Anomalies**: Lost heartbeats or state changes
- **Oracle Alerts**: Rule-triggered anomalies

## Error Handling

The suite handles errors gracefully:

```python
# PCAN missing → Exits cleanly with error message
# No nodes found → Warns and skips fuzzing stages
# No OD files → Warns but continues with fuzzing
# Single node failure → Continues with other nodes
# Test timeout → Moves to next stage
# Keyboard interrupt (Ctrl+C) → Cleanup and exit
```

All errors are:
- Logged with timestamps
- Included in final report
- Tracked in `results.errors` list
- Visible in HTML report's "Issues" section

## API Usage (For Programmatic Integration)

```python
from pathlib import Path
from canopen_security_platform.orchestrator.run_full_security_suite import SecurityTestSuite

# Load custom config
suite = SecurityTestSuite(config_path=Path("my_config.yaml"))

# Run the suite
results = suite.run()

# Access results
print(f"Nodes discovered: {results.passive_nodes | results.active_nodes}")
print(f"Hidden objects found: {sum(len(o) for o in results.hidden_objects.values())}")
print(f"Errors: {len(results.errors)}")

# Programmatic access to stage completion
if "Hidden OD Scan" in results.completed_stages:
    print("Hidden scanning completed successfully")

# Export results
import json
with open("results.json", "w") as f:
    json.dump(results.asdict(), f, indent=2)
```

## Troubleshooting

### "ModuleNotFoundError: No module named 'yaml'"
```bash
pip install PyYAML
```

### "Failed to connect to PCAN"
- Check PCAN hardware is connected
- Verify drivers: Windows: PEAK PCAN-View; Linux: `candump -l`
- Check no other app is using the interface
- Try different `channel` in config.yaml

### "No device descriptions found"
- Create `device_descriptions/` folder in project root
- Copy `.eds` files into it
- Run orchestrator again

### "XDD conversion failed"
- Install CANopen Editor: https://www.beckhoff.com/
- Or manually convert XDD/XDC to EDS using external tool
- Place resulting EDS in `device_descriptions/`

### "No nodes discovered"
- Verify nodes are powered on and connected to CAN
- Check CAN bus bitrate matches your network (default: 250 kbps)
- Try increasing `discovery.passive_timeout` in config.yaml
- Check CAN termination (120Ω resistors at both ends)
- Test with `candump` or similar tool

### "Test suite interrupted by user"
- This is normal when pressing Ctrl+C
- Cleanup is automatic; resources are released

## Performance Notes

### Typical Execution Times

| Stage | Time (5 nodes) |
|-------|---|
| PCAN Connection | 1-2 sec |
| Passive Discovery (10s) | 12 sec |
| Active SDO Discovery | 8-15 sec |
| LSS Discovery | 5-10 sec |
| OD Loading | 2-5 sec |
| Hidden OD Scan | 30-60 sec |
| SDO Fuzzing (100 iter) | 20-40 sec |
| PDO Fuzzing | 15-30 sec |
| NMT Fuzzing | 10-20 sec |
| Report Generation | 1-2 sec |
| **Total** | **2-3 minutes** |

### Optimization Tips

1. **Speed Up**: Set `fuzz_pdo: false` and `fuzz_nmt: false` for quick tests
2. **Parallel Scanning**: Increase `hidden_scanner.max_workers` (use CPU count)
3. **Reduce Iterations**: Lower `fuzzing_sdo.iterations` for quick validation
4. **Skip LSS**: Set `lss_discovery: false` if nodes are already configured
5. **Reduce Timeouts**: Lower discovery timeouts if your network is fast

### Memory Usage

Typical memory footprint:
- **Base**: ~50 MB
- **With 10 nodes**: ~80 MB
- **With full OD + hidden objects**: ~100-150 MB

## Integration Examples

### CI/CD Pipeline

```yaml
# GitHub Actions example
- name: Run CANopen Security Tests
  run: |
    python -m canopen_security_platform.orchestrator.run_full_security_suite \
      --config ci_config.yaml \
      --log-level INFO
  timeout-minutes: 10

- name: Upload Test Report
  if: always()
  uses: actions/upload-artifact@v2
  with:
    name: security-test-report
    path: reports/
```

### Continuous Testing

```bash
#!/bin/bash
# Run tests hourly and archive results
while true; do
    python -m canopen_security_platform.orchestrator.run_full_security_suite \
        --config production_config.yaml
    
    # Archive results to timestamped directory
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    mkdir -p archived_reports/$TIMESTAMP
    mv reports/* archived_reports/$TIMESTAMP/
    
    sleep 3600  # Run every hour
done
```

## Contributing

To extend the orchestrator:

1. **Add New Stage**: Create method `_stage_my_feature()` in `SecurityTestSuite`
2. **Collect Results**: Populate `TestResults` dataclass fields
3. **Add Config Options**: Update `_default_config()` and template
4. **Report Results**: Include in HTML/JSON report generation

## Related Documentation

- [config.yaml](./config.yaml) - Complete configuration reference
- [device_descriptions/README.md](../device_descriptions/README.md) - Device file management
- [../hal/bus_pcan.py](../hal/bus_pcan.py) - CAN bus interface
- [../discovery/](../discovery/) - Discovery module documentation
- [../fuzzing/](../fuzzing/) - Fuzzing module documentation
- [../od/](../od/) - Object Dictionary modules
- [../monitoring/oracle.py](../monitoring/oracle.py) - Anomaly detection

## License

CANopen Security Testing Platform © 2026

## Support

For issues, questions, or contributions:
1. Check this README's Troubleshooting section
2. Review config.yaml for all available options
3. Run with `--log-level DEBUG` for detailed diagnostics
4. Check generated HTML report for detailed findings
