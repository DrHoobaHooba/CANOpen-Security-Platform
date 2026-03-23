# Full Security Suite - Quick Start Guide

> **⚠️ WARNING**: This is AI-assisted research software for EDUCATIONAL/RESEARCH USE ONLY. Use in isolated test environments only. Do NOT use on production systems. See [README.md](README.md) for full disclaimer.

---

## Installation

1. **Install Dependencies**
```bash
cd c:\Users\INSMMOR\Documents\CANOpen\_git\CANOpen-Security-Platform
pip install PyYAML python-can canopen pytest
```

2. **Place Device Descriptions (Optional)**
```bash
# Copy your EDS files to:
od_files/
```

3. **Verify Installation**
```bash
python -m canopen_security_platform.orchestrator.run_full_security_suite --help
```

## Running the Suite

### Option 1: Default Configuration
```bash
python -m canopen_security_platform.orchestrator.run_full_security_suite
```

**Expected Output:**
```
╔══════════════════════════════════════════════════════════════════════╗
║         CANopen Security Testing Platform - Full Suite              ║
║                    Automated Security Assessment                     ║
╚══════════════════════════════════════════════════════════════════════╝

Start Time: 2026-03-03 14:45:23
Configuration: 11 tests enabled
────────────────────────────────────────────────────────────────────────

════════════════════════════════════════════════════════════════════════
  STAGE 1: PCAN Bus Connection
  Establishing connection to CAN bus
════════════════════════════════════════════════════════════════════════

Interface: pcan
Channel: PCAN_USBBUS1
Bitrate: 250000 bps

[May fail here if PCAN hardware not connected - this is normal]
✗ Failed to connect to PCAN: No PCAN interface found

Please ensure:
  1. PCAN hardware is connected
  2. PCAN drivers are installed
  3. No other application is using the interface

✗ TEST SUITE SUMMARY

Total Duration: 1.2 seconds
Stages Completed: 0
Stages Failed: 1

✗ Errors: 1
     [14:45:24] Stage 'PCAN Connection' failed: No compatible interface found
```

### Option 2: Custom Configuration
```bash
# Create custom_test.yaml
python -m canopen_security_platform.orchestrator.run_full_security_suite --config custom_test.yaml
```

### Option 3: Debug Mode
```bash
python -m canopen_security_platform.orchestrator.run_full_security_suite --log-level DEBUG
```

### Option 4: Quiet Mode (Errors Only)
```bash
python -m canopen_security_platform.orchestrator.run_full_security_suite --log-level ERROR
```

## Configuration Examples

### Example 1: Quick Discovery Only
**File: quick_discovery.yaml**
```yaml
bus:
  interface: "pcan"
  channel: "PCAN_USBBUS1"
  bitrate: 250000

tests:
  passive_discovery: true
  active_discovery: true
  lss_discovery: true
  od_load: false           # Skip OD loading
  hidden_od_scan: false    # Skip hidden scanning
  fuzz_sdo: false          # Skip fuzzing
  fuzz_pdo: false
  fuzz_nmt: false
  monitor_emcy: true
  monitor_heartbeat: true

discovery:
  passive_timeout: 5       # Only 5 seconds (quick)
```

Run with:
```bash
python -m canopen_security_platform.orchestrator.run_full_security_suite --config quick_discovery.yaml
```

### Example 2: Full Security Assessment
**File: full_assessment.yaml**
```yaml
bus:
  interface: "pcan"
  channel: "PCAN_USBBUS1"
  bitrate: 250000

tests:
  passive_discovery: true
  active_discovery: true
  lss_discovery: true
  od_load: true
  hidden_od_scan: true
  fuzz_sdo: true
  fuzz_pdo: true           # CAUTION: May disrupt network
  fuzz_nmt: true
  monitor_emcy: true
  monitor_heartbeat: true

fuzzing_sdo:
  iterations: 100          # Full iterations
  strategies:
    - "mutate_cs"
    - "wrong_length"
    - "overflow"
    - "illegal_index"
    - "read_only_write"
    - "invalid_subindex"
    - "data_mutation"
```

Run with:
```bash
python -m canopen_security_platform.orchestrator.run_full_security_suite --config full_assessment.yaml
```

## Output Files

After running, check the `reports/` directory:

```
reports/
├── report_20260303_144523.html      # HTML test report (open in browser)
└── results_20260303_144523.json     # JSON results (for CI/CD)
```

### View HTML Report
```bash
# Windows
start reports\report_20260303_144523.html

# Linux
xdg-open reports/report_20260303_144523.html

# macOS
open reports/report_20260303_144523.html
```

## Troubleshooting

### "ModuleNotFoundError: No module named 'yaml'"
```bash
pip install PyYAML
```

### "Failed to connect to PCAN"
This is expected if PCAN hardware is not connected. The suite will:
- Try to connect
- Fail gracefully
- Exit cleanly
- Show instructions for fixing the issue

To test without hardware, create a virtual CAN interface (Linux):
```bash
# Create virtual CAN interface
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0

# Run with virtual interface
# Edit config.yaml: interface: "virtual", channel: "vcan0"
```

### "No device descriptions found"
1. Create `od_files/` folder in project root
2. Copy your `.eds` files into it
3. Or disable `od_load` in config.yaml

### "No nodes discovered"
1. Verify nodes are powered on
2. Check CAN bus bitrate matches your network
3. Try increasing `discovery.passive_timeout` in config.yaml
4. Check CAN termination (120Ω at both ends)

## API Usage

```python
from pathlib import Path
from canopen_security_platform.orchestrator.run_full_security_suite import SecurityTestSuite

# Run with defaults
suite = SecurityTestSuite()
results = suite.run()

# Access results
print(f"Nodes found: {results.passive_nodes | results.active_nodes}")
print(f"Warnings: {len(results.warnings)}")
print(f"Errors: {len(results.errors)}")

# Run with custom config
suite = SecurityTestSuite(config_path=Path("custom.yaml"))
results = suite.run()

# Check stage completion
for stage in results.completed_stages:
    print(f"✓ {stage}")

for stage in results.failed_stages:
    print(f"✗ {stage}")
```

## Typical Execution Timeline (5 nodes)

```
Stage 1: PCAN Connection      ~2 seconds
Stage 2: Initialize Oracle    ~1 second
Stage 3: Passive Discovery    ~12 seconds (10s listen + overhead)
Stage 4: Active Discovery     ~15 seconds (3s per node)
Stage 5: LSS Discovery        ~10 seconds
Stage 6: OD Loading           ~5 seconds
Stage 7: Hidden Scanning      ~60 seconds (most time-intensive)
Stage 8: SDO Fuzzing          ~40 seconds
Stage 9: PDO Fuzzing          ~30 seconds
Stage 10: NMT Fuzzing         ~20 seconds
Stage 11: Oracle Results      ~2 seconds
Stage 12: Report Generation   ~2 seconds
─────────────────────────────────────
TOTAL:                        ~200 seconds (~3.3 minutes)
```

To speed up:
- Set `fuzz_pdo: false` to skip PDO fuzzing (~30 sec saved)
- Set `fuzz_nmt: false` to skip NMT fuzzing (~20 sec saved)
- Lower `hidden_scanner.max_workers` to reduce resource usage
- Lower fuzzing iterations if quick validation is needed

## Understanding Test Results

### In Console Output

**✓ Success Indicator**
```
✓ Discovered 5 nodes: [1, 2, 5, 10, 15]
```

**✗ Failure Indicator**
```
✗ Failed to connect to PCAN: No interface found
```

**⚠ Warning Indicator**
```
⚠  EMCY Events Detected: 2
⚠  Heartbeat Anomalies: 1
```

### In HTML Report

1. **Node Inventory**: Shows all discovered nodes and their states
2. **Hidden Objects**: Lists undocumented OD indices found
3. **Fuzzing Results**: Anomalies per node and per strategy
4. **Events**: EMCY messages, heartbeat changes
5. **Issues**: All warnings and errors encountered

### In JSON Report

Machine-readable results for programmatic access:
```json
{
  "timestamp": "2026-03-03T14:45:23.123456",
  "duration": 145.3,
  "discovery": {
    "passive_nodes": [1, 2, 5, 10, 15],
    "active_nodes": [1, 2, 5, 10, 15],
    "node_details": {
      "1": {
        "device_type": "0x00000191",
        "device_name": "Motor Driver",
        "passive_state": "OPERATIONAL"
      }
    }
  },
  "hidden_objects": {
    "1": [
      {"index": 4113, "subindex": 0, "access": "read-only"}
    ]
  },
  "fuzzing": {
    "sdo": {
      "1": {
        "total_tests": 700,
        "anomalies": [
          {"strategy": "illegal_index", "anomalies": 2}
        ]
      }
    }
  }
}
```

## Integration with CI/CD

### GitHub Actions Example
```yaml
name: CANopen Security Test

on: [push, pull_request]

jobs:
  security-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.10'
      
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install PyYAML
      
      - name: Run Security Suite
        run: |
          python -m canopen_security_platform.orchestrator.run_full_security_suite \
            --config ci_config.yaml
      
      - name: Upload Report
        if: always()
        uses: actions/upload-artifact@v2
        with:
          name: security-report
          path: reports/
```

### ci_config.yaml Example
```yaml
bus:
  interface: "virtual"     # Use virtual CAN on CI system
  channel: "vcan0"

tests:
  passive_discovery: false # Skip (no real nodes in CI)
  active_discovery: false
  lss_discovery: false
  od_load: true
  hidden_od_scan: false
  fuzz_sdo: false
  fuzz_pdo: false
  fuzz_nmt: false

object_dictionary:
  device_descriptions_dir: "od_files"  # OD file directory
```

## Next Steps

1. **Test with Hardware** (if available): Connect PCAN adapter and run
2. **Configure for Your Network**: Edit config.yaml with your parameters
3. **Load Device Descriptions**: Copy EDS files to `od_files/`
4. **Run Full Suite**: Execute orchestrator and review HTML report
5. **Integrate with CI/CD**: Add to automated testing pipeline
6. **Harden Defaults**: Tune safety and timeout settings for your network

## Support & Documentation

- **Main Documentation**: See [README.md](README.md)
- **Architecture**: See [ARCHITECTURE.md](ARCHITECTURE.md)
- **Orchestrator Guide**: See [ORCHESTRATOR_QUICK_GUIDE.md](ORCHESTRATOR_QUICK_GUIDE.md)
- **Orchestrator Reference**: See [canopen_security_platform/orchestrator/README.md](canopen_security_platform/orchestrator/README.md)
- **Configuration Guide**: See [canopen_security_platform/orchestrator/config.yaml](canopen_security_platform/orchestrator/config.yaml)
