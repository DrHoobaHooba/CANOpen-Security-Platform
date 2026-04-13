# Test Case Expansion & Compliance Testing

> **Status**: Research & Planning (April 2026)
> **Focus**: Comprehensive negative testing and CANopen compliance validation

This document outlines the test case expansion strategy including negative testing, compliance validation, stress scenarios, and recovery testing.

---

## Overview

Current test coverage: ~200 mutation strategies  
Planned expansion: +150-200 test case variations  
Target: **Comprehensive offensive & defensive test coverage**

---

## TEST CASE CATEGORIES

## 1. Negative Test Case Library

### 1.1 Malformed Frame Tests (40+ cases)

#### COB-ID Violations
```python
negative_tests_cob_id = [
    ("cob_id_reserved_0x001", 0x001, "Send frame with reserved COB-ID 0x001"),
    ("cob_id_reserved_0x080", 0x080, "0x080 = NMT, send as data"),
    ("cob_id_broadcast_0x7FF", 0x7FF, "Broadcast address abuse"),
    ("cob_id_0x000", 0x000, "COB-ID 0x000 (invalid)"),
    ("cob_id_negative", -1, "Negative COB-ID (invalid)"),
    ("cob_id_overflow", 0x800, "COB-ID > 0x7FF (invalid)"),
    ("cob_id_float", 3.14, "Float COB-ID (type error)"),
    ("cob_id_collision_nmt", 0x7E0, "Same as NMT consumer (collision)"),
    # ... 32 more cases
]
```

#### DLC (Data Length Code) Violations
```python
negative_tests_dlc = [
    ("dlc_zero", 0, "DLC=0 (no data)"),
    ("dlc_minimum_valid", 1, "DLC=1 (minimum)"),
    ("dlc_maximum_valid", 8, "DLC=8 (maximum CAN classic)"),
    ("dlc_nine", 9, "DLC=9 (CAN FD only)"),
    ("dlc_sixteen", 16, "DLC=16 (invalid)"),
    ("dlc_negative", -1, "Negative DLC"),
    ("dlc_float", 3.5, "Float DLC"),
    ("dlc_none", None, "No DLC specified"),
    # ... 32 more cases
]
```

#### Payload Violations
```python
negative_tests_payload = [
    ("payload_empty", b"", "Empty payload (DLC>0)"),
    ("payload_undersized", b"\x01\x02", "Payload smaller than DLC"),
    ("payload_oversized", b"\x01\x02\x03\x04\x05\x06\x07\x08\x09", "Payload > 8 bytes"),
    ("payload_null_bytes", b"\x00\x00\x00\x00\x00\x00\x00\x00", "All zeros"),
    ("payload_max_value_bytes", b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", "All 0xFF"),
    ("payload_single_corruption", b"\x01\x02\xFF\x04\x05\x06\x07\x08", "Single byte corruption"),
    ("payload_bit_flip", b"\x01\x02\x04\x04\x05\x06\x07\x08", "Single bit flip"),
    # ... 33 more cases
]
```

### 1.2 Protocol Violation Tests (50+ cases)

#### SDO Violations
```python
negative_sdo_tests = [
    ("sdo_invalid_cs", 0xFF, "Command specifier out of range"),
    ("sdo_illegal_sequence", 0x05, "Illegal segment index"),
    ("sdo_missing_toggle", 0x00, 0x01, "Toggle bit not incrementing"),
    ("sdo_toggle_repeated", 0x00, 0x00, "Toggle bit repeated"),
    ("sdo_abort_code_all_zeros", 0x80000000, "Abort with code 0x00000000"),
    ("sdo_abort_code_invalid", 0x80FFFFFF, "Invalid abort code"),
    ("sdo_index_out_of_range", 0x0000, "Index 0x0000 (reserved)"),
    ("sdo_index_0xFFFF", 0xFFFF, "Index 0xFFFF (boundary)"),
    ("sdo_subindex_0xFF", 0xFF, "Subindex 255 (boundary)"),
    ("sdo_download_before_upload_complete" "Interleaved SDO operations"),
    # ... 40+ more cases
]
```

#### NMT Violations
```python
negative_nmt_tests = [
    ("nmt_invalid_command", 0xFF, "Invalid NMT command specifier"),
    ("nmt_invalid_state_0x01", 0x01, "Invalid NMT state 0x01"),
    ("nmt_invalid_state_0x84", 0x84, "Invalid NMT state 0x84"),
    ("nmt_illegal_transition", "OP->INIT", "Transition violating spec"),
    ("nmt_rapid_transitions", 20, "20 NMT transitions in 1 second"),
    ("nmt_heartbeat_timeout", 10000, "Heartbeat missing for 10 seconds"),
    ("nmt_guard_time_violation", 0xFFFF, "Guard time exceeds lifetime"),
    ("nmt_multiple_reset", 5, "5 reset commands within 100ms"),
    # ... 32+ more cases
]
```

#### PDO Violations
```python
negative_pdo_tests = [
    ("pdo_no_synchronization", "Send PDO without SYNC"),
    ("pdo_wrong_transmission_type", 0xFF, "Invalid transmission type"),
    ("pdo_mapping_0x00", b"", "Empty PDO mapping"),
    ("pdo_mapping_recursive", "PDO mapping containing PDO"),
    ("pdo_mapping_exceeds_8_bytes", "PDO > 8 bytes"),
    ("pdo_event_timer_zero", 0x0000, "Event timer = 0 (no update)"),
    ("pdo_event_timer_extreme", 0xFFFF, "Event timer = 65535ms"),
    ("pdo_cob_id_collision", 0x200, "PDO COB-ID collides with NMT"),
    # ... 24+ more cases
]
```

#### EMCY Violations
```python
negative_emcy_tests = [
    ("emcy_invalid_error_code", 0xFFFF, "Undefined error code"),
    ("emcy_reserved_code", 0x0000, "0x0000 = no error on EMCY"),
    ("emcy_rapid_burst", 50, "50 EMCY in 100ms"),
    ("emcy_error_register_invalid", 0xFF, "All error bits set"),
    ("emcy_clear_without_error", "Clear error when none active"),
    ("emcy_recovery_not_possible", "Error requiring reset without reset"),
    # ... 34+ more cases
]
```

### 1.3 Access Violation Tests (30+ cases)

```python
negative_access_tests = [
    ("write_readonly", 0x1000, "Write to read-only device type (0x1000)"),
    ("write_readonly_identity", 0x1018, "Write to identity object (0x1018)"),
    ("read_writeonly", 0x1001, "Read from error register (write-only on some devices)"),
    ("access_undefined_index", 0x2AAA, "Access to undefined index"),
    ("access_undefined_subindex", (0x1000, 0x05), "Valid index, invalid subindex"),
    ("access_below_min_value", (0x6000, 0, -100), "Value below minimum"),
    ("access_above_max_value", (0x6000, 0, 65536), "Value above maximum"),
    ("access_wrong_datatype", (0x6000, 0, "text"), "Wrong datatype for index"),
    # ... 22+ more cases
]
```

---

## 2. CANopen Compliance Test Suites

### 2.1 DS301 Base Compliance (40+ tests)

```python
class DS301ComplianceTests:
    """CANopen Application Layer and Transfer Layer"""
    
    def test_device_type_valid(self):
        """0x1000: Device type must be 32-bit unsigned"""
        pass
    
    def test_error_register_bits(self):
        """0x1001: Error register bit definitions (bits 0-7)"""
        pass
    
    def test_identity_valid_structure(self):
        """0x1018: Identity structure (vendor ID, product code, rev, serial)"""
        pass
    
    def test_nmt_inhibit_time(self):
        """0x102B: NMT inhibit time parameter"""
        pass
    
    def test_heartbeat_producer_consumer(self):
        """0x1017: Heartbeat producer/consumer coordination"""
        pass
    
    def test_guard_time_lifetime_factor(self):
        """0x100C/100D: Guard time and lifetime factor consistency"""
        pass
    
    def test_sdo_communication_parameters(self):
        """0x1200-0x12FF: SDO communication parameter validation"""
        pass
    
    def test_pdo_communication_mapping(self):
        """0x1600-0x17FF: PDO communication and mapping validation"""
        pass
    
    # ... 32+ more DS301 tests
```

### 2.2 DS402 Device Profile Compliance (50+ tests)

```python
class DS402DeviceProfileTests:
    """CANopen Device Profile for Drives and Motion Control"""
    
    def test_device_control_word(self):
        """6040h: Device control word state machine"""
        pass
    
    def test_device_status_word(self):
        """6041h: Device status word consistency"""
        pass
    
    def test_motor_speed_setpoint(self):
        """606Bh: Motor speed setpoint boundaries"""
        pass
    
    def test_acceleration_deceleration(self):
        """6083h/6084h: Acceleration/deceleration limits"""
        pass
    
    def test_emergency_stop_handling(self):
        """605Ah: Emergency stop coordination"""
        pass
    
    def test_fault_reaction_behavior(self):
        """61FFh: Fault reaction option code behavior"""
        pass
    
    # ... 44+ more DS402 tests
```

---

## 3. Device-Specific Test Profiles

### 3.1 Profile Template

```yaml
# profiles/device_specific/vendor_model.yaml
device:
  name: "Vendor Device Model XYZ"
  vendor_id: 0x12345678
  product_code: 0xAABBCCDD
  supported_features:
    - "COB-ID offset"
    - "Segmented SDO"
    - "Block transfer"
    - "LSS configuration"

# Extended test cases specific to this device
extended_tests:
  - name: "cob_id_offset_handling"
    description: "Test device behavior with COB-ID offset (0x200)"
    iterations: 50
    
  - name: "block_transfer_edge_cases"
    description: "Test block transfer with unusual block sizes"
    iterations: 30
    
  - name: "memory_constraints"
    description: "Test with known memory limitations"
    max_sdo_size: 32768  # 32KB limit for this device
    iterations: 50

stress_scenarios:
  - name: "continuous_operation"
    duration_minutes: 60
    message_rate_multiplier: 2
    
  - name: "rapid_reset_cycles"
    reset_count: 100
    delay_between_resets_ms: 500
```

### 3.2 Device Profiles (Planned)

```
profiles/device_specific/
├── beckhoff_cx_series.yaml          # Beckhoff embedded PC
├── maxon_bldc_controller.yaml       # Maxon motion controller
├── siemens_tia_portal.yaml          # Siemens TIA Portal compatible
├── epos2_generic.yaml               # EPOS2 generic profile
├── baumueller_controller.yaml       # Bäumüller controller
└── generic_servo_drive.yaml         # Generic servo drive baseline
```

---

## 4. Stress Test Scenarios

### 4.1 Sustained Message Rate Testing

```python
class SustainedStressTests:
    """Test device behavior under sustained high message rates"""
    
    def test_pdo_sustained_1khz(self):
        """Send PDO at 1000 msg/sec for 5 minutes"""
        # Monitor: buffer overflows, missed messages, errors
        pass
    
    def test_sdo_streaming(self):
        """Streaming SDO writes (1000+ per minute) for 10 minutes"""
        # Monitor: data corruption, timeouts, recovery
        pass
    
    def test_concurrent_all_protocols(self):
        """All protocols simultaneously at max rate"""
        # Monitor: priority handling, message loss, state consistency
        pass
    
    def test_nmt_rapid_state_changes(self):
        """NMT state changes every 100ms for 30 minutes"""
        # Monitor: state machine integrity, recovery after glitches
        pass
    
    def test_heartbeat_producer_loss(self):
        """Heartbeat timeout for 30 seconds then recovery"""
        # Monitor: guard time triggering, recovery behavior
        pass
```

### 4.2 Recovery & Resilience Testing

```python
class RecoveryTests:
    """Test device recovery after errors/anomalies"""
    
    def test_recovery_after_buffer_overflow(self):
        """Device recovery after message buffer overflow"""
        pass
    
    def test_recovery_after_timeout(self):
        """Device recovery after timeout event"""
        pass
    
    def test_recovery_after_error_register_full(self):
        """Device recovery when error register reaches 0xFF"""
        pass
    
    def test_recovery_after_rapid_resets(self):
        """Device stability after 100 rapid resets"""
        pass
    
    def test_watchdog_recovery(self):
        """Watchdog trigger and recovery sequence"""
        pass
    
    def test_concurrent_error_recovery(self):
        """Recovery with multiple errors occurring simultaneously"""
        pass
```

---

## 5. Implementation Structure

### Test Case Library Organization

```
tests/
├── negative_cases/
│   ├── malformed_frames.py          # ~40 test cases
│   ├── protocol_violations.py       # ~50 test cases
│   ├── access_violations.py         # ~30 test cases
│   └── resource_exhaustion.py       # ~20 test cases
│
├── compliance/
│   ├── ds301_base_compliance.py     # ~40 tests
│   ├── ds402_device_profile.py      # ~50 tests
│   └── custom_protocol_compliance.py  # Extensible
│
├── stress_scenarios/
│   ├── sustained_rate_stress.py     # ~15 scenarios
│   ├── recovery_resilience.py       # ~12 scenarios
│   └── fault_injection_recovery.py  # ~10 scenarios
│
├── device_profiles/
│   ├── test_profile_loader.py
│   ├── device_specific_tests.py
│   └── profiles/                    # YAML profiles
│
└── integration/
    ├── test_negative_with_orchestrator.py
    ├── test_compliance_validation.py
    └── test_stress_scenario_suite.py
```

---

## 6. Configuration for Test Case Expansion

### Configuration Section

```yaml
# config.yaml additions

# Negative Testing Configuration
negative_testing:
  enabled: true
  test_case_categories:
    - "malformed_frames"
    - "protocol_violations"
    - "access_violations"
    - "resource_exhaustion"
  skip_dangerous_cases: false  # Set true for production-like networks
  report_all_failures: true

# Compliance Testing
compliance:
  enabled: true
  ds301_base: true
  ds402_profile: true
  custom_profiles_dir: "profiles/device_specific"
  strict_mode: false  # If true, stop on first compliance failure

# Stress Scenarios
stress_scenarios:
  enabled: true
  sustained_rate_tests: true
  recovery_tests: true
  fault_injection_recovery: true
  duration_minutes: 30
  monitor_recovery_time_ms: 5000

# Device-Specific Configuration
device_profiles:
  enabled: true
  auto_detect_profile: true  # Auto-load based on device identity
  profile_override: "profiles/device_specific/generic_servo_drive.yaml"
```

---

## 7. Success Criteria

- ✅ 150+ negative test cases implemented
- ✅ DS301/402 compliance validation (90+ tests)
- ✅ 6+ device-specific profiles
- ✅ 25+ stress scenarios
- ✅ 12+ recovery/resilience tests
- ✅ 80%+ code coverage
- ✅ Negative cases integrated into orchestrator
- ✅ Compliance reporting in HTML/JSON output
- ✅ Device profile auto-detection working

---

## 8. Timeline

- **Week 1-2**: Negative test case library (malformed frames, protocol violations)
- **Week 3**: Access violation & resource exhaustion tests
- **Week 4**: DS301/DS402 compliance test suites
- **Week 5**: Device-specific profile framework and examples
- **Week 6**: Stress scenarios and recovery tests
- **Week 7**: Integration, orchestrator updates, comprehensive testing

---

## Notes

- All test cases have **descriptive names** and **comments**
- Test cases are **parameterized** for easy extension
- Each category can be **enabled/disabled** via config
- Test results include **failure analysis** and **recommendations**
- Device profiles are **YAML-based** for easy customization
- Stress tests include **continuous monitoring** and **anomaly detection**
