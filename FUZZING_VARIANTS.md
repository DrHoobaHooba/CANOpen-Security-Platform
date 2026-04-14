# Fuzzing Variants & Advanced Test Strategies

> **Status**: Phase 1 and 2 Implemented; Phase 3+ Planned (April 2026)
> **Focus**: Offensive & Robustness Testing

This document outlines the fuzzing variants and test strategies planned for the CANopen Security Platform's aggressive expansion into vulnerability discovery and device robustness testing.

---

## Overview

The platform currently has **11 fuzzing engines** (SDO, PDO, NMT, LSS, EMCY, SYNC, Concurrent, CAN ID, Timing, Resource, State Machine). Remaining near-term expansion focuses on **2 additional variants** (Boundary and Cross-Protocol) plus broader test/compliance tracks.

- **Boundary conditions** (min/max values, reserved COB-IDs)
- **Timing attacks** (inter-frame gaps, jitter, synchronization)
- **Resource exhaustion** (buffer stress, message floods)
- **State machine violations** (escape sequences, illegal transitions)
- **Protocol violations** (payload size extremes, payload corruption)
- **Cross-protocol interactions** (race conditions, ordering violations)

---

## Fuzzing Variants - Near-Term Implementation

### 1. CAN ID Fuzzing (COB-ID Boundary Testing)
**File**: `canopen_security_platform/fuzzing/canid_fuzzer.py`  
**Status**: ✅ Implemented

#### Purpose
Test device behavior when receiving frames with:
- Reserved/undefined COB-IDs
- COB-ID boundary values (0x000, 0x7FF, mixed)
- Conflicting COB-IDs (PDO on NMT address, etc.)
- Manufacturer-specific COB-ID ranges

#### Mutation Strategies (8-10 planned)
1. **reserved_cob_ids** - Send frames with reserved COB-IDs (0x1-0x7F)
2. **boundary_cob_ids** - Test COB-ID boundaries (0x000, 0x00F, 0x0F0, 0x0FF, 0x7F0, 0x7FF)
3. **conflicting_cob_ids** - Send legitimate data on wrong COB-IDs (NMT data on PDO, etc.)
4. **cob_id_sweep** - Sweep across full COB-ID space (0x000-0x7FF)
5. **broadcast_vs_unicast** - Test device reaction to broadcast messages on unicast addresses
6. **duplicate_cob_ids** - Multiple devices using same COB-ID (arbitration testing)
7. **cob_id_fuzz_mask** - Bit-flip mutations on COB-ID field
8. **cob_id_extension_frames** - Send 29-bit CAN IDs on 11-bit network
9. **cob_id_mixing** - Random COB-ID injection patterns
10. **cob_id_rate_variation** - Same COB-ID at varying transmission rates

#### Configuration
```yaml
fuzzing_canid:
  enabled: true
  iterations: 100
  strategies:
    - "reserved_cob_ids"
    - "boundary_cob_ids"
    - "conflicting_cob_ids"
    - "cob_id_sweep"
    - "broadcast_vs_unicast"
    - "duplicate_cob_ids"
    - "cob_id_fuzz_mask"
  delay_between_tests_ms: 25
  test_error_frames: true  # Send error frames with invalid COB-IDs
```

---

### 2. Timing & Delay Attack Fuzzing
**File**: `canopen_security_platform/fuzzing/timing_fuzzer.py`  
**Status**: ✅ Implemented

#### Purpose
Test device robustness against timing anomalies:
- Extremely tight inter-frame gaps
- Massive delays between related messages
- Jitter and timing irregularities
- Synchronization violations

#### Mutation Strategies (9-12 planned)
1. **zero_delay_burst** - Send rapid messages with 0ms delay
2. **extreme_jitter** - ±500ms timing variations
3. **interframe_gap_minimum** - Test minimum inter-frame spacing
4. **interframe_gap_maximum** - Test maximum inter-frame gaps (timeouts)
5. **sync_timing_drift** - Intentional SYNC timing errors
6. **heartbeat_timing_violation** - Send heartbeat at wrong intervals
7. **phase_shift_attacks** - Messages arriving at unexpected phase points
8. **timeout_edge_cases** - Messages just before/after timeout windows
9. **rapid_pdo_bursts** - 50+ PDO messages in <100ms
10. **delayed_responses** - Intentionally delayed SDO responses
11. **clock_drift_simulation** - Simulate clock skew across devices
12. **timing_amplification** - Exponential timing variations

#### Configuration
```yaml
fuzzing_timing:
  enabled: true
  iterations: 80
  strategies:
    - "zero_delay_burst"
    - "extreme_jitter"
    - "interframe_gap_minimum"
    - "interframe_gap_maximum"
    - "sync_timing_drift"
    - "heartbeat_timing_violation"
    - "phase_shift_attacks"
    - "timeout_edge_cases"
  min_delay_ms: 0
  max_delay_ms: 5000
  burst_size_max: 100
```

---

### 3. Resource Exhaustion Variants
**File**: `canopen_security_platform/fuzzing/resource_fuzzer.py`  
**Status**: ✅ Implemented

#### Purpose
Stress test device resource limits:
- Message buffer exhaustion
- Memory limitations
- Processing capacity
- Stack overflow scenarios

#### Mutation Strategies (10-12 planned)
1. **sequential_sdo_storm** - 100+ concurrent SDO transfers
2. **pdo_buffer_flood** - Massive PDO reception (500+ msgs/sec)
3. **large_payload_escalation** - Growing payload sizes to limits
4. **segmented_transfer_abuse** - Massive segmented SDO transfers (1MB+)
5. **concurrent_sdo_max** - Maximum concurrent SDO requests
6. **heartbeat_spam** - 100+ heartbeat messages/second
7. **emcy_burst** - Rapid EMCY error codes
8. **sync_burst** - Rapid SYNC messages with counter fuzz
9. **memory_leak_patterns** - Repeated allocation/deallocation cycles
10. **stack_overflow_attempt** - Deep recursion in SDO handling
11. **buffer_wraparound** - Test buffer index wraparound
12. **resource_recovery_test** - Recovery after exhaustion

#### Configuration
```yaml
fuzzing_resource:
  enabled: true
  iterations: 50
  strategies:
    - "sequential_sdo_storm"
    - "pdo_buffer_flood"
    - "large_payload_escalation"
    - "concurrent_sdo_max"
    - "heartbeat_spam"
    - "sync_burst"
  max_concurrent_messages: 256
  max_payload_size: 8192
  burst_duration_seconds: 10
```

---

### 4. State Machine Escape Sequences
**File**: `canopen_security_platform/fuzzing/state_machine_fuzzer.py`  
**Status**: ✅ Implemented

#### Purpose
Test NMT state machine for escape sequences and illegal transitions:
- All possible state combinations
- Transitions prohibited by CANopen spec
- Timing-dependent state vulnerabilities
- Recovery after illegal transitions

#### Mutation Strategies (8-10 planned)
1. **illegal_state_transition** - Try all 16² state combinations (only 10-12 legal in CANopen)
2. **guard_time_manipulation** - OD 0x100D boundary exploitation
3. **lifetime_factor_abuse** - OD 0x100C extreme values (0x0000, 0xFFFF)
4. **bootup_during_operational** - Boot-up message while operational
5. **reset_surge** - Multiple resets in rapid succession
6. **partial_state_corruption** - Send state with invalid bits set
7. **emergency_to_invalid** - Transition from EMCY to non-existent state
8. **producer_consumer_desync** - Heartbeat producer/consumer drift
9. **nmt_spurious_response** - Unexpected NMT responses
10. **state_persistence_test** - State preservation after hostile input

#### Configuration
```yaml
fuzzing_state_machine:
  enabled: true
  iterations: 150
  strategies:
    - "illegal_state_transition"
    - "guard_time_manipulation"
    - "lifetime_factor_abuse"
    - "bootup_during_operational"
    - "reset_surge"
    - "partial_state_corruption"
  test_all_combinations: true  # Try all state transitions
```

---

### 5. Protocol Boundary Fuzzing
**File**: `canopen_security_platform/fuzzing/boundary_fuzzer.py`  
**Status**: ⏳ Planned

#### Purpose
Test edge cases in protocol specifications:
- Minimum/maximum values per field
- DLC (Data Length Code) extremes
- Payload size boundaries
- Index/subindex boundaries

#### Mutation Strategies (10-14 planned)
1. **dlc_zero** - DLC=0 on PDO/SDO (should fail)
2. **dlc_minimum_valid** - DLC=1 (minimum valid)
3. **dlc_maximum_valid** - DLC=8 (CAN classic maximum)
4. **dlc_extended** - DLC>8 (CAN FD, invalid on classic)
5. **payload_minimum** - Empty payload with valid COB-ID
6. **payload_maximum** - Maximum payload (8 bytes)
7. **payload_oversized** - >8 bytes via segmentation abuse
8. **index_boundary_0x0000** - Index 0x0000 (reserved)
9. **index_boundary_0x9999** - Index near profile range limits
10. **index_boundary_0xFFFF** - Maximum index value
11. **subindex_boundary_0x00** - Subindex 0 (primary object)
12. **subindex_boundary_0xFF** - Maximum subindex (255)
13. **length_field_mismatch** - DLC doesn't match actual payload
14. **eol_marker_corruption** - Incorrect end-of-line markers

#### Configuration
```yaml
fuzzing_boundary:
  enabled: true
  iterations: 120
  strategies:
    - "dlc_zero"
    - "dlc_boundary_values"
    - "payload_extremes"
    - "index_boundaries"
    - "subindex_boundaries"
  test_all_dlc_values: true
  test_all_index_values: false  # Set to true for exhaustive (slow)
```

---

### 6. Cross-Protocol Interaction Fuzzing
**File**: `canopen_security_platform/fuzzing/cross_protocol_fuzzer.py`  
**Status**: ⏳ Planned

#### Purpose
Test device behavior when multiple protocols interact:
- Concurrent protocol operations
- Protocol state conflicts
- Message ordering violations
- Resource sharing conflicts

#### Mutation Strategies (9-12 planned)
1. **sdo_interleaved_pdo** - SDO during high-rate PDO
2. **nmt_during_sdo_transfer** - NMT state change mid-SDO
3. **sync_counter_during_pdo** - SYNC counter change mid-PDO cycle
4. **multiple_sdo_segmented** - Multiple segmented SDOs overlapping
5. **sdo_timeout_during_pdo** - SDO timeout concurrent with PDO
6. **emergency_during_transfer** - EMCY during SDO/PDO
7. **protocol_priority_violations** - Intentionally violate priority rules
8. **message_queueing_abuse** - Overwhelming queue depth
9. **resource_contention** - Simultaneous access to same OD index
10. **watchdog_reset_during_operation** - Watchdog trigger during active transfer
11. **heartbeat_loss_during_fuzz** - Heartbeat timeout concurrent with fuzzing
12. **state_change_during_protocol** - State changes during all protocols

#### Configuration
```yaml
fuzzing_cross_protocol:
  enabled: true
  iterations: 100
  strategies:
    - "sdo_interleaved_pdo"
    - "nmt_during_sdo_transfer"
    - "sync_counter_during_pdo"
    - "multiple_sdo_segmented"
    - "emergency_during_transfer"
    - "protocol_priority_violations"
  concurrent_protocol_count: 3
  stress_duration_seconds: 30
```

---

## Test Case Expansion - Near-Term Implementation

### Test Case Library Structure

```
tests/
├── test_fuzzing_canid.py              # CAN ID fuzzing tests
├── test_fuzzing_timing.py             # Timing attack tests
├── test_fuzzing_resource.py           # Resource exhaustion tests
├── test_fuzzing_state_machine.py      # State machine tests
├── test_fuzzing_boundary.py           # Protocol boundary tests
├── test_fuzzing_cross_protocol.py     # Cross-protocol tests
├── negative_test_cases.py             # Negative test library
└── compliance_test_suites.py          # DS301/402 compliance tests
```

### Negative Test Case Categories

1. **Malformed Frames**
   - Invalid COB-IDs
   - Incorrect DLC
   - Corrupted checksums (if applicable)
   - Out-of-spec payloads

2. **Protocol Violations**
   - Illegal SDO commands
   - Invalid NMT states
   - Out-of-order segmented transfers
   - Invalid subindices

3. **Spec Deviations**
   - Non-compliance with CANopen 301
   - Device profile violations
   - Manufacturer-specific mishandling

4. **Access Violations**
   - Write to read-only objects
   - Read from write-only objects
   - Access to non-existent indices

5. **Concurrency Issues**
   - Race conditions
   - Deadlocks
   - Resource contention

---

## Configuration Profiles

### Profile: `config_extreme_indepth.yaml` ✅
Already created - 240-minute maximum runtime, 500+ iterations per fuzzer

### Profile: `config_aggressive_attack.yaml` (Planned)
- Focused on new variants (CAN ID, timing, resource, state machine)
- 120-minute runtime
- 200+ iterations per variant fuzzer
- Cross-protocol stress enabled

### Profile: `config_compliance_audit.yaml` (Planned)
- DS301/402 compliance validation
- Negative test case library
- Device-specific test profiles
- 90-minute runtime

### Profile: `config_stress_test.yaml` (Planned)
- Pure resource exhaustion
- Sustained high-rate messaging
- Recovery testing
- 180-minute runtime

---

## Implementation Workflow

### Phase 1: CAN ID & Timing Fuzzers (Week 1-2)
- [x] Implement `canid_fuzzer.py` (150-200 lines)
- [x] Implement `timing_fuzzer.py` (200-250 lines)
- [x] Add unit tests (100+ lines)
- [x] Add config section
- [x] Integrate into orchestrator

### Phase 2: Resource & State Machine (Week 3-4)
- [x] Implement `resource_fuzzer.py` (200-250 lines)
- [x] Implement `state_machine_fuzzer.py` (180-220 lines)
- [x] Add unit tests
- [x] Add config section
- [x] Integrate into orchestrator

### Phase 3: Boundary & Cross-Protocol (Week 5)
- [ ] Implement `boundary_fuzzer.py` (150-200 lines)
- [ ] Implement `cross_protocol_fuzzer.py` (250-300 lines)
- [ ] Add unit tests
- [ ] Add config section
- [ ] Integrate into orchestrator

### Phase 4: Test Case Library (Week 6)
- [ ] Create negative test case library
- [ ] Create compliance test suites
- [ ] Create device-specific profiles
- [ ] Create stress test scenarios
- [ ] Create recovery test suite

### Phase 5: Configuration & Orchestration (Week 7)
- [ ] Create fuzzing variant config profiles
- [ ] Update orchestrator for 6 new fuzzers (21 total)
- [ ] Integrate all strategies (80+ mutation functions)
- [ ] Comprehensive testing

---

## Success Criteria

- ✅ 4 of 6 planned new fuzzing engines implemented (Phase 1 and 2 complete)
- ✅ 50+ new mutation strategies available across the expanded stack
- ✅ 80%+ code coverage on new modules
- ✅ All fuzzers integrated into orchestrator
- ✅ Verified on hardware (PCAN)
- ✅ Documentation complete
- ✅ Negative test case library (100+ cases)
- ✅ Compliance test suites functional

---

## Notes

- All new fuzzers follow existing pattern (inherited from base fuzzer)
- Configuration via YAML (config.yaml)
- Monitoring/Oracle integration for all fuzzers
- Reporting includes variant-specific results
- Cross-protocol fuzzer runs after single-protocol fuzzers complete
