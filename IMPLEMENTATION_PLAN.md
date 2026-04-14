# Implementation Plan - Offensive Testing Expansion

> **Status**: Phase 1 and Phase 2 Implemented; Phase 3+ Planning Ongoing (April 14, 2026)
> **Target**: Complete remaining variants and expanded compliance/test-case tracks

---

## Executive Summary

Expanding the CANopen Security Platform from 7 fuzzing engines (SDO, PDO, NMT, LSS, EMCY, SYNC, Concurrent) to **13 fuzzing engines** with **80+ mutation strategies**, plus **150-200 new test cases** across negative testing, compliance validation, and stress scenarios.

**Total New Code**: ~2,500-3,000 lines of Python fuzzing logic + ~1,500-2,000 lines of test cases  
**Timeline**: 7 weeks  
**Outcome**: Comprehensive offensive security testing platform with industry-leading fuzzing depth

---

## Phase Breakdown

### PHASE 1: CAN ID & Timing Fuzzers (Weeks 1-2)

#### 1.1 CAN ID Fuzzer (`canid_fuzzer.py`)
- **Status**: ✅ Implemented
- **File**: `canopen_security_platform/fuzzing/canid_fuzzer.py`
- **Lines**: 150-200
- **Dependencies**: `BaseCANFuzzer`, `bus`, `oracle`

**Responsibilities**:
```python
class CANIDFuzzer(BaseCANFuzzer):
    def fuzz_reserved_cob_ids(self):
        """Send frames with COB-IDs 0x001-0x07F (reserved)"""
        
    def fuzz_boundary_cob_ids(self):
        """Test COB-ID boundaries: 0x000, 0x7FF, transitions"""
        
    def fuzz_conflicting_cob_ids(self):
        """Send data on wrong COB-ID (NMT data on PDO, etc.)"""
        
    def fuzz_cob_id_sweep(self):
        """Sweep full COB-ID space: 0x000-0x7FF"""
        
    def fuzz_broadcast_vs_unicast(self):
        """Test broadcast handling on unicast addresses"""
        
    def fuzz_duplicate_cob_ids(self):
        """Multiple devices on same COB-ID"""
        
    def fuzz_cob_id_fuzz_mask(self):
        """Bit-flip mutations on COB-ID field"""
        
    def fuzz_cob_id_extension_frames(self):
        """29-bit CAN IDs on 11-bit network"""
        
    def fuzz_cob_id_mixing(self):
        """Random COB-ID injection patterns"""
        
    def fuzz_cob_id_rate_variation(self):
        """Same COB-ID at varying rates"""
```

**Test File**: `tests/test_fuzzing_canid.py` (80-100 lines)
- Unit tests for each strategy
- Verify frame generation
- Monitor anomaly detection

#### 1.2 Timing & Delay Attack Fuzzer (`timing_fuzzer.py`)
- **Status**: ✅ Implemented
- **File**: `canopen_security_platform/fuzzing/timing_fuzzer.py`
- **Lines**: 200-250
- **Dependencies**: `time`, `threading`, `BaseCANFuzzer`

**Responsibilities**:
```python
class TimingFuzzer(BaseCANFuzzer):
    def fuzz_zero_delay_burst(self):
        """Send rapid messages with 0ms delay"""
        
    def fuzz_extreme_jitter(self):
        """±500ms timing variations"""
        
    def fuzz_interframe_gap_minimum(self):
        """Test minimum inter-frame spacing"""
        
    def fuzz_interframe_gap_maximum(self):
        """Test maximum inter-frame gaps (timeouts)"""
        
    def fuzz_sync_timing_drift(self):
        """Intentional SYNC timing errors"""
        
    def fuzz_heartbeat_timing_violation(self):
        """Send heartbeat at wrong intervals"""
        
    def fuzz_phase_shift_attacks(self):
        """Messages at unexpected phase points"""
        
    def fuzz_timeout_edge_cases(self):
        """Messages just before/after timeout"""
        
    def fuzz_rapid_pdo_bursts(self):
        """50+ PDO in <100ms"""
        
    def fuzz_delayed_responses(self):
        """Intentionally delayed SDO responses"""
        
    def fuzz_clock_drift_simulation(self):
        """Simulate clock skew across devices"""
        
    def fuzz_timing_amplification(self):
        """Exponential timing variations"""
```

**Test File**: `tests/test_fuzzing_timing.py` (100-120 lines)
- Verify timing precision
- Check anomaly detection correlation
- Monitor device state changes

#### 1.3 Configuration Integration
- Add `fuzzing_canid` section to `config.yaml`
- Add `fuzzing_timing` section to `config.yaml`
- Update orchestrator to include both fuzzers

#### Week 1-2 Deliverables
- [x] `canid_fuzzer.py` (150-200 lines)
- [x] `timing_fuzzer.py` (200-250 lines)
- [x] Unit tests (180-220 lines)
- [x] Config section (15-20 lines YAML)
- [x] Orchestrator integration (10-15 lines)
- [x] Documentation updates

**Success Criteria**:
- ✅ Both fuzzers generate valid CAN frames
- ✅ Unit tests pass (>80% coverage)
- ✅ Config loads without errors
- ✅ Orchestrator recognizes both fuzzers
- ✅ Anomaly detection works for both

---

### PHASE 2: Resource & State Machine Fuzzers (Weeks 3-4)

#### 2.1 Resource Exhaustion Fuzzer (`resource_fuzzer.py`)
- **Status**: ✅ Implemented
- **File**: `canopen_security_platform/fuzzing/resource_fuzzer.py`
- **Lines**: 200-250
- **Dependencies**: `threading`, `queue`, `BaseCANFuzzer`

**Strategies** (10-12):
```python
class ResourceFuzzer(BaseCANFuzzer):
    def fuzz_sequential_sdo_storm(self):
        """100+ concurrent SDO transfers"""
        
    def fuzz_pdo_buffer_flood(self):
        """500+ PDO msgs/sec"""
        
    def fuzz_large_payload_escalation(self):
        """Growing payload sizes"""
        
    def fuzz_segmented_transfer_abuse(self):
        """1MB+ segmented SDO"""
        
    def fuzz_concurrent_sdo_max(self):
        """Maximum concurrent SDO requests"""
        
    def fuzz_heartbeat_spam(self):
        """100+ heartbeat msgs/sec"""
        
    def fuzz_emcy_burst(self):
        """Rapid EMCY error codes"""
        
    def fuzz_sync_burst(self):
        """Rapid SYNC messages"""
        
    def fuzz_memory_leak_patterns(self):
        """Repeated allocation/deallocation"""
        
    def fuzz_stack_overflow_attempt(self):
        """Deep recursion in SDO handling"""
        
    def fuzz_buffer_wraparound(self):
        """Test buffer index wraparound"""
        
    def fuzz_resource_recovery_test(self):
        """Recovery after exhaustion"""
```

**Test File**: `tests/test_fuzzing_resource.py` (100-120 lines)

#### 2.2 State Machine Escape Sequences Fuzzer (`state_machine_fuzzer.py`)
- **Status**: ✅ Implemented
- **File**: `canopen_security_platform/fuzzing/state_machine_fuzzer.py`
- **Lines**: 180-220
- **Dependencies**: `BaseCANFuzzer`, `itertools`

**Strategies** (8-10):
```python
class StateMachineFuzzer(BaseCANFuzzer):
    def fuzz_illegal_state_transition(self):
        """All 16² state combinations"""
        
    def fuzz_guard_time_manipulation(self):
        """OD 0x100D boundary exploitation"""
        
    def fuzz_lifetime_factor_abuse(self):
        """OD 0x100C extreme values"""
        
    def fuzz_bootup_during_operational(self):
        """Boot-up while operational"""
        
    def fuzz_reset_surge(self):
        """Multiple resets in rapid succession"""
        
    def fuzz_partial_state_corruption(self):
        """State with invalid bits"""
        
    def fuzz_emergency_to_invalid(self):
        """EMCY to non-existent state"""
        
    def fuzz_producer_consumer_desync(self):
        """Heartbeat drift"""
        
    def fuzz_nmt_spurious_response(self):
        """Unexpected NMT responses"""
        
    def fuzz_state_persistence_test(self):
        """State preservation after attack"""
```

**Test File**: `tests/test_fuzzing_state_machine.py` (100-120 lines)

#### 2.3 Configuration & Integration
- Add `fuzzing_resource` section to `config.yaml`
- Add `fuzzing_state_machine` section to `config.yaml`
- Update orchestrator (10-15 lines)

#### Week 3-4 Deliverables
- [x] `resource_fuzzer.py` (200-250 lines)
- [x] `state_machine_fuzzer.py` (180-220 lines)
- [x] Unit tests (200-240 lines)
- [x] Config sections (20-25 lines YAML)
- [x] Orchestrator integration (10-15 lines)
- [x] Documentation updates

---

### PHASE 3: Boundary & Cross-Protocol Fuzzers (Week 5)

#### 3.1 Protocol Boundary Fuzzer (`boundary_fuzzer.py`)
- **File**: `canopen_security_platform/fuzzing/boundary_fuzzer.py`
- **Lines**: 150-200
- **Strategies** (10-14):
  - `dlc_zero` through `eol_marker_corruption`

#### 3.2 Cross-Protocol Interaction Fuzzer (`cross_protocol_fuzzer.py`)
- **File**: `canopen_security_platform/fuzzing/cross_protocol_fuzzer.py`
- **Lines**: 250-300
- **Strategies** (9-12):
  - `sdo_interleaved_pdo` through `state_change_during_protocol`

#### Week 5 Deliverables
- [ ] `boundary_fuzzer.py` (150-200 lines)
- [ ] `cross_protocol_fuzzer.py` (250-300 lines)
- [ ] Unit tests (200-240 lines)
- [ ] Config sections (20-25 lines YAML)
- [ ] Orchestrator integration (10-15 lines)

---

### PHASE 4: Test Case Library (Week 6)

#### 4.1 Negative Test Cases (400-500 lines)
Files to create:
- `tests/negative_cases/malformed_frames.py` (150-180 lines, 40 test cases)
- `tests/negative_cases/protocol_violations.py` (180-220 lines, 50 test cases)
- `tests/negative_cases/access_violations.py` (120-150 lines, 30 test cases)
- `tests/negative_cases/resource_exhaustion.py` (80-100 lines, 20 test cases)

#### 4.2 Compliance Test Suites (400-500 lines)
Files to create:
- `tests/compliance/ds301_base_compliance.py` (180-220 lines, 40 tests)
- `tests/compliance/ds402_device_profile.py` (200-250 lines, 50 tests)
- `tests/compliance/test_compliance_runner.py` (80-100 lines)

#### 4.3 Stress Scenarios (300-400 lines)
Files to create:
- `tests/stress_scenarios/sustained_rate_stress.py` (150-180 lines, 15 scenarios)
- `tests/stress_scenarios/recovery_resilience.py` (120-150 lines, 12 scenarios)
- `tests/stress_scenarios/fault_injection_recovery.py` (80-100 lines, 10 scenarios)

#### Week 6 Deliverables
- [ ] Negative test case library (400-500 lines, 140 tests)
- [ ] Compliance test suites (400-500 lines, 90 tests)
- [ ] Stress scenarios (300-400 lines, 37 scenarios)
- [ ] Device profile framework (50-100 lines)
- [ ] Profile examples (6 device profiles in YAML)

---

### PHASE 5: Configuration & Orchestration (Week 7)

#### 5.1 Configuration Profiles
Create config variants:
- `config_aggressive_attack.yaml` - Focused on new fuzzing variants
- `config_compliance_audit.yaml` - DS301/402 validation focus
- `config_stress_test.yaml` - Resource exhaustion focus
- Update `config.yaml` with all new sections

#### 5.2 Orchestrator Integration
**File**: `canopen_security_platform/orchestrator/run_full_security_suite.py`

Changes needed:
```python
# Update STAGE count from 15 to 21
# Add stages:
STAGE_16 = "CAN ID Fuzzing"
STAGE_17 = "Timing/Delay Attack Fuzzing"
STAGE_18 = "Resource Exhaustion Fuzzing"
STAGE_19 = "State Machine Escape Sequences"
STAGE_20 = "Protocol Boundary Fuzzing"
STAGE_21 = "Cross-Protocol Interaction Fuzzing"

# Add fuzzer initialization in setup phase
self.canid_fuzzer = CANIDFuzzer(...)
self.timing_fuzzer = TimingFuzzer(...)
# ... etc

# Add execution stages in run() sequence
self._stage_16_canid_fuzzing()
self._stage_17_timing_fuzzing()
# ... etc

# Update reporting to include all fuzzers
# Update TestResults dataclass to include new fields
```

#### 5.3 Reporting Updates
- Add new fuzzer results sections to HTML report
- Add new fuzzer statistics to JSON export
- Create vulnerability correlation analysis
- Add device-specific recommendations

#### Week 7 Deliverables
- [ ] Config profiles (3 new profiles, main config updated)
- [ ] Orchestrator integration (100-150 lines)
- [ ] Reporting updates (100-150 lines)
- [ ] Comprehensive testing
- [ ] Documentation finalization
- [ ] README/WHATS_CHANGED updates

---

## Code Architecture

### New Fuzzer Classes (Inheriting Pattern)

```python
# All new fuzzers inherit from BaseCANFuzzer
from canopen_security_platform.fuzzing.base_fuzzer import BaseCANFuzzer

class CANIDFuzzer(BaseCANFuzzer):
    def __init__(self, bus, od=None, node_id=1, oracle=None):
        super().__init__(bus, od, node_id, oracle)
        self.fuzzer_name = "CAN ID Fuzzer"
    
    def fuzz_reserved_cob_ids(self):
        """Implement mutation strategy"""
        for cob_id in range(0x001, 0x080):
            frame = self._create_test_frame(cob_id, ...)
            self.bus.send(frame)
            self._handle_response()
    
    def execute(self):
        """Main execution entry point"""
        for strategy in self.strategies:
            method = getattr(self, f"fuzz_{strategy}")
            method()
```

### Configuration Schema

```yaml
# Pattern for all new fuzzers
fuzzing_variantname:
  enabled: true
  iterations: 100
  strategies:
    - "strategy1"
    - "strategy2"
    - "strategy3"
  delay_between_tests_ms: 25
  # Fuzzer-specific options
  custom_param: value
```

### Test Results Structure

```python
@dataclass
class TestResults:
    # Existing fields
    sdo_fuzzing_results: Dict[int, FuzzingResult]
    pdo_fuzzing_results: Dict[int, FuzzingResult]
    
    # New fields (Phase 1-3)
    canid_fuzzing_results: Dict[int, FuzzingResult]
    timing_fuzzing_results: Dict[int, FuzzingResult]
    resource_fuzzing_results: Dict[int, FuzzingResult]
    state_machine_fuzzing_results: Dict[int, FuzzingResult]
    boundary_fuzzing_results: Dict[int, FuzzingResult]
    cross_protocol_fuzzing_results: Dict[int, FuzzingResult]
    
    # Compliance and negative testing
    negative_test_results: Dict[str, List[TestCase]]
    compliance_results: ComplianceReport
    stress_scenario_results: List[StressResult]
```

---

## Testing Strategy

### Unit Testing (Per Fuzzer)
- Verify frame generation
- Verify payload mutation
- Verify config loading
- Verify oracle callbacks

### Integration Testing
- All fuzzers work with orchestrator
- Config profiles load correctly
- Results export correctly
- Reporting generates properly

### Hardware Testing (Post-Implementation)
- Run on PCAN hardware
- Monitor for crashes/hangs
- Validate anomaly detection
- Benchmark performance

---

## Milestone Checkpoints

| Week | Milestone | Status |
|------|-----------|--------|
| 1 | CAN ID Fuzzer | ✅ |
| 2 | Timing Fuzzer | ✅ |
| 3 | Resource Fuzzer | ✅ |
| 4 | State Machine Fuzzer | ✅ |
| 5 | Boundary & Cross-Protocol | ⏳ |
| 6 | Test Case Library | ⏳ |
| 7 | Config & Orchestration | ⏳ |
| 8 | Hardware Verification | ⏳ |

---

## Risk Assessment

**High Risk**:
- Cross-protocol timing precision (may vary by OS/hardware)
- Resource exhaustion recovery (device-dependent)

**Medium Risk**:
- Test case library completeness (coverage gaps)
- Compliance test accuracy (spec interpretation)

**Mitigation**:
- Extensive testing on PCAN hardware
- Community feedback integration
- Fuzzer strategy refinement based on results

---

## Success Criteria

**Code**:
- ✅ 6 new fuzzer modules (1,200-1,500 lines fuzzing logic)
- ✅ 150+ negative test cases (900-1,100 lines)
- ✅ 90 compliance tests (400-500 lines)
- ✅ 37 stress scenarios (300-400 lines)
- ✅ 80%+ code coverage

**Functionality**:
- ✅ All fuzzers integrated into orchestrator (21 stages total)
- ✅ Config profiles working
- ✅ Reporting complete and accurate
- ✅ Hardware verified on PCAN

**Documentation**:
- ✅ README updated
- ✅ WHATS_CHANGED updated
- ✅ Detailed fuzzer documentation
- ✅ Test case documentation
- ✅ Usage examples

---

## Next Steps (Post-Implementation)

1. **Week 8**: Hardware verification & refinement
2. **Week 9**: Performance optimization & profiling
3. **Week 10**: Community feedback & iteration
4. **Week 11+**: Advanced fuzzing strategies (genetic algorithms, differential testing)
