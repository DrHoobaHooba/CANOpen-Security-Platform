"""Unit tests for Tier 1 fuzzing engines (EMCY, SYNC, Concurrent)."""

import pytest
import time
from unittest.mock import Mock, MagicMock, patch
import can

from canopen_security_platform.fuzzing.emcy_fuzzer import EMCYFuzzer
from canopen_security_platform.fuzzing.sync_fuzzer import SYNCFuzzer
from canopen_security_platform.fuzzing.concurrent_fuzzer import ConcurrentFuzzer
from canopen_security_platform.od.runtime_od import RuntimeObjectDictionary


class TestEMCYFuzzer:
    """Test EMCY fuzzing engine."""

    @pytest.fixture
    def setup(self):
        """Setup test fixtures."""
        bus_mock = MagicMock(spec=can.BusABC)
        od_mock = RuntimeObjectDictionary()
        
        def oracle_callback(event):
            pass
        
        return {
            'bus': bus_mock,
            'od': od_mock,
            'node_id': 1,
            'oracle': oracle_callback,
        }

    def test_emcy_fuzzer_initialization(self, setup):
        """Test EMCY fuzzer initialization."""
        fuzzer = EMCYFuzzer(
            bus=setup['bus'],
            od=setup['od'],
            node_id=setup['node_id'],
            oracle=setup['oracle'],
        )
        
        assert fuzzer.node_id == 1
        assert fuzzer.emcy_cob_id == 0x081  # 0x080 + 1
        assert fuzzer.fuzzed_count == 0
        assert len(fuzzer.test_results) == 0

    def test_emcy_fuzzer_invalid_node_id(self, setup):
        """Test EMCY fuzzer with invalid node ID."""
        with pytest.raises(ValueError):
            EMCYFuzzer(
                bus=setup['bus'],
                od=setup['od'],
                node_id=128,  # Invalid
                oracle=setup['oracle'],
            )

    def test_emcy_error_code_fuzzing(self, setup):
        """Test EMCY error code fuzzing strategy."""
        fuzzer = EMCYFuzzer(
            bus=setup['bus'],
            od=setup['od'],
            node_id=setup['node_id'],
            oracle=setup['oracle'],
        )
        
        fuzzer.error_code_fuzzing()
        
        assert fuzzer.fuzzed_count > 0
        assert len(fuzzer.test_results) > 0

    def test_emcy_rapid_burst(self, setup):
        """Test EMCY rapid burst strategy."""
        fuzzer = EMCYFuzzer(
            bus=setup['bus'],
            od=setup['od'],
            node_id=setup['node_id'],
            oracle=setup['oracle'],
        )
        
        fuzzer.rapid_emcy_burst()
        
        assert fuzzer.fuzzed_count == 20

    def test_emcy_run_all_strategies(self, setup):
        """Test EMCY run_all_strategies method."""
        fuzzer = EMCYFuzzer(
            bus=setup['bus'],
            od=setup['od'],
            node_id=setup['node_id'],
            oracle=setup['oracle'],
        )
        
        results = fuzzer.run_all_strategies(iterations=1)
        
        assert isinstance(results, list)
        assert fuzzer.fuzzed_count > 0

    def test_emcy_error_register_to_code_mapping(self, setup):
        """Test error code to register bit mapping."""
        fuzzer = EMCYFuzzer(
            bus=setup['bus'],
            od=setup['od'],
            node_id=setup['node_id'],
            oracle=setup['oracle'],
        )
        
        assert fuzzer._error_code_to_register(0x0000) == 0x00  # No error
        assert fuzzer._error_code_to_register(0x1000) == 0x01  # Generic
        assert fuzzer._error_code_to_register(0x2000) == 0x02  # Current
        assert fuzzer._error_code_to_register(0x3000) == 0x04  # Voltage
        assert fuzzer._error_code_to_register(0x4000) == 0x08  # Temperature


class TestSYNCFuzzer:
    """Test SYNC fuzzing engine."""

    @pytest.fixture
    def setup(self):
        """Setup test fixtures."""
        bus_mock = MagicMock(spec=can.BusABC)
        od_mock = RuntimeObjectDictionary()
        
        def oracle_callback(event):
            pass
        
        return {
            'bus': bus_mock,
            'od': od_mock,
            'oracle': oracle_callback,
        }

    def test_sync_fuzzer_initialization(self, setup):
        """Test SYNC fuzzer initialization."""
        fuzzer = SYNCFuzzer(
            bus=setup['bus'],
            od=setup['od'],
            oracle=setup['oracle'],
        )
        
        assert fuzzer.sync_cob_id == 0x080
        assert fuzzer.fuzzed_count == 0
        assert len(fuzzer.test_results) == 0

    def test_sync_counter_overflow(self, setup):
        """Test SYNC counter overflow fuzzing."""
        fuzzer = SYNCFuzzer(
            bus=setup['bus'],
            od=setup['od'],
            oracle=setup['oracle'],
        )
        
        fuzzer.counter_overflow_fuzzing()
        
        assert fuzzer.fuzzed_count > 0

    def test_sync_burst_flooding(self, setup):
        """Test SYNC burst flooding strategy."""
        fuzzer = SYNCFuzzer(
            bus=setup['bus'],
            od=setup['od'],
            oracle=setup['oracle'],
        )
        
        fuzzer.burst_flooding()
        
        assert fuzzer.fuzzed_count == 50

    def test_sync_duplicate_counter(self, setup):
        """Test SYNC duplicate counter handling."""
        fuzzer = SYNCFuzzer(
            bus=setup['bus'],
            od=setup['od'],
            oracle=setup['oracle'],
        )
        
        fuzzer.duplicate_counter_handling()
        
        assert fuzzer.fuzzed_count > 0

    def test_sync_run_all_strategies(self, setup):
        """Test SYNC run_all_strategies method."""
        fuzzer = SYNCFuzzer(
            bus=setup['bus'],
            od=setup['od'],
            oracle=setup['oracle'],
        )
        
        results = fuzzer.run_all_strategies(iterations=1)
        
        assert isinstance(results, list)
        assert fuzzer.fuzzed_count > 0

    def test_sync_missing_frames(self, setup):
        """Test SYNC missing frame scenario."""
        fuzzer = SYNCFuzzer(
            bus=setup['bus'],
            od=setup['od'],
            oracle=setup['oracle'],
        )
        
        fuzzer.missing_sync_frames()
        
        assert fuzzer.fuzzed_count == 17  # 5 + 3 + 4 + 5 = 17


class TestConcurrentFuzzer:
    """Test Concurrent message fuzzing engine."""

    @pytest.fixture
    def setup(self):
        """Setup test fixtures."""
        bus_mock = MagicMock(spec=can.BusABC)
        od_mock = RuntimeObjectDictionary()
        
        def oracle_callback(event):
            pass
        
        return {
            'bus': bus_mock,
            'od': od_mock,
            'node_id': 1,
            'oracle': oracle_callback,
        }

    def test_concurrent_fuzzer_initialization(self, setup):
        """Test Concurrent fuzzer initialization."""
        fuzzer = ConcurrentFuzzer(
            bus=setup['bus'],
            od=setup['od'],
            node_id=setup['node_id'],
            oracle=setup['oracle'],
        )
        
        assert fuzzer.node_id == 1
        assert fuzzer.sdo_rx_cob == 0x601  # 0x600 + 1
        assert fuzzer.sdo_tx_cob == 0x581  # 0x580 + 1
        assert fuzzer.pdo1_rx_cob == 0x201  # 0x200 + 1
        assert fuzzer.pdo1_tx_cob == 0x181  # 0x180 + 1
        assert fuzzer.fuzzed_count == 0

    def test_concurrent_fuzzer_invalid_node_id(self, setup):
        """Test Concurrent fuzzer with invalid node ID."""
        with pytest.raises(ValueError):
            ConcurrentFuzzer(
                bus=setup['bus'],
                od=setup['od'],
                node_id=200,  # Invalid
                oracle=setup['oracle'],
            )

    def test_concurrent_sdo_interleaving(self, setup):
        """Test SDO interleaving fuzzing strategy."""
        fuzzer = ConcurrentFuzzer(
            bus=setup['bus'],
            od=setup['od'],
            node_id=setup['node_id'],
            oracle=setup['oracle'],
        )
        
        fuzzer.sdо_sdo_interleaving()
        
        assert fuzzer.fuzzed_count == 20

    def test_concurrent_nmt_state_change(self, setup):
        """Test NMT state change during transfer."""
        fuzzer = ConcurrentFuzzer(
            bus=setup['bus'],
            od=setup['od'],
            node_id=setup['node_id'],
            oracle=setup['oracle'],
        )
        
        fuzzer.nmt_state_change_during_transfer()
        
        assert fuzzer.fuzzed_count > 0

    def test_concurrent_run_all_strategies(self, setup):
        """Test Concurrent run_all_strategies method."""
        fuzzer = ConcurrentFuzzer(
            bus=setup['bus'],
            od=setup['od'],
            node_id=setup['node_id'],
            oracle=setup['oracle'],
        )
        
        results = fuzzer.run_all_strategies(iterations=1)
        
        assert isinstance(results, list)
        assert fuzzer.fuzzed_count > 0


class TestNMTFuzzerExtensions:
    """Test NMT fuzzer extensions (heartbeat and guard time)."""

    @pytest.fixture
    def setup(self):
        """Setup test fixtures."""
        bus_mock = MagicMock(spec=can.BusABC)
        od_mock = RuntimeObjectDictionary()
        
        def oracle_callback(event):
            pass
        
        return {
            'bus': bus_mock,
            'od': od_mock,
            'node_id': 1,
            'oracle': oracle_callback,
        }

    def test_nmt_heartbeat_fuzzing(self, setup):
        """Test NMT heartbeat fuzzing strategy."""
        from canopen_security_platform.fuzzing.nmt_fuzzer import NMTFuzzer
        
        fuzzer = NMTFuzzer(
            bus=setup['bus'],
            od=setup['od'],
            node_id=setup['node_id'],
            oracle=setup['oracle'],
        )
        
        initial_count = fuzzer.fuzzed_count
        fuzzer.heartbeat_fuzzing()
        
        assert fuzzer.fuzzed_count > initial_count

    def test_nmt_guard_time_fuzzing(self, setup):
        """Test NMT guard time fuzzing strategy."""
        from canopen_security_platform.fuzzing.nmt_fuzzer import NMTFuzzer
        
        fuzzer = NMTFuzzer(
            bus=setup['bus'],
            od=setup['od'],
            node_id=setup['node_id'],
            oracle=setup['oracle'],
        )
        
        initial_count = fuzzer.fuzzed_count
        fuzzer.guard_time_fuzzing()
        
        assert fuzzer.fuzzed_count > initial_count

    def test_nmt_execute_with_new_strategies(self, setup):
        """Test NMT execute includes new strategies."""
        from canopen_security_platform.fuzzing.nmt_fuzzer import NMTFuzzer
        
        fuzzer = NMTFuzzer(
            bus=setup['bus'],
            od=setup['od'],
            node_id=setup['node_id'],
            oracle=setup['oracle'],
        )
        
        fuzzer.execute()
        
        # Should have run multiple strategies
        assert fuzzer.fuzzed_count > 0
        # Should have collected results
        assert len(fuzzer.test_results) > 0


class TestIntegration:
    """Integration tests for Tier 1 fuzzers."""

    @pytest.fixture
    def setup(self):
        """Setup test fixtures."""
        bus_mock = MagicMock(spec=can.BusABC)
        od_mock = RuntimeObjectDictionary()
        
        def oracle_callback(event):
            pass
        
        return {
            'bus': bus_mock,
            'od': od_mock,
            'node_id': 5,
            'oracle': oracle_callback,
        }

    def test_all_tier1_fuzzers_basic_execution(self, setup):
        """Test that all Tier 1 fuzzers can execute without errors."""
        fuzzers = [
            EMCYFuzzer(setup['bus'], setup['od'], setup['node_id'], setup['oracle']),
            SYNCFuzzer(setup['bus'], setup['od'], setup['oracle']),
            ConcurrentFuzzer(setup['bus'], setup['od'], setup['node_id'], setup['oracle']),
        ]
        
        for fuzzer in fuzzers:
            if hasattr(fuzzer, 'run_all_strategies'):
                # EMCY and SYNC and Concurrent have this method
                results = fuzzer.run_all_strategies(iterations=1)
                assert isinstance(results, list)
                assert fuzzer.fuzzed_count > 0

    def test_oracle_callback_coverage(self, setup):
        """Test that oracle callbacks are properly invoked."""
        callback_events = []
        
        def tracking_oracle(event):
            callback_events.append(event)
        
        emcy_fuzzer = EMCYFuzzer(
            setup['bus'],
            setup['od'],
            setup['node_id'],
            tracking_oracle,
        )
        
        emcy_fuzzer.error_code_fuzzing()
        
        # Should have recorded some events
        assert len(callback_events) > 0
