"""Unit tests for Timing & Delay Attack Fuzzer."""

import pytest
import time
from unittest.mock import Mock, MagicMock, patch
from canopen_security_platform.fuzzing.timing_fuzzer import TimingFuzzer, TimingMutationStrategy


@pytest.fixture
def mock_bus():
    """Create mock CAN bus."""
    bus = Mock()
    bus.send = Mock()
    return bus


@pytest.fixture
def mock_oracle():
    """Create mock oracle callback."""
    return Mock()


@pytest.fixture
def fuzzer(mock_bus, mock_oracle):
    """Create timing fuzzer instance."""
    return TimingFuzzer(bus=mock_bus, node_id=1, oracle=mock_oracle)


class TestTimingFuzzerInitialization:
    """Test timing fuzzer initialization."""

    def test_initialization_valid_node_id(self, mock_bus):
        """Test initialization with valid node ID."""
        fuzzer = TimingFuzzer(bus=mock_bus, node_id=1)
        assert fuzzer.node_id == 1
        assert fuzzer.fuzzed_count == 0
        assert len(fuzzer.test_results) == 0

    def test_initialization_invalid_node_id_zero(self, mock_bus):
        """Test initialization fails with node ID 0."""
        with pytest.raises(ValueError):
            TimingFuzzer(bus=mock_bus, node_id=0)

    def test_initialization_invalid_node_id_128(self, mock_bus):
        """Test initialization fails with node ID >127."""
        with pytest.raises(ValueError):
            TimingFuzzer(bus=mock_bus, node_id=128)

    def test_initialization_invalid_node_id_type(self, mock_bus):
        """Test initialization fails with non-integer node ID."""
        with pytest.raises(ValueError):
            TimingFuzzer(bus=mock_bus, node_id="1")

    def test_initialization_with_optional_parameters(self, mock_bus, mock_oracle):
        """Test initialization with optional parameters."""
        fuzzer = TimingFuzzer(bus=mock_bus, node_id=50, oracle=mock_oracle)
        assert fuzzer.node_id == 50
        assert fuzzer.oracle == mock_oracle


class TestTimingFuzzerStrategies:
    """Test individual timing fuzzing strategies."""

    @patch('time.sleep')
    def test_zero_delay_burst(self, mock_sleep, fuzzer, mock_bus):
        """Test zero delay burst strategy."""
        count_before = fuzzer.fuzzed_count
        fuzzer.fuzz_zero_delay_burst()
        
        assert fuzzer.fuzzed_count > count_before
        assert mock_bus.send.called

    @patch('time.sleep')
    def test_extreme_jitter(self, mock_sleep, fuzzer, mock_bus):
        """Test extreme jitter strategy."""
        count_before = fuzzer.fuzzed_count
        fuzzer.fuzz_extreme_jitter()
        
        assert fuzzer.fuzzed_count > count_before
        assert mock_sleep.called

    @patch('time.sleep')
    def test_interframe_gap_minimum(self, mock_sleep, fuzzer, mock_bus):
        """Test minimum inter-frame gap strategy."""
        count_before = fuzzer.fuzzed_count
        fuzzer.fuzz_interframe_gap_minimum()
        
        assert fuzzer.fuzzed_count > count_before
        # Should send 40 messages
        assert fuzzer.fuzzed_count == count_before + 40

    @patch('time.sleep')
    def test_interframe_gap_maximum(self, mock_sleep, fuzzer, mock_bus):
        """Test maximum inter-frame gap strategy."""
        count_before = fuzzer.fuzzed_count
        fuzzer.fuzz_interframe_gap_maximum()
        
        assert fuzzer.fuzzed_count > count_before
        assert mock_sleep.called

    @patch('time.sleep')
    def test_sync_timing_drift(self, mock_sleep, fuzzer, mock_bus):
        """Test SYNC timing drift strategy."""
        count_before = fuzzer.fuzzed_count
        fuzzer.fuzz_sync_timing_drift()
        
        assert fuzzer.fuzzed_count > count_before

    @patch('time.sleep')
    def test_heartbeat_timing_violation(self, mock_sleep, fuzzer, mock_bus):
        """Test heartbeat timing violation strategy."""
        count_before = fuzzer.fuzzed_count
        fuzzer.fuzz_heartbeat_timing_violation()
        
        assert fuzzer.fuzzed_count > count_before

    @patch('time.sleep')
    def test_phase_shift_attacks(self, mock_sleep, fuzzer, mock_bus):
        """Test phase shift attack strategy."""
        count_before = fuzzer.fuzzed_count
        fuzzer.fuzz_phase_shift_attacks()
        
        assert fuzzer.fuzzed_count > count_before

    @patch('time.sleep')
    def test_timeout_edge_cases(self, mock_sleep, fuzzer, mock_bus):
        """Test timeout edge case strategy."""
        count_before = fuzzer.fuzzed_count
        fuzzer.fuzz_timeout_edge_cases()
        
        assert fuzzer.fuzzed_count > count_before

    @patch('time.sleep')
    def test_rapid_pdo_bursts(self, mock_sleep, fuzzer, mock_bus):
        """Test rapid PDO burst strategy."""
        count_before = fuzzer.fuzzed_count
        fuzzer.fuzz_rapid_pdo_bursts()
        
        assert fuzzer.fuzzed_count > count_before
        # Should send 50 messages
        assert fuzzer.fuzzed_count == count_before + 50

    @patch('time.sleep')
    def test_delayed_responses(self, mock_sleep, fuzzer, mock_bus):
        """Test delayed response strategy."""
        count_before = fuzzer.fuzzed_count
        fuzzer.fuzz_delayed_responses()
        
        assert fuzzer.fuzzed_count > count_before

    @patch('time.sleep')
    def test_clock_drift_simulation(self, mock_sleep, fuzzer, mock_bus):
        """Test clock drift simulation strategy."""
        count_before = fuzzer.fuzzed_count
        fuzzer.fuzz_clock_drift_simulation()
        
        assert fuzzer.fuzzed_count > count_before

    @patch('time.sleep')
    def test_timing_amplification(self, mock_sleep, fuzzer, mock_bus):
        """Test timing amplification strategy."""
        count_before = fuzzer.fuzzed_count
        fuzzer.fuzz_timing_amplification()
        
        assert fuzzer.fuzzed_count > count_before


class TestTimingFuzzerRecordResult:
    """Test result recording functionality."""

    def test_record_result_basic(self, fuzzer):
        """Test basic result recording."""
        data = b"\x00" * 8
        fuzzer._record_result(
            TimingMutationStrategy.ZERO_DELAY_BURST,
            0x100, data, timing_ms=0
        )
        
        assert len(fuzzer.test_results) == 1
        result = fuzzer.test_results[0]
        assert result["strategy"] == TimingMutationStrategy.ZERO_DELAY_BURST.value
        assert result["cob_id"] == 0x100
        assert result["timing_ms"] == 0

    def test_record_result_contains_required_fields(self, fuzzer):
        """Test that recorded result contains all required fields."""
        data = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        fuzzer._record_result(
            TimingMutationStrategy.EXTREME_JITTER,
            0x200, data, timing_ms=500
        )
        
        result = fuzzer.test_results[0]
        assert "timestamp" in result
        assert "strategy" in result
        assert "cob_id" in result
        assert "data" in result
        assert "timing_ms" in result

    def test_record_result_calls_oracle(self, fuzzer, mock_oracle):
        """Test that oracle callback is called."""
        data = b"\x00" * 8
        fuzzer._record_result(
            TimingMutationStrategy.SYNC_TIMING_DRIFT,
            0x080, data, timing_ms=100
        )
        
        assert mock_oracle.called
        call_args = mock_oracle.call_args[0][0]
        assert call_args["event_type"] == "fuzz_input_sent"
        assert call_args["fuzzer"] == "timing"
        assert call_args["timing_ms"] == 100


class TestTimingFuzzerExecution:
    """Test full fuzzer execution."""

    @patch('time.sleep')
    def test_execute_runs_all_strategies(self, mock_sleep, fuzzer, mock_bus):
        """Test that execute() runs all strategies."""
        fuzzer.execute()
        
        # Should have sent multiple frames
        assert fuzzer.fuzzed_count > 0
        assert mock_bus.send.called
        assert len(fuzzer.test_results) > 0

    @patch('time.sleep')
    def test_execute_handles_exceptions(self, mock_sleep, fuzzer, mock_bus):
        """Test that execute() handles exceptions gracefully."""
        mock_bus.send.side_effect = Exception("Bus error")
        
        # Should not raise
        fuzzer.execute()
        assert mock_bus.send.called

    @patch('time.sleep')
    def test_execute_timing_complete(self, mock_sleep, fuzzer, mock_bus):
        """Test that execute() completes without hanging."""
        start = time.time()
        fuzzer.execute()
        elapsed = time.time() - start
        
        # Should complete quickly (mocked sleep) in < 10 seconds
        assert elapsed < 10.0


class TestTimingFuzzerConstants:
    """Test timing constant definitions."""

    def test_timing_constants_defined(self, fuzzer):
        """Test that timing constants are properly defined."""
        assert fuzzer.SYNC_PERIOD_DEFAULT == 100
        assert fuzzer.HEARTBEAT_PERIOD_DEFAULT == 1000
        assert fuzzer.NMT_INHIBIT_TIME_DEFAULT == 2
        assert fuzzer.GUARD_TIME_DEFAULT == 100


class TestTimingFuzzerMutationStrategies:
    """Test timing mutation strategy enum."""

    def test_all_strategies_defined(self):
        """Test that all timing mutation strategies are defined."""
        strategies = [
            TimingMutationStrategy.ZERO_DELAY_BURST,
            TimingMutationStrategy.EXTREME_JITTER,
            TimingMutationStrategy.INTERFRAME_GAP_MINIMUM,
            TimingMutationStrategy.INTERFRAME_GAP_MAXIMUM,
            TimingMutationStrategy.SYNC_TIMING_DRIFT,
            TimingMutationStrategy.HEARTBEAT_TIMING_VIOLATION,
            TimingMutationStrategy.PHASE_SHIFT_ATTACKS,
            TimingMutationStrategy.TIMEOUT_EDGE_CASES,
            TimingMutationStrategy.RAPID_PDO_BURSTS,
            TimingMutationStrategy.DELAYED_RESPONSES,
            TimingMutationStrategy.CLOCK_DRIFT_SIMULATION,
            TimingMutationStrategy.TIMING_AMPLIFICATION,
        ]
        assert len(strategies) == 12

    def test_strategy_values_are_unique(self):
        """Test that all strategy values are unique."""
        strategies = TimingMutationStrategy
        values = [s.value for s in strategies]
        assert len(values) == len(set(values))
