"""Unit tests for State Machine Escape Sequences Fuzzer."""

import pytest
from unittest.mock import Mock, MagicMock, patch
from canopen_security_platform.fuzzing.state_machine_fuzzer import (
    StateMachineFuzzer, StateMachineMutationStrategy, NMTState
)


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
    """Create state machine fuzzer instance."""
    return StateMachineFuzzer(bus=mock_bus, node_id=1, oracle=mock_oracle)


class TestStateMachineFuzzerInitialization:
    """Test state machine fuzzer initialization."""

    def test_initialization_valid_node_id(self, mock_bus):
        """Test initialization with valid node ID."""
        fuzzer = StateMachineFuzzer(bus=mock_bus, node_id=1)
        assert fuzzer.node_id == 1
        assert fuzzer.fuzzed_count == 0
        assert len(fuzzer.test_results) == 0

    def test_initialization_invalid_node_id_zero(self, mock_bus):
        """Test initialization fails with node ID 0."""
        with pytest.raises(ValueError):
            StateMachineFuzzer(bus=mock_bus, node_id=0)

    def test_initialization_invalid_node_id_128(self, mock_bus):
        """Test initialization fails with node ID > 127."""
        with pytest.raises(ValueError):
            StateMachineFuzzer(bus=mock_bus, node_id=128)

    def test_initialization_with_optional_parameters(self, mock_bus, mock_oracle):
        """Test initialization with optional parameters."""
        fuzzer = StateMachineFuzzer(bus=mock_bus, node_id=5, oracle=mock_oracle)
        assert fuzzer.node_id == 5
        assert fuzzer.oracle == mock_oracle

    def test_initialization_sets_initial_state(self, mock_bus):
        """Test initialization sets correct initial state."""
        fuzzer = StateMachineFuzzer(bus=mock_bus, node_id=1)
        assert fuzzer.current_state == NMTState.INITIALIZING


class TestNMTStateEnum:
    """Test NMT state enumeration."""

    def test_valid_nmt_states_exist(self):
        """Test all valid NMT states are defined."""
        assert NMTState.INITIALIZING.value == 0x00
        assert NMTState.PREOPERATIONAL.value == 0x7F
        assert NMTState.OPERATIONAL.value == 0x05
        assert NMTState.STOPPED.value == 0x04


class TestStateMachineFuzzerStrategies:
    """Test individual state machine escape sequence strategies."""

    def test_illegal_state_transition(self, fuzzer, mock_bus):
        """Test illegal state transition sends 16² frames."""
        fuzzer.fuzz_illegal_state_transition()
        # Should send 16*16=256 illegal transition attempts
        assert mock_bus.send.call_count == 256

    def test_guard_time_manipulation(self, fuzzer, mock_bus):
        """Test guard time manipulation sends OD 0x100D."""
        fuzzer.fuzz_guard_time_manipulation()
        # Should send 5 SDO frames (one per guard time value)
        assert mock_bus.send.call_count >= 5

    def test_lifetime_factor_abuse(self, fuzzer, mock_bus):
        """Test lifetime factor abuse sends OD 0x100C."""
        fuzzer.fuzz_lifetime_factor_abuse()
        # Should send 4 SDO frames (one per lifetime factor value)
        assert mock_bus.send.call_count >= 4

    def test_bootup_during_operational(self, fuzzer, mock_bus):
        """Test bootup during operational sends boot-up message."""
        fuzzer.fuzz_bootup_during_operational()
        assert mock_bus.send.called
        # Should send operational command + boot-up message
        assert mock_bus.send.call_count >= 2

    def test_reset_surge(self, fuzzer, mock_bus):
        """Test reset surge sends 20 reset commands."""
        fuzzer.fuzz_reset_surge()
        assert mock_bus.send.call_count >= 20

    def test_partial_state_corruption(self, fuzzer, mock_bus):
        """Test partial state corruption sends invalid states."""
        fuzzer.fuzz_partial_state_corruption()
        # Should send 7 invalid state patterns
        assert mock_bus.send.call_count >= 7

    def test_emergency_to_invalid(self, fuzzer, mock_bus):
        """Test EMCY to invalid sends EMCY with invalid codes."""
        fuzzer.fuzz_emergency_to_invalid()
        assert mock_bus.send.called
        # Should send operational + EMCY for each error code
        assert mock_bus.send.call_count >= 8  # 4 error codes * 2 commands

    def test_producer_consumer_desync(self, fuzzer, mock_bus):
        """Test producer/consumer desync sends heartbeats at irregular intervals."""
        fuzzer.fuzz_producer_consumer_desync()
        # Should send 8 heartbeat messages
        assert mock_bus.send.call_count >= 8

    def test_nmt_spurious_response(self, fuzzer, mock_bus):
        """Test NMT spurious response sends unexpected commands."""
        fuzzer.fuzz_nmt_spurious_response()
        # Should send 4 spurious NMT responses
        assert mock_bus.send.call_count >= 4

    def test_state_persistence_test(self, fuzzer, mock_bus):
        """Test state persistence sends attack + recovery + verify."""
        fuzzer.fuzz_state_persistence_test()
        assert mock_bus.send.called
        # Should send attack phase + recovery + verify


class TestStateMachineFuzzerExecution:
    """Test fuzzer execution."""

    def test_execute_runs_all_strategies(self, fuzzer, mock_bus):
        """Test execute runs all strategies."""
        fuzzer.execute()
        assert mock_bus.send.called
        assert fuzzer.fuzzed_count > 0

    def test_execute_collects_results(self, fuzzer, mock_bus):
        """Test execute collects results from all strategies."""
        fuzzer.execute()
        assert len(fuzzer.test_results) > 0

    def test_execute_with_oracle(self, fuzzer, mock_bus, mock_oracle):
        """Test execute calls oracle with events."""
        fuzzer.execute()
        assert mock_oracle.called


class TestStateMachineFuzzerOracleIntegration:
    """Test oracle callback integration."""

    def test_record_result_calls_oracle(self, fuzzer, mock_oracle):
        """Test record result calls oracle callback."""
        fuzzer._record_result(
            StateMachineMutationStrategy.ILLEGAL_STATE_TRANSITION,
            0x000, b"test", "test_detail"
        )
        mock_oracle.assert_called_once()
        call_args = mock_oracle.call_args[0][0]
        assert call_args["event_type"] == "fuzz_input_sent"
        assert call_args["fuzzer"] == "state_machine"

    def test_record_result_contains_required_fields(self, fuzzer):
        """Test record result contains all required fields."""
        fuzzer._record_result(
            StateMachineMutationStrategy.RESET_SURGE,
            0x000, b"test", "detail"
        )
        result = fuzzer.test_results[0]
        assert "timestamp" in result
        assert "strategy" in result
        assert "cob_id" in result
        assert "data" in result
        assert "details" in result
        assert result["strategy"] == "reset_surge"


class TestStateMachineFuzzerFrameGeneration:
    """Test CAN frame generation."""

    def test_illegal_state_transition_targets_nmt_cob_id(self, fuzzer, mock_bus):
        """Test illegal transitions target NMT COB-ID 0x000."""
        fuzzer.fuzz_illegal_state_transition()
        
        for call in mock_bus.send.call_args_list:
            frame = call[0][0]
            assert frame.arbitration_id == 0x000

    def test_guard_time_manipulation_targets_sdo(self, fuzzer, mock_bus):
        """Test guard time targets SDO COB-ID."""
        fuzzer.fuzz_guard_time_manipulation()
        
        for call in mock_bus.send.call_args_list:
            frame = call[0][0]
            # SDO is 0x580 + node_id (1) = 0x581
            assert frame.arbitration_id == 0x581

    def test_frames_have_valid_payload_length(self, fuzzer, mock_bus):
        """Test generated frames have valid payload length."""
        fuzzer.fuzz_reset_surge()
        
        for call in mock_bus.send.call_args_list:
            frame = call[0][0]
            assert hasattr(frame, 'data')
            assert 0 <= len(frame.data) <= 8


class TestStateMachineFuzzerStateTransitions:
    """Test NMT state transition handling."""

    def test_illegal_state_transition_covers_all_combinations(self, fuzzer, mock_bus):
        """Test illegal state transition covers all 16² combinations."""
        fuzzer.fuzz_illegal_state_transition()
        # 16 possible values (0x00-0x0F) * 16 combinations = 256 frames
        assert fuzzer.fuzzed_count >= 256

    def test_reset_surge_rapid_sequence(self, fuzzer, mock_bus):
        """Test reset surge sends rapid reset sequence."""
        fuzzer.fuzz_reset_surge()
        assert fuzzer.fuzzed_count >= 20
        # All should be NMT resets (0x81)
        for call in mock_bus.send.call_args_list[:20]:
            frame = call[0][0]
            assert frame.arbitration_id == 0x000
            assert frame.data[0] == 0x81  # Initialize command
