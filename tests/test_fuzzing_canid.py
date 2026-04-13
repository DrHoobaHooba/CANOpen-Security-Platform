"""Unit tests for CAN ID Fuzzer."""

import pytest
from unittest.mock import Mock, MagicMock, patch
from canopen_security_platform.fuzzing.canid_fuzzer import CANIDFuzzer, CANIDMutationStrategy


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
    """Create CAN ID fuzzer instance."""
    return CANIDFuzzer(bus=mock_bus, node_id=1, oracle=mock_oracle)


class TestCANIDFuzzerInitialization:
    """Test CAN ID fuzzer initialization."""

    def test_initialization_valid_node_id(self, mock_bus):
        """Test initialization with valid node ID."""
        fuzzer = CANIDFuzzer(bus=mock_bus, node_id=1)
        assert fuzzer.node_id == 1
        assert fuzzer.fuzzed_count == 0
        assert len(fuzzer.test_results) == 0

    def test_initialization_invalid_node_id_zero(self, mock_bus):
        """Test initialization fails with node ID 0."""
        with pytest.raises(ValueError):
            CANIDFuzzer(bus=mock_bus, node_id=0)

    def test_initialization_invalid_node_id_128(self, mock_bus):
        """Test initialization fails with node ID >127."""
        with pytest.raises(ValueError):
            CANIDFuzzer(bus=mock_bus, node_id=128)

    def test_initialization_invalid_node_id_negative(self, mock_bus):
        """Test initialization fails with negative node ID."""
        with pytest.raises(ValueError):
            CANIDFuzzer(bus=mock_bus, node_id=-1)

    def test_initialization_invalid_node_id_type(self, mock_bus):
        """Test initialization fails with non-integer node ID."""
        with pytest.raises(ValueError):
            CANIDFuzzer(bus=mock_bus, node_id="1")


class TestCANIDFuzzerStrategies:
    """Test individual fuzzing strategies."""

    def test_reserved_cob_ids(self, fuzzer, mock_bus):
        """Test reserved COB-ID fuzzing."""
        fuzzer.fuzz_reserved_cob_ids()
        assert fuzzer.fuzzed_count > 0
        assert mock_bus.send.called

    def test_boundary_cob_ids(self, fuzzer, mock_bus):
        """Test boundary COB-ID fuzzing."""
        boundary_count_before = fuzzer.fuzzed_count
        fuzzer.fuzz_boundary_cob_ids()
        assert fuzzer.fuzzed_count > boundary_count_before

    def test_conflicting_cob_ids(self, fuzzer, mock_bus):
        """Test conflicting COB-ID fuzzing."""
        conflicting_count_before = fuzzer.fuzzed_count
        fuzzer.fuzz_conflicting_cob_ids()
        assert fuzzer.fuzzed_count > conflicting_count_before

    def test_cob_id_sweep(self, fuzzer, mock_bus):
        """Test COB-ID sweep fuzzing."""
        sweep_count_before = fuzzer.fuzzed_count
        fuzzer.fuzz_cob_id_sweep()
        assert fuzzer.fuzzed_count > sweep_count_before

    def test_duplicate_cob_ids(self, fuzzer, mock_bus):
        """Test duplicate COB-ID fuzzing."""
        dup_count_before = fuzzer.fuzzed_count
        fuzzer.fuzz_duplicate_cob_ids()
        assert fuzzer.fuzzed_count > dup_count_before
        assert fuzzer.fuzzed_count == dup_count_before + 20  # 20 duplicate messages

    def test_cob_id_fuzz_mask(self, fuzzer, mock_bus):
        """Test bit-flip mutations."""
        mask_count_before = fuzzer.fuzzed_count
        fuzzer.fuzz_cob_id_fuzz_mask()
        assert fuzzer.fuzzed_count > mask_count_before


class TestCANIDFuzzerSendFrame:
    """Test frame sending functionality."""

    def test_send_frame_8_bytes(self, fuzzer, mock_bus):
        """Test sending 8-byte frame."""
        data = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        fuzzer._send_frame(0x100, data, CANIDMutationStrategy.RESERVED_COB_IDS)
        
        assert fuzzer.fuzzed_count == 1
        assert mock_bus.send.called

    def test_send_frame_undersized(self, fuzzer, mock_bus):
        """Test sending undersized frame (auto-padded)."""
        data = b"\x01\x02"
        fuzzer._send_frame(0x100, data, CANIDMutationStrategy.RESERVED_COB_IDS)
        
        assert fuzzer.fuzzed_count == 1
        # Verify padding to 8 bytes
        call_args = mock_bus.send.call_args
        sent_msg = call_args[0][0]
        assert len(sent_msg.data) == 8

    def test_send_frame_oversized(self, fuzzer, mock_bus):
        """Test sending oversized frame (truncated)."""
        data = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A"
        fuzzer._send_frame(0x100, data, CANIDMutationStrategy.RESERVED_COB_IDS)
        
        assert fuzzer.fuzzed_count == 1
        # Verify truncation to 8 bytes
        call_args = mock_bus.send.call_args
        sent_msg = call_args[0][0]
        assert len(sent_msg.data) == 8

    def test_send_frame_calls_oracle(self, fuzzer, mock_bus, mock_oracle):
        """Test oracle callback is called."""
        data = b"\x00" * 8
        fuzzer._send_frame(0x100, data, CANIDMutationStrategy.RESERVED_COB_IDS)
        
        assert mock_oracle.called
        call_args = mock_oracle.call_args[0][0]
        assert call_args["event_type"] == "fuzz_input_sent"
        assert call_args["fuzzer"] == "canid"

    def test_send_frame_exception_handling(self, fuzzer, mock_bus):
        """Test exception handling during send."""
        mock_bus.send.side_effect = Exception("Bus error")
        
        data = b"\x00" * 8
        fuzzer._send_frame(0x100, data, CANIDMutationStrategy.RESERVED_COB_IDS)
        
        # Should not raise, but count might not increase
        assert mock_bus.send.called


class TestCANIDFuzzerExecution:
    """Test full fuzzer execution."""

    def test_execute_runs_all_strategies(self, fuzzer, mock_bus):
        """Test that execute() runs all strategies."""
        fuzzer.execute()
        
        # Should have sent multiple frames
        assert fuzzer.fuzzed_count > 0
        assert mock_bus.send.called
        assert len(fuzzer.test_results) > 0

    def test_execute_handles_exceptions(self, fuzzer, mock_bus):
        """Test that execute() handles exceptions gracefully."""
        mock_bus.send.side_effect = Exception("Bus error")
        
        # Should not raise
        fuzzer.execute()
        assert mock_bus.send.called


class TestCANIDFuzzerResultTracking:
    """Test result tracking functionality."""

    def test_results_recorded(self, fuzzer):
        """Test that results are recorded."""
        data = b"\x00" * 8
        fuzzer._send_frame(0x100, data, CANIDMutationStrategy.RESERVED_COB_IDS)
        
        assert len(fuzzer.test_results) == 1
        result = fuzzer.test_results[0]
        assert result["strategy"] == CANIDMutationStrategy.RESERVED_COB_IDS.value
        assert result["cob_id"] == 0x100

    def test_results_contain_required_fields(self, fuzzer):
        """Test that results contain all required fields."""
        data = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        fuzzer._send_frame(0x100, data, CANIDMutationStrategy.BOUNDARY_COB_IDS)
        
        result = fuzzer.test_results[0]
        assert "timestamp" in result
        assert "strategy" in result
        assert "cob_id" in result
        assert "data" in result
