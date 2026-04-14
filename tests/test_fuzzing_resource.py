"""Unit tests for Resource Exhaustion Fuzzer."""

import pytest
from unittest.mock import Mock, MagicMock, patch
from canopen_security_platform.fuzzing.resource_fuzzer import ResourceFuzzer, ResourceMutationStrategy


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
    """Create resource fuzzer instance."""
    return ResourceFuzzer(bus=mock_bus, node_id=1, oracle=mock_oracle, 
                         max_concurrent=5, duration_seconds=1)


class TestResourceFuzzerInitialization:
    """Test resource fuzzer initialization."""

    def test_initialization_valid_node_id(self, mock_bus):
        """Test initialization with valid node ID."""
        fuzzer = ResourceFuzzer(bus=mock_bus, node_id=1)
        assert fuzzer.node_id == 1
        assert fuzzer.fuzzed_count == 0
        assert len(fuzzer.test_results) == 0

    def test_initialization_invalid_node_id_zero(self, mock_bus):
        """Test initialization fails with node ID 0."""
        with pytest.raises(ValueError):
            ResourceFuzzer(bus=mock_bus, node_id=0)

    def test_initialization_invalid_node_id_128(self, mock_bus):
        """Test initialization fails with node ID > 127."""
        with pytest.raises(ValueError):
            ResourceFuzzer(bus=mock_bus, node_id=128)

    def test_initialization_with_optional_parameters(self, mock_bus, mock_oracle):
        """Test initialization with optional parameters."""
        fuzzer = ResourceFuzzer(
            bus=mock_bus, node_id=5, oracle=mock_oracle,
            max_concurrent=10, duration_seconds=5
        )
        assert fuzzer.node_id == 5
        assert fuzzer.oracle == mock_oracle
        assert fuzzer.max_concurrent == 10
        assert fuzzer.duration_seconds == 5

    def test_initialization_default_parameters(self, mock_bus):
        """Test initialization with default parameters."""
        fuzzer = ResourceFuzzer(bus=mock_bus, node_id=1)
        assert fuzzer.max_concurrent == 10
        assert fuzzer.duration_seconds == 5


class TestResourceFuzzerStrategies:
    """Test individual resource exhaustion strategies."""

    def test_sequential_sdo_storm(self, fuzzer, mock_bus):
        """Test SDO storm strategy sends frames."""
        fuzzer.fuzz_sequential_sdo_storm()
        assert mock_bus.send.called
        assert fuzzer.fuzzed_count > 0

    def test_pdo_buffer_flood(self, fuzzer, mock_bus):
        """Test PDO buffer flood strategy."""
        fuzzer.fuzz_pdo_buffer_flood()
        assert mock_bus.send.called
        assert fuzzer.fuzzed_count > 0

    def test_large_payload_escalation(self, fuzzer, mock_bus):
        """Test payload escalation sends correct frame count."""
        fuzzer.fuzz_large_payload_escalation()
        # Should send at least 5 frames (one per size)
        assert mock_bus.send.call_count >= 5

    def test_segmented_transfer_abuse(self, fuzzer, mock_bus):
        """Test segmented transfer sends initiate + segments."""
        fuzzer.fuzz_segmented_transfer_abuse()
        assert mock_bus.send.called
        assert fuzzer.fuzzed_count > 0

    def test_concurrent_sdo_max(self, fuzzer, mock_bus):
        """Test concurrent SDO max sends correct frames."""
        fuzzer.fuzz_concurrent_sdo_max()
        # Should send at least 4 (max) + 5 (exceed) frames
        assert mock_bus.send.call_count >= 9

    def test_heartbeat_spam(self, fuzzer, mock_bus):
        """Test heartbeat spam strategy."""
        fuzzer.fuzz_heartbeat_spam()
        assert mock_bus.send.called
        assert fuzzer.fuzzed_count > 0

    def test_emcy_burst(self, fuzzer, mock_bus):
        """Test EMCY burst sends 50 frames."""
        fuzzer.fuzz_emcy_burst()
        assert mock_bus.send.call_count >= 50

    def test_sync_burst(self, fuzzer, mock_bus):
        """Test SYNC burst strategy."""
        fuzzer.fuzz_sync_burst()
        assert mock_bus.send.called
        assert fuzzer.fuzzed_count > 0

    def test_memory_leak_patterns(self, fuzzer, mock_bus):
        """Test memory leak patterns sends alloc/dealloc pairs."""
        fuzzer.fuzz_memory_leak_patterns()
        # Should send at least 50 * 2 = 100 frames
        assert mock_bus.send.call_count >= 100

    def test_stack_overflow_attempt(self, fuzzer, mock_bus):
        """Test stack overflow sends recursion pattern."""
        fuzzer.fuzz_stack_overflow_attempt()
        assert mock_bus.send.call_count >= 20

    def test_buffer_wraparound(self, fuzzer, mock_bus):
        """Test buffer wraparound sends boundary indices."""
        fuzzer.fuzz_buffer_wraparound()
        # Should send at least 4 frames (for each wraparound index)
        assert mock_bus.send.call_count >= 4

    def test_resource_recovery_test(self, fuzzer, mock_bus):
        """Test recovery sends exhaustion + recovery phases."""
        fuzzer.fuzz_resource_recovery_test()
        # Should send at least 100 (exhaust) + 10 (recovery) frames
        assert mock_bus.send.call_count >= 110


class TestResourceFuzzerExecution:
    """Test fuzzer execution."""

    def test_execute_runs_all_strategies(self, fuzzer, mock_bus):
        """Test execute runs all strategies."""
        fuzzer.execute()
        assert mock_bus.send.called
        assert fuzzer.fuzzed_count > 0

    def test_execute_collects_results(self, fuzzer, mock_bus):
        """Test execute collects results."""
        fuzzer.execute()
        assert len(fuzzer.test_results) > 0

    def test_execute_with_oracle(self, fuzzer, mock_bus, mock_oracle):
        """Test execute calls oracle with events."""
        fuzzer.execute()
        assert mock_oracle.called


class TestResourceFuzzerOracleIntegration:
    """Test oracle callback integration."""

    def test_record_result_calls_oracle(self, fuzzer, mock_oracle):
        """Test record result calls oracle callback."""
        fuzzer._record_result(
            ResourceMutationStrategy.PDO_BUFFER_FLOOD,
            0x180, b"test", "test_detail"
        )
        mock_oracle.assert_called_once()
        call_args = mock_oracle.call_args[0][0]
        assert call_args["event_type"] == "fuzz_input_sent"
        assert call_args["fuzzer"] == "resource"

    def test_record_result_contains_required_fields(self, fuzzer):
        """Test record result contains all required fields."""
        fuzzer._record_result(
            ResourceMutationStrategy.PDO_BUFFER_FLOOD,
            0x180, b"test", "detail"
        )
        result = fuzzer.test_results[0]
        assert "timestamp" in result
        assert "strategy" in result
        assert "cob_id" in result
        assert "data" in result
        assert "details" in result
        assert result["strategy"] == "pdo_buffer_flood"


class TestResourceFuzzerFrameGeneration:
    """Test CAN frame generation."""

    def test_frames_have_valid_cob_ids(self, fuzzer, mock_bus):
        """Test generated frames have valid COB-IDs."""
        fuzzer.fuzz_sequential_sdo_storm()
        
        for call in mock_bus.send.call_args_list:
            frame = call[0][0]  # Get first positional argument
            assert hasattr(frame, 'arbitration_id')
            assert 0 <= frame.arbitration_id <= 0x7FF

    def test_frames_have_valid_payload_length(self, fuzzer, mock_bus):
        """Test generated frames have valid payload length."""
        fuzzer.fuzz_pdo_buffer_flood()
        
        for call in mock_bus.send.call_args_list:
            frame = call[0][0]
            assert hasattr(frame, 'data')
            assert 0 <= len(frame.data) <= 8
