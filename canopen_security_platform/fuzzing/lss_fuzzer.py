"""CANopen LSS (Link Layer Setting) fuzzing engine.

Tests LSS protocol implementation for state confusion vulnerabilities,
timing attacks, and improper bit timing constraints.
"""

import logging
import random
import time
from typing import Callable, Any, Dict, List
from enum import Enum

import can

from ..hal.bus_pcan import BusInterface
from ..od.runtime_od import RuntimeObjectDictionary
from ..utils.logging_utils import get_logger

logger = get_logger(__name__)

OracleCallback = Callable[[Dict[str, Any]], None]


class LSSTxCommand(Enum):
    """LSS transmitter commands (DS305)."""
    ENTER_CONFIG = 0x10
    EXIT_CONFIG = 0x11
    SELECT_VERIFY = 0x40
    SELECT_BITRATE = 0x15
    ACTIVATE_BITRATE = 0x16
    STORE_CONFIG = 0x17
    RESET = 0x05


class LSSFuzzer:
    """LSS protocol fuzzing with state confusion and timing attacks.

    Tests LSS state machine for improper state transitions, timing
    vulnerabilities, and bit selection logic errors.
    """

    # LSS COB-IDs
    LSS_MASTER_TX = 0x7E4
    LSS_SLAVE_RX = 0x7E5

    def __init__(
        self,
        bus: BusInterface,
        od: RuntimeObjectDictionary,
        node_id: int,
        oracle: OracleCallback,
    ) -> None:
        """Initialize LSS fuzzer.

        Args:
            bus: CAN bus interface
            od: Runtime object dictionary
            node_id: Target node ID (0 for network-wide LSS context)
            oracle: Callback for anomaly detection
        """
        if not isinstance(node_id, int) or not (0 <= node_id <= 127):
            raise ValueError(f"node_id must be 0-127, got {node_id}")

        self.bus = bus
        self.od = od
        self.node_id = node_id
        self.oracle = oracle
        self.test_results: List[Dict[str, Any]] = []
        self.fuzzed_count = 0

        logger.debug(
            "LSS Fuzzer initialized for node %d (TX=0x%03X, RX=0x%03X)",
            node_id, self.LSS_MASTER_TX, self.LSS_SLAVE_RX
        )

    def state_confusion(self) -> None:
        """Test LSS state machine for confusion vulnerabilities.

        Attempts invalid state transitions and command sequences that
        violate LSS protocol ordering requirements.
        """
        logger.info("Testing LSS state confusion mutations")

        # Try commands in invalid sequences to confuse state machine
        invalid_sequences = [
            # Exit config without enter
            [LSSTxCommand.EXIT_CONFIG],
            # Select bitrate without entering config
            [LSSTxCommand.SELECT_BITRATE],
            # Store config without entering
            [LSSTxCommand.STORE_CONFIG],
            # Reset during config
            [LSSTxCommand.ENTER_CONFIG, LSSTxCommand.RESET],
            # Multiple enters
            [LSSTxCommand.ENTER_CONFIG, LSSTxCommand.ENTER_CONFIG],
            # Bitrate select with invalid parameters
            [LSSTxCommand.SELECT_BITRATE, LSSTxCommand.ACTIVATE_BITRATE],
        ]

        for sequence in invalid_sequences:
            logger.debug("Testing invalid LSS sequence: %s", [c.name for c in sequence])

            for command in sequence:
                self._send_lss_command(command)
                time.sleep(0.01)  # Small delay between commands

    def bit_timing(self) -> None:
        """Test bit timing parameter fuzzing.

        Sends invalid or extreme bit timing values to test
        robustness against timing-related attacks.
        """
        logger.info("Testing LSS bit timing mutations")

        # Invalid bitrate values
        invalid_bitrates = [
            0x00000000,  # Zero (invalid)
            0xFFFFFFFF,  # Max value
            0x00000001,  # Minimum (1 bps)
            0x7FFFFFFF,  # Signed max
            0x80000000,  # Signed min
        ]

        for bitrate in invalid_bitrates:
            logger.debug("Sending bit timing mutation: 0x%08X", bitrate)

            data = bytearray(8)
            data[0] = 0x15  # Select_BitTiming command
            data[1] = 0
            data[2] = 0
            data[3] = 0
            # Bitrate in bytes 4-7 (little-endian)
            data[4] = bitrate & 0xFF
            data[5] = (bitrate >> 8) & 0xFF
            data[6] = (bitrate >> 16) & 0xFF
            data[7] = (bitrate >> 24) & 0xFF

            self._send_lss_frame(data, strategy="bit_timing")

    def device_identification_fuzzing(self) -> None:
        """Fuzz device identification during selective mode.

        Sends truncated, repeated, or corrupted vendor ID queries
        to test binary search bit-by-bit selection logic.
        """
        logger.info("Testing LSS device identification mutations")

        # Enter LSS selective mode
        self._send_lss_command(LSSTxCommand.ENTER_CONFIG)
        time.sleep(0.05)

        # Fuzz vendor ID selection (identify with masks)
        for attempt in range(10):
            # Query command with various mask patterns
            mask_patterns = [
                0x00000000,  # All zeros
                0xFFFFFFFF,  # All ones
                0x55555555,  # Alternating
                0xAAAAAAAA,  # Alternating inverted
                0xF0F0F0F0,  # Nibble pattern
            ]

            for mask in mask_patterns:
                data = bytearray(8)
                data[0] = 0x40  # Identify object (verify)
                data[1] = 0xFF  # Wildcard
                # Vendor ID (little-endian)
                data[2] = mask & 0xFF
                data[3] = (mask >> 8) & 0xFF
                data[4] = (mask >> 16) & 0xFF
                data[5] = (mask >> 24) & 0xFF
                data[6] = (attempt & 0x1F) << 3  # Bit selection
                data[7] = 0

                self._send_lss_frame(data, strategy="identification")
                time.sleep(0.005)

        # Exit selective mode
        self._send_lss_command(LSSTxCommand.EXIT_CONFIG)

    def rapid_command_sequence(self) -> None:
        """Stress test with rapid command sequences.

        Sends multiple commands without proper delays to test
        asynchronous handling and potential race conditions.
        """
        logger.info("Testing LSS rapid command sequences")

        # Send burst of commands with minimal delays
        for i in range(20):
            cmd = random.choice(list(LSSTxCommand))
            self._send_lss_command(cmd)
            time.sleep(0.001)  # 1ms delay

    def timing_attack(self) -> None:
        """Test timing-based vulnerabilities.

        Measures response times and attempts to infer state
        through timing side channels.
        """
        logger.info("Testing LSS timing attacks")

        timing_results = []

        for test_num in range(5):
            # Send command and measure response time
            start = time.time()

            # Enter config mode
            self._send_lss_command(LSSTxCommand.ENTER_CONFIG)

            # Wait for potential response
            try:
                msg = self.bus.recv(timeout=0.1)
                response_time = time.time() - start

                timing_results.append({
                    "test": test_num,
                    "response_time_ms": response_time * 1000,
                    "responded": msg is not None,
                })

                if msg:
                    logger.debug(
                        "Got LSS response (timing=%0.1f ms): %s",
                        response_time * 1000, msg.data.hex()
                    )

            except Exception as e:
                logger.debug("Timing test error: %s", e)

            # Exit config
            self._send_lss_command(LSSTxCommand.EXIT_CONFIG)
            time.sleep(0.05)

        # Log timing analysis
        if timing_results:
            times = [r["response_time_ms"] for r in timing_results]
            logger.info(
                "LSS timing analysis: min=%.1f ms, max=%.1f ms, avg=%.1f ms",
                min(times), max(times), sum(times) / len(times)
            )

    def execute(self) -> None:
        """Execute full LSS fuzzing suite.

        Runs all LSS fuzzing strategies in sequence.
        """
        logger.info("Executing LSS fuzzer for node %d", self.node_id)
        start_time = time.time()

        try:
            self.state_confusion()
            time.sleep(0.1)

            self.bit_timing()
            time.sleep(0.1)

            self.device_identification_fuzzing()
            time.sleep(0.1)

            self.rapid_command_sequence()
            time.sleep(0.1)

            self.timing_attack()

        except Exception as e:
            logger.error("LSS fuzzing error: %s", e)

        elapsed = time.time() - start_time
        logger.info(
            "LSS fuzzing complete: %d mutations sent in %.1f seconds",
            self.fuzzed_count, elapsed
        )

    def _send_lss_command(self, command: LSSTxCommand) -> None:
        """Send an LSS command.

        Args:
            command: LSSTxCommand to send
        """
        data = bytearray(8)
        data[0] = command.value
        data[1:8] = b"\x00" * 7

        self._send_lss_frame(data, strategy="command")

    def _send_lss_frame(self, data: bytearray, strategy: str) -> None:
        """Send an LSS frame.

        Args:
            data: 8-byte LSS payload
            strategy: Fuzzing strategy name
        """
        if len(data) != 8:
            data = data[:8] + bytearray(8 - len(data))

        try:
            msg = can.Message(
                arbitration_id=self.LSS_MASTER_TX,
                data=bytes(data),
                is_extended_id=False
            )
            self.bus.send(msg)
            self.fuzzed_count += 1

            result = {
                "timestamp": time.time(),
                "strategy": strategy,
                "data": data.hex(),
                "cob_id": self.LSS_MASTER_TX,
            }
            self.test_results.append(result)

            logger.debug("Sent LSS frame (strategy=%s, data=%s)", strategy, data.hex())

        except Exception as e:
            logger.warning("Failed to send LSS frame: %s", e)

    def get_results(self) -> Dict[str, Any]:
        """Get fuzzing results and statistics.

        Returns:
            Dictionary with fuzzing statistics
        """
        return {
            "node_id": self.node_id,
            "total_mutations": self.fuzzed_count,
            "strategies_used": len(set(r["strategy"] for r in self.test_results)),
            "results": self.test_results,
        }
