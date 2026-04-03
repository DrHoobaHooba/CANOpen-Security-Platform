"""CANopen SYNC (Synchronization) fuzzing engine.

Tests SYNC message handling for timing attacks, counter overflow,
missing synchronization, and burst flooding vulnerabilities.
"""

import logging
import random
import time
from typing import Callable, Any, Dict, List

import can

from ..hal.bus_pcan import BusInterface
from ..od.runtime_od import RuntimeObjectDictionary
from ..utils.logging_utils import get_logger

logger = get_logger(__name__)

OracleCallback = Callable[[Dict[str, Any]], None]


class SYNCFuzzer:
    """SYNC protocol fuzzing for synchronization robustness testing.

    Tests SYNC implementation for timing vulnerabilities, counter
    overflow, burst handling, and state machine confusion.
    """

    # SYNC COB-ID (broadcast)
    SYNC_COB_ID = 0x080

    def __init__(
        self,
        bus: BusInterface,
        od: RuntimeObjectDictionary,
        oracle: OracleCallback,
    ) -> None:
        """Initialize SYNC fuzzer.

        Args:
            bus: CAN bus interface
            od: Runtime object dictionary
            oracle: Callback for anomaly detection

        Note:
            SYNC is typically broadcast (no node_id specific COB-ID),
            so this fuzzer does not require a target node_id.
        """
        self.bus = bus
        self.od = od
        self.oracle = oracle
        self.sync_cob_id = self.SYNC_COB_ID
        self.fuzzed_count = 0
        self.test_results: List[Dict[str, Any]] = []

        logger.debug("SYNC Fuzzer initialized (COB-ID=0x%03X)", self.sync_cob_id)

    def counter_overflow_fuzzing(self) -> None:
        """Test SYNC counter overflow (0xFF -> 0x00).

        Tests device handling of counter wraparound and potential
        PDO timing issues during counter transitions.
        """
        logger.info("Testing SYNC counter overflow sequences")

        # Test sequences around counter boundaries
        test_sequences = [
            list(range(252, 258)),  # 252-257 (crossing 255)
            [253, 254, 255, 0, 1, 2],  # Explicit wraparound
            [254, 254, 254],  # Duplicate counters
            [255, 255, 255],  # Stuck at max
            [0, 0, 0],  # Stuck at zero
        ]

        for sequence in test_sequences:
            for counter in sequence:
                self._send_sync(counter, strategy="counter_overflow")
                time.sleep(0.05)

        self.fuzzed_count += sum(len(s) for s in test_sequences)

    def missing_sync_frames(self) -> None:
        """Test missing or delayed SYNC frames.

        Sends SYNC messages with gaps that violate expected
        SYNC period, testing device recovery.
        """
        logger.info("Testing SYNC missing frame scenarios")

        # Normal sequence: send every 10ms
        logger.info("Sending normal SYNC at 10ms intervals")
        for i in range(5):
            self._send_sync(i, strategy="normal_sequence")
            time.sleep(0.01)

        # Missing frame: skip one
        logger.info("Injecting missing SYNC frame")
        for i in range(5, 8):
            self._send_sync(i, strategy="missing_frame")
            if i < 7:
                time.sleep(0.01)
            else:
                time.sleep(0.03)  # 30ms gap instead of 10ms

        # Recovery sequence
        logger.info("Recovering with normal sequence")
        for i in range(8, 12):
            self._send_sync(i, strategy="recovery")
            time.sleep(0.01)

        self.fuzzed_count += 17

    def burst_flooding(self) -> None:
        """Send SYNC messages at extremely high rates.

        Tests device buffer and processing capacity during
        synchronization message floods.
        """
        logger.info("Testing SYNC burst flooding (50 messages in 50ms)")

        counter = 0
        for i in range(50):
            self._send_sync(counter % 256, strategy="burst_flood")
            counter += 1
            time.sleep(0.001)  # 1ms between frames

        self.fuzzed_count += 50

    def jittered_timing(self) -> None:
        """Send SYNC with variable timing intervals (jitter).

        Tests device handling of non-uniform SYNC periods,
        checking for timing-based vulnerabilities.
        """
        logger.info("Testing SYNC with timing jitter")

        # Expected SYNC period is typically 10ms, test with variations
        base_interval = 0.01  # 10ms
        jitter_amounts = [0.001, 0.005, 0.010, 0.015, 0.020]

        counter = 0
        for i in range(20):
            jitter = random.choice(jitter_amounts)
            interval = base_interval + (random.uniform(-jitter, jitter))

            self._send_sync(counter, strategy="jitter_timing")
            counter += 1
            time.sleep(max(0.001, interval))  # Minimum 1ms

        self.fuzzed_count += 20

    def out_of_order_recovery(self) -> None:
        """Send SYNC counters in random order.

        Tests device robustness to out-of-sequence synchronization,
        which could occur on corrupted networks.
        """
        logger.info("Testing SYNC out-of-order counter sequences")

        # Random sequence
        sequence = list(range(20))
        random.shuffle(sequence)

        for counter in sequence:
            self._send_sync(counter, strategy="out_of_order")
            time.sleep(0.02)

        self.fuzzed_count += len(sequence)

    def duplicate_counter_handling(self) -> None:
        """Send duplicate SYNC counter values.

        Tests device handling of repeated counter values
        which could indicate lost or duplicate frames.
        """
        logger.info("Testing SYNC duplicate counter handling")

        duplication_patterns = [
            [1, 1, 2],           # Simple duplicate
            [3, 3, 3, 4],        # Triple duplicate
            [5, 6, 6, 7],        # Mid-sequence duplicate
            [10] * 10,           # Stuck counter (10x repeat)
            [20, 20, 20, 21, 21, 21],  # Multi-duplicate stress
        ]

        for pattern in duplication_patterns:
            for counter in pattern:
                self._send_sync(counter, strategy="duplicate_counter")
                time.sleep(0.01)

        self.fuzzed_count += sum(len(p) for p in duplication_patterns)

    def backward_counter_transitions(self) -> None:
        """Send SYNC counters that go backward (incorrect sequence).

        Tests device state machine for proper handling of
        counter reversals that violate monotonic increment.
        """
        logger.info("Testing SYNC backward counter transitions")

        sequences = [
            [10, 9, 8],           # Simple backward
            [5, 6, 5, 6],         # Alternating
            [20, 19, 18, 17],     # Long backward
            [100, 50, 0],         # Large jumps backward
            [255, 0, 255, 0],     # Wraparound abuse
        ]

        for sequence in sequences:
            for counter in sequence:
                self._send_sync(counter, strategy="backward_counter")
                time.sleep(0.02)

        self.fuzzed_count += sum(len(s) for s in sequences)

    def sync_with_payload_corruption(self) -> None:
        """Send SYNC frames with corrupted or unexpected payload data.

        Standard SYNC can be 0 or 1 byte (counter).
        Tests device handling of oversized or invalid payloads.
        """
        logger.info("Testing SYNC payload corruption")

        payloads = [
            bytes(),              # Empty (valid but unusual)
            bytes([42]),          # Single byte counter
            bytes([0xFF, 0x00]),  # Two bytes
            bytes([1, 2, 3, 4, 5, 6, 7, 8]),  # Full CAN frame
            bytes([0xDE, 0xAD, 0xBE, 0xEF]),  # Nonsense data
        ]

        for payload in payloads:
            self._send_sync_raw(payload, strategy="payload_corruption")
            time.sleep(0.05)

        self.fuzzed_count += len(payloads)

    def long_sync_absence(self) -> None:
        """Simulate prolonged absence of SYNC messages.

        Tests device behavior when SYNC is missing for extended period,
        checking for watchdog triggers, timeouts, etc.
        """
        logger.info("Testing long SYNC absence (sending 3 frames then 500ms gap)")

        # Send initial sequence
        for i in range(3):
            self._send_sync(i, strategy="long_absence_start")
            time.sleep(0.01)

        logger.info("SYNC pause for 500ms...")
        time.sleep(0.5)

        # Send recovery sequence
        for i in range(3, 6):
            self._send_sync(i, strategy="long_absence_recovery")
            time.sleep(0.01)

        self.fuzzed_count += 6

    def run_all_strategies(self, iterations: int = 1) -> List[Dict[str, Any]]:
        """Execute all SYNC fuzzing strategies.

        Args:
            iterations: Number of times to repeat each strategy

        Returns:
            List of test results
        """
        logger.info("Running all SYNC fuzzing strategies (%d iteration(s))", iterations)

        strategies = [
            self.counter_overflow_fuzzing,
            self.missing_sync_frames,
            self.burst_flooding,
            self.jittered_timing,
            self.out_of_order_recovery,
            self.duplicate_counter_handling,
            self.backward_counter_transitions,
            self.sync_with_payload_corruption,
            self.long_sync_absence,
        ]

        for iteration in range(iterations):
            logger.info("SYNC fuzzing iteration %d/%d", iteration + 1, iterations)
            for strategy in strategies:
                try:
                    strategy()
                except Exception as e:
                    error_msg = f"SYNC fuzzing strategy {strategy.__name__} failed: {e}"
                    logger.error(error_msg)
                    self.test_results.append({
                        "strategy": strategy.__name__,
                        "status": "error",
                        "error": str(e),
                        "timestamp": time.time(),
                    })

        logger.info("SYNC fuzzing complete: %d messages fuzzed", self.fuzzed_count)
        return self.test_results

    # --- Private helpers ---

    def _send_sync(self, counter: int, strategy: str) -> None:
        """Send a standard SYNC message with counter.

        Args:
            counter: Counter byte (0-255)
            strategy: Name of fuzzing strategy
        """
        try:
            # SYNC frame: single byte counter (optional)
            msg = can.Message(
                arbitration_id=self.sync_cob_id,
                data=bytes([counter & 0xFF]),
                is_extended_id=False,
            )

            self.bus.send(msg)

            result = {
                "strategy": strategy,
                "counter": counter,
                "timestamp": time.time(),
                "status": "sent",
            }

            self.test_results.append(result)
            self.oracle(result)

        except Exception as e:
            logger.warning("Failed to send SYNC: %s", e)

    def _send_sync_raw(self, payload: bytes, strategy: str) -> None:
        """Send a SYNC message with custom payload.

        Args:
            payload: Custom message payload
            strategy: Name of fuzzing strategy
        """
        try:
            msg = can.Message(
                arbitration_id=self.sync_cob_id,
                data=payload,
                is_extended_id=False,
            )

            self.bus.send(msg)

            result = {
                "strategy": strategy,
                "payload": payload.hex(),
                "timestamp": time.time(),
                "status": "sent",
            }

            self.test_results.append(result)
            self.oracle(result)

        except Exception as e:
            logger.warning("Failed to send SYNC with custom payload: %s", e)
