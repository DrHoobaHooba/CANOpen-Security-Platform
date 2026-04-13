"""Timing & Delay Attack fuzzing engine.

Implements comprehensive timing-based mutation strategies to detect vulnerabilities
in device handling of frames with anomalous timing, jitter, and inter-frame gaps.

Tests for:
- Zero/minimal delay bursts
- Extreme jitter and timing variations
- Inter-frame gap violations
- Synchronization timing errors
- Timeout edge cases
- Clock drift simulation
"""

import logging
import random
import time
import threading
from typing import Callable, Any, Dict, List, Optional
from enum import Enum

import can

from ..hal.bus_pcan import BusInterface
from ..od.runtime_od import RuntimeObjectDictionary
from ..utils.logging_utils import get_logger

logger = get_logger(__name__)

OracleCallback = Callable[[Dict[str, Any]], None]


class TimingMutationStrategy(Enum):
    """Timing and delay fuzzing mutation strategies."""
    ZERO_DELAY_BURST = "zero_delay_burst"                # Rapid messages with minimal gap
    EXTREME_JITTER = "extreme_jitter"                    # ±500ms timing variations
    INTERFRAME_GAP_MINIMUM = "interframe_gap_minimum"    # Minimum inter-frame spacing
    INTERFRAME_GAP_MAXIMUM = "interframe_gap_maximum"    # Maximum inter-frame gaps
    SYNC_TIMING_DRIFT = "sync_timing_drift"              # SYNC timing errors
    HEARTBEAT_TIMING_VIOLATION = "heartbeat_timing_violation"  # Wrong interval
    PHASE_SHIFT_ATTACKS = "phase_shift_attacks"          # Unexpected phase points
    TIMEOUT_EDGE_CASES = "timeout_edge_cases"            # Messages at timeout boundaries
    RAPID_PDO_BURSTS = "rapid_pdo_bursts"                # High-rate PDO floods
    DELAYED_RESPONSES = "delayed_responses"              # Late SDO responses
    CLOCK_DRIFT_SIMULATION = "clock_drift_simulation"    # Clock skew simulation
    TIMING_AMPLIFICATION = "timing_amplification"        # Exponential timing variation


class TimingFuzzer:
    """Timing & delay attack fuzzing engine.

    Tests device robustness against timing anomalies, jitter, and synchronization
    violations. Helps identify timing-dependent vulnerabilities and state machine
    bugs triggered by unusual message timing.
    """

    # CANopen protocol timing constants (ms)
    SYNC_PERIOD_DEFAULT = 100
    HEARTBEAT_PERIOD_DEFAULT = 1000
    NMT_INHIBIT_TIME_DEFAULT = 2
    GUARD_TIME_DEFAULT = 100

    def __init__(
        self,
        bus: BusInterface,
        od: Optional[RuntimeObjectDictionary] = None,
        node_id: int = 1,
        oracle: Optional[OracleCallback] = None,
    ) -> None:
        """Initialize timing fuzzer.

        Args:
            bus: CAN bus interface for sending frames
            od: Optional runtime object dictionary (for context)
            node_id: Target node ID (1-127)
            oracle: Optional callback for anomaly detection
        """
        if not isinstance(node_id, int) or not (1 <= node_id <= 127):
            raise ValueError(f"node_id must be 1-127, got {node_id}")

        self.bus = bus
        self.od = od
        self.node_id = node_id
        self.oracle = oracle
        self.fuzzed_count = 0
        self.test_results: List[Dict[str, Any]] = []

        logger.debug(
            "Timing Fuzzer initialized for node %d", node_id
        )

    def fuzz_zero_delay_burst(self) -> None:
        """Send rapid messages with minimal/zero delay between frames.

        Tests device buffer handling and processing capacity under burst conditions.
        """
        logger.info("Testing zero delay burst mutations")

        burst_size = 50
        cob_id = 0x180 + self.node_id  # Use PDO address
        
        start_time = time.time()
        
        for i in range(burst_size):
            data = bytes([i % 256, (i >> 8) % 256] + [0] * 6)
            try:
                msg = can.Message(
                    arbitration_id=cob_id,
                    data=data,
                    is_extended_id=False
                )
                self.bus.send(msg)
                self.fuzzed_count += 1

                self._record_result(
                    TimingMutationStrategy.ZERO_DELAY_BURST,
                    cob_id, data, timing_ms=0
                )
            except Exception as e:
                logger.warning("Failed to send burst frame: %s", e)

        elapsed = time.time() - start_time
        logger.debug("Burst sent %d messages in %.3f seconds", burst_size, elapsed)

    def fuzz_extreme_jitter(self) -> None:
        """Send messages with extreme timing jitter (±500ms variation).

        Tests device timing assumptions and state machine recovery from jitter.
        """
        logger.info("Testing extreme jitter mutations")

        cob_id = 0x700 + self.node_id  # Heartbeat address
        base_interval = self.HEARTBEAT_PERIOD_DEFAULT  # 1000ms default
        
        for i in range(30):
            # Generate extreme jitter: ±500ms
            jitter = random.randint(-500, 500)
            delay_ms = max(1, base_interval + jitter)
            
            data = bytes([0x05])  # Operational state
            data = data + b"\x00" * 7
            
            time.sleep(delay_ms / 1000.0)
            
            try:
                msg = can.Message(
                    arbitration_id=cob_id,
                    data=data,
                    is_extended_id=False
                )
                self.bus.send(msg)
                self.fuzzed_count += 1

                self._record_result(
                    TimingMutationStrategy.EXTREME_JITTER,
                    cob_id, data, timing_ms=delay_ms
                )
            except Exception as e:
                logger.warning("Failed to send jitter frame: %s", e)

    def fuzz_interframe_gap_minimum(self) -> None:
        """Test minimum inter-frame gaps by sending messages as fast as possible.

        Stresses device processing and message queue handling.
        """
        logger.info("Testing minimum inter-frame gap mutations")

        cob_id = 0x200 + self.node_id  # RPDO address
        
        for i in range(40):
            data = bytes([i % 256] + [0] * 7)
            
            try:
                msg = can.Message(
                    arbitration_id=cob_id,
                    data=data,
                    is_extended_id=False
                )
                self.bus.send(msg)
                self.fuzzed_count += 1

                self._record_result(
                    TimingMutationStrategy.INTERFRAME_GAP_MINIMUM,
                    cob_id, data, timing_ms=0
                )
            except Exception as e:
                logger.warning("Failed to send minimum gap frame: %s", e)

    def fuzz_interframe_gap_maximum(self) -> None:
        """Test maximum inter-frame gaps by sending messages very far apart.

        Tests device timeout handling and state recovery.
        """
        logger.info("Testing maximum inter-frame gap mutations")

        cob_id = 0x180 + self.node_id  # TPDO address
        max_gap_ms = 5000  # 5 seconds
        
        for i in range(15):
            data = bytes([i % 256] + [0] * 7)
            
            time.sleep(max_gap_ms / 1000.0)
            
            try:
                msg = can.Message(
                    arbitration_id=cob_id,
                    data=data,
                    is_extended_id=False
                )
                self.bus.send(msg)
                self.fuzzed_count += 1

                self._record_result(
                    TimingMutationStrategy.INTERFRAME_GAP_MAXIMUM,
                    cob_id, data, timing_ms=max_gap_ms
                )
            except Exception as e:
                logger.warning("Failed to send maximum gap frame: %s", e)

    def fuzz_sync_timing_drift(self) -> None:
        """Send SYNC messages at wrong intervals to test synchronization.

        Tests device SYNC counter handling and PDO transmission timing.
        """
        logger.info("Testing SYNC timing drift mutations")

        sync_cob_id = 0x080  # SYNC broadcast
        
        drift_values = [10, 50, 100, 200, 500, 1000]  # ms
        
        for drift_ms in drift_values:
            for i in range(10):
                sync_counter = i % 256
                data = bytes([sync_counter])
                data = data + b"\x00" * 7
                
                time.sleep(drift_ms / 1000.0)
                
                try:
                    msg = can.Message(
                        arbitration_id=sync_cob_id,
                        data=data,
                        is_extended_id=False
                    )
                    self.bus.send(msg)
                    self.fuzzed_count += 1

                    self._record_result(
                        TimingMutationStrategy.SYNC_TIMING_DRIFT,
                        sync_cob_id, data, timing_ms=drift_ms
                    )
                except Exception as e:
                    logger.warning("Failed to send SYNC drift frame: %s", e)

    def fuzz_heartbeat_timing_violation(self) -> None:
        """Send heartbeat messages at wrong intervals.

        Tests device heartbeat producer/consumer validation and guard time handling.
        """
        logger.info("Testing heartbeat timing violation mutations")

        hb_cob_id = 0x700 + self.node_id  # Heartbeat
        
        # Test various non-standard intervals
        intervals_ms = [100, 333, 777, 1500, 3000, 5000]
        
        for interval_ms in intervals_ms:
            for state in [0x04, 0x05, 0x7F]:  # STOP, OPERATIONAL, PRE-OP
                data = bytes([state])
                data = data + b"\x00" * 7
                
                time.sleep(interval_ms / 1000.0)
                
                try:
                    msg = can.Message(
                        arbitration_id=hb_cob_id,
                        data=data,
                        is_extended_id=False
                    )
                    self.bus.send(msg)
                    self.fuzzed_count += 1

                    self._record_result(
                        TimingMutationStrategy.HEARTBEAT_TIMING_VIOLATION,
                        hb_cob_id, data, timing_ms=interval_ms
                    )
                except Exception as e:
                    logger.warning("Failed to send heartbeat violation: %s", e)

    def fuzz_phase_shift_attacks(self) -> None:
        """Send messages at unexpected phase points in device cycle.

        Tests if device behavior is vulnerable to messages arriving at specific
        cycle phases or state machine positions.
        """
        logger.info("Testing phase shift attack mutations")

        cob_id = 0x200 + self.node_id
        cycle_time = 100  # 100ms cycle
        
        for phase_offset_percent in range(0, 100, 10):
            phase_delay_ms = (cycle_time * phase_offset_percent) / 100.0
            
            for i in range(20):
                data = bytes([i % 256] + [0] * 7)
                
                time.sleep(phase_delay_ms / 1000.0)
                
                try:
                    msg = can.Message(
                        arbitration_id=cob_id,
                        data=data,
                        is_extended_id=False
                    )
                    self.bus.send(msg)
                    self.fuzzed_count += 1

                    self._record_result(
                        TimingMutationStrategy.PHASE_SHIFT_ATTACKS,
                        cob_id, data, timing_ms=phase_delay_ms
                    )
                except Exception as e:
                    logger.warning("Failed to send phase shift frame: %s", e)

    def fuzz_timeout_edge_cases(self) -> None:
        """Send messages just before and after expected timeout windows.

        Tests device timeout detection and edge case handling.
        """
        logger.info("Testing timeout edge case mutations")

        cob_id = 0x700 + self.node_id
        timeout_ms = 1000  # 1 second timeout
        
        # Test just before timeout
        for i in range(10):
            delay_ms = timeout_ms - random.randint(1, 100)
            time.sleep(delay_ms / 1000.0)
            
            data = bytes([0x05] + [0] * 7)
            
            try:
                msg = can.Message(
                    arbitration_id=cob_id,
                    data=data,
                    is_extended_id=False
                )
                self.bus.send(msg)
                self.fuzzed_count += 1

                self._record_result(
                    TimingMutationStrategy.TIMEOUT_EDGE_CASES,
                    cob_id, data, timing_ms=delay_ms
                )
            except Exception as e:
                logger.warning("Failed to send timeout edge frame: %s", e)

    def fuzz_rapid_pdo_bursts(self) -> None:
        """Send rapid PDO burst sequences (50+ messages in <100ms).

        Tests PDO handling under extreme bandwidth utilization.
        """
        logger.info("Testing rapid PDO burst mutations")

        cob_id = 0x200 + self.node_id
        burst_count = 50
        
        start_time = time.time()
        
        for i in range(burst_count):
            data = bytes([i % 256, (i >> 8) % 256] + [0] * 6)
            
            try:
                msg = can.Message(
                    arbitration_id=cob_id,
                    data=data,
                    is_extended_id=False
                )
                self.bus.send(msg)
                self.fuzzed_count += 1

                self._record_result(
                    TimingMutationStrategy.RAPID_PDO_BURSTS,
                    cob_id, data, timing_ms=0
                )
            except Exception as e:
                logger.warning("Failed to send PDO burst frame: %s", e)

        elapsed = time.time() - start_time
        logger.debug("PDO burst: %d messages in %.3f seconds", burst_count, elapsed)

    def fuzz_delayed_responses(self) -> None:
        """Simulate intentionally delayed SDO responses.

        Tests device behavior when responses arrive with unusual delays.
        """
        logger.info("Testing delayed response mutations")

        sdo_tx_cob = 0x580 + self.node_id
        
        delay_ms_values = [100, 500, 1000, 2000, 5000]
        
        for delay_ms in delay_ms_values:
            for i in range(8):
                data = bytes([0x40 | i] + [0] * 7)  # Abort-like response
                
                time.sleep(delay_ms / 1000.0)
                
                try:
                    msg = can.Message(
                        arbitration_id=sdo_tx_cob,
                        data=data,
                        is_extended_id=False
                    )
                    self.bus.send(msg)
                    self.fuzzed_count += 1

                    self._record_result(
                        TimingMutationStrategy.DELAYED_RESPONSES,
                        sdo_tx_cob, data, timing_ms=delay_ms
                    )
                except Exception as e:
                    logger.warning("Failed to send delayed response: %s", e)

    def fuzz_clock_drift_simulation(self) -> None:
        """Simulate clock drift across devices with varying clock speeds.

        Tests device synchronization when device clocks diverge.
        """
        logger.info("Testing clock drift simulation mutations")

        cob_id = 0x080  # SYNC
        base_period = 100  # 100ms
        
        # Simulate clock drifts: +/-10%, +/-5%
        drift_factors = [0.90, 0.95, 1.00, 1.05, 1.10]
        
        for drift_factor in drift_factors:
            for i in range(20):
                adjusted_period = base_period * drift_factor
                
                time.sleep(adjusted_period / 1000.0)
                
                data = bytes([i % 256] + [0] * 7)
                
                try:
                    msg = can.Message(
                        arbitration_id=cob_id,
                        data=data,
                        is_extended_id=False
                    )
                    self.bus.send(msg)
                    self.fuzzed_count += 1

                    self._record_result(
                        TimingMutationStrategy.CLOCK_DRIFT_SIMULATION,
                        cob_id, data, timing_ms=int(adjusted_period)
                    )
                except Exception as e:
                    logger.warning("Failed to send clock drift frame: %s", e)

    def fuzz_timing_amplification(self) -> None:
        """Send messages with exponentially amplifying timing variations.

        Tests device state machine stability under accelerating timing changes.
        """
        logger.info("Testing timing amplification mutations")

        cob_id = 0x700 + self.node_id
        base_delay_ms = 50
        
        for iteration in range(15):
            # Double delay each iteration
            delay_ms = int(base_delay_ms * (2 ** iteration))
            delay_ms = min(delay_ms, 5000)  # Cap at 5 seconds
            
            data = bytes([iteration % 256] + [0] * 7)
            
            time.sleep(delay_ms / 1000.0)
            
            try:
                msg = can.Message(
                    arbitration_id=cob_id,
                    data=data,
                    is_extended_id=False
                )
                self.bus.send(msg)
                self.fuzzed_count += 1

                self._record_result(
                    TimingMutationStrategy.TIMING_AMPLIFICATION,
                    cob_id, data, timing_ms=delay_ms
                )
            except Exception as e:
                logger.warning("Failed to send timing amplification frame: %s", e)

    def execute(self) -> None:
        """Execute full timing fuzzing suite.

        Runs all configured timing-based mutation strategies.
        """
        logger.info("Executing timing fuzzer for node %d", self.node_id)
        start_time = time.time()

        try:
            self.fuzz_zero_delay_burst()
            self.fuzz_extreme_jitter()
            self.fuzz_interframe_gap_minimum()
            self.fuzz_interframe_gap_maximum()
            self.fuzz_sync_timing_drift()
            self.fuzz_heartbeat_timing_violation()
            self.fuzz_phase_shift_attacks()
            self.fuzz_timeout_edge_cases()
            self.fuzz_rapid_pdo_bursts()
            self.fuzz_delayed_responses()
            self.fuzz_clock_drift_simulation()
            self.fuzz_timing_amplification()

        except Exception as e:
            logger.error("Timing fuzzing error: %s", e)

        elapsed = time.time() - start_time
        logger.info(
            "Timing fuzzing complete: %d mutations sent in %.1f seconds",
            self.fuzzed_count, elapsed
        )

    def _record_result(
        self,
        strategy: TimingMutationStrategy,
        cob_id: int,
        data: bytes,
        timing_ms: int,
    ) -> None:
        """Record fuzzing result for analysis.

        Args:
            strategy: Mutation strategy used
            cob_id: CAN Object ID
            data: Frame payload
            timing_ms: Timing parameter used (ms)
        """
        result = {
            "timestamp": time.time(),
            "strategy": strategy.value,
            "cob_id": cob_id,
            "data": data.hex(),
            "timing_ms": timing_ms,
        }
        self.test_results.append(result)

        # Notify oracle if callback provided
        if self.oracle:
            self.oracle({
                "event_type": "fuzz_input_sent",
                "fuzzer": "timing",
                "strategy": strategy.value,
                "timing_ms": timing_ms,
            })
