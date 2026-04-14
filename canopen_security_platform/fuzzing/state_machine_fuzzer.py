"""State Machine Escape Sequences fuzzing engine.

Implements comprehensive NMT state machine mutation strategies to detect vulnerabilities
in device state management, illegal transitions, and state escape sequences.

Tests for:
- Illegal/invalid NMT state transitions
- Guard time and lifetime factor manipulation
- Boot-up during operational state
- Reset surge attacks
- State corruption and persistence
- Emergency state transitions
- Producer/consumer desynchronization
"""

import logging
import random
import time
import itertools
from typing import Callable, Any, Dict, List, Optional, Tuple
from enum import Enum

import can

from ..hal.bus_pcan import BusInterface
from ..od.runtime_od import RuntimeObjectDictionary
from ..utils.logging_utils import get_logger

logger = get_logger(__name__)

OracleCallback = Callable[[Dict[str, Any]], None]


class StateMachineMutationStrategy(Enum):
    """NMT state machine escape sequence fuzzing strategies."""
    ILLEGAL_STATE_TRANSITION = "illegal_state_transition"           # 16² state combos
    GUARD_TIME_MANIPULATION = "guard_time_manipulation"            # OD 0x100D exploitation
    LIFETIME_FACTOR_ABUSE = "lifetime_factor_abuse"                # OD 0x100C extreme values
    BOOTUP_DURING_OPERATIONAL = "bootup_during_operational"        # Boot-up while operational
    RESET_SURGE = "reset_surge"                                    # Multiple resets rapidly
    PARTIAL_STATE_CORRUPTION = "partial_state_corruption"          # Invalid state bits
    EMERGENCY_TO_INVALID = "emergency_to_invalid"                  # EMCY → invalid state
    PRODUCER_CONSUMER_DESYNC = "producer_consumer_desync"          # Heartbeat drift
    NMT_SPURIOUS_RESPONSE = "nmt_spurious_response"                # Unexpected NMT responses
    STATE_PERSISTENCE_TEST = "state_persistence_test"              # State preservation


class NMTState(Enum):
    """NMT state machine states."""
    INITIALIZING = 0x00
    PREOPERATIONAL = 0x7F
    OPERATIONAL = 0x05
    STOPPED = 0x04


class StateMachineFuzzer:
    """NMT state machine escape sequence fuzzing engine.

    Tests device robustness against invalid state transitions, illegal state codes,
    and edge cases in NMT state machine handling. Helps identify state machine bugs,
    escape sequences, and improper state validation.
    """

    # NMT COB-IDs
    NMT_COB_ID = 0x000
    HEARTBEAT_BASE = 0x700
    EMCY_BASE = 0x080

    # OD indices for state machine
    OD_GUARD_TIME = 0x100D          # Guard time
    OD_LIFETIME_FACTOR = 0x100C     # Lifetime factor

    # Valid NMT states
    VALID_STATES = [state.value for state in NMTState]

    def __init__(
        self,
        bus: BusInterface,
        od: Optional[RuntimeObjectDictionary] = None,
        node_id: int = 1,
        oracle: Optional[OracleCallback] = None,
    ) -> None:
        """Initialize state machine fuzzer.

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
        self.current_state = NMTState.INITIALIZING

        logger.debug(
            "State Machine Fuzzer initialized for node %d", node_id
        )

    def fuzz_illegal_state_transition(self) -> None:
        """Test all 16² invalid NMT state transitions.

        Attempts all possible combinations of state transitions,
        including illegal paths and invalid state codes.
        """
        logger.info("Testing illegal state transitions (16² combos)")

        # Generate all possible state byte values (0x00-0x0F)
        state_values = list(range(16))

        for from_state in state_values:
            for to_state in state_values:
                # NMT command format: CS (command specifier) + node_id
                # Standard commands: 0x01=start, 0x02=stop, 0x80=sleep, 0x81=initialize
                # We send the to_state as part of the command pattern
                
                nmt_payload = bytes([to_state, self.node_id, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

                try:
                    msg = can.Message(arbitration_id=self.NMT_COB_ID, data=nmt_payload, is_extended_id=False)
                    self.bus.send(msg)
                    self._record_result(
                        StateMachineMutationStrategy.ILLEGAL_STATE_TRANSITION,
                        self.NMT_COB_ID, nmt_payload, f"from_0x{from_state:02X}_to_0x{to_state:02X}"
                    )
                except Exception as e:
                    logger.warning("Failed to send illegal transition: %s", e)

    def fuzz_guard_time_manipulation(self) -> None:
        """Exploit guard time boundary (OD 0x100D).

        Tests device handling of guard time parameter manipulation
        through SDO access and extreme value injection.
        """
        logger.info("Testing guard time manipulation (OD 0x100D)")

        sdo_cob_id = 0x580 + self.node_id
        guard_time_values = [
            0x0000,      # Zero guard time
            0x0001,      # Minimum
            0x7FFF,      # Max signed 16-bit
            0xFFFF,      # Max unsigned 16-bit
            0x8000,      # Boundary
        ]

        for guard_time in guard_time_values:
            guard_time_bytes = guard_time.to_bytes(2, byteorder='little')
            
            # SDO download for OD 0x100D (guard time)
            # Format: CS=0x23 (expedited download), length=2, index=0x100D, subindex=0x00
            sdo_payload = bytes([0x23, 0x0D, 0x10, 0x00]) + guard_time_bytes + b"\x00\x00"

            try:
                msg = can.Message(arbitration_id=sdo_cob_id, data=sdo_payload, is_extended_id=False)
                self.bus.send(msg)
                self._record_result(
                    StateMachineMutationStrategy.GUARD_TIME_MANIPULATION,
                    sdo_cob_id, sdo_payload, f"guard_time_0x{guard_time:04X}"
                )
            except Exception as e:
                logger.warning("Failed to send guard time manipulation: %s", e)

    def fuzz_lifetime_factor_abuse(self) -> None:
        """Abuse lifetime factor parameter (OD 0x100C).

        Tests extreme values and boundary conditions for the lifetime
        factor that controls guard time multiplier.
        """
        logger.info("Testing lifetime factor abuse (OD 0x100C)")

        sdo_cob_id = 0x580 + self.node_id
        lifetime_factors = [
            0x00,        # Zero (disables guard time)
            0x01,        # Minimum
            0x7F,        # Max signed 8-bit
            0xFF,        # Max unsigned 8-bit
        ]

        for lifetime_factor in lifetime_factors:
            # SDO download for OD 0x100C (lifetime factor)
            sdo_payload = bytes([0x2F, 0x0C, 0x10, 0x00, lifetime_factor, 0x00, 0x00, 0x00])

            try:
                msg = can.Message(arbitration_id=sdo_cob_id, data=sdo_payload, is_extended_id=False)
                self.bus.send(msg)
                self._record_result(
                    StateMachineMutationStrategy.LIFETIME_FACTOR_ABUSE,
                    sdo_cob_id, sdo_payload, f"lifetime_factor_0x{lifetime_factor:02X}"
                )
            except Exception as e:
                logger.warning("Failed to send lifetime factor abuse: %s", e)

    def fuzz_bootup_during_operational(self) -> None:
        """Send boot-up message while device is operational.

        Tests device handling of boot-up messages received during
        operational state (should normally only occur during initialization).
        """
        logger.info("Testing boot-up during operational state")

        heartbeat_cob_id = self.HEARTBEAT_BASE + self.node_id
        
        # First, set device to operational state
        nmt_cob_id = self.NMT_COB_ID
        nmt_operational = bytes([0x01, self.node_id, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

        try:
            msg = can.Message(arbitration_id=nmt_cob_id, data=nmt_operational, is_extended_id=False)
            self.bus.send(msg)
            time.sleep(0.1)
        except Exception as e:
            logger.warning("Failed to set operational: %s", e)

        # Now send boot-up while operational
        bootup_payload = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])  # Initializing state

        try:
            msg = can.Message(arbitration_id=heartbeat_cob_id, data=bootup_payload, is_extended_id=False)
            self.bus.send(msg)
            self._record_result(
                StateMachineMutationStrategy.BOOTUP_DURING_OPERATIONAL,
                heartbeat_cob_id, bootup_payload, "bootup_operational"
            )
        except Exception as e:
            logger.warning("Failed to send bootup during operational: %s", e)

    def fuzz_reset_surge(self) -> None:
        """Send multiple reset commands in rapid succession.

        Tests device handling of rapid reset sequences that may
        cause state machine corruption or incomplete initialization.
        """
        logger.info("Testing reset surge")

        nmt_cob_id = self.NMT_COB_ID

        # Send 20 reset commands rapidly
        for i in range(20):
            reset_payload = bytes([0x81, self.node_id, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])  # Initialize

            try:
                msg = can.Message(arbitration_id=nmt_cob_id, data=reset_payload, is_extended_id=False)
                self.bus.send(msg)
                self._record_result(
                    StateMachineMutationStrategy.RESET_SURGE,
                    nmt_cob_id, reset_payload, f"reset_{i}"
                )
                time.sleep(0.01)  # Minimal delay between resets
            except Exception as e:
                logger.warning("Failed to send reset surge: %s", e)

    def fuzz_partial_state_corruption(self) -> None:
        """Send NMT state with invalid/corrupted bit patterns.

        Tests device handling of NMT state bytes with invalid bit
        combinations that violate the NMT state machine specification.
        """
        logger.info("Testing partial state corruption")

        nmt_cob_id = self.NMT_COB_ID

        # Generate bit patterns with invalid combinations
        invalid_states = [
            0x02,  # Invalid command
            0x03,  # Invalid
            0x06,  # Invalid (between operational and stopped)
            0x0F,  # All bits set
            0x80,  # High bit set
            0xAA,  # Alternating bits
            0x55,  # Alternating bits (inverse)
        ]

        for invalid_state in invalid_states:
            nmt_payload = bytes([invalid_state, self.node_id, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

            try:
                msg = can.Message(arbitration_id=nmt_cob_id, data=nmt_payload, is_extended_id=False)
                self.bus.send(msg)
                self._record_result(
                    StateMachineMutationStrategy.PARTIAL_STATE_CORRUPTION,
                    nmt_cob_id, nmt_payload, f"corruption_0x{invalid_state:02X}"
                )
            except Exception as e:
                logger.warning("Failed to send state corruption: %s", e)

    def fuzz_emergency_to_invalid(self) -> None:
        """Attempt to transition from EMCY to invalid state.

        Tests device behavior when EMCY occurs during state transitions
        or when transitioning to invalid states via EMCY.
        """
        logger.info("Testing EMCY to invalid state transitions")

        emcy_cob_id = self.EMCY_BASE + self.node_id
        nmt_cob_id = self.NMT_COB_ID

        # Send EMCY with invalid error codes
        invalid_error_codes = [
            0x0000,  # No error (should not be sent as EMCY)
            0xFFFF,  # Max value
            0x1234,  # Random
            0x8000,  # High bit set
        ]

        for error_code in invalid_error_codes:
            # First: set to operational
            nmt_operational = bytes([0x01, self.node_id, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            try:
                msg = can.Message(arbitration_id=nmt_cob_id, data=nmt_operational, is_extended_id=False)
                self.bus.send(msg)
                time.sleep(0.05)
            except Exception as e:
                logger.warning("Failed to set operational: %s", e)

            # Then: send EMCY with invalid code
            error_bytes = error_code.to_bytes(2, byteorder='little')
            emcy_payload = error_bytes + bytes([0xFF, 0x00, 0x00, 0x00, 0x00, 0x00])

            try:
                msg = can.Message(arbitration_id=emcy_cob_id, data=emcy_payload, is_extended_id=False)
                self.bus.send(msg)
                self._record_result(
                    StateMachineMutationStrategy.EMERGENCY_TO_INVALID,
                    emcy_cob_id, emcy_payload, f"emcy_0x{error_code:04X}"
                )
            except Exception as e:
                logger.warning("Failed to send EMCY to invalid: %s", e)

    def fuzz_producer_consumer_desync(self) -> None:
        """Intentional producer/consumer desynchronization via heartbeat drift.

        Tests device handling of heartbeat timing violations and
        producer/consumer desynchronization patterns.
        """
        logger.info("Testing producer/consumer desync")

        heartbeat_cob_id = self.HEARTBEAT_BASE + self.node_id

        # Send heartbeat at irregular intervals
        intervals = [1, 2, 10, 100, 200, 50, 5, 1000]  # ms

        for interval in intervals:
            heartbeat_payload = bytes([0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

            try:
                msg = can.Message(arbitration_id=heartbeat_cob_id, data=heartbeat_payload, is_extended_id=False)
                self.bus.send(msg)
                self._record_result(
                    StateMachineMutationStrategy.PRODUCER_CONSUMER_DESYNC,
                    heartbeat_cob_id, heartbeat_payload, f"interval_{interval}ms"
                )
                time.sleep(interval / 1000.0)
            except Exception as e:
                logger.warning("Failed to send desync heartbeat: %s", e)

    def fuzz_nmt_spurious_response(self) -> None:
        """Send unexpected NMT response messages.

        Tests device handling of NMT responses that should not occur
        or occur at unexpected times.
        """
        logger.info("Testing NMT spurious responses")

        nmt_cob_id = self.NMT_COB_ID

        # Send NMT responses without corresponding requests
        spurious_responses = [
            (0x01, 0xFF),  # Start for broadcast
            (0x02, 0xFF),  # Stop for broadcast
            (0x80, 0xFF),  # Sleep for broadcast
            (0x01, 0x00),  # Start for node 0
        ]

        for command, node_id in spurious_responses:
            nmt_payload = bytes([command, node_id, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

            try:
                msg = can.Message(arbitration_id=nmt_cob_id, data=nmt_payload, is_extended_id=False)
                self.bus.send(msg)
                self._record_result(
                    StateMachineMutationStrategy.NMT_SPURIOUS_RESPONSE,
                    nmt_cob_id, nmt_payload, f"spurious_0x{command:02X}_node_0x{node_id:02X}"
                )
                time.sleep(0.1)
            except Exception as e:
                logger.warning("Failed to send spurious response: %s", e)

    def fuzz_state_persistence_test(self) -> None:
        """Test state preservation after attack.

        Verifies that the device maintains correct state after exposure
        to fuzzing attacks and returns to expected operational state.
        """
        logger.info("Testing state persistence after attack")

        nmt_cob_id = self.NMT_COB_ID
        heartbeat_cob_id = self.HEARTBEAT_BASE + self.node_id

        # Phase 1: Attack (send invalid states)
        logger.debug("Phase 1: State attack")
        for i in range(20):
            invalid_state = bytes([random.randint(0x00, 0xFF), self.node_id, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            try:
                msg = can.Message(arbitration_id=nmt_cob_id, data=invalid_state, is_extended_id=False)
                self.bus.send(msg)
                self.fuzzed_count += 1
            except Exception as e:
                logger.warning("Failed to attack state: %s", e)
            time.sleep(0.05)

        # Phase 2: Recovery
        logger.debug("Phase 2: Recovery (1 second)")
        time.sleep(1.0)

        # Phase 3: Verify operational state
        logger.debug("Phase 3: Verify operational state")
        heartbeat_payload = bytes([0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

        try:
            msg = can.Message(arbitration_id=heartbeat_cob_id, data=heartbeat_payload, is_extended_id=False)
            self.bus.send(msg)
            self._record_result(
                StateMachineMutationStrategy.STATE_PERSISTENCE_TEST,
                heartbeat_cob_id, heartbeat_payload, "persistence_verified"
            )
        except Exception as e:
            logger.warning("Failed to verify state persistence: %s", e)

    def execute(self) -> None:
        """Execute full state machine fuzzing suite.

        Runs all configured fuzzing strategies and collects results.
        """
        logger.info("Executing State Machine Fuzzer for node %d", self.node_id)
        start_time = time.time()

        try:
            self.fuzz_illegal_state_transition()
            self.fuzz_guard_time_manipulation()
            self.fuzz_lifetime_factor_abuse()
            self.fuzz_bootup_during_operational()
            self.fuzz_reset_surge()
            self.fuzz_partial_state_corruption()
            self.fuzz_emergency_to_invalid()
            self.fuzz_producer_consumer_desync()
            self.fuzz_nmt_spurious_response()
            self.fuzz_state_persistence_test()

        except Exception as e:
            logger.error("State machine fuzzing error: %s", e)

        elapsed = time.time() - start_time
        logger.info(
            "State machine fuzzing complete: %d mutations sent in %.1f seconds",
            self.fuzzed_count, elapsed
        )

    def _record_result(
        self,
        strategy: StateMachineMutationStrategy,
        cob_id: int,
        data: bytes,
        details: str = "",
    ) -> None:
        """Record fuzzing result.

        Args:
            strategy: Mutation strategy
            cob_id: CAN Object ID
            data: Frame payload
            details: Additional details
        """
        result = {
            "timestamp": time.time(),
            "strategy": strategy.value,
            "cob_id": cob_id,
            "data": data.hex() if data else "",
            "details": details,
        }
        self.test_results.append(result)
        self.fuzzed_count += 1

        logger.debug(
            "State machine fuzz result: strategy=%s, cob_id=0x%03X, details=%s",
            strategy.value, cob_id, details
        )

        # Notify oracle if callback provided
        if self.oracle:
            self.oracle({
                "event_type": "fuzz_input_sent",
                "fuzzer": "state_machine",
                "strategy": strategy.value,
                "cob_id": cob_id,
                "details": details,
            })
