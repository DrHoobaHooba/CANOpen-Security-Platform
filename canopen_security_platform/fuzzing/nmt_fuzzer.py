"""CANopen NMT (Network Management) fuzzing engine.

Tests NMT state machine for improper transitions, invalid commands,
and potential denial-of-service vulnerabilities.
"""

import logging
import random
import time
from typing import Callable, Any, Dict, List
from enum import IntEnum

import can

from ..hal.bus_pcan import BusInterface
from ..od.runtime_od import RuntimeObjectDictionary
from ..utils.logging_utils import get_logger

logger = get_logger(__name__)

OracleCallback = Callable[[Dict[str, Any]], None]


class NMTCommand(IntEnum):
    """NMT commands (DS301)."""
    START = 0x01        # Start remote node
    STOP = 0x02         # Stop remote node
    ENTER_PREOP = 0x80  # Enter pre-operational
    RESET_COMM = 0x82   # Reset communication
    RESET_DEVICE = 0x81 # Reset device


class NMTState(IntEnum):
    """NMT states."""
    INITIALIZING = 0x00
    STOPPED = 0x04
    OPERATIONAL = 0x05
    PRE_OPERATIONAL = 0x7F


class NMTFuzzer:
    """NMT protocol fuzzing with state machine attacks.

    Tests NMT implementation for invalid state transitions,
    improper command handling, and potential crashes.
    """

    # NMT COB-IDs
    NMT_CMD_COB_ID = 0x000
    NMT_ERROR_COB_ID = 0x700

    def __init__(
        self,
        bus: BusInterface,
        od: RuntimeObjectDictionary,
        node_id: int,
        oracle: OracleCallback,
    ) -> None:
        """Initialize NMT fuzzer.

        Args:
            bus: CAN bus interface
            od: Runtime object dictionary
            node_id: Target node ID
            oracle: Callback for anomaly detection

        Raises:
            ValueError: If node_id is invalid
        """
        if not isinstance(node_id, int) or not (1 <= node_id <= 127):
            raise ValueError(f"node_id must be 1-127, got {node_id}")

        self.bus = bus
        self.od = od
        self.node_id = node_id
        self.oracle = oracle
        self.test_results: List[Dict[str, Any]] = []
        self.fuzzed_count = 0
        self.current_state = NMTState.INITIALIZING

        logger.debug("NMT Fuzzer initialized for node %d", node_id)

    def rapid_transitions(self) -> None:
        """Send rapid successive NMT state transition commands.

        Tests device handling of high-frequency state changes.
        """
        logger.info("Testing NMT rapid state transitions")

        # Send burst of alternating commands
        commands = [
            (NMTCommand.START, "start"),
            (NMTCommand.STOP, "stop"),
            (NMTCommand.ENTER_PREOP, "preop"),
        ]

        for i in range(30):
            cmd, label = random.choice(commands)
            self._send_nmt_command(cmd, self.node_id, strategy="rapid_transition")
            time.sleep(0.01)  # 10ms between commands

    def illegal_transitions(self) -> None:
        """Test NMT state machine violation transitions.

        Attempts commands that violate proper state machine flow.
        """
        logger.info("Testing NMT illegal state transitions")

        # Invalid transition sequences
        invalid_sequences = [
            # Stop before start
            [(NMTCommand.STOP, "stop_before_start")],
            # Double start
            [(NMTCommand.START, "start"),
             (NMTCommand.START, "double_start")],
            # Pre-op then operational without reset
            [(NMTCommand.ENTER_PREOP, "preop"),
             (NMTCommand.START, "start_from_preop")],
            # Reset in operational
            [(NMTCommand.START, "start"),
             (NMTCommand.RESET_COMM, "reset_while_operational")],
            # Invalid transitions at 50ms intervals
            [(NMTCommand.RESET_DEVICE, "reset_device"),
             (NMTCommand.STOP, "stop_after_reset")],
        ]

        for sequence in invalid_sequences:
            logger.debug("Testing illegal sequence: %s", [s[1] for s in sequence])

            for cmd, label in sequence:
                self._send_nmt_command(cmd, self.node_id, strategy=label)
                time.sleep(0.05)

    def broadcast_attack(self) -> None:
        """Fuzz NMT broadcast with all combinations of commands/nodes.

        Tests broadcast command processing robustness.
        """
        logger.info("Testing NMT broadcast attack vectors")

        commands = [
            NMTCommand.START,
            NMTCommand.STOP,
            NMTCommand.ENTER_PREOP,
            NMTCommand.RESET_COMM,
            NMTCommand.RESET_DEVICE,
        ]

        node_ids = [
            0,                   # Broadcast
            self.node_id,        # Specific node
            (self.node_id + 1) % 128,  # Other node
            127,                 # Max node
            255,                 # Invalid node
        ]

        for cmd in commands:
            for node_id in node_ids:
                self._send_nmt_command(cmd, node_id, strategy="broadcast_attack")
                time.sleep(0.005)

    def command_field_corruption(self) -> None:
        """Send NMT frames with corrupted command fields.

        Tests handling of undefined command bytes.
        """
        logger.info("Testing NMT command field corruption")

        # Invalid command bytes
        invalid_commands = [
            0x00,       # No command
            0x03,       # Undefined
            0x04,       # Undefined
            0x7E,       # Undefined
            0x7F,       # Pre-op code (may confuse)
            0x83,       # Undefined
            0xFF,       # Max value
            0xAA,       # Random
            0x55,       # Random
        ]

        for cmd_byte in invalid_commands:
            self._send_nmt_command(cmd_byte, self.node_id, strategy="command_corruption")

    def heartbeat_fuzzing(self) -> None:
        """Fuzz NMT heartbeat producer (0x700 + node_id).

        Tests handling of missing, corrupted, or malformed heartbeat messages
        that signal node state changes.
        """
        logger.info("Testing NMT heartbeat fuzzing for node %d", self.node_id)

        # Heartbeat COB-ID for this node
        heartbeat_cob_id = self.NMT_ERROR_COB_ID + self.node_id

        # Valid heartbeat state bytes
        valid_states = [
            NMTState.INITIALIZING,
            NMTState.STOPPED,
            NMTState.PRE_OPERATIONAL,
            NMTState.OPERATIONAL,
        ]

        # Test 1: Valid state heartbeats
        logger.info("  Testing valid heartbeat states")
        for state in valid_states:
            msg = can.Message(
                arbitration_id=heartbeat_cob_id,
                data=bytes([state]),
                is_extended_id=False
            )
            self.bus.send(msg)
            time.sleep(0.05)
            self.fuzzed_count += 1

        # Test 2: Invalid heartbeat states
        logger.info("  Testing invalid heartbeat states")
        invalid_states = [0x01, 0x02, 0x03, 0x06, 0x08, 0x80, 0xFF]
        for state in invalid_states:
            msg = can.Message(
                arbitration_id=heartbeat_cob_id,
                data=bytes([state]),
                is_extended_id=False
            )
            self.bus.send(msg)
            time.sleep(0.02)
            self.fuzzed_count += 1

        # Test 3: Rapid heartbeat changes
        logger.info("  Testing rapid heartbeat state changes")
        for i in range(20):
            state = random.choice(valid_states)
            msg = can.Message(
                arbitration_id=heartbeat_cob_id,
                data=bytes([state]),
                is_extended_id=False
            )
            self.bus.send(msg)
            time.sleep(0.001)  # 1ms between heartbeats
            self.fuzzed_count += 1

        # Test 4: Missing heartbeat (long pause)
        logger.info("  Testing missing heartbeat scenario")
        msg = can.Message(
            arbitration_id=heartbeat_cob_id,
            data=bytes([NMTState.OPERATIONAL]),
            is_extended_id=False
        )
        self.bus.send(msg)
        time.sleep(0.5)  # Long gap (should trigger timeout on real devices)
        self.fuzzed_count += 1

        # Test 5: Oversized heartbeat frames
        logger.info("  Testing oversized heartbeat frames")
        for payload_len in [2, 4, 8]:
            msg = can.Message(
                arbitration_id=heartbeat_cob_id,
                data=bytes([NMTState.OPERATIONAL] + [0] * (payload_len - 1)),
                is_extended_id=False
            )
            self.bus.send(msg)
            time.sleep(0.02)
            self.fuzzed_count += 1

    def guard_time_fuzzing(self) -> None:
        """Fuzz NMT guard time and lifetime monitoring via SDO.

        Tests OD entries 0x100C (Guard Time) and 0x100D (Lifetime Factor).
        These control heartbeat producer/consumer timing.
        """
        logger.info("Testing NMT guard time fuzzing")

        # OD indices for guard time / lifetime
        GUARD_TIME_INDEX = 0x100C
        LIFETIME_FACTOR_INDEX = 0x100D

        # Test 1: Guard time boundary values
        logger.info("  Testing guard time boundary values")
        guard_time_values = [
            0x0000,       # No guarding
            0x0001,       # Minimum
            0x00FF,       # Byte boundary
            0x0100,       # Word boundary
            0x0FFF,       # Partial word
            0xFFFF,       # Maximum
            0xFFFE,       # Maximum - 1
        ]

        for gt_value in guard_time_values:
            # Try to write guard time via SDO
            self._write_via_sdo(GUARD_TIME_INDEX, 0, gt_value, strategy="guard_time")
            time.sleep(0.1)

        # Test 2: Lifetime factor variations
        logger.info("  Testing lifetime factor values")
        lifetime_values = [
            0x00,         # No lifetime
            0x01,         # Minimum
            0x0F,         # Nibble boundary
            0x80,         # Bit 7 set
            0xFF,         # Maximum
        ]

        for lf_value in lifetime_values:
            # Try to write lifetime factor via SDO
            self._write_via_sdo(LIFETIME_FACTOR_INDEX, 0, lf_value, strategy="lifetime_factor")
            time.sleep(0.1)

        # Test 3: Combined extreme scenarios
        logger.info("  Testing guard time + lifetime extreme combinations")
        scenarios = [
            (0x0000, 0x00),  # No guarding
            (0xFFFF, 0xFF),  # Maximum of both
            (0x0001, 0xFF),  # Minimum guard, max lifetime
            (0xFFFF, 0x01),  # Maximum guard, min lifetime
        ]

        for gt, lf in scenarios:
            self._write_via_sdo(GUARD_TIME_INDEX, 0, gt, strategy="guard_combo")
            self._write_via_sdo(LIFETIME_FACTOR_INDEX, 0, lf, strategy="lifetime_combo")
            time.sleep(0.05)

        logger.info("Guard time fuzzing complete")

    def execute(self) -> None:
        """Execute full NMT fuzzing suite.

        Runs all NMT fuzzing strategies in sequence.
        """
        logger.info("Executing NMT fuzzer for node %d", self.node_id)
        start_time = time.time()

        try:
            self.rapid_transitions()
            time.sleep(0.1)

            self.illegal_transitions()
            time.sleep(0.1)

            self.broadcast_attack()
            time.sleep(0.1)

            self.command_field_corruption()
            time.sleep(0.1)

            self.heartbeat_fuzzing()
            time.sleep(0.1)

            self.guard_time_fuzzing()

        except Exception as e:
            logger.error("NMT fuzzing error: %s", e)

        elapsed = time.time() - start_time
        logger.info(
            "NMT fuzzing complete: %d mutations sent in %.1f seconds",
            self.fuzzed_count, elapsed
        )

    def _send_nmt_command(
        self,
        cmd: int,
        node_id: int,
        strategy: str = "nmt_command",
    ) -> None:
        """Send an NMT command frame.

        Args:
            cmd: NMT command byte
            node_id: Target node ID (0=broadcast)
            strategy: Fuzzing strategy name
        """
        try:
            if not isinstance(cmd, int) or not (0 <= cmd <= 0xFF):
                cmd = cmd & 0xFF

            if not isinstance(node_id, int) or not (0 <= node_id <= 0xFF):
                node_id = node_id & 0xFF

            data = bytes([cmd, node_id])
            msg = can.Message(
                arbitration_id=self.NMT_CMD_COB_ID,
                data=data,
                is_extended_id=False
            )
            self.bus.send(msg)
            self.fuzzed_count += 1

            self.test_results.append({
                "timestamp": time.time(),
                "strategy": strategy,
                "command": cmd,
                "node_id": node_id,
                "data": data.hex(),
            })

            logger.debug(
                "Sent NMT command (cmd=0x%02X, node=%d, strategy=%s)",
                cmd, node_id, strategy
            )

        except Exception as e:
            logger.warning("Failed to send NMT command: %s", e)

    def _write_via_sdo(
        self,
        index: int,
        subindex: int,
        value: int,
        strategy: str = "sdo_write"
    ) -> None:
        """Write to OD via SDO for parameter fuzzing.

        Args:
            index: OD index (0x0000-0xFFFF)
            subindex: OD subindex (0x00-0xFF)
            value: Value to write (up to 32-bit)
            strategy: Fuzzing strategy name
        """
        try:
            sdo_rx_cob = 0x600 + self.node_id
            sdo_tx_cob = 0x580 + self.node_id

            # SDO download initiate (expedited, 4 bytes)
            data = bytearray(8)
            data[0] = 0x23  # Download initiate, expedited, 4 bytes
            data[1] = index & 0xFF
            data[2] = (index >> 8) & 0xFF
            data[3] = subindex
            data[4] = (value & 0xFF)
            data[5] = ((value >> 8) & 0xFF)
            data[6] = ((value >> 16) & 0xFF)
            data[7] = ((value >> 24) & 0xFF)

            msg = can.Message(
                arbitration_id=sdo_rx_cob,
                data=bytes(data),
                is_extended_id=False
            )
            self.bus.send(msg)
            self.fuzzed_count += 1

            self.test_results.append({
                "timestamp": time.time(),
                "strategy": strategy,
                "index": hex(index),
                "subindex": subindex,
                "value": hex(value),
            })

        except Exception as e:
            logger.warning(
                "Failed to write via SDO (0x%04X:%02X = 0x%X): %s",
                index, subindex, value, e
            )

    def get_results(self) -> Dict[str, Any]:
        """Get fuzzing results and statistics.

        Returns:
            Dictionary with fuzzing statistics and results
        """
        return {
            "node_id": self.node_id,
            "total_mutations": self.fuzzed_count,
            "strategies_used": len(set(r["strategy"] for r in self.test_results)),
            "results": self.test_results,
        }
