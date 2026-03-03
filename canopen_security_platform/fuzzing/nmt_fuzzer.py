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
