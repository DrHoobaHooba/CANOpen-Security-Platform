"""Passive CANopen discovery by listening to bus frames.

Detects nodes via boot-up, heartbeat, and EMCY frames without active
participation. Provides frame classification and NMT state tracking.
"""

import logging
from typing import Set, Optional, Dict, Any, List
from enum import IntEnum
import time

import can

from ..utils.logging_utils import get_logger

logger = get_logger(__name__)


class NMTState(IntEnum):
    """CANopen NMT states from heartbeat/boot-up frames.
    
    Refer to DS301 §5.9.2 for state definitions.
    """
    INITIALIZING = 0x00  # Device is initializing
    STOPPED = 0x04       # Stopped state
    OPERATIONAL = 0x05   # Operational state
    PRE_OPERATIONAL = 0x7F  # Pre-operational state

    def __str__(self) -> str:
        """Return human-readable state name."""
        states = {
            0x00: "INITIALIZING",
            0x04: "STOPPED",
            0x05: "OPERATIONAL",
            0x7F: "PRE_OPERATIONAL",
        }
        return states.get(self.value, f"UNKNOWN(0x{self.value:02X})")


class PassiveDiscovery:
    """Listen passively for boot-up, heartbeat, and EMCY frames.

    Non-invasive discovery that observes CANopen heartbeat mechanisms
    to build network topology without transmitting on the bus.
    """

    # CANopen COB-ID ranges (CiA 301)
    COB_HEARTBEAT_BASE = 0x700  # Heartbeat: 0x700 + node_id (1-127)
    COB_EMCY_BASE = 0x080       # EMCY: 0x080 + node_id
    COB_TPDO1_BASE = 0x180      # Transmit PDO1: 0x180 + node_id
    COB_RPDO1_BASE = 0x200      # Receive PDO1: 0x200 + node_id
    COB_TPDO2_BASE = 0x280      # Transmit PDO2: 0x280 + node_id
    COB_RPDO2_BASE = 0x300      # Receive PDO2: 0x300 + node_id
    COB_TPDO3_BASE = 0x380      # Transmit PDO3: 0x380 + node_id
    COB_RPDO3_BASE = 0x400      # Receive PDO3: 0x400 + node_id
    COB_TPDO4_BASE = 0x480      # Transmit PDO4: 0x480 + node_id
    COB_RPDO4_BASE = 0x500      # Receive PDO4: 0x500 + node_id

    def __init__(self, bus: Any) -> None:
        """Initialize passive discovery.

        Args:
            bus: Bus instance for frame reception (python-can or BusInterface)

        Raises:
            TypeError: If bus does not provide a recv() method
        """
        if bus is None or not hasattr(bus, "recv"):
            raise TypeError(f"bus must provide recv(), got {type(bus)}")

        self.bus = bus
        self.nodes: Set[int] = set()
        self.node_info: Dict[int, Dict[str, Any]] = {}
        self.emcy_events: Dict[int, List[Dict[str, Any]]] = {}
        self.frame_stats: Dict[str, int] = {
            "heartbeat": 0,
            "emcy": 0,
            "pdo": 0,
            "other": 0,
            "invalid": 0,
        }

    def run(self, timeout: float = 5.0) -> Set[int]:
        """Run passive discovery and collect frame data.

        Args:
            timeout: Listen timeout in seconds

        Returns:
            Set of discovered node IDs

        Raises:
            ValueError: If timeout is invalid
            can.CanOperationError: If bus I/O fails
        """
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError(f"timeout must be positive, got {timeout}")

        def _safe_log(level: str, message: str, *args: Any) -> None:
            try:
                getattr(logger, level)(message, *args)
            except Exception:
                pass

        _safe_log("info", "Starting passive discovery for %.1f seconds", timeout)
        start = time.monotonic()
        frame_count = 0

        try:
            while time.monotonic() - start < timeout:
                remaining = timeout - (time.monotonic() - start)
                try:
                    msg = self.bus.recv(timeout=max(0.01, remaining))
                    if msg is None:
                        continue

                    frame_count += 1
                    node_id = self._parse_frame(msg)

                    if node_id is not None and 1 <= node_id <= 127:
                        self.nodes.add(node_id)

                except can.CanOperationError as e:
                    _safe_log("warning", "Bus receive error: %s", e)
                    self.frame_stats["invalid"] += 1

        except Exception as e:
            _safe_log("error", "Unexpected error during passive discovery: %s", e)
            raise

        elapsed = time.monotonic() - start
        _safe_log(
            "info",
            "Passive discovery complete: found %d nodes in %d frames (%.1f seconds) | "
            "HB=%d EMCY=%d PDO=%d OTHER=%d",
            len(self.nodes), frame_count, elapsed,
            self.frame_stats["heartbeat"], self.frame_stats["emcy"],
            self.frame_stats["pdo"], self.frame_stats["other"]
        )

        return self.nodes

    def _parse_frame(self, msg: can.Message) -> Optional[int]:
        """Parse CANopen frame and extract node ID with classification.

        Args:
            msg: CAN frame to parse

        Returns:
            Node ID if frame is valid CANopen frame, None otherwise
        """
        if msg is None or msg.arbitration_id is None:
            self.frame_stats["invalid"] += 1
            return None

        cob_id = msg.arbitration_id
        node_id = None
        frame_type = None

        # Heartbeat/boot-up: 0x700 + node_id
        if self.COB_HEARTBEAT_BASE <= cob_id < self.COB_HEARTBEAT_BASE + 128:
            node_id = cob_id - self.COB_HEARTBEAT_BASE
            frame_type = "heartbeat"
            self._parse_heartbeat(node_id, msg)

        # EMCY: 0x080 + node_id
        elif self.COB_EMCY_BASE <= cob_id < self.COB_EMCY_BASE + 128:
            node_id = cob_id - self.COB_EMCY_BASE
            frame_type = "emcy"
            self._parse_emcy(node_id, msg)

        # PDO frames
        elif self._is_pdo_cob(cob_id):
            node_id = self._extract_node_id_from_pdo(cob_id)
            frame_type = "pdo"
            self.frame_stats["pdo"] += 1

        if node_id is not None and 1 <= node_id <= 127:
            if node_id not in self.node_info:
                self.node_info[node_id] = {
                    "first_seen": time.time(),
                    "last_seen": time.time(),
                    "frames": [],
                    "nmt_state": None,
                    "emcy_count": 0,
                    "total_frames": 0,
                }
            else:
                self.node_info[node_id]["last_seen"] = time.time()
                self.node_info[node_id]["total_frames"] += 1

            self.node_info[node_id]["frames"].append(frame_type)
            logger.debug("Node %d: %s frame (COB-ID=0x%03X)", node_id, frame_type, cob_id)
            return node_id

        if frame_type is None:
            self.frame_stats["other"] += 1

        return None

    def _is_pdo_cob(self, cob_id: int) -> bool:
        """Check if COB-ID is a PDO frame."""
        # Check all PDO ranges (TPDO1-4, RPDO1-4)
        pdo_ranges = [
            (self.COB_TPDO1_BASE, self.COB_TPDO1_BASE + 128),
            (self.COB_RPDO1_BASE, self.COB_RPDO1_BASE + 128),
            (self.COB_TPDO2_BASE, self.COB_TPDO2_BASE + 128),
            (self.COB_RPDO2_BASE, self.COB_RPDO2_BASE + 128),
            (self.COB_TPDO3_BASE, self.COB_TPDO3_BASE + 128),
            (self.COB_RPDO3_BASE, self.COB_RPDO3_BASE + 128),
            (self.COB_TPDO4_BASE, self.COB_TPDO4_BASE + 128),
            (self.COB_RPDO4_BASE, self.COB_RPDO4_BASE + 128),
        ]

        for start, end in pdo_ranges:
            if start <= cob_id < end:
                return True

        return False

    def _extract_node_id_from_pdo(self, cob_id: int) -> Optional[int]:
        """Extract node ID from PDO COB-ID."""
        # Check each PDO range
        pdo_bases = [
            self.COB_TPDO1_BASE, self.COB_RPDO1_BASE,
            self.COB_TPDO2_BASE, self.COB_RPDO2_BASE,
            self.COB_TPDO3_BASE, self.COB_RPDO3_BASE,
            self.COB_TPDO4_BASE, self.COB_RPDO4_BASE,
        ]

        for base in pdo_bases:
            if base <= cob_id < base + 128:
                return cob_id - base

        return None

    def _parse_heartbeat(self, node_id: int, msg: can.Message) -> None:
        """Parse heartbeat/boot-up frame (COB-ID 0x700 + node_id).

        Boot-up (first heartbeat after reset):
        - state_byte[7] = 1 (boot-up indicator)
        - state_byte[0:6] = 00 (initializing state)

        Heartbeat:
        - state_byte[7] = 0
        - state_byte[0:6] = NMT state

        Args:
            node_id: Node ID extracted from COB-ID
            msg: CAN frame with heartbeat data
        """
        if len(msg.data) < 1:
            logger.debug("Heartbeat from node %d has no data", node_id)
            return

        state_byte = msg.data[0]
        nmt_state = NMTState(state_byte & 0x7F)
        boot_up = (state_byte & 0x80) != 0

        if boot_up:
            logger.info("Node %d BOOT-UP detected", node_id)

        if node_id in self.node_info:
            old_state = self.node_info[node_id].get("nmt_state")
            self.node_info[node_id]["nmt_state"] = nmt_state

            if old_state is not None and old_state != nmt_state:
                logger.info(
                    "Node %d NMT state transition: %s -> %s",
                    node_id, old_state, nmt_state
                )

        self.frame_stats["heartbeat"] += 1

    def _parse_emcy(self, node_id: int, msg: can.Message) -> None:
        """Parse EMCY frame (COB-ID 0x080 + node_id).

        EMCY frame format (DS301 §5.8.3.1):
        - Bytes 0-1: Error code (little-endian, 0x0000=error resolved)
        - Byte 2: Error register
        - Bytes 3-7: Manufacturer-specific error data

        Args:
            node_id: Node ID extracted from COB-ID
            msg: CAN frame with EMCY data
        """
        if len(msg.data) < 3:
            logger.debug("EMCY from node %d has insufficient data", node_id)
            return

        error_code = msg.data[0] | (msg.data[1] << 8)
        error_register = msg.data[2]
        manufacturer_data = msg.data[3:] if len(msg.data) > 3 else b""

        if node_id not in self.emcy_events:
            self.emcy_events[node_id] = []

        event = {
            "timestamp": time.time(),
            "error_code": error_code,
            "error_register": error_register,
            "manufacturer_data": manufacturer_data.hex(),
        }
        self.emcy_events[node_id].append(event)

        if node_id in self.node_info:
            self.node_info[node_id]["emcy_count"] += 1

        # Log error with severity based on error code
        if error_code == 0x0000:
            logger.info(
                "Node %d EMCY: error resolved (register=0x%02X)",
                node_id, error_register
            )
        else:
            error_class = self._classify_error_code(error_code)
            logger.warning(
                "Node %d EMCY: code=0x%04X (%s) register=0x%02X mfg_data=%s",
                node_id, error_code, error_class, error_register,
                manufacturer_data.hex()
            )

        self.frame_stats["emcy"] += 1

    @staticmethod
    def _classify_error_code(error_code: int) -> str:
        """Classify EMCY error code per DS301.

        Args:
            error_code: 16-bit EMCY error code

        Returns:
            Human-readable error class name
        """
        if error_code == 0x0000:
            return "Error Reset or No Error"
        elif 0x1000 <= error_code < 0x2000:
            return "Generic Error"
        elif 0x2000 <= error_code < 0x3000:
            return "Current"
        elif 0x3000 <= error_code < 0x4000:
            return "Voltage"
        elif 0x4000 <= error_code < 0x5000:
            return "Temperature"
        elif 0x5000 <= error_code < 0x6000:
            return "Device Hardware"
        elif 0x6000 <= error_code < 0x7000:
            return "Device Software"
        elif 0x7000 <= error_code < 0x8000:
            return "Additional Modules"
        elif 0x8000 <= error_code < 0x9000:
            return "Monitoring"
        elif 0x9000 <= error_code < 0xF000:
            return "External Error"
        elif 0xF000 <= error_code < 0x10000:
            return "Additional Functions"
        else:
            return f"Unknown (0x{error_code:04X})"

    def get_node_info(self, node_id: int) -> Optional[Dict[str, Any]]:
        """Get detailed info for discovered node.

        Args:
            node_id: Node ID to query

        Returns:
            Node information dictionary or None if not discovered
        """
        return self.node_info.get(node_id)

    def get_all_node_info(self) -> Dict[int, Dict[str, Any]]:
        """Get info for all discovered nodes.

        Returns:
            Dictionary mapping node IDs to their info
        """
        return self.node_info.copy()

    def get_emcy_history(self, node_id: int) -> List[Dict[str, Any]]:
        """Get EMCY event history for node.

        Args:
            node_id: Node ID

        Returns:
            List of EMCY events for this node
        """
        return self.emcy_events.get(node_id, []).copy()

    def get_statistics(self) -> Dict[str, Any]:
        """Get discovery session statistics.

        Returns:
            Dictionary with frame counts and summary statistics
        """
        total_emcy_events = sum(len(events) for events in self.emcy_events.values())

        return {
            "nodes_discovered": len(self.nodes),
            "node_ids": sorted(self.nodes),
            "frame_stats": self.frame_stats.copy(),
            "total_emcy_events": total_emcy_events,
            "avg_frames_per_node": (
                sum(info["total_frames"] for info in self.node_info.values()) / len(self.nodes)
                if self.nodes else 0
            ),
        }
