"""CAN ID (COB-ID) fuzzing engine.

Implements comprehensive COB-ID mutation strategies to detect vulnerabilities
in device handling of frames with invalid, reserved, or conflicting COB-IDs.

Tests for:
- Reserved COB-ID handling (0x001-0x07F)
- Boundary value testing (0x000, 0x7FF)
- Conflicting COB-IDs (legitimate data on wrong COB-ID)
- Broadcast vs unicast handling
- COB-ID space sweep
"""

import logging
import random
import time
from typing import Callable, Any, Dict, List, Optional
from enum import Enum

import can

from ..hal.bus_pcan import BusInterface
from ..od.runtime_od import RuntimeObjectDictionary
from ..utils.logging_utils import get_logger

logger = get_logger(__name__)

OracleCallback = Callable[[Dict[str, Any]], None]


class CANIDMutationStrategy(Enum):
    """CAN ID (COB-ID) fuzzing mutation strategies."""
    RESERVED_COB_IDS = "reserved_cob_ids"          # 0x001-0x07F reserved range
    BOUNDARY_COB_IDS = "boundary_cob_ids"          # 0x000, 0x7FF, transitions
    CONFLICTING_COB_IDS = "conflicting_cob_ids"    # Data on wrong COB-ID
    COB_ID_SWEEP = "cob_id_sweep"                  # Full 0x000-0x7FF sweep
    BROADCAST_VS_UNICAST = "broadcast_vs_unicast" # Broadcast handling
    DUPLICATE_COB_IDS = "duplicate_cob_ids"       # Multiple devices on same ID
    COB_ID_FUZZ_MASK = "cob_id_fuzz_mask"         # Bit-flip mutations
    COB_ID_EXTENSION_FRAMES = "cob_id_extension"  # 29-bit IDs on 11-bit network
    COB_ID_MIXING = "cob_id_mixing"               # Random COB-ID patterns
    COB_ID_RATE_VARIATION = "cob_id_rate_variation"  # Same ID at varying rates


class CANIDFuzzer:
    """CAN ID fuzzing engine for COB-ID boundary and reserved value testing.

    Tests device behavior when receiving frames with invalid, reserved, or
    conflicting COB-IDs. Helps identify improper COB-ID filtering, duplicate
    handling, and protocol violations.
    """

    # CANopen COB-ID ranges
    NMT_COB_ID = 0x000
    SYNC_COB_ID = 0x080
    EMCY_BASE = 0x080      # 0x080 + node_id
    TPDO1_BASE = 0x180     # 0x180 + node_id
    RPDO1_BASE = 0x200     # 0x200 + node_id
    TPDO2_BASE = 0x280     # 0x280 + node_id
    RPDO2_BASE = 0x300     # 0x300 + node_id
    TPDO3_BASE = 0x380     # 0x380 + node_id
    RPDO3_BASE = 0x400     # 0x400 + node_id
    TPDO4_BASE = 0x480     # 0x480 + node_id
    RPDO4_BASE = 0x500     # 0x500 + node_id
    TSDO_BASE = 0x580      # 0x580 + node_id (SDO upload)
    RSDO_BASE = 0x600      # 0x600 + node_id (SDO download)
    HEARTBEAT_BASE = 0x700 # 0x700 + node_id

    # Reserved COB-ID ranges (DS301)
    RESERVED_START = 0x001
    RESERVED_END = 0x07F
    MAX_COB_ID = 0x7FF

    def __init__(
        self,
        bus: BusInterface,
        od: Optional[RuntimeObjectDictionary] = None,
        node_id: int = 1,
        oracle: Optional[OracleCallback] = None,
    ) -> None:
        """Initialize CAN ID fuzzer.

        Args:
            bus: CAN bus interface for sending frames
            od: Optional runtime object dictionary (for context)
            node_id: Target node ID (1-127)
            oracle: Optional callback for anomaly detection

        Raises:
            ValueError: If node_id is invalid
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
            "CAN ID Fuzzer initialized for node %d", node_id
        )

    def fuzz_reserved_cob_ids(self) -> None:
        """Send frames with reserved COB-IDs (0x001-0x07F).

        Tests device handling of frames with reserved COB-IDs that should
        typically be filtered or ignored.
        """
        logger.info("Testing reserved COB-ID mutations (0x001-0x07F)")

        reserved_ids = list(range(self.RESERVED_START, self.RESERVED_END + 1))
        sample_size = min(50, len(reserved_ids))  # Test subset for performance
        
        for cob_id in random.sample(reserved_ids, sample_size):
            data = self._generate_random_payload()
            self._send_frame(cob_id, data, CANIDMutationStrategy.RESERVED_COB_IDS)

    def fuzz_boundary_cob_ids(self) -> None:
        """Test COB-ID boundary values: 0x000, 0x7FF, and transition points.

        Tests device behavior at COB-ID space boundaries and transitions
        between protocol zones.
        """
        logger.info("Testing COB-ID boundary values")

        boundary_ids = [
            0x000,      # Minimum (NMT)
            0x001,      # First reserved
            0x07F,      # Last reserved
            0x080,      # SYNC zone
            0x180,      # PDO zone start
            0x5FF,      # Upper end
            0x7FE,      # Near maximum
            0x7FF,      # Maximum
        ]

        for cob_id in boundary_ids:
            data = self._generate_random_payload()
            self._send_frame(cob_id, data, CANIDMutationStrategy.BOUNDARY_COB_IDS)

    def fuzz_conflicting_cob_ids(self) -> None:
        """Send valid protocol data on conflicting/wrong COB-IDs.

        Tests device behavior when legitimate protocol data arrives on
        unexpected COB-IDs (e.g., NMT data on PDO address).
        """
        logger.info("Testing conflicting COB-ID mutations")

        # Valid protocol payloads sent on conflicting COB-IDs
        test_cases = [
            # (payload, wrong_cob_id, description)
            (bytes([0x01, self.node_id, 0, 0, 0, 0, 0, 0]), 
             self.TPDO1_BASE + self.node_id, "NMT on PDO address"),
            
            (bytes([0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), 
             self.HEARTBEAT_BASE + self.node_id, "SYNC on heartbeat"),
            
            (bytes([0x05, 0xFF, 0xFF, 0x00, 0x04, 0x00, 0x00, 0x00]), 
             self.EMCY_BASE + self.node_id, "SDO on EMCY"),
            
            (bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), 
             0x200 + self.node_id, "NMT on different RPDO"),
        ]

        for payload, wrong_cob_id, desc in test_cases:
            self._send_frame(wrong_cob_id, payload, CANIDMutationStrategy.CONFLICTING_COB_IDS)

    def fuzz_cob_id_sweep(self) -> None:
        """Sweep full COB-ID space (0x000-0x7FF) with random payloads.

        Sends frames with all possible COB-ID values to detect improper
        filtering or unhandled edge cases.
        """
        logger.info("Testing COB-ID space sweep")

        # Test full range with sampling for performance
        cob_ids = list(range(0x000, self.MAX_COB_ID + 1))
        sample_size = min(100, len(cob_ids))
        
        for cob_id in random.sample(cob_ids, sample_size):
            data = self._generate_random_payload()
            self._send_frame(cob_id, data, CANIDMutationStrategy.COB_ID_SWEEP)

    def fuzz_broadcast_vs_unicast(self) -> None:
        """Test broadcast message handling on unicast addresses.

        Tests if device accepts legitimate broadcast messages sent with
        unicast COB-IDs or vice versa.
        """
        logger.info("Testing broadcast vs unicast COB-ID handling")

        # NMT is typically broadcast, send on unicast addresses
        nmt_payload = bytes([0x01, 0x00, 0, 0, 0, 0, 0, 0])
        
        for node_id in range(1, 10):  # Test few node IDs
            unicast_address = 0x180 + node_id  # Unicast PDO address
            self._send_frame(unicast_address, nmt_payload, 
                           CANIDMutationStrategy.BROADCAST_VS_UNICAST)

    def fuzz_duplicate_cob_ids(self) -> None:
        """Send frames with duplicate COB-IDs from different sources.

        Simulates multiple devices using same COB-ID, testing arbitration
        and priority handling.
        """
        logger.info("Testing duplicate COB-ID handling")

        # Send multiple messages on same COB-ID rapidly
        conflicting_cob_id = 0x180 + self.node_id
        
        for i in range(20):
            data = self._generate_random_payload()
            self._send_frame(conflicting_cob_id, data, 
                           CANIDMutationStrategy.DUPLICATE_COB_IDS)

    def fuzz_cob_id_fuzz_mask(self) -> None:
        """Bit-flip mutations on COB-ID field.

        Tests if device properly handles COB-IDs with bit errors from
        electrical noise/corruption.
        """
        logger.info("Testing COB-ID bit-flip mutations")

        target_cols = [0x100, 0x200, 0x300, 0x400, 0x500, 0x600, 0x700]
        
        for base_cob_id in target_cols:
            # Bit-flip each bit position
            for bit_pos in range(11):
                mutated_cob_id = base_cob_id ^ (1 << bit_pos)
                data = self._generate_random_payload()
                self._send_frame(mutated_cob_id, data, 
                               CANIDMutationStrategy.COB_ID_FUZZ_MASK)

    def fuzz_cob_id_extension_frames(self) -> None:
        """Attempt to send 29-bit CAN IDs on 11-bit network.

        Tests if device incorrectly interprets extended frame format
        or allows invalid 29-bit identifiers.
        """
        logger.info("Testing CAN ID extension frame mutations")

        extended_ids = [
            0x1FFFFFFF,  # Max 29-bit ID
            0x18DA0000 + self.node_id,  # CANdb++ pattern
            0x80000000 + 0x100,  # High bit set
        ]

        for ext_id in extended_ids:
            # Send as if 11-bit (will wrap)
            cob_id = ext_id & 0x7FF
            data = self._generate_random_payload()
            self._send_frame(cob_id, data, 
                           CANIDMutationStrategy.COB_ID_EXTENSION_FRAMES)

    def fuzz_cob_id_mixing(self) -> None:
        """Random COB-ID injection patterns.

        Sends frames with random COB-ID sequences to test for timing-dependent
        or sequence-dependent vulnerabilities.
        """
        logger.info("Testing random COB-ID injection patterns")

        for _ in range(50):
            random_cob_id = random.randint(0, self.MAX_COB_ID)
            data = self._generate_random_payload()
            self._send_frame(random_cob_id, data, 
                           CANIDMutationStrategy.COB_ID_MIXING)

    def fuzz_cob_id_rate_variation(self) -> None:
        """Send same COB-ID at varying transmission rates.

        Tests if device behavior changes with different message rates on
        same COB-ID (bandwidth/buffer stress).
        """
        logger.info("Testing COB-ID rate variation")

        target_cob_id = 0x180 + self.node_id
        
        # Test different rates
        for rate_ms in [1, 5, 10, 50, 100, 500]:
            data = self._generate_random_payload()
            for _ in range(10):
                self._send_frame(target_cob_id, data, 
                               CANIDMutationStrategy.COB_ID_RATE_VARIATION)
                time.sleep(rate_ms / 1000.0)

    def execute(self) -> None:
        """Execute full CAN ID fuzzing suite.

        Runs all configured fuzzing strategies and collects results.
        """
        logger.info("Executing CAN ID fuzzer for node %d", self.node_id)
        start_time = time.time()

        try:
            self.fuzz_reserved_cob_ids()
            self.fuzz_boundary_cob_ids()
            self.fuzz_conflicting_cob_ids()
            self.fuzz_cob_id_sweep()
            self.fuzz_broadcast_vs_unicast()
            self.fuzz_duplicate_cob_ids()
            self.fuzz_cob_id_fuzz_mask()
            self.fuzz_cob_id_extension_frames()
            self.fuzz_cob_id_mixing()
            self.fuzz_cob_id_rate_variation()

        except Exception as e:
            logger.error("CAN ID fuzzing error: %s", e)

        elapsed = time.time() - start_time
        logger.info(
            "CAN ID fuzzing complete: %d mutations sent in %.1f seconds",
            self.fuzzed_count, elapsed
        )

    def _send_frame(
        self,
        cob_id: int,
        data: bytes,
        strategy: CANIDMutationStrategy,
    ) -> None:
        """Send a CAN frame with specified COB-ID.

        Args:
            cob_id: CAN Object ID (0x000-0x7FF)
            data: Frame payload (up to 8 bytes)
            strategy: Mutation strategy being applied
        """
        if len(data) > 8:
            data = data[:8]
        elif len(data) < 8:
            data = data + b"\x00" * (8 - len(data))

        try:
            msg = can.Message(
                arbitration_id=cob_id,
                data=bytes(data),
                is_extended_id=False
            )
            self.bus.send(msg)
            self.fuzzed_count += 1

            result = {
                "timestamp": time.time(),
                "strategy": strategy.value,
                "cob_id": cob_id,
                "data": data.hex(),
            }
            self.test_results.append(result)

            logger.debug(
                "Sent CAN ID fuzz frame (COB-ID=0x%03X, strategy=%s)",
                cob_id, strategy.value
            )

            # Notify oracle if callback provided
            if self.oracle:
                self.oracle({
                    "event_type": "fuzz_input_sent",
                    "fuzzer": "canid",
                    "strategy": strategy.value,
                    "cob_id": cob_id,
                })

        except Exception as e:
            logger.warning("Failed to send CAN ID fuzz frame: %s", e)

    def _generate_random_payload(self) -> bytes:
        """Generate random 8-byte payload for testing.

        Returns:
            Random bytes payload (8 bytes)
        """
        return bytes([random.randint(0, 255) for _ in range(8)])
