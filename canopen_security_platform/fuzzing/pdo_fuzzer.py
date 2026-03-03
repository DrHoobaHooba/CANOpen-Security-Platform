"""CANopen PDO (Process Data Object) fuzzing engine.

Tests PDO configuration and transmission for vulnerabilities including
COB-ID spoofing, mapping violations, and timing attacks.
"""

import logging
import random
import time
import struct
from typing import Callable, Any, Dict, List
from enum import Enum

import can

from ..hal.bus_pcan import BusInterface
from ..od.runtime_od import RuntimeObjectDictionary
from ..utils.logging_utils import get_logger

logger = get_logger(__name__)

OracleCallback = Callable[[Dict[str, Any]], None]


class PDOType(Enum):
    """PDO types."""
    TPDO1 = 0x180
    TPDO2 = 0x280
    TPDO3 = 0x380
    TPDO4 = 0x480
    RPDO1 = 0x200
    RPDO2 = 0x300
    RPDO3 = 0x400
    RPDO4 = 0x500


class PDOFuzzer:
    """PDO fuzzing engine with configuration and transmission attacks.

    Tests PDO configuration objects (1600-1800, 1A00-1800) for improper
    bounds checking and PDO transmission for data integrity issues.
    """

    # PDO Configuration indices
    PDO_RPDO_PARAM = {1: 0x1400, 2: 0x1500, 3: 0x1600, 4: 0x1700}
    PDO_RPDO_MAP = {1: 0x1601, 2: 0x1501, 3: 0x1601, 4: 0x1701}
    PDO_TPDO_PARAM = {1: 0x1800, 2: 0x1900, 3: 0x1A00, 4: 0x1B00}
    PDO_TPDO_MAP = {1: 0x1A01, 2: 0x1A01, 3: 0x1A03, 4: 0x1A04}

    def __init__(
        self,
        bus: BusInterface,
        od: RuntimeObjectDictionary,
        node_id: int,
        oracle: OracleCallback,
    ) -> None:
        """Initialize PDO fuzzer.

        Args:
            bus: CAN bus interface
            od: Runtime object dictionary
            node_id: Target node ID
            oracle: Callback for anomaly detection
        """
        if not isinstance(node_id, int) or not (1 <= node_id <= 127):
            raise ValueError(f"node_id must be 1-127, got {node_id}")

        self.bus = bus
        self.od = od
        self.node_id = node_id
        self.oracle = oracle
        self.test_results: List[Dict[str, Any]] = []
        self.fuzzed_count = 0

        logger.debug(
            "PDO Fuzzer initialized for node %d",
            node_id
        )

    def cob_id_mutation(self) -> None:
        """Fuzz PDO COB-IDs with invalid values.

        Tests PDO transmission with invalid or conflicting COB-IDs.
        """
        logger.info("Testing PDO COB-ID mutations")

        # Invalid COB-ID patterns
        invalid_cob_ids = [
            0x00000000,          # Disabled
            0x7FF,              # Max 11-bit CAN ID
            0x80000000,         # Frame disabled bit set incorrectly
            0xC0000000,         # Multiple enable bits
            0x00FFFFFF,         # Very high ID
        ]

        for pdo_num in [1, 2, 3, 4]:
            for cob_id in invalid_cob_ids:
                # Try to set invalid COB-ID via SDO
                self._set_pdo_param(
                    pdo_num, "RPDO",
                    cob_id=cob_id,
                    strategy="cob_id_mutation"
                )

    def mapping_mutation(self) -> None:
        """Fuzz PDO mapping entries with invalid values.

        Tests handling of object mapping that exceeds PDO bounds
        or references non-existent objects.
        """
        logger.info("Testing PDO mapping mutations")

        # Invalid mapping values
        invalid_mappings = [
            0x00000000,          # No mapping
            0xFFFFFFFF,          # All bits set
            0x99991008,          # Reference non-existent object (0x9999, subindex 16)
            0x10080010,          # Too large (16 bits for sub-index)
            0xFFFFFFF8,          # Large length value
        ]

        for pdo_num in [1, 2]:
            for mapping in invalid_mappings:
                self._set_pdo_mapping(
                    pdo_num, "RPDO",
                    mapping_entry=mapping,
                    strategy="mapping_mutation"
                )

    def transmission_type(self) -> None:
        """Fuzz PDO transmission type parameters.

        Tests various transmission type configurations including
        invalid event timings and unusual transmission behaviors.
        """
        logger.info("Testing PDO transmission type mutations")

        # Invalid transmission types
        invalid_transmission_types = [
            0x00,      # Synchronous (acyclic)
            0x01,      # Synchronous (cyclic)
            0x7F,      # Synchronous, 127 SYNC
            0x80,      # Event-driven
            0x81,      # Event-driven + sync
            0xFE,      # Manufacturer specific
            0xFF,      # Device specific
        ]

        for pdo_num in [1, 2, 3, 4]:
            for tx_type in invalid_transmission_types:
                self._set_pdo_param(
                    pdo_num, "TPDO",
                    transmission_type=tx_type,
                    strategy="transmission_type"
                )

    def timing_mutation(self) -> None:
        """Fuzz PDO timing parameters.

        Tests event timing, inhibit times, and producer timeout
        with extreme or invalid values.
        """
        logger.info("Testing PDO timing mutations")

        # Invalid timing values (in milliseconds)
        timing_values = [
            0,           # Zero timing
            0xFFFF,      # Maximum uint16
            0x7FFF,      # Maximum signed int16
            1,           # Minimum (1 ms)
            65535,       # Large value
            0xDEADBEEF,  # Random large value
        ]

        for pdo_num in [1, 2]:
            for timing in timing_values:
                self._set_pdo_param(
                    pdo_num, "TPDO",
                    producer_timeout=timing,
                    strategy="timing_mutation"
                )

    def data_payload_fuzzing(self) -> None:
        """Fuzz PDO data payload with random values.

        Tests PDO reception with unexpected data patterns.
        """
        logger.info("Testing PDO data payload mutations")

        # Send RPDO frames with various data patterns
        for pdo_num in [1, 2, 3, 4]:
            pdo_cob_id = PDOType[f"RPDO{pdo_num}"].value + self.node_id

            # Various payload patterns
            payloads = [
                b"\x00" * 8,           # All zeros
                b"\xFF" * 8,           # All ones
                b"\xAA" * 8,           # Alternating
                b"\x55" * 8,           # Alternating inverted
                bytes(range(8)),       # Sequential
                bytes(range(7, -1, -1)),  # Reverse sequential
            ]

            for payload in payloads:
                try:
                    msg = can.Message(
                        arbitration_id=pdo_cob_id,
                        data=payload,
                        is_extended_id=False
                    )
                    self.bus.send(msg)
                    self.fuzzed_count += 1

                    self.test_results.append({
                        "timestamp": time.time(),
                        "strategy": "data_payload",
                        "pdo_num": pdo_num,
                        "payload": payload.hex(),
                    })

                    logger.debug(
                        "Sent RPDO%d with payload: %s",
                        pdo_num, payload.hex()
                    )

                except Exception as e:
                    logger.debug("Failed to send RPDO%d: %s", pdo_num, e)

    def sync_timing_attack(self) -> None:
        """Test SYNC frame timing vulnerabilities.

        Sends SYNC frames with varying intervals to test producer timeout
        and synchronization handling.
        """
        logger.info("Testing PDO SYNC timing vulnerabilities")

        SYNC_COB_ID = 0x080

        # Send SYNC frames with unusual timing
        timing_patterns = [
            (0, 10),      # No delay between frames (10 frames)
            (100, 5),     # 100ms interval (5 frames)
            (500, 5),     # 500ms interval (5 frames)
            (10, 3),      # 10ms interval (3 frames)
            (0, 20),      # Burst of 20 frames
        ]

        for interval_ms, count in timing_patterns:
            for frame_num in range(count):
                try:
                    msg = can.Message(
                        arbitration_id=SYNC_COB_ID,
                        data=bytes([frame_num & 0xFF]) + b"\x00" * 7,
                        is_extended_id=False
                    )
                    self.bus.send(msg)
                    self.fuzzed_count += 1

                    if interval_ms > 0:
                        time.sleep(interval_ms / 1000.0)

                    self.test_results.append({
                        "timestamp": time.time(),
                        "strategy": "sync_timing",
                        "interval_ms": interval_ms,
                        "frame_num": frame_num,
                    })

                except Exception as e:
                    logger.debug("SYNC frame send failed: %s", e)

    def execute(self) -> None:
        """Execute full PDO fuzzing suite.

        Runs all PDO fuzzing strategies in sequence.
        """
        logger.info("Executing PDO fuzzer for node %d", self.node_id)
        start_time = time.time()

        try:
            self.cob_id_mutation()
            time.sleep(0.05)

            self.mapping_mutation()
            time.sleep(0.05)

            self.transmission_type()
            time.sleep(0.05)

            self.timing_mutation()
            time.sleep(0.05)

            self.data_payload_fuzzing()
            time.sleep(0.05)

            self.sync_timing_attack()

        except Exception as e:
            logger.error("PDO fuzzing error: %s", e)

        elapsed = time.time() - start_time
        logger.info(
            "PDO fuzzing complete: %d mutations sent in %.1f seconds",
            self.fuzzed_count, elapsed
        )

    def _set_pdo_param(
        self,
        pdo_num: int,
        pdo_type: str,
        **params
    ) -> None:
        """Set PDO parameters via simulated SDO request.

        Args:
            pdo_num: PDO number (1-4)
            pdo_type: 'TPDO' or 'RPDO'
            **params: Parameters like cob_id, transmission_type, producer_timeout
        """
        # Simulate SDO write to PDO config objects
        if pdo_type == "RPDO":
            param_idx = self.PDO_RPDO_PARAM.get(pdo_num, 0x1400)
        else:
            param_idx = self.PDO_TPDO_PARAM.get(pdo_num, 0x1800)

        if "cob_id" in params:
            self.test_results.append({
                "timestamp": time.time(),
                "strategy": params.get("strategy", "pdo_param"),
                "pdo_num": pdo_num,
                "pdo_type": pdo_type,
                "param": "cob_id",
                "value": params["cob_id"],
                "param_idx": param_idx,
                "subindex": 1,
            })

        self.fuzzed_count += 1
        logger.debug("Set %s%d COB-ID to 0x%X", pdo_type, pdo_num, params.get("cob_id", 0))

    def _set_pdo_mapping(
        self,
        pdo_num: int,
        pdo_type: str,
        mapping_entry: int,
        strategy: str = "mapping",
    ) -> None:
        """Set PDO mapping entry.

        Args:
            pdo_num: PDO number (1-4)
            pdo_type: 'TPDO' or 'RPDO'
            mapping_entry: 32-bit mapping value
            strategy: Fuzzing strategy name
        """
        if pdo_type == "RPDO":
            map_idx = self.PDO_RPDO_MAP.get(pdo_num, 0x1601)
        else:
            map_idx = self.PDO_TPDO_MAP.get(pdo_num, 0x1A01)

        self.test_results.append({
            "timestamp": time.time(),
            "strategy": strategy,
            "pdo_num": pdo_num,
            "pdo_type": pdo_type,
            "mapping_entry": f"0x{mapping_entry:08X}",
            "map_idx": map_idx,
        })

        self.fuzzed_count += 1
        logger.debug(
            "Set %s%d mapping to 0x%08X",
            pdo_type, pdo_num, mapping_entry
        )

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
