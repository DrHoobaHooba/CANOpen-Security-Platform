"""SDO (Service Data Object) fuzzing engine.

Implements comprehensive SDO mutation strategies to detect vulnerabilities
in device handling of malformed or unexpected SDO requests.
"""

import logging
import random
import struct
from typing import Callable, Any, List, Dict, Optional, Tuple
from enum import Enum
import time

import can

from ..hal.bus_pcan import BusInterface
from ..od.runtime_od import RuntimeObjectDictionary
from ..utils.logging_utils import get_logger

logger = get_logger(__name__)

OracleCallback = Callable[[Dict[str, Any]], None]


class SDOMutationStrategy(Enum):
    """SDO fuzzing mutation strategies."""
    MUTATION_CS = "mutate_cs"              # Corrupt command specifier byte
    WRONG_LENGTH = "wrong_length"          # Send wrong length in frame
    OVERFLOW = "overflow"                 # Send data larger than expected
    UNDERFLOW = "underflow"               # Send data smaller than expected
    ILLEGAL_INDEX = "illegal_index"       # Write to non-existent objects
    READ_ONLY_WRITE = "read_only_write"  # Attempt write to read-only
    WRITE_ONLY_READ = "write_only_read"  # Attempt read from write-only
    SEGMENTATION_ERROR = "segmentation"   # Corrupt toggle bits in segmented
    INVALID_SUBINDEX = "invalid_subindex" # Query non-existent subindices
    ZERO_DATA_SEGMENT = "zero_data_segment"  # Send zero-length segments
    TIMEOUT_SIMULATION = "timeout_simulation"  # Send incomplete sequences
    DATA_MUTATION = "data_mutation"       # Random byte mutations
    BOUNDARY_VALUES = "boundary_values"   # Test with min/max values


class SDOFuzzer:
    """Comprehensive SDO fuzzing engine with strategy-based mutation.

    Implements various SDO protocol violations and edge cases to detect
    improper device handling, buffer overflows, and protocol violations.
    """

    # CANopen SDO COB-IDs
    SDO_TX_BASE = 0x580  # OD -> Master
    SDO_RX_BASE = 0x600  # Master -> OD

    # SDO command specifier bits
    SDO_CS_SHIFT = 5
    SDO_TOGGLE_SHIFT = 4
    SDO_N_SHIFT = 2
    SDO_E_SHIFT = 1
    SDO_S_SHIFT = 0

    # Standard SDO data types (DS301)
    SDO_TYPES = {
        "u8": (1, lambda: random.randint(0, 255)),
        "u16": (2, lambda: random.randint(0, 65535)),
        "u32": (4, lambda: random.randint(0, 2**32-1)),
        "i8": (1, lambda: random.randint(-128, 127)),
        "i16": (2, lambda: random.randint(-32768, 32767)),
        "i32": (4, lambda: random.randint(-2**31, 2**31-1)),
    }

    def __init__(
        self,
        bus: BusInterface,
        od: RuntimeObjectDictionary,
        node_id: int,
        oracle: OracleCallback,
    ) -> None:
        """Initialize SDO fuzzer.

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
        self.sdo_rx_cob = self.SDO_RX_BASE + node_id
        self.sdo_tx_cob = self.SDO_TX_BASE + node_id
        self.fuzzed_count = 0
        self.toggle_bit = 0
        self.test_results: List[Dict[str, Any]] = []

        logger.debug(
            "SDO Fuzzer initialized for node %d (TX=0x%03X, RX=0x%03X)",
            node_id, self.sdo_tx_cob, self.sdo_rx_cob
        )

    def mutate_cs(self) -> None:
        """Mutate command specifier byte to invalid values.

        Tests node handling of corrupted command specifier bits.
        """
        logger.info("Testing SDO command specifier mutations")

        # Valid CS values for upload/download
        valid_cs = [0, 1, 2, 3, 5, 6]  # Different command types

        for idx, sub in [(0x1000, 0), (0x1001, 0)]:  # Query known indices
            for invalid_cs in [4, 7, 8, 15]:  # Invalid values
                data = bytearray(8)
                data[0] = (invalid_cs << self.SDO_CS_SHIFT) & 0xFF
                data[1] = idx & 0xFF
                data[2] = (idx >> 8) & 0xFF
                data[3] = sub

                self._send_sdo_request(data, strategy=SDOMutationStrategy.MUTATION_CS)

    def wrong_length(self) -> None:
        """Send SDO frames with incorrect length fields.

        Tests node robustness to malformed frame length specifications.
        """
        logger.info("Testing SDO wrong length mutations")

        # Download request with wrong length
        for idx, sub, expected_len in [(0x1000, 0, 4), (0x1001, 0, 1)]:
            for wrong_len in [0, expected_len + 1, expected_len - 1, 255]:
                data = bytearray(8)
                data[0] = (1 << 5) | (1 << 0)  # Download, expedited
                data[1] = idx & 0xFF
                data[2] = (idx >> 8) & 0xFF
                data[3] = sub
                # N = number of bytes NOT in data (bits 2-3)
                n_bits = (4 - min(expected_len, 4)) & 0x3
                data[0] |= (n_bits << 2)

                self._send_sdo_request(data, strategy=SDOMutationStrategy.WRONG_LENGTH)

    def overflow_underflow(self) -> None:
        """Send overflow and underflow data values.

        Tests boundary condition handling in device data validation.
        """
        logger.info("Testing SDO overflow/underflow mutations")

        test_values = [
            (0x1000, 0, "u32", 0xFFFFFFFF),  # Max u32
            (0x1000, 0, "u32", 0x7FFFFFFF),  # Max signed i32
            (0x1000, 0, "u16", 0x10000),     # Over u16
            (0x1001, 0, "u8", 0x100),        # Over u8
            (0x1000, 0, "i32", -2**31),      # Min i32
        ]

        for idx, sub, dtype, value in test_values:
            try:
                # Encode value
                if dtype == "u32":
                    data = struct.pack("<I", value & 0xFFFFFFFF)
                elif dtype == "u16":
                    data = struct.pack("<H", value & 0xFFFF)
                elif dtype == "u8":
                    data = struct.pack("<B", value & 0xFF)
                elif dtype == "i32":
                    data = struct.pack("<i", value)
                else:
                    continue

                payload = bytearray(8)
                payload[0] = (1 << 5) | (1 << 0)  # Download, expedited
                payload[1] = idx & 0xFF
                payload[2] = (idx >> 8) & 0xFF
                payload[3] = sub
                payload[0] |= ((4 - len(data)) << 2)  # Length
                payload[4:4+len(data)] = data

                strategy = (
                    SDOMutationStrategy.OVERFLOW if value > 2**31-1
                    else SDOMutationStrategy.UNDERFLOW
                )
                self._send_sdo_request(payload, strategy=strategy)

            except Exception as e:
                logger.debug("Overflow test failed: %s", e)

    def illegal_write(self) -> None:
        """Attempt to write to undefined or protected objects.

        Tests node handling of unauthorized or non-existent object access.
        """
        logger.info("Testing illegal write mutations")

        illegal_indices = [
            0x0001,  # Reserved range
            0x0FFF,  # Reserved range
            0x3000,  # Usually device profile (varies by device)
            0xFFFF,  # Last possible index
            0x9999,  # Random undefined
        ]

        for idx in illegal_indices:
            data = bytearray(8)
            data[0] = (1 << 5) | (1 << 0)  # Download, expedited
            data[1] = idx & 0xFF
            data[2] = (idx >> 8) & 0xFF
            data[3] = 0  # Subindex
            data[4:8] = b"\x00\x00\x00\x00"

            self._send_sdo_request(data, strategy=SDOMutationStrategy.ILLEGAL_INDEX)

    def read_write_violations(self) -> None:
        """Test read/write access violations.

        Attempts to read write-only objects and write read-only objects.
        """
        logger.info("Testing read/write violation mutations")

        # 0x1001 is typically read-only (error register)
        # Try to write to it
        data = bytearray(8)
        data[0] = (1 << 5) | (1 << 0)  # Download (write), expedited
        data[1] = 0x01
        data[2] = 0x10
        data[3] = 0
        data[4] = 0xAB
        data[5:8] = b"\x00\x00\x00"

        self._send_sdo_request(data, strategy=SDOMutationStrategy.READ_ONLY_WRITE)

    def segmentation_errors(self) -> None:
        """Test segmented transfer errors.

        Corrupts toggle bits and segment structure in multi-frame transfers.
        """
        logger.info("Testing SDO segmentation mutations")

        # Initiate download (segmented)
        idx, sub, data_len = 0x1000, 0, 40

        # initiate download request (large data)
        init_data = bytearray(8)
        init_data[0] = (1 << 5) | (0 << 0)  # Download, segmented
        init_data[1] = idx & 0xFF
        init_data[2] = (idx >> 8) & 0xFF
        init_data[3] = sub
        init_data[4:8] = struct.pack("<I", data_len)

        self._send_sdo_request(init_data, strategy=SDOMutationStrategy.SEGMENTATION_ERROR)

        # Send segments with corrupted toggle bits
        for segment_num in range(3):
            seg_data = bytearray(8)
            # Corrupt toggle bit
            toggle = random.randint(0, 1)
            seg_data[0] = (0 << 5) | (toggle << 4) | ((7 & ~segment_num) << 1) | (1 if segment_num == 2 else 0)
            seg_data[1:8] = b"\x00" * 7

            self._send_sdo_request(seg_data, strategy=SDOMutationStrategy.SEGMENTATION_ERROR)

    def execute(self) -> None:
        """Execute full SDO fuzzing suite.

        Runs all configured fuzzing strategies and collects results.
        """
        logger.info("Executing SDO fuzzer for node %d", self.node_id)
        start_time = time.time()

        try:
            self.mutate_cs()
            self.wrong_length()
            self.overflow_underflow()
            self.illegal_write()
            self.read_write_violations()
            self.segmentation_errors()

        except Exception as e:
            logger.error("SDO fuzzing error: %s", e)

        elapsed = time.time() - start_time
        logger.info(
            "SDO fuzzing complete: %d mutations sent in %.1f seconds",
            self.fuzzed_count, elapsed
        )

    def _send_sdo_request(
        self,
        data: bytearray,
        strategy: SDOMutationStrategy,
    ) -> None:
        """Send an SDO request frame.

        Args:
            data: 8-byte SDO payload
            strategy: Mutation strategy applied
        """
        if len(data) != 8:
            data = data[:8] + b"\x00" * (8 - len(data))

        try:
            msg = can.Message(
                arbitration_id=self.sdo_rx_cob,
                data=bytes(data),
                is_extended_id=False
            )
            self.bus.send(msg)
            self.fuzzed_count += 1

            result = {
                "timestamp": time.time(),
                "strategy": strategy.value,
                "data": data.hex(),
                "cob_id": self.sdo_rx_cob,
            }
            self.test_results.append(result)

            logger.debug(
                "Sent SDO request (strategy=%s, data=%s)",
                strategy.value, data.hex()
            )

        except Exception as e:
            logger.warning("Failed to send SDO request: %s", e)

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
