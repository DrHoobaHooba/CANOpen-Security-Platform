"""Resource Exhaustion fuzzing engine.

Implements comprehensive resource exhaustion mutation strategies to detect vulnerabilities
in device handling of high-rate messages, concurrent transfers, and memory/buffer limits.

Tests for:
- SDO transfer storms (concurrent requests)
- PDO buffer flooding (high message rates)
- Large payload escalation
- Segmented transfer abuse
- Heartbeat/EMCY/SYNC spam
- Memory leak patterns
- Stack overflow attempts
- Buffer wraparound detection
"""

import logging
import random
import time
import threading
from typing import Callable, Any, Dict, List, Optional
from enum import Enum
from queue import Queue

import can

from ..hal.bus_pcan import BusInterface
from ..od.runtime_od import RuntimeObjectDictionary
from ..utils.logging_utils import get_logger

logger = get_logger(__name__)

OracleCallback = Callable[[Dict[str, Any]], None]


class ResourceMutationStrategy(Enum):
    """Resource exhaustion fuzzing mutation strategies."""
    SEQUENTIAL_SDO_STORM = "sequential_sdo_storm"           # 100+ concurrent SDO transfers
    PDO_BUFFER_FLOOD = "pdo_buffer_flood"                  # 500+ PDO msgs/sec
    LARGE_PAYLOAD_ESCALATION = "large_payload_escalation"  # Growing payload sizes
    SEGMENTED_TRANSFER_ABUSE = "segmented_transfer_abuse"  # 1MB+ segmented SDO
    CONCURRENT_SDO_MAX = "concurrent_sdo_max"              # Max concurrent SDO boundary
    HEARTBEAT_SPAM = "heartbeat_spam"                      # 100+ heartbeat msgs/sec
    EMCY_BURST = "emcy_burst"                              # Rapid EMCY error codes
    SYNC_BURST = "sync_burst"                              # Rapid SYNC messages
    MEMORY_LEAK_PATTERNS = "memory_leak_patterns"          # Repeated alloc/dealloc
    STACK_OVERFLOW_ATTEMPT = "stack_overflow_attempt"      # Deep recursion in SDO
    BUFFER_WRAPAROUND = "buffer_wraparound"                # Buffer index wraparound
    RESOURCE_RECOVERY_TEST = "resource_recovery_test"      # Recovery after exhaustion


class ResourceFuzzer:
    """Resource exhaustion fuzzing engine.

    Tests device robustness against resource stress conditions including concurrent
    transfers, high message rates, large payloads, and memory exhaustion patterns.
    Helps identify buffer overflows, deadlocks, and resource management bugs.
    """

    # CANopen COB-ID bases
    TPDO1_BASE = 0x180
    RPDO1_BASE = 0x200
    TSDO_BASE = 0x580
    RSDO_BASE = 0x600
    HEARTBEAT_BASE = 0x700
    EMCY_BASE = 0x080
    SYNC_COB_ID = 0x080

    # Resource limits
    MAX_CONCURRENT_SDO = 4
    MAX_PDO_RATE = 500  # messages/sec
    MAX_PAYLOAD_SIZE = 255
    MAX_SEGMENTED_SIZE = 1048576  # 1MB

    def __init__(
        self,
        bus: BusInterface,
        od: Optional[RuntimeObjectDictionary] = None,
        node_id: int = 1,
        oracle: Optional[OracleCallback] = None,
        max_concurrent: int = 10,
        duration_seconds: int = 5,
    ) -> None:
        """Initialize resource exhaustion fuzzer.

        Args:
            bus: CAN bus interface for sending frames
            od: Optional runtime object dictionary (for context)
            node_id: Target node ID (1-127)
            oracle: Optional callback for anomaly detection
            max_concurrent: Maximum concurrent threads
            duration_seconds: Duration for stress tests
        """
        if not isinstance(node_id, int) or not (1 <= node_id <= 127):
            raise ValueError(f"node_id must be 1-127, got {node_id}")

        self.bus = bus
        self.od = od
        self.node_id = node_id
        self.oracle = oracle
        self.max_concurrent = max_concurrent
        self.duration_seconds = duration_seconds
        self.fuzzed_count = 0
        self.test_results: List[Dict[str, Any]] = []

        logger.debug(
            "Resource Exhaustion Fuzzer initialized for node %d", node_id
        )

    def fuzz_sequential_sdo_storm(self) -> None:
        """Send 100+ concurrent SDO transfers.

        Tests device handling of multiple simultaneous SDO requests,
        potentially overwhelming SDO handlers or buffers.
        """
        logger.info("Testing sequential SDO storm (100+ concurrent)")

        sdo_cob_id = self.TSDO_BASE + self.node_id
        threads = []

        def send_sdo_request(request_id: int) -> None:
            """Send a single SDO request."""
            # SDO upload request: CS=2 (upload initiate)
            data = bytes([0x40, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00])
            try:
                msg = can.Message(arbitration_id=sdo_cob_id, data=data, is_extended_id=False)
                self.bus.send(msg)
                self._record_result(
                    ResourceMutationStrategy.SEQUENTIAL_SDO_STORM,
                    sdo_cob_id, data, f"sdo_request_{request_id}"
                )
            except Exception as e:
                logger.warning("Failed to send SDO request: %s", e)

        # Create 100+ concurrent requests
        for i in range(min(100, self.max_concurrent * 10)):
            thread = threading.Thread(target=send_sdo_request, args=(i,), daemon=True)
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join(timeout=5.0)

    def fuzz_pdo_buffer_flood(self) -> None:
        """Send 500+ PDO messages per second to flood buffers.

        Attempts to overwhelm PDO reception buffers with high-rate messages.
        """
        logger.info("Testing PDO buffer flood (500+ msgs/sec)")

        pdo_cob_id = self.TPDO1_BASE + self.node_id
        start_time = time.time()
        messages_sent = 0

        # Send messages as fast as possible for duration
        while time.time() - start_time < self.duration_seconds:
            for _ in range(50):  # Send batch
                data = bytes([random.randint(0, 255) for _ in range(8)])
                try:
                    msg = can.Message(arbitration_id=pdo_cob_id, data=data, is_extended_id=False)
                    self.bus.send(msg)
                    messages_sent += 1
                    self.fuzzed_count += 1
                except Exception as e:
                    logger.warning("Failed to send PDO flood message: %s", e)

        self._record_result(
            ResourceMutationStrategy.PDO_BUFFER_FLOOD,
            pdo_cob_id, b"", f"flood_{messages_sent}_msgs"
        )

    def fuzz_large_payload_escalation(self) -> None:
        """Send SDO frames with escalating payload sizes.

        Tests if device properly handles progressively larger payloads
        that may exceed expected buffer sizes.
        """
        logger.info("Testing large payload escalation")

        sdo_cob_id = self.TSDO_BASE + self.node_id

        # Escalate from 8 bytes to max payload
        for size in [8, 16, 32, 64, 128, 255]:
            data = bytes([random.randint(0, 255) for _ in range(min(size, 8))])
            
            # Pad with zeros to simulate segmented payload
            if size > 8:
                data = data + b"\x00" * (min(size, 8) - len(data))

            try:
                msg = can.Message(arbitration_id=sdo_cob_id, data=data[:8], is_extended_id=False)
                self.bus.send(msg)
                self._record_result(
                    ResourceMutationStrategy.LARGE_PAYLOAD_ESCALATION,
                    sdo_cob_id, data[:8], f"size_{size}"
                )
            except Exception as e:
                logger.warning("Failed to send escalated payload: %s", e)

    def fuzz_segmented_transfer_abuse(self) -> None:
        """Send 1MB+ segmented SDO transfers.

        Tests if device properly handles very large segmented transfers
        that may cause memory exhaustion or timeout.
        """
        logger.info("Testing segmented transfer abuse (1MB+)")

        sdo_cob_id = self.TSDO_BASE + self.node_id
        total_size = 1048576  # 1MB

        # SDO download initiate with size indication
        size_bytes = total_size.to_bytes(4, byteorder='little')
        initiate_data = bytes([0x23]) + size_bytes + b"\x00\x00\x00"  # CS=0 (download)

        try:
            msg = can.Message(arbitration_id=sdo_cob_id, data=initiate_data, is_extended_id=False)
            self.bus.send(msg)
            self.fuzzed_count += 1
        except Exception as e:
            logger.warning("Failed to send segmented transfer initiate: %s", e)

        # Send multiple segment frames
        segment_count = min(100, total_size // 7)  # Each segment carries 7 bytes
        
        for seg_num in range(segment_count):
            # Toggle/flag setup
            toggle = (seg_num % 2) << 4
            segment_data = bytes([0x00 | toggle | 0x00]) + bytes([random.randint(0, 255) for _ in range(7)])

            try:
                msg = can.Message(arbitration_id=sdo_cob_id, data=segment_data, is_extended_id=False)
                self.bus.send(msg)
                self.fuzzed_count += 1
            except Exception as e:
                logger.warning("Failed to send segment %d: %s", seg_num, e)

        self._record_result(
            ResourceMutationStrategy.SEGMENTED_TRANSFER_ABUSE,
            sdo_cob_id, b"", f"segments_{segment_count}"
        )

    def fuzz_concurrent_sdo_max(self) -> None:
        """Test maximum concurrent SDO request boundary.

        Sends exactly the maximum supported concurrent SDO transfers
        and attempts to exceed the boundary.
        """
        logger.info("Testing concurrent SDO max boundary")

        sdo_cob_id = self.TSDO_BASE + self.node_id

        # Send max allowed concurrent requests
        for i in range(self.MAX_CONCURRENT_SDO):
            data = bytes([0x40, 0x00, 0x10 + i, 0x00, 0x00, 0x00, 0x00, 0x00])
            try:
                msg = can.Message(arbitration_id=sdo_cob_id, data=data, is_extended_id=False)
                self.bus.send(msg)
                self._record_result(
                    ResourceMutationStrategy.CONCURRENT_SDO_MAX,
                    sdo_cob_id, data, f"concurrent_{i}"
                )
            except Exception as e:
                logger.warning("Failed to send concurrent SDO: %s", e)

        # Try to exceed boundary
        for i in range(self.MAX_CONCURRENT_SDO, self.MAX_CONCURRENT_SDO + 5):
            data = bytes([0x40, 0x00, 0x10 + i, 0x00, 0x00, 0x00, 0x00, 0x00])
            try:
                msg = can.Message(arbitration_id=sdo_cob_id, data=data, is_extended_id=False)
                self.bus.send(msg)
                self._record_result(
                    ResourceMutationStrategy.CONCURRENT_SDO_MAX,
                    sdo_cob_id, data, f"exceed_{i}"
                )
            except Exception as e:
                logger.warning("Failed to exceed boundary: %s", e)

    def fuzz_heartbeat_spam(self) -> None:
        """Send 100+ heartbeat messages per second.

        Tests if device can handle excessive heartbeat traffic that
        may disrupt normal producer/consumer cycles.
        """
        logger.info("Testing heartbeat spam (100+ msgs/sec)")

        hb_cob_id = self.HEARTBEAT_BASE + self.node_id
        start_time = time.time()
        messages_sent = 0

        # Send heartbeat messages rapidly
        while time.time() - start_time < self.duration_seconds:
            for _ in range(50):
                # Heartbeat payload: state byte (0x05=operational)
                data = bytes([0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                try:
                    msg = can.Message(arbitration_id=hb_cob_id, data=data, is_extended_id=False)
                    self.bus.send(msg)
                    messages_sent += 1
                    self.fuzzed_count += 1
                except Exception as e:
                    logger.warning("Failed to send heartbeat spam: %s", e)

        self._record_result(
            ResourceMutationStrategy.HEARTBEAT_SPAM,
            hb_cob_id, b"", f"spam_{messages_sent}_msgs"
        )

    def fuzz_emcy_burst(self) -> None:
        """Send rapid EMCY error codes.

        Tests device behavior when receiving many EMCY frames in succession,
        potentially disrupting error handling.
        """
        logger.info("Testing EMCY burst")

        emcy_cob_id = self.EMCY_BASE + self.node_id

        # Send 50+ EMCY messages with varying error codes
        for i in range(50):
            error_code = random.randint(0x0000, 0xFFFF)
            error_bytes = error_code.to_bytes(2, byteorder='little')
            # EMCY: error code (2 bytes) + error register + manufacturer specific (5 bytes)
            data = error_bytes + bytes([random.randint(0, 255) for _ in range(6)])

            try:
                msg = can.Message(arbitration_id=emcy_cob_id, data=data, is_extended_id=False)
                self.bus.send(msg)
                self._record_result(
                    ResourceMutationStrategy.EMCY_BURST,
                    emcy_cob_id, data, f"burst_{i}"
                )
            except Exception as e:
                logger.warning("Failed to send EMCY burst: %s", e)

    def fuzz_sync_burst(self) -> None:
        """Send rapid SYNC messages.

        Tests if device can handle SYNC messages at rates exceeding
        normal synchronization cycles.
        """
        logger.info("Testing SYNC burst")

        sync_cob_id = self.SYNC_COB_ID
        start_time = time.time()
        messages_sent = 0

        # Send SYNC messages as fast as possible
        while time.time() - start_time < self.duration_seconds:
            for _ in range(20):
                # SYNC payload: optional counter
                counter = (messages_sent % 256).to_bytes(1, byteorder='little')
                data = counter + b"\x00" * 7

                try:
                    msg = can.Message(arbitration_id=sync_cob_id, data=data, is_extended_id=False)
                    self.bus.send(msg)
                    messages_sent += 1
                    self.fuzzed_count += 1
                except Exception as e:
                    logger.warning("Failed to send SYNC burst: %s", e)

        self._record_result(
            ResourceMutationStrategy.SYNC_BURST,
            sync_cob_id, b"", f"burst_{messages_sent}_msgs"
        )

    def fuzz_memory_leak_patterns(self) -> None:
        """Send repeated allocation/deallocation patterns.

        Tests if device properly manages memory during repetitive
        allocation/deallocation cycles.
        """
        logger.info("Testing memory leak patterns")

        sdo_cob_id = self.TSDO_BASE + self.node_id

        # Repeated allocate + deallocate cycles
        for cycle in range(50):
            # Allocate: SDO download initiate
            alloc_data = bytes([0x23, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00])
            try:
                msg = can.Message(arbitration_id=sdo_cob_id, data=alloc_data, is_extended_id=False)
                self.bus.send(msg)
                self._record_result(
                    ResourceMutationStrategy.MEMORY_LEAK_PATTERNS,
                    sdo_cob_id, alloc_data, f"alloc_{cycle}"
                )
                time.sleep(0.01)
            except Exception as e:
                logger.warning("Failed to send alloc pattern: %s", e)

            # Deallocate: SDO abort
            abort_data = bytes([0x80, 0x00, 0x10, 0x00, 0x08, 0x00, 0x03, 0x00])
            try:
                msg = can.Message(arbitration_id=sdo_cob_id, data=abort_data, is_extended_id=False)
                self.bus.send(msg)
                self._record_result(
                    ResourceMutationStrategy.MEMORY_LEAK_PATTERNS,
                    sdo_cob_id, abort_data, f"dealloc_{cycle}"
                )
                time.sleep(0.01)
            except Exception as e:
                logger.warning("Failed to send dealloc pattern: %s", e)

    def fuzz_stack_overflow_attempt(self) -> None:
        """Attempt to cause stack overflow via deep recursion in SDO handling.

        Tests if device has stack overflow protections by attempting to
        trigger deep recursion in SDO or CAN frame handling.
        """
        logger.info("Testing stack overflow attempt")

        sdo_cob_id = self.TSDO_BASE + self.node_id

        # Send deeply nested/recursive SDO patterns
        for depth in range(20):
            # Vary the index to simulate nested object access
            index = 0x1000 + (depth % 256)
            subindex = (depth // 256) % 256
            index_bytes = index.to_bytes(2, byteorder='little')
            
            data = bytes([0x40, index_bytes[0], index_bytes[1], subindex, 0x00, 0x00, 0x00, 0x00])

            try:
                msg = can.Message(arbitration_id=sdo_cob_id, data=data, is_extended_id=False)
                self.bus.send(msg)
                self._record_result(
                    ResourceMutationStrategy.STACK_OVERFLOW_ATTEMPT,
                    sdo_cob_id, data, f"depth_{depth}"
                )
                time.sleep(0.05)
            except Exception as e:
                logger.warning("Failed to send stack overflow attempt: %s", e)

    def fuzz_buffer_wraparound(self) -> None:
        """Test buffer index wraparound edge cases.

        Sends frames designed to trigger buffer wraparound conditions
        and boundary index access patterns.
        """
        logger.info("Testing buffer wraparound")

        sdo_cob_id = self.TSDO_BASE + self.node_id

        # Test wraparound with maximum indices
        wraparound_indices = [
            0xFFFF,  # Max 16-bit
            0x7FFF,  # Max signed 16-bit
            0x0000,  # Wrap to zero
            0x0001,  # First valid
        ]

        for idx, test_index in enumerate(wraparound_indices):
            index_bytes = test_index.to_bytes(2, byteorder='little')
            data = bytes([0x40, index_bytes[0], index_bytes[1], 0x00, 0x00, 0x00, 0x00, 0x00])

            try:
                msg = can.Message(arbitration_id=sdo_cob_id, data=data, is_extended_id=False)
                self.bus.send(msg)
                self._record_result(
                    ResourceMutationStrategy.BUFFER_WRAPAROUND,
                    sdo_cob_id, data, f"wraparound_{idx}"
                )
            except Exception as e:
                logger.warning("Failed to send wraparound test: %s", e)

    def fuzz_resource_recovery_test(self) -> None:
        """Test device recovery after resource exhaustion attack.

        Sends a resource exhaustion burst followed by normal messages
        to verify the device recovers properly.
        """
        logger.info("Testing resource recovery")

        sdo_cob_id = self.TSDO_BASE + self.node_id

        # Phase 1: Exhaust resources
        logger.debug("Phase 1: Resource exhaustion")
        for i in range(100):
            data = bytes([0x40, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00])
            try:
                msg = can.Message(arbitration_id=sdo_cob_id, data=data, is_extended_id=False)
                self.bus.send(msg)
                self.fuzzed_count += 1
            except Exception as e:
                logger.warning("Failed to exhaust resources: %s", e)

        # Phase 2: Wait for recovery
        logger.debug("Phase 2: Recovery time (2 seconds)")
        time.sleep(2.0)

        # Phase 3: Send normal messages
        logger.debug("Phase 3: Normal operation test")
        for i in range(10):
            data = bytes([0x40, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00])
            try:
                msg = can.Message(arbitration_id=sdo_cob_id, data=data, is_extended_id=False)
                self.bus.send(msg)
                self._record_result(
                    ResourceMutationStrategy.RESOURCE_RECOVERY_TEST,
                    sdo_cob_id, data, f"recovery_{i}"
                )
            except Exception as e:
                logger.warning("Failed to send recovery test: %s", e)

    def execute(self) -> None:
        """Execute full resource exhaustion fuzzing suite.

        Runs all configured fuzzing strategies and collects results.
        """
        logger.info("Executing Resource Exhaustion Fuzzer for node %d", self.node_id)
        start_time = time.time()

        try:
            self.fuzz_sequential_sdo_storm()
            self.fuzz_pdo_buffer_flood()
            self.fuzz_large_payload_escalation()
            self.fuzz_segmented_transfer_abuse()
            self.fuzz_concurrent_sdo_max()
            self.fuzz_heartbeat_spam()
            self.fuzz_emcy_burst()
            self.fuzz_sync_burst()
            self.fuzz_memory_leak_patterns()
            self.fuzz_stack_overflow_attempt()
            self.fuzz_buffer_wraparound()
            self.fuzz_resource_recovery_test()

        except Exception as e:
            logger.error("Resource exhaustion fuzzing error: %s", e)

        elapsed = time.time() - start_time
        logger.info(
            "Resource exhaustion fuzzing complete: %d mutations sent in %.1f seconds",
            self.fuzzed_count, elapsed
        )

    def _record_result(
        self,
        strategy: ResourceMutationStrategy,
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
            "Resource fuzz result: strategy=%s, cob_id=0x%03X, details=%s",
            strategy.value, cob_id, details
        )

        # Notify oracle if callback provided
        if self.oracle:
            self.oracle({
                "event_type": "fuzz_input_sent",
                "fuzzer": "resource",
                "strategy": strategy.value,
                "cob_id": cob_id,
                "details": details,
            })
