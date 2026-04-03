"""CANopen Concurrent Message fuzzing engine.

Tests for race conditions and state machine confusion caused by
interleaved PDO, SDO, and NMT messages.
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


class ConcurrentFuzzer:
    """Concurrent message fuzzing for race condition detection.

    Tests CANopen devices exposed to concurrent messages from
    different protocols (NMT, PDO, SDO) to identify race conditions,
    state machine confusion, and buffer overflow vulnerabilities.
    """

    def __init__(
        self,
        bus: BusInterface,
        od: RuntimeObjectDictionary,
        node_id: int,
        oracle: OracleCallback,
    ) -> None:
        """Initialize Concurrent fuzzer.

        Args:
            bus: CAN bus interface
            od: Runtime object dictionary
            node_id: Target node ID (1-127)
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
        self.fuzzed_count = 0
        self.test_results: List[Dict[str, Any]] = []
        self._stop_threads = False

        # COB-IDs
        self.nmt_cmd_cob = 0x000
        self.sync_cob = 0x080
        self.pdo1_rx_cob = 0x200 + node_id
        self.pdo1_tx_cob = 0x180 + node_id
        self.sdo_rx_cob = 0x600 + node_id
        self.sdo_tx_cob = 0x580 + node_id

        logger.debug("Concurrent Fuzzer initialized for node %d", node_id)

    def sdо_sdo_interleaving(self) -> None:
        """Fuzz SDO by interrupting transfers with other SDO requests.

        Sends multiple concurrent SDO uploads/downloads to test
        device handling of overlapping SDO transfers.
        """
        logger.info("Testing concurrent SDO interleaving")

        # Create multiple SDO requests to different objects
        requests = [
            (0x1000, 0),   # Device type
            (0x1001, 0),   # Error register
            (0x1002, 0),   # Manufacturer device name
        ]

        toggle_bits = [0, 1, 0, 1]
        request_idx = 0

        for i in range(20):
            obj_idx, obj_sub = requests[request_idx % len(requests)]
            toggle = toggle_bits[i % len(toggle_bits)]

            # SDO upload initiate
            data = bytearray(8)
            data[0] = (2 << 5) | (toggle << 4) | 3  # Upload init, toggle, expedited
            data[1] = obj_idx & 0xFF
            data[2] = (obj_idx >> 8) & 0xFF
            data[3] = obj_sub

            msg = can.Message(
                arbitration_id=self.sdo_rx_cob,
                data=bytes(data),
                is_extended_id=False
            )
            self.bus.send(msg)
            request_idx += 1
            self.fuzzed_count += 1

            time.sleep(0.005)  # 5ms between requests

        logger.info("SDO interleaving test sent %d concurrent messages", 20)

    def sdo_during_pdo_transmission(self) -> None:
        """Send SDO requests while PDO transmission is active.

        Simulates real-world scenario where SDO transfers overlap with
        periodic PDO updates, testing state synchronization.
        """
        logger.info("Testing concurrent SDO during PDO transmission")

        # Thread function to send PDOs
        def send_pdo_stream():
            counter = 0
            start_time = time.time()
            while time.time() - start_time < 0.5 and not self._stop_threads:
                pdo_data = bytearray(8)
                pdo_data[0] = counter & 0xFF
                pdo_data[1:] = [random.randint(0, 255) for _ in range(7)]

                msg = can.Message(
                    arbitration_id=self.pdo1_tx_cob,
                    data=bytes(pdo_data),
                    is_extended_id=False
                )
                self.bus.send(msg)
                counter += 1
                self.fuzzed_count += 1
                time.sleep(0.05)  # PDO every 50ms

        # Thread function to send SDOs
        def send_sdo_stream():
            sdo_requests = [
                (0x1000, 0),
                (0x2000, 0),
                (0x3000, 0),
            ]
            idx = 0
            start_time = time.time()
            while time.time() - start_time < 0.5 and not self._stop_threads:
                obj_idx, obj_sub = sdo_requests[idx % len(sdo_requests)]
                toggle = (idx // len(sdo_requests)) % 2

                data = bytearray(8)
                data[0] = (2 << 5) | (toggle << 4) | 3
                data[1] = obj_idx & 0xFF
                data[2] = (obj_idx >> 8) & 0xFF
                data[3] = obj_sub

                msg = can.Message(
                    arbitration_id=self.sdo_rx_cob,
                    data=bytes(data),
                    is_extended_id=False
                )
                self.bus.send(msg)
                idx += 1
                self.fuzzed_count += 1
                time.sleep(0.08)  # Staggered SDO timing

        # Run both streams concurrently
        self._stop_threads = False
        pdo_thread = threading.Thread(target=send_pdo_stream)
        sdo_thread = threading.Thread(target=send_sdo_stream)

        pdo_thread.start()
        sdo_thread.start()

        pdo_thread.join()
        sdo_thread.join()

        logger.info("SDO+PDO concurrent test completed")

    def nmt_state_change_during_transfer(self) -> None:
        """Send NMT state transition commands during active transfers.

        Tests if device properly handles state transitions (START/STOP)
        while in the middle of PDO or SDO operations.
        """
        logger.info("Testing NMT state changes during active transfers")

        # Start with a normal state
        self._send_nmt_command(0x01, self.node_id)  # Start
        time.sleep(0.1)

        # Send PDO stream in background
        for cycle in range(4):
            # Send several PDOs
            for i in range(3):
                self._send_pdo(bytearray([i, i+1, i+2, 0, 0, 0, 0, 0]))
                time.sleep(0.05)

            # Inject NMT command mid-transfer
            if cycle % 2 == 0:
                logger.info("  Injecting STOP command during PDO transmission")
                self._send_nmt_command(0x02, self.node_id)  # Stop
                time.sleep(0.05)

                logger.info("  Injecting START command to recover")
                self._send_nmt_command(0x01, self.node_id)  # Start
            else:
                logger.info("  Injecting PREOP command during PDO transmission")
                self._send_nmt_command(0x80, self.node_id)  # PreOp
                time.sleep(0.05)

                logger.info("  Injecting START command to recover")
                self._send_nmt_command(0x01, self.node_id)  # Start

            time.sleep(0.2)

        logger.info("NMT state change test completed")

    def pdo_mapping_change_during_transmission(self) -> None:
        """Change PDO mapping via SDO while PDOs are being transmitted.

        Tests if device properly handles PDO configuration changes
        (via SDO writes to 0x1600/0x1A00 ranges) while active transmission
        is occurring.
        """
        logger.info("Testing PDO mapping change during transmission")

        # Start sending PDOs
        for cycle in range(3):
            logger.info("  PDO transmission cycle %d", cycle + 1)

            # Send initial PDOs
            for i in range(5):
                self._send_pdo(bytearray([i, i+1, 0, 0, 0, 0, 0, 0]))
                self.fuzzed_count += 1
                time.sleep(0.05)

            # Mid-transmission: attempt to change PDO mapping (0x1600 or 0x1A00)
            logger.info("  Injecting PDO mapping change (SDO to 0x1600)")
            self._write_pdo_mapping(0x1600, 0x00, 0x00000000)  # Disable
            time.sleep(0.1)

            # Continue PDO transmission
            for i in range(5, 10):
                self._send_pdo(bytearray([i, i+1, 0, 0, 0, 0, 0, 0]))
                self.fuzzed_count += 1
                time.sleep(0.05)

            # Re-enable mapping
            logger.info("  Re-enabling PDO mapping")
            self._write_pdo_mapping(0x1600, 0x00, 0x00000001)
            time.sleep(0.1)

        logger.info("PDO mapping change test completed")

    def sync_during_sdo_transfer(self) -> None:
        """Send SYNC messages while SDO transfers are in progress.

        Tests PDO SYNC signal handling when concurrent with SDO traffic,
        which could cause timing confusion or missed synchronizations.
        """
        logger.info("Testing SYNC during SDO transfer")

        # Setup: Send initial SYNC
        self._send_sync(0)
        time.sleep(0.1)

        # Main test: alternate SYNC and SDO
        sync_counter = 0
        sdo_obj_idx = 0x1000

        for i in range(15):
            if i % 3 == 0:
                # Send SYNC
                logger.info("  Sending SYNC counter=%d", sync_counter)
                self._send_sync(sync_counter)
                sync_counter += 1
            elif i % 3 == 1:
                # Send SDO request
                logger.info("  Sending SDO to 0x%04X", sdo_obj_idx + (i // 3))
                self._send_sdo_request(sdo_obj_idx + (i // 3), 0)
            else:
                # Send SYNC again
                logger.info("  Sending SYNC counter=%d", sync_counter)
                self._send_sync(sync_counter)
                sync_counter += 1

            time.sleep(0.05)

        logger.info("SYNC+SDO concurrent test completed")

    def broadcast_nmt_with_unicast_transfers(self) -> None:
        """Send broadcast NMT commands while unicast transfers are active.

        Tests if broadcast NMT (node_id=0) properly affects device
        when it's in the middle of node-specific operations.
        """
        logger.info("Testing broadcast NMT during unicast transfers")

        # Start device
        self._send_nmt_command(0x01, self.node_id)
        time.sleep(0.1)

        # Send various unicast operations
        for i in range(3):
            # SDO transfer
            logger.info("  Cycle %d: Starting SDO transfer", i + 1)
            self._send_sdo_request(0x1000, 0)
            time.sleep(0.05)

            # Inject broadcast STOP
            logger.info("  Broadcasting STOP command")
            self._send_nmt_command(0x02, 0)  # Broadcast stop
            time.sleep(0.1)

            # Recover with broadcast START
            logger.info("  Broadcasting START command")
            self._send_nmt_command(0x01, 0)  # Broadcast start
            time.sleep(0.1)

        logger.info("Broadcast NMT test completed")

    def rapid_pdo_config_mutations(self) -> None:
        """Rapidly mutate PDO configurations while transmission is active.

        Tests device robustness to frequent PDO parameter changes
        via rapid-fire SDO writes to PDO configuration objects.
        """
        logger.info("Testing rapid PDO configuration mutations")

        # PDO configuration indices
        pdo_param_indices = [0x1400, 0x1500, 0x1600, 0x1700]  # RPDO params
        pdo_param_cobid_subindex = 0x01  # COB-ID subindex

        # Send PDOs while mutating config
        for cycle in range(3):
            logger.info("  Mutation cycle %d", cycle + 1)

            # Send background PDO stream
            for i in range(5):
                self._send_pdo(bytearray([i, i+1, i+2, 0, 0, 0, 0, 0]))
                self.fuzzed_count += 1

                # Every 2 PDOs, mutate a PDO param
                if i % 2 == 1:
                    pdo_idx = random.choice(pdo_param_indices)
                    new_cob_id = random.randint(0x200, 0x400)
                    logger.info("    Mutating PDO 0x%04X COB-ID to 0x%03X", pdo_idx, new_cob_id)
                    self._write_pdo_param(pdo_idx, pdo_param_cobid_subindex, new_cob_id)

                time.sleep(0.05)

        logger.info("Rapid PDO mutation test completed")

    def run_all_strategies(self, iterations: int = 1) -> List[Dict[str, Any]]:
        """Execute all concurrent fuzzing strategies.

        Args:
            iterations: Number of times to repeat each strategy

        Returns:
            List of test results
        """
        logger.info("Running all concurrent fuzzing strategies (%d iteration(s))", iterations)

        strategies = [
            self.sdо_sdo_interleaving,
            self.sdo_during_pdo_transmission,
            self.nmt_state_change_during_transfer,
            self.pdo_mapping_change_during_transmission,
            self.sync_during_sdo_transfer,
            self.broadcast_nmt_with_unicast_transfers,
            self.rapid_pdo_config_mutations,
        ]

        for iteration in range(iterations):
            logger.info("Concurrent fuzzing iteration %d/%d", iteration + 1, iterations)
            for strategy in strategies:
                try:
                    strategy()
                except Exception as e:
                    error_msg = f"Concurrent fuzzing strategy {strategy.__name__} failed: {e}"
                    logger.error(error_msg)
                    self.test_results.append({
                        "strategy": strategy.__name__,
                        "status": "error",
                        "error": str(e),
                        "timestamp": time.time(),
                    })

        logger.info("Concurrent fuzzing complete: %d messages fuzzed", self.fuzzed_count)
        return self.test_results

    # --- Private helpers ---

    def _send_nmt_command(self, cmd: int, node_id: int) -> None:
        """Send NMT command."""
        try:
            msg = can.Message(
                arbitration_id=self.nmt_cmd_cob,
                data=bytes([cmd, node_id]),
                is_extended_id=False
            )
            self.bus.send(msg)
            self.fuzzed_count += 1
        except Exception as e:
            logger.warning("Failed to send NMT command: %s", e)

    def _send_sync(self, counter: int) -> None:
        """Send SYNC message."""
        try:
            msg = can.Message(
                arbitration_id=self.sync_cob,
                data=bytes([counter & 0xFF]),
                is_extended_id=False
            )
            self.bus.send(msg)
            self.fuzzed_count += 1
        except Exception as e:
            logger.warning("Failed to send SYNC: %s", e)

    def _send_pdo(self, data: bytearray) -> None:
        """Send PDO (TPDO1 in this case)."""
        try:
            msg = can.Message(
                arbitration_id=self.pdo1_tx_cob,
                data=bytes(data),
                is_extended_id=False
            )
            self.bus.send(msg)
        except Exception as e:
            logger.warning("Failed to send PDO: %s", e)

    def _send_sdo_request(self, obj_idx: int, obj_sub: int) -> None:
        """Send SDO upload initiate request."""
        try:
            data = bytearray(8)
            data[0] = 0x40  # Upload initiate
            data[1] = obj_idx & 0xFF
            data[2] = (obj_idx >> 8) & 0xFF
            data[3] = obj_sub

            msg = can.Message(
                arbitration_id=self.sdo_rx_cob,
                data=bytes(data),
                is_extended_id=False
            )
            self.bus.send(msg)
            self.fuzzed_count += 1
        except Exception as e:
            logger.warning("Failed to send SDO request: %s", e)

    def _write_pdo_param(self, pdo_idx: int, subindex: int, value: int) -> None:
        """Write PDO parameter via SDO."""
        try:
            data = bytearray(8)
            data[0] = 0x23  # Download initiate, expedited, 4 bytes
            data[1] = pdo_idx & 0xFF
            data[2] = (pdo_idx >> 8) & 0xFF
            data[3] = subindex
            data[4] = value & 0xFF
            data[5] = (value >> 8) & 0xFF
            data[6] = (value >> 16) & 0xFF
            data[7] = (value >> 24) & 0xFF

            msg = can.Message(
                arbitration_id=self.sdo_rx_cob,
                data=bytes(data),
                is_extended_id=False
            )
            self.bus.send(msg)
            self.fuzzed_count += 1
        except Exception as e:
            logger.warning("Failed to write PDO param: %s", e)

    def _write_pdo_mapping(self, pdo_idx: int, subindex: int, mapping: int) -> None:
        """Write PDO mapping entry via SDO."""
        self._write_pdo_param(pdo_idx, subindex, mapping)
