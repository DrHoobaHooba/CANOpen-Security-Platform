"""CANopen EMCY (Emergency) fuzzing engine.

Tests EMCY message handling for vulnerabilities including
error code fuzzing, state-dependent transitions, and rapid bursts.
"""

import logging
import random
import time
from typing import Callable, Any, Dict, List

import can

from ..hal.bus_pcan import BusInterface
from ..od.runtime_od import RuntimeObjectDictionary
from ..utils.logging_utils import get_logger

logger = get_logger(__name__)

OracleCallback = Callable[[Dict[str, Any]], None]


class EMCYFuzzer:
    """EMCY protocol fuzzing for error message robustness testing.

    Tests EMCY implementation for improper error handling,
    invalid error codes, state machine confusion, and DoS vulnerabilities.
    """

    # EMCY COB-ID
    EMCY_COB_ID = 0x080

    # Standard EMCY Error Codes (DS301)
    ERROR_CODE_CATEGORIES = {
        "no_error": 0x0000,
        "generic": 0x1000,
        "current": 0x2000,
        "voltage": 0x3000,
        "temperature": 0x4000,
        "device_hardware": 0x5000,
        "device_software": 0x6000,
        "additional_modules": 0x7000,
        "monitoring": 0x8000,
        "external_error": 0x9000,
        "additional_functions": 0xF000,
        "device_specific": 0xFF00,
    }

    def __init__(
        self,
        bus: BusInterface,
        od: RuntimeObjectDictionary,
        node_id: int,
        oracle: OracleCallback,
    ) -> None:
        """Initialize EMCY fuzzer.

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
        self.emcy_cob_id = self.EMCY_COB_ID + node_id
        self.fuzzed_count = 0
        self.test_results: List[Dict[str, Any]] = []

        logger.debug("EMCY Fuzzer initialized for node %d (COB-ID=0x%03X)", 
                     node_id, self.emcy_cob_id)

    def error_code_fuzzing(self) -> None:
        """Fuzz EMCY error codes across all categories.

        Tests proper handling of valid, invalid, and extreme error codes.
        """
        logger.info("Testing EMCY error code fuzzing")

        # Valid category codes
        valid_categories = list(self.ERROR_CODE_CATEGORIES.values())
        
        # Generate test error codes
        test_codes = []
        
        # Include valid category bases
        for cat in valid_categories:
            test_codes.append(cat)
            # Add manufacturer-specific within each category
            test_codes.append(cat + random.randint(1, 255))
        
        # Add boundary and extreme values
        test_codes.extend([0x0000, 0x0001, 0x7FFF, 0x8000, 0xFFFF, 0xFFFE])
        
        for error_code in test_codes:
            self._send_emcy(
                error_code=error_code,
                error_reg=self._generate_error_register(),
                manufacturer_data=bytes([random.randint(0, 255) for _ in range(5)]),
                strategy="error_code_fuzzing"
            )
            time.sleep(0.05)

        self.fuzzed_count += len(test_codes)

    def manufacturer_specific_codes(self) -> None:
        """Fuzz manufacturer-specific error codes (0x1000-0xFFFF).

        Tests handling of non-standard error codes outside DS301 scope.
        """
        logger.info("Testing EMCY manufacturer-specific codes")

        # Common manufacturer-specific ranges
        manufacturer_ranges = [
            (0x1000, 0x1FFF),  # Manufacturer range 1
            (0x2001, 0x2FFF),  # Manufacturer range 2
            (0xF000, 0xFEFF),  # Device-specific
        ]

        test_codes = []
        for range_start, range_end in manufacturer_ranges:
            # Sample within each range
            test_codes.append(range_start)
            test_codes.append(range_end)
            test_codes.append((range_start + range_end) // 2)

        for error_code in test_codes:
            self._send_emcy(
                error_code=error_code,
                error_reg=0xFF,  # All bits set
                manufacturer_data=bytes([0xDE, 0xAD, 0xBE, 0xEF, 0x00]),
                strategy="manufacturer_specific"
            )
            time.sleep(0.05)

        self.fuzzed_count += len(test_codes)

    def error_register_mutations(self) -> None:
        """Fuzz the error register field (byte 2 of EMCY frame).

        Tests proper interpretation of EMCY error register bits:
        - Bit 0: Generic error
        - Bit 1: Current
        - Bit 2: Voltage
        - Bit 3: Temperature
        - Bit 4: Device hardware
        - Bit 5: Device software
        - Bit 6: Additional modules
        - Bit 7: Monitoring
        """
        logger.info("Testing EMCY error register mutations")

        # Generate various error register patterns
        test_registers = [
            0x00,      # No error (should clear EMCY?)
            0x01,      # Generic
            0x02,      # Current
            0x04,      # Voltage
            0x08,      # Temperature
            0x10,      # Hardware
            0x20,      # Software
            0x40,      # Additional modules
            0x80,      # Monitoring
            0xFF,      # All errors set
            0xAA,      # Alternating bits
            0x55,      # Alternating bits (inverse)
        ]

        for error_code in [0x2000, 0x3000, 0x4000]:  # Current, Voltage, Temperature
            for error_reg in test_registers:
                self._send_emcy(
                    error_code=error_code,
                    error_reg=error_reg,
                    manufacturer_data=bytes([0] * 5),
                    strategy="error_register_mutation"
                )
                time.sleep(0.02)

        self.fuzzed_count += len(test_registers) * 3

    def rapid_emcy_burst(self) -> None:
        """Send rapid successive EMCY messages with varying codes.

        Tests device buffer handling and rapid error state transitions.
        """
        logger.info("Testing EMCY rapid burst (20 messages in 200ms)")

        error_codes = [
            0x0000,  # No error
            0x1000,  # Generic
            0x2000,  # Current
            0x3000,  # Voltage
            0x4000,  # Temperature
            0x5000,  # Hardware
        ]

        for i in range(20):
            error_code = random.choice(error_codes)
            self._send_emcy(
                error_code=error_code,
                error_reg=random.randint(0, 255),
                manufacturer_data=bytes([random.randint(0, 255) for _ in range(5)]),
                strategy="rapid_burst"
            )
            time.sleep(0.01)  # 10ms between messages

        self.fuzzed_count += 20

    def state_dependent_transitions(self) -> None:
        """Test EMCY state transitions from various device states.

        Tests if device properly handles error transitions:
        - No error -> Error -> No error (recovery)
        - Error code 1 -> Error code 2 (code change)
        - Error -> Emergency stop scenarios
        """
        logger.info("Testing EMCY state-dependent transitions")

        # Transition sequences
        sequences = [
            [0x0000, 0x1000, 0x0000],          # Generic error and recovery
            [0x0000, 0x2000, 0x2100],          # Current error, then sub-error
            [0x1000, 0x2000, 0x3000],          # Error escalation
            [0x0000, 0x1000, 0x1100, 0x0000],  # Multiple errors then recovery
        ]

        for sequence in sequences:
            for error_code in sequence:
                self._send_emcy(
                    error_code=error_code,
                    error_reg=self._error_code_to_register(error_code),
                    manufacturer_data=bytes([0] * 5),
                    strategy="state_transition"
                )
                time.sleep(0.1)  # 100ms between steps

        self.fuzzed_count += len(sequences) * 4  # Approximate

    def emcy_recovery_sequence(self) -> None:
        """Test error recovery by sending clear/recovery sequences.

        Tests if device properly clears errors after 0x0000 EMCY.
        """
        logger.info("Testing EMCY recovery sequences")

        # First trigger an error
        error_codes = [0x2000, 0x3000, 0x4000]

        for error_code in error_codes:
            # Send error
            self._send_emcy(
                error_code=error_code,
                error_reg=0xFF,
                manufacturer_data=bytes([0] * 5),
                strategy="recovery_start"
            )
            time.sleep(0.1)

            # Send recovery
            self._send_emcy(
                error_code=0x0000,
                error_reg=0x00,
                manufacturer_data=bytes([0] * 5),
                strategy="recovery_clear"
            )
            time.sleep(0.1)

        self.fuzzed_count += len(error_codes) * 2

    def run_all_strategies(self, iterations: int = 1) -> List[Dict[str, Any]]:
        """Execute all EMCY fuzzing strategies.

        Args:
            iterations: Number of times to repeat each strategy

        Returns:
            List of test results
        """
        logger.info("Running all EMCY fuzzing strategies (%d iteration(s))", iterations)

        strategies = [
            self.error_code_fuzzing,
            self.manufacturer_specific_codes,
            self.error_register_mutations,
            self.rapid_emcy_burst,
            self.state_dependent_transitions,
            self.emcy_recovery_sequence,
        ]

        for _ in range(iterations):
            for strategy in strategies:
                try:
                    strategy()
                except Exception as e:
                    error_msg = f"EMCY fuzzing strategy {strategy.__name__} failed: {e}"
                    logger.error(error_msg)
                    self.test_results.append({
                        "strategy": strategy.__name__,
                        "status": "error",
                        "error": str(e),
                        "timestamp": time.time(),
                    })

        logger.info("EMCY fuzzing complete: %d messages fuzzed", self.fuzzed_count)
        return self.test_results

    # --- Private helpers ---

    def _send_emcy(
        self,
        error_code: int,
        error_reg: int,
        manufacturer_data: bytes,
        strategy: str,
    ) -> None:
        """Send an EMCY frame and record the attempt.

        Args:
            error_code: 2-byte error code (0x0000-0xFFFF)
            error_reg: Error register byte (0x00-0xFF)
            manufacturer_data: 5-byte manufacturer-specific data
            strategy: Name of fuzzing strategy
        """
        try:
            # EMCY format: [ErrorCode_Low, ErrorCode_High, ErrorReg, MfgData[0-4]]
            data = bytearray(8)
            data[0] = error_code & 0xFF
            data[1] = (error_code >> 8) & 0xFF
            data[2] = error_reg & 0xFF
            data[3:8] = manufacturer_data[:5]

            msg = can.Message(
                arbitration_id=self.emcy_cob_id,
                data=bytes(data),
                is_extended_id=False,
            )

            self.bus.send(msg)

            result = {
                "strategy": strategy,
                "error_code": hex(error_code),
                "error_reg": hex(error_reg),
                "timestamp": time.time(),
                "status": "sent",
            }

            self.test_results.append(result)
            self.oracle(result)

        except Exception as e:
            logger.warning("Failed to send EMCY: %s", e)

    def _generate_error_register(self) -> int:
        """Generate a random error register value."""
        return random.randint(0, 255)

    def _error_code_to_register(self, error_code: int) -> int:
        """Map error code to appropriate error register bits."""
        if error_code == 0x0000:
            return 0x00
        
        # Extract category from error code
        category = error_code & 0xF000
        
        category_map = {
            0x1000: 0x01,  # Generic
            0x2000: 0x02,  # Current
            0x3000: 0x04,  # Voltage
            0x4000: 0x08,  # Temperature
            0x5000: 0x10,  # Hardware
            0x6000: 0x20,  # Software
            0x7000: 0x40,  # Additional modules
            0x8000: 0x80,  # Monitoring
        }
        
        return category_map.get(category, 0x01)
