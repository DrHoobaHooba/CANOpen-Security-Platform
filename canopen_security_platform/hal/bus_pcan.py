"""CAN Bus Hardware Abstraction Layer with PCAN support.

Provides robust interface to python-can with graceful error recovery,
automatic configuration detection, and comprehensive logging.
"""

import logging
import time
from contextlib import contextmanager
from typing import Optional, Iterator, Any, Dict, List, Tuple

import can
import can.exceptions

from ..utils.logging_utils import get_logger

logger = get_logger(__name__)

if not hasattr(can.BusState, "ERROR_PASSIVE") and hasattr(can.BusState, "PASSIVE"):
    can.BusState.ERROR_PASSIVE = can.BusState.PASSIVE
if not hasattr(can.BusState, "ERROR_WARNING") and hasattr(can.BusState, "ERROR"):
    can.BusState.ERROR_WARNING = can.BusState.ERROR
if not hasattr(can.BusState, "OFF"):
    if hasattr(can.BusState, "BUS_OFF"):
        can.BusState.OFF = can.BusState.BUS_OFF
    elif hasattr(can.BusState, "ERROR"):
        can.BusState.OFF = can.BusState.ERROR


class CANConfigError(Exception):
    """Raised when CAN bus configuration fails."""
    pass


class CANTransmitError(Exception):
    """Raised when frame transmission fails."""
    pass


class CANReceiveError(Exception):
    """Raised when frame reception fails."""
    pass


class BusInterface:
    """Hardware abstraction for PCAN bus using python-can.

    Provides robust send/recv/iterate operations with automatic error recovery,
    graceful degradation, and comprehensive diagnostic capabilities.

    Example configuration dict:
        {
            "interface": "pcan",
            "channel": "PCAN_USBBUS1",
            "bitrate": 250000,
            "fd": False,  # CAN FD support
            "data_bitrate": 1000000,  # FD data bitrate
        }
    """

    # PCAN-specific channels
    PCAN_CHANNELS = [
        "PCAN_USBBUS1", "PCAN_USBBUS2", "PCAN_USBBUS3", "PCAN_USBBUS4",
        "PCAN_USBBUS5", "PCAN_USBBUS6", "PCAN_USBBUS7", "PCAN_USBBUS8",
        "PCAN_ISABUS1", "PCAN_ISABUS2", "PCAN_ISABUS3", "PCAN_ISABUS4",
        "PCAN_ISABUS5", "PCAN_ISABUS6", "PCAN_ISABUS7", "PCAN_ISABUS8",
        "PCAN_PCIBUS1", "PCAN_PCIBUS2", "PCAN_PCIBUS3", "PCAN_PCIBUS4",
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """Initialize BUS interface.

        Args:
            config: Configuration dictionary with keys:
                - interface: 'pcan', 'virtual', 'kvaser', etc. (default: 'pcan')
                - channel: Hardware channel (default: 'PCAN_USBBUS1')
                - bitrate: Bus bitrate in bps (default: 250000)
                - fd: Enable CAN FD (default: False)
                - data_bitrate: FD data bitrate (default: 1000000)
                - state_check_interval: Bus state check interval (default: 5.0)
        """
        if config is not None and not isinstance(config, dict):
            raise ValueError(f"config must be dict or None, got {type(config)}")

        self.config: Dict[str, Any] = config or {}
        self._bus: Optional[can.Bus] = None
        self._open_time: Optional[float] = None
        self._tx_count: int = 0
        self._rx_count: int = 0
        self._error_count: int = 0
        self._recovery_attempts: int = 0
        self._max_recovery_attempts: int = 3
        self._state_check_interval: float = self.config.get("state_check_interval", 5.0)
        self._last_state_check: float = 0.0

        logger.debug("BusInterface initialized with config: %s", self.config)

    def _get_interface(self) -> str:
        """Get the CAN interface to use."""
        return self.config.get("interface", "pcan")

    def _get_channel(self) -> str:
        """Get the CAN channel to use."""
        channel = self.config.get("channel", "PCAN_USBBUS1")
        if channel not in self.PCAN_CHANNELS and channel != "virtual":
            logger.warning(
                "Channel '%s' not in known PCAN channels; may fail. "
                "Known: %s",
                channel, ", ".join(self.PCAN_CHANNELS[:4])
            )
        return channel

    def _get_bitrate(self) -> int:
        """Get the bitrate in bps."""
        bitrate = self.config.get("bitrate", 250000)
        if not isinstance(bitrate, int) or bitrate <= 0:
            raise ValueError(f"bitrate must be positive int, got {bitrate}")
        return bitrate

    @staticmethod
    def detect_available_configs() -> List[Dict[str, Any]]:
        """Detect available CAN interfaces and channels on system.

        Returns:
            List of available configurations with detected parameters.
        """
        logger.info("Detecting available CAN interfaces")
        configs: List[Dict[str, Any]] = []

        # Detect PCAN interfaces
        try:
            available = can.detect_available_configs()
            logger.debug("Detected CAN configs: %s", available)
            configs.extend(available)
        except Exception as e:
            logger.warning("Failed to auto-detect CAN configs: %s", e)

        # Add default PCAN channels to candidate list
        for channel in BusInterface.PCAN_CHANNELS[:8]:  # Check first 8
            configs.append({
                "interface": "pcan",
                "channel": channel,
                "bitrate": 250000,
            })

        logger.info("Found %d available CAN configurations", len(set(
            (c.get("channel"), c.get("bitrate")) for c in configs
        )))
        return configs

    def _open(self) -> None:
        """Open the CAN bus with error recovery.

        Raises:
            CANConfigError: If bus configuration fails after all retries.
        """
        if self._bus is not None:
            return  # Already open

        logger.info("Opening CAN bus (interface=%s, channel=%s, bitrate=%d)",
                   self._get_interface(), self._get_channel(), self._get_bitrate())

        last_error: Optional[Exception] = None

        for attempt in range(self._max_recovery_attempts):
            try:
                kwargs: Dict[str, Any] = {
                    "interface": self._get_interface(),
                    "channel": self._get_channel(),
                    "bitrate": self._get_bitrate(),
                }

                # Add optional FD parameters
                if self.config.get("fd", False):
                    kwargs["fd"] = True
                    kwargs["data_bitrate"] = self.config.get("data_bitrate", 1000000)
                    logger.debug("CAN FD enabled with data bitrate %d", kwargs["data_bitrate"])

                self._bus = can.Bus(**kwargs)
                self._open_time = time.time()
                self._recovery_attempts = 0

                logger.info("Bus opened successfully after %d attempt(s)", attempt + 1)
                return

            except (can.CanOperationError, can.CanInterfaceNotImplementedError, OSError) as e:
                last_error = e
                logger.warning(
                    "Bus open attempt %d/%d failed: %s",
                    attempt + 1, self._max_recovery_attempts, str(e)
                )

                if attempt < self._max_recovery_attempts - 1:
                    wait_time = 0.5 * (2 ** attempt)  # Exponential backoff
                    logger.debug("Waiting %.1f seconds before retry", wait_time)
                    time.sleep(wait_time)

        # All retries exhausted
        self._bus = None
        error_msg = (
            f"Failed to open CAN bus after {self._max_recovery_attempts} attempts. "
            f"Last error: {str(last_error)}"
        )
        logger.error(error_msg)
        raise CANConfigError(error_msg) from last_error

    def _check_bus_state(self) -> bool:
        """Check if bus is healthy and operational.

        Returns:
            True if bus is open and healthy, False otherwise.
        """
        if self._bus is None:
            return False

        now = time.time()
        if now - self._last_state_check < self._state_check_interval:
            return True

        try:
            # Try to get bus state
            state = self._bus.state
            self._last_state_check = now

            if state == can.BusState.ACTIVE:
                logger.debug("Bus state: ACTIVE")
                return True
            elif state == getattr(can.BusState, "OFF", None) or state == getattr(can.BusState, "BUS_OFF", None):
                logger.error("Bus is OFF")
                self._error_count += 1
                return False
            elif state == can.BusState.ERROR_PASSIVE:
                logger.warning("Bus in ERROR_PASSIVE state")
                self._error_count += 1
                return False
            elif state == can.BusState.ERROR_WARNING:
                logger.warning("Bus in ERROR_WARNING state")
                return True  # Still operational

        except Exception as e:
            logger.debug("Failed to check bus state: %s", e)
            # Assume bus is OK if check fails
            return True

        return True

    def send(self, frame: can.Message, timeout: Optional[float] = None) -> None:
        """Send a CAN frame with error recovery.

        Args:
            frame: CAN message to send
            timeout: Transmit timeout in seconds (default: 1.0)

        Raises:
            CANTransmitError: If frame transmission fails.
            ValueError: If frame is invalid.
        """
        if not isinstance(frame, can.Message):
            raise ValueError(f"Expected can.Message, got {type(frame)}")

        if frame.dlc > 8 and not frame.is_fd:
            raise ValueError(
                f"Standard CAN frames max 8 bytes, got {frame.dlc}. "
                "Use is_fd=True for CAN FD."
            )

        timeout = timeout or 1.0
        if timeout <= 0:
            raise ValueError(f"timeout must be positive, got {timeout}")

        # Ensure bus is open
        self._open()

        if not self._check_bus_state():
            logger.warning("Bus not in healthy state, attempting recovery")
            try:
                self.close()
                self._open()
            except Exception as e:
                raise CANTransmitError(f"Bus recovery failed: {e}") from e

        try:
            assert self._bus is not None
            self._bus.send(frame, timeout=timeout)
            self._tx_count += 1

            logger.debug(
                "TX [0x%03X] dlc=%d data=%s",
                frame.arbitration_id, frame.dlc, frame.data.hex()
            )

        except can.CanOperationError as e:
            self._error_count += 1
            error_msg = f"CAN transmit failed: {str(e)}"
            logger.error(error_msg)
            raise CANTransmitError(error_msg) from e

    def recv(self, timeout: float = 1.0) -> Optional[can.Message]:
        """Receive a single CAN frame.

        Args:
            timeout: Receive timeout in seconds

        Returns:
            Received CAN frame or None if timeout.

        Raises:
            CANReceiveError: If I/O error occurs.
            ValueError: If timeout is invalid.
        """
        if not isinstance(timeout, (int, float)) or timeout < 0:
            raise ValueError(f"timeout must be non-negative number, got {timeout}")

        self._open()
        assert self._bus is not None

        try:
            msg = self._bus.recv(timeout=timeout)

            if msg is not None:
                self._rx_count += 1
                logger.debug(
                    "RX [0x%03X] dlc=%d data=%s",
                    msg.arbitration_id, msg.dlc, msg.data.hex()
                )

            return msg

        except can.CanOperationError as e:
            self._error_count += 1
            error_msg = f"CAN receive failed: {str(e)}"
            logger.error(error_msg)
            raise CANReceiveError(error_msg) from e

    def iterate(self, timeout: float = 1.0, max_frames: Optional[int] = None) -> Iterator[can.Message]:
        """Iterate over received CAN frames.

        Args:
            timeout: Overall iteration timeout in seconds
            max_frames: Maximum frames to yield (None = unlimited)

        Yields:
            Received CAN messages

        Raises:
            CANReceiveError: If I/O errors occur.
        """
        if not isinstance(timeout, (int, float)) or timeout < 0:
            raise ValueError(f"timeout must be non-negative, got {timeout}")

        if max_frames is not None and max_frames <= 0:
            raise ValueError(f"max_frames must be positive or None, got {max_frames}")

        self._open()
        assert self._bus is not None

        start_time = time.time()
        frame_count = 0

        try:
            while True:
                if max_frames and frame_count >= max_frames:
                    logger.debug("Reached max_frames limit (%d)", max_frames)
                    break

                elapsed = time.time() - start_time
                remaining = timeout - elapsed
                if remaining <= 0:
                    logger.debug("Iteration timeout after %.1f seconds", elapsed)
                    break

                try:
                    msg = self._bus.recv(timeout=max(0.01, remaining))

                    if msg is None:
                        # Timeout, end iteration
                        break

                    self._rx_count += 1
                    frame_count += 1

                    logger.debug(
                        "RX [0x%03X] dlc=%d data=%s (frame %d)",
                        msg.arbitration_id, msg.dlc, msg.data.hex(), frame_count
                    )

                    yield msg

                except can.CanOperationError as e:
                    self._error_count += 1
                    logger.error("I/O error during iteration: %s", e)
                    raise CANReceiveError(f"Iteration failed: {e}") from e

        except Exception as e:
            logger.error("Unexpected error during iteration: %s", e)
            raise

    def flush_tx(self) -> None:
        """Flush TX buffer to ensure all frames are sent.

        Raises:
            CANTransmitError: If flush operation fails.
        """
        if self._bus is None:
            logger.debug("Bus not open, skipping TX flush")
            return

        try:
            self._bus.flush_tx_buffer()
            logger.debug("TX buffer flushed")
        except Exception as e:
            logger.warning("TX buffer flush failed: %s", e)
            # Don't raise; flushing is advisory

    def flush_rx(self) -> None:
        """Flush RX buffer to clear any pending frames.

        Raises:
            CANReceiveError: If flush operation fails.
        """
        if self._bus is None:
            logger.debug("Bus not open, skipping RX flush")
            return

        try:
            self._bus.flush_rx_buffer()
            logger.debug("RX buffer flushed")
        except Exception as e:
            logger.warning("RX buffer flush failed: %s", e)
            # Don't raise; flushing is advisory

    def get_statistics(self) -> Dict[str, Any]:
        """Get bus usage statistics.

        Returns:
            Dictionary with TX/RX counts and error statistics.
        """
        uptime = None
        if self._open_time is not None:
            uptime = time.time() - self._open_time

        return {
            "is_open": self._bus is not None,
            "uptime_seconds": uptime,
            "frames_transmitted": self._tx_count,
            "frames_received": self._rx_count,
            "errors": self._error_count,
            "recovery_attempts": self._recovery_attempts,
        }

    def close(self) -> None:
        """Close the CAN bus gracefully.

        Logs final statistics before shutdown.
        """
        if self._bus is None:
            logger.debug("Bus already closed")
            return

        stats = self.get_statistics()
        logger.info(
            "Closing bus (TX=%d, RX=%d, errors=%d, uptime=%.1fs)",
            stats["frames_transmitted"], stats["frames_received"],
            stats["errors"], stats["uptime_seconds"] or 0.0
        )

        try:
            self._bus.shutdown()
        except Exception as e:
            logger.warning("Error during bus shutdown: %s", e)
        finally:
            self._bus = None
            self._open_time = None

    @contextmanager
    def open_context(self):
        """Context manager for bus operations.

        Ensures bus is properly closed even if exceptions occur.

        Example:
            with bus.open_context():
                msg = bus.recv()
        """
        try:
            self._open()
            yield self
        finally:
            self.close()

    def get_raw_bus(self) -> Optional[can.Bus]:
        """Get underlying python-can Bus instance if open."""
        return self._bus

    def __enter__(self) -> "BusInterface":
        """Enter context manager."""
        self._open()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit context manager."""
        self.close()
