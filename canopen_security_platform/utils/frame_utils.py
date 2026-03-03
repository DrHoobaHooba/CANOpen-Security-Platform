"""CAN frame utilities and helpers.

Provides convenience functions for constructing and analyzing CAN/CANopen frames.
"""

import logging
from typing import Tuple, Optional, Dict, Any
import struct

import can

from .logging_utils import get_logger

logger = get_logger(__name__)


def make_message(
    arbitration_id: int,
    data: bytes,
    is_extended_id: bool = False,
    dlc: Optional[int] = None,
) -> can.Message:
    """Create a CAN message with validation.

    Args:
        arbitration_id: CAN frame ID (11-bit or 29-bit)
        data: Frame payload (0-8 bytes, or 0-64 for CAN FD)
        is_extended_id: Use 29-bit IDs if True
        dlc: Data Length Code (auto-detected if None)

    Returns:
        Constructed can.Message instance

    Raises:
        ValueError: If frame parameters are invalid
    """
    if not isinstance(arbitration_id, int):
        raise ValueError(f"arbitration_id must be int, got {type(arbitration_id)}")

    if not isinstance(data, (bytes, bytearray)):
        raise ValueError(f"data must be bytes/bytearray, got {type(data)}")

    # Validate ID range
    max_id = 0x1FFFFFFF if is_extended_id else 0x7FF
    if arbitration_id < 0 or arbitration_id > max_id:
        raise ValueError(
            f"arbitration_id 0x{arbitration_id:X} exceeds max "
            f"({'extended' if is_extended_id else 'standard'} ID)"
        )

    # Validate data length
    if len(data) > 8:
        # CAN FD
        if len(data) not in [12, 16, 20, 24, 32, 48, 64]:
            raise ValueError(f"Invalid CAN FD data length: {len(data)}")

    logger.debug(
        "Creating CAN message (ID=0x%X, dlc=%d, extended=%s)",
        arbitration_id, len(data), is_extended_id
    )

    return can.Message(
        arbitration_id=arbitration_id,
        data=bytes(data),
        is_extended_id=is_extended_id,
        dlc=dlc,
    )


def parse_cob_id(arbitration_id: int) -> Tuple[str, Optional[int]]:
    """Parse CANopen COB-ID to identify frame type and node ID.

    Args:
        arbitration_id: CAN arbitration ID

    Returns:
        Tuple of (frame_type, node_id)
        - frame_type: 'NMT', 'Sync', 'EMCY', 'TPDO1/2/3/4', 'RPDO1/2/3/4', 'TXSDO', 'RXSDO', etc.
        - node_id: Node ID (1-127) or None if not applicable

    Example:
        >>> parse_cob_id(0x701)
        ('EMCY', 1)
        >>> parse_cob_id(0x700)
        ('Heartbeat', 0)
    """
    # Standard CANopen COB-ID definitions (DS301)
    if arbitration_id == 0x000:
        return ("NMT", None)
    elif arbitration_id == 0x080:
        return ("Sync", None)

    # Extract node ID from lower 7 bits
    node_id = arbitration_id & 0x7F

    # Check frame type based on upper bits
    cob_id_base = arbitration_id & 0x780

    if cob_id_base == 0x080:
        return ("EMCY", node_id)
    elif cob_id_base == 0x100:
        return ("Time", node_id)
    elif cob_id_base == 0x180:
        return ("TPDO1", node_id)
    elif cob_id_base == 0x200:
        return ("RPDO1", node_id)
    elif cob_id_base == 0x280:
        return ("TPDO2", node_id)
    elif cob_id_base == 0x300:
        return ("RPDO2", node_id)
    elif cob_id_base == 0x380:
        return ("TPDO3", node_id)
    elif cob_id_base == 0x400:
        return ("RPDO3", node_id)
    elif cob_id_base == 0x480:
        return ("TPDO4", node_id)
    elif cob_id_base == 0x500:
        return ("RPDO4", node_id)
    elif cob_id_base == 0x580:
        return ("TXSDO", node_id)
    elif cob_id_base == 0x600:
        return ("RXSDO", node_id)
    elif cob_id_base == 0x700:
        return ("Heartbeat", node_id)
    else:
        return ("Unknown", node_id)


def decode_sdo_expedited_data(
    data_bytes: bytes,
    length: int,
) -> Any:
    """Decode expedited SDO transfer data.

    Args:
        data_bytes: SDO data bytes (typically 4 bytes for expedited)
        length: Number of valid data bytes

    Returns:
        Decoded value (int, bytes, or None)
    """
    if length == 0:
        return None
    elif length == 1:
        return data_bytes[0]
    elif length == 2:
        return struct.unpack("<H", data_bytes[:2])[0]
    elif length == 4:
        return struct.unpack("<I", data_bytes[:4])[0]
    else:
        return bytes(data_bytes[:length])


def encode_sdo_expedited_data(
    value: Any,
    data_type: Optional[str] = None,
) -> Tuple[bytes, int]:
    """Encode value for SDO expedited transfer.

    Args:
        value: Value to encode (int, bytes, etc.)
        data_type: Optional type hint ('u8', 'u16', 'u32', 'bytes')

    Returns:
        Tuple of (data_bytes, length)
    """
    if isinstance(value, int):
        if value <= 0xFF or data_type == "u8":
            return (struct.pack("B", value & 0xFF), 1)
        elif value <= 0xFFFF or data_type == "u16":
            return (struct.pack("<H", value & 0xFFFF), 2)
        else:
            return (struct.pack("<I", value & 0xFFFFFFFF), 4)
    elif isinstance(value, bytes):
        if len(value) > 4:
            raise ValueError("expedited transfer limited to 4 bytes")
        padded = value + b"\x00" * (4 - len(value))
        return (padded, len(value))
    else:
        raise ValueError(f"Cannot encode type {type(value)}")


def get_sdo_abort_code_description(abort_code: int) -> str:
    """Get human-readable description of SDO abort code.

    Args:
        abort_code: 32-bit abort code

    Returns:
        Description string
    """
    descriptions = {
        0x05040000: "Segmentation error",
        0x05040001: "Toggle bit not alternated",
        0x05040002: "Client timed out",
        0x05040003: "Server timed out",
        0x05040004: "Client CRC error",
        0x05040005: "Server CRC error",
        0x06020000: "Object does not exist",
        0x06040041: "Object is read-only",
        0x06040042: "Object is write-only",
        0x06060000: "Attempted to read write-only",
        0x06070010: "Parameter does not exist",
        0x060F0000: "No access",
        0x08000000: "General error",
        0x08000020: "Data type does not match",
        0x08000021: "Data type too long",
        0x08000022: "Data type too short",
        0x08000023: "Sub-index does not exist",
        0x09010000: "Sub-index ranges exceeded",
        0x06090031: "Value range exceeded",
    }

    return descriptions.get(abort_code, f"Unknown abort code (0x{abort_code:08X})")


def frame_to_dict(msg: can.Message) -> Dict[str, Any]:
    """Convert CAN message to dictionary for logging/storage.

    Args:
        msg: CAN message to convert

    Returns:
        Dictionary with frame data
    """
    frame_type, node_id = parse_cob_id(msg.arbitration_id)

    return {
        "timestamp": getattr(msg, 'timestamp', None),
        "arbitration_id": msg.arbitration_id,
        "arbitration_id_hex": f"0x{msg.arbitration_id:03X}" if msg.arbitration_id <= 0x7FF else f"0x{msg.arbitration_id:08X}",
        "frame_type": frame_type,
        "node_id": node_id,
        "dlc": msg.dlc,
        "data": msg.data.hex(),
        "is_extended_id": msg.is_extended_id,
        "is_error_frame": getattr(msg, 'is_error_frame', False),
        "is_remote_frame": getattr(msg, 'is_remote_frame', False),
    }
