from unittest import mock
import pytest
import can

from canopen_security_platform.hal.bus_pcan import (
    BusInterface,
    CANConfigError,
    CANTransmitError,
    CANReceiveError,
)


def test_detect_available_configs_includes_defaults(monkeypatch):
    monkeypatch.setattr(can, "detect_available_configs", lambda: [{
        "interface": "pcan",
        "channel": "PCAN_USBBUS1",
        "bitrate": 250000,
    }])
    configs = BusInterface.detect_available_configs()
    channels = [c.get("channel") for c in configs]
    assert "PCAN_USBBUS1" in channels


def test_get_interface_channel_bitrate():
    bus = BusInterface({"interface": "pcan", "channel": "PCAN_USBBUS1", "bitrate": 500000})
    assert bus._get_interface() == "pcan"
    assert bus._get_channel() == "PCAN_USBBUS1"
    assert bus._get_bitrate() == 500000


def test_send_recv_iterate_with_fake_bus(monkeypatch):
    class LocalBus:
        def __init__(self):
            self.sent = []
            self._rx = []
            self.state = can.BusState.ACTIVE

        def send(self, msg, timeout=None):
            self.sent.append(msg)

        def recv(self, timeout=None):
            if self._rx:
                return self._rx.pop(0)
            return None

        def flush_tx_buffer(self):
            return None

        def flush_rx_buffer(self):
            return None

        def shutdown(self):
            return None

    local_bus = LocalBus()
    local_bus._rx = [
        can.Message(arbitration_id=0x100, data=b"\x01", is_extended_id=False),
        can.Message(arbitration_id=0x101, data=b"\x02", is_extended_id=False),
    ]

    monkeypatch.setattr(
        "canopen_security_platform.hal.bus_pcan.can.Bus",
        lambda **kwargs: local_bus
    )

    bus = BusInterface({"interface": "pcan", "channel": "PCAN_USBBUS1", "bitrate": 250000})
    msg = can.Message(arbitration_id=0x123, data=b"\xAA", is_extended_id=False)
    bus.send(msg)
    assert len(local_bus.sent) == 1

    recv_msg = bus.recv(timeout=0.1)
    assert recv_msg is not None
    assert recv_msg.arbitration_id == 0x100

    frames = list(bus.iterate(timeout=0.1, max_frames=2))
    assert len(frames) == 1
    assert frames[0].arbitration_id == 0x101

    bus.close()


def test_flush_and_statistics(monkeypatch):
    class LocalBus:
        def __init__(self):
            self.sent = []
            self._rx = []
            self.state = can.BusState.ACTIVE

        def send(self, msg, timeout=None):
            self.sent.append(msg)

        def recv(self, timeout=None):
            return None

        def flush_tx_buffer(self):
            return None

        def flush_rx_buffer(self):
            return None

        def shutdown(self):
            return None

    local_bus = LocalBus()
    monkeypatch.setattr(
        "canopen_security_platform.hal.bus_pcan.can.Bus",
        lambda **kwargs: local_bus
    )

    bus = BusInterface({"interface": "pcan", "channel": "PCAN_USBBUS1", "bitrate": 250000})
    msg = can.Message(arbitration_id=0x123, data=b"\xAA", is_extended_id=False)
    bus.send(msg)
    bus.flush_tx()
    bus.flush_rx()

    stats = bus.get_statistics()
    assert stats["frames_transmitted"] == 1
    bus.close()


def test_open_context_and_get_raw_bus(monkeypatch):
    class LocalBus:
        def __init__(self):
            self.state = can.BusState.ACTIVE

        def send(self, msg, timeout=None):
            return None

        def recv(self, timeout=None):
            return None

        def flush_tx_buffer(self):
            return None

        def flush_rx_buffer(self):
            return None

        def shutdown(self):
            return None

    local_bus = LocalBus()
    monkeypatch.setattr(
        "canopen_security_platform.hal.bus_pcan.can.Bus",
        lambda **kwargs: local_bus
    )

    bus = BusInterface({"interface": "pcan", "channel": "PCAN_USBBUS1", "bitrate": 250000})
    with bus.open_context():
        assert bus.get_raw_bus() is local_bus
    assert bus.get_raw_bus() is None


def test_check_bus_state_off(monkeypatch):
    class LocalBus:
        def __init__(self):
            self.state = can.BusState.OFF

        def shutdown(self):
            return None

    bus = BusInterface({"interface": "pcan", "channel": "PCAN_USBBUS1", "bitrate": 250000})
    bus._bus = LocalBus()
    assert bus._check_bus_state() is False


def test_recv_invalid_timeout():
    bus = BusInterface({"interface": "pcan", "channel": "PCAN_USBBUS1", "bitrate": 250000})
    with pytest.raises(ValueError):
        bus.recv(timeout=-1)


def test_open_failure_raises(monkeypatch):
    def _raise(**kwargs):
        raise can.CanOperationError("no device")

    monkeypatch.setattr("canopen_security_platform.hal.bus_pcan.can.Bus", _raise)
    monkeypatch.setattr("canopen_security_platform.hal.bus_pcan.time.sleep", lambda s: None)

    bus = BusInterface({"interface": "pcan", "channel": "PCAN_USBBUS1", "bitrate": 250000})
    bus._max_recovery_attempts = 1
    with pytest.raises(CANConfigError):
        bus._open()


def test_open_uses_mock_bus(monkeypatch):
    mock_bus = mock.MagicMock()
    monkeypatch.setattr(
        "canopen_security_platform.hal.bus_pcan.can.Bus",
        lambda **kwargs: mock_bus
    )

    bus = BusInterface({"interface": "pcan", "channel": "PCAN_USBBUS1", "bitrate": 250000})
    bus._open()
    assert bus.get_raw_bus() is mock_bus
