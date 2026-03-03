import pytest
from unittest import mock
import can

from canopen_security_platform.monitoring.oracle import Oracle, AlertRule


class DummySdoAbortedError(Exception):
    def __init__(self, code=0x06020000):
        super().__init__(f"SDO abort 0x{code:08X}")
        self.code = code


class FakeSDOResponder:
    def __init__(self, mapping):
        self.mapping = mapping
        self.timeout = 1.0

    def upload(self, idx, sub):
        key = (idx, sub)
        if key not in self.mapping:
            raise DummySdoAbortedError(0x06020000)
        value = self.mapping[key]
        if isinstance(value, Exception):
            raise value
        return value


class FakeBus:
    def __init__(self, messages=None):
        self._messages = list(messages or [])
        self.sent = []
        self.state = can.BusState.ACTIVE

    def send(self, msg, timeout=None):
        self.sent.append(msg)

    def recv(self, timeout=None):
        if self._messages:
            return self._messages.pop(0)
        return None

    def flush_tx_buffer(self):
        return None

    def flush_rx_buffer(self):
        return None

    def shutdown(self):
        return None


class FakeOD:
    def __init__(self, items):
        self._items = dict(items)

    def __len__(self):
        return len(self._items)

    def items(self):
        return self._items.items()

    @property
    def indices(self):
        return list(self._items.keys())

    def __contains__(self, key):
        return key in self._items

    def __getitem__(self, key):
        return self._items[key]


@pytest.fixture()
def fake_bus():
    return FakeBus()


@pytest.fixture()
def fake_od():
    return FakeOD({0x1000: {0: 0x1234}, 0x2000: {0: 0x01}})


@pytest.fixture()
def fake_sdo_responder():
    mapping = {
        (0x1000, 0): 0x12345678,
        (0x1001, 0): 0x10,
        (0x1008, 0): "Device",
        (0x1009, 0): "HW",
        (0x100A, 0): "FW",
        (0x1018, 0): 4,
        (0x1018, 1): 0x11111111,
        (0x1018, 2): 0x22222222,
        (0x1018, 3): 0x33333333,
        (0x1018, 4): 0x44444444,
    }
    return FakeSDOResponder(mapping)


@pytest.fixture()
def dummy_monitor(tmp_path):
    oracle = Oracle(persist_dir=str(tmp_path))
    rule = AlertRule(
        name="any_emcy",
        event_type="emcy",
        condition=lambda e: True,
        severity="warning",
    )
    oracle.add_alert_rule(rule)
    return oracle
