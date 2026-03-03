import random
import can
import pytest

from canopen_security_platform.fuzzing.sdo_fuzzer import SDOFuzzer, SDOMutationStrategy
from canopen_security_platform.od.runtime_od import RuntimeObjectDictionary


class FakeBus:
    def __init__(self):
        self.sent = []

    def send(self, msg, timeout=None):
        self.sent.append(msg)


def test_execute_records_results():
    random.seed(1)
    bus = FakeBus()
    od = RuntimeObjectDictionary()

    fuzzer = SDOFuzzer(bus, od, 1, lambda e: None)
    fuzzer.execute()

    results = fuzzer.get_results()
    assert results["total_mutations"] > 0
    assert results["strategies_used"] > 0


def test_send_sdo_request_padding():
    bus = FakeBus()
    od = RuntimeObjectDictionary()
    fuzzer = SDOFuzzer(bus, od, 1, lambda e: None)

    fuzzer._send_sdo_request(bytearray(b"\x01\x02\x03"), SDOMutationStrategy.MUTATION_CS)
    assert len(bus.sent) == 1
    assert isinstance(bus.sent[0], can.Message)
    assert len(bus.sent[0].data) == 8


def test_invalid_node_id():
    bus = FakeBus()
    od = RuntimeObjectDictionary()
    with pytest.raises(ValueError):
        SDOFuzzer(bus, od, 0, lambda e: None)
