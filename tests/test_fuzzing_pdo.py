import random
import pytest

from canopen_security_platform.fuzzing.pdo_fuzzer import PDOFuzzer
from canopen_security_platform.od.runtime_od import RuntimeObjectDictionary


class FakeBus:
    def __init__(self):
        self.sent = []

    def send(self, msg, timeout=None):
        self.sent.append(msg)


def test_execute_collects_results(monkeypatch):
    bus = FakeBus()
    od = RuntimeObjectDictionary()
    fuzzer = PDOFuzzer(bus, od, 1, lambda e: None)

    monkeypatch.setattr("canopen_security_platform.fuzzing.pdo_fuzzer.time.sleep", lambda s: None)
    fuzzer.execute()

    results = fuzzer.get_results()
    assert results["total_mutations"] > 0
    assert results["strategies_used"] > 0


def test_data_payload_fuzzing_sends():
    bus = FakeBus()
    od = RuntimeObjectDictionary()
    fuzzer = PDOFuzzer(bus, od, 1, lambda e: None)

    fuzzer.data_payload_fuzzing()
    assert len(bus.sent) > 0


def test_set_pdo_param_and_mapping():
    bus = FakeBus()
    od = RuntimeObjectDictionary()
    fuzzer = PDOFuzzer(bus, od, 1, lambda e: None)

    fuzzer._set_pdo_param(1, "RPDO", cob_id=0x200)
    fuzzer._set_pdo_mapping(1, "RPDO", mapping_entry=0x10080010)
    results = fuzzer.get_results()
    assert results["total_mutations"] >= 2


def test_invalid_node_id():
    bus = FakeBus()
    od = RuntimeObjectDictionary()
    with pytest.raises(ValueError):
        PDOFuzzer(bus, od, 0, lambda e: None)
