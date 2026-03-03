import json
import pytest
import canopen

from canopen_security_platform.od import hidden_scanner
from canopen_security_platform.od.hidden_scanner import HiddenObjectScanner


class FakeRemoteNode:
    def __init__(self, node_id, sdo):
        self.node_id = node_id
        self.sdo = sdo


def test_probe_index_collects_subindices(monkeypatch):
    network = canopen.Network()
    scanner = HiddenObjectScanner(network)

    class DummyAbort(Exception):
        def __init__(self, code=0x06020000):
            self.code = code

    monkeypatch.setattr(hidden_scanner.canopen, "SdoAbortedError", DummyAbort)

    class LocalSDO:
        def upload(self, idx, sub):
            if (idx, sub) == (0x1000, 0):
                return 0x1234
            raise DummyAbort(0x06020000)

    def _fake_remote_node(node_id, _):
        return FakeRemoteNode(node_id, LocalSDO())

    monkeypatch.setattr(hidden_scanner.canopen, "RemoteNode", _fake_remote_node)

    idx, sub_results = scanner._probe_index(FakeRemoteNode(1, LocalSDO()), 0x1000)
    assert idx == 0x1000
    assert 0 in sub_results


def test_scan_node_sequential(monkeypatch):
    network = canopen.Network()
    scanner = HiddenObjectScanner(network)

    def _fake_remote_node(node_id, _):
        class LocalNode:
            def __init__(self, node_id):
                self.node_id = node_id
                self.sdo = type("SDO", (), {"timeout": 0.1})()
        return LocalNode(node_id)

    monkeypatch.setattr(hidden_scanner.canopen, "RemoteNode", _fake_remote_node)

    def _probe_index(node, idx):
        return (idx, {0: idx})

    monkeypatch.setattr(scanner, "_probe_index", _probe_index)
    results = scanner.scan_node(1, index_range=(0x1000, 0x1001), parallel=False)
    assert set(results.keys()) == {0x1000, 0x1001}
    stats = scanner.get_statistics(1)
    assert stats["objects_found"] == 2


def test_diff_with_eds(fake_od):
    network = canopen.Network()
    scanner = HiddenObjectScanner(network)

    scanner.results[1] = {0x2000: {0: 1}}
    diffs = scanner.diff_with_eds(1, fake_od)
    assert 0x2000 in diffs["hidden"]
    assert 0x1000 in diffs["missing"] or 0x2000 in diffs["hidden"]


def test_export_report(tmp_path):
    network = canopen.Network()
    scanner = HiddenObjectScanner(network)

    scanner.results[1] = {0x1000: {0: 123}}
    scanner.scan_times[1] = 0.1

    report_path = tmp_path / "scan.json"
    out_path = scanner.export_report(1, str(report_path))
    data = json.loads(report_path.read_text())

    assert out_path == str(report_path)
    assert data["node_id"] == 1
