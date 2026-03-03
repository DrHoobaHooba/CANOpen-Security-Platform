import pytest
import canopen

from canopen_security_platform.discovery import sdo_probe
from canopen_security_platform.discovery.sdo_probe import SDOProbe


class FakeRemoteNode:
    def __init__(self, node_id, sdo):
        self.node_id = node_id
        self.sdo = sdo


def test_probe_success(monkeypatch, fake_sdo_responder):
    network = canopen.Network()

    def _fake_remote_node(node_id, _):
        return FakeRemoteNode(node_id, fake_sdo_responder)

    monkeypatch.setattr(sdo_probe.canopen, "RemoteNode", _fake_remote_node)
    monkeypatch.setattr(sdo_probe.canopen, "SdoAbortedError", type("E", (Exception,), {}))

    probe = SDOProbe(network, timeout=0.1, retries=0)
    info = probe.probe(1)
    assert info is not None
    assert info["node_id"] == 1
    assert "identity" in info
    assert info["identity"].get("vendor_id") == 0x11111111

    stats = probe.get_statistics()
    assert stats["nodes_probed"] == 1
    assert 1 in probe.get_probed_nodes()
    assert probe.get_probe_result(1) is not None


def test_probe_timeout_returns_none(monkeypatch, fake_sdo_responder):
    network = canopen.Network()

    class TimeoutSDO:
        def __init__(self):
            self.timeout = 1.0

        def upload(self, idx, sub):
            raise TimeoutError("timeout")

    def _fake_remote_node(node_id, _):
        return FakeRemoteNode(node_id, TimeoutSDO())

    monkeypatch.setattr(sdo_probe.canopen, "RemoteNode", _fake_remote_node)
    monkeypatch.setattr(sdo_probe.canopen, "SdoAbortedError", type("E", (Exception,), {}))

    probe = SDOProbe(network, timeout=0.1, retries=0)
    info = probe.probe(1)
    assert info is None


def test_scan_invalid_range():
    network = canopen.Network()
    probe = SDOProbe(network)
    with pytest.raises(ValueError):
        probe.scan(start=10, end=1)


def test_query_identity_handles_abort(monkeypatch, fake_sdo_responder):
    network = canopen.Network()

    class AbortSDO:
        def __init__(self):
            self.timeout = 1.0

        def upload(self, idx, sub):
            if (idx, sub) == (0x1018, 0):
                return 1
            raise sdo_probe.canopen.SdoAbortedError("abort")

    def _fake_remote_node(node_id, _):
        return FakeRemoteNode(node_id, AbortSDO())

    monkeypatch.setattr(sdo_probe.canopen, "RemoteNode", _fake_remote_node)
    monkeypatch.setattr(sdo_probe.canopen, "SdoAbortedError", type("E", (Exception,), {}))

    probe = SDOProbe(network, timeout=0.1, retries=0)
    identity = probe._query_identity_object(FakeRemoteNode(1, AbortSDO()))
    assert identity.get("num_entries") == 1
