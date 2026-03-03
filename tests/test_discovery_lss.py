import types
import pytest
import canopen

from canopen_security_platform.discovery.lss_scan import LSSScanner


class FakeIdentity:
    def __init__(self, vendor_id, product_code, revision_number, serial_number):
        self.vendor_id = vendor_id
        self.product_code = product_code
        self.revision_number = revision_number
        self.serial_number = serial_number


class FakeLssMaster:
    def broadcast_identification(self):
        return [FakeIdentity(1, 2, 3, 4)]

    def configure_node_id(self, node_id):
        return True

    def store_configuration(self):
        return True

    def query_identification(self, timeout=1.0):
        return True


def test_fast_scan_native(monkeypatch):
    network = canopen.Network()
    monkeypatch.setattr(canopen.lss, "LssMaster", FakeLssMaster)

    scanner = LSSScanner(network)
    results = scanner.fast_scan(timeout=1.0)
    assert results == [(1, 2, 3, 4)]


def test_assign_node_id_invalid():
    network = canopen.Network()
    scanner = LSSScanner(network)
    with pytest.raises(ValueError):
        scanner.assign_node_id((1, 2, 3, 4), 0)


def test_query_any_device_handles_exception(monkeypatch):
    network = canopen.Network()
    scanner = LSSScanner(network)

    class BadLss:
        def query_identification(self, timeout=1.0):
            raise RuntimeError("fail")

    scanner.lss = BadLss()
    scanner.has_lss_master = True
    assert scanner.query_any_device(timeout=0.1) is False


def test_query_any_device_invalid_timeout():
    network = canopen.Network()
    scanner = LSSScanner(network)
    with pytest.raises(ValueError):
        scanner.query_any_device(timeout=0)


def test_assign_next_available(monkeypatch):
    network = canopen.Network()
    scanner = LSSScanner(network)
    scanner.lss = FakeLssMaster()
    scanner.has_lss_master = True

    node_id = scanner.assign_next_available((1, 2, 3, 4))
    assert node_id == 1
    assert scanner.get_node_identity(1) == (1, 2, 3, 4)
    stats = scanner.get_statistics()
    assert stats["node_ids_assigned"] == 1
    assert scanner.get_discovered_nodes()[1] == (1, 2, 3, 4)
