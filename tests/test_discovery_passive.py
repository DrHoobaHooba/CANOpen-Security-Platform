import pytest
import can

from canopen_security_platform.discovery.passive import PassiveDiscovery, NMTState


def test_nmt_state_str():
    assert str(NMTState.OPERATIONAL) == "OPERATIONAL"


def test_parse_heartbeat_emcy_and_pdo(fake_bus):
    discovery = PassiveDiscovery(fake_bus)

    hb = can.Message(
        arbitration_id=0x701,
        data=bytes([0x7F]),
        is_extended_id=False,
    )
    emcy = can.Message(
        arbitration_id=0x081,
        data=bytes([0x01, 0x10, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00]),
        is_extended_id=False,
    )
    pdo = can.Message(
        arbitration_id=0x181,
        data=bytes([0xAA] * 8),
        is_extended_id=False,
    )

    node_id_hb = discovery._parse_frame(hb)
    node_id_emcy = discovery._parse_frame(emcy)
    node_id_pdo = discovery._parse_frame(pdo)

    assert node_id_hb == 1
    assert node_id_emcy == 1
    assert node_id_pdo == 1
    assert discovery.get_node_info(1) is not None
    assert len(discovery.get_emcy_history(1)) == 1
    all_info = discovery.get_all_node_info()
    assert 1 in all_info


def test_classify_error_code_ranges():
    assert PassiveDiscovery._classify_error_code(0x0000) == "Error Reset or No Error"
    assert PassiveDiscovery._classify_error_code(0x1001) == "Generic Error"
    assert PassiveDiscovery._classify_error_code(0x9001) == "External Error"


def test_run_timeout_invalid(fake_bus):
    discovery = PassiveDiscovery(fake_bus)
    with pytest.raises(ValueError):
        discovery.run(timeout=0)


def test_run_handles_can_error(monkeypatch):
    class ErrorBus:
        def recv(self, timeout=None):
            raise can.CanOperationError("rx error")

    discovery = PassiveDiscovery(ErrorBus())

    times = [0.0, 0.0, 0.6, 1.2]
    it = iter(times)
    monkeypatch.setattr("canopen_security_platform.discovery.passive.time.time", lambda: next(it))

    nodes = discovery.run(timeout=1.0)
    assert nodes == set()
    stats = discovery.get_statistics()
    assert stats["frame_stats"]["invalid"] >= 1
