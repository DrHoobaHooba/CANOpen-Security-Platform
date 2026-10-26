import time

import can

from canopen_security_platform.monitoring.oracle import Oracle
from canopen_security_platform.monitoring.device_monitor import (
    DeviceMonitor,
    _DeviceResponseListener,
)


def _anomalies(oracle):
    return [
        e
        for e in oracle.get_event_log()
        if e.get("event_classification") == "device_anomaly_detected"
    ]


def test_emcy_with_error_code_is_anomaly():
    oracle = Oracle()
    lst = _DeviceResponseListener(oracle)
    # EMCY from node 10 (COB 0x08A) with non-zero error code
    lst.on_message_received(
        can.Message(
            arbitration_id=0x08A,
            data=bytes([0x30, 0x81, 0x01, 0, 0, 0, 0, 0]),
            is_extended_id=False,
        )
    )
    anomalies = _anomalies(oracle)
    assert lst.emcy_seen == 1
    assert len(anomalies) == 1
    assert anomalies[0]["type"] == "emcy"
    assert anomalies[0]["node_id"] == 10


def test_emcy_error_reset_is_not_anomaly():
    oracle = Oracle()
    lst = _DeviceResponseListener(oracle)
    # EMCY error-reset (code 0x0000) is an observed event, not an anomaly
    lst.on_message_received(
        can.Message(arbitration_id=0x08A, data=bytes(8), is_extended_id=False)
    )
    assert lst.emcy_seen == 1
    assert _anomalies(oracle) == []


def test_bootup_frame_is_reboot_anomaly():
    oracle = Oracle()
    lst = _DeviceResponseListener(oracle)
    # Heartbeat COB 0x70A with state byte 0x00 => boot-up
    lst.on_message_received(
        can.Message(arbitration_id=0x70A, data=bytes([0x00]), is_extended_id=False)
    )
    anomalies = _anomalies(oracle)
    assert lst.bootup_seen == 1
    assert len(anomalies) == 1
    assert anomalies[0]["type"] == "reboot"


def test_normal_heartbeat_is_not_anomaly():
    oracle = Oracle()
    lst = _DeviceResponseListener(oracle)
    # Heartbeat operational (0x05)
    lst.on_message_received(
        can.Message(arbitration_id=0x70A, data=bytes([0x05]), is_extended_id=False)
    )
    assert lst.heartbeat_seen == 1
    assert _anomalies(oracle) == []


def test_sync_and_extended_frames_ignored():
    oracle = Oracle()
    lst = _DeviceResponseListener(oracle)
    # SYNC (0x080) and an extended-id frame should both be ignored
    lst.on_message_received(
        can.Message(arbitration_id=0x080, data=bytes([0x00]), is_extended_id=False)
    )
    lst.on_message_received(
        can.Message(arbitration_id=0x08A, data=bytes([0x30, 0x81]), is_extended_id=True)
    )
    assert lst.frames_seen == 0
    assert oracle.get_event_log() == []


def test_monitor_start_stop_with_virtual_bus():
    oracle = Oracle()
    rx = can.Bus(interface="virtual", channel="dm-unit-test")
    tx = can.Bus(interface="virtual", channel="dm-unit-test")
    monitor = DeviceMonitor(oracle, rx)
    try:
        assert monitor.start() is True
        assert monitor.running is True

        tx.send(
            can.Message(
                arbitration_id=0x08A,
                data=bytes([0x10, 0x10, 0x01, 0, 0, 0, 0, 0]),
                is_extended_id=False,
            )
        )
        tx.send(
            can.Message(arbitration_id=0x70A, data=bytes([0x00]), is_extended_id=False)
        )

        deadline = time.time() + 2.0
        while monitor.frames_seen < 2 and time.time() < deadline:
            time.sleep(0.05)

        monitor.stop()
        assert monitor.running is False
        assert monitor.frames_seen == 2
        anomalies = _anomalies(oracle)
        assert {e["type"] for e in anomalies} == {"emcy", "reboot"}
    finally:
        tx.shutdown()
        rx.shutdown()


def test_monitor_without_bus_is_noop():
    oracle = Oracle()
    monitor = DeviceMonitor(oracle, None)
    assert monitor.start() is False
    assert monitor.running is False
    # stop() must be safe to call even when never started
    monitor.stop()


def _hb(node_id, state):
    return can.Message(
        arbitration_id=0x700 + node_id, data=bytes([state]), is_extended_id=False
    )


def test_state_regression_detected():
    oracle = Oracle()
    lst = _DeviceResponseListener(oracle)
    # Node 10 operational, then drops to stopped => regression anomaly
    lst.on_message_received(_hb(10, 0x05))
    lst.on_message_received(_hb(10, 0x04))
    anomalies = _anomalies(oracle)
    assert lst.state_regressions == 1
    assert len(anomalies) == 1
    assert anomalies[0]["type"] == "state_regression"
    assert anomalies[0]["node_id"] == 10


def test_normal_state_progression_not_regression():
    oracle = Oracle()
    lst = _DeviceResponseListener(oracle)
    # Pre-operational -> operational is a normal progression, not a regression
    lst.on_message_received(_hb(10, 0x7F))
    lst.on_message_received(_hb(10, 0x05))
    assert lst.state_regressions == 0
    assert _anomalies(oracle) == []


def test_liveness_timeout_and_recovery():
    oracle = Oracle()
    lst = _DeviceResponseListener(
        oracle, liveness_timeout_floor=0.5, liveness_interval_factor=3.0
    )
    # Two heartbeats so an interval can be learned and the node is "live".
    lst.on_message_received(_hb(10, 0x05))
    lst.on_message_received(_hb(10, 0x05))

    # No timeout immediately.
    assert lst.scan_timeouts(now=time.time()) == []

    # Far in the future the node is silent -> one timeout anomaly.
    timed_out = lst.scan_timeouts(now=time.time() + 100)
    assert timed_out == [10]
    assert lst.timeouts == 1
    timeout_events = [e for e in _anomalies(oracle) if e["type"] == "timeout"]
    assert len(timeout_events) == 1

    # Scanning again must not re-fire for the same silence episode.
    lst.scan_timeouts(now=time.time() + 200)
    assert lst.timeouts == 1

    # The node resuming heartbeats is a recovery and re-arms the watchdog.
    lst.on_message_received(_hb(10, 0x05))
    assert lst.recoveries == 1


def test_liveness_ignores_single_heartbeat():
    oracle = Oracle()
    lst = _DeviceResponseListener(oracle, liveness_timeout_floor=0.5)
    # Only one heartbeat: not enough to establish liveness, so never times out.
    lst.on_message_received(_hb(10, 0x05))
    assert lst.scan_timeouts(now=time.time() + 100) == []
    assert lst.timeouts == 0

