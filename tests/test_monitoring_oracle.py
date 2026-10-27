import json
import time

from canopen_security_platform.monitoring.oracle import Oracle, AlertRule


def test_alert_rule_triggered(tmp_path):
    oracle = Oracle(persist_dir=str(tmp_path))
    rule = AlertRule(
        name="emcy_any",
        event_type="emcy",
        condition=lambda e: True,
        severity="warning",
    )
    oracle.add_alert_rule(rule)

    oracle.on_emcy(1, 0x1000, b"\x00\x00\x00\x00\x00")
    alerts = oracle.get_triggered_alerts()
    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "emcy_any"
    assert (tmp_path / "events.jsonl").exists()


def test_export_report(tmp_path):
    oracle = Oracle(persist_dir=str(tmp_path))
    oracle.on_heartbeat(1, 0x7F)
    output = tmp_path / "report.json"

    out_path = oracle.export_report(str(output))
    data = json.loads(output.read_text())

    assert out_path == str(output)
    assert data["statistics"]["total_events"] == 1


def test_get_node_summary():
    oracle = Oracle()
    oracle.on_heartbeat(1, 0x05)
    oracle.on_timeout(1)
    oracle.on_reboot(1)
    summary = oracle.get_node_summary(1)

    assert summary["heartbeat_count"] == 1
    assert summary["timeout_count"] == 1
    assert summary["reboot_count"] == 1


def test_event_log_and_decoders():
    oracle = Oracle()
    oracle.on_heartbeat(2, 0x7F)
    oracle.on_state_change(2, "old", "new")
    log = oracle.get_event_log(2)
    assert len(log) == 2
    assert oracle._decode_emcy_code(0x1000) == "(generic error)"
    assert oracle._nmt_state_name(0x7F) == "PRE_OPERATIONAL"


def test_record_event_classification_no_alert_for_fuzz_input():
    oracle = Oracle()
    oracle.add_alert_rule(
        AlertRule(
            name="emcy_any",
            event_type="emcy",
            condition=lambda e: True,
            severity="warning",
        )
    )

    oracle.record_event(
        {
            "type": "emcy",
            "node_id": 1,
            "error_code": 0x1000,
            "event_classification": "fuzz_input_sent",
        }
    )

    assert len(oracle.get_event_log()) == 1
    assert len(oracle.get_triggered_alerts()) == 0


def test_record_event_classification_alert_for_device_anomaly():
    oracle = Oracle()
    oracle.add_alert_rule(
        AlertRule(
            name="timeout_any",
            event_type="timeout",
            condition=lambda e: True,
            severity="critical",
        )
    )

    oracle.record_event(
        {
            "type": "timeout",
            "node_id": 7,
            "event_classification": "device_anomaly_detected",
        }
    )

    assert len(oracle.get_triggered_alerts()) == 1
    assert oracle.get_triggered_alerts()[0]["rule_name"] == "timeout_any"


def test_anomaly_inside_injection_window_is_induced():
    oracle = Oracle()
    oracle.begin_injection_window("NMT Fuzzing")
    oracle.on_state_regression(10, "OPERATIONAL", "STOPPED")
    oracle.end_injection_window("NMT Fuzzing")

    event = oracle.get_event_log()[-1]
    assert event["correlation"] == "induced"
    assert event["correlation_stage"] == "NMT Fuzzing"


def test_anomaly_outside_injection_window_is_spontaneous():
    oracle = Oracle()
    # No window open at all.
    oracle.on_reboot(10)

    event = oracle.get_event_log()[-1]
    assert event["correlation"] == "spontaneous"
    assert "correlation_stage" not in event


def test_anomaly_after_window_but_within_grace_is_induced():
    oracle = Oracle(induced_anomaly_grace=5.0)
    oracle.begin_injection_window("State Machine Fuzzing")
    oracle.end_injection_window("State Machine Fuzzing")
    # Window just closed; grace of 5s still applies.
    oracle.on_timeout(10)

    event = oracle.get_event_log()[-1]
    assert event["correlation"] == "induced"
    assert event["correlation_stage"] == "State Machine Fuzzing"


def test_anomaly_after_grace_expires_is_spontaneous():
    oracle = Oracle(induced_anomaly_grace=0.0)
    oracle.begin_injection_window("NMT Fuzzing")
    oracle.end_injection_window("NMT Fuzzing")
    time.sleep(0.01)  # past the zero grace period
    oracle.on_reboot(10)

    event = oracle.get_event_log()[-1]
    assert event["correlation"] == "spontaneous"


def test_record_event_anomaly_is_correlated():
    oracle = Oracle()
    oracle.begin_injection_window("NMT Fuzzing")
    oracle.record_event(
        {
            "type": "state_regression",
            "node_id": 5,
            "event_classification": "device_anomaly_detected",
        }
    )
    oracle.end_injection_window("NMT Fuzzing")

    event = oracle.get_event_log()[-1]
    assert event["correlation"] == "induced"
    assert event["correlation_stage"] == "NMT Fuzzing"


def test_fuzz_input_event_not_correlated():
    oracle = Oracle()
    oracle.begin_injection_window("NMT Fuzzing")
    oracle.record_event(
        {
            "type": "nmt",
            "node_id": 5,
            "event_classification": "fuzz_input_sent",
        }
    )
    oracle.end_injection_window("NMT Fuzzing")

    event = oracle.get_event_log()[-1]
    assert "correlation" not in event
