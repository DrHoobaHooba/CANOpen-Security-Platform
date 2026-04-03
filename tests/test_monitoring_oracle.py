import json

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
