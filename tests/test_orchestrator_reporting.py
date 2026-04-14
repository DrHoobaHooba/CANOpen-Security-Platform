import json
from datetime import datetime, timedelta

from canopen_security_platform.orchestrator.run_full_security_suite import SecurityTestSuite, TestResults as SuiteResults


ALL_FUZZER_KEYS = {
    "sdo",
    "pdo",
    "nmt",
    "emcy",
    "sync",
    "concurrent",
    "canid",
    "timing",
    "resource",
    "state_machine",
}


def build_suite() -> SecurityTestSuite:
    suite = SecurityTestSuite()
    suite.config = {
        "tests": {},
        "reporting": {},
    }
    suite.results = SuiteResults(config=suite.config)
    suite.results.start_time = datetime(2026, 4, 14, 10, 0, 0)
    suite.results.end_time = suite.results.start_time + timedelta(seconds=42)
    suite.results.completed_stages = ["PCAN Connection", "Monitoring Collection"]
    suite.results.failed_stages = []
    suite.results.sdo_fuzzing_results = {112: {"total_tests": 31, "fuzz_input_events": 0, "device_anomalies": 0, "test_results": []}}
    suite.results.pdo_fuzzing_results = {112: {"total_tests": 137, "fuzz_input_events": 0, "device_anomalies": 0, "test_results": []}}
    suite.results.nmt_fuzzing_results = {112: {"total_tests": 128, "fuzz_input_events": 0, "device_anomalies": 0, "test_results": []}}
    suite.results.emcy_fuzzing_results = {112: {"total_tests": 3510, "fuzz_input_events": 3420, "device_anomalies": 0, "test_results": []}}
    suite.results.sync_fuzzing_results = {"total_tests": 3680, "fuzz_input_events": 3580, "device_anomalies": 0, "test_results": []}
    suite.results.concurrent_fuzzing_results = {112: {"total_tests": 64, "fuzz_input_events": 0, "device_anomalies": 0, "test_results": []}}
    suite.results.canid_fuzzing_results = {112: {"total_tests": 381, "fuzz_input_events": 381, "device_anomalies": 0, "test_results": []}}
    suite.results.timing_fuzzing_results = {112: {"total_tests": 628, "fuzz_input_events": 628, "device_anomalies": 0, "test_results": []}}
    suite.results.resource_fuzzing_results = {112: {"total_tests": 24573, "fuzz_input_events": 104, "device_anomalies": 0, "test_results": []}}
    suite.results.state_machine_fuzzing_results = {112: {"total_tests": 0, "fuzz_input_events": 0, "device_anomalies": 0, "test_results": []}}
    suite.results.hidden_objects = {112: {0x2000: {0: "rw", 1: "ro"}, 0x2001: {0: "rw"}}}
    suite.results.fuzz_input_events = [{"fuzzer": "emcy"}, {"fuzzer": "sync"}]
    suite.results.device_anomaly_events = []
    suite.results.emcy_events = []
    suite.results.heartbeat_anomalies = []
    suite.results.oracle_alerts = []
    return suite


def test_export_json_includes_complete_fuzzing_schema(tmp_path):
    suite = build_suite()
    output_path = tmp_path / "results.json"

    suite._export_json(output_path, include_report_generation=True)
    data = json.loads(output_path.read_text())

    assert data["duration"] == 42.0
    assert set(data["fuzzing"].keys()) == ALL_FUZZER_KEYS
    assert "Report Generation" in data["summary"]["completed_stages"]
    assert data["fuzzing"]["emcy"]["112"]["fuzz_input_events"] == 3420
    assert data["fuzzing"]["sync"]["total_tests"] == 3680


def test_generate_html_report_handles_hidden_object_mapping(tmp_path):
    suite = build_suite()
    output_path = tmp_path / "report.html"

    suite._generate_html_report(output_path, include_report_generation=True)
    html = output_path.read_text(encoding="utf-8")

    assert "42.0 seconds" in html
    assert "Node 112: 2 hidden indices" in html
    assert "0x2000" in html
    assert "State Machine Fuzzing" in html
    assert "SYNC Fuzzing" in html
