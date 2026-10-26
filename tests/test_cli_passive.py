import can

from canopen_security_platform.cli import main as cli


def test_passive_enumeration_uses_hardware_listen_only(monkeypatch, tmp_path):
    class FakeBus:
        def __init__(self):
            self.messages = [
                can.Message(arbitration_id=0x70A, data=b"\x7f", is_extended_id=False)
            ]
            self.closed = False

        def recv(self, timeout=None):
            return self.messages.pop(0) if self.messages else None

        def shutdown(self):
            self.closed = True

    fake_bus = FakeBus()
    bus_options = {}

    def create_bus(**kwargs):
        bus_options.update(kwargs)
        return fake_bus

    monkeypatch.setattr(cli.can, "Bus", create_bus)
    output_path = tmp_path / "inventory.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "cansec",
            "--bitrate", "250000",
            "--channel", "PCAN_USBBUS1",
            "enumerate",
            "--passive-only",
            "--timeout", "0.01",
            "--output", str(output_path),
        ],
    )

    assert cli.main() == 0
    assert bus_options["state"] is can.BusState.PASSIVE
    assert bus_options["receive_own_messages"] is False
    assert fake_bus.closed
    assert '"10"' in output_path.read_text(encoding="utf-8")