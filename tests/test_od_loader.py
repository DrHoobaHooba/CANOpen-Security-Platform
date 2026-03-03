import pytest
import canopen

from canopen_security_platform.od.eds_loader import EDSLoader


def test_load_missing_file():
    loader = EDSLoader()
    with pytest.raises(FileNotFoundError):
        loader.load("does_not_exist.eds")


def test_load_with_cache(monkeypatch, tmp_path, fake_od):
    eds_path = tmp_path / "device.eds"
    eds_path.write_text("[Device]\n")

    call_count = {"count": 0}

    def _import_od(path):
        call_count["count"] += 1
        return fake_od

    monkeypatch.setattr(canopen, "import_od", _import_od)

    loader = EDSLoader()
    od1 = loader.load(str(eds_path))
    od2 = loader.load(str(eds_path))

    assert od1 is od2
    assert call_count["count"] == 1

    loader.clear_cache()
    assert loader._cache == {}


def test_get_od_metadata_categories(fake_od):
    loader = EDSLoader()
    metadata = loader.get_od_metadata(fake_od)
    assert "manufacturer" in metadata["objects"] or "device_params" in metadata["objects"]


def test_load_from_node_invalid():
    class FakeNode:
        def __init__(self):
            self.node_id = 1
            self.object_dictionary = {}

    loader = EDSLoader()
    with pytest.raises(ValueError):
        loader.load_from_node(FakeNode())


def test_discover_default_od_file_prefers_eds(tmp_path):
    od_dir = tmp_path / "od_files"
    od_dir.mkdir()
    (od_dir / "device.xdd").write_text("<xdd/>")
    expected = od_dir / "device.eds"
    expected.write_text("[Device]\n")

    loader = EDSLoader()
    discovered = loader.discover_default_od_file(str(tmp_path))

    assert discovered == expected


def test_load_auto_xdd_uses_converter(monkeypatch, tmp_path, fake_od):
    xdd_path = tmp_path / "device.xdd"
    xdd_path.write_text("<xdd/>")
    generated_eds = tmp_path / "device.eds"
    generated_eds.write_text("[Device]\n")

    class FakeConverter:
        def is_available(self):
            return True

        def convert(self, xml_file):
            assert xml_file == str(xdd_path.resolve())
            return str(generated_eds.resolve())

    monkeypatch.setattr("canopen_security_platform.od.xdd_converter.XDDConverter", FakeConverter)
    monkeypatch.setattr(canopen, "import_od", lambda path: fake_od)

    loader = EDSLoader()
    od = loader.load_auto(str(xdd_path))

    assert od is fake_od
