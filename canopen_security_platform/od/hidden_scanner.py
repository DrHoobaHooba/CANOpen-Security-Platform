"""Offline OD comparison and reporting helpers.

Live SDO enumeration is intentionally disabled. Use this module to compare
locally supplied scan results with an EDS or to exercise scanner logic with
test doubles that do not access a CAN bus.
"""

import json
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import canopen


class HiddenObjectScanner:
    """Compare supplied OD data and emit reports without probing live nodes."""

    def __init__(
        self,
        network: Any = None,
        max_workers: int = 1,
        sdo_timeout: float = 1.0,
    ) -> None:
        self.network = network
        self.max_workers = max(1, int(max_workers))
        self.sdo_timeout = float(sdo_timeout)
        self.results: Dict[int, Dict[int, Dict[int, Any]]] = {}
        self.scan_times: Dict[int, float] = {}

    def _require_disconnected_network(self) -> None:
        if self.network is None:
            return
        bus = getattr(self.network, "bus", None)
        if bus is None:
            bus = getattr(self.network, "_bus", None)
        if bus is not None:
            raise RuntimeError(
                "Live hidden-object SDO scanning is disabled. This scanner only "
                "supports offline data and disconnected test doubles."
            )

    def _probe_index(self, node: Any, index: int) -> Tuple[int, Dict[int, Any]]:
        """Probe a supplied test double; production bus enumeration is blocked."""
        values: Dict[int, Any] = {}
        try:
            count_value = node.sdo.upload(index, 0)
        except canopen.SdoAbortedError:
            return index, values
        except Exception:
            return index, values

        values[0] = count_value
        subindex_count = count_value if isinstance(count_value, int) else 0
        if 0 < subindex_count <= 0xFF:
            for subindex in range(1, subindex_count + 1):
                try:
                    values[subindex] = node.sdo.upload(index, subindex)
                except Exception:
                    continue
        return index, values

    def scan_node(
        self,
        node_id: int,
        index_range: Optional[Tuple[int, int]] = None,
        parallel: bool = True,
    ) -> Dict[int, Dict[int, Any]]:
        self._require_disconnected_network()
        if not isinstance(node_id, int) or not 1 <= node_id <= 127:
            raise ValueError(f"node_id must be from 1 to 127, got {node_id!r}")
        start, end = index_range or (0x1000, 0x1FFF)
        if not 0 <= start <= end <= 0xFFFF:
            raise ValueError("index_range must be an inclusive range within 0x0000-0xFFFF")

        started = time.monotonic()
        results: Dict[int, Dict[int, Any]] = {}
        for index in range(start, end + 1):
            _, values = self._probe_index(canopen.RemoteNode(node_id, None), index)
            if values:
                results[index] = values

        self.results[node_id] = results
        self.scan_times[node_id] = time.monotonic() - started
        return results

    def diff_with_eds(self, node_id: int, object_dictionary: Any) -> Dict[str, Any]:
        found = self.results.get(node_id, {})
        expected_indices = getattr(object_dictionary, "indices", None)
        if expected_indices is None and hasattr(object_dictionary, "keys"):
            expected_indices = object_dictionary.keys()
        expected = {int(index) for index in (expected_indices or ())}
        discovered = set(found)

        subindex_diffs: Dict[int, Dict[str, list]] = {}
        for index in sorted(expected & discovered):
            try:
                entry = object_dictionary[index]
            except (KeyError, TypeError):
                continue
            if isinstance(entry, dict):
                expected_subindices = {int(subindex) for subindex in entry}
            else:
                expected_subindices = {0}
            actual_subindices = set(found[index])
            missing_subindices = sorted(expected_subindices - actual_subindices)
            extra_subindices = sorted(actual_subindices - expected_subindices)
            if missing_subindices or extra_subindices:
                subindex_diffs[index] = {
                    "missing": missing_subindices,
                    "extra": extra_subindices,
                }

        return {
            "hidden": sorted(discovered - expected),
            "missing": sorted(expected - discovered),
            "subindex_diffs": subindex_diffs,
        }

    def get_statistics(self, node_id: int) -> Dict[str, Any]:
        node_results = self.results.get(node_id, {})
        return {
            "node_id": node_id,
            "objects_found": len(node_results),
            "subindices_found": sum(len(values) for values in node_results.values()),
            "scan_duration": self.scan_times.get(node_id, 0.0),
        }

    def export_report(self, node_id: int, output_path: str) -> str:
        destination = Path(output_path).expanduser()
        destination.parent.mkdir(parents=True, exist_ok=True)
        report = {
            "node_id": node_id,
            "results": self.results.get(node_id, {}),
            "statistics": self.get_statistics(node_id),
        }
        destination.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        return str(destination)