"""In-memory object-dictionary snapshots and local modification tracking."""

from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple


class RuntimeObjectDictionary:
    """Track local OD snapshots without issuing SDO requests to a device."""

    def __init__(self) -> None:
        self.nodes: Dict[int, Any] = {}
        self.node_values: Dict[int, Dict[Tuple[int, int], Any]] = {}
        self.modifications: Dict[int, list] = {}
        self.sync_status: Dict[int, Dict[str, Any]] = {}

    def register_node(self, node: Any, sync_on_register: bool = False) -> Any:
        node_id = getattr(node, "node_id", None)
        object_dictionary = getattr(node, "object_dictionary", None)
        if not isinstance(node_id, int) or not 1 <= node_id <= 127:
            raise ValueError(f"node must have a CANopen node_id from 1 to 127, got {node_id!r}")
        if object_dictionary is None:
            raise ValueError(f"node {node_id} has no object dictionary")

        self.nodes[node_id] = object_dictionary
        self.node_values.setdefault(node_id, {})
        self.modifications.setdefault(node_id, [])
        if sync_on_register:
            self.sync_from_node(node)
        return object_dictionary

    def sync_from_node(self, node: Any) -> Dict[Tuple[int, int], Any]:
        """Snapshot values already present locally; this never reads from the bus."""
        node_id = getattr(node, "node_id", None)
        if node_id not in self.nodes:
            self.register_node(node)

        object_dictionary = self.nodes[node_id]
        values = self.node_values[node_id]
        indices = getattr(object_dictionary, "indices", ())
        if callable(indices):
            indices = indices()
        if not indices and hasattr(object_dictionary, "keys"):
            indices = object_dictionary.keys()

        for raw_index in indices:
            try:
                index = int(raw_index)
                entry = object_dictionary[index]
            except (KeyError, TypeError, ValueError):
                continue

            if isinstance(entry, dict):
                subentries = entry.items()
            else:
                subentries = ((0, getattr(entry, "value", None)),)

            for raw_subindex, value in subentries:
                try:
                    subindex = int(raw_subindex)
                except (TypeError, ValueError):
                    continue
                values[(index, subindex)] = value

        self.sync_status[node_id] = {
            "synced_at": datetime.now(timezone.utc).isoformat(),
            "source": "local_object_dictionary",
            "values": len(values),
        }
        return dict(values)

    def get_value(self, node_id: int, index: int, subindex: int = 0, default: Any = None) -> Any:
        return self.node_values.get(node_id, {}).get((index, subindex), default)

    def set_value(
        self,
        node_id: int,
        index: int,
        subindex: int,
        value: Any,
        source: str = "local",
    ) -> None:
        if node_id not in self.nodes:
            raise KeyError(f"node {node_id} is not registered")
        key = (index, subindex)
        values = self.node_values.setdefault(node_id, {})
        previous = values.get(key)
        values[key] = value
        self.modifications.setdefault(node_id, []).append(
            {
                "index": index,
                "subindex": subindex,
                "old_value": previous,
                "new_value": value,
                "source": source,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )