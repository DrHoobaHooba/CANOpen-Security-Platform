"""EDS loading, caching, discovery, and object-dictionary metadata helpers."""

import logging
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import canopen

logger = logging.getLogger(__name__)


class EDSLoader:
    """Load EDS files through python-canopen and cache parsed dictionaries."""

    DEFAULT_DIRECTORIES = (
        "od_files",
        "object_dictionary",
        "object_dictionaries",
        "od",
        "eds",
    )
    FILE_PRIORITY = (".eds", ".xdc", ".xdd")

    def __init__(self, cache_dir: Optional[str] = None) -> None:
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self._cache: Dict[Tuple[str, int, int], Any] = {}

    def load(self, path: str):
        source = Path(path).expanduser()
        if not source.is_file():
            raise FileNotFoundError(source)

        resolved = source.resolve()
        stat = resolved.stat()
        cache_key = (str(resolved), stat.st_mtime_ns, stat.st_size)
        if cache_key in self._cache:
            return self._cache[cache_key]

        object_dictionary = canopen.import_od(str(resolved))
        self._cache[cache_key] = object_dictionary
        return object_dictionary

    def load_auto(self, path: str):
        source = Path(path).expanduser().resolve()
        if not source.is_file():
            raise FileNotFoundError(source)
        suffix = source.suffix.lower()
        if suffix == ".eds":
            return self.load(str(source))
        if suffix not in {".xdd", ".xdc"}:
            raise ValueError(f"Unsupported object-dictionary format: {source.suffix}")

        from .xdd_converter import XDDConverter

        converter = XDDConverter()
        if not converter.is_available():
            raise RuntimeError("No XDD/XDC converter is available")
        converted_path = converter.convert(str(source))
        return self.load(converted_path)

    def clear_cache(self) -> None:
        self._cache.clear()

    def discover_default_od_file(self, search_dir: Optional[str] = None) -> Optional[Path]:
        root = Path(search_dir or Path.cwd()).expanduser().resolve()
        for directory_name in self.DEFAULT_DIRECTORIES:
            directory = root / directory_name
            if not directory.is_dir():
                continue
            for extension in self.FILE_PRIORITY:
                candidates = sorted(directory.glob(f"*{extension}"))
                if candidates:
                    return candidates[0]
        return None

    def get_od_metadata(self, object_dictionary: Any) -> Dict[str, Any]:
        categories = {
            "device_params": [],
            "manufacturer": [],
            "device_profile": [],
            "communication": [],
            "other": [],
        }
        indices = getattr(object_dictionary, "indices", None)
        if indices is None and hasattr(object_dictionary, "keys"):
            indices = object_dictionary.keys()

        for raw_index in indices or ():
            try:
                index = int(raw_index)
            except (TypeError, ValueError):
                continue
            if 0x1000 <= index <= 0x1FFF:
                category = "device_params"
            elif 0x2000 <= index <= 0x5FFF:
                category = "manufacturer"
            elif 0x6000 <= index <= 0x9FFF:
                category = "device_profile"
            elif 0x0000 <= index <= 0x0FFF:
                category = "communication"
            else:
                category = "other"

            try:
                entry = object_dictionary[index]
                name = getattr(entry, "name", None)
            except (KeyError, TypeError, AttributeError):
                name = None
            categories[category].append({"index": index, "name": name})

        return {
            "objects": categories,
            "counts": {name: len(entries) for name, entries in categories.items()},
            "total": sum(map(len, categories.values())),
        }

    def load_from_node(self, node: Any):
        object_dictionary = getattr(node, "object_dictionary", None)
        if object_dictionary is None or not hasattr(object_dictionary, "__len__"):
            raise ValueError("Node does not provide a valid object dictionary")
        if len(object_dictionary) == 0:
            raise ValueError("Node object dictionary is empty")
        return object_dictionary