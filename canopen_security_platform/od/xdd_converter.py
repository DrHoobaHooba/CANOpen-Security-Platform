"""Optional external XDD/XDC-to-EDS converter integration."""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional


class XDDConverter:
    """Invoke a separately installed XDD-to-EDS conversion utility."""

    def __init__(self, executable: Optional[str] = None, timeout: float = 30.0) -> None:
        self.executable = executable or os.environ.get("CANOPEN_XDD_CONVERTER", "xdd2eds")
        self.timeout = timeout

    def is_available(self) -> bool:
        return shutil.which(self.executable) is not None

    def convert(self, xml_file: str, output_file: Optional[str] = None) -> str:
        source = Path(xml_file).expanduser().resolve()
        if not source.is_file():
            raise FileNotFoundError(source)
        if source.suffix.lower() not in {".xdd", ".xdc"}:
            raise ValueError(f"Expected an .xdd or .xdc file: {source}")

        executable = shutil.which(self.executable)
        if executable is None:
            raise RuntimeError(
                "XDD/XDC conversion is unavailable; install an xdd2eds-compatible "
                "converter or set CANOPEN_XDD_CONVERTER"
            )

        destination = (
            Path(output_file).expanduser().resolve()
            if output_file
            else source.with_suffix(".eds")
        )
        completed = subprocess.run(
            [executable, str(source), str(destination)],
            capture_output=True,
            text=True,
            timeout=self.timeout,
            check=False,
        )
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip()
            raise RuntimeError(
                f"XDD converter exited with status {completed.returncode}"
                + (f": {detail}" if detail else "")
            )
        if not destination.is_file() or destination.stat().st_size == 0:
            raise RuntimeError(f"XDD converter did not produce a valid EDS file: {destination}")
        return str(destination)