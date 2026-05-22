from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
from datetime import datetime


class NmapNotInstalledError(RuntimeError):
    pass


NMAP_PATH = r"C:\Program Files (x86)\Nmap\nmap.exe"


class NmapRunner:
    def __init__(self, output_dir: str | Path = "scan_outputs"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def ensure_available(self) -> None:
        if Path(NMAP_PATH).exists():
            return

        if shutil.which("nmap") is None:
            raise NmapNotInstalledError(
                "Nmap was not found. Check NMAP_PATH or add Nmap to PATH."
            )

    def get_nmap_command(self) -> str:
        if Path(NMAP_PATH).exists():
            return NMAP_PATH
        return "nmap"

    def run_scan(self, target: str, profile: str = "service_inventory") -> Path:
        self.ensure_available()

        nmap_command = self.get_nmap_command()

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"nmap_scan_{timestamp}.xml"

        if profile == "discovery":
            command = [nmap_command, "-sn", "-oX", str(output_file), target]
        elif profile == "service_inventory":
            command = [
                nmap_command,
                "-sV",
                "--top-ports",
                "1000",
                "-oX",
                str(output_file),
                target,
            ]
        else:
            raise ValueError("Unsupported profile. Use 'discovery' or 'service_inventory'.")

        result = subprocess.run(command, capture_output=True, text=True, check=False)

        if result.returncode != 0:
            raise RuntimeError(
                f"Nmap scan failed.\nCommand: {' '.join(command)}\nSTDERR:\n{result.stderr}"
            )

        return output_file