"""
Optional Azure CLI collector starter.

The demo project uses CSV data by default. For real Azure data:
1. Install Azure CLI.
2. Run: az login
3. Run collector methods to export JSON from your authorised subscription.
"""

import json
import subprocess
from typing import Any, Dict, List


class AzureCliCollector:
    @staticmethod
    def _run_az(args: List[str]) -> Any:
        completed = subprocess.run(
            ["az", *args, "--output", "json"],
            check=True,
            capture_output=True,
            text=True,
        )
        return json.loads(completed.stdout)

    def list_vms(self) -> List[Dict[str, Any]]:
        return self._run_az(["vm", "list", "--show-details"])

    def list_nsg_rules(self, resource_group: str, nsg_name: str) -> List[Dict[str, Any]]:
        return self._run_az([
            "network", "nsg", "rule", "list",
            "--resource-group", resource_group,
            "--nsg-name", nsg_name,
        ])
