from __future__ import annotations

import argparse
import json

from app import db
from app.core.tool_registry import inspect_all_tools
from app.core.ai_service import provider_health


def main() -> None:
    parser = argparse.ArgumentParser(description="YashSec Autopilot utilities")
    parser.add_argument("command", choices=["init", "doctor"])
    args = parser.parse_args()
    db.init_db()
    if args.command == "init":
        print("YashSec database initialised. Create the first local owner in the first-run wizard.")
    else:
        tools = inspect_all_tools()
        print("\nYashSec Autopilot tool diagnostic\n")
        for tool in tools:
            status = "READY" if tool["available"] else "MISSING"
            print(f"[{status:7}] {tool['name']}")
            if tool["version"]:
                print(f"          {tool['version']}")
            if not tool["available"]:
                for step in tool["install_windows"]:
                    print(f"          - {step}")
        try:
            health = provider_health()
        except Exception as exc:
            health = {"error": str(exc)}
        print("\nLocal AI providers")
        if "error" in health:
            print(f"[ERROR  ] Provider check failed: {health['error']}")
        else:
            print(f"[{'READY' if health.get('ollama') else 'MISSING':7}] Ollama at {health['config']['ollama_url']}")
            print(f"[{'READY' if health.get('airllm') else 'MISSING':7}] AirLLM worker at {health['config']['airllm_url']}")
        print("\nJSON summary:\n" + json.dumps({"tools": tools, "ai": health}, indent=2))


if __name__ == "__main__":
    main()
