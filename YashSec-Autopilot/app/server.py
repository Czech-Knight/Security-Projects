from __future__ import annotations

import argparse
import os
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="YashSec Autopilot local backend")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--transport-token", default="")
    parser.add_argument("--data-dir", default="")
    parser.add_argument("--log-level", default="warning", choices=("critical", "error", "warning", "info", "debug"))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.host not in {"127.0.0.1", "localhost"}:
        raise SystemExit("YashSec refuses non-loopback backend binding.")

    os.environ["YASHSEC_HOST"] = args.host
    os.environ["YASHSEC_PORT"] = str(args.port)
    os.environ["YASHSEC_TRANSPORT_TOKEN"] = args.transport_token
    os.environ["YASHSEC_ENV"] = "production"
    os.environ["YASHSEC_DOCS_ENABLED"] = "false"
    if args.data_dir:
        data_dir = Path(args.data_dir).expanduser().resolve()
        data_dir.mkdir(parents=True, exist_ok=True)
        os.environ["YASHSEC_DATA_DIR"] = str(data_dir)

    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=args.host,
        port=args.port,
        log_level=args.log_level,
        access_log=False,
        reload=False,
        workers=1,
    )


if __name__ == "__main__":
    main()
