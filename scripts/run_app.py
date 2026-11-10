"""Start the Tollgate web app on http://127.0.0.1:8000 (this computer only).

    .venv\\Scripts\\python.exe scripts\\run_app.py            # demo mode (default)
    .venv\\Scripts\\python.exe scripts\\run_app.py --port 8001

Settings come from environment variables, loaded from .env if present (values are never
printed): TOLLGATE_AUTH_MODE (demo | real), TOLLGATE_SESSION_KEY (real mode),
TOLLGATE_MODE (mock | sandbox), TOLLGATE_DATA_DIR (default: data).

There is deliberately no --host option: the app listens on 127.0.0.1 only.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

HOST = "127.0.0.1"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the Tollgate web app (localhost only).")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        print("port must be between 1024 and 65535")
        return 2

    from dotenv import load_dotenv
    import uvicorn

    from tollgate.app.main import create_app
    from tollgate.config import ConfigError

    load_dotenv(ROOT / ".env")          # loads values silently; never prints them
    try:
        app = create_app()
    except ConfigError as exc:          # messages name variables, never values
        print(f"Not started: {exc}")
        return 2
    mode = app.state.ctx.mode.value
    print(f"Tollgate ({mode} mode) on http://{HOST}:{args.port}  (Ctrl+C to stop)")
    uvicorn.run(app, host=HOST, port=args.port, log_level="warning", access_log=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
