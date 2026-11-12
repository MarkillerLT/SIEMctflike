"""
siem-ctf — server launcher.

Run with:  python -m server

Picks the port to bind (honoring the PORT env var, otherwise auto-selecting a
free one from config.PORT_CANDIDATES), records it so the other CLIs can find it,
prints the LAN URL classmates should use, then starts Uvicorn.
"""

import atexit

import uvicorn

from . import config
from .main import app


def main() -> None:
    port = config.resolve_port()
    config.write_runtime_port(port)
    # Belt-and-suspenders: also clear the runtime port file on interpreter exit,
    # not just via the finally below (covers paths where uvicorn exits early).
    atexit.register(config.clear_runtime_port)

    ip = config.lan_ip()
    print(f"[*] siem-ctf server starting on {config.HOST}:{port}  (Ctrl-C to stop)")
    if port != config.DEFAULT_PORT:
        import os
        if os.environ.get("PORT"):
            print(f"[*] using requested port {port}")
        else:
            print(f"[*] port {config.DEFAULT_PORT} was busy — fell back to {port}")
    print(f"[*] classmates connect to:  ws://{ip}:{port}/ws")
    print(f"[*] local monitor/attacker:  ws://127.0.0.1:{port}/ws")

    try:
        uvicorn.run(app, host=config.HOST, port=port)
    finally:
        config.clear_runtime_port()


if __name__ == "__main__":
    main()
