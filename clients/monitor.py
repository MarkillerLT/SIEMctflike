#!/usr/bin/env python3
"""
siem-ctf — host SIEM monitor CLI.

Connects as a passive "host" and prints every login attempt in the classroom as
a live log line. Suspicious events (threshold crossed / lockouts) are highlighted,
and a running per-attacker attempt counter is shown.

Usage:
    python monitor.py --url ws://127.0.0.1:8000/ws
    (as the host you usually run this against your own machine, 127.0.0.1)
"""

import argparse
import asyncio
import json
import os
from collections import defaultdict

import websockets

if os.name == "nt":
    os.system("")   # enable ANSI colors in the Windows console

# ANSI colors (works in most terminals; harmless if not supported)
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
DIM = "\033[2m"
RESET = "\033[0m"

# per-attacker counters: {nickname: {"attempts": n, "fails": n}}
counters: dict[str, dict[str, int]] = defaultdict(lambda: {"attempts": 0, "fails": 0})


def render_event(event: dict) -> str:
    ts = event.get("timestamp", "")
    who = event.get("attacker", "?")
    user = event.get("username", "?")
    pw = event.get("password", "")
    result = event.get("result", "")
    risk = event.get("risk", "normal")
    level = event.get("level")

    if result in ("monitor_connected",):
        return f"{DIM}{ts}  host monitor connected{RESET}"

    # update counters for real attempts
    if result in ("incorrect", "success", "locked"):
        counters[who]["attempts"] += 1
        if result != "success":
            counters[who]["fails"] += 1

    c = counters[who]
    tag_level = f"[{level}]" if level else "[unknown-user]"

    if result == "success":
        body = (f"{GREEN}SUCCESS{RESET} {who} cracked {user}:{pw} {tag_level}")
    elif result == "locked":
        body = (f"{RED}LOCKED {RESET} {who} hit locked account {user} {tag_level}")
    elif risk == "suspicious":
        body = (f"{YELLOW}SUSPECT{RESET} {who} tried {user}:{pw} {tag_level}")
    else:
        body = (f"{DIM}try    {who} tried {user}:{pw} {tag_level}{RESET}")

    counter = f"{CYAN}[{who}: {c['attempts']} attempts, {c['fails']} fails]{RESET}"
    return f"{DIM}{ts}{RESET}  {body}  {counter}"


async def monitor(url: str) -> None:
    async with websockets.connect(url) as ws:
        await ws.send(json.dumps({"type": "join", "role": "host",
                                  "nickname": "host-monitor"}))
        print(f"{CYAN}=== siem-ctf monitor — live event feed ==={RESET}")
        print(f"{DIM}connected to {url}{RESET}\n")
        while True:
            raw = await ws.recv()
            msg = json.loads(raw)
            mtype = msg.get("type")
            if mtype == "new_event":
                print(render_event(msg.get("event", {})))
            elif mtype == "alert":
                print(f"{RED}  !! ALERT: {msg.get('message', '')}{RESET}")
                if msg.get("defense"):
                    d = msg["defense"]
                    print(f"{RED}  !! DEFENSE LOGGED: {d.get('note', '')}{RESET}")


def main() -> None:
    ap = argparse.ArgumentParser(description="siem-ctf host monitor CLI")
    ap.add_argument("--url", default="ws://127.0.0.1:8000/ws",
                    help="server WebSocket URL")
    args = ap.parse_args()
    try:
        asyncio.run(monitor(args.url))
    except (KeyboardInterrupt, EOFError):
        print("\n[*] monitor closed")


if __name__ == "__main__":
    main()
