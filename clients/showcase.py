#!/usr/bin/env python3
"""
siem-ctf — showcase / smoke-test workflow.

One command that demos AND tests the whole exercise end to end:

    python clients/showcase.py            # full run (~10 s)
    python clients/showcase.py --quiet    # only the PASS/FAIL checklist
    python clients/showcase.py --keep     # keep the generated logs afterwards

What it does:
  1. Starts the real server (server.main:app) IN-PROCESS on 127.0.0.1 and a
     random free port, writing its logs to a TEMP folder — your real
     data/events.jsonl and data/defense.jsonl are never touched, and no
     firewall prompt appears (loopback only).
  2. Connects a host monitor and prints the live SIEM feed.
  3. Runs the scenarios below as scripted attackers, checking each result.
  4. Builds the grade table from the temp event log.
  5. Exits 0 if every check passed, 1 otherwise (usable in CI).

Pure Python + the project's requirements — no bash, curl, jq or tail — so it
behaves the same on Linux, macOS and Windows.
"""

import argparse
import asyncio
import json
import os
import shutil
import socket
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "clients"))

import uvicorn  # noqa: E402
import websockets  # noqa: E402

from server import config  # noqa: E402
from server import main as server_main  # noqa: E402
import grade  # noqa: E402
import monitor as monitor_cli  # noqa: E402

# Windows: enable ANSI colors in the legacy console and avoid UnicodeEncodeError
# on cp1252 code pages when output is redirected.
if os.name == "nt":
    os.system("")
for stream in (sys.stdout, sys.stderr):
    try:
        stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

GREEN, RED, YELLOW, CYAN, DIM, BOLD, RESET = (
    "\033[92m", "\033[91m", "\033[93m", "\033[96m", "\033[2m", "\033[1m", "\033[0m")

SHOWCASE_LOCKOUT_SECONDS = 3   # shortened so the lock-expiry demo is quick


# --------------------------------------------------------------------------
# Tiny check recorder
# --------------------------------------------------------------------------
class Checks:
    def __init__(self) -> None:
        self.results: list[tuple[str, bool, str]] = []

    def check(self, name: str, ok: bool, detail: str = "") -> bool:
        self.results.append((name, ok, detail))
        mark = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
        extra = f"  {DIM}{detail}{RESET}" if detail else ""
        print(f"  [{mark}] {name}{extra}")
        return ok

    @property
    def failed(self) -> int:
        return sum(1 for _, ok, _ in self.results if not ok)


def banner(title: str) -> None:
    print(f"\n{BOLD}{CYAN}== {title} =={RESET}")


# --------------------------------------------------------------------------
# Server + clients
# --------------------------------------------------------------------------
def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def isolate_data(tmp: Path) -> None:
    """Point the server's logs at a temp dir and shorten the lockout."""
    config.DATA_DIR = tmp
    config.EVENT_LOG = tmp / "events.jsonl"
    config.DEFENSE_LOG = tmp / "defense.jsonl"
    config.LOCKOUT_SECONDS = SHOWCASE_LOCKOUT_SECONDS
    # fresh in-memory state
    server_main.fail_counts.clear()
    server_main.locks.clear()
    server_main.host_monitors.clear()


async def start_server(port: int) -> tuple[uvicorn.Server, asyncio.Task]:
    srv = uvicorn.Server(uvicorn.Config(
        server_main.app, host="127.0.0.1", port=port, log_level="warning"))
    task = asyncio.create_task(srv.serve())
    deadline = time.monotonic() + 10
    while not srv.started:
        if task.done() or time.monotonic() > deadline:
            raise RuntimeError(f"server did not start on 127.0.0.1:{port}")
        await asyncio.sleep(0.05)
    return srv, task


class Monitor:
    """Host monitor that records everything and (optionally) prints it."""

    def __init__(self, url: str, show: bool) -> None:
        self.url, self.show = url, show
        self.events: list[dict] = []
        self.alerts: list[dict] = []
        self._task: asyncio.Task | None = None
        self._ready = asyncio.Event()

    async def _run(self) -> None:
        async with websockets.connect(self.url) as ws:
            await ws.send(json.dumps({"type": "join", "role": "host",
                                      "nickname": "showcase-monitor"}))
            async for raw in ws:
                msg = json.loads(raw)
                if msg.get("type") == "new_event":
                    ev = msg.get("event", {})
                    if ev.get("result") == "monitor_connected":
                        self._ready.set()
                    else:
                        self.events.append(ev)
                    if self.show:
                        print("    " + monitor_cli.render_event(ev))
                elif msg.get("type") == "alert":
                    self.alerts.append(msg)
                    if self.show:
                        print(f"    {RED}!! ALERT: {msg.get('message', '')}{RESET}")
                        if msg.get("defense"):
                            print(f"    {RED}!! DEFENSE LOGGED: "
                                  f"{msg['defense'].get('note', '')}{RESET}")

    async def start(self) -> None:
        self._task = asyncio.create_task(self._run())
        await asyncio.wait_for(self._ready.wait(), timeout=5)

    async def settle(self) -> None:
        """Give in-flight broadcasts a moment to arrive."""
        await asyncio.sleep(0.15)

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass


class Attacker:
    def __init__(self, url: str, nick: str) -> None:
        self.url, self.nick, self.ws = url, nick, None

    async def __aenter__(self):
        self.ws = await websockets.connect(self.url)
        await self.ws.send(json.dumps({"type": "join", "role": "attacker",
                                       "nickname": self.nick}))
        await self.ws.recv()                     # hello
        return self

    async def __aexit__(self, *exc):
        await self.ws.close()

    async def try_login(self, username: str, password: str) -> dict:
        await self.ws.send(json.dumps({"type": "login_attempt",
                                       "username": username, "password": password}))
        return json.loads(await self.ws.recv())

    async def dictionary(self, username: str, words: list[str]):
        """Naive loop. Returns (attempts, last_reply)."""
        reply: dict = {}
        for i, pw in enumerate(words, 1):
            reply = await self.try_login(username, pw)
            if reply.get("result") in ("success", "locked"):
                return i, reply
        return len(words), reply


# --------------------------------------------------------------------------
# Scenarios
# --------------------------------------------------------------------------
async def run(args) -> int:
    tmp = Path(tempfile.mkdtemp(prefix="siem-ctf-showcase-"))
    isolate_data(tmp)
    words = [w.strip() for w in
             config.WORDLIST_FILE.read_text(encoding="utf-8").splitlines() if w.strip()]
    acc = config.ACCOUNTS
    port = free_port()
    url = f"ws://127.0.0.1:{port}/ws"
    c = Checks()

    print(f"{BOLD}siem-ctf showcase{RESET}  {DIM}python {sys.version.split()[0]} · "
          f"{sys.platform} · server {url} · logs {tmp}{RESET}")

    srv, srv_task = await start_server(port)
    mon = Monitor(url, show=not args.quiet)
    try:
        # 0 ── health ------------------------------------------------------
        banner("0. Health check (HTTP GET /)")
        body = await asyncio.to_thread(
            lambda: json.loads(urllib.request.urlopen(
                f"http://127.0.0.1:{port}/", timeout=5).read()))
        c.check("GET / answers with the 3 levels",
                body.get("levels") == list(acc.keys()), str(body))
        await mon.start()
        c.check("host monitor connected", True)

        # 1 ── easy --------------------------------------------------------
        banner(f"1. EASY — dictionary attack on '{acc['easy']['username']}'")
        async with Attacker(url, "alice") as a:
            n, r = await a.dictionary(acc["easy"]["username"], words)
        await mon.settle()
        c.check("cracked", r.get("result") == "success", f"after {n} attempt(s)")
        c.check("correct flag returned", r.get("flag") == acc["easy"]["flag"])
        c.check("monitor saw the SUCCESS event",
                any(e["attacker"] == "alice" and e["result"] == "success"
                    for e in mon.events))

        # 2 ── medium ------------------------------------------------------
        banner(f"2. MEDIUM — dictionary attack on '{acc['medium']['username']}'")
        alerts_before = len(mon.alerts)
        async with Attacker(url, "bob") as a:
            n, r = await a.dictionary(acc["medium"]["username"], words)
        await mon.settle()
        c.check("cracked (no lockout on this level)",
                r.get("result") == "success", f"after {n} attempt(s)")
        c.check("correct flag returned", r.get("flag") == acc["medium"]["flag"])
        suspects = [e for e in mon.events
                    if e["attacker"] == "bob" and e["risk"] == "suspicious"]
        c.check(f"attempts flagged SUSPECT after {config.FAIL_THRESHOLD} fails",
                len(suspects) == max(0, n - config.FAIL_THRESHOLD),
                f"{len(suspects)} suspicious events")
        c.check("exactly one SIEM alert fired",
                len(mon.alerts) - alerts_before == 1)

        # 3 ── hard: naive -------------------------------------------------
        root = acc["hard"]["username"]
        banner(f"3. HARD — naive dictionary attack on '{root}' (lockout ON)")
        async with Attacker(url, "carol") as a:
            n, r = await a.dictionary(root, words)
            c.check("blocked by lockout", r.get("result") == "locked",
                    f"locked at attempt {n}: {r.get('message')}")
            r2 = await a.try_login(root, acc["hard"]["password"])
            c.check("even the RIGHT password is refused while locked",
                    r2.get("result") == "locked")
        await mon.settle()
        defense = [json.loads(l) for l in
                   config.DEFENSE_LOG.read_text(encoding="utf-8").splitlines() if l]
        c.check("defense logbook has 'account_locked'",
                any(d.get("action") == "account_locked" and d.get("username") == root
                    for d in defense))
        c.check("monitor got the LOCKED alert",
                any("LOCKED" in al.get("message", "") for al in mon.alerts))

        # 4 ── hard: lock expiry ------------------------------------------
        banner(f"4. HARD — lock expires after {config.LOCKOUT_SECONDS}s "
               f"(showcase value; real config uses {SHOWCASE_LOCKOUT_REAL}s)")
        await asyncio.sleep(config.LOCKOUT_SECONDS + 0.5)
        async with Attacker(url, "carol") as a:
            r = await a.try_login(root, "definitely-wrong")
        c.check("account accepts attempts again", r.get("result") == "incorrect")

        # 5 ── hard: identity rotation ------------------------------------
        per_id = config.FAIL_THRESHOLD - 1
        banner(f"5. HARD — 'low and slow' bypass: rotate nickname every {per_id} tries")
        print(f"  {DIM}The fail counter is per (nickname, account) but the lock is per "
              f"account, so an attacker who never reaches {config.FAIL_THRESHOLD} fails "
              f"per nickname is never locked. Good class discussion point.{RESET}")
        cracked, tried, ident = None, 0, 0
        for start in range(0, len(words), per_id):
            ident += 1
            async with Attacker(url, f"dave-{ident}") as a:
                for pw in words[start:start + per_id]:
                    tried += 1
                    r = await a.try_login(root, pw)
                    if r.get("result") != "incorrect":
                        cracked = r
                        break
            if cracked:
                break
        await mon.settle()
        c.check("root cracked without triggering lockout",
                bool(cracked) and cracked.get("result") == "success",
                f"{tried} attempts across {ident} nicknames")

        # 6 ── protocol robustness ----------------------------------------
        banner("6. Protocol robustness")
        async with Attacker(url, "eve") as a:
            r = await a.try_login("nobody", "x")
        c.check("unknown user -> generic 'incorrect' (no user enumeration)",
                r.get("result") == "incorrect" and r.get("level") is None)
        async with websockets.connect(url) as ws:
            await ws.send(json.dumps({"type": "login_attempt",
                                      "username": "admin", "password": "x"}))
            r = json.loads(await ws.recv())
        c.check("first message must be 'join'", r.get("result") == "error")

        # 7 ── grading -----------------------------------------------------
        banner("7. Grade report (from the server-side event log)")
        results = grade.build_results(grade.load_events(config.EVENT_LOG))
        grade.print_table(results)
        expect = {"alice": 1, "bob": 1, "carol": 0, f"dave-{ident}": 1}
        got = {who: sum(v.values()) for who, v in results.items()}
        c.check("scores match the scenarios",
                all(got.get(k) == v for k, v in expect.items()),
                ", ".join(f"{k}={got.get(k)}" for k in expect))
    finally:
        await mon.stop()
        srv.should_exit = True
        await srv_task

    # ── summary -----------------------------------------------------------
    total = len(c.results)
    banner("Summary")
    if c.failed:
        print(f"  {RED}{c.failed}/{total} checks FAILED{RESET}")
        for name, ok, detail in c.results:
            if not ok:
                print(f"   - {name} {DIM}{detail}{RESET}")
    else:
        print(f"  {GREEN}all {total} checks passed{RESET}")

    if args.keep:
        print(f"  logs kept in {tmp}")
    else:
        shutil.rmtree(tmp, ignore_errors=True)
    return 1 if c.failed else 0


SHOWCASE_LOCKOUT_REAL = config.LOCKOUT_SECONDS   # captured before isolate_data()


def main() -> None:
    ap = argparse.ArgumentParser(description="siem-ctf showcase / smoke test")
    ap.add_argument("--quiet", action="store_true", help="hide the live monitor feed")
    ap.add_argument("--keep", action="store_true", help="keep the temp logs")
    args = ap.parse_args()
    try:
        sys.exit(asyncio.run(run(args)))
    except KeyboardInterrupt:
        print("\n[*] showcase aborted")
        sys.exit(130)


if __name__ == "__main__":
    main()
