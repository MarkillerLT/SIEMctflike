"""
siem-ctf — WebSocket server (FastAPI + native WebSockets, run with Uvicorn).

Toy classroom simulation of brute-forcing an SSH login, with live SIEM-style
monitoring for the host. No real SSH; login logic + in-memory fake accounts only.

Clients connect to ws://<host>:<port>/ws and declare a role with a `join`
message:
  - "attacker": sends login_attempt messages, gets login_result back.
  - "host":     passive monitor, receives new_event and alert messages.

Message protocol (every message is JSON with a "type" field):
  client -> server:
    {"type":"join", "role":"attacker"|"host", "nickname":"..."}
    {"type":"login_attempt", "username":"...", "password":"..."}
  server -> client:
    {"type":"login_result", "result":"incorrect"|"locked"|"success",
       "message":"...", "flag":"..."(on success), "level":"easy|medium|hard"}
    {"type":"new_event", "event":{...}}        # to hosts: one per attempt
    {"type":"alert", "event":{...}, "message":"..."}  # to hosts: suspicious/lockout
"""

import json
import time
from datetime import datetime, timezone

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from . import config

app = FastAPI(title="siem-ctf")


# --------------------------------------------------------------------------
# In-memory state (resets when the server restarts)
# --------------------------------------------------------------------------
host_monitors: set[WebSocket] = set()        # connected host monitor sockets

# per (nickname, username) failed-attempt counters
fail_counts: dict[tuple[str, str], int] = {}

# locked accounts: username -> unix timestamp when the lock expires
locks: dict[str, float] = {}


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def append_jsonl(path, record: dict) -> None:
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


async def broadcast_to_hosts(message: dict) -> None:
    """Send a JSON message to every connected host monitor."""
    dead = []
    for ws in host_monitors:
        try:
            await ws.send_text(json.dumps(message))
        except Exception:
            dead.append(ws)
    for ws in dead:
        host_monitors.discard(ws)


def log_defense(action: str, detail: dict) -> dict:
    """Write a defensive action to the defense logbook (bitácora)."""
    record = {"timestamp": now_iso(), "action": action, **detail}
    append_jsonl(config.DEFENSE_LOG, record)
    return record


# --------------------------------------------------------------------------
# Core login logic
# --------------------------------------------------------------------------
def process_login(nickname: str, username: str, password: str) -> tuple[dict, dict, dict | None]:
    """
    Evaluate one login attempt.

    Returns (result, event, alert):
      result -> the login_result payload to send back to the attacker
      event  -> the recorded event (broadcast to hosts as new_event)
      alert  -> an alert payload to push to hosts, or None
    """
    level, acct = config.account_for_username(username)
    key = (nickname, username)
    alert_payload = None

    # 1) Is this account currently locked?
    if acct and acct["lockout"]:
        expires = locks.get(username)
        if expires and expires > time.time():
            remaining = int(expires - time.time())
            event = record_event(
                nickname, username, password,
                result="locked", level=level, risk="suspicious",
            )
            alert_payload = {
                "type": "alert",
                "message": f"Account '{username}' is LOCKED ({remaining}s left) — brute force blocked",
                "event": event,
            }
            return (
                {"type": "login_result", "result": "locked",
                 "message": f"Account locked. Try again in {remaining}s.",
                 "level": level},
                event,
                alert_payload,
            )
        elif expires:
            # lock expired -> clear it and the counter
            locks.pop(username, None)
            fail_counts.pop(key, None)

    # 2) Correct credentials?
    if acct and password == acct["password"]:
        fail_counts.pop(key, None)                      # reset on success
        event = record_event(
            nickname, username, password,
            result="success", level=level, risk="normal",
        )
        return (
            {"type": "login_result", "result": "success",
             "message": f"Access granted to {username}@sshd — level '{level}' cracked!",
             "flag": acct["flag"], "level": level},
            event,
            None,
        )

    # 3) Wrong credentials (bad password, or unknown user).
    fail_counts[key] = fail_counts.get(key, 0) + 1
    count = fail_counts[key]
    risk = "suspicious" if count >= config.FAIL_THRESHOLD else "normal"

    event = record_event(
        nickname, username, password,
        result="incorrect", level=level, risk=risk,
    )

    # SIEM rule: fire the alert ONCE, on the attempt that crosses the threshold
    # (count == FAIL_THRESHOLD). Attempts above threshold stay flagged suspicious
    # in the event log but don't re-alert. The counter resets on success or when a
    # lock expires, so a renewed burst legitimately re-alerts.
    if count == config.FAIL_THRESHOLD:
        alert_payload = {
            "type": "alert",
            "message": f"SUSPICIOUS: '{nickname}' made {count} failed attempts on '{username}'",
            "event": event,
        }
        if acct and acct["lockout"] and username not in locks:
            locks[username] = time.time() + config.LOCKOUT_SECONDS
            defense = log_defense(
                "account_locked",
                {"username": username, "attacker": nickname,
                 "failed_attempts": count,
                 "lock_seconds": config.LOCKOUT_SECONDS,
                 "note": f"account {username} locked after {count} failed attempts "
                         f"(fail2ban-style defense)"},
            )
            alert_payload["message"] += f" -> account LOCKED for {config.LOCKOUT_SECONDS}s"
            alert_payload["defense"] = defense

    return (
        {"type": "login_result", "result": "incorrect",
         "message": "Permission denied (publickey,password).",
         "level": level},
        event,
        alert_payload,
    )


def record_event(nickname, username, password, *, result, level, risk) -> dict:
    """Build the event, write it to the vulnerability/event log, return it."""
    event = {
        "timestamp": now_iso(),
        "attacker": nickname,
        "username": username,
        "password": password,
        "result": result,
        "risk": risk,                      # normal | suspicious
        "level": level,                    # easy | medium | hard | None (unknown user)
    }
    append_jsonl(config.EVENT_LOG, event)
    return event


# --------------------------------------------------------------------------
# WebSocket endpoint
# --------------------------------------------------------------------------
@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    role = None
    nickname = "anon"
    try:
        # First message must be a join.
        raw = await ws.receive_text()
        msg = json.loads(raw)
        if msg.get("type") != "join":
            await ws.send_text(json.dumps(
                {"type": "login_result", "result": "error",
                 "message": "first message must be type 'join'"}))
            await ws.close()
            return

        role = msg.get("role", "attacker")
        nickname = (msg.get("nickname") or "anon").strip() or "anon"

        if role == "host":
            host_monitors.add(ws)
            await ws.send_text(json.dumps(
                {"type": "new_event", "event": {
                    "timestamp": now_iso(), "attacker": "SERVER",
                    "username": "-", "password": "-", "result": "monitor_connected",
                    "risk": "normal", "level": None}}))
            # Host just listens; keep the socket open.
            while True:
                await ws.receive_text()      # ignore anything hosts send
        else:
            # Attacker loop.
            await ws.send_text(json.dumps(
                {"type": "login_result", "result": "info",
                 "message": f"Connected as '{nickname}'. Send login_attempt messages."}))
            while True:
                raw = await ws.receive_text()
                msg = json.loads(raw)
                if msg.get("type") != "login_attempt":
                    continue
                username = str(msg.get("username", ""))
                password = str(msg.get("password", ""))

                result, event, alert = process_login(nickname, username, password)

                # Reply to the attacker.
                await ws.send_text(json.dumps(result))
                # Push the real recorded event to all hosts.
                await broadcast_to_hosts({"type": "new_event", "event": event})
                if alert:
                    await broadcast_to_hosts(alert)

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        try:
            await ws.send_text(json.dumps(
                {"type": "login_result", "result": "error", "message": str(exc)}))
        except Exception:
            pass
    finally:
        host_monitors.discard(ws)


@app.get("/")
def index():
    return {"service": "siem-ctf", "ws": "/ws",
            "levels": list(config.ACCOUNTS.keys())}
