"""
siem-ctf — central configuration.

This is a TOY classroom simulation. There is no real SSH server here; it is just
login LOGIC plus an SSH theme, used to teach dictionary brute-force attacks and
SIEM-style event monitoring. All credentials below are fake and live only in
memory on the host's own machine.

Edit the constants in this file to tune the exercise. Nothing else needs changing.
"""

import os
import socket
from pathlib import Path

# --------------------------------------------------------------------------
# Network
# --------------------------------------------------------------------------
# 0.0.0.0 so classmates on the same LAN can reach it. See MANUAL.md for how to
# find your IP and the WiFi client-isolation caveat.
HOST = "0.0.0.0"

# Preferred port. You can override it at launch with the PORT env var
# (e.g.  PORT=9000 ./run.sh server )  or by passing it to run.sh
# (e.g.  ./run.sh server 9000 ). If the chosen port is busy, the server
# automatically falls back to the next free one in PORT_CANDIDATES below.
DEFAULT_PORT = 8000
PORT = DEFAULT_PORT  # kept for backwards reference; resolve_port() is what binds

# Ordered list of ports to try when the preferred one is taken.
PORT_CANDIDATES = [8000, 8080, 8081, 8082, 8090, 8800, 9000]

# --------------------------------------------------------------------------
# SIEM rule
# --------------------------------------------------------------------------
# After this many FAILED attempts from one attacker against one account, the
# event is flagged "suspicious" and an alert is pushed to the host monitor(s).
FAIL_THRESHOLD = 5

# For accounts with lockout enabled (see "hard" below), the account is locked
# for this many seconds once the threshold is crossed (fail2ban-style).
LOCKOUT_SECONDS = 60

# --------------------------------------------------------------------------
# The three levels = three fake SSH accounts, each with its own flag.
# Tune usernames / passwords / flags freely. "lockout" turns the fail2ban-style
# defense on for that account.
# --------------------------------------------------------------------------
ACCOUNTS = {
    "easy": {
        "username": "admin",
        "password": "123456",            # near TOP of passwords.txt -> cracks instantly
        # Flags are opaque SHA1-style tokens (hardcoded, not real hashes): they
        # can't be guessed or re-derived, so the only way to get one is to
        # actually crack the account. They're just the "incentive" — the real
        # record of who got in lives in the SIEM event log / grade report.
        "flag": "FLAG{admin_da0d83bca6237159ccce753c68f5150e4a4deb24}",
        "lockout": False,
    },
    "medium": {
        "username": "devops",
        "password": "dragon2024",         # deeper in the wordlist -> takes more tries
        "flag": "FLAG{devops_382e697b712c68b790b60756f7b2a6e0189116fd}",
        "lockout": False,
    },
    "hard": {
        "username": "root",
        "password": "Sup3rSecret!",       # deep in the wordlist + lockout defense ON
        "flag": "FLAG{root_7e7014c9f59aee1d095910eae98f4492b78e3bef}",
        "lockout": True,
    },
}

# --------------------------------------------------------------------------
# Files
# --------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"

WORDLIST_FILE = DATA_DIR / "passwords.txt"     # the dictionary attackers iterate
EVENT_LOG = DATA_DIR / "events.jsonl"          # vulnerability / event log (JSON Lines)
DEFENSE_LOG = DATA_DIR / "defense.jsonl"       # defense logbook / bitácora (JSON Lines)

# Written by the server on startup with the port it actually bound to, so the
# other helpers (monitor, ip, attacker) can find a running server even when it
# auto-jumped to a fallback port. Removed when the server stops.
RUNTIME_PORT_FILE = DATA_DIR / ".runtime_port"


# --------------------------------------------------------------------------
# Port selection
# --------------------------------------------------------------------------
def port_is_free(port: int, host: str = HOST) -> bool:
    """True if we can bind host:port right now."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
            return True
        except OSError:
            return False


def resolve_port(preferred: int | None = None, host: str = HOST) -> int:
    """
    Decide which port to bind.

    - An explicit choice (the `preferred` arg or the PORT env var) is honored,
      and only falls back to another port if it is already in use.
    - With no explicit choice, try PORT_CANDIDATES in order (8000, 8080, ...).
    - If everything is busy, return 0 so the OS picks any free port.
    """
    if preferred is None:
        env_port = os.environ.get("PORT")
        if env_port:
            try:
                preferred = int(env_port)
            except ValueError:
                preferred = None

    if preferred is not None:
        if port_is_free(preferred, host):
            return preferred
        candidates = [p for p in PORT_CANDIDATES if p != preferred]
    else:
        candidates = list(PORT_CANDIDATES)

    for port in candidates:
        if port_is_free(port, host):
            return port
    return 0  # let the OS assign a free port as a last resort


def write_runtime_port(port: int) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    RUNTIME_PORT_FILE.write_text(str(port), encoding="utf-8")


def read_runtime_port() -> int | None:
    try:
        return int(RUNTIME_PORT_FILE.read_text(encoding="utf-8").strip())
    except (FileNotFoundError, ValueError):
        return None


def clear_runtime_port() -> None:
    try:
        RUNTIME_PORT_FILE.unlink()
    except FileNotFoundError:
        pass


def lan_ip() -> str:
    """Best-effort LAN IP classmates can use to reach this host."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("1.1.1.1", 80))   # no packets actually sent for UDP connect
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def account_for_username(username: str):
    """Return (level, account_dict) for a tried username, or (None, None)."""
    for level, acct in ACCOUNTS.items():
        if acct["username"] == username:
            return level, acct
    return None, None
