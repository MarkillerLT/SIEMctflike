#!/usr/bin/env python3
"""
siem-ctf — attacker CLI (SSH-style front end).

Connects to the fake SSH server and presents a terminal that imitates logging in
over SSH: it asks for a user, then a (masked) password, and answers like a real
sshd would ("Permission denied (publickey,password).") until you crack an
account — at which point it prints the FLAG.

This is a toy classroom exercise: the "server" is a local simulation your
instructor is running, not a real host. The intended way to beat it is a
dictionary / brute-force attack against the shared password library
(data/passwords.txt) — either by hand, or with a script you write yourself that
speaks the WebSocket protocol.

Usage:
    python attacker.py --url ws://<server-ip>:8000/ws --nick alice
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path

import websockets

DEFAULT_WORDLIST = Path(__file__).resolve().parent.parent / "data" / "passwords.txt"

# How many password tries sshd gives you before dropping the connection prompt.
MAX_PW_TRIES = 3


# --------------------------------------------------------------------------
# Terminal helpers
# --------------------------------------------------------------------------
def read_password(prompt: str = "Password: ") -> str:
    """
    Read a password, echoing a '*' per character (like the mockup).

    Falls back to getpass (hidden input) when stdin isn't an interactive TTY.
    """
    if not sys.stdin.isatty():
        import getpass
        return getpass.getpass(prompt)

    try:
        import termios
        import tty
    except ImportError:
        import getpass
        return getpass.getpass(prompt)

    sys.stdout.write(prompt)
    sys.stdout.flush()
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    buf: list[str] = []
    try:
        tty.setraw(fd)
        while True:
            ch = sys.stdin.read(1)
            if ch in ("\r", "\n"):
                break
            if ch == "\x03":                       # Ctrl-C
                raise KeyboardInterrupt
            if ch == "\x04":                       # Ctrl-D on empty -> EOF
                if not buf:
                    raise EOFError
                continue
            if ch in ("\x7f", "\b"):               # backspace
                if buf:
                    buf.pop()
                    sys.stdout.write("\b \b")
                    sys.stdout.flush()
                continue
            buf.append(ch)
            sys.stdout.write("*")
            sys.stdout.flush()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
        sys.stdout.write("\n")
        sys.stdout.flush()
    return "".join(buf)


async def ainput(prompt: str = "") -> str:
    """Async wrapper around blocking input()."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, input, prompt)


async def aread_password(prompt: str = "Password: ") -> str:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, read_password, prompt)


# --------------------------------------------------------------------------
# Protocol helpers
# --------------------------------------------------------------------------
def load_wordlist(path: Path) -> list[str]:
    try:
        with open(path, encoding="utf-8") as fh:
            return [line.strip() for line in fh if line.strip()]
    except FileNotFoundError:
        print(f"[!] wordlist not found: {path}")
        return []


async def send_attempt(ws, username: str, password: str) -> dict:
    await ws.send(json.dumps({"type": "login_attempt",
                              "username": username, "password": password}))
    return json.loads(await ws.recv())


# --------------------------------------------------------------------------
# Internal-only automatic dictionary attack (not documented for students).
# Trigger by typing  `auto <user>`  at the login prompt.
# --------------------------------------------------------------------------
async def auto_attack(ws, username: str, wordlist: list[str]) -> None:
    print(f"[*] auto dictionary attack on '{username}' ({len(wordlist)} passwords)...")
    for i, pw in enumerate(wordlist, 1):
        reply = await send_attempt(ws, username, pw)
        result = reply.get("result")
        if result == "success":
            print(f"[*] cracked after {i} attempt(s): {username}:{pw}")
            print(f"[+] FLAG: {reply.get('flag')}")
            return
        if result == "locked":
            print(f"[x] {reply.get('message')}")
            print("[*] account locked — naive brute force blocked.")
            return
        await asyncio.sleep(0.05)
    print("[*] wordlist exhausted — no success.")


# --------------------------------------------------------------------------
# SSH-style interactive session
# --------------------------------------------------------------------------
async def session(url: str, nickname: str, wordlist_path: Path) -> None:
    wordlist = load_wordlist(wordlist_path)
    async with websockets.connect(url) as ws:
        await ws.send(json.dumps({"type": "join", "role": "attacker",
                                  "nickname": nickname}))
        json.loads(await ws.recv())   # consume the server's hello

        print("LOADING SSH")
        await asyncio.sleep(0.4)
        print(f"{nickname}@Server.app")

        while True:
            try:
                user = (await ainput("User: ")).strip()
            except (EOFError, KeyboardInterrupt):
                print("\nConnection to Server.app closed.")
                return

            if user in ("quit", "exit", "logout"):
                print("Connection to Server.app closed.")
                return
            if not user:
                continue

            # Hidden internal shortcut: `auto <user>` (not for students).
            parts = user.split()
            if parts[0] == "auto" and len(parts) >= 2:
                await auto_attack(ws, parts[1], wordlist)
                print()
                continue

            cracked = await password_prompts(ws, user)
            print()
            if cracked:
                # Let them go on to target the next account in the same session.
                continue


async def password_prompts(ws, user: str) -> bool:
    """Ask for a password up to MAX_PW_TRIES times. Returns True on success."""
    for _ in range(MAX_PW_TRIES):
        try:
            password = await aread_password("Password: ")
        except (EOFError, KeyboardInterrupt):
            print()
            return False

        reply = await send_attempt(ws, user, password)
        result = reply.get("result")

        if result == "success":
            print(f"Welcome to {user}@sshd.")
            print(reply.get("message", ""))
            print(f"FLAG: {reply.get('flag')}")
            return True
        if result == "locked":
            print(reply.get("message", "Account locked."))
            return False
        # incorrect / unknown user -> sshd's generic denial
        print("Permission denied (publickey,password).")

    print(f"{user}@Server.app: Permission denied (publickey,password).")
    return False


def main() -> None:
    ap = argparse.ArgumentParser(description="siem-ctf attacker CLI")
    ap.add_argument("--url", default="ws://127.0.0.1:8000/ws",
                    help="server WebSocket URL (ws://<ip>:<port>/ws)")
    ap.add_argument("--nick", default="attacker", help="your handle (shown to the monitor)")
    ap.add_argument("--wordlist", default=str(DEFAULT_WORDLIST),
                    help="path to passwords.txt")
    args = ap.parse_args()
    try:
        asyncio.run(session(args.url, args.nick, Path(args.wordlist)))
    except (KeyboardInterrupt, EOFError):
        print("\nConnection to Server.app closed.")


if __name__ == "__main__":
    main()
