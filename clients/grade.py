#!/usr/bin/env python3
"""
siem-ctf — grade / report tool.

Reads the SIEM event log (data/events.jsonl) and prints, per attacker, which of
the three accounts they actually cracked. The flag is only an in-game incentive;
THIS log is the source of truth for grading — a student can't fake a success
here because every real login_attempt is recorded server-side.

For each attacker it shows one row per level:

    alice    admin    FLAG{admin_...}   Pass
    alice    devops   FLAG{devops_...}  Pass
    alice    root     FLAG{null}        not pass

Run after a session:
    python clients/grade.py
    python clients/grade.py --log data/events.jsonl --csv results.csv
"""

import argparse
import csv
import json
import os
import sys
from pathlib import Path

# Make the project root importable so we can read the account/flag table.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from server import config  # noqa: E402

NULL_FLAG = "FLAG{null}"


def load_events(path: Path) -> list[dict]:
    events = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        print(f"[!] event log not found: {path}")
        print("    Run a session first (the server writes it as attacks come in).")
    return events


def build_results(events: list[dict]) -> dict[str, dict[str, bool]]:
    """
    Return {attacker: {level: cracked_bool}} covering every attacker seen and
    every configured level (defaulting to not-cracked).
    """
    levels = list(config.ACCOUNTS.keys())
    # username -> level lookup
    user_to_level = {acct["username"]: lvl for lvl, acct in config.ACCOUNTS.items()}

    attackers: set[str] = set()
    cracked: dict[tuple[str, str], bool] = {}

    for ev in events:
        who = ev.get("attacker")
        if not who or who == "SERVER":
            continue
        attackers.add(who)
        if ev.get("result") == "success":
            lvl = ev.get("level") or user_to_level.get(ev.get("username", ""))
            if lvl in levels:
                cracked[(who, lvl)] = True

    results: dict[str, dict[str, bool]] = {}
    for who in sorted(attackers):
        results[who] = {lvl: cracked.get((who, lvl), False) for lvl in levels}
    return results


def rows_for(results: dict[str, dict[str, bool]]):
    """Yield (attacker, account_username, flag, status, passed) rows."""
    for who, per_level in results.items():
        for lvl, passed in per_level.items():
            acct = config.ACCOUNTS[lvl]
            flag = acct["flag"] if passed else NULL_FLAG
            status = "Pass" if passed else "not pass"
            yield (who, acct["username"], flag, status, passed)


if os.name == "nt":
    os.system("")   # enable ANSI colors in the Windows console

# ANSI (harmless if unsupported)
GREEN = "\033[92m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_table(results: dict[str, dict[str, bool]], color: bool = True) -> None:
    rows = list(rows_for(results))
    if not rows:
        print("No attacker activity recorded yet.")
        return

    user_w = max(len("ATTACKER"), max(len(r[0]) for r in rows))
    acct_w = max(len("ACCOUNT"), max(len(r[1]) for r in rows))
    flag_w = max(len("FLAG"), max(len(r[2]) for r in rows))

    header = f"{'ATTACKER':<{user_w}}  {'ACCOUNT':<{acct_w}}  {'FLAG':<{flag_w}}  STATUS"
    print(header)
    print("-" * len(header))

    last = None
    for who, acct, flag, status, passed in rows:
        if last is not None and who != last:
            print()                      # blank line between attackers
        last = who
        line = f"{who:<{user_w}}  {acct:<{acct_w}}  {flag:<{flag_w}}  {status}"
        if color:
            if passed:
                line = f"{who:<{user_w}}  {acct:<{acct_w}}  {flag:<{flag_w}}  {GREEN}{status}{RESET}"
            else:
                line = f"{who:<{user_w}}  {acct:<{acct_w}}  {DIM}{flag:<{flag_w}}  {status}{RESET}"
        print(line)

    # Per-attacker score summary.
    print()
    total = len(config.ACCOUNTS)
    print(f"{BOLD}Score (levels cleared):{RESET}" if color else "Score (levels cleared):")
    for who, per_level in results.items():
        n = sum(1 for v in per_level.values() if v)
        print(f"  {who:<{user_w}}  {n}/{total}")


def write_csv(results: dict[str, dict[str, bool]], path: Path) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["attacker", "account", "flag", "status"])
        for who, acct, flag, status, _ in rows_for(results):
            w.writerow([who, acct, flag, status])
    print(f"[*] wrote {path}")


def main() -> None:
    ap = argparse.ArgumentParser(description="siem-ctf grade / report tool")
    ap.add_argument("--log", default=str(config.EVENT_LOG),
                    help="path to events.jsonl")
    ap.add_argument("--csv", help="also write the table to this CSV file")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    args = ap.parse_args()

    events = load_events(Path(args.log))
    results = build_results(events)
    print_table(results, color=not args.no_color)
    if args.csv:
        write_csv(results, Path(args.csv))


if __name__ == "__main__":
    main()
