#!/usr/bin/env bash
#
# siem-ctf — helper launcher (Linux / macOS).  Windows: use run.ps1
#
# Usage:
#   ./run.sh setup              one-time: create .venv and install requirements
#   ./run.sh server [port]      start the WebSocket server (auto-picks a free port)
#   ./run.sh monitor            start the host SIEM monitor CLI (127.0.0.1)
#   ./run.sh attack [nick] [url] start an attacker CLI (students: pass the host URL)
#   ./run.sh grade              print the per-attacker results table (grading)
#   ./run.sh ip                 print the URL classmates should connect to
#   ./run.sh reset              empty the event + defense logs
#   ./run.sh showcase [--quiet] end-to-end demo + smoke test (isolated temp logs)
#
# Port: by default the server tries 8000, then 8080/8081/... if busy. Force a
# specific port with the PORT env var or a positional arg:
#     PORT=9000 ./run.sh server      ./run.sh server 9000
# The other commands auto-discover the port the running server chose.
# Students on another PC:  ./run.sh attack alice ws://192.168.1.42:8000/ws
#   (or URL=ws://192.168.1.42:8000/ws ./run.sh attack alice)
#
set -euo pipefail

# Always operate from the project root (this script's directory).
# (no `readlink -f`: it is missing on older macOS)
cd "$(cd "$(dirname "$0")" && pwd)"

VENV=".venv"
PY="$VENV/bin/python"

# Find a system Python >= 3.10 (macOS usually only has `python3`).
find_python() {
    local c
    for c in python3 python; do
        if command -v "$c" >/dev/null 2>&1 &&
           "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
            echo "$c"; return 0
        fi
    done
    return 1
}

# Which port should clients target?
#   1. an explicit PORT env var wins
#   2. else the port the running server wrote to data/.runtime_port
#   3. else the default 8000
resolve_port() {
    if [[ -n "${PORT:-}" ]]; then echo "$PORT"; return; fi
    if [[ -s data/.runtime_port ]]; then cat data/.runtime_port; return; fi
    echo 8000
}

need_venv() {
    if [[ ! -x "$PY" ]]; then
        echo "[!] no venv found. Run:  ./run.sh setup" >&2
        exit 1
    fi
}

cmd="${1:-help}"
shift || true

case "$cmd" in
    setup)
        if ! SYS_PY="$(find_python)"; then
            echo "[!] Python 3.10+ not found." >&2
            echo "    macOS:  brew install python   (or https://www.python.org/downloads/)" >&2
            echo "    Linux:  install python3 + python3-venv with your package manager" >&2
            exit 1
        fi
        echo "[*] using $("$SYS_PY" --version) ($SYS_PY)"
        echo "[*] creating venv in $VENV ..."
        "$SYS_PY" -m venv "$VENV"
        "$PY" -m pip install --upgrade pip
        "$PY" -m pip install -r requirements.txt
        echo "[*] done. Host:  ./run.sh server     Student:  ./run.sh attack <nick> ws://<host-ip>:<port>/ws"
        ;;

    server)
        need_venv
        # Optional positional port -> exported so config.resolve_port() honors it.
        if [[ -n "${1:-}" ]]; then export PORT="$1"; fi
        # The launcher picks/announces the port and writes data/.runtime_port.
        exec "$PY" -m server
        ;;

    monitor)
        need_venv
        port="$(resolve_port)"
        exec "$PY" clients/monitor.py --url "ws://127.0.0.1:${port}/ws"
        ;;

    attack)
        need_venv
        nick="${1:-attacker}"
        port="$(resolve_port)"
        url="${2:-${URL:-ws://127.0.0.1:${port}/ws}}"
        exec "$PY" clients/attacker.py --url "$url" --nick "$nick"
        ;;

    grade)
        need_venv
        exec "$PY" clients/grade.py ${@+"$@"}
        ;;

    ip)
        port="$(resolve_port)"
        ip_addr=""
        # Same detection the server uses (works on Linux, macOS and Windows).
        if [[ -x "$PY" ]]; then
            ip_addr="$("$PY" -c 'from server import config; print(config.lan_ip())' 2>/dev/null || true)"
        fi
        if [[ -n "$ip_addr" && "$ip_addr" != "127.0.0.1" ]]; then
            echo "ws://${ip_addr}:${port}/ws"
        else
            echo "ws://<your-ip>:${port}/ws   (could not auto-detect; Linux: ip addr | macOS: ipconfig getifaddr en0)"
        fi
        ;;

    showcase)
        need_venv
        exec "$PY" clients/showcase.py ${@+"$@"}
        ;;

    reset)
        mkdir -p data
        : > data/events.jsonl
        : > data/defense.jsonl
        echo "[*] logs reset (data/events.jsonl, data/defense.jsonl)"
        ;;

    help|-h|--help|*)
        sed -n '3,20p' "$0" | sed 's/^# \{0,1\}//'
        ;;
esac
