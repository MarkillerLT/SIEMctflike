#!/usr/bin/env bash
#
# siem-ctf — helper launcher.
#
# Usage:
#   ./run.sh setup              one-time: create .venv and install requirements
#   ./run.sh server [port]      start the WebSocket server (auto-picks a free port)
#   ./run.sh monitor            start the host SIEM monitor CLI (127.0.0.1)
#   ./run.sh attack [nick]      start an attacker CLI (default nick: attacker)
#   ./run.sh grade              print the per-attacker results table (grading)
#   ./run.sh ip                 print the URL classmates should connect to
#   ./run.sh reset              empty the event + defense logs
#
# Port: by default the server tries 8000, then 8080/8081/... if busy. Force a
# specific port with the PORT env var or a positional arg:
#     PORT=9000 ./run.sh server      ./run.sh server 9000
# The other commands auto-discover the port the running server chose. Override
# the full client URL with:  URL=ws://192.168.1.42:8000/ws ./run.sh attack bob
#
set -euo pipefail

# Always operate from the project root (this script's directory).
cd "$(dirname "$(readlink -f "$0")")"

VENV=".venv"
PY="$VENV/bin/python"

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
        echo "[*] creating venv in $VENV ..."
        python -m venv "$VENV"
        "$VENV/bin/pip" install --upgrade pip
        "$VENV/bin/pip" install -r requirements.txt
        echo "[*] done. Next:  ./run.sh server"
        ;;

    server)
        need_venv
        # Optional positional port -> exported so config.resolve_port() honors it.
        [[ -n "${1:-}" ]] && export PORT="$1"
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
        url="${URL:-ws://127.0.0.1:${port}/ws}"
        exec "$PY" clients/attacker.py --url "$url" --nick "$nick"
        ;;

    grade)
        need_venv
        exec "$PY" clients/grade.py "$@"
        ;;

    ip)
        port="$(resolve_port)"
        ip_addr="$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')"
        if [[ -n "${ip_addr:-}" ]]; then
            echo "ws://${ip_addr}:${port}/ws"
        else
            echo "ws://<your-ip>:${port}/ws   (could not auto-detect; try: ip addr)"
        fi
        ;;

    reset)
        : > data/events.jsonl
        : > data/defense.jsonl
        echo "[*] logs reset (data/events.jsonl, data/defense.jsonl)"
        ;;

    help|-h|--help|*)
        sed -n '3,18p' "$0" | sed 's/^# \{0,1\}//'
        ;;
esac
