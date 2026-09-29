#!/usr/bin/env bash
# Stop the full Cyber Patrol stack. Needs root to signal root-owned
# processes started by run_all.sh.
set -u

if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: must run as root (services were started by root)."
    echo "  sudo bash $0"
    exit 1
fi

for pat in cyber-patrol-loader 'bin/broker' uvicorn; do
    pids="$(pgrep -f "$pat" 2>/dev/null || true)"
    if [[ -n "$pids" ]]; then
        kill $pids 2>/dev/null
        echo "stopped: $pat (pids $pids)"
    fi
done
sleep 1
echo "== cyber-patrol stack stopped =="