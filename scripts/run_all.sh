#!/usr/bin/env bash
# Single-command bring-up for the full Cyber Patrol stack.
#
# Usage:
#   sudo bash scripts/run_all.sh     # start everything
#   sudo bash scripts/stop_all.sh    # stop everything
#
# The hunter reads its provider settings from <repo>/.env (gitignored; see
# .env.example). The eBPF sensor + broker need root (CAP_BPF / pinned-map
# read), so this script must run under sudo or as root.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
ROOT="$(pwd)"
LOG_DIR="${CYBER_PATROL_LOG_DIR:-/var/lib/cyber-patrol}"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: must run as root (eBPF sensor + pinned-map access need CAP_BPF)."
    echo "  sudo bash $0"
    exit 1
fi

echo "== cyber-patrol one-shot bring-up =="

# 1. clear any leftover instances
bash scripts/stop_all.sh

# 2. build anything missing
[[ -x "$ROOT/sensor/target/release/cyber-patrol-loader" ]] || {
    echo "[build] sensor..."; (cd "$ROOT/sensor" && cargo build --release -p cyber-patrol-loader) || exit 1
}
[[ -x "$ROOT/broker/bin/broker" ]] || {
    echo "[build] broker..."; (cd "$ROOT/broker" && go build -buildvcs=false -o bin/broker .) || exit 1
}
[[ -x "$ROOT/hunter/.venv/bin/uvicorn" ]] || {
    echo "[build] hunter venv..."; (cd "$ROOT/hunter" && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt) || exit 1
}

# 3. make sure kernel surfaces are mounted
mkdir -p /sys/fs/bpf
mountpoint -q /sys/fs/bpf        || mount -t bpf bpf /sys/fs/bpf
mountpoint -q /sys/kernel/tracing || mount -t tracefs tracefs /sys/kernel/tracing
mkdir -p /sys/fs/bpf/cyber_patrol "$LOG_DIR"

# 4. load hunter provider settings from repo .env (key, base_url, model, max_tokens)
if [[ -f "$ROOT/.env" ]]; then
    set -a; source "$ROOT/.env"; set +a
fi

# 5. start the three services (each logs to $LOG_DIR/<name>.log)
nohup "$ROOT/sensor/target/release/cyber-patrol-loader" > "$LOG_DIR/sensor.log" 2>&1 &
echo "sensor  pid $!"
nohup "$ROOT/broker/bin/broker" \
    -map-path=/sys/fs/bpf/cyber_patrol/EVENTS \
    -hunter-url=http://localhost:8000 \
    -overflow-path="$LOG_DIR/overflow.jsonl" \
    -audit-path="$LOG_DIR/audit.jsonl" \
    > "$LOG_DIR/broker.log" 2>&1 &
echo "broker  pid $!"
(
    cd "$ROOT/hunter" || exit 1
    nohup .venv/bin/uvicorn app:app --host 0.0.0.0 --port 8000 > "$LOG_DIR/hunter.log" 2>&1 &
    echo "hunter  pid $!"
)

# 6. readiness check (up to ~20s)
echo "waiting for hunter (:8000) and broker (:9090) to become ready..."
up=0
for _ in $(seq 1 20); do
    h=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8000/healthz 2>/dev/null)
    b=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:9090/healthz 2>/dev/null)
    [[ "$h" == "200" && "$b" == "200" ]] && { up=1; break; }
    sleep 1
done

echo
if [[ "$up" == "1" ]]; then
    "$ROOT/hunter/.venv/bin/python" "$ROOT/scripts/banner.py" 2>/dev/null \
        || echo "== cyber-patrol is UP =="
else
    echo "== WARNING: not all services came up. Check: =="
    echo "  $LOG_DIR/sensor.log"
    echo "  $LOG_DIR/broker.log"
    echo "  $LOG_DIR/hunter.log"
fi