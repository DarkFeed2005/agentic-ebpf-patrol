#!/usr/bin/env bash
# Privileged, PID-reuse-safe process terminator for the Cyber Patrol
# response mechanism.
#
# Intended to be invoked ONLY by hunter/responder.py's `_kill_via_script`,
# via a sudoers rule scoped to this exact path (see hunter/Dockerfile and
# README "Response Mechanism"). Do not grant broader sudo access to the
# hunter service account than this one command.
#
# Usage: kill_pid.sh <pid> <expected_comm>
#
# Never signals without first re-verifying the target's /proc/<pid>/comm
# matches what the eBPF sensor observed at exec time, guarding against a
# PID-reuse race between event capture and this script executing.

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <pid> <expected_comm>" >&2
    exit 2
fi

pid="$1"
expected_comm="$2"

if ! [[ "$pid" =~ ^[0-9]+$ ]]; then
    echo "error: pid must be numeric, got: $pid" >&2
    exit 2
fi

if (( pid <= 1 )); then
    echo "error: refusing to touch pid $pid (init/invalid)" >&2
    exit 3
fi

comm_path="/proc/${pid}/comm"
if [[ ! -r "$comm_path" ]]; then
    echo "info: pid $pid already exited, nothing to do"
    exit 0
fi

current_comm="$(tr -d '\n' < "$comm_path")"
if [[ "$current_comm" != "$expected_comm" ]]; then
    echo "error: comm mismatch for pid $pid (expected '$expected_comm', found '$current_comm') -- possible PID reuse, refusing to kill" >&2
    exit 4
fi

kill -SIGKILL "$pid"
echo "killed pid $pid (comm=$current_comm)"
