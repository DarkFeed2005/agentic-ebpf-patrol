#!/usr/bin/env bash
# Pre-flight checks for the eBPF sensor. Run before starting
# cyber-patrol-loader on a new host.

set -uo pipefail

echo "== Cyber Patrol sensor pre-flight checks =="

if [[ -r /sys/kernel/btf/vmlinux ]]; then
    echo "OK:   kernel BTF present (/sys/kernel/btf/vmlinux) -- CO-RE features usable"
else
    echo "FAIL: no /sys/kernel/btf/vmlinux -- kernel lacks BTF; rebuild with CONFIG_DEBUG_INFO_BTF=y"
fi

if mount | grep -q "on /sys/fs/bpf type bpf"; then
    echo "OK:   bpffs mounted at /sys/fs/bpf"
else
    echo "WARN: /sys/fs/bpf is not mounted as bpffs; pinning will fail. Fix with:"
    echo "        sudo mount -t bpf bpf /sys/fs/bpf"
fi

kernel_version="$(uname -r)"
echo "INFO: kernel $kernel_version (ring buffer maps require >= 5.8)"

if [[ -r /sys/kernel/tracing/events/syscalls/sys_enter_execve/format ]]; then
    echo "OK:   sys_enter_execve tracepoint format available"
else
    echo "WARN: tracing filesystem not found at /sys/kernel/tracing -- check it's mounted"
    echo "        sudo mount -t tracefs tracefs /sys/kernel/tracing"
fi

if command -v bpftool >/dev/null 2>&1; then
    echo "OK:   bpftool available (bpftool prog list / bpftool map list for debugging)"
else
    echo "WARN: bpftool not found -- install linux-tools-$(uname -r) or your distro's equivalent"
fi

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "WARN: not running as root -- the loader needs CAP_BPF + CAP_PERFMON (or root) to load programs"
fi

echo "== Pre-flight checks complete =="
