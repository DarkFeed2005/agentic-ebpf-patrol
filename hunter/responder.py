"""Host-side process termination, invoked when a Verdict carries
action=Action.KILL.

This mirrors `broker/internal/hunter/respond.go`'s Go implementation.
Which one actually executes the kill depends on your deployment topology --
see the README's "Response Mechanism" section:

  * Single-node / same PID namespace (hunter and sensor on the same host,
    not container-isolated from each other): this module works directly.
  * Multi-node, or hunter isolated in its own container/PID namespace
    (the default docker-compose.yml topology): prefer the Go broker's
    responder, since it runs alongside the sensor in the host's PID
    namespace. This module then becomes a no-op-in-practice fallback (the
    /proc/<pid>/comm lookup below will simply never find a matching PID in
    a foreign namespace) -- which is safe, not silently wrong.

Both implementations are idempotent against an already-exited process and
independently re-verify comm before signaling, so running both is safe.
"""

from __future__ import annotations

import logging
import os
import signal
import subprocess

logger = logging.getLogger("cyber_patrol.responder")

# Path baked into the hunter container image; see hunter/Dockerfile and
# scripts/kill_pid.sh. Only used by the privileged-fallback path below.
_KILL_SCRIPT = "/opt/cyber-patrol/scripts/kill_pid.sh"


def kill_pid(pid: int, expected_comm: str) -> bool:
    """Attempt to SIGKILL pid, re-verifying its comm first to guard against
    a PID-reuse race between event capture and this action executing.
    Returns True if a kill was actually delivered."""
    comm_path = f"/proc/{pid}/comm"
    try:
        with open(comm_path, "r") as f:
            current_comm = f.read().strip()
    except FileNotFoundError:
        logger.info("pid=%s not visible in this namespace or already exited", pid)
        return False

    if current_comm != expected_comm:
        logger.warning(
            "refusing to kill pid=%s: comm mismatch (expected=%s, current=%s) -- likely PID reuse",
            pid, expected_comm, current_comm,
        )
        return False

    try:
        os.kill(pid, signal.SIGKILL)
        logger.critical("terminated pid=%s (comm=%s) per AI critical verdict", pid, expected_comm)
        return True
    except ProcessLookupError:
        logger.info("pid=%s exited before SIGKILL was delivered", pid)
        return False
    except PermissionError:
        logger.warning("insufficient privilege to signal pid=%s directly; trying privileged helper", pid)
        return _kill_via_script(pid, expected_comm)


def _kill_via_script(pid: int, expected_comm: str) -> bool:
    """Fallback for when the hunter process lacks CAP_KILL over the target
    (e.g. running as an unprivileged container user, per hunter/Dockerfile).
    Requires a sudoers rule scoped to this ONE script -- see README. Do NOT
    grant the service account broader sudo access than this single command;
    the script itself re-validates comm independently before killing."""
    try:
        result = subprocess.run(
            ["sudo", "-n", _KILL_SCRIPT, str(pid), expected_comm],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            logger.critical("terminated pid=%s via privileged helper script", pid)
            return True
        logger.error("kill_pid.sh failed for pid=%s (rc=%s): %s", pid, result.returncode, result.stderr.strip())
        return False
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        logger.error("could not invoke privileged helper for pid=%s: %s", pid, exc)
        return False
