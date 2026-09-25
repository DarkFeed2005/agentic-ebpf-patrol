package hunter

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

// KillProcess sends SIGKILL to pid, the response mechanism for a
// severity=critical, action=kill verdict.
//
// Why this lives in the Go broker rather than only in Python: the broker
// runs alongside the sensor, on the same host and PID namespace as the
// monitored processes. The Python hunter is a horizontally-scalable
// evaluation service and may run on a different host/container/PID
// namespace entirely (see docker-compose.yml), where os.Kill(pid) would
// target the wrong namespace's pid 12345. hunter/responder.py implements
// the same action for single-node deployments where hunter *does* share a
// PID namespace with the sensor -- pick whichever matches your topology
// (both are safe to run together: killing an already-dead process is a
// no-op error, not a hazard).
//
// PID-reuse safety: SIGKILL is definitionally destructive and pid alone is
// not a stable process identity across time -- the process the sensor
// observed at exec time may have already exited, with pid recycled to an
// unrelated process, by the time the AI verdict comes back (LLM round-trip
// latency is on the order of hundreds of milliseconds to a few seconds).
// We re-check /proc/<pid>/comm against what the sensor captured before
// killing. This is best-effort, not airtight: a hardened implementation
// should instead capture /proc/<pid>/stat's start-time (field 22) in the
// eBPF event and compare that, which is race-free (comm can coincidentally
// match a reused pid; the exact start-time practically cannot).
func KillProcess(pid uint32, expectedComm string) error {
	if pid <= 1 {
		return fmt.Errorf("refusing to signal pid %d (init/invalid)", pid)
	}

	commPath := fmt.Sprintf("/proc/%d/comm", pid)
	commBytes, err := os.ReadFile(commPath)
	if err != nil {
		return fmt.Errorf("pid=%d already exited, nothing to kill: %w", pid, err)
	}

	current := strings.TrimSpace(string(commBytes))
	if current != expectedComm {
		return fmt.Errorf(
			"refusing to kill pid=%d: comm mismatch (expected %q, found %q) -- likely PID reuse",
			pid, expectedComm, current,
		)
	}

	if err := syscall.Kill(int(pid), syscall.SIGKILL); err != nil {
		return fmt.Errorf("kill pid=%d: %w", pid, err)
	}
	return nil
}
