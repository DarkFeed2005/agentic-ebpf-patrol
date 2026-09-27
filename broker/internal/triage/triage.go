// Package triage applies cheap, local heuristics to decide which exec
// events are worth an LLM call. Every event is still durably written to
// the local audit log by the pipeline regardless of this decision (see
// pipeline.Pipeline.HandleRaw) -- triage only gates the (comparatively
// expensive, higher-latency) AI evaluation path.
//
// This is intentionally high-recall / low-precision: a false positive
// costs one API call, a false negative costs a missed detection. Bias
// toward forwarding.
package triage

import (
	"strings"

	"github.com/kalana/ebpf-cyber-patrol/broker/internal/events"
)

// interpreterBinaries are commonly abused for one-liner reverse shells,
// staged payload execution, etc. Presence alone isn't malicious (this is
// every developer's daily driver) -- it just means "worth the AI's
// judgment on the full argv", which is exactly what triage is for.
var interpreterBinaries = map[string]struct{}{
	"python": {}, "python3": {}, "python2": {},
	"perl": {}, "ruby": {}, "php": {}, "node": {},
	"bash": {}, "sh": {}, "dash": {}, "zsh": {},
	"nc": {}, "ncat": {}, "netcat": {}, "socat": {},
}

// suspiciousDirs are world-writable-by-convention locations commonly used
// to stage droppers.
var suspiciousDirs = []string{"/tmp/", "/dev/shm/", "/var/tmp/", "/run/"}

// IsSuspicious returns true if the event clears at least one heuristic and
// should be queued for AI evaluation.
func IsSuspicious(e events.Event) bool {
	base := baseName(e.Filename)

	if _, ok := interpreterBinaries[base]; ok {
		return true
	}
	for _, dir := range suspiciousDirs {
		if strings.HasPrefix(e.Filename, dir) {
			return true
		}
	}
	if base == "chmod" && hasExecFlag(e.Args) {
		return true
	}
	if isHiddenPath(e.Filename) {
		return true
	}
	if isMasquerading(base, e.Comm) {
		return true
	}
	return false
}

// hasExecFlag looks for a `+x`-style argument, the classic
// `chmod +x payload` pattern.
func hasExecFlag(args []string) bool {
	for _, a := range args {
		if strings.Contains(a, "+x") {
			return true
		}
	}
	return false
}

// isHiddenPath reports whether any path component starts with `.` (and
// isn't `.`/`..`) -- e.g. `/home/user/.cache/.update/payload`.
func isHiddenPath(path string) bool {
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." {
			continue
		}
		if strings.HasPrefix(part, ".") {
			return true
		}
	}
	return false
}

// isMasquerading flags a mismatch between the exec target's basename and
// the reported comm. comm is truncated to TASK_COMM_LEN-1 (15) visible
// characters by the kernel, so we compare on the shorter of the two
// lengths to avoid false positives from that truncation alone.
func isMasquerading(execBase, comm string) bool {
	if execBase == "" || comm == "" {
		return false
	}
	n := len(comm)
	if len(execBase) < n {
		n = len(execBase)
	}
	return execBase[:n] != comm[:n]
}

func baseName(path string) string {
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[i+1:]
	}
	return path
}
