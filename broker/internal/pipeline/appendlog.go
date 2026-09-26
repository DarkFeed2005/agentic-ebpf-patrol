package pipeline

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/kalana/ebpf-cyber-patrol/broker/internal/events"
)

// appendLog is a minimal, thread-safe JSON-lines append-only file. It backs
// both the full-fidelity audit log and the disk-based backpressure overflow
// queue.
//
// This is deliberately simple for a portfolio-scale showcase. A production
// deployment pushing sustained high event rates should replace this with a
// proper embedded log/queue (e.g. BoltDB/BadgerDB, or a segment-rotated
// append log with acked offsets) to bound file size and avoid the
// O(file size) replay cost in drainOverflow. That swap is fully contained
// to this file and rotate()/drainOverflow() in pipeline.go.
type appendLog struct {
	mu   sync.Mutex
	path string
	f    *os.File
	w    *bufio.Writer
	enc  *json.Encoder
}

func newAppendLog(path string) (*appendLog, error) {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	w := bufio.NewWriter(f)
	return &appendLog{path: path, f: f, w: w, enc: json.NewEncoder(w)}, nil
}

func (a *appendLog) Append(ev events.Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.enc.Encode(ev); err != nil {
		return err
	}
	return a.w.Flush()
}

func (a *appendLog) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.w.Flush(); err != nil {
		a.f.Close()
		return err
	}
	return a.f.Close()
}

// rotate closes the current file, renames it aside (for the caller to
// drain/replay), and reopens a fresh file at the same path. Writers are
// never blocked by a concurrent replay pass since rotation is instant and
// happens entirely under the same mutex Append uses.
func (a *appendLog) rotate() (rotatedPath string, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if err := a.w.Flush(); err != nil {
		return "", err
	}
	if err := a.f.Close(); err != nil {
		return "", err
	}

	rotated := a.path + ".replay"
	if err := os.Rename(a.path, rotated); err != nil {
		if os.IsNotExist(err) {
			rotated = "" // nothing had been written yet; nothing to replay
		} else {
			return "", err
		}
	}

	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return "", err
	}
	a.f = f
	a.w = bufio.NewWriter(f)
	a.enc = json.NewEncoder(a.w)
	return rotated, nil
}
