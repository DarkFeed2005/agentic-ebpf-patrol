// Package ingest is the Rust -> Go IPC boundary: it opens the EVENTS ring
// buffer that cyber-patrol-loader (Rust) pinned to bpffs, and consumes it
// directly via cilium/ebpf -- no socket, no RPC, no serialization format
// negotiated between the two languages. The kernel ring buffer *is* the
// interface; both sides only need to agree on where it's pinned and how an
// ExecEvent's bytes are laid out (see internal/events).
package ingest

import (
	"context"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// RawEventHandler processes one raw ring buffer record. Implementations
// must not block indefinitely -- Run's read loop is single-threaded, and a
// slow handler directly reduces sensor throughput. (Our handler,
// pipeline.Pipeline.HandleRaw, does a bounded amount of local work and
// hands off to a worker pool; see internal/pipeline.)
type RawEventHandler func(raw []byte)

// Reader wraps a pinned BPF_MAP_TYPE_RINGBUF map opened as a
// cilium/ebpf ringbuf.Reader.
type Reader struct {
	m      *ebpf.Map
	reader *ringbuf.Reader
}

// Open opens the ring buffer map pinned at pinPath (e.g.
// "/sys/fs/bpf/cyber_patrol/EVENTS", as produced by cyber-patrol-loader's
// EbpfLoader::map_pin_path). Returns an error -- rather than retrying
// internally -- if the sensor hasn't started yet or hasn't pinned the map;
// callers (main.go) decide the retry/backoff policy.
func Open(pinPath string) (*Reader, error) {
	m, err := ebpf.LoadPinnedMap(pinPath, nil)
	if err != nil {
		return nil, fmt.Errorf(
			"open pinned ring buffer at %s (has the Rust sensor been started, and did it pin successfully?): %w",
			pinPath, err,
		)
	}
	rd, err := ringbuf.NewReader(m)
	if err != nil {
		m.Close()
		return nil, fmt.Errorf("attach ring buffer reader to %s: %w", pinPath, err)
	}
	return &Reader{m: m, reader: rd}, nil
}

// Close releases the ring buffer reader and the underlying map fd.
func (r *Reader) Close() error {
	err := r.reader.Close()
	if cerr := r.m.Close(); cerr != nil && err == nil {
		err = cerr
	}
	return err
}

// Run blocks, invoking handle for every raw event, until ctx is cancelled.
// cilium/ebpf's ringbuf.Reader.Read blocks internally on an epoll wait; we
// unblock it on shutdown by closing the reader from a separate goroutine,
// which is the documented way to interrupt a blocked Read.
func (r *Reader) Run(ctx context.Context, handle RawEventHandler) error {
	go func() {
		<-ctx.Done()
		_ = r.reader.Close()
	}()

	for {
		record, err := r.reader.Read()
		if err != nil {
			if ctx.Err() != nil {
				return nil // clean shutdown: ctx cancellation closed the reader
			}
			log.Printf("ingest: ring buffer read error: %v", err)
			continue
		}
		handle(record.RawSample)
	}
}
