// Command broker is the Go event broker: it consumes the eBPF sensor's
// pinned ring buffer directly (no RPC to the Rust process -- see
// internal/ingest), normalizes and triages events, and dispatches
// suspicious ones to the Python AI threat hunter via a bounded,
// backpressure-safe concurrent pipeline (see internal/pipeline).
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/kalana/ebpf-cyber-patrol/broker/internal/hunter"
	"github.com/kalana/ebpf-cyber-patrol/broker/internal/ingest"
	"github.com/kalana/ebpf-cyber-patrol/broker/internal/pipeline"
)

func main() {
	var (
		mapPath      = flag.String("map-path", "/sys/fs/bpf/cyber_patrol/EVENTS", "pinned ring buffer map path")
		hunterURL    = flag.String("hunter-url", "http://localhost:8000", "AI threat hunter base URL")
		hunterTO     = flag.Duration("hunter-timeout", 5*time.Second, "per-request timeout for the AI hunter")
		hunterRetry  = flag.Int("hunter-retries", 3, "retry attempts per hunter evaluation")
		workers      = flag.Int("workers", 8, "hunter dispatch worker pool size")
		queueSize    = flag.Int("queue-size", 4096, "in-memory hunter dispatch queue depth")
		overflowPath = flag.String("overflow-path", "/var/lib/cyber-patrol/overflow.jsonl", "disk overflow path for backpressure")
		auditPath    = flag.String("audit-path", "/var/lib/cyber-patrol/audit.jsonl", "full local audit log path")
		replayEvery  = flag.Duration("replay-every", 30*time.Second, "how often the overflow queue is retried")
		metricsAddr  = flag.String("metrics-addr", ":9090", "address for /healthz and /metrics")
		openRetries  = flag.Int("open-retries", 10, "attempts to open the pinned map before giving up (waits for the sensor to start)")
	)
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	hc := hunter.New(*hunterURL, *hunterTO, *hunterRetry)
	pl, err := pipeline.New(pipeline.Config{
		HunterClient: hc,
		QueueSize:    *queueSize,
		Workers:      *workers,
		OverflowPath: *overflowPath,
		AuditPath:    *auditPath,
		ReplayEvery:  *replayEvery,
	})
	if err != nil {
		log.Fatalf("broker: failed to initialize pipeline: %v", err)
	}

	pl.Start(ctx)

	reader, err := openWithRetry(*mapPath, *openRetries)
	if err != nil {
		log.Fatalf("broker: %v", err)
	}
	defer reader.Close()

	go serveObservability(*metricsAddr, pl)

	log.Printf("broker: online, reading %s -> %s", *mapPath, *hunterURL)
	if err := reader.Run(ctx, pl.HandleRaw); err != nil {
		log.Printf("broker: ring buffer reader stopped: %v", err)
	}

	log.Println("broker: shutting down, draining in-flight work...")
	if err := pl.Close(); err != nil {
		log.Printf("broker: pipeline close error: %v", err)
	}
	log.Println("broker: shutdown complete")
}

// openWithRetry tolerates the common startup race where the broker starts
// before the Rust sensor has finished loading and pinning its map.
func openWithRetry(mapPath string, attempts int) (*ingest.Reader, error) {
	var lastErr error
	for i := 0; i < attempts; i++ {
		reader, err := ingest.Open(mapPath)
		if err == nil {
			return reader, nil
		}
		lastErr = err
		log.Printf("broker: waiting for sensor to pin %s (attempt %d/%d): %v", mapPath, i+1, attempts, err)
		time.Sleep(2 * time.Second)
	}
	return nil, lastErr
}

func serveObservability(addr string, pl *pipeline.Pipeline) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/metrics", pl.MetricsHandler)
	log.Printf("broker: observability endpoint listening on %s (/healthz, /metrics)", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Printf("broker: observability server stopped: %v", err)
	}
}
