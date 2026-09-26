package pipeline

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
)

// Metrics are plain atomic counters, exposed as JSON rather than a full
// Prometheus client to keep the broker dependency-light. Swap
// MetricsHandler's body for a promhttp.Handler-backed one if you wire in
// github.com/prometheus/client_golang -- the counters themselves are
// already safe to read concurrently from any exporter.
type Metrics struct {
	EventsTotal     atomic.Uint64
	SuspiciousTotal atomic.Uint64
	QueueOverflows  atomic.Uint64
	HunterErrors    atomic.Uint64
	EventsLost      atomic.Uint64
	ActionsKill     atomic.Uint64
	DecodeErrors    atomic.Uint64
	OverflowReplays atomic.Uint64
}

func (p *Pipeline) MetricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]uint64{
		"events_total":      p.metrics.EventsTotal.Load(),
		"suspicious_total":  p.metrics.SuspiciousTotal.Load(),
		"queue_overflows":   p.metrics.QueueOverflows.Load(),
		"hunter_errors":     p.metrics.HunterErrors.Load(),
		"events_lost":       p.metrics.EventsLost.Load(),
		"actions_kill":      p.metrics.ActionsKill.Load(),
		"decode_errors":     p.metrics.DecodeErrors.Load(),
		"overflow_replays":  p.metrics.OverflowReplays.Load(),
		"queue_depth":       uint64(len(p.queue)),
		"queue_capacity":    uint64(cap(p.queue)),
	})
}
