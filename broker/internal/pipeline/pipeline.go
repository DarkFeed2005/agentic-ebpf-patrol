// Package pipeline is the high-throughput concurrent core of the broker:
// decode -> audit -> triage -> (bounded queue | disk overflow) -> worker
// pool -> AI hunter -> response.
//
// Design goals, in priority order:
//  1. Never silently drop a suspicious event. Under load the in-memory
//     dispatch queue can saturate; rather than drop, we spill to a
//     disk-backed overflow log and replay it later.
//  2. Never let the ring buffer reader (internal/ingest) block. HandleRaw
//     does a small, bounded amount of work (decode + audit write + a
//     non-blocking channel send) and returns; all AI evaluation happens
//     off a worker pool.
//  3. Every event is durably recorded locally (the audit log), independent
//     of whether it's forwarded to the AI hunter at all -- the triage
//     heuristic only gates the *AI* evaluation path, not observability.
package pipeline

import (
	"bufio"
	"context"
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"

	"github.com/kalana/ebpf-cyber-patrol/broker/internal/events"
	"github.com/kalana/ebpf-cyber-patrol/broker/internal/hunter"
	"github.com/kalana/ebpf-cyber-patrol/broker/internal/triage"
)

// Config wires a Pipeline's dependencies and tunables.
type Config struct {
	HunterClient  *hunter.Client
	QueueSize     int
	Workers       int
	OverflowPath  string
	AuditPath     string
	ReplayEvery   time.Duration // how often the overflow queue is retried
}

// Pipeline owns the dispatch queue, the audit/overflow logs, and the
// worker pool that evaluates suspicious events against the AI hunter.
type Pipeline struct {
	cfg      Config
	queue    chan events.Event
	metrics  Metrics
	audit    *appendLog
	overflow *appendLog
	wg       sync.WaitGroup
}

// New constructs a Pipeline. Callers must call Start to begin processing
// and Close on shutdown (after the ring buffer reader has stopped feeding
// HandleRaw) to flush and close the log files.
func New(cfg Config) (*Pipeline, error) {
	if cfg.ReplayEvery <= 0 {
		cfg.ReplayEvery = 30 * time.Second
	}
	audit, err := newAppendLog(cfg.AuditPath)
	if err != nil {
		return nil, err
	}
	overflow, err := newAppendLog(cfg.OverflowPath)
	if err != nil {
		_ = audit.Close()
		return nil, err
	}
	return &Pipeline{
		cfg:      cfg,
		queue:    make(chan events.Event, cfg.QueueSize),
		audit:    audit,
		overflow: overflow,
	}, nil
}

// Start launches the worker pool and the overflow-replay loop. Both stop
// when ctx is cancelled.
func (p *Pipeline) Start(ctx context.Context) {
	for i := 0; i < p.cfg.Workers; i++ {
		p.wg.Add(1)
		go p.worker(ctx, i)
	}
	p.wg.Add(1)
	go p.replayLoop(ctx)
}

// Close waits for in-flight work to finish and flushes/closes the log
// files. Call after the ring buffer reader (the sole producer into this
// pipeline) has stopped.
func (p *Pipeline) Close() error {
	p.wg.Wait()
	if err := p.audit.Close(); err != nil {
		log.Printf("pipeline: audit log close error: %v", err)
	}
	return p.overflow.Close()
}

// HandleRaw is the ingest.RawEventHandler entry point: decode, durably
// audit-log, triage, and either enqueue for AI evaluation or spill to the
// disk overflow queue if the in-memory queue is saturated. Never blocks on
// the AI hunter -- that happens entirely in worker().
func (p *Pipeline) HandleRaw(raw []byte) {
	ev, err := events.Decode(raw)
	if err != nil {
		p.metrics.DecodeErrors.Add(1)
		log.Printf("pipeline: decode error: %v", err)
		return
	}
	p.metrics.EventsTotal.Add(1)

	if err := p.audit.Append(ev); err != nil {
		// Audit-log failures are logged but never block the pipeline --
		// losing an audit record is bad, but stalling live threat
		// detection because a disk write failed would be worse.
		log.Printf("pipeline: audit log write failed for pid=%d: %v", ev.PID, err)
	}

	if !triage.IsSuspicious(ev) {
		return
	}
	p.metrics.SuspiciousTotal.Add(1)

	select {
	case p.queue <- ev:
	default:
		p.metrics.QueueOverflows.Add(1)
		if err := p.overflow.Append(ev); err != nil {
			log.Printf("pipeline: CRITICAL overflow persistence failed, event lost pid=%d: %v", ev.PID, err)
			p.metrics.EventsLost.Add(1)
		}
	}
}

func (p *Pipeline) worker(ctx context.Context, id int) {
	defer p.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-p.queue:
			p.evaluate(ctx, ev)
		}
	}
}

func (p *Pipeline) evaluate(ctx context.Context, ev events.Event) {
	verdict, err := p.cfg.HunterClient.Evaluate(ctx, ev)
	if err != nil {
		p.metrics.HunterErrors.Add(1)
		log.Printf("pipeline: hunter evaluation failed pid=%d: %v (spilling to overflow for retry)", ev.PID, err)
		if aerr := p.overflow.Append(ev); aerr != nil {
			log.Printf("pipeline: CRITICAL could not spill failed event pid=%d: %v", ev.PID, aerr)
			p.metrics.EventsLost.Add(1)
		}
		return
	}

	log.Printf(
		"verdict pid=%d comm=%q cmd=%q severity=%s action=%s technique=%s confidence=%.2f",
		ev.PID, ev.Comm, ev.CommandLine, verdict.Severity, verdict.Action, verdict.MitreTechnique, verdict.Confidence,
	)

	if verdict.Action != hunter.ActionKill {
		return
	}
	p.metrics.ActionsKill.Add(1)
	if err := hunter.KillProcess(ev.PID, ev.Comm); err != nil {
		// Not necessarily an error worth paging on: the most common cause
		// is the process having already exited on its own.
		log.Printf("pipeline: response action failed pid=%d: %v", ev.PID, err)
	} else {
		log.Printf("pipeline: terminated pid=%d (comm=%s) per critical AI verdict, technique=%s", ev.PID, ev.Comm, verdict.MitreTechnique)
	}
}

// replayLoop periodically rotates the overflow log and retries every event
// in it against the AI hunter. Events that fail again are re-spilled (they
// re-enter the newly-rotated file via Append -> rotate on the *next* tick,
// having been written to the fresh file opened by rotate()).
func (p *Pipeline) replayLoop(ctx context.Context) {
	defer p.wg.Done()
	ticker := time.NewTicker(p.cfg.ReplayEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.drainOverflow(ctx)
		}
	}
}

func (p *Pipeline) drainOverflow(ctx context.Context) {
	rotated, err := p.overflow.rotate()
	if err != nil {
		log.Printf("pipeline: overflow rotate failed: %v", err)
		return
	}
	if rotated == "" {
		return // nothing had been written since the last drain
	}
	defer os.Remove(rotated)

	f, err := os.Open(rotated)
	if err != nil {
		log.Printf("pipeline: could not open rotated overflow file %s: %v", rotated, err)
		return
	}
	defer f.Close()

	dec := json.NewDecoder(bufio.NewReader(f))
	var replayed, respilled int
	for {
		var ev events.Event
		if err := dec.Decode(&ev); err != nil {
			break // EOF or a malformed trailing line -- stop, don't crash the loop
		}
		if _, err := p.cfg.HunterClient.Evaluate(ctx, ev); err != nil {
			respilled++
			if aerr := p.overflow.Append(ev); aerr != nil {
				log.Printf("pipeline: CRITICAL lost event pid=%d during overflow replay: %v", ev.PID, aerr)
				p.metrics.EventsLost.Add(1)
			}
			continue
		}
		replayed++
	}
	if replayed+respilled > 0 {
		p.metrics.OverflowReplays.Add(uint64(replayed))
		log.Printf("pipeline: overflow replay complete: %d succeeded, %d re-spilled", replayed, respilled)
	}
}
