// Package pipeline moves events from the inputs through storage and the rule
// engine, and fans new alerts out to notifiers and live subscribers.
package pipeline

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/roywenangr/mini-siem/internal/event"
	"github.com/roywenangr/mini-siem/internal/rules"
	"github.com/roywenangr/mini-siem/internal/store"
)

// Notifier is told about every new alert. Notify must not block for long;
// slow notifiers should hand off to their own goroutine.
type Notifier interface {
	Notify(a *event.Alert)
}

// Options tune the pipeline. Zero values pick sensible defaults.
type Options struct {
	QueueSize     int           // buffered events before Submit blocks
	BatchSize     int           // events stored per transaction
	FlushInterval time.Duration // max wait before a partial batch is stored
	Retention     time.Duration // delete events older than this; 0 keeps forever
}

// Pipeline is the core event loop.
type Pipeline struct {
	store     *store.Store
	engine    *rules.Engine
	notifiers []Notifier
	hub       *Hub
	opts      Options
	log       *slog.Logger

	in chan *event.Event

	ingested atomic.Int64
	alerts   atomic.Int64
	failures atomic.Int64

	mu       sync.Mutex
	latestTS time.Time // newest event time seen; the engine's notion of "now"
}

// New creates a pipeline. Call Run to start it.
func New(st *store.Store, eng *rules.Engine, hub *Hub, log *slog.Logger, opts Options, notifiers ...Notifier) *Pipeline {
	if opts.QueueSize <= 0 {
		opts.QueueSize = 10000
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 500
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = 200 * time.Millisecond
	}
	if log == nil {
		log = slog.Default()
	}
	return &Pipeline{
		store:     st,
		engine:    eng,
		notifiers: notifiers,
		hub:       hub,
		opts:      opts,
		log:       log,
		in:        make(chan *event.Event, opts.QueueSize),
	}
}

// ErrStopped is returned by Submit after the pipeline has shut down.
var ErrStopped = errors.New("pipeline stopped")

// Submit queues events, blocking while the queue is full (backpressure for
// the HTTP ingest endpoint and file tailers) until ctx is done.
func (p *Pipeline) Submit(ctx context.Context, evs ...*event.Event) error {
	for _, ev := range evs {
		select {
		case p.in <- ev:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// Counters reports running totals.
type Counters struct {
	Ingested    int64 `json:"ingested"`
	Alerts      int64 `json:"alerts"`
	Failures    int64 `json:"store_failures"`
	Queued      int   `json:"queued"`
	EngineState int   `json:"engine_state"`
}

// Counters returns the current counters.
func (p *Pipeline) Counters() Counters {
	return Counters{
		Ingested:    p.ingested.Load(),
		Alerts:      p.alerts.Load(),
		Failures:    p.failures.Load(),
		Queued:      len(p.in),
		EngineState: p.engine.StateSize(),
	}
}

// Run processes events until ctx is cancelled, then drains what is already
// queued and returns.
func (p *Pipeline) Run(ctx context.Context) {
	flush := time.NewTicker(p.opts.FlushInterval)
	defer flush.Stop()
	sweep := time.NewTicker(time.Minute)
	defer sweep.Stop()
	retention := time.NewTicker(time.Hour)
	defer retention.Stop()
	p.applyRetention()

	batch := make([]*event.Event, 0, p.opts.BatchSize)
	for {
		select {
		case ev := <-p.in:
			batch = append(batch, ev)
			if len(batch) >= p.opts.BatchSize {
				p.process(batch)
				batch = batch[:0]
			}
		case <-flush.C:
			if len(batch) > 0 {
				p.process(batch)
				batch = batch[:0]
			}
		case <-sweep.C:
			p.mu.Lock()
			now := p.latestTS
			p.mu.Unlock()
			if !now.IsZero() {
				p.engine.Sweep(now)
			}
		case <-retention.C:
			p.applyRetention()
		case <-ctx.Done():
			for {
				select {
				case ev := <-p.in:
					batch = append(batch, ev)
					if len(batch) >= p.opts.BatchSize {
						p.process(batch)
						batch = batch[:0]
					}
				default:
					if len(batch) > 0 {
						p.process(batch)
					}
					p.hub.Close()
					return
				}
			}
		}
	}
}

// process stores a batch, runs it through the rule engine in timestamp
// order and publishes the results. It uses its own context so that a
// shutdown does not abandon a batch half written.
func (p *Pipeline) process(batch []*event.Event) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sort.SliceStable(batch, func(i, j int) bool { return batch[i].Timestamp.Before(batch[j].Timestamp) })
	if err := p.store.InsertEvents(ctx, batch); err != nil {
		p.failures.Add(1)
		p.log.Error("store events failed; batch dropped", "events", len(batch), "err", err)
		return
	}
	p.ingested.Add(int64(len(batch)))

	p.mu.Lock()
	if last := batch[len(batch)-1].Timestamp; last.After(p.latestTS) {
		p.latestTS = last
	}
	p.mu.Unlock()

	for _, ev := range batch {
		for _, a := range p.engine.Process(ev) {
			if err := p.store.InsertAlert(ctx, a); err != nil {
				p.failures.Add(1)
				p.log.Error("store alert failed", "rule", a.RuleID, "err", err)
				continue
			}
			p.alerts.Add(1)
			p.log.Warn("alert", "id", a.ID, "rule", a.RuleID, "severity", a.Severity, "group", a.GroupKey, "desc", a.Description)
			p.hub.Publish(Message{Kind: "alert", Alert: a})
			for _, n := range p.notifiers {
				n.Notify(a)
			}
		}
	}
	p.hub.Publish(Message{Kind: "events", Events: len(batch)})
}

func (p *Pipeline) applyRetention() {
	if p.opts.Retention <= 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	n, err := p.store.DeleteEventsBefore(ctx, time.Now().Add(-p.opts.Retention))
	if err != nil {
		p.log.Error("retention failed", "err", err)
		return
	}
	if n > 0 {
		p.log.Info("retention removed old events", "events", n)
	}
}
