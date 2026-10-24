package notify

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/SantanaCharles/sentinels/internal/finding"
	"github.com/SantanaCharles/sentinels/internal/watch"
)

// Channel is a notifier with its own threshold.
type Channel struct {
	Notifier    Notifier
	MinSeverity finding.Severity
}

// Fanout implements watch.Alerter. Each channel has its own queue and worker,
// so a slow or failing channel never blocks detection or the other channels.
type Fanout struct {
	Host string
	Log  func(format string, args ...any)

	workers []*worker
	wg      sync.WaitGroup
}

const queueSize = 200

type worker struct {
	ch      Channel
	queue   chan Message
	limiter *limiter
	log     func(string, ...any)
	mu      sync.Mutex
	dropped int // lost because the queue was full or the limit was hit
}

// NewFanout starts one worker per channel; they stop when ctx ends.
func NewFanout(ctx context.Context, host string, chans []Channel, log func(string, ...any)) *Fanout {
	if log == nil {
		log = func(string, ...any) {}
	}
	f := &Fanout{Host: host, Log: log}
	for _, c := range chans {
		w := &worker{ch: c, queue: make(chan Message, queueSize), limiter: newLimiter(), log: log}
		f.workers = append(f.workers, w)
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			w.run(ctx)
		}()
	}
	return f
}

// Wait blocks until every worker has stopped (after ctx is cancelled).
func (f *Fanout) Wait() { f.wg.Wait() }

func (f *Fanout) Alert(_ context.Context, a watch.Alert) error {
	m := FromAlert(a, f.Host)
	for _, w := range f.workers {
		if m.Severity < w.ch.MinSeverity {
			continue
		}
		select {
		case w.queue <- m:
		default:
			w.mu.Lock()
			w.dropped++
			w.mu.Unlock()
		}
	}
	return nil
}

func (w *worker) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case m := <-w.queue:
			if !w.limiter.allow(m.Severity, time.Now()) {
				w.mu.Lock()
				w.dropped++
				w.mu.Unlock()
				continue
			}
			if n := w.takeDropped(); n > 0 {
				w.deliver(ctx, Message{
					Severity: finding.High, Host: m.Host, Time: time.Now(),
					Title: fmt.Sprintf("%d alerta(s) não enviados por limite de frequência", n),
					Lines: []string{"Possível ataque em massa ou regra ruidosa. Veja: sentinels events --since 1h"},
				})
			}
			w.deliver(ctx, m)
		}
	}
}

func (w *worker) takeDropped() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := w.dropped
	w.dropped = 0
	return n
}

// deliver retries transient failures with backoff: 2s, 8s, 30s.
func (w *worker) deliver(ctx context.Context, m Message) {
	delays := []time.Duration{2 * time.Second, 8 * time.Second, 30 * time.Second}
	for attempt := 0; ; attempt++ {
		err := w.ch.Notifier.Send(ctx, m)
		if err == nil {
			return
		}
		if attempt == len(delays) || ctx.Err() != nil {
			w.log("notificador %s: falhou após %d tentativa(s): %v", w.ch.Notifier.Name(), attempt+1, err)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delays[attempt]):
		}
	}
}

// limiter is a token bucket per class: critical alerts have their own budget
// so a flood of lower alerts never starves them.
type limiter struct {
	mu      sync.Mutex
	buckets map[bool]*bucket
}

type bucket struct {
	tokens   float64
	capacity float64
	perSec   float64
	last     time.Time
}

func newLimiter() *limiter {
	return &limiter{buckets: map[bool]*bucket{
		true:  {tokens: 30, capacity: 30, perSec: 1.0 / 60}, // critical: 30 burst, +1/min
		false: {tokens: 10, capacity: 10, perSec: 1.0 / 60}, // others: 10 burst, +1/min
	}}
}

func (l *limiter) allow(sev finding.Severity, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[sev == finding.Critical]
	if !b.last.IsZero() {
		b.tokens = min(b.capacity, b.tokens+now.Sub(b.last).Seconds()*b.perSec)
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
