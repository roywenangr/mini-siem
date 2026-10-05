package pipeline

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/roywenangr/mini-siem/internal/event"
)

// Webhook posts alerts at or above MinSeverity as JSON to URL. Delivery runs
// on a background goroutine with a small queue; when the receiver is down,
// excess alerts are dropped and logged rather than blocking detection.
type Webhook struct {
	url    string
	minSev int
	client *http.Client
	queue  chan *event.Alert
	log    *slog.Logger
}

// NewWebhook starts a webhook notifier.
func NewWebhook(url, minSeverity string, log *slog.Logger) (*Webhook, error) {
	if minSeverity == "" {
		minSeverity = event.SeverityLow
	}
	rank := event.SeverityRank(minSeverity)
	if rank == 0 {
		return nil, fmt.Errorf("webhook: unknown min severity %q", minSeverity)
	}
	if log == nil {
		log = slog.Default()
	}
	w := &Webhook{
		url:    url,
		minSev: rank,
		client: &http.Client{Timeout: 10 * time.Second},
		queue:  make(chan *event.Alert, 256),
		log:    log,
	}
	go w.loop()
	return w, nil
}

// Notify implements Notifier.
func (w *Webhook) Notify(a *event.Alert) {
	if event.SeverityRank(a.Severity) < w.minSev {
		return
	}
	select {
	case w.queue <- a:
	default:
		w.log.Warn("webhook queue full; alert not delivered", "alert", a.ID)
	}
}

// payload carries a "text" field so the same webhook works with Slack and
// Discord-style incoming webhooks as well as custom receivers.
type payload struct {
	Text  string       `json:"text"`
	Alert *event.Alert `json:"alert"`
}

func (w *Webhook) loop() {
	for a := range w.queue {
		body, _ := json.Marshal(payload{
			Text:  fmt.Sprintf("[%s] %s: %s", a.Severity, a.RuleName, a.Description),
			Alert: a,
		})
		if err := w.post(body); err != nil {
			w.log.Error("webhook delivery failed", "alert", a.ID, "err", err)
		}
	}
}

func (w *Webhook) post(body []byte) error {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
		}
		resp, err := w.client.Post(w.url, "application/json", bytes.NewReader(body))
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()
		if resp.StatusCode < 300 {
			return nil
		}
		lastErr = fmt.Errorf("status %s", resp.Status)
		if resp.StatusCode < 500 {
			return lastErr // client errors will not succeed on retry
		}
	}
	return lastErr
}
