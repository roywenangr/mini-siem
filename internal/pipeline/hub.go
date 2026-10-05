package pipeline

import (
	"sync"

	"github.com/roywenangr/mini-siem/internal/event"
)

// Message is pushed to live subscribers (the dashboard's event stream).
type Message struct {
	Kind   string       `json:"kind"` // "alert" or "events"
	Alert  *event.Alert `json:"alert,omitempty"`
	Events int          `json:"events,omitempty"` // events stored in the last batch
}

// Hub fans messages out to subscribers. A subscriber that falls behind
// loses messages rather than stalling the pipeline.
type Hub struct {
	mu     sync.Mutex
	subs   map[chan Message]struct{}
	closed bool
}

// NewHub returns an empty hub.
func NewHub() *Hub { return &Hub{subs: map[chan Message]struct{}{}} }

// Subscribe returns a channel of messages and a function to unsubscribe.
// The channel is closed when the hub closes or after unsubscribe.
func (h *Hub) Subscribe() (<-chan Message, func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	ch := make(chan Message, 64)
	if h.closed {
		close(ch)
		return ch, func() {}
	}
	h.subs[ch] = struct{}{}
	return ch, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if _, ok := h.subs[ch]; ok {
			delete(h.subs, ch)
			close(ch)
		}
	}
}

// Publish sends m to every subscriber without blocking.
func (h *Hub) Publish(m Message) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- m:
		default:
		}
	}
}

// Close closes every subscriber channel.
func (h *Hub) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	for ch := range h.subs {
		delete(h.subs, ch)
		close(ch)
	}
}
