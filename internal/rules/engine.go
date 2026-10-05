package rules

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/roywenangr/mini-siem/internal/event"
)

// maxHitsPerGroup bounds memory for a single noisy group key. Once reached,
// the oldest hits are dropped; counts above this are reported as the cap.
const maxHitsPerGroup = 10000

// maxAlertEventIDs is how many contributing event ids an alert carries.
const maxAlertEventIDs = 50

// Engine evaluates rules against events in timestamp order. Windows are
// measured in event time, not wall-clock time, so replaying an old log file
// produces the same alerts it would have live. It is safe for concurrent use.
type Engine struct {
	mu    sync.Mutex
	rules []*Rule
	state map[stateKey]*groupState
}

type stateKey struct{ rule, group string }

type hit struct {
	ts       time.Time
	eventID  int64
	distinct string
}

type groupState struct {
	hits []hit
	// suppressUntil stops the same rule and group from re-alerting until
	// one window has passed since the last alert.
	suppressUntil time.Time
	lastSeen      time.Time
}

// NewEngine returns an engine for the given rules. Disabled rules are kept
// (so they can be listed) but never evaluated.
func NewEngine(rs []*Rule) *Engine {
	return &Engine{rules: rs, state: map[stateKey]*groupState{}}
}

// Rules returns the loaded rules.
func (e *Engine) Rules() []*Rule {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]*Rule(nil), e.rules...)
}

// Process evaluates ev against every rule and returns the alerts it raised.
// ev.ID should already be set so alerts can reference it.
func (e *Engine) Process(ev *event.Event) []*event.Alert {
	e.mu.Lock()
	defer e.mu.Unlock()

	var alerts []*event.Alert
	for _, r := range e.rules {
		if r.Disabled {
			continue
		}
		var a *event.Alert
		switch r.Kind {
		case KindMatch:
			a = e.evalMatch(r, ev)
		case KindThreshold:
			a = e.evalThreshold(r, ev)
		case KindSequence:
			a = e.evalSequence(r, ev)
		}
		if a != nil {
			alerts = append(alerts, a)
		}
	}
	return alerts
}

func (e *Engine) evalMatch(r *Rule, ev *event.Event) *event.Alert {
	if !r.Where.Match(ev) {
		return nil
	}
	group := groupValue(r, ev)
	if r.Window > 0 {
		st := e.group(r, group)
		if ev.Timestamp.Before(st.suppressUntil) {
			return nil
		}
		st.suppressUntil = ev.Timestamp.Add(r.Window)
		st.lastSeen = ev.Timestamp
	}
	return newAlert(r, group, 1, ev.Timestamp, ev.Timestamp, []int64{ev.ID})
}

func (e *Engine) evalThreshold(r *Rule, ev *event.Event) *event.Alert {
	if !r.Where.Match(ev) {
		return nil
	}
	group, ok := ev.Get(r.GroupBy)
	if !ok || group == "" {
		return nil
	}
	h := hit{ts: ev.Timestamp, eventID: ev.ID}
	if r.Distinct != "" {
		h.distinct, _ = ev.Get(r.Distinct)
	}

	st := e.group(r, group)
	st.add(h, ev.Timestamp.Add(-r.Window))

	count := len(st.hits)
	if r.Distinct != "" {
		count = st.distinctCount()
	}
	if count < r.Threshold || ev.Timestamp.Before(st.suppressUntil) {
		return nil
	}
	a := newAlert(r, group, count, st.hits[0].ts, ev.Timestamp, st.eventIDs())
	st.hits = st.hits[:0]
	st.suppressUntil = ev.Timestamp.Add(r.Window)
	return a
}

func (e *Engine) evalSequence(r *Rule, ev *event.Event) *event.Alert {
	isFirst, isThen := r.Where.Match(ev), r.Then.Match(ev)
	if !isFirst && !isThen {
		return nil
	}
	group, ok := ev.Get(r.GroupBy)
	if !ok || group == "" {
		return nil
	}
	cutoff := ev.Timestamp.Add(-r.Window)

	// Then is checked against the hits gathered before this event, so an
	// event matching both conditions cannot complete its own sequence.
	if isThen {
		key := stateKey{r.ID, group}
		if st, ok := e.state[key]; ok {
			st.prune(cutoff)
			if len(st.hits) >= r.Threshold && !ev.Timestamp.Before(st.suppressUntil) {
				ids := append(st.eventIDs(), ev.ID)
				a := newAlert(r, group, len(st.hits), st.hits[0].ts, ev.Timestamp, ids)
				st.hits = st.hits[:0]
				st.suppressUntil = ev.Timestamp.Add(r.Window)
				return a
			}
		}
	}
	if isFirst {
		e.group(r, group).add(hit{ts: ev.Timestamp, eventID: ev.ID}, cutoff)
	}
	return nil
}

func (e *Engine) group(r *Rule, group string) *groupState {
	key := stateKey{r.ID, group}
	st, ok := e.state[key]
	if !ok {
		st = &groupState{}
		e.state[key] = st
	}
	return st
}

// Sweep drops per-group state that can no longer affect any rule, given
// that no event older than now will arrive. Call it periodically to keep
// memory bounded when many distinct groups (IPs) come and go.
func (e *Engine) Sweep(now time.Time) int {
	e.mu.Lock()
	defer e.mu.Unlock()

	windows := map[string]time.Duration{}
	for _, r := range e.rules {
		windows[r.ID] = r.Window
	}
	removed := 0
	for k, st := range e.state {
		w, ok := windows[k.rule]
		if !ok || (now.Sub(st.lastSeen) > w && !now.Before(st.suppressUntil)) {
			delete(e.state, k)
			removed++
		}
	}
	return removed
}

// StateSize reports how many rule/group states are being tracked.
func (e *Engine) StateSize() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.state)
}

func (st *groupState) add(h hit, cutoff time.Time) {
	st.prune(cutoff)
	if len(st.hits) >= maxHitsPerGroup {
		st.hits = st.hits[1:]
	}
	st.hits = append(st.hits, h)
	if h.ts.After(st.lastSeen) {
		st.lastSeen = h.ts
	}
}

// prune drops hits at or before cutoff. Hits arrive roughly in order, so
// the scan stops at the first one inside the window.
func (st *groupState) prune(cutoff time.Time) {
	i := 0
	for i < len(st.hits) && !st.hits[i].ts.After(cutoff) {
		i++
	}
	if i > 0 {
		st.hits = append(st.hits[:0], st.hits[i:]...)
	}
}

func (st *groupState) distinctCount() int {
	seen := make(map[string]struct{}, len(st.hits))
	for _, h := range st.hits {
		seen[h.distinct] = struct{}{}
	}
	return len(seen)
}

func (st *groupState) eventIDs() []int64 {
	hs := st.hits
	if len(hs) > maxAlertEventIDs {
		hs = hs[len(hs)-maxAlertEventIDs:]
	}
	ids := make([]int64, len(hs))
	for i, h := range hs {
		ids[i] = h.eventID
	}
	return ids
}

func groupValue(r *Rule, ev *event.Event) string {
	if r.GroupBy == "" {
		return ""
	}
	v, _ := ev.Get(r.GroupBy)
	return v
}

func newAlert(r *Rule, group string, count int, first, last time.Time, ids []int64) *event.Alert {
	return &event.Alert{
		RuleID:      r.ID,
		RuleName:    r.Name,
		Severity:    r.Severity,
		GroupKey:    group,
		Count:       count,
		Description: describe(r, group, count),
		FirstSeen:   first,
		LastSeen:    last,
		EventIDs:    ids,
		Status:      event.StatusOpen,
	}
}

// describe fills the {group}, {count}, {window} and {threshold} placeholders
// in the rule description.
func describe(r *Rule, group string, count int) string {
	if r.Description == "" {
		if group == "" {
			return r.Name
		}
		return fmt.Sprintf("%s: %s", r.Name, group)
	}
	return strings.NewReplacer(
		"{group}", group,
		"{count}", fmt.Sprint(count),
		"{window}", r.Window.String(),
		"{threshold}", fmt.Sprint(r.Threshold),
	).Replace(r.Description)
}
