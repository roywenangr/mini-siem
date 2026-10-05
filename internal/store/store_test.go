package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/roywenangr/mini-siem/internal/event"
)

func TestEventsAndAlertsRoundTrip(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "siem.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	t0 := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	evs := []*event.Event{
		{Timestamp: t0, Source: "ssh", Type: "auth_failure", SrcIP: "1.1.1.1", User: "root", Message: "Failed password 100%_done"},
		{Timestamp: t0.Add(time.Minute), Source: "nginx", Type: "http_request", SrcIP: "2.2.2.2", Message: "GET / HTTP/1.1", Fields: map[string]string{"status": "200"}},
		{Timestamp: t0.Add(2 * time.Minute), Source: "ssh", Type: "auth_success", SrcIP: "1.1.1.1", User: "roy", Message: "Accepted"},
	}
	if err := s.InsertEvents(ctx, evs); err != nil {
		t.Fatal(err)
	}
	if evs[0].ID == 0 || evs[2].ID <= evs[0].ID {
		t.Fatalf("ids not assigned: %d %d", evs[0].ID, evs[2].ID)
	}

	got, err := s.ListEvents(ctx, EventFilter{SrcIP: "1.1.1.1"})
	if err != nil || len(got) != 2 || got[0].User != "roy" {
		t.Fatalf("list by ip: %v %+v", err, got)
	}
	// LIKE wildcards in the query are literal.
	if got, _ := s.ListEvents(ctx, EventFilter{Query: "100%_"}); len(got) != 1 {
		t.Errorf("escaped search = %d results", len(got))
	}
	if got, _ := s.ListEvents(ctx, EventFilter{Query: "%"}); len(got) != 1 {
		t.Errorf("literal %% search = %d results", len(got))
	}
	if got, _ := s.ListEvents(ctx, EventFilter{BeforeID: evs[2].ID, Limit: 1}); len(got) != 1 || got[0].ID != evs[1].ID {
		t.Errorf("paging: %+v", got)
	}
	if got, _ := s.GetEvents(ctx, []int64{evs[1].ID}); len(got) != 1 || got[0].Fields["status"] != "200" || !got[0].Timestamp.Equal(evs[1].Timestamp) {
		t.Errorf("get events: %+v", got)
	}

	a := &event.Alert{RuleID: "r", RuleName: "R", Severity: "high", GroupKey: "1.1.1.1", Count: 2,
		Description: "d", FirstSeen: t0, LastSeen: t0.Add(2 * time.Minute), EventIDs: []int64{evs[0].ID, evs[2].ID}}
	if err := s.InsertAlert(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAlertStatus(ctx, a.ID, event.StatusClosed); err != nil {
		t.Fatal(err)
	}
	back, err := s.GetAlert(ctx, a.ID)
	if err != nil || back.Status != "closed" || len(back.EventIDs) != 2 {
		t.Fatalf("get alert: %v %+v", err, back)
	}
	if _, err := s.GetAlert(ctx, 999); err != ErrNotFound {
		t.Errorf("missing alert err = %v", err)
	}

	st, err := s.Stats(ctx, t0.Add(-time.Minute), t0.Add(5*time.Minute), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if st.WindowEvents != 3 || st.EventsByType["auth_failure"] != 1 || st.AlertsByStatus["closed"] != 1 {
		t.Errorf("stats: %+v", st)
	}
	if len(st.TopSources) == 0 || st.TopSources[0].Key != "1.1.1.1" || st.TopSources[0].Count != 2 {
		t.Errorf("top sources: %+v", st.TopSources)
	}
	if len(st.Timeline) != 7 || st.Timeline[1].Events != 1 || st.Timeline[3].Events != 1 || st.Timeline[3].Alerts != 1 {
		t.Errorf("timeline: %+v", st.Timeline)
	}

	n, err := s.DeleteEventsBefore(ctx, t0.Add(90*time.Second))
	if err != nil || n != 2 {
		t.Fatalf("retention deleted %d, %v", n, err)
	}
}
