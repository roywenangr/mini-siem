package api

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/roywenangr/mini-siem/internal/event"
	"github.com/roywenangr/mini-siem/internal/pipeline"
	"github.com/roywenangr/mini-siem/internal/rules"
	"github.com/roywenangr/mini-siem/internal/store"
)

type harness struct {
	t   *testing.T
	srv *httptest.Server
	tok string
}

func newHarness(t *testing.T, token string) *harness {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	rs, err := rules.LoadFile("../../rules/default.yaml")
	if err != nil {
		t.Fatal(err)
	}
	eng := rules.NewEngine(rs)
	hub := pipeline.NewHub()
	pipe := pipeline.New(st, eng, hub, nil, pipeline.Options{FlushInterval: 10 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { pipe.Run(ctx); close(done) }()

	s := &Server{Store: st, Pipeline: pipe, Engine: eng, Hub: hub, Token: token}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(func() {
		hub.Close()
		srv.Close()
		cancel()
		<-done
		st.Close()
	})
	return &harness{t: t, srv: srv, tok: token}
}

func (h *harness) do(method, path, body string) (int, map[string]any) {
	h.t.Helper()
	req, _ := http.NewRequest(method, h.srv.URL+path, strings.NewReader(body))
	if h.tok != "" {
		req.Header.Set("Authorization", "Bearer "+h.tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// waitAlerts polls until at least n alerts exist.
func (h *harness) waitAlerts(n int) []any {
	h.t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, out := h.do("GET", "/api/alerts?status=", "")
		if alerts, _ := out["alerts"].([]any); len(alerts) >= n {
			return alerts
		}
		time.Sleep(20 * time.Millisecond)
	}
	h.t.Fatalf("timed out waiting for %d alerts", n)
	return nil
}

func sshLines(ip string, n int, now time.Time) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "%s web1 sshd[1]: Failed password for root from %s port %d ssh2\n", now.Format("Jan _2 15:04:05"), ip, 1000+i)
	}
	return b.String()
}

func TestIngestToAlertFlow(t *testing.T) {
	h := newHarness(t, "")
	now := time.Now()

	code, out := h.do("POST", "/api/ingest?parser=ssh", sshLines("203.0.113.5", 6, now)+"garbage line\n"+
		now.Format("Jan _2 15:04:05")+" web1 sshd[1]: Connection closed by 10.0.0.1 port 22\n")
	if code != http.StatusAccepted {
		t.Fatalf("ingest status %d: %v", code, out)
	}
	if out["accepted"].(float64) != 6 || out["failed"].(float64) != 1 || out["skipped"].(float64) != 1 {
		t.Errorf("ingest counts = %v", out)
	}

	alerts := h.waitAlerts(1)
	a := alerts[0].(map[string]any)
	if a["rule_id"] != "ssh-bruteforce" || a["group_key"] != "203.0.113.5" || a["status"] != "open" {
		t.Fatalf("unexpected alert %v", a)
	}
	id := int(a["id"].(float64))

	// Detail includes the triggering events.
	code, out = h.do("GET", fmt.Sprintf("/api/alerts/%d", id), "")
	if code != 200 || len(out["events"].([]any)) != 5 {
		t.Fatalf("detail: %d %v", code, out)
	}

	// Status changes.
	code, out = h.do("PATCH", fmt.Sprintf("/api/alerts/%d", id), `{"status":"acknowledged"}`)
	if code != 200 || out["alert"].(map[string]any)["status"] != "acknowledged" {
		t.Fatalf("patch: %d %v", code, out)
	}
	if code, _ := h.do("PATCH", fmt.Sprintf("/api/alerts/%d", id), `{"status":"bogus"}`); code != 400 {
		t.Errorf("bad status accepted: %d", code)
	}
	if code, _ := h.do("PATCH", "/api/alerts/999999", `{"status":"closed"}`); code != 404 {
		t.Errorf("missing alert: %d", code)
	}
	_, out = h.do("GET", "/api/alerts?status=open", "")
	if n := len(out["alerts"].([]any)); n != 0 {
		t.Errorf("open alerts after ack = %d", n)
	}

	// Events are queryable and filterable.
	_, out = h.do("GET", "/api/events?src_ip=203.0.113.5&type=auth_failure", "")
	if n := len(out["events"].([]any)); n != 6 {
		t.Errorf("filtered events = %d, want 6", n)
	}
	_, out = h.do("GET", "/api/events?q=port%201003", "")
	if n := len(out["events"].([]any)); n != 1 {
		t.Errorf("search events = %d, want 1", n)
	}

	// Stats reflect it.
	code, out = h.do("GET", "/api/stats?range=15m", "")
	if code != 200 {
		t.Fatalf("stats: %d %v", code, out)
	}
	stats := out["stats"].(map[string]any)
	if stats["window_events"].(float64) != 6 {
		t.Errorf("window_events = %v", stats["window_events"])
	}
	var tlEvents float64
	for _, b := range stats["timeline"].([]any) {
		tlEvents += b.(map[string]any)["events"].(float64)
	}
	if tlEvents != 6 {
		t.Errorf("timeline events sum = %v, want 6", tlEvents)
	}
	if code, _ := h.do("GET", "/api/stats?range=7y", ""); code != 400 {
		t.Errorf("bad range accepted: %d", code)
	}

	_, out = h.do("GET", "/api/rules", "")
	if n := len(out["rules"].([]any)); n < 5 {
		t.Errorf("rules = %d", n)
	}
	r0 := out["rules"].([]any)[0].(map[string]any)
	if r0["window"] != "1m0s" {
		t.Errorf("rule window rendered as %v", r0["window"])
	}
}

func TestBadRequests(t *testing.T) {
	h := newHarness(t, "")
	if code, _ := h.do("POST", "/api/ingest?parser=nope", "x"); code != 400 {
		t.Errorf("unknown parser: %d", code)
	}
	if code, _ := h.do("GET", "/api/events?limit=-1", ""); code != 400 {
		t.Errorf("negative limit: %d", code)
	}
	if code, _ := h.do("GET", "/api/events?since=yesterday", ""); code != 400 {
		t.Errorf("bad since: %d", code)
	}
	if code, _ := h.do("GET", "/api/alerts/abc", ""); code != 400 {
		t.Errorf("bad id: %d", code)
	}
}

func TestAuth(t *testing.T) {
	h := newHarness(t, "s3cret")
	if code, _ := h.do("GET", "/api/alerts", ""); code != 200 {
		t.Errorf("with token: %d", code)
	}
	h.tok = "wrong"
	if code, _ := h.do("GET", "/api/alerts", ""); code != 401 {
		t.Errorf("wrong token: %d", code)
	}
	h.tok = ""
	if code, _ := h.do("POST", "/api/ingest", "{}"); code != 401 {
		t.Errorf("no token on ingest: %d", code)
	}
	if code, _ := h.do("GET", "/api/alerts?token=s3cret", ""); code != 200 {
		t.Errorf("query token: %d", code)
	}
	// The dashboard shell itself is public; it prompts for the token.
	resp, err := http.Get(h.srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "Mini SIEM") {
		t.Errorf("dashboard: %d", resp.StatusCode)
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") {
		t.Errorf("missing CSP: %q", csp)
	}
}

func TestStreamDeliversAlerts(t *testing.T) {
	h := newHarness(t, "")
	resp, err := http.Get(h.srv.URL + "/api/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content type %q", ct)
	}
	got := make(chan event.Alert, 1)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		kind := ""
		for sc.Scan() {
			line := sc.Text()
			if strings.HasPrefix(line, "event: ") {
				kind = strings.TrimPrefix(line, "event: ")
			}
			if strings.HasPrefix(line, "data: ") && kind == "alert" {
				var m pipeline.Message
				if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &m) == nil && m.Alert != nil {
					got <- *m.Alert
					return
				}
			}
		}
	}()
	// Give the subscription a moment to register before ingesting.
	time.Sleep(50 * time.Millisecond)
	h.do("POST", "/api/ingest?parser=ssh", sshLines("198.51.100.9", 5, time.Now()))
	select {
	case a := <-got:
		if a.GroupKey != "198.51.100.9" {
			t.Errorf("streamed alert for %q", a.GroupKey)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no alert on stream")
	}
}
