// Package api serves the REST API, the live event stream and the dashboard.
package api

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/roywenangr/mini-siem/internal/event"
	"github.com/roywenangr/mini-siem/internal/ingest"
	"github.com/roywenangr/mini-siem/internal/parser"
	"github.com/roywenangr/mini-siem/internal/pipeline"
	"github.com/roywenangr/mini-siem/internal/rules"
	"github.com/roywenangr/mini-siem/internal/store"
)

//go:embed web
var webFS embed.FS

// maxIngestBytes caps one ingest request body.
const maxIngestBytes = 10 << 20

// Server holds the API's dependencies.
type Server struct {
	Store    *store.Store
	Pipeline *pipeline.Pipeline
	Engine   *rules.Engine
	Hub      *pipeline.Hub
	// Token, when set, is required as "Authorization: Bearer <token>" (or
	// ?token= for the event stream, which browsers cannot add headers to)
	// on every /api route.
	Token string
	Log   *slog.Logger
	// Now is the clock; tests override it.
	Now func() time.Time
}

// Handler returns the HTTP handler for the whole app.
func (s *Server) Handler() http.Handler {
	if s.Now == nil {
		s.Now = time.Now
	}
	if s.Log == nil {
		s.Log = slog.Default()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/ingest", s.auth(s.handleIngest))
	mux.HandleFunc("GET /api/events", s.auth(s.handleEvents))
	mux.HandleFunc("GET /api/alerts", s.auth(s.handleAlerts))
	mux.HandleFunc("GET /api/alerts/{id}", s.auth(s.handleAlert))
	mux.HandleFunc("PATCH /api/alerts/{id}", s.auth(s.handleAlertUpdate))
	mux.HandleFunc("GET /api/stats", s.auth(s.handleStats))
	mux.HandleFunc("GET /api/rules", s.auth(s.handleRules))
	mux.HandleFunc("GET /api/stream", s.auth(s.handleStream))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "pipeline": s.Pipeline.Counters()})
	})

	web, _ := fs.Sub(webFS, "web")
	mux.Handle("GET /", http.FileServerFS(web))
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	if s.Token == "" {
		return next
	}
	want := []byte(s.Token)
	return func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if got == "" {
			got = r.URL.Query().Get("token")
		}
		if subtle.ConstantTimeCompare([]byte(got), want) != 1 {
			writeError(w, http.StatusUnauthorized, "missing or invalid token")
			return
		}
		next(w, r)
	}
}

// handleIngest accepts raw log lines in the body (one per line) and parses
// them with ?parser= (default json).
func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("parser")
	if name == "" {
		name = "json"
	}
	p, err := parser.Get(name)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxIngestBytes))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("body larger than %d bytes", maxIngestBytes))
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	lines := strings.Split(string(body), "\n")
	evs, skipped, failed, errs := ingest.ParseLines(p, lines, s.Now(), 5)
	if err := s.Pipeline.Submit(r.Context(), evs...); err != nil {
		writeError(w, http.StatusServiceUnavailable, "pipeline busy: "+err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"accepted": len(evs),
		"skipped":  skipped,
		"failed":   failed,
		"errors":   errs,
	})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.EventFilter{
		Type:   q.Get("type"),
		Source: q.Get("source"),
		SrcIP:  q.Get("src_ip"),
		User:   q.Get("user"),
		Query:  q.Get("q"),
	}
	var err error
	if f.Limit, err = intParam(q.Get("limit")); err != nil {
		writeError(w, http.StatusBadRequest, "limit: "+err.Error())
		return
	}
	if f.BeforeID, err = int64Param(q.Get("before_id")); err != nil {
		writeError(w, http.StatusBadRequest, "before_id: "+err.Error())
		return
	}
	if f.Since, err = timeParam(q.Get("since"), s.Now()); err != nil {
		writeError(w, http.StatusBadRequest, "since: "+err.Error())
		return
	}
	if f.Until, err = timeParam(q.Get("until"), s.Now()); err != nil {
		writeError(w, http.StatusBadRequest, "until: "+err.Error())
		return
	}
	evs, err := s.Store.ListEvents(r.Context(), f)
	if err != nil {
		s.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": evs})
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.AlertFilter{
		Status:   q.Get("status"),
		Severity: q.Get("severity"),
		RuleID:   q.Get("rule_id"),
		GroupKey: q.Get("group"),
	}
	var err error
	if f.Limit, err = intParam(q.Get("limit")); err != nil {
		writeError(w, http.StatusBadRequest, "limit: "+err.Error())
		return
	}
	if f.BeforeID, err = int64Param(q.Get("before_id")); err != nil {
		writeError(w, http.StatusBadRequest, "before_id: "+err.Error())
		return
	}
	alerts, err := s.Store.ListAlerts(r.Context(), f)
	if err != nil {
		s.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"alerts": alerts})
}

// handleAlert returns one alert with the events that triggered it.
func (s *Server) handleAlert(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad alert id")
		return
	}
	a, err := s.Store.GetAlert(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "alert not found")
		return
	}
	if err != nil {
		s.internalError(w, err)
		return
	}
	evs, err := s.Store.GetEvents(r.Context(), a.EventIDs)
	if err != nil {
		s.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"alert": a, "events": evs})
}

func (s *Server) handleAlertUpdate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad alert id")
		return
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if !event.ValidStatus(body.Status) {
		writeError(w, http.StatusBadRequest, "status must be open, acknowledged or closed")
		return
	}
	switch err := s.Store.SetAlertStatus(r.Context(), id, body.Status); {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "alert not found")
		return
	case err != nil:
		s.internalError(w, err)
		return
	}
	a, err := s.Store.GetAlert(r.Context(), id)
	if err != nil {
		s.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"alert": a})
}

// handleStats returns the dashboard summary. ?range= picks the window
// (15m, 1h, 6h, 24h; default 1h).
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	ranges := map[string]time.Duration{
		"15m": 15 * time.Minute, "1h": time.Hour, "6h": 6 * time.Hour, "24h": 24 * time.Hour,
	}
	buckets := map[string]time.Duration{
		"15m": 30 * time.Second, "1h": time.Minute, "6h": 5 * time.Minute, "24h": 15 * time.Minute,
	}
	rng := r.URL.Query().Get("range")
	if rng == "" {
		rng = "1h"
	}
	d, ok := ranges[rng]
	if !ok {
		writeError(w, http.StatusBadRequest, "range must be 15m, 1h, 6h or 24h")
		return
	}
	now := s.Now()
	st, err := s.Store.Stats(r.Context(), now.Add(-d), now, buckets[rng])
	if err != nil {
		s.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"range": rng, "stats": st, "pipeline": s.Pipeline.Counters()})
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"rules": s.Engine.Rules()})
}

// handleStream is a Server-Sent Events feed of new alerts and event counts.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	msgs, unsubscribe := s.Hub.Subscribe()
	defer unsubscribe()
	keepalive := time.NewTicker(20 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case m, ok := <-msgs:
			if !ok {
				return
			}
			data, err := json.Marshal(m)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", m.Kind, data)
			flusher.Flush()
		case <-keepalive.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (s *Server) internalError(w http.ResponseWriter, err error) {
	s.Log.Error("api error", "err", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func intParam(s string) (int, error) {
	if s == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("must be a non-negative integer")
	}
	return n, nil
}

func int64Param(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("must be a non-negative integer")
	}
	return n, nil
}

// timeParam accepts RFC 3339 or a relative duration such as "15m" (meaning
// that long before now).
func timeParam(s string, now time.Time) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if d, err := time.ParseDuration(s); err == nil {
		return now.Add(-d), nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("use RFC 3339 or a duration like 15m")
	}
	return t, nil
}
