package ingest

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/roywenangr/mini-siem/internal/event"
	"github.com/roywenangr/mini-siem/internal/parser"
)

type collector struct {
	mu  sync.Mutex
	evs []*event.Event
}

func (c *collector) Submit(_ context.Context, evs ...*event.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evs = append(c.evs, evs...)
	return nil
}

func (c *collector) users() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, e := range c.evs {
		out = append(out, e.User)
	}
	return out
}

func (c *collector) waitFor(t *testing.T, n int) []string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if u := c.users(); len(u) >= n {
			return u
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out: have %v, want %d events", c.users(), n)
	return nil
}

func line(user string) string {
	return `{"type":"auth_failure","user":"` + user + `"}` + "\n"
}

func appendTo(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
	f.Close()
}

func TestTailerFollowsAppendsAndRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	appendTo(t, path, line("old"))

	c := &collector{}
	tl := &Tailer{Path: path, Parser: parser.JSON{}, Poll: 10 * time.Millisecond, Out: c}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { tl.Run(ctx); close(done) }()

	// Existing content is skipped when not reading from the start.
	time.Sleep(50 * time.Millisecond)
	appendTo(t, path, line("a"))
	// A line written in two parts is delivered once, whole.
	appendTo(t, path, `{"type":"auth_failure",`)
	time.Sleep(40 * time.Millisecond)
	appendTo(t, path, `"user":"b"}`+"\n")
	c.waitFor(t, 2)

	// Rotate: move the file away and start a new one.
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	appendTo(t, path, line("c"))
	got := c.waitFor(t, 3)

	// Truncate in place (copytruncate-style rotation).
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	appendTo(t, path, line("d"))
	got = c.waitFor(t, 4)

	cancel()
	<-done
	want := []string{"a", "b", "c", "d"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestTailerFromStartAndMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "later.log")
	c := &collector{}
	tl := &Tailer{Path: path, Parser: parser.JSON{}, FromStart: true, Poll: 10 * time.Millisecond, Out: c}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tl.Run(ctx)

	time.Sleep(30 * time.Millisecond)
	appendTo(t, path, line("x")+line("y"))
	got := c.waitFor(t, 2)
	if got[0] != "x" || got[1] != "y" {
		t.Fatalf("got %v", got)
	}
}
