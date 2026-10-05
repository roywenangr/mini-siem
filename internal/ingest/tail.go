// Package ingest feeds raw log lines into the pipeline.
package ingest

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/roywenangr/mini-siem/internal/event"
	"github.com/roywenangr/mini-siem/internal/parser"
)

// Submitter is the part of the pipeline inputs need.
type Submitter interface {
	Submit(ctx context.Context, evs ...*event.Event) error
}

// ParseLines parses raw lines. It returns the events, how many lines were
// skipped as noise, and up to maxErrs parse errors (with the total count).
func ParseLines(p parser.Parser, lines []string, now time.Time, maxErrs int) (evs []*event.Event, skipped, failed int, errs []string) {
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		ev, err := p.Parse(line, now)
		switch {
		case errors.Is(err, parser.ErrSkip):
			skipped++
		case err != nil:
			failed++
			if len(errs) < maxErrs {
				errs = append(errs, err.Error())
			}
		default:
			evs = append(evs, ev)
		}
	}
	return evs, skipped, failed, errs
}

// Tailer follows a log file like `tail -F`: it picks up appended lines, and
// reopens the file when it is rotated (replaced) or truncated.
type Tailer struct {
	Path      string
	Parser    parser.Parser
	FromStart bool // read existing content first instead of starting at the end
	Poll      time.Duration
	Out       Submitter
	Log       *slog.Logger
}

// Run tails until ctx is cancelled. A missing file is waited for.
func (t *Tailer) Run(ctx context.Context) {
	if t.Poll <= 0 {
		t.Poll = 500 * time.Millisecond
	}
	log := t.Log
	if log == nil {
		log = slog.Default()
	}
	log = log.With("path", t.Path)

	fromStart := t.FromStart
	for ctx.Err() == nil {
		err := t.follow(ctx, fromStart, log)
		if ctx.Err() != nil {
			return
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Warn("tail error; retrying", "err", err)
		}
		// Any file that appears after the first open is new: read it whole.
		fromStart = true
		sleep(ctx, t.Poll*4)
	}
}

// follow reads one incarnation of the file until it is rotated or truncated.
func (t *Tailer) follow(ctx context.Context, fromStart bool, log *slog.Logger) error {
	f, err := os.Open(t.Path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	var offset int64
	if !fromStart {
		if offset, err = f.Seek(0, io.SeekEnd); err != nil {
			return err
		}
	}
	log.Info("tailing file", "offset", offset)

	r := bufio.NewReaderSize(f, 64*1024)
	var partial strings.Builder
	var lines []string
	for {
		line, err := r.ReadString('\n')
		if len(line) > 0 {
			offset += int64(len(line))
			if strings.HasSuffix(line, "\n") {
				partial.WriteString(line)
				lines = append(lines, partial.String())
				partial.Reset()
			} else {
				// Writer is mid-line; keep the fragment until the rest arrives.
				partial.WriteString(line)
			}
		}
		if err == nil && len(lines) < 1000 {
			continue
		}
		if len(lines) > 0 {
			t.emit(ctx, lines, log)
			lines = lines[:0]
		}
		if err == nil {
			continue
		}
		if !errors.Is(err, io.EOF) {
			return err
		}

		// At EOF: wait, then check for rotation or truncation.
		if !sleep(ctx, t.Poll) {
			return nil
		}
		cur, statErr := os.Stat(t.Path)
		if statErr != nil || !os.SameFile(info, cur) {
			// Rotated: finish whatever the old file still has, then reopen.
			t.drain(ctx, r, &partial, log)
			log.Info("file rotated; reopening")
			return nil
		}
		if cur.Size() < offset {
			log.Info("file truncated; reopening")
			return nil
		}
	}
}

func (t *Tailer) drain(ctx context.Context, r *bufio.Reader, partial *strings.Builder, log *slog.Logger) {
	rest, _ := io.ReadAll(r)
	text := partial.String() + string(rest)
	if text == "" {
		return
	}
	t.emit(ctx, strings.Split(strings.TrimRight(text, "\n"), "\n"), log)
}

func (t *Tailer) emit(ctx context.Context, lines []string, log *slog.Logger) {
	evs, _, failed, errs := ParseLines(t.Parser, lines, time.Now(), 1)
	if failed > 0 {
		log.Debug("unparsed lines", "count", failed, "example", errs[0])
	}
	if err := t.Out.Submit(ctx, evs...); err != nil && ctx.Err() == nil {
		log.Error("submit failed", "err", err)
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}
