// Package intel loads IP threat-intelligence feeds (blocklists of addresses
// and CIDR ranges) and tags events whose source IP is listed.
package intel

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/roywenangr/mini-siem/internal/event"
)

// Field is the event field that receives the names of matching feeds,
// comma separated.
const Field = "ti_lists"

// maxFeedBytes caps a downloaded feed.
const maxFeedBytes = 64 << 20

// Feed is one blocklist source: a URL or a local file with one IP or CIDR
// per line. Text after "#" or ";" is a comment, and only the first token of
// a line is read, which fits the common FireHOL, Spamhaus DROP, abuse.ch and
// plain-list formats.
type Feed struct {
	Name string `yaml:"name" json:"name"`
	URL  string `yaml:"url" json:"url,omitempty"`
	Path string `yaml:"path" json:"path,omitempty"`
}

// FeedStatus reports the last load of a feed.
type FeedStatus struct {
	Feed
	Entries  int       `json:"entries"`
	LoadedAt time.Time `json:"loaded_at,omitempty"`
	Error    string    `json:"error,omitempty"`
}

// set is a fast membership test over many prefixes: one hash map per prefix
// length, so a lookup costs one map probe per distinct length in the feed.
type set struct {
	byLen map[int]map[netip.Addr]struct{}
	lens  []int // descending
	n     int
}

func newSet(prefixes []netip.Prefix) *set {
	s := &set{byLen: map[int]map[netip.Addr]struct{}{}}
	for _, p := range prefixes {
		p = p.Masked()
		bits := p.Bits()
		if p.Addr().Is6() {
			bits += 1000 // keep IPv6 lengths apart from IPv4 ones
		}
		m := s.byLen[bits]
		if m == nil {
			m = map[netip.Addr]struct{}{}
			s.byLen[bits] = m
			s.lens = append(s.lens, bits)
		}
		if _, dup := m[p.Addr()]; !dup {
			m[p.Addr()] = struct{}{}
			s.n++
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(s.lens)))
	return s
}

func (s *set) contains(a netip.Addr) bool {
	v6 := a.Is6()
	for _, l := range s.lens {
		bits := l
		if v6 {
			if l < 1000 {
				continue
			}
			bits -= 1000
		} else if l >= 1000 {
			continue
		}
		p, err := a.Prefix(bits)
		if err != nil {
			continue
		}
		if _, ok := s.byLen[l][p.Addr()]; ok {
			return true
		}
	}
	return false
}

// Intel holds the loaded feeds. It is safe for concurrent use.
type Intel struct {
	feeds  []Feed
	client *http.Client
	log    *slog.Logger

	mu     sync.RWMutex
	sets   map[string]*set
	status map[string]*FeedStatus
}

// New creates an Intel for the given feeds. Call Refresh (or Run) to load
// them.
func New(feeds []Feed, log *slog.Logger) (*Intel, error) {
	seen := map[string]bool{}
	for _, f := range feeds {
		if f.Name == "" || strings.ContainsAny(f.Name, ", ") {
			return nil, fmt.Errorf("intel: feed name %q must be non-empty without commas or spaces", f.Name)
		}
		if (f.URL == "") == (f.Path == "") {
			return nil, fmt.Errorf("intel: feed %s needs exactly one of url or path", f.Name)
		}
		if seen[f.Name] {
			return nil, fmt.Errorf("intel: duplicate feed name %s", f.Name)
		}
		seen[f.Name] = true
	}
	if log == nil {
		log = slog.Default()
	}
	in := &Intel{
		feeds:  feeds,
		client: &http.Client{Timeout: time.Minute},
		log:    log,
		sets:   map[string]*set{},
		status: map[string]*FeedStatus{},
	}
	for _, f := range feeds {
		in.status[f.Name] = &FeedStatus{Feed: f}
	}
	return in, nil
}

// Refresh reloads every feed. A feed that fails keeps its previous
// contents, so a flaky download does not blind detection.
func (in *Intel) Refresh(ctx context.Context) {
	for _, f := range in.feeds {
		prefixes, err := in.fetch(ctx, f)
		in.mu.Lock()
		st := in.status[f.Name]
		if err != nil {
			st.Error = err.Error()
			in.mu.Unlock()
			in.log.Warn("threat intel feed failed; keeping previous data", "feed", f.Name, "err", err)
			continue
		}
		s := newSet(prefixes)
		in.sets[f.Name] = s
		st.Entries, st.LoadedAt, st.Error = s.n, time.Now().UTC(), ""
		in.mu.Unlock()
		in.log.Info("threat intel feed loaded", "feed", f.Name, "entries", s.n)
	}
}

// Run refreshes every interval until ctx ends. Call Refresh first for the
// initial load.
func (in *Intel) Run(ctx context.Context, every time.Duration) {
	if every <= 0 {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			in.Refresh(ctx)
		}
	}
}

func (in *Intel) fetch(ctx context.Context, f Feed) ([]netip.Prefix, error) {
	if f.Path != "" {
		file, err := os.Open(f.Path)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		return parseList(io.LimitReader(file, maxFeedBytes))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "mini-siem")
	resp, err := in.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download: %s", resp.Status)
	}
	return parseList(io.LimitReader(resp.Body, maxFeedBytes))
}

// parseList reads one IP or CIDR per line. Unparseable lines are ignored,
// but a feed with content and no valid entry at all is treated as an error
// (it is probably an HTML error page).
func parseList(r io.Reader) ([]netip.Prefix, error) {
	var out []netip.Prefix
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	nonEmpty := 0
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		nonEmpty++
		tok := fields[0]
		if strings.Contains(tok, "/") {
			if p, err := netip.ParsePrefix(tok); err == nil {
				out = append(out, p)
			}
			continue
		}
		if a, err := netip.ParseAddr(tok); err == nil {
			a = a.Unmap()
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if nonEmpty > 0 && len(out) == 0 {
		return nil, fmt.Errorf("no valid IP entries in %d lines", nonEmpty)
	}
	return out, nil
}

// Lookup returns the names of the feeds that list addr, in feed order.
func (in *Intel) Lookup(addr netip.Addr) []string {
	addr = addr.Unmap()
	in.mu.RLock()
	defer in.mu.RUnlock()
	var out []string
	for _, f := range in.feeds {
		if s := in.sets[f.Name]; s != nil && s.contains(addr) {
			out = append(out, f.Name)
		}
	}
	return out
}

// Enrich implements pipeline.Enricher: it sets Field on events whose source
// IP is listed. Private, loopback, link-local and multicast addresses are
// never looked up: many feeds include those ranges as "bogons", which would
// flag every internal client.
func (in *Intel) Enrich(ev *event.Event) {
	if ev.SrcIP == "" {
		return
	}
	a, err := netip.ParseAddr(ev.SrcIP)
	if err != nil {
		return
	}
	a = a.Unmap()
	if a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() {
		return
	}
	if names := in.Lookup(a); len(names) > 0 {
		if ev.Fields == nil {
			ev.Fields = map[string]string{}
		}
		ev.Fields[Field] = strings.Join(names, ",")
	}
}

// Status returns the state of every feed.
func (in *Intel) Status() []FeedStatus {
	in.mu.RLock()
	defer in.mu.RUnlock()
	out := make([]FeedStatus, 0, len(in.feeds))
	for _, f := range in.feeds {
		out = append(out, *in.status[f.Name])
	}
	return out
}
