package intel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/roywenangr/mini-siem/internal/event"
)

const firehol = `#
# firehol_level1 style
#
0.0.0.0/8
10.0.0.0/8
203.0.113.0/25
2001:db8:bad::/48
`

const spamhaus = `; Spamhaus DROP style
198.51.100.0/24 ; SBL123
`

func TestLookupAndEnrich(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(spamhaus))
	}))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "local.txt")
	os.WriteFile(path, []byte(firehol+"192.0.2.66\n::ffff:192.0.2.77\ngarbage line\n"), 0o644)

	in, err := New([]Feed{{Name: "local", Path: path}, {Name: "drop", URL: srv.URL}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	in.Refresh(context.Background())

	cases := map[string]string{
		"203.0.113.5":         "local",
		"203.0.113.200":       "",
		"198.51.100.1":        "drop",
		"192.0.2.66":          "local",
		"192.0.2.77":          "local", // listed as IPv4-mapped IPv6
		"192.0.2.67":          "",
		"2001:db8:bad:1::1":   "local",
		"2001:db8:900d::1":    "",
		"::ffff:203.0.113.10": "local",
		"10.1.2.3":            "", // private: never looked up
		"not-an-ip":           "",
	}
	for ip, want := range cases {
		ev := &event.Event{SrcIP: ip}
		in.Enrich(ev)
		if got := ev.Fields[Field]; got != want {
			t.Errorf("%s: got %q, want %q", ip, got, want)
		}
	}

	both := netip.MustParseAddr("198.51.100.9")
	os.WriteFile(path, []byte("198.51.100.0/26\n"), 0o644)
	in.Refresh(context.Background())
	if got := in.Lookup(both); strings.Join(got, ",") != "local,drop" {
		t.Errorf("lookup = %v", got)
	}

	st := in.Status()
	if len(st) != 2 || st[0].Entries != 1 || st[1].Entries != 1 || st[0].LoadedAt.IsZero() {
		t.Errorf("status %+v", st)
	}
}

func TestFailedRefreshKeepsData(t *testing.T) {
	fail := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			w.Write([]byte("<html>rate limited</html>"))
			return
		}
		w.Write([]byte("203.0.113.1\n"))
	}))
	defer srv.Close()
	in, _ := New([]Feed{{Name: "f", URL: srv.URL}}, nil)
	in.Refresh(context.Background())
	fail = true
	in.Refresh(context.Background())
	if len(in.Lookup(netip.MustParseAddr("203.0.113.1"))) != 1 {
		t.Error("data lost after a failed refresh")
	}
	if st := in.Status()[0]; st.Error == "" || st.Entries != 1 {
		t.Errorf("status %+v", st)
	}
}

func TestNewValidates(t *testing.T) {
	bad := [][]Feed{
		{{Name: "", Path: "x"}},
		{{Name: "a,b", Path: "x"}},
		{{Name: "a"}},
		{{Name: "a", Path: "x", URL: "http://y"}},
		{{Name: "a", Path: "x"}, {Name: "a", Path: "y"}},
	}
	for _, feeds := range bad {
		if _, err := New(feeds, nil); err == nil {
			t.Errorf("expected error for %+v", feeds)
		}
	}
}
