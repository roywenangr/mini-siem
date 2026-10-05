package rules

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/roywenangr/mini-siem/internal/event"
	"github.com/roywenangr/mini-siem/internal/parser"
)

var t0 = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

func mustParse(t *testing.T, y string) []*Rule {
	t.Helper()
	rs, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return rs
}

type feeder struct {
	t      *testing.T
	eng    *Engine
	nextID int64
}

func (f *feeder) send(ev event.Event) []*event.Alert {
	f.nextID++
	ev.ID = f.nextID
	return f.eng.Process(&ev)
}

func sshFail(ip, user string, at time.Duration) event.Event {
	return event.Event{Timestamp: t0.Add(at), Source: "ssh", Type: event.TypeAuthFailure, SrcIP: ip, User: user}
}

const thresholdRule = `
rules:
  - id: bf
    severity: high
    type: threshold
    where: {source: ssh, type: auth_failure}
    group_by: src_ip
    threshold: 3
    window: 1m
    description: "{count} from {group} in {window}"
`

func TestThresholdFiresAndSuppresses(t *testing.T) {
	f := &feeder{t: t, eng: NewEngine(mustParse(t, thresholdRule))}

	if a := f.send(sshFail("1.1.1.1", "root", 0)); a != nil {
		t.Fatal("fired too early")
	}
	f.send(sshFail("1.1.1.1", "root", 10*time.Second))
	alerts := f.send(sshFail("1.1.1.1", "root", 20*time.Second))
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1", len(alerts))
	}
	a := alerts[0]
	if a.GroupKey != "1.1.1.1" || a.Count != 3 || len(a.EventIDs) != 3 {
		t.Errorf("unexpected alert %+v", a)
	}
	if a.Description != "3 from 1.1.1.1 in 1m0s" {
		t.Errorf("description = %q", a.Description)
	}
	if !a.FirstSeen.Equal(t0) || !a.LastSeen.Equal(t0.Add(20*time.Second)) {
		t.Errorf("first/last = %v/%v", a.FirstSeen, a.LastSeen)
	}

	// Within the suppression window, more failures do not re-alert.
	for i := 0; i < 5; i++ {
		if a := f.send(sshFail("1.1.1.1", "root", 30*time.Second)); a != nil {
			t.Fatal("re-alerted during suppression")
		}
	}
	// Once the window has passed, a fresh burst alerts again.
	f.send(sshFail("1.1.1.1", "root", 90*time.Second))
	f.send(sshFail("1.1.1.1", "root", 91*time.Second))
	if a := f.send(sshFail("1.1.1.1", "root", 92*time.Second)); len(a) != 1 {
		t.Fatal("expected a second alert after suppression ended")
	}
}

func TestThresholdWindowAndGroups(t *testing.T) {
	f := &feeder{t: t, eng: NewEngine(mustParse(t, thresholdRule))}

	// Spread out beyond the window: never three inside one minute.
	for i := 0; i < 6; i++ {
		if a := f.send(sshFail("2.2.2.2", "root", time.Duration(i)*40*time.Second)); a != nil {
			t.Fatalf("fired for events spread across windows at i=%d", i)
		}
	}
	// Different IPs are counted separately.
	f.send(sshFail("3.3.3.3", "root", 0))
	f.send(sshFail("4.4.4.4", "root", 0))
	if a := f.send(sshFail("5.5.5.5", "root", 0)); a != nil {
		t.Fatal("events from different groups were combined")
	}
	// Non-matching events are ignored.
	ok := event.Event{Timestamp: t0, Source: "ssh", Type: event.TypeAuthSuccess, SrcIP: "3.3.3.3"}
	f.send(ok)
	f.send(ok)
	if a := f.send(ok); a != nil {
		t.Fatal("non-matching events counted")
	}
}

func TestThresholdDistinct(t *testing.T) {
	rs := mustParse(t, `
rules:
  - id: spray
    severity: high
    type: threshold
    where: {type: auth_failure}
    group_by: src_ip
    distinct: user
    threshold: 3
    window: 5m
`)
	f := &feeder{t: t, eng: NewEngine(rs)}
	for i := 0; i < 10; i++ {
		if a := f.send(sshFail("6.6.6.6", "root", time.Duration(i)*time.Second)); a != nil {
			t.Fatal("same user repeated should not count as distinct")
		}
	}
	f.send(sshFail("6.6.6.6", "admin", 11*time.Second))
	a := f.send(sshFail("6.6.6.6", "oracle", 12*time.Second))
	if len(a) != 1 || a[0].Count != 3 {
		t.Fatalf("got %+v, want one alert with 3 distinct users", a)
	}
}

func TestSequence(t *testing.T) {
	rs := mustParse(t, `
rules:
  - id: seq
    severity: critical
    type: sequence
    where: {type: auth_failure}
    then: {type: auth_success}
    group_by: src_ip
    threshold: 3
    window: 10m
`)
	f := &feeder{t: t, eng: NewEngine(rs)}
	success := func(ip string, at time.Duration) event.Event {
		return event.Event{Timestamp: t0.Add(at), Type: event.TypeAuthSuccess, SrcIP: ip, User: "roy"}
	}

	// A success with too few failures before it is not suspicious.
	f.send(sshFail("7.7.7.7", "roy", 0))
	f.send(sshFail("7.7.7.7", "roy", time.Second))
	if a := f.send(success("7.7.7.7", 2*time.Second)); a != nil {
		t.Fatal("fired with only two failures")
	}

	f.send(sshFail("8.8.8.8", "roy", 0))
	f.send(sshFail("8.8.8.8", "roy", time.Second))
	f.send(sshFail("8.8.8.8", "roy", 2*time.Second))
	// A success from another IP does not complete this IP's sequence.
	if a := f.send(success("9.9.9.9", 3*time.Second)); a != nil {
		t.Fatal("sequence crossed groups")
	}
	a := f.send(success("8.8.8.8", 4*time.Second))
	if len(a) != 1 || a[0].Count != 3 || len(a[0].EventIDs) != 4 {
		t.Fatalf("got %+v, want one alert with 3 failures + the success", a)
	}

	// Failures that fell out of the window do not count.
	f.send(sshFail("10.0.0.1", "roy", 0))
	f.send(sshFail("10.0.0.1", "roy", time.Second))
	f.send(sshFail("10.0.0.1", "roy", 2*time.Second))
	if a := f.send(success("10.0.0.1", 11*time.Minute)); a != nil {
		t.Fatal("fired on failures outside the window")
	}
}

func TestMatchWithSuppression(t *testing.T) {
	rs := mustParse(t, `
rules:
  - id: env
    severity: medium
    type: match
    where:
      fields.path: {regex: '^/\.env'}
    group_by: src_ip
    window: 10m
`)
	f := &feeder{t: t, eng: NewEngine(rs)}
	req := func(ip, path string, at time.Duration) event.Event {
		return event.Event{Timestamp: t0.Add(at), Type: event.TypeHTTPRequest, SrcIP: ip, Fields: map[string]string{"path": path}}
	}
	if a := f.send(req("1.2.3.4", "/index.html", 0)); a != nil {
		t.Fatal("matched a harmless path")
	}
	if a := f.send(req("1.2.3.4", "/.env", 0)); len(a) != 1 {
		t.Fatal("did not match /.env")
	}
	if a := f.send(req("1.2.3.4", "/.env.bak", time.Minute)); a != nil {
		t.Fatal("not suppressed inside window")
	}
	if a := f.send(req("5.6.7.8", "/.env", time.Minute)); len(a) != 1 {
		t.Fatal("suppression leaked across groups")
	}
	if a := f.send(req("1.2.3.4", "/.env", 11*time.Minute)); len(a) != 1 {
		t.Fatal("did not re-alert after window")
	}
}

func TestMatchers(t *testing.T) {
	rs := mustParse(t, `
rules:
  - id: m
    severity: low
    type: match
    where:
      fields.status: {gte: 500, lte: 599}
      fields.method: {not_in: [HEAD, OPTIONS]}
      fields.agent: {exists: false}
      message: {contains: "/api/", prefix: "GET"}
`)
	f := &feeder{t: t, eng: NewEngine(rs)}
	ev := func(status, method, msg string, extra map[string]string) event.Event {
		fields := map[string]string{"status": status, "method": method}
		for k, v := range extra {
			fields[k] = v
		}
		return event.Event{Timestamp: t0, Message: msg, Fields: fields}
	}
	cases := []struct {
		ev   event.Event
		want bool
	}{
		{ev("502", "GET", "GET /api/x", nil), true},
		{ev("404", "GET", "GET /api/x", nil), false},
		{ev("502", "HEAD", "GET /api/x", nil), false},
		{ev("502", "GET", "GET /web", nil), false},
		{ev("502", "GET", "POST /api/x", nil), false},
		{ev("502", "GET", "GET /api/x", map[string]string{"agent": "x"}), false},
		{ev("abc", "GET", "GET /api/x", nil), false},
	}
	for i, c := range cases {
		if got := len(f.send(c.ev)) == 1; got != c.want {
			t.Errorf("case %d: matched=%v, want %v", i, got, c.want)
		}
	}
}

func TestValidation(t *testing.T) {
	bad := map[string]string{
		"missing id":       `{rules: [{severity: high, type: match}]}`,
		"bad severity":     `{rules: [{id: a, severity: urgent, type: match}]}`,
		"bad type":         `{rules: [{id: a, severity: high, type: magic}]}`,
		"no group_by":      `{rules: [{id: a, severity: high, type: threshold, threshold: 2, window: 1m}]}`,
		"no window":        `{rules: [{id: a, severity: high, type: threshold, group_by: src_ip, threshold: 2}]}`,
		"sequence no then": `{rules: [{id: a, severity: high, type: sequence, group_by: src_ip, threshold: 2, window: 1m}]}`,
		"bad regex":        `{rules: [{id: a, severity: high, type: match, where: {message: {regex: "("}}}]}`,
		"duplicate":        `{rules: [{id: a, severity: high, type: match}, {id: a, severity: low, type: match}]}`,
	}
	for name, y := range bad {
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

func TestSweep(t *testing.T) {
	eng := NewEngine(mustParse(t, thresholdRule))
	f := &feeder{t: t, eng: eng}
	f.send(sshFail("1.1.1.1", "root", 0))
	f.send(sshFail("2.2.2.2", "root", 50*time.Second))
	if eng.StateSize() != 2 {
		t.Fatalf("state size = %d", eng.StateSize())
	}
	if n := eng.Sweep(t0.Add(90 * time.Second)); n != 1 {
		t.Fatalf("swept %d, want 1", n)
	}
	if n := eng.Sweep(t0.Add(10 * time.Minute)); n != 1 || eng.StateSize() != 0 {
		t.Fatalf("swept %d, state %d", n, eng.StateSize())
	}
}

// TestDefaultRules runs realistic log lines through the shipped rules file.
func TestDefaultRules(t *testing.T) {
	rs, err := LoadFile("../../rules/default.yaml")
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine(rs)
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	var id int64
	fired := map[string]int{}
	feed := func(p parser.Parser, line string) {
		ev, err := p.Parse(line, now)
		if err != nil {
			t.Fatalf("parse %q: %v", line, err)
		}
		id++
		ev.ID = id
		for _, a := range eng.Process(ev) {
			fired[a.RuleID]++
		}
	}

	users := []string{"root", "admin", "oracle", "test", "ubuntu"}
	for i, u := range users {
		feed(parser.SSH{}, sshLine(i, "Failed password for invalid user "+u+" from 203.0.113.7 port 4000 ssh2"))
	}
	feed(parser.SSH{}, sshLine(6, "Accepted password for ubuntu from 203.0.113.7 port 4001 ssh2"))
	feed(parser.SSH{}, sshLine(7, "Accepted publickey for root from 198.51.100.1 port 4002 ssh2"))

	for i := 0; i < 25; i++ {
		feed(parser.Nginx{}, webLine("192.0.2.50", i, "GET /admin"+strings.Repeat("x", i)+" HTTP/1.1", 404))
	}
	feed(parser.Nginx{}, webLine("192.0.2.51", 0, "GET /.git/config HTTP/1.1", 404))
	feed(parser.Nginx{}, webLine("192.0.2.52", 0, "GET /item?id=1%20UNION%20SELECT%20password HTTP/1.1", 200))
	for i := 0; i < 12; i++ {
		feed(parser.Nginx{}, webLine("192.0.2.53", i, "POST /wp-login.php HTTP/1.1", 403))
	}
	feed(parser.Nginx{}, webLine("192.0.2.54", 0, "GET / HTTP/1.1", 200))

	want := map[string]int{
		"ssh-bruteforce":               1,
		"ssh-password-spray":           1,
		"ssh-success-after-bruteforce": 1,
		"ssh-root-login":               1,
		"web-scan":                     1,
		"web-sensitive-file":           1,
		"web-injection-attempt":        1,
		"web-auth-bruteforce":          1,
	}
	for rule, n := range want {
		if fired[rule] != n {
			t.Errorf("%s fired %d times, want %d", rule, fired[rule], n)
		}
	}
	for rule := range fired {
		if _, ok := want[rule]; !ok {
			t.Errorf("unexpected rule fired: %s", rule)
		}
	}
}

func sshLine(sec int, msg string) string {
	return t0.Add(time.Duration(sec)*time.Second).Format("Jan _2 15:04:05") + " web1 sshd[100]: " + msg
}

func webLine(ip string, sec int, req string, status int) string {
	ts := t0.Add(time.Duration(sec) * time.Second).Format("02/Jan/2006:15:04:05 -0700")
	return ip + ` - - [` + ts + `] "` + req + `" ` + strconv.Itoa(status) + ` 100 "-" "test"`
}
