package parser

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/roywenangr/mini-siem/internal/event"
)

// Nginx parses the "combined" access log format (also Apache's default):
//
//	1.2.3.4 - user [05/Oct/2026:11:46:38 +0000] "GET /path HTTP/1.1" 404 153 "referer" "agent"
type Nginx struct{}

var nginxCombined = regexp.MustCompile(`^(\S+) \S+ (\S+) \[([^\]]+)\] "([^"]*)" (\d{3}) (\d+|-)(?: "([^"]*)" "([^"]*)")?`)

func (Nginx) Parse(line string, _ time.Time) (*event.Event, error) {
	line = strings.TrimRight(line, "\r\n")
	m := nginxCombined.FindStringSubmatch(line)
	if m == nil {
		return nil, fmt.Errorf("nginx: not a combined log line")
	}
	ts, err := time.Parse("02/Jan/2006:15:04:05 -0700", m[3])
	if err != nil {
		return nil, fmt.Errorf("nginx: bad timestamp %q: %w", m[3], err)
	}

	ev := &event.Event{
		Timestamp: ts,
		Source:    "nginx",
		Type:      event.TypeHTTPRequest,
		SrcIP:     m[1],
		Message:   m[4],
		Fields: map[string]string{
			"status": m[5],
			"bytes":  m[6],
		},
	}
	if m[2] != "-" {
		ev.User = m[2]
	}
	// The request line is normally "METHOD PATH PROTO", but scanners send
	// garbage here, so keep whatever parts are present.
	if parts := strings.SplitN(m[4], " ", 3); len(parts) >= 2 {
		ev.Fields["method"] = parts[0]
		ev.Fields["path"] = parts[1]
	}
	if m[7] != "" && m[7] != "-" {
		ev.Fields["referer"] = m[7]
	}
	if m[8] != "" && m[8] != "-" {
		ev.Fields["user_agent"] = m[8]
	}
	return ev, nil
}
