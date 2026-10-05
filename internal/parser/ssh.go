package parser

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/roywenangr/mini-siem/internal/event"
)

// SSH parses OpenSSH lines from auth.log / secure, in either classic syslog
// format ("Oct  5 11:46:38 host sshd[123]: ...") or the RFC 3339 format newer
// rsyslog and journald exports use.
type SSH struct{}

var (
	sshClassic = regexp.MustCompile(`^([A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (\S+) sshd(?:-session)?\[\d+\]: (.*)$`)
	sshRFC3339 = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\S+) (\S+) sshd(?:-session)?\[\d+\]: (.*)$`)

	sshFailed   = regexp.MustCompile(`^Failed (\S+) for (invalid user )?(\S*) from (\S+) port (\d+)`)
	sshAccepted = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port (\d+)`)
	sshInvalid  = regexp.MustCompile(`^Invalid user (\S*) from (\S+)(?: port (\d+))?`)
)

func (SSH) Parse(line string, now time.Time) (*event.Event, error) {
	line = strings.TrimRight(line, "\r\n")

	var ts time.Time
	var host, msg string
	if m := sshClassic.FindStringSubmatch(line); m != nil {
		t, err := parseSyslogTime(m[1], now)
		if err != nil {
			return nil, err
		}
		ts, host, msg = t, m[2], m[3]
	} else if m := sshRFC3339.FindStringSubmatch(line); m != nil {
		t, err := time.Parse(time.RFC3339Nano, m[1])
		if err != nil {
			return nil, fmt.Errorf("ssh: bad timestamp %q: %w", m[1], err)
		}
		ts, host, msg = t, m[2], m[3]
	} else {
		return nil, fmt.Errorf("ssh: not an sshd line")
	}

	ev := &event.Event{
		Timestamp: ts,
		Source:    "ssh",
		Host:      host,
		Message:   msg,
		Fields:    map[string]string{},
	}

	switch {
	case sshFailed.MatchString(msg):
		m := sshFailed.FindStringSubmatch(msg)
		ev.Type = event.TypeAuthFailure
		ev.User, ev.SrcIP = m[3], m[4]
		ev.Fields["method"] = m[1]
		ev.Fields["port"] = m[5]
		if m[2] != "" {
			ev.Fields["invalid_user"] = "true"
		}
	case sshAccepted.MatchString(msg):
		m := sshAccepted.FindStringSubmatch(msg)
		ev.Type = event.TypeAuthSuccess
		ev.User, ev.SrcIP = m[2], m[3]
		ev.Fields["method"] = m[1]
		ev.Fields["port"] = m[4]
	case sshInvalid.MatchString(msg):
		m := sshInvalid.FindStringSubmatch(msg)
		ev.Type = event.TypeInvalidUser
		ev.User, ev.SrcIP = m[1], m[2]
		if m[3] != "" {
			ev.Fields["port"] = m[3]
		}
	default:
		return nil, ErrSkip
	}
	return ev, nil
}

// parseSyslogTime parses "Oct  5 11:46:38", which carries no year or zone.
// It assumes now's year and location, and steps back a year when that would
// put the timestamp more than a day in the future (a December log read in
// January).
func parseSyslogTime(s string, now time.Time) (time.Time, error) {
	t, err := time.ParseInLocation("Jan _2 15:04:05", s, now.Location())
	if err != nil {
		return time.Time{}, fmt.Errorf("ssh: bad syslog timestamp %q: %w", s, err)
	}
	t = t.AddDate(now.Year(), 0, 0)
	if t.Sub(now) > 24*time.Hour {
		t = t.AddDate(-1, 0, 0)
	}
	return t, nil
}
