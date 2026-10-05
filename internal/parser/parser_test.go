package parser

import (
	"errors"
	"testing"
	"time"

	"github.com/roywenangr/mini-siem/internal/event"
)

var now = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

func TestSSH(t *testing.T) {
	tests := []struct {
		name, line         string
		typ, user, ip      string
		wantInvalidUserTag bool
	}{
		{
			name: "failed password",
			line: "Oct  5 11:46:38 web1 sshd[1234]: Failed password for root from 203.0.113.7 port 52211 ssh2",
			typ:  event.TypeAuthFailure, user: "root", ip: "203.0.113.7",
		},
		{
			name: "failed password invalid user",
			line: "Oct  5 11:46:39 web1 sshd[1234]: Failed password for invalid user admin from 203.0.113.7 port 52212 ssh2",
			typ:  event.TypeAuthFailure, user: "admin", ip: "203.0.113.7", wantInvalidUserTag: true,
		},
		{
			name: "accepted publickey rfc3339",
			line: "2026-10-05T11:47:00.123456+00:00 web1 sshd[99]: Accepted publickey for roy from 198.51.100.4 port 40000 ssh2: ED25519 SHA256:abc",
			typ:  event.TypeAuthSuccess, user: "roy", ip: "198.51.100.4",
		},
		{
			name: "invalid user",
			line: "Oct  5 11:46:37 web1 sshd[1234]: Invalid user oracle from 203.0.113.7 port 52210",
			typ:  event.TypeInvalidUser, user: "oracle", ip: "203.0.113.7",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev, err := SSH{}.Parse(tt.line, now)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if ev.Type != tt.typ || ev.User != tt.user || ev.SrcIP != tt.ip {
				t.Errorf("got type=%q user=%q ip=%q, want %q %q %q", ev.Type, ev.User, ev.SrcIP, tt.typ, tt.user, tt.ip)
			}
			if ev.Host != "web1" {
				t.Errorf("host = %q, want web1", ev.Host)
			}
			if got := ev.Fields["invalid_user"] == "true"; got != tt.wantInvalidUserTag {
				t.Errorf("invalid_user tag = %v, want %v", got, tt.wantInvalidUserTag)
			}
		})
	}
}

func TestSSHSyslogYear(t *testing.T) {
	jan := time.Date(2027, 1, 1, 0, 5, 0, 0, time.UTC)
	ev, err := SSH{}.Parse("Dec 31 23:59:59 h sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2", jan)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Timestamp.Year() != 2026 {
		t.Errorf("year = %d, want 2026 (December line read in January)", ev.Timestamp.Year())
	}
}

func TestSSHSkipsNoise(t *testing.T) {
	_, err := SSH{}.Parse("Oct  5 11:46:38 web1 sshd[1234]: pam_unix(sshd:session): session closed for user roy", now)
	if !errors.Is(err, ErrSkip) {
		t.Fatalf("err = %v, want ErrSkip", err)
	}
	if _, err := (SSH{}).Parse("Oct  5 11:46:38 web1 cron[1]: hello", now); err == nil || errors.Is(err, ErrSkip) {
		t.Fatalf("non-sshd line should be a parse error, got %v", err)
	}
}

func TestNginx(t *testing.T) {
	line := `203.0.113.9 - - [05/Oct/2026:11:46:38 +0700] "GET /.env HTTP/1.1" 404 153 "-" "curl/8.0"`
	ev, err := Nginx{}.Parse(line, now)
	if err != nil {
		t.Fatal(err)
	}
	if ev.SrcIP != "203.0.113.9" || ev.Fields["path"] != "/.env" || ev.Fields["status"] != "404" || ev.Fields["method"] != "GET" {
		t.Errorf("unexpected event: %+v", ev)
	}
	if ev.Fields["uri_stem"] != "/.env" || ev.Fields["uri_query"] != "" {
		t.Errorf("uri split: %v", ev.Fields)
	}
	if ev.Fields["user_agent"] != "curl/8.0" {
		t.Errorf("user_agent = %q", ev.Fields["user_agent"])
	}
	if want := time.Date(2026, 10, 5, 4, 46, 38, 0, time.UTC); !ev.Timestamp.Equal(want) {
		t.Errorf("timestamp = %v, want %v", ev.Timestamp, want)
	}

	ev, err = Nginx{}.Parse(`1.2.3.4 - - [05/Oct/2026:11:46:38 +0000] "GET /app/login.php?next=/a.b HTTP/1.1" 200 1 "-" "-"`, now)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Fields["uri_stem"] != "/app/login.php" || ev.Fields["uri_query"] != "next=/a.b" || ev.Fields["uri_extension"] != "php" {
		t.Errorf("uri split: %v", ev.Fields)
	}

	// Scanners send malformed request lines; they must still parse.
	ev, err = Nginx{}.Parse(`203.0.113.9 - - [05/Oct/2026:11:46:38 +0000] "\x16\x03\x01" 400 157 "-" "-"`, now)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Fields["status"] != "400" || ev.Fields["path"] != "" {
		t.Errorf("unexpected event for garbage request: %+v", ev)
	}
}

func TestJSON(t *testing.T) {
	ev, err := JSON{}.Parse(`{"timestamp":"2026-10-05T11:00:00Z","type":"auth_failure","ip":"1.2.3.4","user":"roy","app":"api","attempt":3,"nested":{"a":1}}`, now)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Type != "auth_failure" || ev.SrcIP != "1.2.3.4" || ev.User != "roy" {
		t.Errorf("unexpected event: %+v", ev)
	}
	if ev.Fields["app"] != "api" || ev.Fields["attempt"] != "3" {
		t.Errorf("fields = %v", ev.Fields)
	}
	if _, ok := ev.Fields["nested"]; ok {
		t.Error("nested objects should not be indexed")
	}

	ev, err = JSON{}.Parse(`{"ts":1791201600,"msg":"hi"}`, now)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Timestamp.Unix() != 1791201600 || ev.Message != "hi" || ev.Type != event.TypeGeneric {
		t.Errorf("unexpected event: %+v", ev)
	}

	if _, err := (JSON{}).Parse(`not json`, now); err == nil {
		t.Error("expected error for invalid JSON")
	}
}
