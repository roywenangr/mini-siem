package parser

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/roywenangr/mini-siem/internal/event"
)

// JSON parses one JSON object per line, for applications that log
// structured events. Recognized keys map onto Event fields; every other
// scalar key lands in Fields.
//
//	{"timestamp":"2026-10-05T11:46:38Z","type":"auth_failure","src_ip":"1.2.3.4","user":"roy","app":"api"}
type JSON struct{}

func (JSON) Parse(line string, now time.Time) (*event.Event, error) {
	var raw map[string]any
	dec := json.NewDecoder(strings.NewReader(line))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("json: %w", err)
	}

	ev := &event.Event{
		Timestamp: now,
		Source:    "json",
		Type:      event.TypeGeneric,
		Fields:    map[string]string{},
	}
	for k, v := range raw {
		s, ok := scalarString(v)
		if !ok {
			continue // nested objects and arrays are not indexed
		}
		switch k {
		case "timestamp", "time", "@timestamp", "ts":
			t, err := parseJSONTime(v)
			if err != nil {
				return nil, err
			}
			ev.Timestamp = t
		case "type", "event_type":
			ev.Type = s
		case "source":
			ev.Source = s
		case "host", "hostname":
			ev.Host = s
		case "src_ip", "ip", "client_ip", "remote_addr":
			ev.SrcIP = s
		case "user", "username":
			ev.User = s
		case "message", "msg":
			ev.Message = s
		default:
			ev.Fields[k] = s
		}
	}
	return ev, nil
}

func scalarString(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case json.Number:
		return x.String(), true
	case bool:
		return strconv.FormatBool(x), true
	case nil:
		return "", true
	}
	return "", false
}

// parseJSONTime accepts RFC 3339 strings or Unix epoch seconds.
func parseJSONTime(v any) (time.Time, error) {
	switch x := v.(type) {
	case string:
		t, err := time.Parse(time.RFC3339Nano, x)
		if err != nil {
			return time.Time{}, fmt.Errorf("json: bad timestamp %q: %w", x, err)
		}
		return t, nil
	case json.Number:
		f, err := x.Float64()
		if err != nil {
			return time.Time{}, fmt.Errorf("json: bad timestamp %q: %w", x, err)
		}
		sec := int64(f)
		return time.Unix(sec, int64((f-float64(sec))*1e9)).UTC(), nil
	}
	return time.Time{}, fmt.Errorf("json: unsupported timestamp %v", v)
}
