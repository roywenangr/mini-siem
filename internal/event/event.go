// Package event defines the normalized event and alert types shared by every
// part of the SIEM. Parsers produce Events, the rule engine consumes them and
// produces Alerts.
package event

import "time"

// Well-known event types emitted by the built-in parsers.
const (
	TypeAuthFailure = "auth_failure"
	TypeAuthSuccess = "auth_success"
	TypeInvalidUser = "invalid_user"
	TypeHTTPRequest = "http_request"
	TypeGeneric     = "generic"
)

// Event is a single normalized log record.
type Event struct {
	ID        int64             `json:"id"`
	Timestamp time.Time         `json:"timestamp"`
	Source    string            `json:"source"` // parser that produced it: ssh, nginx, json
	Host      string            `json:"host,omitempty"`
	Type      string            `json:"type"`
	SrcIP     string            `json:"src_ip,omitempty"`
	User      string            `json:"user,omitempty"`
	Message   string            `json:"message"`
	Fields    map[string]string `json:"fields,omitempty"`
}

// Get returns the value of a field by name. Top-level names (type, source,
// host, src_ip, user, message) are checked first, then "fields.<name>" or a
// bare name is looked up in Fields. The second return value reports whether
// the field exists.
func (e *Event) Get(name string) (string, bool) {
	switch name {
	case "type":
		return e.Type, true
	case "source":
		return e.Source, true
	case "host":
		return e.Host, e.Host != ""
	case "src_ip":
		return e.SrcIP, e.SrcIP != ""
	case "user":
		return e.User, e.User != ""
	case "message":
		return e.Message, true
	}
	if len(name) > 7 && name[:7] == "fields." {
		name = name[7:]
	}
	v, ok := e.Fields[name]
	return v, ok
}

// Severity levels, ordered from least to most severe.
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// SeverityRank maps a severity to a sortable number; unknown values rank 0.
func SeverityRank(s string) int {
	switch s {
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	}
	return 0
}

// Alert status values.
const (
	StatusOpen         = "open"
	StatusAcknowledged = "acknowledged"
	StatusClosed       = "closed"
)

// ValidStatus reports whether s is a known alert status.
func ValidStatus(s string) bool {
	return s == StatusOpen || s == StatusAcknowledged || s == StatusClosed
}

// Alert is raised by the rule engine when a rule fires.
type Alert struct {
	ID          int64     `json:"id"`
	RuleID      string    `json:"rule_id"`
	RuleName    string    `json:"rule_name"`
	Severity    string    `json:"severity"`
	GroupKey    string    `json:"group_key"` // e.g. the offending src_ip
	Count       int       `json:"count"`
	Description string    `json:"description"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	EventIDs    []int64   `json:"event_ids"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
}
