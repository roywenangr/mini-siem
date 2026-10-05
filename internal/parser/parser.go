// Package parser turns raw log lines into normalized events.
package parser

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/roywenangr/mini-siem/internal/event"
)

// ErrSkip is returned for lines that are valid but carry nothing worth
// recording (for example sshd session noise).
var ErrSkip = errors.New("line skipped")

// Parser converts one raw line into an Event. now is used to fill in a
// timestamp, or the missing year of a syslog timestamp.
type Parser interface {
	Parse(line string, now time.Time) (*event.Event, error)
}

var registry = map[string]Parser{
	"ssh":   SSH{},
	"nginx": Nginx{},
	"json":  JSON{},
}

// Get returns the parser registered under name.
func Get(name string) (Parser, error) {
	p, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown parser %q (available: %v)", name, Names())
	}
	return p, nil
}

// Names lists the registered parser names in sorted order.
func Names() []string {
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
