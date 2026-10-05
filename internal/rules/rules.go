// Package rules loads detection rules and evaluates them against the event
// stream.
package rules

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/roywenangr/mini-siem/internal/event"
)

// Rule kinds.
const (
	// KindMatch fires on any single event matching Where.
	KindMatch = "match"
	// KindThreshold fires when at least Threshold events matching Where (or
	// Threshold distinct values of Distinct) share a GroupBy value within
	// Window.
	KindThreshold = "threshold"
	// KindSequence fires when an event matching Then arrives after at least
	// Threshold events matching Where for the same GroupBy value within
	// Window, e.g. a successful login after a run of failures.
	KindSequence = "sequence"
)

// Rule is one detection rule as written in the rules file.
type Rule struct {
	ID          string        `yaml:"id" json:"id"`
	Name        string        `yaml:"name" json:"name"`
	Description string        `yaml:"description" json:"description"`
	Severity    string        `yaml:"severity" json:"severity"`
	Kind        string        `yaml:"type" json:"type"`
	Disabled    bool          `yaml:"disabled" json:"disabled"`
	Where       Condition     `yaml:"where" json:"where"`
	Then        Condition     `yaml:"then" json:"then,omitempty"`
	GroupBy     string        `yaml:"group_by" json:"group_by,omitempty"`
	Distinct    string        `yaml:"distinct" json:"distinct,omitempty"`
	Threshold   int           `yaml:"threshold" json:"threshold,omitempty"`
	Window      time.Duration `yaml:"window" json:"-"`
	Tags        []string      `yaml:"tags" json:"tags,omitempty"`
}

// MarshalJSON renders Window as a duration string ("1m0s") rather than
// nanoseconds.
func (r *Rule) MarshalJSON() ([]byte, error) {
	type plain Rule
	out := struct {
		*plain
		Window string `json:"window,omitempty"`
	}{plain: (*plain)(r)}
	if r.Window > 0 {
		out.Window = r.Window.String()
	}
	return json.Marshal(out)
}

// File is the top-level shape of a rules YAML file.
type File struct {
	Rules []*Rule `yaml:"rules"`
}

// LoadFile reads and validates a rules file.
func LoadFile(path string) ([]*Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse decodes and validates rules from YAML.
func Parse(data []byte) ([]*Rule, error) {
	var f File
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("rules: %w", err)
	}
	seen := map[string]bool{}
	for i, r := range f.Rules {
		if err := r.validate(); err != nil {
			return nil, fmt.Errorf("rules[%d] %q: %w", i, r.ID, err)
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("rules[%d]: duplicate id %q", i, r.ID)
		}
		seen[r.ID] = true
	}
	return f.Rules, nil
}

func (r *Rule) validate() error {
	if r.ID == "" {
		return fmt.Errorf("id is required")
	}
	if r.Name == "" {
		r.Name = r.ID
	}
	if event.SeverityRank(r.Severity) == 0 {
		return fmt.Errorf("severity must be low, medium, high or critical, got %q", r.Severity)
	}
	if err := r.Where.compile(); err != nil {
		return fmt.Errorf("where: %w", err)
	}
	if err := r.Then.compile(); err != nil {
		return fmt.Errorf("then: %w", err)
	}

	switch r.Kind {
	case KindMatch:
		if r.Window < 0 {
			return fmt.Errorf("window must not be negative")
		}
	case KindThreshold, KindSequence:
		if r.GroupBy == "" {
			return fmt.Errorf("group_by is required for %s rules", r.Kind)
		}
		if r.Threshold < 1 {
			return fmt.Errorf("threshold must be at least 1")
		}
		if r.Window <= 0 {
			return fmt.Errorf("window must be positive for %s rules", r.Kind)
		}
		if r.Kind == KindSequence && len(r.Then) == 0 {
			return fmt.Errorf("sequence rules need a then condition")
		}
	default:
		return fmt.Errorf("type must be match, threshold or sequence, got %q", r.Kind)
	}
	if r.Kind != KindSequence && len(r.Then) > 0 {
		return fmt.Errorf("then is only valid for sequence rules")
	}
	if r.Distinct != "" && r.Kind != KindThreshold {
		return fmt.Errorf("distinct is only valid for threshold rules")
	}
	return nil
}
