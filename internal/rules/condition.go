package rules

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/roywenangr/mini-siem/internal/event"
)

// Condition is a set of field matchers that must all hold (logical AND).
//
//	where:
//	  type: auth_failure            # shorthand for equals
//	  fields.status: {in: ["401", "403"]}
//	  fields.path: {regex: '^/(\.env|\.git)'}
type Condition map[string]*Matcher

// Match reports whether every matcher in c accepts ev. An empty condition
// matches everything.
func (c Condition) Match(ev *event.Event) bool {
	for field, m := range c {
		v, ok := ev.Get(field)
		if !m.match(v, ok) {
			return false
		}
	}
	return true
}

func (c Condition) compile() error {
	for field, m := range c {
		if m == nil {
			return fmt.Errorf("field %q: empty matcher", field)
		}
		if err := m.compile(); err != nil {
			return fmt.Errorf("field %q: %w", field, err)
		}
	}
	return nil
}

// Matcher tests a single field value. Multiple operators in one matcher are
// combined with AND.
type Matcher struct {
	Equals   *string  `yaml:"equals" json:"equals,omitempty"`
	Not      *string  `yaml:"not" json:"not,omitempty"`
	In       []string `yaml:"in" json:"in,omitempty"`
	NotIn    []string `yaml:"not_in" json:"not_in,omitempty"`
	Contains string   `yaml:"contains" json:"contains,omitempty"`
	Prefix   string   `yaml:"prefix" json:"prefix,omitempty"`
	Regex    string   `yaml:"regex" json:"regex,omitempty"`
	GTE      *float64 `yaml:"gte" json:"gte,omitempty"`
	LTE      *float64 `yaml:"lte" json:"lte,omitempty"`
	Exists   *bool    `yaml:"exists" json:"exists,omitempty"`

	re *regexp.Regexp
}

// UnmarshalYAML accepts either a scalar (an equals match) or a mapping of
// operators.
func (m *Matcher) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		v := n.Value
		m.Equals = &v
		return nil
	}
	type plain Matcher
	return n.Decode((*plain)(m))
}

func (m *Matcher) compile() error {
	if m.Regex != "" {
		re, err := regexp.Compile(m.Regex)
		if err != nil {
			return fmt.Errorf("bad regex: %w", err)
		}
		m.re = re
	}
	return nil
}

func (m *Matcher) match(v string, exists bool) bool {
	if m.Exists != nil && *m.Exists != exists {
		return false
	}
	if m.Equals != nil && v != *m.Equals {
		return false
	}
	if m.Not != nil && v == *m.Not {
		return false
	}
	if m.In != nil && !contains(m.In, v) {
		return false
	}
	if m.NotIn != nil && contains(m.NotIn, v) {
		return false
	}
	if m.Contains != "" && !strings.Contains(v, m.Contains) {
		return false
	}
	if m.Prefix != "" && !strings.HasPrefix(v, m.Prefix) {
		return false
	}
	if m.re != nil && !m.re.MatchString(v) {
		return false
	}
	if m.GTE != nil || m.LTE != nil {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return false
		}
		if m.GTE != nil && f < *m.GTE {
			return false
		}
		if m.LTE != nil && f > *m.LTE {
			return false
		}
	}
	return true
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
