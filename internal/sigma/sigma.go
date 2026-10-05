// Package sigma compiles Sigma detection rules (https://sigmahq.io) into
// mini-siem rules.
//
// Supported: single-document rules for the log sources mini-siem parses
// (web server access logs and OpenSSH), field selections with the common
// modifiers (contains, startswith, endswith, all, re, cidr, gt/gte/lt/lte,
// exists, cased), wildcards, null values, keyword searches, and the full
// condition grammar (and, or, not, parentheses, "1 of", "all of", "them").
//
// Not supported: aggregations in the condition ("| count() > 5"),
// correlation rules, multi-document rule collections, encoding modifiers
// (base64, utf16, windash) and regular expressions RE2 cannot compile.
// Such rules are skipped and counted in the load report.
package sigma

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/roywenangr/mini-siem/internal/event"
	"github.com/roywenangr/mini-siem/internal/rules"
)

// Document is a Sigma rule file as written.
type Document struct {
	Title          string    `yaml:"title"`
	ID             string    `yaml:"id"`
	Status         string    `yaml:"status"`
	Description    string    `yaml:"description"`
	Level          string    `yaml:"level"`
	Logsource      Logsource `yaml:"logsource"`
	Detection      yaml.Node `yaml:"detection"`
	Tags           []string  `yaml:"tags"`
	References     []string  `yaml:"references"`
	FalsePositives []string  `yaml:"falsepositives"`
	Correlation    yaml.Node `yaml:"correlation"`
	Action         string    `yaml:"action"`
}

// Logsource says which logs a rule applies to.
type Logsource struct {
	Category string `yaml:"category"`
	Product  string `yaml:"product"`
	Service  string `yaml:"service"`
}

func (l Logsource) String() string {
	var parts []string
	for _, kv := range [][2]string{{"category", l.Category}, {"product", l.Product}, {"service", l.Service}} {
		if kv[1] != "" {
			parts = append(parts, kv[0]+"="+kv[1])
		}
	}
	return strings.Join(parts, " ")
}

// Options control compilation.
type Options struct {
	// DedupWindow suppresses repeat alerts for the same rule and source IP
	// for this long. Zero means 10 minutes.
	DedupWindow time.Duration
	// MinLevel drops rules below this severity (low, medium, high, critical).
	MinLevel string
	// IncludeProxy also applies rules written for proxy logs to web server
	// logs. Their user-agent and URI checks are meaningful for inbound
	// traffic, but they were tuned for outbound browsing, so expect more
	// noise.
	IncludeProxy bool
}

// UnsupportedError marks a rule that is valid Sigma but uses something
// mini-siem cannot evaluate. Reason is short and stable so load reports can
// group by it.
type UnsupportedError struct{ Reason string }

func (e *UnsupportedError) Error() string { return "unsupported: " + e.Reason }

func unsupported(format string, args ...any) error {
	return &UnsupportedError{Reason: fmt.Sprintf(format, args...)}
}

// Parse decodes one Sigma rule file.
func Parse(data []byte) (*Document, error) {
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	var doc Document
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return nil, unsupported("multi-document rule")
	}
	return &doc, nil
}

var levels = map[string]string{
	"informational": event.SeverityLow,
	"low":           event.SeverityLow,
	"medium":        event.SeverityMedium,
	"high":          event.SeverityHigh,
	"critical":      event.SeverityCritical,
}

// Compile turns a Sigma document into a mini-siem rule.
func Compile(doc *Document, opts Options) (*rules.Rule, error) {
	if doc.Correlation.Kind != 0 {
		return nil, unsupported("correlation rule")
	}
	if doc.Action != "" {
		return nil, unsupported("rule collection")
	}
	switch doc.Status {
	case "deprecated", "unsupported":
		return nil, unsupported("status %s", doc.Status)
	}
	if doc.Title == "" {
		return nil, errors.New("missing title")
	}
	sev, ok := levels[strings.ToLower(doc.Level)]
	if !ok {
		return nil, fmt.Errorf("unknown level %q", doc.Level)
	}
	if opts.MinLevel != "" && event.SeverityRank(sev) < event.SeverityRank(opts.MinLevel) {
		return nil, unsupported("below minimum level")
	}

	ls, err := resolveLogsource(doc.Logsource, opts)
	if err != nil {
		return nil, err
	}
	if doc.Detection.Kind != yaml.MappingNode {
		return nil, errors.New("detection must be a mapping")
	}

	var conditions []string
	selections := map[string]node{}
	for i := 0; i+1 < len(doc.Detection.Content); i += 2 {
		key, val := doc.Detection.Content[i].Value, doc.Detection.Content[i+1]
		switch key {
		case "condition":
			switch val.Kind {
			case yaml.ScalarNode:
				conditions = append(conditions, val.Value)
			case yaml.SequenceNode:
				for _, c := range val.Content {
					conditions = append(conditions, c.Value)
				}
			}
		case "timeframe":
			// Only meaningful with aggregations, which are rejected below.
		default:
			sel, err := compileSelection(key, val, ls)
			if err != nil {
				return nil, err
			}
			selections[key] = sel
		}
	}
	if len(conditions) == 0 {
		return nil, errors.New("missing condition")
	}

	var alts []node
	for _, c := range conditions {
		n, err := parseCondition(c, selections)
		if err != nil {
			return nil, err
		}
		alts = append(alts, n)
	}
	cond := alts[0]
	if len(alts) > 1 {
		cond = orNode(alts)
	}

	dedup := opts.DedupWindow
	if dedup <= 0 {
		dedup = 10 * time.Minute
	}
	id := doc.ID
	if id == "" {
		id = slug(doc.Title)
	}
	source := ls.source
	r := &rules.Rule{
		ID:          "sigma-" + id,
		Name:        doc.Title,
		Description: "{group}: {event.message}",
		Severity:    sev,
		Kind:        rules.KindMatch,
		GroupBy:     "src_ip",
		Window:      dedup,
		Tags:        doc.Tags,
		Origin:      "sigma",
		Logic:       strings.Join(conditions, " or ") + "  [" + doc.Logsource.String() + "]",
		References:  httpOnly(doc.References),
		Predicate: func(ev *event.Event) bool {
			return ev.Source == source && cond.match(ev)
		},
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

func httpOnly(refs []string) []string {
	var out []string
	for _, r := range refs {
		if strings.HasPrefix(r, "https://") || strings.HasPrefix(r, "http://") {
			out = append(out, r)
		}
	}
	return out
}

func slug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			if b.Len() > 0 && !strings.HasSuffix(b.String(), "-") {
				b.WriteByte('-')
			}
		}
	}
	return strings.TrimSuffix(b.String(), "-")
}
