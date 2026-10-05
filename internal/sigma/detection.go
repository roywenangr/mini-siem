package sigma

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/roywenangr/mini-siem/internal/event"
)

// node is a compiled piece of detection logic.
type node interface {
	match(ev *event.Event) bool
}

type andNode []node

func (n andNode) match(ev *event.Event) bool {
	for _, c := range n {
		if !c.match(ev) {
			return false
		}
	}
	return true
}

type orNode []node

func (n orNode) match(ev *event.Event) bool {
	for _, c := range n {
		if c.match(ev) {
			return true
		}
	}
	return false
}

type notNode struct{ n node }

func (n notNode) match(ev *event.Event) bool { return !n.n.match(ev) }

// atLeastNode is "N of x*".
type atLeastNode struct {
	n     int
	nodes []node
}

func (a atLeastNode) match(ev *event.Event) bool {
	hits := 0
	for _, c := range a.nodes {
		if c.match(ev) {
			hits++
			if hits >= a.n {
				return true
			}
		}
	}
	return false
}

// fieldNode tests one Sigma field against its values: any value must
// match, or every value with the "all" modifier. A Sigma field can map to
// several event fields (see mapping.go); a value matches if it matches any
// of them, except null and exists checks, which look at the first only.
type fieldNode struct {
	targets []string
	values  []valueMatcher
	all     bool
}

func (f fieldNode) matchValue(ev *event.Event, m valueMatcher) bool {
	switch m.(type) {
	case nullMatcher, existsMatcher:
		v, ok := ev.Get(f.targets[0])
		return m.match(v, ok)
	}
	for _, t := range f.targets {
		if v, ok := ev.Get(t); m.match(v, ok) {
			return true
		}
	}
	return false
}

func (f fieldNode) match(ev *event.Event) bool {
	for _, m := range f.values {
		hit := f.matchValue(ev, m)
		if f.all && !hit {
			return false
		}
		if !f.all && hit {
			return true
		}
	}
	return f.all
}

// keywordNode is a full-text search: a value matches if it is found in the
// message or in any field value.
type keywordNode struct {
	values []valueMatcher
	all    bool
}

func (k keywordNode) match(ev *event.Event) bool {
	found := func(m valueMatcher) bool {
		if m.match(ev.Message, true) {
			return true
		}
		for _, v := range ev.Fields {
			if m.match(v, true) {
				return true
			}
		}
		return false
	}
	for _, m := range k.values {
		hit := found(m)
		if k.all && !hit {
			return false
		}
		if !k.all && hit {
			return true
		}
	}
	return k.all
}

// compileSelection compiles one named search identifier.
func compileSelection(name string, n *yaml.Node, ls *logsource) (node, error) {
	switch n.Kind {
	case yaml.MappingNode:
		return compileMap(n, ls)
	case yaml.SequenceNode:
		if len(n.Content) > 0 && n.Content[0].Kind == yaml.MappingNode {
			var alts orNode
			for _, item := range n.Content {
				if item.Kind != yaml.MappingNode {
					return nil, fmt.Errorf("selection %s: mixed list", name)
				}
				m, err := compileMap(item, ls)
				if err != nil {
					return nil, err
				}
				alts = append(alts, m)
			}
			return alts, nil
		}
		ms, err := compileValues(n, nil, true)
		if err != nil {
			return nil, err
		}
		return keywordNode{values: ms}, nil
	case yaml.ScalarNode:
		ms, err := compileValues(n, nil, true)
		if err != nil {
			return nil, err
		}
		return keywordNode{values: ms}, nil
	}
	return nil, fmt.Errorf("selection %s: unexpected YAML", name)
}

func compileMap(n *yaml.Node, ls *logsource) (node, error) {
	var and andNode
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, val := n.Content[i].Value, n.Content[i+1]
		parts := strings.Split(key, "|")
		field, mods := parts[0], parts[1:]
		all := false
		var valueMods []string
		for _, m := range mods {
			if m == "all" {
				all = true
			} else {
				valueMods = append(valueMods, m)
			}
		}
		ms, err := compileValues(val, valueMods, field == "")
		if err != nil {
			return nil, err
		}
		if field == "" {
			and = append(and, keywordNode{values: ms, all: all})
			continue
		}
		targets, err := ls.field(field)
		if err != nil {
			return nil, err
		}
		and = append(and, fieldNode{targets: targets, values: ms, all: all})
	}
	return and, nil
}

// compileValues compiles a scalar or list of values with the given
// modifiers. Keyword searches imply "contains".
func compileValues(n *yaml.Node, mods []string, keyword bool) ([]valueMatcher, error) {
	var items []*yaml.Node
	switch n.Kind {
	case yaml.ScalarNode:
		items = []*yaml.Node{n}
	case yaml.SequenceNode:
		items = n.Content
	default:
		return nil, fmt.Errorf("unexpected value type")
	}
	var out []valueMatcher
	for _, it := range items {
		if it.Kind != yaml.ScalarNode {
			return nil, fmt.Errorf("nested value lists are not valid")
		}
		m, err := compileValue(it, mods, keyword)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// valueMatcher tests one field value. exists is false when the event has no
// such field.
type valueMatcher interface {
	match(v string, exists bool) bool
}

func compileValue(n *yaml.Node, mods []string, keyword bool) (valueMatcher, error) {
	isNull := n.Tag == "!!null"
	val := n.Value

	var (
		kind     = "eq"
		cased    bool
		reFlags  string
		isRe     bool
		isCIDR   bool
		cmp      string
		isExists bool
	)
	if keyword {
		kind = "contains"
	}
	for _, m := range mods {
		switch m {
		case "contains", "startswith", "endswith":
			kind = m
		case "cased":
			cased = true
		case "re":
			isRe = true
		case "i", "m", "s":
			reFlags += m
		case "cidr":
			isCIDR = true
		case "gt", "gte", "lt", "lte":
			cmp = m
		case "exists":
			isExists = true
		default:
			return nil, unsupported("modifier %s", m)
		}
	}

	switch {
	case isExists:
		want, err := strconv.ParseBool(val)
		if err != nil {
			return nil, fmt.Errorf("exists needs true or false")
		}
		return existsMatcher(want), nil
	case isNull:
		return nullMatcher{}, nil
	case isRe:
		expr := val
		if reFlags != "" {
			expr = "(?" + reFlags + ")" + expr
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, unsupported("regex syntax")
		}
		return reMatcher{re}, nil
	case isCIDR:
		p, err := netip.ParsePrefix(val)
		if err != nil {
			return nil, fmt.Errorf("bad cidr %q", val)
		}
		return cidrMatcher{p.Masked()}, nil
	case cmp != "":
		f, err := strconv.ParseFloat(val, 64)
		if err != nil {
			return nil, fmt.Errorf("%s needs a number", cmp)
		}
		return numMatcher{op: cmp, n: f}, nil
	}
	return newStringMatcher(val, kind, cased), nil
}

type existsMatcher bool

func (e existsMatcher) match(_ string, exists bool) bool { return bool(e) == exists }

type nullMatcher struct{}

func (nullMatcher) match(v string, exists bool) bool { return !exists || v == "" }

type reMatcher struct{ re *regexp.Regexp }

func (r reMatcher) match(v string, exists bool) bool { return exists && r.re.MatchString(v) }

type cidrMatcher struct{ p netip.Prefix }

func (c cidrMatcher) match(v string, exists bool) bool {
	if !exists {
		return false
	}
	a, err := netip.ParseAddr(v)
	return err == nil && c.p.Contains(a.Unmap())
}

type numMatcher struct {
	op string
	n  float64
}

func (m numMatcher) match(v string, exists bool) bool {
	if !exists {
		return false
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return false
	}
	switch m.op {
	case "gt":
		return f > m.n
	case "gte":
		return f >= m.n
	case "lt":
		return f < m.n
	}
	return f <= m.n
}

// stringMatcher implements Sigma's default string semantics: case
// insensitive, with * and ? wildcards (escaped with a backslash). Plain
// patterns use fast string comparisons; wildcard patterns become a regex.
type stringMatcher struct {
	kind  string // eq, contains, startswith, endswith
	lit   string
	cased bool
	re    *regexp.Regexp
}

func newStringMatcher(val, kind string, cased bool) valueMatcher {
	lit, wild := unescape(val)
	if !wild {
		if !cased {
			lit = strings.ToLower(lit)
		}
		return stringMatcher{kind: kind, lit: lit, cased: cased}
	}
	var b strings.Builder
	if !cased {
		b.WriteString("(?i)")
	}
	b.WriteString("(?s)")
	if kind == "eq" || kind == "startswith" {
		b.WriteString("^")
	}
	b.WriteString(globToRegex(val))
	if kind == "eq" || kind == "endswith" {
		b.WriteString("$")
	}
	return stringMatcher{re: regexp.MustCompile(b.String())}
}

func (s stringMatcher) match(v string, exists bool) bool {
	if !exists {
		return false
	}
	if s.re != nil {
		return s.re.MatchString(v)
	}
	if !s.cased {
		v = strings.ToLower(v)
	}
	switch s.kind {
	case "contains":
		return strings.Contains(v, s.lit)
	case "startswith":
		return strings.HasPrefix(v, s.lit)
	case "endswith":
		return strings.HasSuffix(v, s.lit)
	}
	return v == s.lit
}

// unescape resolves Sigma escapes and reports whether the value contains
// unescaped wildcards.
func unescape(s string) (string, bool) {
	var b strings.Builder
	wild := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s) && (s[i+1] == '*' || s[i+1] == '?' || s[i+1] == '\\'):
			b.WriteByte(s[i+1])
			i++
		case c == '*' || c == '?':
			wild = true
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), wild
}

func globToRegex(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s) && (s[i+1] == '*' || s[i+1] == '?' || s[i+1] == '\\'):
			b.WriteString(regexp.QuoteMeta(string(s[i+1])))
			i++
		case c == '*':
			b.WriteString(".*")
		case c == '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	return b.String()
}
