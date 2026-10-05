package sigma

import (
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
)

// parseCondition compiles a Sigma condition expression:
//
//	expr    = or
//	or      = and { "or" and }
//	and     = not { "and" not }
//	not     = "not" not | primary
//	primary = "(" expr ")" | quant "of" (pattern | "them") | identifier
//	quant   = "1" | "all" | "any" | N
func parseCondition(s string, sels map[string]node) (node, error) {
	if strings.Contains(s, "|") {
		return nil, unsupported("aggregation in condition")
	}
	p := &condParser{toks: tokenize(s), sels: sels}
	n, err := p.or()
	if err != nil {
		return nil, fmt.Errorf("condition %q: %w", s, err)
	}
	if p.pos != len(p.toks) {
		return nil, fmt.Errorf("condition %q: unexpected %q", s, p.toks[p.pos])
	}
	return n, nil
}

func tokenize(s string) []string {
	s = strings.ReplaceAll(s, "(", " ( ")
	s = strings.ReplaceAll(s, ")", " ) ")
	return strings.Fields(s)
}

type condParser struct {
	toks []string
	pos  int
	sels map[string]node
}

func (p *condParser) peek() string {
	if p.pos < len(p.toks) {
		return strings.ToLower(p.toks[p.pos])
	}
	return ""
}

func (p *condParser) next() string {
	t := p.toks[p.pos]
	p.pos++
	return t
}

func (p *condParser) or() (node, error) {
	left, err := p.and()
	if err != nil {
		return nil, err
	}
	alts := orNode{left}
	for p.peek() == "or" {
		p.pos++
		right, err := p.and()
		if err != nil {
			return nil, err
		}
		alts = append(alts, right)
	}
	if len(alts) == 1 {
		return left, nil
	}
	return alts, nil
}

func (p *condParser) and() (node, error) {
	left, err := p.not()
	if err != nil {
		return nil, err
	}
	all := andNode{left}
	for p.peek() == "and" {
		p.pos++
		right, err := p.not()
		if err != nil {
			return nil, err
		}
		all = append(all, right)
	}
	if len(all) == 1 {
		return left, nil
	}
	return all, nil
}

func (p *condParser) not() (node, error) {
	if p.peek() == "not" {
		p.pos++
		n, err := p.not()
		if err != nil {
			return nil, err
		}
		return notNode{n}, nil
	}
	return p.primary()
}

func (p *condParser) primary() (node, error) {
	switch tok := p.peek(); {
	case tok == "":
		return nil, fmt.Errorf("unexpected end")
	case tok == "(":
		p.pos++
		n, err := p.or()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, fmt.Errorf("missing )")
		}
		p.pos++
		return n, nil
	case p.pos+1 < len(p.toks) && strings.ToLower(p.toks[p.pos+1]) == "of":
		quant := p.next()
		p.pos++ // "of"
		if p.pos >= len(p.toks) {
			return nil, fmt.Errorf("missing pattern after of")
		}
		return p.quantified(quant, p.next())
	default:
		name := p.next()
		n, ok := p.sels[name]
		if !ok {
			return nil, fmt.Errorf("unknown identifier %q", name)
		}
		return n, nil
	}
}

func (p *condParser) quantified(quant, pattern string) (node, error) {
	var names []string
	for name := range p.sels {
		if strings.EqualFold(pattern, "them") {
			names = append(names, name)
			continue
		}
		if ok, _ := path.Match(pattern, name); ok {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("pattern %q matches no identifier", pattern)
	}
	sort.Strings(names) // deterministic evaluation order
	nodes := make([]node, len(names))
	for i, n := range names {
		nodes[i] = p.sels[n]
	}
	switch q := strings.ToLower(quant); q {
	case "all":
		return andNode(nodes), nil
	case "1", "any":
		return orNode(nodes), nil
	default:
		n, err := strconv.Atoi(q)
		if err != nil || n < 1 {
			return nil, fmt.Errorf("bad quantifier %q", quant)
		}
		return atLeastNode{n: n, nodes: nodes}, nil
	}
}
