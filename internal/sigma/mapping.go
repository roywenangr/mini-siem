package sigma

import "strings"

// logsource is a resolved Sigma logsource: which mini-siem parser produces
// those events, and how Sigma field names map onto event fields.
type logsource struct {
	source string
	fields map[string]string
}

// Field names follow the W3C extended log format Sigma uses for web logs
// (and the variants that appear in community rules), mapped to what the
// nginx parser emits. A comma-separated value lists several event fields.
//
// cs-uri-query is the query string in W3C logs, but most community rules
// use it for the whole request URI ("/cgi-bin/.%2e/..."), so it is checked
// against both.
var webFields = map[string]string{
	"c-ip":            "src_ip",
	"clientip":        "src_ip",
	"client_ip":       "src_ip",
	"src_ip":          "src_ip",
	"cs-method":       "fields.method",
	"method":          "fields.method",
	"c-uri":           "fields.path",
	"cs-uri":          "fields.path",
	"uri":             "fields.path",
	"request":         "fields.path",
	"cs-uri-stem":     "fields.uri_stem",
	"c-uri-stem":      "fields.uri_stem",
	"uri_stem":        "fields.uri_stem",
	"cs-uri-query":    "fields.uri_query,fields.path",
	"c-uri-query":     "fields.uri_query,fields.path",
	"uri_query":       "fields.uri_query",
	"c-uri-extension": "fields.uri_extension",
	"sc-status":       "fields.status",
	"status":          "fields.status",
	"cs-user-agent":   "fields.user_agent",
	"c-useragent":     "fields.user_agent",
	"cs(user-agent)":  "fields.user_agent",
	"user-agent":      "fields.user_agent",
	"useragent":       "fields.user_agent",
	"cs-referer":      "fields.referer",
	"cs-referrer":     "fields.referer",
	"cs(referer)":     "fields.referer",
	"cs-username":     "user",
	"sc-bytes":        "fields.bytes",
}

// The SSH parser does not split sshd messages into Sigma fields; sshd rules
// are keyword searches over the message.
var sshFields = map[string]string{
	"user":     "user",
	"src_ip":   "src_ip",
	"hostname": "host",
}

func resolveLogsource(l Logsource, opts Options) (*logsource, error) {
	cat, prod, svc := strings.ToLower(l.Category), strings.ToLower(l.Product), strings.ToLower(l.Service)
	switch {
	case cat == "webserver":
		return &logsource{source: "nginx", fields: webFields}, nil
	case cat == "" && (prod == "nginx" || prod == "apache") && (svc == "" || svc == "access"):
		return &logsource{source: "nginx", fields: webFields}, nil
	case cat == "proxy" && opts.IncludeProxy:
		return &logsource{source: "nginx", fields: webFields}, nil
	case cat == "" && prod == "linux" && svc == "sshd":
		return &logsource{source: "ssh", fields: sshFields}, nil
	}
	return nil, unsupported("logsource")
}

func (l *logsource) field(name string) ([]string, error) {
	if t, ok := l.fields[strings.ToLower(name)]; ok {
		return strings.Split(t, ","), nil
	}
	return nil, unsupported("unmapped field %s", strings.ToLower(name))
}
