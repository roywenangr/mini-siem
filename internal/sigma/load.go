package sigma

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/roywenangr/mini-siem/internal/rules"
)

// Report summarizes a load.
type Report struct {
	Files   int            `json:"files"`
	Loaded  int            `json:"loaded"`
	Skipped map[string]int `json:"skipped"` // reason -> count
	Errors  []string       `json:"errors,omitempty"`
}

const maxReportErrors = 20

// LoadPaths compiles every .yml/.yaml file under the given files or
// directories. Rules that are unsupported or fail to parse are skipped and
// recorded in the report; only an unreadable path is an error.
func LoadPaths(paths []string, opts Options) ([]*rules.Rule, *Report, error) {
	rep := &Report{Skipped: map[string]int{}}
	var out []*rules.Rule
	seen := map[string]bool{}

	var files []string
	for _, p := range paths {
		err := filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if strings.HasPrefix(d.Name(), ".") && path != p {
					return filepath.SkipDir
				}
				return nil
			}
			if ext := filepath.Ext(path); ext == ".yml" || ext == ".yaml" {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			return nil, nil, fmt.Errorf("sigma: %w", err)
		}
	}
	sort.Strings(files)

	for _, f := range files {
		rep.Files++
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, nil, fmt.Errorf("sigma: %w", err)
		}
		r, err := compileFile(data, opts)
		var un *UnsupportedError
		switch {
		case errors.As(err, &un):
			rep.Skipped[un.Reason]++
			continue
		case err != nil:
			rep.Skipped["invalid rule"]++
			if len(rep.Errors) < maxReportErrors {
				rep.Errors = append(rep.Errors, fmt.Sprintf("%s: %v", f, err))
			}
			continue
		}
		if seen[r.ID] {
			rep.Skipped["duplicate id"]++
			continue
		}
		seen[r.ID] = true
		r.Source = f
		out = append(out, r)
		rep.Loaded++
	}
	return out, rep, nil
}

func compileFile(data []byte, opts Options) (*rules.Rule, error) {
	doc, err := Parse(data)
	if err != nil {
		return nil, err
	}
	return Compile(doc, opts)
}
