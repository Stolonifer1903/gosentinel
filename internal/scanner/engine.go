package scanner

import (
	"context"
	"sort"
	"sync"

	"github.com/Stolonifer1903/gosentinel/internal/crawler"
)

// Engine orchestrates all registered scanner modules, runs them concurrently,
// and returns a deduplicated, severity-sorted slice of findings.
type Engine struct {
	modules []Module
}

// NewEngine creates an Engine mapped with the provided modules.
func NewEngine(modules []Module) *Engine {
	if modules == nil {
		modules = []Module{}
	}
	return &Engine{modules: modules}
}

// Result combines all findings from all modules after a scan.
type Result struct {
	Findings []Finding
}

// Run executes all registered modules concurrently against the provided
// endpoints, then merges and sorts the findings.
func (e *Engine) Run(ctx context.Context, endpoints []crawler.Endpoint) (*Result, error) {
	var (
		mu          sync.Mutex
		wg          sync.WaitGroup
		allFindings []Finding
	)

	for _, mod := range e.modules {
		wg.Add(1)
		go func(m Module) {
			defer wg.Done()

			findings, err := m.Run(ctx, endpoints)
			if err != nil {
				// Non-fatal: a module failure doesn't stop other modules.
				return
			}

			mu.Lock()
			allFindings = append(allFindings, findings...)
			mu.Unlock()
		}(mod)
	}

	wg.Wait()

	// Sort all findings across modules by severity: Critical first.
	sort.Slice(allFindings, func(i, j int) bool {
		return allFindings[i].Rank() > allFindings[j].Rank()
	})

	return &Result{Findings: allFindings}, nil
}

// Group aggregates identical findings (same Title and Severity) into GroupedFinding structs.
// It returns a slice sorted by severity (Critical first).
func (r *Result) Group() []GroupedFinding {
	type key struct {
		title       string
		severity    Severity
		owasp       string
		description string
		evidence    string
		remediation string
	}

	groups := make(map[key]*GroupedFinding)
	var order []key

	for _, f := range r.Findings {
		k := key{
			title:       f.Title,
			severity:    f.Severity,
			owasp:       f.OWASP,
			description: f.Description,
			evidence:    f.Evidence,
			remediation: f.Remediation,
		}

		if g, ok := groups[k]; ok {
			// Check for URL deduplication within the group
			exists := false
			for _, url := range g.Endpoints {
				if url == f.URL {
					exists = true
					break
				}
			}
			if !exists {
				g.Endpoints = append(g.Endpoints, f.URL)
			}
		} else {
			groups[k] = &GroupedFinding{
				Title:       f.Title,
				Severity:    f.Severity,
				OWASP:       f.OWASP,
				Description: f.Description,
				Evidence:    f.Evidence,
				Remediation: f.Remediation,
				Endpoints:   []string{f.URL},
			}
			order = append(order, k)
		}
	}

	result := make([]GroupedFinding, 0, len(groups))
	for _, k := range order {
		result = append(result, *groups[k])
	}

	// Sort by severity rank
	sort.Slice(result, func(i, j int) bool {
		return result[i].Rank() > result[j].Rank()
	})

	return result
}
