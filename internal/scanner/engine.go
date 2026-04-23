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

// ModuleResult encapsulates findings and any error returned by a specific module.
type ModuleResult struct {
	ModuleName string
	Findings   []Finding
	Error      error
}

// Result combines all findings from all modules after a scan.
type Result struct {
	Findings      []Finding
	ModuleResults []ModuleResult
}

// Run executes all registered modules concurrently against the provided
// endpoints, then merges and sorts the findings.
func (e *Engine) Run(ctx context.Context, endpoints []crawler.Endpoint) (*Result, error) {
	var (
		mu            sync.Mutex
		wg            sync.WaitGroup
		allFindings   []Finding
		moduleResults []ModuleResult
	)

	for _, mod := range e.modules {
		wg.Add(1)
		go func(m Module) {
			defer wg.Done()

			findings, err := m.Run(ctx, endpoints)

			mu.Lock()
			if findings != nil {
				allFindings = append(allFindings, findings...)
			}
			moduleResults = append(moduleResults, ModuleResult{
				ModuleName: m.Name(),
				Findings:   findings,
				Error:      err,
			})
			mu.Unlock()
		}(mod)
	}

	wg.Wait()

	// Sort all findings across modules by severity: Critical first.
	sort.Slice(allFindings, func(i, j int) bool {
		return allFindings[i].Rank() > allFindings[j].Rank()
	})

	return &Result{
		Findings:      allFindings,
		ModuleResults: moduleResults,
	}, nil
}

// Group aggregates identical findings (same Title and Severity) into GroupedFinding structs.
// It returns a slice sorted by severity (Critical first).
func (r *Result) Group() []GroupedFinding {
	type key struct {
		title       string
		severity    Severity
		owasp       string
		confidence  Confidence
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
			confidence:  f.Confidence,
			description: f.Description,
			evidence:    f.Evidence,
			remediation: f.Remediation,
		}

		if g, ok := groups[k]; ok {
			// Check for URL deduplication within the group
			exists := false
			for _, end := range g.Endpoints {
				if end.URL == f.URL && end.Detail == f.EndpointDetail {
					exists = true
					break
				}
			}
			if !exists {
				g.Endpoints = append(g.Endpoints, AffectedEndpoint{URL: f.URL, Detail: f.EndpointDetail})
			}
		} else {
			groups[k] = &GroupedFinding{
				Title:       f.Title,
				Severity:    f.Severity,
				OWASP:       f.OWASP,
				Confidence:  f.Confidence,
				Description: f.Description,
				Evidence:    f.Evidence,
				Remediation: f.Remediation,
				Endpoints:   []AffectedEndpoint{{URL: f.URL, Detail: f.EndpointDetail}},
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
