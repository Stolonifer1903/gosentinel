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
		mu       sync.Mutex
		wg       sync.WaitGroup
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
