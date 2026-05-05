package scanner

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/Stolonifer1903/gosentinel/internal/crawler"
)

// ProgressStage indicates whether a module is starting or has finished.
type ProgressStage string

const (
	StageStart ProgressStage = "start"
	StageDone  ProgressStage = "done"
)

// ProgressEvent is emitted by the engine before and after each module runs.
type ProgressEvent struct {
	ModuleName string
	ModuleType ModuleType
	Stage      ProgressStage
	Elapsed    time.Duration // only meaningful when Stage == StageDone
	FindCount  int           // only meaningful when Stage == StageDone
}

// ProgressFunc is called synchronously by the engine on each module lifecycle event.
// Implementations must be goroutine-safe when passive modules run concurrently.
type ProgressFunc func(ProgressEvent)

// Engine orchestrates all registered scanner modules, running passive modules
// concurrently and active modules sequentially to prevent data races.
type Engine struct {
	modules    []Module
	OnProgress ProgressFunc // optional; called before and after each module run
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

// Run executes all registered modules against the provided endpoints.
// It uses a two-phase execution strategy:
// Phase 1: All passive modules run concurrently.
// Phase 2: All active modules run sequentially in registration order.
//
// The findings in Result.Findings are in insertion order (passive results first,
// then active in registration order). Callers should use Result.Group() to obtain
// a severity-sorted, deduplicated view.
func (e *Engine) Run(ctx context.Context, endpoints []crawler.Endpoint) (*Result, error) {
	var (
		mu            sync.Mutex
		wg            sync.WaitGroup
		allFindings   []Finding
		moduleResults []ModuleResult
	)

	// Partition modules to preserve registration order within each group.
	var passive []Module
	var active []Module
	for _, mod := range e.modules {
		if mod.Type() == TypePassive {
			passive = append(passive, mod)
		} else {
			active = append(active, mod)
		}
	}

	// Phase 1: Concurrent Passive Modules
	for _, mod := range passive {
		wg.Add(1)
		go func(m Module) {
			defer wg.Done()
			start := time.Now()
			e.emit(ProgressEvent{ModuleName: m.Name(), ModuleType: TypePassive, Stage: StageStart})

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

			e.emit(ProgressEvent{
				ModuleName: m.Name(),
				ModuleType: TypePassive,
				Stage:      StageDone,
				Elapsed:    time.Since(start),
				FindCount:  len(findings),
			})
		}(mod)
	}
	wg.Wait()

	// Phase 2: Sequential Active Modules
	for _, mod := range active {
		// Check for cancellation before starting each active module.
		// Active modules can mutate target state (e.g. StoredXSS writes data),
		// so we must honour cancellation promptly rather than finishing the batch.
		select {
		case <-ctx.Done():
			return &Result{Findings: allFindings, ModuleResults: moduleResults}, ctx.Err()
		default:
		}

		start := time.Now()
		e.emit(ProgressEvent{ModuleName: mod.Name(), ModuleType: TypeActive, Stage: StageStart})

		findings, err := mod.Run(ctx, endpoints)

		if findings != nil {
			allFindings = append(allFindings, findings...)
		}
		moduleResults = append(moduleResults, ModuleResult{
			ModuleName: mod.Name(),
			Findings:   findings,
			Error:      err,
		})
		e.emit(ProgressEvent{
			ModuleName: mod.Name(),
			ModuleType: TypeActive,
			Stage:      StageDone,
			Elapsed:    time.Since(start),
			FindCount:  len(findings),
		})
	}

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
		description string
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
			remediation: f.Remediation,
		}

		if g, ok := groups[k]; ok {
			// If the new finding has higher confidence, promote the group's confidence and evidence.
			if confidenceRank[f.Confidence] > confidenceRank[g.Confidence] {
				g.Confidence = f.Confidence
				g.Evidence = f.Evidence
			}

			// Check for URL deduplication within the group
			exists := false
			normalizedURL := stripTrailingSlash(f.URL)
			for _, end := range g.Endpoints {
				if stripTrailingSlash(end.URL) == normalizedURL && end.Detail == f.EndpointDetail {
					exists = true
					break
				}
			}
			if !exists {
				g.Endpoints = append(g.Endpoints, AffectedEndpoint{URL: normalizedURL, Detail: f.EndpointDetail})
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
				Endpoints:   []AffectedEndpoint{{URL: stripTrailingSlash(f.URL), Detail: f.EndpointDetail}},
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

func stripTrailingSlash(url string) string {
	if len(url) > 1 && url[len(url)-1] == '/' {
		return url[:len(url)-1]
	}
	return url
}

// emit fires a progress event if OnProgress is set.
// Safe to call from goroutines — the nil check is a read of an immutable field set
// before Run() is called, so no synchronization is needed here.
func (e *Engine) emit(ev ProgressEvent) {
	if e.OnProgress != nil {
		e.OnProgress(ev)
	}
}
