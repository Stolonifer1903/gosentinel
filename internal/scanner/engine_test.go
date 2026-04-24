package scanner

import (
	"context"
	"errors"
	"testing"

	"github.com/Stolonifer1903/gosentinel/internal/crawler"
)

// MockModule implements the Module interface for testing.
type MockModule struct {
	name     string
	modType  ModuleType
	findings []Finding
	err      error
	called   bool
}

func (m *MockModule) Name() string { return m.name }
func (m *MockModule) Type() ModuleType { return m.modType }
func (m *MockModule) Run(ctx context.Context, endpoints []crawler.Endpoint) ([]Finding, error) {
	m.called = true
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return m.findings, m.err
	}
}

func TestNewEngine(t *testing.T) {
	t.Run("nil modules", func(t *testing.T) {
		e := NewEngine(nil)
		if e == nil {
			t.Fatal("expected non-nil engine")
		}
		if len(e.modules) != 0 {
			t.Errorf("expected 0 modules, got %d", len(e.modules))
		}
	})

	t.Run("populated modules", func(t *testing.T) {
		mods := []Module{&MockModule{name: "test"}}
		e := NewEngine(mods)
		if len(e.modules) != 1 {
			t.Errorf("expected 1 module, got %d", len(e.modules))
		}
		if e.modules[0].Name() != "test" {
			t.Errorf("expected module 'test', got '%s'", e.modules[0].Name())
		}
	})
}

func TestEngine_Run(t *testing.T) {
	t.Run("findings collected and sorted", func(t *testing.T) {
		pMod := &MockModule{
			name:    "passive",
			modType: TypePassive,
			findings: []Finding{
				{Title: "Medium Issue", Severity: Medium},
			},
		}
		aMod := &MockModule{
			name:    "active",
			modType: TypeActive,
			findings: []Finding{
				{Title: "Critical Issue", Severity: Critical},
				{Title: "High Issue", Severity: High},
			},
		}

		e := NewEngine([]Module{pMod, aMod})
		res, err := e.Run(context.Background(), []crawler.Endpoint{{URL: "http://example.com"}})

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(res.Findings) != 3 {
			t.Errorf("expected 3 findings, got %d", len(res.Findings))
		}

		// Verify sorting (Critical -> High -> Medium)
		if res.Findings[0].Severity != Critical {
			t.Errorf("expected first finding to be Critical, got %s", res.Findings[0].Severity)
		}
		if res.Findings[1].Severity != High {
			t.Errorf("expected second finding to be High, got %s", res.Findings[1].Severity)
		}
		if res.Findings[2].Severity != Medium {
			t.Errorf("expected third finding to be Medium, got %s", res.Findings[2].Severity)
		}
	})

	t.Run("module error captured", func(t *testing.T) {
		errMod := &MockModule{
			name: "error-prone",
			err:  errors.New("scan failed"),
		}
		e := NewEngine([]Module{errMod})
		res, err := e.Run(context.Background(), []crawler.Endpoint{{URL: "http://example.com"}})

		if err != nil {
			t.Fatalf("Engine.Run should not return error on module failure, got %v", err)
		}
		if len(res.ModuleResults) != 1 {
			t.Fatalf("expected 1 module result, got %d", len(res.ModuleResults))
		}
		if res.ModuleResults[0].ModuleName != "error-prone" {
			t.Errorf("expected module name 'error-prone', got '%s'", res.ModuleResults[0].ModuleName)
		}
		if res.ModuleResults[0].Error == nil || res.ModuleResults[0].Error.Error() != "scan failed" {
			t.Errorf("expected error 'scan failed', got %v", res.ModuleResults[0].Error)
		}
	})

	t.Run("empty endpoints", func(t *testing.T) {
		e := NewEngine([]Module{&MockModule{name: "test"}})
		res, err := e.Run(context.Background(), nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res == nil {
			t.Fatal("expected non-nil result")
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		e := NewEngine([]Module{&MockModule{name: "test", modType: TypeActive}})
		res, err := e.Run(ctx, []crawler.Endpoint{{URL: "http://example.com"}})

		// Depending on implementation, Run might return nil error but the module result will have context.Canceled
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(res.ModuleResults) > 0 && res.ModuleResults[0].Error != context.Canceled {
			t.Errorf("expected context.Canceled error in module result, got %v", res.ModuleResults[0].Error)
		}
	})
}

func TestResult_Group(t *testing.T) {
	t.Run("basic aggregation and distinct findings", func(t *testing.T) {
		res := &Result{
			Findings: []Finding{
				{Title: "XSS", Severity: High, URL: "http://a.com", OWASP: "A03"},
				{Title: "XSS", Severity: High, URL: "http://b.com", OWASP: "A03"},
				{Title: "CSRF", Severity: Medium, URL: "http://c.com", OWASP: "A01"},
			},
		}
		groups := res.Group()
		if len(groups) != 2 {
			t.Errorf("expected 2 groups, got %d", len(groups))
		}

		// XSS group should have 2 endpoints
		for _, g := range groups {
			if g.Title == "XSS" {
				if len(g.Endpoints) != 2 {
					t.Errorf("expected 2 endpoints for XSS, got %d", len(g.Endpoints))
				}
			}
		}
	})

	t.Run("confidence promotion and evidence preservation", func(t *testing.T) {
		res := &Result{
			Findings: []Finding{
				{
					Title:      "XSS",
					Severity:   High,
					Confidence: LowConfidence,
					Evidence:   "weak evidence",
					URL:        "http://a.com",
				},
				{
					Title:      "XSS",
					Severity:   High,
					Confidence: ConfirmedConfidence,
					Evidence:   "strong evidence",
					URL:        "http://b.com",
				},
			},
		}
		groups := res.Group()
		if len(groups) != 1 {
			t.Fatalf("expected 1 group, got %d", len(groups))
		}
		if groups[0].Confidence != ConfirmedConfidence {
			t.Errorf("expected promoted confidence Confirmed, got %s", groups[0].Confidence)
		}
		if groups[0].Evidence != "strong evidence" {
			t.Errorf("expected promoted evidence 'strong evidence', got '%s'", groups[0].Evidence)
		}
	})

	t.Run("URL deduplication and trailing slash stripping", func(t *testing.T) {
		res := &Result{
			Findings: []Finding{
				{Title: "XSS", Severity: High, URL: "http://example.com/", OWASP: "A03"},
				{Title: "XSS", Severity: High, URL: "http://example.com", OWASP: "A03"},
			},
		}
		groups := res.Group()
		if len(groups) != 1 {
			t.Fatalf("expected 1 group, got %d", len(groups))
		}
		if len(groups[0].Endpoints) != 1 {
			t.Errorf("expected 1 endpoint after deduplication, got %d", len(groups[0].Endpoints))
		}
	})

	t.Run("severity sorting and single finding passthrough", func(t *testing.T) {
		res := &Result{
			Findings: []Finding{
				{Title: "Low", Severity: Low, OWASP: "A"},
				{Title: "Critical", Severity: Critical, OWASP: "B"},
				{Title: "High", Severity: High, OWASP: "C"},
			},
		}
		groups := res.Group()
		if len(groups) != 3 {
			t.Fatalf("expected 3 groups, got %d", len(groups))
		}

		if groups[0].Severity != Critical {
			t.Errorf("expected first group to be Critical, got %s", groups[0].Severity)
		}
		if groups[1].Severity != High {
			t.Errorf("expected second group to be High, got %s", groups[1].Severity)
		}
		if groups[2].Severity != Low {
			t.Errorf("expected third group to be Low, got %s", groups[2].Severity)
		}
	})
}
