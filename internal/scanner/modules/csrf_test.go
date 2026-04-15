package modules

import (
	"context"
	"strings"
	"testing"

	"github.com/Stolonifer1903/gosentinel/internal/crawler"
	"github.com/Stolonifer1903/gosentinel/internal/scanner"
	"github.com/Stolonifer1903/gosentinel/internal/scanner/descriptions"
)

func TestCSRFModule(t *testing.T) {
	module := &CSRFModule{}
	
	tests := []struct {
		name          string
		endpoints     []crawler.Endpoint
		wantFlags     int // Number of raw findings expected
		wantGrouped   int // Number of GroupedFindings expected via Engine grouping
		wantEndpoints int // Number of URL endpoints after grouping
	}{
		{
			name: "GET form is ignored",
			endpoints: []crawler.Endpoint{
				{URL: "http://example.com/search", Method: "GET", Source: "Form", Params: []string{"q"}},
			},
			wantFlags:     0,
			wantGrouped:   0,
			wantEndpoints: 0,
		},
		{
			name: "POST form with standard token is ignored",
			endpoints: []crawler.Endpoint{
				{URL: "http://example.com/update", Method: "POST", Source: "Form", Params: []string{"data", "csrf_token"}},
			},
			wantFlags:     0,
			wantGrouped:   0,
			wantEndpoints: 0,
		},
		{
			name: "Token aliases are correctly identified as safe",
			endpoints: []crawler.Endpoint{
				{URL: "http://example.com/a", Method: "POST", Source: "Form", Params: []string{"_csrf"}},
				{URL: "http://example.com/b", Method: "POST", Source: "Form", Params: []string{"xsrf_token"}},
				{URL: "http://example.com/c", Method: "POST", Source: "Form", Params: []string{"__RequestVerificationToken"}},
				{URL: "http://example.com/d", Method: "POST", Source: "Form", Params: []string{"authenticity_token"}},
				{URL: "http://example.com/e", Method: "POST", Source: "Form", Params: []string{"nonce"}},
			},
			wantFlags:     0,
			wantGrouped:   0,
			wantEndpoints: 0,
		},
		{
			name: "POST form without token is flagged",
			endpoints: []crawler.Endpoint{
				{URL: "http://example.com/delete", Method: "POST", Source: "Form", Params: []string{"id", "confirm"}},
			},
			wantFlags:     1,
			wantGrouped:   1,
			wantEndpoints: 1,
		},
		{
			name: "Duplicate identical forms deduped",
			endpoints: []crawler.Endpoint{
				{URL: "http://example.com/delete", Method: "POST", Source: "Form", Params: []string{"id"}},
				{URL: "http://example.com/delete", Method: "POST", Source: "Form", Params: []string{"id"}},
			},
			wantFlags:     1,
			wantGrouped:   1,
			wantEndpoints: 1,
		},
		{
			name: "Non-form POST endpoints are safely ignored",
			endpoints: []crawler.Endpoint{
				{URL: "http://example.com/api/delete", Method: "POST", Source: "API", Params: []string{"id"}},
				{URL: "http://example.com/api/create", Method: "POST", Source: "Link", Params: []string{"payload"}},
			},
			wantFlags:     0,
			wantGrouped:   0,
			wantEndpoints: 0,
		},
		{
			name: "Multiple distinct vulnerable forms on different URLs group into one finding",
			endpoints: []crawler.Endpoint{
				{URL: "http://example.com/delete", Method: "POST", Source: "Form", Params: []string{"id"}},
				{URL: "http://example.com/update", Method: "POST", Source: "Form", Params: []string{"user", "email"}},
				{URL: "http://example.com/post", Method: "POST", Source: "Form", Params: []string{"content"}},
			},
			// They yield distinct findings out of the module...
			wantFlags:     3,
			// ...but they group perfectly into 1 Finding with 3 Endpoints via Engine logic!
			wantGrouped:   1,
			wantEndpoints: 3,
		},
		{
			name:          "Empty endpoints slice does not panic and yields zero flags",
			endpoints:     []crawler.Endpoint{},
			wantFlags:     0,
			wantGrouped:   0,
			wantEndpoints: 0,
		},
	}

	for _, tt := range tests {
		tt := tt // captured loop variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings, err := module.Run(context.Background(), tt.endpoints)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			
			if len(findings) != tt.wantFlags {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantFlags)
			}
			
			// Simulate the Engine grouping logic
			res := &scanner.Result{Findings: findings}
			grouped := res.Group()

			if len(grouped) != tt.wantGrouped {
				t.Fatalf("expected exactly %d GroupedFinding(s), got %d", tt.wantGrouped, len(grouped))
			}

			// Validate endpoint grouping count if we expect a grouped finding
			if tt.wantGrouped > 0 {
				g := grouped[0]
				if len(g.Endpoints) != tt.wantEndpoints {
					t.Errorf("grouped finding contained %d endpoints, want %d", len(g.Endpoints), tt.wantEndpoints)
				}
			}

			// Verify context mapping if flagged
			if tt.wantFlags > 0 {
				for _, f := range findings {
					if f.Title != "Missing Anti-CSRF Token" {
						t.Errorf("unexpected finding title: %s", f.Title)
					}
					if f.OWASP != descriptions.GetCategory(descriptions.CSRFTokenMissing) {
						t.Errorf("unexpected OWASP mapping: %s", f.OWASP)
					}
					// Ensure evidence mentions our exact new static string.
					if !strings.Contains(f.Evidence, "does not contain an anti-CSRF token") {
						t.Errorf("evidence does not match expected static format: %s", f.Evidence)
					}
				}
			}
		})
	}

	// Additional test for context cancellation
	t.Run("Context cancellation aborts module cleanly", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		endpoints := []crawler.Endpoint{
			{URL: "http://example.com/delete", Method: "POST", Source: "Form", Params: []string{"id"}},
		}

		findings, err := module.Run(ctx, endpoints)
		if err != context.Canceled {
			t.Errorf("expected context.Canceled error, got %v", err)
		}
		if len(findings) != 0 {
			t.Errorf("expected 0 findings on cancelled context, got %d", len(findings))
		}
	})
}
