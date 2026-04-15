package modules

import (
	"context"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Stolonifer1903/gosentinel/internal/crawler"
	"github.com/Stolonifer1903/gosentinel/internal/scanner"
	"github.com/Stolonifer1903/gosentinel/internal/scanner/descriptions"
)

// CSRFModule scans HTML forms for the absence of anti-CSRF tokens.
type CSRFModule struct{}

func (m *CSRFModule) Name() string { return "Missing CSRF Token" }

// Run filters endpoints for state-changing forms and checks their parameters.
func (m *CSRFModule) Run(ctx context.Context, endpoints []crawler.Endpoint) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	// Heuristic pattern to identify token fields based on standard naming conventions.
	tokenPattern := regexp.MustCompile(`(?i)(csrf|xsrf|token|authenticity|nonce)`)
	
	// Track which unique forms we've already flagged to avoid duplicates if 
	// the crawler gives us identical forms on the same page.
	flaggedForms := make(map[string]bool)

	for _, ep := range endpoints {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		// Only inspect forms that perform state-changing actions
		if ep.Source != "Form" {
			continue
		}
		
		method := strings.ToUpper(ep.Method)
		if method == "GET" || method == "HEAD" || method == "OPTIONS" {
			// GET forms (like search bars) generally don't need CSRF tokens
			continue
		}

		// Create a unique key for this form submission to avoid duplicates
		formKey := ep.URL + "|" + method + "|" + strings.Join(ep.Params, ",")
		if flaggedForms[formKey] {
			continue
		}

		// Check if any parameter name matches our token heuristic
		hasToken := false
		for _, param := range ep.Params {
			if tokenPattern.MatchString(param) {
				hasToken = true
				break
			}
		}

		if !hasToken {
			flaggedForms[formKey] = true
			
			// Format evidence string
			evidence := "State-changing form does not contain an anti-CSRF token parameter."

			detail := ""
			if len(ep.Params) > 0 {
				detail = strings.Join(ep.Params, ", ")
			}

			findings = append(findings, scanner.Finding{
				Title:          "Missing Anti-CSRF Token",
				Severity:       scanner.High,
				OWASP:          descriptions.GetCategory(descriptions.CSRFTokenMissing),
				Description:    descriptions.GetDescription(descriptions.CSRFTokenMissing),
				URL:            ep.URL,
				Method:         method,
				Evidence:       evidence,
				EndpointDetail: detail,
				Remediation:    "Implement synchronized synchronizer token pattern by returning a unique, cryptographically strong, and unpredictable CSRF token in the HTML form. Note: If this application is an SPA utilizing header-driven tokens (like X-CSRF-Token), ensure they are strictly validated server-side.",
				Timestamp:      time.Now(),
			})
		}
	}

	// Sort findings by severity
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Rank() > findings[j].Rank()
	})

	return findings, nil
}
