package modules

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Stolonifer1903/gosentinel/internal/crawler"
	"github.com/Stolonifer1903/gosentinel/internal/httpclient"
	"github.com/Stolonifer1903/gosentinel/internal/scanner"
)

// securityHeaderChecks defines the full set of security headers the module
// audits, keyed by lowercase canonical name.
var securityHeaderChecks = map[string]headerCheck{
	"strict-transport-security": {
		Description: "HSTS — enforces HTTPS connections",
		Severity:    scanner.Medium,
		OWASP:       "A05:2021 - Security Misconfiguration",
		Remediation: "Add 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload' to all HTTPS responses.",
	},
	"content-security-policy": {
		Description: "CSP — mitigates XSS and data injection attacks",
		Severity:    scanner.High,
		OWASP:       "A05:2021 - Security Misconfiguration",
		Remediation: "Define a strict Content-Security-Policy header. Start with 'default-src \\'self\\'' and add directives as needed.",
	},
	"x-frame-options": {
		Description: "Clickjacking protection",
		Severity:    scanner.Medium,
		OWASP:       "A05:2021 - Security Misconfiguration",
		Remediation: "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent the page from being embedded in iframes.",
	},
	"x-content-type-options": {
		Description: "Prevents MIME-type sniffing",
		Severity:    scanner.Low,
		OWASP:       "A05:2021 - Security Misconfiguration",
		Remediation: "Add 'X-Content-Type-Options: nosniff' to instruct browsers not to guess content types.",
	},
	"referrer-policy": {
		Description: "Controls referrer information leakage",
		Severity:    scanner.Low,
		OWASP:       "A05:2021 - Security Misconfiguration",
		Remediation: "Add 'Referrer-Policy: no-referrer' or 'strict-origin-when-cross-origin'.",
	},
	"permissions-policy": {
		Description: "Restricts access to browser features (camera, geolocation, etc.)",
		Severity:    scanner.Low,
		OWASP:       "A05:2021 - Security Misconfiguration",
		Remediation: "Add a 'Permissions-Policy' header to explicitly restrict feature access.",
	},
}

// headerCheck holds the metadata for a single header rule.
type headerCheck struct {
	Description string
	Severity    scanner.Severity
	OWASP       string
	Remediation string
}

// HeadersModule checks security-relevant HTTP response headers.
type HeadersModule struct{}

func (m *HeadersModule) Name() string { return "Security Headers (A05)" }

// Run fetches the root URL from each unique host in the endpoint list
// and checks for missing or misconfigured security headers.
func (m *HeadersModule) Run(ctx context.Context, endpoints []crawler.Endpoint) ([]scanner.Finding, error) {
	// Deduplicate by host — we only need to check each origin once.
	checkedHosts := make(map[string]bool)
	var findings []scanner.Finding

	for _, ep := range endpoints {
		if checkedHosts[ep.URL] || ep.Method != "GET" {
			continue
		}

		result, err := httpclient.FetchHeaders(ep.URL)
		if err != nil {
			continue
		}
		checkedHosts[ep.URL] = true

		findings = append(findings, auditHeaders(ep.URL, result.Headers)...)
	}

	// Sort by severity rank descending.
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Rank() > findings[j].Rank()
	})

	return findings, nil
}

// auditHeaders compares the given headers against the checklist and returns
// one Finding per missing header.
func auditHeaders(targetURL string, headers http.Header) []scanner.Finding {
	var findings []scanner.Finding

	for headerKey, check := range securityHeaderChecks {
		present := false
		for name := range headers {
			if strings.EqualFold(name, headerKey) {
				present = true
				break
			}
		}

		if !present {
			findings = append(findings, scanner.Finding{
				Title:       "Missing Security Header: " + canonicalHeader(headerKey),
				Severity:    check.Severity,
				OWASP:       check.OWASP,
				URL:         targetURL,
				Method:      "GET",
				Evidence:    "Header '" + canonicalHeader(headerKey) + "' was not present in the response.",
				Remediation: check.Remediation,
				Timestamp:   time.Now(),
			})
		}
	}

	return findings
}

// canonicalHeader converts "content-security-policy" → "Content-Security-Policy".
func canonicalHeader(s string) string {
	parts := strings.Split(s, "-")
	for i, p := range parts {
		if len(p) > 0 {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, "-")
}
