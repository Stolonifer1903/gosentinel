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
	"github.com/Stolonifer1903/gosentinel/internal/scanner/descriptions"
)

// headerCheckInfo defines the metadata for a single security header check.
// Each header is mapped to its CheckID, severity level, and remediation guidance.
type headerCheckInfo struct {
	CheckID     descriptions.CheckID
	Severity    scanner.Severity
	OWASP       string
	Remediation string
}

// securityHeaderChecks defines the full set of security headers the module audits,
// keyed by lowercase canonical name. CheckIDs are used to look up detailed descriptions.
var securityHeaderChecks = map[string]headerCheckInfo{
	"strict-transport-security": {
		CheckID:     descriptions.HeaderHSTSMissing,
		Severity:    scanner.Medium,
		OWASP:       "A05:2021 - Security Misconfiguration",
		Remediation: "Add 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload' to all HTTPS responses.",
	},
	"content-security-policy": {
		CheckID:     descriptions.HeaderCSPMissing,
		Severity:    scanner.High,
		OWASP:       "A05:2021 - Security Misconfiguration",
		Remediation: "Define a strict Content-Security-Policy header. Start with 'default-src \\'self\\'' and add directives as needed.",
	},
	"x-frame-options": {
		CheckID:     descriptions.HeaderXFrameOptionsMissing,
		Severity:    scanner.Medium,
		OWASP:       "A05:2021 - Security Misconfiguration",
		Remediation: "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent the page from being embedded in iframes.",
	},
	"x-content-type-options": {
		CheckID:     descriptions.HeaderXContentTypeMissing,
		Severity:    scanner.Low,
		OWASP:       "A05:2021 - Security Misconfiguration",
		Remediation: "Add 'X-Content-Type-Options: nosniff' to instruct browsers not to guess content types.",
	},
	"referrer-policy": {
		CheckID:     descriptions.HeaderReferrerPolicyMissing,
		Severity:    scanner.Low,
		OWASP:       "A05:2021 - Security Misconfiguration",
		Remediation: "Add 'Referrer-Policy: no-referrer' or 'strict-origin-when-cross-origin'.",
	},
	"permissions-policy": {
		CheckID:     descriptions.HeaderPermissionsPolicyMissing,
		Severity:    scanner.Low,
		OWASP:       "A05:2021 - Security Misconfiguration",
		Remediation: "Add a 'Permissions-Policy' header to explicitly restrict feature access.",
	},
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
// one Finding per missing header, with descriptions populated from the central registry.
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
				Description: descriptions.GetDescription(check.CheckID),
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
