package modules

import (
	"context"
	"net/http"
	"net/url"
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
	Remediation string
}

// securityHeaderChecks defines the full set of security headers the module audits,
// keyed by lowercase canonical name. CheckIDs are used to look up detailed descriptions.
var securityHeaderChecks = map[string]headerCheckInfo{
	"strict-transport-security": {
		CheckID:     descriptions.HeaderHSTSMissing,
		Severity:    scanner.Medium,
		Remediation: "Add 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload' to all HTTPS responses.",
	},
	"content-security-policy": {
		CheckID:     descriptions.HeaderCSPMissing,
		Severity:    scanner.High,
		Remediation: "Define a strict Content-Security-Policy header. Start with 'default-src 'self'' and add directives as needed.",
	},
	"x-frame-options": {
		CheckID:     descriptions.HeaderXFrameOptionsMissing,
		Severity:    scanner.Medium,
		Remediation: "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent the page from being embedded in iframes.",
	},
	"x-content-type-options": {
		CheckID:     descriptions.HeaderXContentTypeMissing,
		Severity:    scanner.Low,
		Remediation: "Add 'X-Content-Type-Options: nosniff' to instruct browsers not to guess content types.",
	},
	"referrer-policy": {
		CheckID:     descriptions.HeaderReferrerPolicyMissing,
		Severity:    scanner.Low,
		Remediation: "Add 'Referrer-Policy: no-referrer' or 'strict-origin-when-cross-origin'.",
	},
	"permissions-policy": {
		CheckID:     descriptions.HeaderPermissionsPolicyMissing,
		Severity:    scanner.Low,
		Remediation: "Add a 'Permissions-Policy' header to explicitly restrict feature access.",
	},
}

// HeadersModule checks security-relevant HTTP response headers.
type HeadersModule struct{}

func (m *HeadersModule) Name() string { return "Security Headers" }

func (m *HeadersModule) Type() scanner.ModuleType { return scanner.TypePassive }

// Run audits security headers for all discovered endpoints. Headers are fetched
// once per origin (scheme + host) for efficiency, then findings are generated
// for every GET endpoint so that Group() reports the full attack surface.
func (m *HeadersModule) Run(ctx context.Context, endpoints []crawler.Endpoint) ([]scanner.Finding, error) {
	// Pass 1: Fetch headers once per origin. We store a *http.Header (nil = fetch failed).
	originHeaders := make(map[string]http.Header)

	for _, ep := range endpoints {
		if ep.Method != "GET" || ep.IsDestructive {
			continue
		}

		origin := originOf(ep.URL)
		if _, checked := originHeaders[origin]; checked {
			continue
		}

		result, err := httpclient.FetchHeadersWithContext(ctx, ep.URL)
		if err != nil {
			originHeaders[origin] = nil // mark as checked-but-failed
			continue
		}
		originHeaders[origin] = result.Headers
	}

	// Pass 2: Emit ONE finding per origin per missing header.
	// Pick a representative URL: prefer Seed, then first GET endpoint.
	representativeURL := make(map[string]crawler.Endpoint)
	for _, ep := range endpoints {
		if ep.Method != "GET" || ep.IsDestructive {
			continue
		}
		origin := originOf(ep.URL)
		if _, exists := representativeURL[origin]; !exists {
			representativeURL[origin] = ep
		}
		if ep.Source == "Seed" {
			representativeURL[origin] = ep // Seed always wins
		}
	}

	var findings []scanner.Finding
	for origin, ep := range representativeURL {
		headers := originHeaders[origin]
		if headers == nil {
			continue // origin either failed to fetch or was not checked
		}
		findings = append(findings, auditHeaders(ep, headers)...)
	}

	// Sort by severity rank descending.
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Rank() > findings[j].Rank()
	})

	return findings, nil
}

// auditHeaders compares the given headers against the checklist and returns
// one Finding per missing header, with descriptions populated from the central registry.
func auditHeaders(ep crawler.Endpoint, headers http.Header) []scanner.Finding {
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
				Title:          "Missing Security Header: " + canonicalHeader(headerKey),
				Severity:       check.Severity,
				OWASP:          descriptions.GetCategory(check.CheckID),
				Confidence:     scanner.HighConfidence,
				Description:    descriptions.GetDescription(check.CheckID),
				URL:            ep.URL,
				Method:         ep.Method,
				EndpointDetail: ep.Method + " \u00b7 Source: " + ep.Source,
				Evidence:       "Header '" + canonicalHeader(headerKey) + "' was not present in the response.",
				Remediation:    check.Remediation,
				Timestamp:      time.Now(),
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

func originOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Scheme + "://" + u.Host
}
