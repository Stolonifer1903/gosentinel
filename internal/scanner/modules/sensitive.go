package modules

import (
	"context"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Stolonifer1903/gosentinel/internal/crawler"
	"github.com/Stolonifer1903/gosentinel/internal/httpclient"
	"github.com/Stolonifer1903/gosentinel/internal/scanner"
	"github.com/Stolonifer1903/gosentinel/internal/scanner/descriptions"
)

type sensitivePattern struct {
	CheckID  descriptions.CheckID
	Severity scanner.Severity
	Title    string
	Regex    *regexp.Regexp
}

// sensitiveRules defines the full set of regex-based rules for sensitive data exposure.
var sensitiveRules = []sensitivePattern{
	{
		CheckID:  descriptions.SensitiveDataAWSKey,
		Severity: scanner.Critical,
		Title:    "Exposed AWS Access Key",
		Regex:    regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	},
	{
		CheckID:  descriptions.SensitiveDataPrivateKey,
		Severity: scanner.Critical,
		Title:    "Exposed Private Key",
		Regex:    regexp.MustCompile(`-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----`),
	},
	{
		CheckID:  descriptions.SensitiveDataPassword,
		Severity: scanner.High,
		Title:    "Hardcoded GitHub Token",
		Regex:    regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
	},
	{
		CheckID:  descriptions.SensitiveDataPassword,
		Severity: scanner.High,
		Title:    "Potential Hardcoded Credential",
		Regex:    regexp.MustCompile(`(?i)(?:password|passwd|api_key|secret|token)\s*[:=]+\s*["']([^"']+)["']`),
	},
	{
		CheckID:  descriptions.SensitiveDataStackTrace,
		Severity: scanner.Medium,
		Title:    "Detailed Error/Stack Trace Exposure",
		Regex:    regexp.MustCompile(`(?i)(?:stack[ -]?trace|exception in thread|at [a-z0-9_.]+\([a-z0-9_]\.[a-z0-9_.]+\.go:\d+\)|line \d+ in .+\.php|Traceback \(most recent call last\):)`),
	},
	{
		CheckID:  descriptions.SensitiveDataDirectoryListing,
		Severity: scanner.Medium,
		Title:    "Directory Listing Enabled",
		Regex:    regexp.MustCompile(`(?i)<title>Index of /.*</title>|\[To Parent Directory\]`),
	},
}

// SensitiveModule scans response bodies for leaked secrets using regex patterns.
type SensitiveModule struct{}

func (m *SensitiveModule) Name() string { return "Sensitive Data Exposure" }

func (m *SensitiveModule) Type() scanner.ModuleType { return scanner.TypePassive }

// Run fetches the full body of each discovered endpoint and scans for sensitive patterns.
func (m *SensitiveModule) Run(ctx context.Context, endpoints []crawler.Endpoint) ([]scanner.Finding, error) {
	var findings []scanner.Finding
	checkedURLs := make(map[string]bool)

	for _, ep := range endpoints {
		// Only check GET endpoints for passive body scanning to avoid side effects.
		// Also deduplicate to avoid scanning the same page multiple times.
		if ep.Method != "GET" || checkedURLs[ep.URL] {
			continue
		}

		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		result, err := httpclient.Fetch(ep.URL)
		if err != nil {
			continue
		}
		checkedURLs[ep.URL] = true

		findings = append(findings, auditBody(ep.URL, result.Body)...)
	}

	// Sort findings by severity rank.
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Rank() > findings[j].Rank()
	})

	return findings, nil
}

// auditBody runs all sensitive detection rules against the provided response body.
func auditBody(targetURL, body string) []scanner.Finding {
	var findings []scanner.Finding

	for _, rule := range sensitiveRules {
		matches := rule.Regex.FindAllString(body, -1)
		if len(matches) > 0 {
			// Deduplicate matches within the same page
			uniqueMatches := make(map[string]bool)
			for _, m := range matches {
				// Truncate match if it's too long (e.g. for stack traces)
				if len(m) > 100 {
					m = m[:97] + "..."
				}
				uniqueMatches[m] = true
			}

			evidenceParts := make([]string, 0, len(uniqueMatches))
			for m := range uniqueMatches {
				evidenceParts = append(evidenceParts, m)
			}

			findings = append(findings, scanner.Finding{
				Title:       rule.Title,
				Severity:    rule.Severity,
				OWASP:       descriptions.GetCategory(rule.CheckID),
				Description: descriptions.GetDescription(rule.CheckID),
				URL:         targetURL,
				Method:      "GET",
				Evidence:    "Identified sensitive pattern in response body: " + strings.Join(evidenceParts, ", "),
				Remediation: getRemediation(rule.CheckID),
				Timestamp:   time.Now(),
			})
		}
	}

	return findings
}

// getRemediation returns specific fix advice for sensitive data leaks.
func getRemediation(id descriptions.CheckID) string {
	switch id {
	case descriptions.SensitiveDataAWSKey, descriptions.SensitiveDataPrivateKey:
		return "Immediately revoke the exposed key/token. Regenerate a new version and store it securely (e.g. AWS Secrets Manager, GitHub Secrets). Never commit secrets to source control."
	case descriptions.SensitiveDataPassword:
		return "Remove hardcoded credentials from source code or comments immediately. Rotate any leaked passwords or API keys."
	case descriptions.SensitiveDataStackTrace:
		return "Disable detailed error messages in production. Use generic user-facing alerts and log detailed traces to a secure backend logging system."
	case descriptions.SensitiveDataDirectoryListing:
		return "Disable directory indexing in your web server configuration (e.g., 'Options -Indexes' in Apache or 'autoindex off' in Nginx)."
	default:
		return "Remove the sensitive information from the public-facing response immediately."
	}
}
