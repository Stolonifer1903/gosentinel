// Package scanner provides the core vulnerability scanning engine and all
// detection modules. Each module implements the Module interface and returns
// a slice of Finding structs. The Engine orchestrates modules concurrently.
package scanner

import "time"

// Severity represents the risk level of a finding.
type Severity string

const (
	Critical Severity = "Critical"
	High     Severity = "High"
	Medium   Severity = "Medium"
	Low      Severity = "Low"
	Info     Severity = "Info"
)

// severityRank maps severities to a numeric rank for sorting.
var severityRank = map[Severity]int{
	Critical: 5,
	High:     4,
	Medium:   3,
	Low:      2,
	Info:     1,
}

// Finding represents a single discovered vulnerability or security issue.
type Finding struct {
	// Title is a short, human-readable name for the issue.
	Title string
	// Severity is the risk classification.
	Severity Severity
	// OWASP is the relevant OWASP Top 10 category (e.g. "A05:2021").
	OWASP string
	// URL is the affected endpoint.
	URL string
	// Method is the HTTP method used (GET, POST, etc.).
	Method string
	// Parameter is the affected query/form parameter, if applicable.
	Parameter string
	// Evidence is a short snippet showing proof of the issue.
	Evidence string
	// Remediation is actionable advice for the developer.
	Remediation string
	// Timestamp is when the finding was recorded.
	Timestamp time.Time
}

// Rank returns the numeric rank for severity-based sorting.
func (f Finding) Rank() int {
	return severityRank[f.Severity]
}

// GroupedFinding represents a collection of identical findings across multiple endpoints.
type GroupedFinding struct {
	Title       string
	Severity    Severity
	OWASP       string
	Evidence    string
	Remediation string
	Endpoints   []string
}

// Rank returns the numeric rank for severity-based sorting of grouped findings.
func (g GroupedFinding) Rank() int {
	return severityRank[g.Severity]
}
