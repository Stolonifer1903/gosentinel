package scanner

import (
	"context"

	"github.com/Stolonifer1903/gosentinel/internal/crawler"
)

// ModuleType defines the execution phase of a scanner module.
type ModuleType string

const (
	// TypePassive modules do not mutate target state (e.g., headers, CSRF).
	// They can be executed concurrently without interfering with each other.
	TypePassive ModuleType = "passive"
	
	// TypeActive modules inject payloads or mutate target state (e.g., XSS, SQLi).
	// They must be executed sequentially to prevent state-mutation race conditions.
	TypeActive ModuleType = "active"
)

// Module is the interface that every vulnerability scanner must implement.
// Adding a new check is simply creating a new file that satisfies this interface.
type Module interface {
	// Name returns the human-readable name of the module (used in progress output).
	Name() string
	// Type returns the execution category of the module (Passive or Active).
	Type() ModuleType
	// Run executes the check against the given endpoints and returns findings.
	Run(ctx context.Context, endpoints []crawler.Endpoint) ([]Finding, error)
}
