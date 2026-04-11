package scanner

import (
	"context"

	"github.com/Stolonifer1903/gosentinel/internal/crawler"
)

// Module is the interface that every vulnerability scanner must implement.
// Adding a new check is simply creating a new file that satisfies this interface.
type Module interface {
	// Name returns the human-readable name of the module (used in progress output).
	Name() string
	// Run executes the check against the given endpoints and returns findings.
	Run(ctx context.Context, endpoints []crawler.Endpoint) ([]Finding, error)
}
