// Package httpclient provides a shared HTTP client used by all scanner modules.
// All network I/O is centralised here so that modules never call net/http directly.
package httpclient

import (
	"fmt"
	"net/http"
	"time"
)

// HeaderResult holds the response metadata returned after fetching a URL.
type HeaderResult struct {
	URL        string
	StatusCode int
	Status     string
	Headers    http.Header
	Duration   time.Duration
}

// DefaultClient is a pre-configured HTTP client with a sensible timeout and
// a custom User-Agent that identifies the tool.
var DefaultClient = &http.Client{
	Timeout: 15 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		// Follow up to 5 redirects, which is enough for most targets.
		if len(via) >= 5 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	},
}

// FetchHeaders performs an HTTP GET against the given URL and returns the
// response status code, status text, and all response headers plus timing info.
// The response body is discarded — we only care about headers at this stage.
func FetchHeaders(url string) (*HeaderResult, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("User-Agent", "GoSentinel/0.1 (security-scanner)")

	start := time.Now()
	resp, err := DefaultClient.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	return &HeaderResult{
		URL:        url,
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		Headers:    resp.Header,
		Duration:   elapsed,
	}, nil
}
