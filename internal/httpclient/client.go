// Package httpclient provides a shared HTTP client used by all scanner modules.
// All network I/O is centralised here so that modules never call net/http directly.
package httpclient

import (
	"context"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const userAgent = "GoSentinel/0.1 (security-scanner)"

// Body is capped at 10 MB. Content beyond this limit is silently truncated.
// Sensitive data patterns in very large responses may be missed.
const maxBodySize = 10 * 1024 * 1024 // 10MB

// HeaderResult holds the response metadata returned after fetching a URL.
type HeaderResult struct {
	URL        string
	StatusCode int
	Status     string
	Headers    http.Header
	Duration   time.Duration
}

// SubmitRequest encapsulates a fully parameterised HTTP request for active injection.
type SubmitRequest struct {
	Method  string
	URL     string
	Params  map[string]string
	Headers map[string]string
	Ctx     context.Context
}

// ResponseResult captures the full HTTP response for analysis by active modules.
type ResponseResult struct {
	URL         string
	StatusCode  int
	Status      string
	Headers     http.Header
	Body        string
	Duration    time.Duration
	FinalURL    string
	ContentType string
}

// Client wraps an http.Client so scanner modules can share request behaviour.
type Client struct {
	httpClient     *http.Client
	// DefaultHeaders are applied to every outgoing request before per-request
	// headers. Used for auth cookies, bearer tokens, and custom headers.
	DefaultHeaders map[string]string
}

// DefaultClient is a pre-configured HTTP client with a sensible timeout and
// a custom User-Agent that identifies the tool.
var DefaultClient = NewClient(&http.Client{
	Timeout: 15 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		// Follow up to 5 redirects, which is enough for most targets.
		if len(via) >= 5 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	},
})

// NewClient creates a Client using the provided http.Client or a default one when nil.
func NewClient(httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &Client{httpClient: httpClient}
}

// NewClientWithAuth creates a Client with default headers applied to every request.
// Use for authenticated scanning where cookies or bearer tokens must be attached.
func NewClientWithAuth(httpClient *http.Client, defaultHeaders map[string]string) *Client {
	c := NewClient(httpClient)
	c.DefaultHeaders = defaultHeaders
	return c
}

// SetDefaultClient replaces the package-level DefaultClient. Call this before
// starting the crawler or scanner so that all code paths (including the
// crawler's implicit use of DefaultClient) pick up auth headers.
func SetDefaultClient(c *Client) {
	DefaultClient = c
}

// HTTPClient exposes the wrapped net/http client for read-only integration points.
func (c *Client) HTTPClient() *http.Client {
	return c.httpClient
}

// Submit performs a parameterised GET or POST request and returns the full response.
func (c *Client) Submit(req SubmitRequest) (*ResponseResult, error) {
	ctx := req.Ctx
	if ctx == nil {
		return nil, fmt.Errorf("httpclient: nil context")
	}

	httpReq, err := buildSubmitRequest(ctx, req)
	if err != nil {
		return nil, err
	}

	// Apply default (auth) headers first, then per-request overrides.
	applyDefaultHeaders(httpReq, c.DefaultHeaders)

	start := time.Now()
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return nil, err
	}
	elapsed := time.Since(start)

	// Ignore the error; if the Content-Type header is malformed or absent,
	// contentType will be an empty string, which is fine for our use case.
	contentType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))

	// FinalURL records the URL of the last request after all redirects.
	// If the HTTP client doesn't expose the final request (e.g. the response
	// was synthesised or resp.Request.URL is nil), we fall back to the
	// original URL so that callers can always do a meaningful comparison:
	finalURL := req.URL
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}

	return &ResponseResult{
		URL:         req.URL,
		StatusCode:  resp.StatusCode,
		Status:      resp.Status,
		Headers:     resp.Header,
		Body:        string(bodyBytes),
		Duration:    elapsed,
		FinalURL:    finalURL,
		ContentType: contentType,
	}, nil
}

func buildSubmitRequest(ctx context.Context, req SubmitRequest) (*http.Request, error) {
	switch strings.ToUpper(req.Method) {
	case http.MethodGet:
		u, err := url.Parse(req.URL)
		if err != nil {
			return nil, err
		}

		query := u.Query()
		for key, value := range req.Params {
			query.Set(key, value)
		}
		u.RawQuery = query.Encode()

		httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		applyHeaders(httpReq, req.Headers)
		return httpReq, nil

	case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
		form := url.Values{}
		for key, value := range req.Params {
			form.Set(key, value)
		}

		httpReq, err := http.NewRequestWithContext(ctx, strings.ToUpper(req.Method), req.URL, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		if len(req.Params) > 0 {
			httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		applyHeaders(httpReq, req.Headers)
		return httpReq, nil

	default:
		return nil, fmt.Errorf("httpclient: unsupported method %q", req.Method)
	}
}

func applyHeaders(req *http.Request, headers map[string]string) {
	req.Header.Set("User-Agent", userAgent)
	for key, value := range headers {
		req.Header.Set(key, value)
	}
}

// applyDefaultHeaders injects the client-level default headers (auth cookies,
// bearer tokens, etc.) onto the request. Per-request headers set by
// applyHeaders will have already been applied via buildSubmitRequest, so
// defaults must not overwrite them — we only set if not already present.
func applyDefaultHeaders(req *http.Request, defaults map[string]string) {
	for key, value := range defaults {
		if req.Header.Get(key) == "" {
			req.Header.Set(key, value)
		}
	}
}

// Fetch performs an HTTP GET against the given URL and returns the full response
// including the body as a string.
func Fetch(url string) (*ResponseResult, error) {
	result, err := DefaultClient.Submit(SubmitRequest{
		Method: http.MethodGet,
		URL:    url,
		Ctx:    context.Background(),
	})
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	return result, nil
}

// FetchHeadersWithContext performs an HTTP GET against the given URL and
// returns the response status code, status text, and all response headers plus
// timing info. The response body is discarded — we only care about headers at
// this stage.
//
// ctx is forwarded into the request so that context cancellation and any
// deadline set by the caller (e.g. a --timeout scan flag) are respected.
// CheckRedirect is honoured because the request goes through DefaultClient's
// underlying http.Client, which carries the redirect policy.
func FetchHeadersWithContext(ctx context.Context, rawURL string) (*HeaderResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)

	// Apply auth headers so the initial status check reflects the
	// authenticated view of the site.
	applyDefaultHeaders(req, DefaultClient.DefaultHeaders)

	start := time.Now()
	resp, err := DefaultClient.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	elapsed := time.Since(start)

	defer func() {
		// Drain and close the body to allow TCP connection reuse.
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	return &HeaderResult{
		URL:        rawURL,
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		Headers:    resp.Header,
		Duration:   elapsed,
	}, nil
}

// FetchHeaders is a convenience wrapper around FetchHeadersWithContext that
// uses context.Background(). Prefer FetchHeadersWithContext when a scan-scoped
// context (with a timeout or cancellation signal) is available.
func FetchHeaders(rawURL string) (*HeaderResult, error) {
	return FetchHeadersWithContext(context.Background(), rawURL)
}
