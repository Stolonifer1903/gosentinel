package crawler

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/Stolonifer1903/gosentinel/internal/httpclient"
	"golang.org/x/net/html"
)

// Endpoint represents a discovered web resource or form.
type Endpoint struct {
	URL           string
	Method        string
	Params        map[string]string
	Source        string // "Link", "Form"
	IsDestructive bool   // true if the path is known to destroy session state
}

// Spider manages the crawling process.
type Spider struct {
	BaseURL     *url.URL
	MaxDepth    int
	Visited     map[string]bool
	mu          sync.Mutex
	Endpoints   []Endpoint
	endpointIdx map[string]int
	endpointsMu sync.Mutex
	Sem         chan struct{} // Concurrency semaphore
}

// NewSpider creates a new spider instance.
func NewSpider(targetURL string, maxDepth int, concurrency int) (*Spider, error) {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid spider URL: %w", err)
	}

	return &Spider{
		BaseURL:     parsed,
		MaxDepth:    maxDepth,
		Visited:     make(map[string]bool),
		endpointIdx: make(map[string]int),
		Sem:         make(chan struct{}, concurrency),
	}, nil
}

// destructivePaths contains path patterns that are known to destroy server-side
// session state. URLs matching these are discovered but never crawled.
var destructivePaths = []string{
	"/logout", "/logout.php", "/signout", "/sign-out",
	"/log-out", "/logoff", "/logoff.php", "/setup.php",
}

func isDestructivePath(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	p := strings.ToLower(parsed.Path)
	for _, blocked := range destructivePaths {
		if p == blocked || strings.HasSuffix(p, blocked) {
			return true
		}
	}
	return false
}

// normaliseEndpointKey returns a canonical key for deduplication.
// Trailing slashes are stripped (unless it's the root path) so "/path/" and "/path" are the same endpoint.
func normaliseEndpointKey(rawURL, method string) string {
	u := rawURL
	if parsed, err := url.Parse(rawURL); err == nil && parsed.Path != "/" && strings.HasSuffix(u, "/") {
		u = u[:len(u)-1]
	}
	return strings.ToLower(u) + "|" + strings.ToUpper(method)
}

// Crawl starts the BFS crawling process.
func (s *Spider) Crawl(ctx context.Context) ([]Endpoint, error) {
	normalizedSeed := s.resolveURL(s.BaseURL.String(), "")
	currentLevel := []string{normalizedSeed}

	seedBase, seedParams := extractQueryParams(normalizedSeed)
	s.addEndpoint(Endpoint{
		URL:    seedBase,
		Method: "GET",
		Params: seedParams,
		Source: "Seed",
	})

	for depth := 0; depth <= s.MaxDepth; depth++ {
		var nextLevel []string
		var nextLevelMu sync.Mutex
		var wg sync.WaitGroup

		for _, link := range currentLevel {
			if s.shouldVisitAndMark(link) {
				wg.Add(1)
				s.Sem <- struct{}{} // Acquire semaphore

				go func(target string) {
					defer wg.Done()
					defer func() { <-s.Sem }() // Release semaphore

					discoveredLinks, err := s.processURL(ctx, target)
					if err == nil && len(discoveredLinks) > 0 {
						nextLevelMu.Lock()
						nextLevel = append(nextLevel, discoveredLinks...)
						nextLevelMu.Unlock()
					}
				}(link)
			}
		}

		// Wait for all goroutines at this depth to finish
		wg.Wait()

		currentLevel = nextLevel
		if len(currentLevel) == 0 {
			break
		}
	}

	return s.Endpoints, nil
}

func (s *Spider) isInScope(link string) bool {
	parsed, err := url.Parse(link)
	if err != nil {
		return false
	}
	// Stay within exact host OR subdomains (e.g. sub.example.com)
	return parsed.Host == s.BaseURL.Host || strings.HasSuffix(parsed.Host, "."+s.BaseURL.Host)
}

func (s *Spider) shouldVisitAndMark(link string) bool {
	if !s.isInScope(link) {
		return false
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Visited[link] {
		return false
	}
	s.Visited[link] = true
	return true
}

func (s *Spider) addEndpoint(e Endpoint) {
	if e.URL == "" {
		return
	}

	// Normalise trailing slash on stored URL.
	if parsed, err := url.Parse(e.URL); err == nil && parsed.Path != "/" && strings.HasSuffix(e.URL, "/") {
		e.URL = e.URL[:len(e.URL)-1]
	}
	key := normaliseEndpointKey(e.URL, e.Method)

	s.endpointsMu.Lock()
	defer s.endpointsMu.Unlock()

	if idx, exists := s.endpointIdx[key]; exists {
		existing := &s.Endpoints[idx]
		// Upgrade: prefer the entry with more params. If equal, prefer Form (often has better values).
		if len(e.Params) > len(existing.Params) || (len(e.Params) == len(existing.Params) && existing.Source == "Link" && e.Source == "Form") {
			existing.Params = e.Params
			existing.Source = e.Source
		}
		// Ensure destructive flag is persistent
		if e.IsDestructive {
			existing.IsDestructive = true
		}
		return
	}
	s.endpointIdx[key] = len(s.Endpoints)
	s.Endpoints = append(s.Endpoints, e)
}

func (s *Spider) processURL(ctx context.Context, target string) ([]string, error) {
	req := httpclient.SubmitRequest{
		Method: http.MethodGet,
		URL:    target,
		Ctx:    ctx,
	}
	resp, err := httpclient.DefaultClient.Submit(req)
	if err != nil {
		return nil, err
	}

	if !strings.Contains(resp.ContentType, "text/html") {
		return nil, nil
	}

	doc, err := html.Parse(strings.NewReader(resp.Body))
	if err != nil {
		return nil, err
	}

	var discovered []string
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "a":
				for _, a := range n.Attr {
					if a.Key == "href" {
						fullURL := s.resolveURL(resp.FinalURL, a.Val)
						if fullURL != "" && s.isInScope(fullURL) {
							// Use the base URL (no query string) as the crawl target
							// so the visited-set deduplication is query-string-agnostic.
							baseURL, params := extractQueryParams(fullURL)
							isDestructive := isDestructivePath(baseURL)
							if !isDestructive {
								discovered = append(discovered, baseURL)
							}
							s.addEndpoint(Endpoint{
								URL:           baseURL,
								Method:        "GET",
								Params:        params,
								Source:        "Link",
								IsDestructive: isDestructive,
							})
						}
					}
				}
			case "form":
				form := s.parseForm(resp.FinalURL, n)
				s.addEndpoint(form)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)
	return discovered, nil
}

func (s *Spider) resolveURL(base, ref string) string {
	baseURL, _ := url.Parse(base)
	refURL, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	resolved := baseURL.ResolveReference(refURL)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return ""
	}
	// Strip fragments
	resolved.Fragment = ""

	if resolved.Path == "" {
		resolved.Path = "/"
	} else if resolved.Path != "/" && strings.HasSuffix(resolved.Path, "/") {
		resolved.Path = strings.TrimSuffix(resolved.Path, "/")
	}

	return resolved.String()
}

func (s *Spider) parseForm(baseURL string, n *html.Node) Endpoint {
	var action, method string
	params := make(map[string]string)

	for _, a := range n.Attr {
		if a.Key == "action" {
			action = a.Val
		}
		if a.Key == "method" {
			method = strings.ToUpper(a.Val)
		}
	}
	if method == "" {
		method = "GET"
	}

	var extractInputs func(*html.Node)
	extractInputs = func(n *html.Node) {
		if n.Type == html.ElementNode && (n.Data == "input" || n.Data == "textarea" || n.Data == "select") {
			name := ""
			val := ""
			for _, a := range n.Attr {
				if a.Key == "name" {
					name = a.Val
				}
				if a.Key == "value" {
					val = a.Val
				}
			}
			if name != "" {
				params[name] = val
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extractInputs(c)
		}
	}
	extractInputs(n)

	resolvedAction := s.resolveURL(baseURL, action)
	if action == "" {
		resolvedAction = baseURL
	} else if resolvedAction == "" {
		return Endpoint{}
	}

	// Only add forms that are in scope
	if !s.isInScope(resolvedAction) {
		return Endpoint{}
	}

	actionBase, _ := extractQueryParams(resolvedAction)
	return Endpoint{
		URL:           resolvedAction,
		Method:        method,
		Params:        params,
		Source:        "Form",
		IsDestructive: isDestructivePath(actionBase),
	}
}

// extractQueryParams parses a full URL and returns:
//   - the base URL with the query string stripped
//   - a map of query parameter names to their first value
//
// Stripping the query string from the URL keeps the visited-set and endpoint
// deduplication query-agnostic, while the params map is surfaced to active
// modules so they can inject payloads into each parameter individually.
func extractQueryParams(rawURL string) (base string, params map[string]string) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.RawQuery == "" {
		return rawURL, nil
	}

	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return rawURL, nil
	}

	params = make(map[string]string)
	for key, values := range query {
		if len(values) > 0 {
			params[key] = values[0]
		} else {
			params[key] = ""
		}
	}

	parsed.RawQuery = ""
	return parsed.String(), params
}
