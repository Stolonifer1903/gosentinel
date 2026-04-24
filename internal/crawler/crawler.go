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
	URL    string
	Method string
	Params []string
	Source string // "Link", "Form"
}

// Spider manages the crawling process.
type Spider struct {
	BaseURL     *url.URL
	MaxDepth    int
	Visited     map[string]bool
	mu          sync.Mutex
	Endpoints   []Endpoint
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
		BaseURL:  parsed,
		MaxDepth: maxDepth,
		Visited:  make(map[string]bool),
		Sem:      make(chan struct{}, concurrency),
	}, nil
}

// Crawl starts the BFS crawling process.
func (s *Spider) Crawl(ctx context.Context) ([]Endpoint, error) {
	normalizedSeed := s.resolveURL(s.BaseURL.String(), "")
	currentLevel := []string{normalizedSeed}

	s.addEndpoint(Endpoint{
		URL:    normalizedSeed,
		Method: "GET",
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
	s.endpointsMu.Lock()
	defer s.endpointsMu.Unlock()

	// Avoid duplicates in results
	for _, existing := range s.Endpoints {
		if existing.URL == e.URL && existing.Method == e.Method && strings.Join(existing.Params, ",") == strings.Join(e.Params, ",") {
			return
		}
	}
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
							discovered = append(discovered, fullURL)
							s.addEndpoint(Endpoint{
								URL:    fullURL,
								Method: "GET",
								Source: "Link",
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
	params := []string{}

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
			for _, a := range n.Attr {
				if a.Key == "name" && a.Val != "" {
					params = append(params, a.Val)
				}
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

	return Endpoint{
		URL:    resolvedAction,
		Method: method,
		Params: params,
		Source: "Form",
	}
}
