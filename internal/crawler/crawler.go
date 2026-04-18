package crawler

import (
	"fmt"
	"io"
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
func (s *Spider) Crawl() ([]Endpoint, error) {
	currentLevel := []string{s.BaseURL.String()}

	for depth := 0; depth <= s.MaxDepth; depth++ {
		var nextLevel []string
		var nextLevelMu sync.Mutex
		var wg sync.WaitGroup

		for _, link := range currentLevel {
			if s.shouldVisit(link) {
				s.markVisited(link)

				wg.Add(1)
				s.Sem <- struct{}{} // Acquire semaphore

				go func(target string) {
					defer wg.Done()
					defer func() { <-s.Sem }() // Release semaphore

					discoveredLinks, err := s.processURL(target)
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

func (s *Spider) shouldVisit(link string) bool {
	if !s.isInScope(link) {
		return false
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.Visited[link]
}

func (s *Spider) markVisited(link string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Visited[link] = true
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

func (s *Spider) processURL(target string) ([]string, error) {
	resp, err := httpclient.DefaultClient.HTTPClient().Get(target)
	if err != nil {
		return nil, err
	}
	defer func() {
		// Drain and close the body to allow TCP connection reuse
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	if !strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		return nil, nil
	}

	doc, err := html.Parse(resp.Body)
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
						fullURL := s.resolveURL(target, a.Val)
						if fullURL != "" {
							discovered = append(discovered, fullURL)
							// Only add to endpoints if it's in scope
							if s.isInScope(fullURL) {
								s.addEndpoint(Endpoint{
									URL:    fullURL,
									Method: "GET",
									Source: "Link",
								})
							}
						}
					}
				}
			case "form":
				form := s.parseForm(target, n)
				s.addEndpoint(form)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	// Initial crawl of the page
	// We also count the page itself as an endpoint if it's the root
	if target == s.BaseURL.String() {
		s.addEndpoint(Endpoint{
			URL:    target,
			Method: "GET",
			Source: "Seed",
		})
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
	if resolvedAction == "" {
		resolvedAction = baseURL
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
