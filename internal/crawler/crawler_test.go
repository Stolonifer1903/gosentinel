package crawler

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"testing"
)

func TestSpider_DepthControl(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<a href="/page1">Level 1</a>`))
	})
	mux.HandleFunc("/page1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<a href="/page2">Level 2</a>`))
	})
	mux.HandleFunc("/page2", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<a href="/page3">Level 3</a>`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	tests := []struct {
		name          string
		maxDepth      int
		expectedLinks []string
	}{
		{"Depth 0", 0, []string{server.URL, server.URL + "/page1"}},
		{"Depth 1", 1, []string{server.URL, server.URL + "/page1", server.URL + "/page2"}},
		{"Depth 2", 2, []string{server.URL, server.URL + "/page1", server.URL + "/page2", server.URL + "/page3"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := NewSpider(server.URL, tc.maxDepth)
			endpoints, err := s.Crawl()
			if err != nil {
				t.Fatalf("Crawl failed: %v", err)
			}

			var found []string
			for _, e := range endpoints {
				found = append(found, e.URL)
			}
			sort.Strings(found)
			sort.Strings(tc.expectedLinks)

			if !reflect.DeepEqual(found, tc.expectedLinks) {
				t.Errorf("Expected endpoints %v, got %v", tc.expectedLinks, found)
			}
		})
	}
}

func TestSpider_ScopeEnforcement(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`
			<a href="/internal">Internal</a>
			<a href="https://externalside.com">External</a>
			<a href="http://sub.127.0.0.1">Subdomain (if handled as host string)</a>
			<a href="mailto:test@example.com">Email</a>
			<a href="javascript:alert(1)">JS</a>
			<form action="https://outsidesite.com/login" method="POST">
				<input name="user" type="text">
			</form>
		`))
	})
	mux.HandleFunc("/internal", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`OK`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	s, _ := NewSpider(server.URL, 1)
	endpoints, err := s.Crawl()
	if err != nil {
		t.Fatalf("Crawl failed: %v", err)
	}

	for _, e := range endpoints {
		if e.URL == "https://externalside.com" {
			t.Error("Spider included an out-of-scope external link")
		}
		if e.URL == "https://outsidesite.com/login" {
			t.Error("Spider included an out-of-scope form action")
		}
		if e.URL == "mailto:test@example.com" {
			t.Error("Spider included a mailto link")
		}
		if e.URL == "javascript:alert(1)" {
			t.Error("Spider included a javascript link")
		}
	}
}

func TestSpider_FormExtraction(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Test nested inputs, varied cases for method, missing method, missing action
		w.Write([]byte(`
			<!-- Standard login form -->
			<form action="/login" method="poSt">
				<div>
					<input name="username" type="text">
					<span>
						<input name="password" type="password">
					</span>
				</div>
			</form>
			<!-- Form missing action and method (defaults to GET, action to base URL) -->
			<form>
				<input name="search" type="text">
				<textarea name="desc"></textarea>
				<select name="category"></select>
			</form>
		`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	s, _ := NewSpider(server.URL, 0)
	endpoints, err := s.Crawl()
	if err != nil {
		t.Fatalf("Crawl failed: %v", err)
	}

	var forms []Endpoint
	for _, e := range endpoints {
		if e.Source == "Form" {
			forms = append(forms, e)
		}
	}

	if len(forms) != 2 {
		t.Fatalf("Expected 2 forms, found %d", len(forms))
	}

	// Map them by action for easy checking
	formMap := make(map[string]Endpoint)
	for _, f := range forms {
		formMap[f.URL] = f
	}

	// Check the standard form
	loginForm, ok := formMap[server.URL+"/login"]
	if !ok {
		t.Error("Missing /login form")
	} else {
		if loginForm.Method != "POST" {
			t.Errorf("Expected method POST for /login, got %s", loginForm.Method)
		}
		expectedParams := []string{"username", "password"}
		if !reflect.DeepEqual(loginForm.Params, expectedParams) {
			t.Errorf("Expected params %v for /login, got %v", expectedParams, loginForm.Params)
		}
	}

	// Check the implicit form (defaults to current URL, GET)
	implicitForm, ok := formMap[server.URL]
	if !ok {
		t.Error("Missing implicit form (action=current URL)")
	} else {
		if implicitForm.Method != "GET" {
			t.Errorf("Expected method GET for implicit form, got %s", implicitForm.Method)
		}
		expectedParams := []string{"search", "desc", "category"}
		if !reflect.DeepEqual(implicitForm.Params, expectedParams) {
			t.Errorf("Expected params %v for implicit form, got %v", expectedParams, implicitForm.Params)
		}
	}
}

func TestSpider_LinkExtraction(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`
			<a href="/absolute-path">1</a>
			<a href="relative-path">2</a>
			<a href="?query=1">3</a>
			<a href="#fragment">4</a>
		`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	s, _ := NewSpider(server.URL, 0)
	endpoints, err := s.Crawl()
	if err != nil {
		t.Fatalf("Crawl failed: %v", err)
	}

	expectedURLs := map[string]bool{
		server.URL:                  true, // Seed
		server.URL + "/absolute-path": true,
		server.URL + "/relative-path": true,
		server.URL + "?query=1":       true,
		// Fragments are stripped, so "#fragment" resolves to the base URL and deduplicates
	}

	for _, e := range endpoints {
		if e.Source == "Link" || e.Source == "Seed" {
			if !expectedURLs[e.URL] {
				t.Errorf("Unexpected URL extracted: %s", e.URL)
			}
			delete(expectedURLs, e.URL)
		}
	}

	for missing := range expectedURLs {
		t.Errorf("Expected URL not extracted: %s", missing)
	}
}

func TestSpider_Deduplication(t *testing.T) {
	s, _ := NewSpider("http://example.com", 0)

	s.addEndpoint(Endpoint{URL: "http://example.com/test", Method: "GET", Source: "Link"})
	s.addEndpoint(Endpoint{URL: "http://example.com/test", Method: "GET", Source: "Link"})
	s.addEndpoint(Endpoint{URL: "http://example.com/test", Method: "POST", Source: "Form"})

	if len(s.Endpoints) != 2 {
		t.Errorf("Deduplication failed: expected 2 distinct endpoints, got %d", len(s.Endpoints))
	}
}

func TestSpider_ScopeSecurity(t *testing.T) {
	s, _ := NewSpider("http://example.com", 0)

	tests := []struct {
		url     string
		inScope bool
	}{
		{"http://example.com/test", true},
		{"http://sub.example.com/test", true},
		{"http://deeper.sub.example.com/test", true},
		{"http://evil-example.com/test", false}, // Suffix squatting
		{"http://anotherexample.com/test", false},
		{"http://example.com.evil.com/test", false},
	}

	for _, tc := range tests {
		got := s.isInScope(tc.url)
		if got != tc.inScope {
			t.Errorf("isInScope(%q) = %v; want %v", tc.url, got, tc.inScope)
		}
	}
}
