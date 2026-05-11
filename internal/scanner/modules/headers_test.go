package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Stolonifer1903/gosentinel/internal/crawler"
	"github.com/Stolonifer1903/gosentinel/internal/scanner"
)

func TestHeadersModule_EmitsOneEntryPerOrigin(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// No security headers returned
		w.Write([]byte("OK"))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	endpoints := []crawler.Endpoint{
		{URL: server.URL + "/", Method: "GET", Source: "Seed"},
		{URL: server.URL + "/a", Method: "GET", Source: "Link"},
		{URL: server.URL + "/b", Method: "GET", Source: "Link"},
		{URL: server.URL + "/form", Method: "POST", Source: "Form"},
	}

	module := &HeadersModule{}
	findings, err := module.Run(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// We have 6 missing security headers
	if len(findings) != len(securityHeaderChecks) {
		t.Fatalf("Expected %d findings, got %d", len(securityHeaderChecks), len(findings))
	}

	res := &scanner.Result{Findings: findings}
	grouped := res.Group()

	if len(grouped) != len(securityHeaderChecks) {
		t.Fatalf("Expected %d grouped findings, got %d", len(securityHeaderChecks), len(grouped))
	}

	for _, g := range grouped {
		if len(g.Endpoints) != 1 {
			t.Errorf("Grouped finding %q has %d endpoints, expected 1", g.Title, len(g.Endpoints))
		}
		if g.Endpoints[0].URL != server.URL {
			t.Errorf("Expected endpoint URL to be %s, got %s", server.URL, g.Endpoints[0].URL)
		}
		if g.Endpoints[0].Detail != "GET \u00b7 Source: Seed" {
			t.Errorf("Expected endpoint source to be Seed, got %s", g.Endpoints[0].Detail)
		}
	}
}

func TestHeadersModule_NoDuplicateURLsInGroup(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	endpoints := []crawler.Endpoint{
		{URL: server.URL + "/vuln", Method: "GET", Source: "Link"},
		{URL: server.URL + "/vuln", Method: "GET", Source: "Form"},
	}

	module := &HeadersModule{}
	findings, err := module.Run(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	res := &scanner.Result{Findings: findings}
	grouped := res.Group()

	for _, g := range grouped {
		if len(g.Endpoints) != 1 {
			t.Errorf("Expected 1 endpoint for %q, got %d", g.Title, len(g.Endpoints))
		}
	}
}

func TestHeadersModule_SkipsFailedOrigins(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	endpoints := []crawler.Endpoint{
		{URL: server.URL + "/", Method: "GET", Source: "Seed"},
		{URL: "http://127.0.0.1:0/", Method: "GET", Source: "Link"}, // Invalid/down server
	}

	module := &HeadersModule{}
	findings, err := module.Run(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	for _, f := range findings {
		if f.URL != server.URL+"/" {
			t.Errorf("Finding URL should only be from working server %s, got %s", server.URL+"/", f.URL)
		}
	}
}
