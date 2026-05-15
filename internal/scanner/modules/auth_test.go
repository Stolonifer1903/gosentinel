package modules

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Stolonifer1903/gosentinel/internal/crawler"
	"github.com/Stolonifer1903/gosentinel/internal/httpclient"
)

func TestAuthModule_ForcedBrowsing(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "Admin Dashboard - Secret Data")
		} else {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "Public Page")
		}
	}))
	defer ts.Close()

	m := &AuthModule{
		Client: httpclient.DefaultClient,
		Config: DefaultAuthConfig,
	}

	ep := crawler.Endpoint{
		Method: "GET",
		URL:    ts.URL + "/admin",
		Source: "manual",
	}

	findings, err := m.Run(context.Background(), []crawler.Endpoint{ep})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("Expected a finding for forced browsing on /admin, got none")
	}

	found := false
	for _, f := range findings {
		if f.Title == "Forced Browsing / Missing Authentication" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected Forced Browsing finding in results")
	}
}

func TestAuthModule_MethodTampering(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "Deleted successfully")
		} else {
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer ts.Close()

	m := &AuthModule{
		Client: httpclient.DefaultClient,
		Config: DefaultAuthConfig,
	}

	ep := crawler.Endpoint{
		Method: "GET",
		URL:    ts.URL + "/resource",
		Source: "manual",
	}

	findings, err := m.Run(context.Background(), []crawler.Endpoint{ep})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Title == "HTTP Method Tampering" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected Method Tampering finding when DELETE was accepted")
	}
}

func TestAuthModule_CORS(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	m := &AuthModule{
		Client: httpclient.DefaultClient,
		Config: DefaultAuthConfig,
	}

	ep := crawler.Endpoint{
		Method: "GET",
		URL:    ts.URL + "/api",
		Source: "manual",
	}

	findings, err := m.Run(context.Background(), []crawler.Endpoint{ep})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Title == "CORS Misconfiguration" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected CORS Misconfiguration finding")
	}
}
