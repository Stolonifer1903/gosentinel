package modules

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Stolonifer1903/gosentinel/internal/crawler"
	"github.com/Stolonifer1903/gosentinel/internal/httpclient"
	"github.com/Stolonifer1903/gosentinel/internal/scanner"
)

func TestSQLiModule_Type(t *testing.T) {
	m := &SQLiModule{}
	if m.Type() != scanner.TypeActive {
		t.Errorf("Expected TypeActive, got %v", m.Type())
	}
}

func TestSQLiModule_ErrorBased(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("id")
		if q == "'" {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "You have an error in your SQL syntax; check the manual...")
		} else {
			fmt.Fprint(w, "Welcome to the page")
		}
	}))
	defer ts.Close()

	client := httpclient.NewClient(ts.Client())
	m := &SQLiModule{Client: client}

	endpoints := []crawler.Endpoint{
		{URL: ts.URL, Method: "GET", Params: []string{"id"}, Source: "Link"},
	}

	findings, err := m.Run(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("Expected 1 finding, got %d", len(findings))
	}

	if findings[0].Severity != scanner.High {
		t.Errorf("Expected High severity, got %v", findings[0].Severity)
	}
}

func TestSQLiModule_ErrorBased_BaselineFP(t *testing.T) {
	// Server always returns the error signature, even in baseline
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Our documentation says: You have an error in your SQL syntax is a common error.")
	}))
	defer ts.Close()

	client := httpclient.NewClient(ts.Client())
	m := &SQLiModule{Client: client}

	endpoints := []crawler.Endpoint{
		{URL: ts.URL, Method: "GET", Params: []string{"id"}, Source: "Link"},
	}

	findings, err := m.Run(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("Expected 0 findings due to baseline FP prevention, got %d", len(findings))
	}
}

func TestSQLiModule_TimeBased(t *testing.T) {
	delay := 100 * time.Millisecond // Use short delay for tests
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("id")
		if strings.Contains(q, "SLEEP") {
			time.Sleep(delay)
		}
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	client := httpclient.NewClient(ts.Client())
	m := &SQLiModule{
		Client: client,
		Config: SQLiModuleConfig{
			TimeBasedDelay:   delay,
			TimeBasedTimeout: 500 * time.Millisecond,
			ConfirmTimeBased: false,
		},
	}

	endpoints := []crawler.Endpoint{
		{URL: ts.URL, Method: "GET", Params: []string{"id"}, Source: "Link"},
	}

	findings, err := m.Run(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("Expected 1 finding, got %d", len(findings))
	}

	if findings[0].Severity != scanner.Critical {
		t.Errorf("Expected Critical severity, got %v", findings[0].Severity)
	}
}

func TestSQLiModule_TimeBased_SlowServerFP(t *testing.T) {
	// Server is naturally slow, but doesn't correlate with payload
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	client := httpclient.NewClient(ts.Client())
	m := &SQLiModule{
		Client: client,
		Config: SQLiModuleConfig{
			TimeBasedDelay:   50 * time.Millisecond,
			TimeBasedTimeout: 500 * time.Millisecond,
			ConfirmTimeBased: false,
		},
	}

	endpoints := []crawler.Endpoint{
		{URL: ts.URL, Method: "GET", Params: []string{"id"}, Source: "Link"},
	}

	findings, err := m.Run(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("Expected 0 findings because slow response is baseline, got %d", len(findings))
	}
}

func TestSQLiModule_ContextCancellation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1 * time.Second)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	client := httpclient.NewClient(ts.Client())
	m := &SQLiModule{Client: client}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	endpoints := []crawler.Endpoint{
		{URL: ts.URL, Method: "GET", Params: []string{"id"}, Source: "Link"},
	}

	_, err := m.Run(ctx, endpoints)
	if err != context.Canceled {
		t.Errorf("Expected context.Canceled, got %v", err)
	}
}
