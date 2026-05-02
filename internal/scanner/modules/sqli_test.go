package modules

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
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

func TestSQLiModule_AllPayloadsTested(t *testing.T) {
	var receivedPayloads []string
	var mu sync.Mutex

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		q := r.URL.Query().Get("q")
		if q != "" && q != "1" { // Ignore baseline default value "1"
			receivedPayloads = append(receivedPayloads, q)
		}
		mu.Unlock()
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
		{URL: ts.URL, Method: "GET", Params: []string{"q"}, Source: "Form"},
	}

	m.Run(context.Background(), endpoints)

	// 4 error payloads + 5 time payloads = 9 distinct payloads
	// (no dedup should block any payload since none trigger a finding)
	mu.Lock()
	defer mu.Unlock()
	if len(receivedPayloads) < 9 {
		t.Errorf("Expected at least 9 payload requests (4 error + 5 time), got %d: %v", len(receivedPayloads), receivedPayloads)
	}
}

func TestSQLiModule_SkipsParamlessEndpoints(t *testing.T) {
	var requestCount int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	client := httpclient.NewClient(ts.Client())
	m := &SQLiModule{Client: client}

	endpoints := []crawler.Endpoint{
		{URL: ts.URL + "/about", Method: "GET", Params: nil, Source: "Link"},
		{URL: ts.URL + "/blog", Method: "GET", Params: nil, Source: "Link"},
	}

	findings, err := m.Run(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("Expected 0 findings for paramless endpoints, got %d", len(findings))
	}
	if atomic.LoadInt32(&requestCount) != 0 {
		t.Errorf("Expected 0 HTTP requests for paramless endpoints, got %d", requestCount)
	}
}

func TestSQLiModule_HeaderInjectionGated(t *testing.T) {
	var headerProbes int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if any of the injection headers (except User-Agent) are present
		for _, header := range injectionHeaders {
			if header == "User-Agent" {
				continue // Client sends User-Agent by default
			}
			if r.Header.Get(header) != "" {
				atomic.AddInt32(&headerProbes, 1)
				break
			}
		}
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	client := httpclient.NewClient(ts.Client())
	endpoints := []crawler.Endpoint{
		{URL: ts.URL, Method: "GET", Params: []string{"id"}, Source: "Link"},
	}

	// 1. Run with header injection disabled
	mDisabled := &SQLiModule{
		Client: client,
		Config: SQLiModuleConfig{EnableHeaderInjection: false},
	}
	mDisabled.Run(context.Background(), endpoints)

	if atomic.LoadInt32(&headerProbes) != 0 {
		t.Errorf("Expected 0 header probes with EnableHeaderInjection=false, got %d", headerProbes)
	}

	// 2. Run with header injection enabled
	mEnabled := &SQLiModule{
		Client: client,
		Config: SQLiModuleConfig{EnableHeaderInjection: true},
	}
	mEnabled.Run(context.Background(), endpoints)

	if atomic.LoadInt32(&headerProbes) == 0 {
		t.Errorf("Expected >0 header probes with EnableHeaderInjection=true, got 0")
	}
}

