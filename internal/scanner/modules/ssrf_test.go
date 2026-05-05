package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Stolonifer1903/gosentinel/internal/crawler"
	"github.com/Stolonifer1903/gosentinel/internal/httpclient"
	"github.com/Stolonifer1903/gosentinel/internal/scanner"
	"github.com/Stolonifer1903/gosentinel/internal/scanner/descriptions"
)

func newSSRFTestServer() *httptest.Server {
	mux := http.NewServeMux()

	// Endpoint that reflects internal content if payload matches loopback
	mux.HandleFunc("/proxy/fetch", func(w http.ResponseWriter, r *http.Request) {
		urlStr := r.URL.Query().Get("url")

		if strings.Contains(urlStr, "169.254.169.254") {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(`ami-id: ami-12345\niam/security-credentials/role-name\n`))
			return
		}

		if strings.Contains(urlStr, "127.0.0.1") || strings.Contains(urlStr, "localhost") {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><head><title>apache2 ubuntu default page: it works</title></head></html>`))
			return
		}

		// Status Differential
		if strings.Contains(urlStr, "127.0.0.1:22") {
			w.WriteHeader(http.StatusOK) // "open" port
			w.Write([]byte("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"))
			return
		}
		if strings.Contains(urlStr, "127.0.0.1:65534") {
			w.WriteHeader(http.StatusInternalServerError) // "closed" port
			w.Write([]byte("Connection refused"))
			return
		}

		// Timing Anomaly
		if strings.Contains(urlStr, "192.0.2.1") {
			time.Sleep(3100 * time.Millisecond) // Simulated unroutable timeout
			w.WriteHeader(http.StatusGatewayTimeout)
			w.Write([]byte("Gateway Timeout"))
			return
		}

		// Baseline response
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>Proxy fetched successfully.</body></html>"))
	})

	// Baseline FP Test (always reflects internal marker)
	mux.HandleFunc("/proxy/always-apache", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head><title>apache2 ubuntu default page: it works</title></head></html>`))
	})

	return httptest.NewServer(mux)
}

func TestSSRFModule_Type(t *testing.T) {
	m := &SSRFModule{}
	if m.Type() != scanner.TypeActive {
		t.Errorf("Expected TypeActive, got %v", m.Type())
	}
	if m.Name() != "SSRF" {
		t.Errorf("Expected name 'SSRF', got %q", m.Name())
	}
}

func TestSSRFModule_CloudMetadataReflection(t *testing.T) {
	ts := newSSRFTestServer()
	defer ts.Close()

	// Default has EnableCloudMetadata=false, so we need a custom config
	cfg := DefaultSSRFConfig
	cfg.EnableCloudMetadata = true

	m := &SSRFModule{
		Client: httpclient.NewClient(ts.Client()),
		Config: cfg,
	}

	endpoints := []crawler.Endpoint{
		{URL: ts.URL + "/proxy/fetch", Method: "GET", Params: []string{"url"}},
	}

	findings, err := m.Run(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatalf("Expected cloud metadata SSRF finding, got 0")
	}

	// Should find both the 127.0.0.1 reflection and the cloud metadata reflection
	foundCloud := false
	for _, f := range findings {
		if f.Severity == scanner.Critical && strings.Contains(f.Evidence, "ami-id") {
			foundCloud = true
			if f.Confidence != scanner.ConfirmedConfidence {
				t.Errorf("Expected Confirmed confidence, got %s", f.Confidence)
			}
			if f.OWASP != descriptions.GetCategory(descriptions.SSRFCloudMetadata) {
				t.Errorf("Expected SSRF OWASP category")
			}
		}
	}
	if !foundCloud {
		t.Fatalf("Expected cloud metadata SSRF finding")
	}
}

func TestSSRFModule_InternalIPReflection(t *testing.T) {
	ts := newSSRFTestServer()
	defer ts.Close()

	m := &SSRFModule{
		Client: httpclient.NewClient(ts.Client()),
		Config: DefaultSSRFConfig,
	}

	endpoints := []crawler.Endpoint{
		{URL: ts.URL + "/proxy/fetch", Method: "GET", Params: []string{"url"}},
	}

	findings, err := m.Run(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// Should find the 127.0.0.1 reflection
	if len(findings) == 0 {
		t.Fatalf("Expected internal IP SSRF finding, got 0")
	}

	f := findings[0]
	if f.Severity != scanner.High {
		t.Errorf("Expected High severity, got %s", f.Severity)
	}
	if f.Confidence != scanner.ConfirmedConfidence {
		t.Errorf("Expected Confirmed confidence, got %s", f.Confidence)
	}
	if !strings.Contains(f.Evidence, "<title>apache") {
		t.Errorf("Expected evidence to mention marker '<title>apache', got %q", f.Evidence)
	}
}

func TestSSRFModule_BaselineFP(t *testing.T) {
	ts := newSSRFTestServer()
	defer ts.Close()

	m := &SSRFModule{
		Client: httpclient.NewClient(ts.Client()),
		Config: DefaultSSRFConfig,
	}

	endpoints := []crawler.Endpoint{
		{URL: ts.URL + "/proxy/always-apache", Method: "GET", Params: []string{"url"}},
	}

	findings, err := m.Run(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(findings) != 0 {
		t.Fatalf("Expected 0 findings due to baseline FP check, got %d", len(findings))
	}
}

func TestSSRFModule_StatusDifferential(t *testing.T) {
	ts := newSSRFTestServer()
	defer ts.Close()



	endpoints := []crawler.Endpoint{
		// using 'api' as param so it is considered priority but avoids the '127.0.0.1' content reflection 
		// because our mock server triggers content reflection on 'url' parameter if it contains 127.0.0.1.
		// Wait, the mock server checks r.URL.Query().Get("url").
		// If we use param "api", the mock server gets url="" and falls through to baseline.
		// Let's modify the mock to read the first parameter regardless of name for status/timing tests.
		// Actually, we can just use "url" but we need to ensure the content reflection doesn't trigger first.
		// The mock triggers content reflection if it sees "127.0.0.1" anywhere in urlStr.
		// But our status differential payloads are "127.0.0.1:22" and "127.0.0.1:65534".
		// Oh, the mock checks strings.Contains("127.0.0.1"). So it will trigger content reflection!
		// Let's update the test by creating a specific endpoint just for status diff.
	}
	_ = endpoints // will re-do with a custom mock just for status
}

// Dedicated mock for status differential
func TestSSRFModule_StatusDifferential_Dedicated(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		urlStr := r.URL.Query().Get("url")
		if strings.Contains(urlStr, "127.0.0.1:22") {
			w.WriteHeader(http.StatusOK)
		} else if strings.Contains(urlStr, "127.0.0.1:65534") {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	m := &SSRFModule{
		Client: httpclient.NewClient(ts.Client()),
		Config: DefaultSSRFConfig,
	}

	endpoints := []crawler.Endpoint{
		{URL: ts.URL + "/", Method: "GET", Params: []string{"url"}},
	}

	findings, err := m.Run(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatalf("Expected status diff SSRF finding, got 0")
	}

	f := findings[0]
	if f.Severity != scanner.High {
		t.Errorf("Expected High severity, got %s", f.Severity)
	}
	if f.Confidence != scanner.MediumConfidence {
		t.Errorf("Expected Medium confidence, got %s", f.Confidence)
	}
	if !strings.Contains(f.Title, "Partial") {
		t.Errorf("Expected Partial title, got %s", f.Title)
	}
}

func TestSSRFModule_TimingAnomaly(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		urlStr := r.URL.Query().Get("url")
		if strings.Contains(urlStr, "192.0.2.1") {
			time.Sleep(3100 * time.Millisecond)
		}
		w.WriteHeader(http.StatusOK)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	m := &SSRFModule{
		Client: httpclient.NewClient(ts.Client()),
		Config: DefaultSSRFConfig,
	}

	endpoints := []crawler.Endpoint{
		{URL: ts.URL + "/", Method: "GET", Params: []string{"url"}},
	}

	findings, err := m.Run(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatalf("Expected timing anomaly SSRF finding, got 0")
	}

	f := findings[0]
	if f.Severity != scanner.Medium {
		t.Errorf("Expected Medium severity, got %s", f.Severity)
	}
	if f.Confidence != scanner.LowConfidence {
		t.Errorf("Expected Low confidence, got %s", f.Confidence)
	}
	if !strings.Contains(f.Title, "Timing Indicator") {
		t.Errorf("Expected Timing Indicator title, got %s", f.Title)
	}
}

func TestSSRFModule_ContextCancellation(t *testing.T) {
	ts := newSSRFTestServer()
	defer ts.Close()

	m := &SSRFModule{
		Client: httpclient.NewClient(ts.Client()),
		Config: DefaultSSRFConfig,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	endpoints := []crawler.Endpoint{
		{URL: ts.URL + "/proxy/fetch", Method: "GET", Params: []string{"url"}},
	}

	findings, err := m.Run(ctx, endpoints)
	if err != context.Canceled {
		t.Fatalf("Expected context.Canceled, got %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("Expected 0 findings")
	}
}

func TestSSRFModule_NoParamsSkipped(t *testing.T) {
	m := &SSRFModule{Config: DefaultSSRFConfig}
	endpoints := []crawler.Endpoint{
		{URL: "http://example.com/", Method: "GET", Params: nil},
	}

	findings, err := m.Run(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("Expected 0 findings")
	}
}

func TestSSRF_BypassVariants(t *testing.T) {
	expected := []string{
		"127.0.0.1",
		"2130706433",
		"0177.0.0.1",
		"0x7f.0x0.0x0.0x1",
		"%31%32%37.0.0.1",
		"attacker.com@127.0.0.1",
		"localtest.me",
	}

	var results []string
	for _, fn := range bypassVariants {
		results = append(results, fn("127.0.0.1"))
	}

	if !reflect.DeepEqual(results, expected) {
		t.Errorf("Bypass variants mismatch.\nExpected: %v\nGot: %v", expected, results)
	}
}
