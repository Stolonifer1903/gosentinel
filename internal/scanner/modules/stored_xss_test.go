package modules

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/Stolonifer1903/gosentinel/internal/crawler"
	"github.com/Stolonifer1903/gosentinel/internal/httpclient"
	"github.com/Stolonifer1903/gosentinel/internal/scanner"
)

func TestStoredXSSModule(t *testing.T) {
	ts := newStoredXSSTestServer()
	defer ts.Close()

	client := httpclient.NewClient(ts.Client())
	module := NewStoredXSSModule(client, true)

	t.Run("Canary stored and found on read page", func(t *testing.T) {
		ts.reset()
		endpoints := []crawler.Endpoint{
			{URL: ts.URL + "/post", Method: "POST", Source: "Form", Params: []string{"comment"}},
			{URL: ts.URL + "/view", Method: "GET", Source: "Link"},
		}

		findings, err := module.Run(context.Background(), endpoints)
		if err != nil {
			t.Fatalf("Run failed: %v", err)
		}

		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}

		f := findings[0]
		if f.Title != "Stored Cross-Site Scripting (XSS)" {
			t.Errorf("unexpected title: %s", f.Title)
		}
		if f.Parameter != "comment" {
			t.Errorf("unexpected parameter: %s", f.Parameter)
		}
	})

	t.Run("Dedup works for same canary on multiple read pages", func(t *testing.T) {
		ts.reset()
		endpoints := []crawler.Endpoint{
			{URL: ts.URL + "/post", Method: "POST", Source: "Form", Params: []string{"comment"}},
			{URL: ts.URL + "/view", Method: "GET", Source: "Link"},
			{URL: ts.URL + "/view-dup", Method: "GET", Source: "Link"},
		}

		findings, err := module.Run(context.Background(), endpoints)
		if err != nil {
			t.Fatalf("Run failed: %v", err)
		}

		// One canary, two different read URLs -> two findings according to the plan
		if len(findings) != 2 {
			t.Fatalf("expected 2 findings, got %d", len(findings))
		}
	})

	t.Run("Context cancellation in inject phase", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := module.Run(ctx, []crawler.Endpoint{
			{URL: ts.URL + "/post", Method: "POST", Source: "Form", Params: []string{"comment"}},
		})
		if err != context.Canceled {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	})

	// ── Gap #1: No writable endpoints ─────────────────────────────────────────
	t.Run("No writable endpoints produces zero findings", func(t *testing.T) {
		ts.reset()
		endpoints := []crawler.Endpoint{
			{URL: ts.URL + "/view", Method: "GET", Source: "Link"},
		}

		findings, err := module.Run(context.Background(), endpoints)
		if err != nil {
			t.Fatalf("Run failed: %v", err)
		}
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %d", len(findings))
		}
	})

	// ── Gap #2: Server discards input (false-positive guard) ──────────────────
	t.Run("Server discards input yields zero findings", func(t *testing.T) {
		ts.reset()
		endpoints := []crawler.Endpoint{
			{URL: ts.URL + "/discard-post", Method: "POST", Source: "Form", Params: []string{"comment"}},
			{URL: ts.URL + "/view", Method: "GET", Source: "Link"},
		}

		findings, err := module.Run(context.Background(), endpoints)
		if err != nil {
			t.Fatalf("Run failed: %v", err)
		}
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings (canary discarded), got %d", len(findings))
		}
	})

	// ── Gap #3: Multiple params each produce independent findings ─────────────
	t.Run("Multiple params each produce independent findings", func(t *testing.T) {
		ts.reset()
		endpoints := []crawler.Endpoint{
			{URL: ts.URL + "/multi-post", Method: "POST", Source: "Form", Params: []string{"title", "body"}},
			{URL: ts.URL + "/view", Method: "GET", Source: "Link"},
		}

		findings, err := module.Run(context.Background(), endpoints)
		if err != nil {
			t.Fatalf("Run failed: %v", err)
		}
		if len(findings) != 2 {
			t.Fatalf("expected 2 findings (one per param), got %d", len(findings))
		}

		params := map[string]bool{}
		for _, f := range findings {
			params[f.Parameter] = true
		}
		if !params["title"] || !params["body"] {
			t.Fatalf("expected findings for both 'title' and 'body', got %v", params)
		}
	})

	// ── Gap #4: Finding field assertions ──────────────────────────────────────
	t.Run("Finding fields are correctly populated", func(t *testing.T) {
		ts.reset()
		endpoints := []crawler.Endpoint{
			{URL: ts.URL + "/post", Method: "POST", Source: "Form", Params: []string{"comment"}},
			{URL: ts.URL + "/view", Method: "GET", Source: "Link"},
		}

		findings, err := module.Run(context.Background(), endpoints)
		if err != nil {
			t.Fatalf("Run failed: %v", err)
		}
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}

		f := findings[0]
		if f.Title != "Stored Cross-Site Scripting (XSS)" {
			t.Errorf("Title = %q", f.Title)
		}
		if f.Severity != scanner.High {
			t.Errorf("Severity = %q, want High", f.Severity)
		}
		if f.Confidence != scanner.ConfirmedConfidence {
			t.Errorf("Confidence = %q, want %q", f.Confidence, scanner.ConfirmedConfidence)
		}
		if f.OWASP != "A03:2021 - Injection" {
			t.Errorf("OWASP = %q, want A03:2021 - Injection", f.OWASP)
		}
		if f.Parameter != "comment" {
			t.Errorf("Parameter = %q, want comment", f.Parameter)
		}
		if f.URL != ts.URL+"/post" {
			t.Errorf("URL = %q, want %s/post", f.URL, ts.URL)
		}
		if f.Method != "POST" {
			t.Errorf("Method = %q, want POST", f.Method)
		}
		if !strings.Contains(f.Evidence, "found unescaped") {
			t.Errorf("Evidence = %q, missing 'found unescaped'", f.Evidence)
		}
		if !strings.Contains(f.EndpointDetail, "Write: POST") {
			t.Errorf("EndpointDetail = %q, missing 'Write: POST'", f.EndpointDetail)
		}
		if !strings.Contains(f.EndpointDetail, "Read:") {
			t.Errorf("EndpointDetail = %q, missing 'Read:'", f.EndpointDetail)
		}
		if f.Remediation == "" {
			t.Errorf("Remediation is empty")
		}
		if f.Timestamp.IsZero() {
			t.Errorf("Timestamp is zero")
		}
	})

	// ── Gap #5: Sweep-phase context cancellation ─────────────────────────────
	t.Run("Sweep phase context cancellation returns error", func(t *testing.T) {
		ts.reset()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		canary := storedXSSCanary(ts.URL+"/post", "POST", "comment")
		canaryIndex := map[string]storedXSSProbe{
			canary: {
				Canary:  canary,
				WriteEp: crawler.Endpoint{URL: ts.URL + "/post", Method: "POST"},
				Param:   "comment",
			},
		}

		_, err := module.sweepPhase(ctx, []crawler.Endpoint{
			{URL: ts.URL + "/view", Method: "GET", Source: "Link"},
		}, canaryIndex)
		if err != context.Canceled {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	})

	// ── Gap #6: Inject-phase HTTP failure ────────────────────────────────────
	t.Run("Inject phase HTTP error yields zero findings", func(t *testing.T) {
		// Create a server and close it immediately to force connection errors.
		errSrv := httptest.NewServer(http.NotFoundHandler())
		errClient := httpclient.NewClient(errSrv.Client())
		errSrv.Close()

		mod := NewStoredXSSModule(errClient, true)
		endpoints := []crawler.Endpoint{
			{URL: errSrv.URL + "/post", Method: "POST", Source: "Form", Params: []string{"x"}},
			{URL: errSrv.URL + "/view", Method: "GET", Source: "Link"},
		}

		findings, err := mod.Run(context.Background(), endpoints)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %d", len(findings))
		}
	})

	// ── Gap #7: Sweep-phase resilience to HTTP errors ────────────────────────
	t.Run("Sweep skips unreachable pages and still reports reachable ones", func(t *testing.T) {
		ts.reset()

		// Manually seed canary so we can control the sweep without
		// depending on inject phase. This lets us add a broken URL
		// that the test-server transport can't reach.
		canary := storedXSSCanary(ts.URL+"/post", "POST", "comment")
		ts.mu.Lock()
		ts.data = append(ts.data, canary)
		ts.mu.Unlock()

		canaryIndex := map[string]storedXSSProbe{
			canary: {
				Canary:  canary,
				WriteEp: crawler.Endpoint{URL: ts.URL + "/post", Method: "POST"},
				Param:   "comment",
			},
		}

		// /hang-up forcibly closes the TCP connection → Submit returns an error.
		// /view works normally and contains the canary.
		endpoints := []crawler.Endpoint{
			{URL: ts.URL + "/hang-up", Method: "GET", Source: "Link"},
			{URL: ts.URL + "/view", Method: "GET", Source: "Link"},
		}

		findings, err := module.sweepPhase(context.Background(), endpoints, canaryIndex)
		if err != nil {
			t.Fatalf("sweepPhase failed: %v", err)
		}
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding from /view despite /hang-up error, got %d", len(findings))
		}
	})
}

func TestStoredXSSConfirmationPrompt(t *testing.T) {
	// Note: t.Parallel() must not be used here since we are mutating os.Stdin

	origStdin := os.Stdin
	defer func() { os.Stdin = origStdin }()

	tests := []struct {
		name        string
		input       string
		wantProceed bool
	}{
		{"Confirm with yes", "yes\n", true},
		{"Confirm with y", "y\n", true},
		{"Reject with no", "no\n", false},
		{"Reject with n", "n\n", false},
		{"Reject with empty", "\n", false},
		{"Reject with EOF", "", false}, // simulates EOF on reading Stdin
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatalf("os.Pipe failed: %v", err)
			}

			os.Stdin = r
			go func() {
				if tt.input != "" {
					w.Write([]byte(tt.input))
				}
				w.Close() // closing writer simulates EOF if no more input
			}()

			mod := NewStoredXSSModule(nil, false)
			proceed, err := mod.awaitConfirmation(context.Background())
			if err != nil {
				t.Fatalf("awaitConfirmation returned error: %v", err)
			}
			if proceed != tt.wantProceed {
				t.Errorf("awaitConfirmation() = %v, want %v", proceed, tt.wantProceed)
			}
		})
	}
}

func TestStoredXSSCanary(t *testing.T) {
	u, m, p := "http://example.com", "POST", "param"
	c1 := storedXSSCanary(u, m, p)
	c2 := storedXSSCanary(u, m, p)

	if c1 != c2 {
		t.Errorf("canaries for same input should be equal")
	}

	if len(c1) != 19 || c1[:3] != "gs-" {
		t.Errorf("invalid canary format: %s", c1)
	}

	c3 := storedXSSCanary(u, m, "other")
	if c1 == c3 {
		t.Errorf("canaries for different inputs should be different")
	}
}

// ── Gap #8: buildStoredXSSFinding unit test ──────────────────────────────────

func TestBuildStoredXSSFinding(t *testing.T) {
	probe := storedXSSProbe{
		Canary:  "gs-aabbccdd",
		WriteEp: crawler.Endpoint{URL: "http://example.com/post", Method: "post"},
		Param:   "comment",
	}

	f := buildStoredXSSFinding(probe, "http://example.com/view", "text/html")

	if f.Title != "Stored Cross-Site Scripting (XSS)" {
		t.Errorf("Title = %q", f.Title)
	}
	if f.Severity != scanner.High {
		t.Errorf("Severity = %q, want High", f.Severity)
	}
	if f.Confidence != scanner.ConfirmedConfidence {
		t.Errorf("Confidence = %q, want %q", f.Confidence, scanner.ConfirmedConfidence)
	}
	if f.OWASP != "A03:2021 - Injection" {
		t.Errorf("OWASP = %q, want A03:2021 - Injection", f.OWASP)
	}
	if f.URL != "http://example.com/post" {
		t.Errorf("URL = %q", f.URL)
	}
	if f.Method != "POST" {
		t.Errorf("Method = %q, want POST (uppercased)", f.Method)
	}
	if f.Parameter != "comment" {
		t.Errorf("Parameter = %q", f.Parameter)
	}

	wantDetail := "Write: POST http://example.com/post (comment) → Read: http://example.com/view | Proof: Canary gs-aabbccdd on http://example.com/view"
	if f.EndpointDetail != wantDetail {
		t.Errorf("EndpointDetail = %q, want %q", f.EndpointDetail, wantDetail)
	}

	wantEvidence := "Canary gs-aabbccdd found unescaped on http://example.com/view"
	if f.Evidence != wantEvidence {
		t.Errorf("Evidence = %q, want %q", f.Evidence, wantEvidence)
	}

	if f.Remediation == "" {
		t.Errorf("Remediation is empty")
	}
	if f.Timestamp.IsZero() {
		t.Errorf("Timestamp is zero")
	}
}

// ── test server ──────────────────────────────────────────────────────────────

type storedXSSTestServer struct {
	*httptest.Server
	data []string
	mu   sync.Mutex
}

func newStoredXSSTestServer() *storedXSSTestServer {
	s := &storedXSSTestServer{}
	mux := http.NewServeMux()

	mux.HandleFunc("/post", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		comment := r.FormValue("comment")
		if comment != "" {
			s.mu.Lock()
			s.data = append(s.data, comment)
			s.mu.Unlock()
		}
		w.WriteHeader(http.StatusCreated)
	})

	mux.HandleFunc("/view", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		fmt.Fprintf(w, "<html><body>")
		for _, d := range s.data {
			fmt.Fprintf(w, "<div>%s</div>", d)
		}
		fmt.Fprintf(w, "</body></html>")
	})

	mux.HandleFunc("/view-dup", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		fmt.Fprintf(w, "<html><body>")
		for _, d := range s.data {
			fmt.Fprintf(w, "<div>%s</div>", d)
		}
		fmt.Fprintf(w, "</body></html>")
	})

	// Accepts POST but never stores — for false-positive guard test.
	mux.HandleFunc("/discard-post", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})

	// Stores ALL non-filler form values — for multi-param test.
	mux.HandleFunc("/multi-post", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		s.mu.Lock()
		for _, values := range r.Form {
			for _, v := range values {
				if v != "" && v != "test" {
					s.data = append(s.data, v)
				}
			}
		}
		s.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	})

	// Forcibly closes the TCP connection — for sweep-phase error resilience test.
	mux.HandleFunc("/hang-up", func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		conn, _, _ := hj.Hijack()
		conn.Close()
	})

	s.Server = httptest.NewServer(mux)
	return s
}

func (s *storedXSSTestServer) reset() {
	s.mu.Lock()
	s.data = nil
	s.mu.Unlock()
}
