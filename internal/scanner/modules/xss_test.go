package modules

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/Stolonifer1903/gosentinel/internal/crawler"
	"github.com/Stolonifer1903/gosentinel/internal/httpclient"
	"github.com/Stolonifer1903/gosentinel/internal/scanner"
)

func TestXSSModule(t *testing.T) {
	ts := newXSSTestServer()
	t.Cleanup(ts.Close)

	module := &XSSModule{Client: httpclient.NewClient(ts.Client())}

	tests := []struct {
		name           string
		endpoints      []crawler.Endpoint
		wantFindings   int
		wantSeverity   scanner.Severity
		wantConfidence string
		wantParameter  string
		wantGrouped    int
		wantEndpoints  int
		wantEvidences  []string
	}{
		{
			name: "GET reflected XSS flagged",
			endpoints: []crawler.Endpoint{
				{URL: ts.URL + "/reflect/get", Method: "GET", Source: "Form", Params: []string{"q"}},
			},
			wantFindings:   1,
			wantSeverity:   scanner.High,
			wantConfidence: "Confirmed",
			wantParameter:  "q",
			wantGrouped:    1,
			wantEndpoints:  1,
			wantEvidences:  []string{"Parameter reflected unescaped in text/html response (HTML body breakout)"},
		},
		{
			name: "POST reflected XSS flagged",
			endpoints: []crawler.Endpoint{
				{URL: ts.URL + "/reflect/post", Method: "POST", Source: "Form", Params: []string{"input"}},
			},
			wantFindings:   1,
			wantSeverity:   scanner.High,
			wantConfidence: "Confirmed",
			wantParameter:  "input",
			wantGrouped:    1,
			wantEndpoints:  1,
			wantEvidences:  []string{"Parameter reflected unescaped in text/html response (HTML body breakout)"},
		},
		{
			name: "Escaped reflection not flagged",
			endpoints: []crawler.Endpoint{
				{URL: ts.URL + "/safe/get", Method: "GET", Source: "Form", Params: []string{"q"}},
			},
			wantFindings:  0,
			wantGrouped:   0,
			wantEndpoints: 0,
		},
		{
			name: "JSON reflection downgraded",
			endpoints: []crawler.Endpoint{
				{URL: ts.URL + "/reflect/json", Method: "GET", Source: "Form", Params: []string{"q"}},
			},
			wantFindings:   1,
			wantSeverity:   scanner.Medium,
			wantConfidence: "Potential",
			wantParameter:  "q",
			wantGrouped:    1,
			wantEndpoints:  1,
			wantEvidences:  []string{"Parameter reflected unescaped in application/json response (HTML body breakout)"},
		},
		{
			name: "Only unsafe param flagged",
			endpoints: []crawler.Endpoint{
				{URL: ts.URL + "/reflect/partial", Method: "GET", Source: "Form", Params: []string{"safe", "unsafe"}},
			},
			wantFindings:   1,
			wantSeverity:   scanner.High,
			wantConfidence: "Confirmed",
			wantParameter:  "unsafe",
			wantGrouped:    1,
			wantEndpoints:  1,
			wantEvidences:  []string{"Parameter reflected unescaped in text/html response (HTML body breakout)"},
		},
		{
			name: "Non-form endpoint ignored",
			endpoints: []crawler.Endpoint{
				{URL: ts.URL + "/reflect/get", Method: "GET", Source: "API", Params: []string{"q"}},
			},
			wantFindings:  0,
			wantGrouped:   0,
			wantEndpoints: 0,
		},
		{
			name:         "Empty endpoints slice",
			endpoints:    []crawler.Endpoint{},
			wantFindings: 0,
			wantGrouped:  0,
		},
		{
			name: "Grouped findings across two URLs",
			endpoints: []crawler.Endpoint{
				{URL: ts.URL + "/reflect/get", Method: "GET", Source: "Form", Params: []string{"q"}},
				{URL: ts.URL + "/reflect/get-alt", Method: "GET", Source: "Form", Params: []string{"q"}},
			},
			wantFindings:   2,
			wantSeverity:   scanner.High,
			wantConfidence: "Confirmed",
			wantParameter:  "q",
			wantGrouped:    1,
			wantEndpoints:  2,
			wantEvidences: []string{
				"Parameter reflected unescaped in text/html response (HTML body breakout)",
				"Parameter reflected unescaped in text/html response (HTML body breakout)",
			},
		},
		{
			name: "Tier 2 fallback yields one finding",
			endpoints: []crawler.Endpoint{
				{URL: ts.URL + "/reflect/fallback", Method: "GET", Source: "Form", Params: []string{"q"}},
			},
			wantFindings:   1,
			wantSeverity:   scanner.High,
			wantConfidence: "Confirmed",
			wantParameter:  "q",
			wantGrouped:    1,
			wantEndpoints:  1,
			wantEvidences:  []string{"Parameter reflected unescaped in text/html response (Encoded javascript URI anchor)"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings, err := module.Run(context.Background(), tt.endpoints)
			if err != nil {
				t.Fatalf("Run returned error: %v", err)
			}

			if len(findings) != tt.wantFindings {
				t.Fatalf("got %d findings, want %d", len(findings), tt.wantFindings)
			}

			grouped := (&scanner.Result{Findings: findings}).Group()
			if len(grouped) != tt.wantGrouped {
				t.Fatalf("got %d grouped findings, want %d", len(grouped), tt.wantGrouped)
			}
			if tt.wantGrouped > 0 && len(grouped[0].Endpoints) != tt.wantEndpoints {
				t.Fatalf("got %d grouped endpoints, want %d", len(grouped[0].Endpoints), tt.wantEndpoints)
			}

			if tt.wantFindings == 0 {
				return
			}

			var gotEvidences []string
			for _, finding := range findings {
				if finding.Title != "Reflected Cross-Site Scripting (XSS)" {
					t.Fatalf("unexpected title %q", finding.Title)
				}
				if finding.Severity != tt.wantSeverity {
					t.Fatalf("got severity %q, want %q", finding.Severity, tt.wantSeverity)
				}
				if finding.Confidence != tt.wantConfidence {
					t.Fatalf("got confidence %q, want %q", finding.Confidence, tt.wantConfidence)
				}
				if finding.Parameter != tt.wantParameter {
					t.Fatalf("got parameter %q, want %q", finding.Parameter, tt.wantParameter)
				}
				gotEvidences = append(gotEvidences, finding.Evidence)
			}

			if len(tt.wantEvidences) > 0 {
				sort.Strings(gotEvidences)
				sort.Strings(tt.wantEvidences)
				for i := range tt.wantEvidences {
					if gotEvidences[i] != tt.wantEvidences[i] {
						t.Fatalf("got evidences %v, want %v", gotEvidences, tt.wantEvidences)
					}
				}
			}
		})
	}

	t.Run("Context cancellation aborts module cleanly", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		findings, err := module.Run(ctx, []crawler.Endpoint{
			{URL: ts.URL + "/reflect/get", Method: "GET", Source: "Form", Params: []string{"q"}},
		})
		if err != context.Canceled {
			t.Fatalf("got error %v, want %v", err, context.Canceled)
		}
		if len(findings) != 0 {
			t.Fatalf("got %d findings, want 0", len(findings))
		}
	})

	t.Run("payload set excludes legacy browser dependent vectors", func(t *testing.T) {
		t.Parallel()

		disallowedFragments := []string{
			"vbscript:",
			"DYNSRC",
			"LOWSRC",
			"expression(",
			"%00",
		}

		for _, payload := range xssPayloads {
			for _, fragment := range disallowedFragments {
				if containsCaseInsensitive(payload.Template, fragment) {
					t.Fatalf("payload %q contains legacy fragment %q", payload.Template, fragment)
				}
			}
		}
	})
}

func TestGroupingKeepsDifferentConfidenceTiersSeparate(t *testing.T) {
	t.Parallel()

	findings := []scanner.Finding{
		{
			Title:       "Reflected Cross-Site Scripting (XSS)",
			Severity:    scanner.High,
			OWASP:       "A03:2021 - Injection",
			Confidence:  "Confirmed",
			Description: "same description",
			URL:         "http://example.com/a",
			Evidence:    "same evidence",
			Remediation: "same remediation",
		},
		{
			Title:       "Reflected Cross-Site Scripting (XSS)",
			Severity:    scanner.High,
			OWASP:       "A03:2021 - Injection",
			Confidence:  "Potential",
			Description: "same description",
			URL:         "http://example.com/b",
			Evidence:    "same evidence",
			Remediation: "same remediation",
		},
	}

	grouped := (&scanner.Result{Findings: findings}).Group()
	if len(grouped) != 2 {
		t.Fatalf("got %d grouped findings, want 2", len(grouped))
	}
}

func TestAnalyseResponse(t *testing.T) {
	probe := xssPayloads[0]

	t.Run("raw reflection is detected", func(t *testing.T) {
		t.Parallel()

		result := analyseResponse(&httpclient.ResponseResult{
			Body:        `<html><body>"><script>alert('gosentinel_q')</script></body></html>`,
			ContentType: "text/html",
		}, "gosentinel_q", "q", probe)

		if !result.Reflected || result.Escaped {
			t.Fatalf("expected reflected=true escaped=false, got %+v", result)
		}
	})

	t.Run("raw SVG reflection is detected", func(t *testing.T) {
		t.Parallel()

		probe := xssPayloads[1]
		result := analyseResponse(&httpclient.ResponseResult{
			Body:        `<html><body><svg/onload=alert('gosentinel_q')></body></html>`,
			ContentType: "text/html",
		}, "gosentinel_q", "q", probe)

		if !result.Reflected || result.Escaped {
			t.Fatalf("expected reflected=true escaped=false, got %+v", result)
		}
	})

	t.Run("escaped reflection is detected", func(t *testing.T) {
		t.Parallel()

		escaped := html.EscapeString(`"><script>alert('gosentinel_q')</script>`)
		result := analyseResponse(&httpclient.ResponseResult{
			Body:        "<html><body>" + escaped + "</body></html>",
			ContentType: "text/html",
		}, "gosentinel_q", "q", probe)

		if !result.Reflected || !result.Escaped {
			t.Fatalf("expected reflected=true escaped=true, got %+v", result)
		}
	})

	t.Run("escaped SVG reflection is detected", func(t *testing.T) {
		t.Parallel()

		probe := xssPayloads[1]
		escaped := html.EscapeString(`<svg/onload=alert('gosentinel_q')>`)
		result := analyseResponse(&httpclient.ResponseResult{
			Body:        "<html><body>" + escaped + "</body></html>",
			ContentType: "text/html",
		}, "gosentinel_q", "q", probe)

		if !result.Reflected || !result.Escaped {
			t.Fatalf("expected reflected=true escaped=true, got %+v", result)
		}
	})

	t.Run("raw encoded anchor reflection is detected", func(t *testing.T) {
		t.Parallel()

		probe := xssPayloads[4]
		result := analyseResponse(&httpclient.ResponseResult{
			Body:        `<html><body><a href="jav&#x61;script:alert('gosentinel_q')">x</a></body></html>`,
			ContentType: "text/html",
		}, "gosentinel_q", "q", probe)

		if !result.Reflected || result.Escaped {
			t.Fatalf("expected reflected=true escaped=false, got %+v", result)
		}
	})

	t.Run("escaped encoded anchor reflection is detected", func(t *testing.T) {
		t.Parallel()

		probe := xssPayloads[4]
		escaped := html.EscapeString(`<a href="jav&#x61;script:alert('gosentinel_q')">x</a>`)
		result := analyseResponse(&httpclient.ResponseResult{
			Body:        "<html><body>" + escaped + "</body></html>",
			ContentType: "text/html",
		}, "gosentinel_q", "q", probe)

		if !result.Reflected || !result.Escaped {
			t.Fatalf("expected reflected=true escaped=true, got %+v", result)
		}
	})

	t.Run("canary only reflection is treated as unescaped", func(t *testing.T) {
		t.Parallel()

		result := analyseResponse(&httpclient.ResponseResult{
			Body:        `<html><body>gosentinel_q</body></html>`,
			ContentType: "text/html",
		}, "gosentinel_q", "q", probe)

		if !result.Reflected || result.Escaped {
			t.Fatalf("expected reflected=true escaped=false, got %+v", result)
		}
	})

	t.Run("no reflection returns clean result", func(t *testing.T) {
		t.Parallel()

		result := analyseResponse(&httpclient.ResponseResult{
			Body:        `<html><body>hello world</body></html>`,
			ContentType: "text/html",
		}, "gosentinel_q", "q", probe)

		if result.Reflected || result.Escaped {
			t.Fatalf("expected reflected=false escaped=false, got %+v", result)
		}
	})
}

func newXSSTestServer() *httptest.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/reflect/get", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body>%s</body></html>", r.URL.Query().Get("q"))
	})

	mux.HandleFunc("/reflect/get-alt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body>%s</body></html>", r.URL.Query().Get("q"))
	})

	mux.HandleFunc("/reflect/post", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body>%s</body></html>", r.FormValue("input"))
	})

	mux.HandleFunc("/safe/get", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body>%s</body></html>", html.EscapeString(r.URL.Query().Get("q")))
	})

	mux.HandleFunc("/reflect/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"result":"%s"}`, r.URL.Query().Get("q"))
	})

	mux.HandleFunc("/reflect/partial", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		safe := html.EscapeString(r.URL.Query().Get("safe"))
		unsafeValue := r.URL.Query().Get("unsafe")
		fmt.Fprintf(w, "<html><body>%s %s</body></html>", safe, unsafeValue)
	})

	mux.HandleFunc("/reflect/fallback", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		value := r.URL.Query().Get("q")
		if strings.Contains(value, "<a href=\"jav&#x61;script:alert('gosentinel_q')\">x</a>") {
			fmt.Fprintf(w, "<html><body>%s</body></html>", value)
			return
		}
		fmt.Fprintf(w, "<html><body>%s</body></html>", html.EscapeString(value))
	})

	return httptest.NewServer(mux)
}

func containsCaseInsensitive(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
