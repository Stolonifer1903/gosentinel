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

	type expectedFinding struct {
		Title      string
		Severity   scanner.Severity
		Confidence scanner.Confidence
		Parameter  string
		Evidence   string
	}

	tests := []struct {
		name          string
		endpoints     []crawler.Endpoint
		wantGrouped   int
		wantEndpoints int
		wantFindings  []expectedFinding
	}{
		{
			name: "GET reflected XSS flagged",
			endpoints: []crawler.Endpoint{
				{URL: ts.URL + "/reflect/get", Method: "GET", Source: "Form", Params: []string{"q"}},
			},
			wantGrouped:   1,
			wantEndpoints: 1,
			wantFindings: []expectedFinding{
				{
					Title:      "Reflected Cross-Site Scripting (XSS)",
					Severity:   scanner.High,
					Confidence: scanner.ConfirmedConfidence,
					Parameter:  "q",
					Evidence:   "Parameter reflected unescaped in text/html response (HTML body breakout)",
				},
			},
		},
		{
			name: "POST reflected XSS flagged",
			endpoints: []crawler.Endpoint{
				{URL: ts.URL + "/reflect/post", Method: "POST", Source: "Form", Params: []string{"input"}},
			},
			wantGrouped:   1,
			wantEndpoints: 1,
			wantFindings: []expectedFinding{
				{
					Title:      "Reflected Cross-Site Scripting (XSS)",
					Severity:   scanner.High,
					Confidence: scanner.ConfirmedConfidence,
					Parameter:  "input",
					Evidence:   "Parameter reflected unescaped in text/html response (HTML body breakout)",
				},
			},
		},
		{
			name: "Escaped reflection flagged as potential",
			endpoints: []crawler.Endpoint{
				{URL: ts.URL + "/safe/get", Method: "GET", Source: "Form", Params: []string{"q"}},
			},
			wantGrouped:   1,
			wantEndpoints: 1,
			wantFindings: []expectedFinding{
				{
					Title:      "Potential Reflected XSS (Output Escaped)",
					Severity:   scanner.Low,
					Confidence: scanner.MediumConfidence,
					Parameter:  "q",
					Evidence:   "Parameter reflected with output escaping in text/html response (HTML body breakout). Direct exploitation was not confirmed.",
				},
			},
		},
		{
			name: "JSON reflection downgraded",
			endpoints: []crawler.Endpoint{
				{URL: ts.URL + "/reflect/json", Method: "GET", Source: "Form", Params: []string{"q"}},
			},
			wantGrouped:   1,
			wantEndpoints: 1,
			wantFindings: []expectedFinding{
				{
					Title:      "Reflected Cross-Site Scripting (XSS)",
					Severity:   scanner.Medium,
					Confidence: scanner.MediumConfidence,
					Parameter:  "q",
					Evidence:   "Parameter reflected unescaped in application/json response (HTML body breakout)",
				},
			},
		},
		{
			name: "Both safe and unsafe params flagged appropriately",
			endpoints: []crawler.Endpoint{
				{URL: ts.URL + "/reflect/partial", Method: "GET", Source: "Form", Params: []string{"safe", "unsafe"}},
			},
			wantGrouped:   2,
			wantEndpoints: 1,
			wantFindings: []expectedFinding{
				{
					Title:      "Potential Reflected XSS (Output Escaped)",
					Severity:   scanner.Low,
					Confidence: scanner.MediumConfidence,
					Parameter:  "safe",
					Evidence:   "Parameter reflected with output escaping in text/html response (HTML body breakout). Direct exploitation was not confirmed.",
				},
				{
					Title:      "Reflected Cross-Site Scripting (XSS)",
					Severity:   scanner.High,
					Confidence: scanner.ConfirmedConfidence,
					Parameter:  "unsafe",
					Evidence:   "Parameter reflected unescaped in text/html response (HTML body breakout)",
				},
			},
		},
		{
			// Any endpoint with params is now tested regardless of Source.
			// The old guard (Source == "Form") was too narrow and missed GET link params.
			name: "Non-form endpoint with params is tested",
			endpoints: []crawler.Endpoint{
				{URL: ts.URL + "/reflect/get", Method: "GET", Source: "Link", Params: []string{"q"}},
			},
			wantGrouped:   1,
			wantEndpoints: 1,
			wantFindings: []expectedFinding{
				{
					Title:      "Reflected Cross-Site Scripting (XSS)",
					Severity:   scanner.High,
					Confidence: scanner.ConfirmedConfidence,
					Parameter:  "q",
					Evidence:   "Parameter reflected unescaped in text/html response (HTML body breakout)",
				},
			},
		},
		{
			name:          "Empty endpoints slice",
			endpoints:     []crawler.Endpoint{},
			wantGrouped:   0,
			wantEndpoints: 0,
			wantFindings:  nil,
		},
		{
			name: "Grouped findings across two URLs",
			endpoints: []crawler.Endpoint{
				{URL: ts.URL + "/reflect/get", Method: "GET", Source: "Form", Params: []string{"q"}},
				{URL: ts.URL + "/reflect/get-alt", Method: "GET", Source: "Form", Params: []string{"q"}},
			},
			wantGrouped:   1,
			wantEndpoints: 2,
			wantFindings: []expectedFinding{
				{
					Title:      "Reflected Cross-Site Scripting (XSS)",
					Severity:   scanner.High,
					Confidence: scanner.ConfirmedConfidence,
					Parameter:  "q",
					Evidence:   "Parameter reflected unescaped in text/html response (HTML body breakout)",
				},
				{
					Title:      "Reflected Cross-Site Scripting (XSS)",
					Severity:   scanner.High,
					Confidence: scanner.ConfirmedConfidence,
					Parameter:  "q",
					Evidence:   "Parameter reflected unescaped in text/html response (HTML body breakout)",
				},
			},
		},
		{
			name: "Tier 2 fallback yields one finding",
			endpoints: []crawler.Endpoint{
				{URL: ts.URL + "/reflect/fallback", Method: "GET", Source: "Form", Params: []string{"q"}},
			},
			wantGrouped:   1,
			wantEndpoints: 1,
			wantFindings: []expectedFinding{
				{
					Title:      "Reflected Cross-Site Scripting (XSS)",
					Severity:   scanner.High,
					Confidence: scanner.ConfirmedConfidence,
					Parameter:  "q",
					Evidence:   "Parameter reflected unescaped in text/html response (Encoded javascript URI anchor)",
				},
			},
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

			if len(findings) != len(tt.wantFindings) {
				t.Fatalf("got %d findings, want %d", len(findings), len(tt.wantFindings))
			}

			grouped := (&scanner.Result{Findings: findings}).Group()
			if len(grouped) != tt.wantGrouped {
				t.Fatalf("got %d grouped findings, want %d", len(grouped), tt.wantGrouped)
			}
			if tt.wantGrouped > 0 && len(grouped[0].Endpoints) != tt.wantEndpoints {
				t.Fatalf("got %d grouped endpoints, want %d", len(grouped[0].Endpoints), tt.wantEndpoints)
			}

			if len(tt.wantFindings) == 0 {
				return
			}

			var gotEvidences []string
			var wantEvidences []string

			// We sort both so we can easily compare when there are multiple findings.
			// The structs map exactly if we match them up or just verify the fields exist.
			for _, finding := range findings {
				gotEvidences = append(gotEvidences, finding.Evidence)
			}
			for _, wantF := range tt.wantFindings {
				wantEvidences = append(wantEvidences, wantF.Evidence)
			}

			sort.Strings(gotEvidences)
			sort.Strings(wantEvidences)
			for i := range wantEvidences {
				if gotEvidences[i] != wantEvidences[i] {
					t.Fatalf("got evidences %v, want %v", gotEvidences, wantEvidences)
				}
			}

			// Validate titles, severities, confidences and parameters
			for _, wantF := range tt.wantFindings {
				found := false
				for _, finding := range findings {
					if finding.Evidence == wantF.Evidence &&
						finding.Title == wantF.Title &&
						finding.Severity == wantF.Severity &&
						finding.Confidence == wantF.Confidence &&
						finding.Parameter == wantF.Parameter {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("expected finding %+v not found in actual findings %+v", wantF, findings)
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

func TestGroupingPromotesHighestConfidence(t *testing.T) {
	t.Parallel()

	findings := []scanner.Finding{
		{
			Title:       "Reflected Cross-Site Scripting (XSS)",
			Severity:    scanner.High,
			OWASP:       "A03:2021 - Injection",
			Confidence:  scanner.MediumConfidence,
			Description: "same description",
			URL:         "http://example.com/a",
			Evidence:    "medium evidence",
			Remediation: "same remediation",
		},
		{
			Title:       "Reflected Cross-Site Scripting (XSS)",
			Severity:    scanner.High,
			OWASP:       "A03:2021 - Injection",
			Confidence:  scanner.ConfirmedConfidence,
			Description: "same description",
			URL:         "http://example.com/b",
			Evidence:    "confirmed evidence",
			Remediation: "same remediation",
		},
		{
			Title:       "Reflected Cross-Site Scripting (XSS)",
			Severity:    scanner.High,
			OWASP:       "A03:2021 - Injection",
			Confidence:  scanner.LowConfidence,
			Description: "same description",
			URL:         "http://example.com/c",
			Evidence:    "low evidence",
			Remediation: "same remediation",
		},
	}

	grouped := (&scanner.Result{Findings: findings}).Group()
	if len(grouped) != 1 {
		t.Fatalf("got %d grouped findings, want 1", len(grouped))
	}

	g := grouped[0]
	if g.Confidence != scanner.ConfirmedConfidence {
		t.Errorf("got confidence %q, want %q", g.Confidence, scanner.ConfirmedConfidence)
	}
	if g.Evidence != "confirmed evidence" {
		t.Errorf("got evidence %q, want %q", g.Evidence, "confirmed evidence")
	}
	if len(g.Endpoints) != 3 {
		t.Errorf("got %d endpoints, want 3", len(g.Endpoints))
	}
}

func TestGroupingDoesNotDowngradeConfidence(t *testing.T) {
	t.Parallel()

	findings := []scanner.Finding{
		{
			Title:       "Reflected Cross-Site Scripting (XSS)",
			Severity:    scanner.High,
			OWASP:       "A03:2021 - Injection",
			Confidence:  scanner.ConfirmedConfidence,
			Description: "same description",
			URL:         "http://example.com/a",
			Evidence:    "confirmed evidence",
			Remediation: "same remediation",
		},
		{
			Title:       "Reflected Cross-Site Scripting (XSS)",
			Severity:    scanner.High,
			OWASP:       "A03:2021 - Injection",
			Confidence:  scanner.LowConfidence,
			Description: "same description",
			URL:         "http://example.com/b",
			Evidence:    "low evidence",
			Remediation: "same remediation",
		},
	}

	grouped := (&scanner.Result{Findings: findings}).Group()
	if len(grouped) != 1 {
		t.Fatalf("got %d grouped findings, want 1", len(grouped))
	}

	g := grouped[0]
	if g.Confidence != scanner.ConfirmedConfidence {
		t.Errorf("got confidence %q, want %q", g.Confidence, scanner.ConfirmedConfidence)
	}
	if g.Evidence != "confirmed evidence" {
		t.Errorf("got evidence %q, want %q", g.Evidence, "confirmed evidence")
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

	t.Run("canary only reflection is treated as escaped", func(t *testing.T) {
		t.Parallel()

		result := analyseResponse(&httpclient.ResponseResult{
			Body:        `<html><body>gosentinel_q</body></html>`,
			ContentType: "text/html",
		}, "gosentinel_q", "q", probe)

		if !result.Reflected || !result.Escaped {
			t.Fatalf("expected reflected=true escaped=true, got %+v", result)
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
