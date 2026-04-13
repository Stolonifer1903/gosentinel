package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Stolonifer1903/gosentinel/internal/crawler"
)

func TestSensitiveModule(t *testing.T) {
	// 1. Setup a mock server that serves "vulnerable" content
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/leak":
			w.Write([]byte(`
				<html>
					<body>
						<!-- AWS_KEY=AKIA1234567812345678 -->
						<p>Deployment successful</p>
					</body>
				</html>
			`))
		case "/safe":
			w.Write([]byte(`<html><body>Welcome</body></html>`))
		case "/trace":
			w.Write([]byte(`
				Error: unexpected character at line 42 in index.php
				Stack trace:
				#0 /var/www/html/index.php(42): do_something()
			`))
		}
	}))
	defer ts.Close()

	// 2. Define endpoints pointing to the mock server
	endpoints := []crawler.Endpoint{
		{URL: ts.URL + "/leak", Method: "GET"},
		{URL: ts.URL + "/safe", Method: "GET"},
		{URL: ts.URL + "/trace", Method: "GET"},
	}

	// 3. Run the module
	mod := &SensitiveModule{}
	findings, err := mod.Run(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Module execution failed: %v", err)
	}

	// 4. Verify findings
	// We expect 2 findings: One for AWS Key and one for Stack Trace
	if len(findings) != 2 {
		t.Errorf("Expected 2 findings, got %d", len(findings))
		for _, f := range findings {
			t.Logf("Finding: %s at %s", f.Title, f.URL)
		}
	}

	foundAWS := false
	foundTrace := false
	for _, f := range findings {
		if f.Title == "Exposed AWS Access Key" {
			foundAWS = true
		}
		if f.Title == "Detailed Error/Stack Trace Exposure" {
			foundTrace = true
		}
	}

	if !foundAWS {
		t.Error("Missing 'Exposed AWS Access Key' finding")
	}
	if !foundTrace {
		t.Error("Missing 'Detailed Error/Stack Trace Exposure' finding")
	}
}

func TestAuditBody(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected []string
	}{
		{
			name:     "AWS Access Key",
			body:     "Secret: AKIAABCDEFGHIJKLMNOP",
			expected: []string{"Exposed AWS Access Key"},
		},
		{
			name:     "RSA Private Key",
			body:     "-----BEGIN RSA PRIVATE KEY----- .... content .... ",
			expected: []string{"Exposed Private Key"},
		},
		{
			name:     "EC Private Key",
			body:     "-----BEGIN EC PRIVATE KEY----- .... content .... ",
			expected: []string{"Exposed Private Key"},
		},
		{
			name:     "OpenSSH Private Key",
			body:     "-----BEGIN OPENSSH PRIVATE KEY----- .... content .... ",
			expected: []string{"Exposed Private Key"},
		},
		{
			name:     "GitHub Token",
			body:     "token = ghp_123456789012345678901234567890123456",
			expected: []string{"Hardcoded GitHub Token"},
		},
		{
			name:     "Directory Listing",
			body:     "<title>Index of /uploads</title>",
			expected: []string{"Directory Listing Enabled"},
		},
		{
			name:     "Mixed Findings",
			body:     "AWS: AKIA1234567812345678 and Trace: exception in thread main",
			expected: []string{"Exposed AWS Access Key", "Detailed Error/Stack Trace Exposure"},
		},
		{
			name:     "False Positive - Short AWS",
			body:     "This is not a key: AKIA123",
			expected: []string{},
		},
		{
			name:     "False Positive - Generic Word",
			body:     "The token of appreciation was great.",
			expected: []string{},
		},
		{
			name:     "Hardcoded Password Pattern",
			body:     `db_password := "SuperSecret123!"`,
			expected: []string{"Potential Hardcoded Credential"},
		},
		{
			name:     "Case Insensitive Password",
			body:     `PASSWD: 'admin123'`,
			expected: []string{"Potential Hardcoded Credential"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := auditBody("http://test.com", tt.body)
			if len(findings) != len(tt.expected) {
				t.Errorf("%s: expected %d findings, got %d", tt.name, len(tt.expected), len(findings))
			}
			// Map results to titles for easier comparison
			titles := make(map[string]bool)
			for _, f := range findings {
				titles[f.Title] = true
			}
			for _, exp := range tt.expected {
				if !titles[exp] {
					t.Errorf("%s: missing expected finding %q", tt.name, exp)
				}
			}
		})
	}
}

func TestDeduplication(t *testing.T) {
	body := `
		Key 1: AKIA1234567812345678
		Key 2: AKIA1234567812345678
		Key 3: AKIA1111111111111111
	`
	findings := auditBody("http://test.com", body)

	// We expect 1 finding of type "Exposed AWS Access Key" per page,
	// but the evidence should contain both unique matches.
	if len(findings) != 1 {
		t.Fatalf("Expected 1 finding for AWS keys (deduplicated), got %d", len(findings))
	}

	finding := findings[0]
	if finding.Title != "Exposed AWS Access Key" {
		t.Errorf("Expected title 'Exposed AWS Access Key', got %q", finding.Title)
	}

	// Finding evidence should contain both unique keys
	if !strings.Contains(finding.Evidence, "AKIA1234567812345678") || !strings.Contains(finding.Evidence, "AKIA1111111111111111") {
		t.Errorf("Evidence missing one of the unique keys: %s", finding.Evidence)
	}
}

func TestEvidenceCleanup(t *testing.T) {
	body := "Error at line 1 in app.go, Error at line 1 in app.go"
	findings := auditBody("http://test.com", body)

	for _, f := range findings {
		if f.Title == "Detailed Error/Stack Trace Exposure" {
			// Evidence should only mention the error once if it's identical
			if strings.Count(f.Evidence, "Error at line 1 in app.go") > 1 {
				t.Errorf("Evidence was not properly deduplicated: %s", f.Evidence)
			}
		}
	}
}
