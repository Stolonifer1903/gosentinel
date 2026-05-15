package modules

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/Stolonifer1903/gosentinel/internal/crawler"
	"github.com/Stolonifer1903/gosentinel/internal/httpclient"
	"github.com/Stolonifer1903/gosentinel/internal/scanner"
)

func TestIDORModule_Type(t *testing.T) {
	m := &IDORModule{}
	if m.Name() != "IDOR" {
		t.Errorf("Expected Name() = IDOR, got %s", m.Name())
	}
	if m.Type() != scanner.TypeActive {
		t.Errorf("Expected Type() = active, got %s", m.Type())
	}
}

func TestIDORModule_AdjacentIDReturnsNewData(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if id == "42" {
			fmt.Fprint(w, "User Profile: Alice. Email: alice@example.com. Phone: 123-456.")
		} else if id == "43" {
			fmt.Fprint(w, "User Profile: Bob. Email: bob@example.com. Phone: 789-012.")
		} else {
			fmt.Fprint(w, "User Profile: Anonymous.")
		}
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	m := &IDORModule{
		Client: httpclient.NewClient(ts.Client()),
		Config: DefaultIDORConfig,
	}

	endpoints := []crawler.Endpoint{
		{URL: ts.URL + "/profile", Method: "GET", Params: map[string]string{"id": "42"}, Source: "Link"},
	}

	findings, err := m.Run(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("Expected 1 finding, got %d", len(findings))
	}
	if findings[0].Parameter != "id" {
		t.Errorf("Expected parameter id, got %s", findings[0].Parameter)
	}
}

func TestIDORModule_SameDataNoFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Constant content regardless of ID")
	}))
	defer ts.Close()

	m := &IDORModule{
		Client: httpclient.NewClient(ts.Client()),
		Config: DefaultIDORConfig,
	}

	endpoints := []crawler.Endpoint{
		{URL: ts.URL, Method: "GET", Params: map[string]string{"id": "42"}, Source: "Link"},
	}

	findings, err := m.Run(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("Expected 0 findings for identical bodies, got %d", len(findings))
	}
}

func TestIDORModule_403OnProbe(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if id == "42" {
			fmt.Fprint(w, "Authorized Content")
		} else {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "Access Denied")
		}
	}))
	defer ts.Close()

	m := &IDORModule{
		Client: httpclient.NewClient(ts.Client()),
		Config: DefaultIDORConfig,
	}

	endpoints := []crawler.Endpoint{
		{URL: ts.URL, Method: "GET", Params: map[string]string{"id": "42"}, Source: "Link"},
	}

	findings, err := m.Run(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("Expected 0 findings when server blocks probe, got %d", len(findings))
	}
}

func TestIDORModule_ErrorPageNoFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if id == "42" {
			fmt.Fprint(w, "<html><body><h1>Profile</h1><p>Welcome Alice</p></body></html>")
		} else {
			// Returns a generic success page but with completely different structure
			fmt.Fprint(w, "Success")
		}
	}))
	defer ts.Close()

	m := &IDORModule{
		Client: httpclient.NewClient(ts.Client()),
		Config: DefaultIDORConfig,
	}

	endpoints := []crawler.Endpoint{
		{URL: ts.URL, Method: "GET", Params: map[string]string{"id": "42"}, Source: "Link"},
	}

	findings, err := m.Run(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("Expected 0 findings for very low similarity (error page-like), got %d", len(findings))
	}
}

func TestIDORModule_ContextCancellation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := &IDORModule{Client: httpclient.NewClient(ts.Client())}
	endpoints := []crawler.Endpoint{
		{URL: ts.URL, Method: "GET", Params: map[string]string{"id": "42"}, Source: "Link"},
	}

	_, err := m.Run(ctx, endpoints)
	if err != context.Canceled {
		t.Errorf("Expected context.Canceled, got %v", err)
	}
}

func TestIsIDORCandidate(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{"id", "42", true},
		{"user_id", "1001", true},
		{"uid", "1", true},
		{"UID", "5", true},
		{"orderId", "99", true},
		{"ID_param", "123", true},
		{"page", "1", false},      // blocklisted
		{"limit", "10", false},    // blocklisted
		{"q", "1", false},        // no match pattern
		{"id", "abc", false},      // non-numeric
		{"id", "0", false},        // non-positive
		{"id", "-1", false},       // non-positive
		{"invoice", "500", true},
	}

	for _, tt := range tests {
		got := isIDORCandidate(tt.name, tt.value)
		if got != tt.want {
			t.Errorf("isIDORCandidate(%q, %q) = %v, want %v", tt.name, tt.value, got, tt.want)
		}
	}
}

func TestAdjacentIDs(t *testing.T) {
	tests := []struct {
		base      int
		adjacency int
		want      []int
	}{
		{42, 2, []int{40, 41, 43, 44}},
		{1, 2, []int{2, 3}}, // skips <= 0
		{2, 2, []int{1, 3, 4}},
	}

	for _, tt := range tests {
		got := adjacentIDs(tt.base, tt.adjacency)
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("adjacentIDs(%d, %d) = %v, want %v", tt.base, tt.adjacency, got, tt.want)
		}
	}
}

func TestJaccardSimilarity(t *testing.T) {
	tests := []struct {
		a    []string
		b    []string
		want float64
	}{
		{[]string{"apple", "banana"}, []string{"apple", "banana"}, 1.0},
		{[]string{"apple", "banana"}, []string{"apple", "cherry"}, 0.333}, // intersection {apple}, union {apple, banana, cherry}
		{[]string{"apple"}, []string{"banana"}, 0.0},
		{[]string{}, []string{}, 1.0},
	}

	for _, tt := range tests {
		sa := make(map[string]struct{})
		for _, s := range tt.a {
			sa[s] = struct{}{}
		}
		sb := make(map[string]struct{})
		for _, s := range tt.b {
			sb[s] = struct{}{}
		}
		res := JaccardSimilarity(sa, sb)
		if fmt.Sprintf("%.3f", res) != fmt.Sprintf("%.3f", tt.want) {
			t.Errorf("jaccardSimilarity(%v, %v) = %.3f, want %.3f", tt.a, tt.b, res, tt.want)
		}
	}
}

func TestNormaliseBody(t *testing.T) {
	input := "<html><!-- comment --><body>ID: abcdef1234567890abcdef1234567890 Time: 2023-10-27T10:00:00Z Unix: 1698393600</body></html>"
	got := NormaliseBody(input)
	if strings.Contains(got, "comment") {
		t.Error("Comment not stripped")
	}
	if !strings.Contains(got, "token") {
		t.Error("Hex token not replaced")
	}
	if !strings.Contains(got, "timestamp") {
		t.Error("Timestamps not replaced")
	}
}

func TestTokenise(t *testing.T) {
	input := strings.ToLower("hello world. This is a test! apple, banana.")
	got := Tokenise(input)
	expected := []string{"hello", "world", "this", "is", "test", "apple", "banana"}
	for _, e := range expected {
		if _, ok := got[e]; !ok {
			t.Errorf("Token %q not found", e)
		}
	}
	if len(got) != 7 {
		t.Errorf("Expected 7 tokens, got %d: %v", len(got), got)
	}
}

func TestIDORModule_ParamPreservation(t *testing.T) {
	var capturedParams map[string]string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		id := r.FormValue("id")
		if id != "42" && id != "" {
			capturedParams = make(map[string]string)
			for k, v := range r.Form {
				capturedParams[k] = v[0]
			}
			fmt.Fprint(w, "Different content for ID "+id)
		} else {
			fmt.Fprint(w, "Baseline content")
		}
	}))
	defer ts.Close()

	m := &IDORModule{
		Client: httpclient.NewClient(ts.Client()),
		Config: DefaultIDORConfig,
	}

	endpoints := []crawler.Endpoint{
		{
			URL:    ts.URL,
			Method: "POST",
			Params: map[string]string{"id": "42", "other": "value"},
			Source: "Form",
		},
	}

	_, _ = m.Run(context.Background(), endpoints)

	if capturedParams == nil {
		t.Fatal("No probe request captured")
	}
	if capturedParams["other"] != "value" {
		t.Errorf("Expected 'other' param to be preserved as 'value', got %q", capturedParams["other"])
	}
}
