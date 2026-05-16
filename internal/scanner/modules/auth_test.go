package modules

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Stolonifer1903/gosentinel/internal/crawler"
	"github.com/Stolonifer1903/gosentinel/internal/httpclient"
	"github.com/Stolonifer1903/gosentinel/internal/scanner"
)

// --- 4.1 Forced Browsing Tests ---

func TestForcedBrowsing_AnonClientStripsAuth(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Secret Data")
	}))
	defer ts.Close()

	client := httpclient.NewClientWithAuth(httpclient.DefaultClient.HTTPClient(), map[string]string{"Authorization": "Bearer secret"})
	m := &AuthModule{Client: client, Config: DefaultAuthConfig}
	ep := crawler.Endpoint{Method: "GET", URL: ts.URL + "/admin", Source: "manual"}

	findings, _ := m.Run(context.Background(), []crawler.Endpoint{ep})
	if !hasFinding(findings, "Forced Browsing / Missing Authentication") {
		t.Errorf("Expected Forced Browsing finding, got none. This means AnonClient failed to strip auth (server returned 403) or the logic is broken.")
	}
}

func TestForcedBrowsing_PublicResourceNoFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	m := &AuthModule{Client: httpclient.DefaultClient, Config: DefaultAuthConfig}
	ep := crawler.Endpoint{Method: "GET", URL: ts.URL + "/login.php", Source: "manual"}
	findings, _ := m.Run(context.Background(), []crawler.Endpoint{ep})
	if hasFinding(findings, "Forced Browsing / Missing Authentication") {
		t.Errorf("Expected no finding for public resource")
	}
}

func TestForcedBrowsing_LoginPageBodyNoFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Please login to continue")
	}))
	defer ts.Close()

	m := &AuthModule{Client: httpclient.DefaultClient, Config: DefaultAuthConfig}
	ep := crawler.Endpoint{Method: "GET", URL: ts.URL + "/dashboard", Source: "manual"}
	findings, _ := m.Run(context.Background(), []crawler.Endpoint{ep})
	if hasFinding(findings, "Forced Browsing / Missing Authentication") {
		t.Errorf("Expected no finding because body contains 'login'")
	}
}

func TestForcedBrowsing_SignInBodyNoFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Sign in to your account")
	}))
	defer ts.Close()

	m := &AuthModule{Client: httpclient.DefaultClient, Config: DefaultAuthConfig}
	ep := crawler.Endpoint{Method: "GET", URL: ts.URL + "/dashboard", Source: "manual"}
	findings, _ := m.Run(context.Background(), []crawler.Endpoint{ep})
	if hasFinding(findings, "Forced Browsing / Missing Authentication") {
		t.Errorf("Expected no finding because body contains 'sign in'")
	}
}

func TestForcedBrowsing_Returns401Anon(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	m := &AuthModule{Client: httpclient.DefaultClient, Config: DefaultAuthConfig}
	ep := crawler.Endpoint{Method: "GET", URL: ts.URL + "/admin", Source: "manual"}
	findings, _ := m.Run(context.Background(), []crawler.Endpoint{ep})
	if hasFinding(findings, "Forced Browsing / Missing Authentication") {
		t.Errorf("Expected no finding since anon gets 401")
	}
}

// --- 4.2 Method Tampering Tests ---

func TestMethodTampering_BypassDetected(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.Method == "DELETE" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer ts.Close()

	client := httpclient.NewClientWithAuth(httpclient.DefaultClient.HTTPClient(), map[string]string{"Authorization": "Bearer ok"})
	m := &AuthModule{Client: client, Config: DefaultAuthConfig}
	ep := crawler.Endpoint{Method: "GET", URL: ts.URL + "/resource", Source: "manual"}

	findings, _ := m.Run(context.Background(), []crawler.Endpoint{ep})
	if !hasFinding(findings, "HTTP Method Tampering") {
		t.Errorf("Expected Method Tampering finding")
	}
}

func TestMethodTampering_AnonAlsoSucceeds(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := httpclient.NewClientWithAuth(httpclient.DefaultClient.HTTPClient(), map[string]string{"Authorization": "Bearer ok"})
	m := &AuthModule{Client: client, Config: DefaultAuthConfig}
	ep := crawler.Endpoint{Method: "GET", URL: ts.URL + "/resource", Source: "manual"}

	findings, _ := m.Run(context.Background(), []crawler.Endpoint{ep})
	if hasFinding(findings, "HTTP Method Tampering") {
		t.Errorf("Expected no Method Tampering finding because anon probe also succeeds")
	}
}

func TestMethodTampering_BothFail(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer ts.Close()

	client := httpclient.NewClientWithAuth(httpclient.DefaultClient.HTTPClient(), map[string]string{"Authorization": "Bearer ok"})
	m := &AuthModule{Client: client, Config: DefaultAuthConfig}
	ep := crawler.Endpoint{Method: "GET", URL: ts.URL + "/resource", Source: "manual"}

	findings, _ := m.Run(context.Background(), []crawler.Endpoint{ep})
	if hasFinding(findings, "HTTP Method Tampering") {
		t.Errorf("Expected no finding since both fail")
	}
}

func TestMethodTampering_DeleteReturns204(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.Method == "DELETE" {
			w.WriteHeader(http.StatusNoContent) // 204
		} else {
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer ts.Close()

	client := httpclient.NewClientWithAuth(httpclient.DefaultClient.HTTPClient(), map[string]string{"Authorization": "Bearer ok"})
	m := &AuthModule{Client: client, Config: DefaultAuthConfig}
	ep := crawler.Endpoint{Method: "GET", URL: ts.URL + "/resource", Source: "manual"}

	findings, _ := m.Run(context.Background(), []crawler.Endpoint{ep})
	if !hasFinding(findings, "HTTP Method Tampering") {
		t.Errorf("Expected Method Tampering finding for 204")
	}
}

// --- 4.3 Path Bypass URL construction tests ---

func TestPathBypass_Scenarios(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.URL.Path == "/admin/..;/admin" || r.URL.Path == "/ADMIN" || r.URL.Path == "/admin/%2e%2e/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		
		if r.URL.Path == "/public" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.URL.Path == "/public/..;/public" {
			w.WriteHeader(http.StatusOK)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	m := &AuthModule{
		Client: httpclient.DefaultClient,
		Config: AuthModuleConfig{
			PathTraversalPayloads: []string{"/..;/", "/ADMIN", "/%2e%2e/"},
		},
	}

	// Case 1: Original blocked, bypass works
	ep1 := crawler.Endpoint{Method: "GET", URL: ts.URL + "/admin"}
	findings, _ := m.Run(context.Background(), []crawler.Endpoint{ep1})
	
	// Should flag ONCE because checkPathBypass returns early on the first successful payload
	count := 0
	for _, f := range findings {
		if f.Title == "Path Traversal Auth Bypass" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("Expected 1 bypass finding, got %d", count)
	}

	// Case 2: Original allowed, bypass works -> NO finding
	ep2 := crawler.Endpoint{Method: "GET", URL: ts.URL + "/public"}
	findings2, _ := m.Run(context.Background(), []crawler.Endpoint{ep2})
	if hasFinding(findings2, "Path Traversal Auth Bypass") {
		t.Errorf("Expected NO finding because original was 200 OK")
	}
}

// --- 4.5 Admin endpoint detection tests ---

func TestIsAdminEndpoint(t *testing.T) {
	m := &AuthModule{Config: DefaultAuthConfig}

	testCases := []struct {
		url      string
		expected bool
	}{
		{"https://example.com/admin/users", true},
		{"https://example.com/dashboard", true},
		{"https://example.com/backoffice", true},
		{"https://example.com/control/panel", true},
		{"https://example.com/users/profile", false},
		{"https://example.com/api/v1/data", false},
	}

	for _, tc := range testCases {
		if m.isAdminEndpoint(tc.url) != tc.expected {
			t.Errorf("isAdminEndpoint(%q) = %v, want %v", tc.url, !tc.expected, tc.expected)
		}
	}
}

// --- 4.6 Privilege Escalation config tests ---

func TestPrivEsc_NoRolesEmitsInfoFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	m := &AuthModule{Client: httpclient.DefaultClient, Config: DefaultAuthConfig} // no Roles
	ep := crawler.Endpoint{Method: "GET", URL: ts.URL + "/admin"}
	
	findings, _ := m.Run(context.Background(), []crawler.Endpoint{ep})
	foundInfo := false
	for _, f := range findings {
		if f.Title == "Vertical Privilege Escalation" && f.Severity == scanner.Info {
			foundInfo = true
			break
		}
	}
	if !foundInfo {
		t.Errorf("Expected Info-level finding for unconfigured Roles")
	}
}

func TestPrivEsc_LowPrivAccessesAdminPath(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	roles := []AuthContext{
		{RoleName: "Admin", Headers: map[string]string{"Authorization": "Bearer admin"}},
		{RoleName: "LowPriv", Headers: map[string]string{"Authorization": "Bearer low"}},
	}
	m := &AuthModule{
		Client: httpclient.DefaultClient,
		Config: AuthModuleConfig{
			Roles:         roles,
			AdminPatterns: DefaultAdminPatterns,
		},
	}
	ep := crawler.Endpoint{Method: "GET", URL: ts.URL + "/admin"}
	findings, _ := m.Run(context.Background(), []crawler.Endpoint{ep})
	
	found := false
	for _, f := range findings {
		if f.Title == "Vertical Privilege Escalation" && f.Severity == scanner.High {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected High-severity finding for priv esc")
	}
}

func TestPrivEsc_LowPrivBlockedOnAdminPath(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden) // Blocked!
	}))
	defer ts.Close()

	roles := []AuthContext{
		{RoleName: "Admin", Headers: map[string]string{"Authorization": "Bearer admin"}},
		{RoleName: "LowPriv", Headers: map[string]string{"Authorization": "Bearer low"}},
	}
	m := &AuthModule{
		Client: httpclient.DefaultClient,
		Config: AuthModuleConfig{
			Roles:         roles,
			AdminPatterns: DefaultAdminPatterns,
		},
	}
	ep := crawler.Endpoint{Method: "GET", URL: ts.URL + "/admin"}
	findings, _ := m.Run(context.Background(), []crawler.Endpoint{ep})
	
	if hasFinding(findings, "Vertical Privilege Escalation") {
		t.Errorf("Expected NO finding because low priv got 403")
	}
}

// --- 4.7 JWT extraction tests ---

func TestExtractJWT_BearerHeader(t *testing.T) {
	client := httpclient.NewClientWithAuth(nil, map[string]string{"Authorization": "Bearer abc.def.ghi"})
	k, v := extractJWT(client)
	if k != "Authorization" || v != "abc.def.ghi" {
		t.Errorf("Expected (Authorization, abc.def.ghi), got (%q, %q)", k, v)
	}
}

func TestExtractJWT_JWTCookie(t *testing.T) {
	client := httpclient.NewClientWithAuth(nil, map[string]string{"Cookie": "session=xyz; jwt=abc.def.ghi"})
	k, v := extractJWT(client)
	if k != "Cookie" || v != "abc.def.ghi" {
		t.Errorf("Expected (Cookie, abc.def.ghi), got (%q, %q)", k, v)
	}
}

func TestExtractJWT_AccessTokenCookie(t *testing.T) {
	client := httpclient.NewClientWithAuth(nil, map[string]string{"Cookie": "access_token=t.t.t; other=1"})
	k, v := extractJWT(client)
	if k != "Cookie" || v != "t.t.t" {
		t.Errorf("Expected (Cookie, t.t.t), got (%q, %q)", k, v)
	}
}

func TestExtractJWT_NoneFound(t *testing.T) {
	client := httpclient.NewClientWithAuth(nil, map[string]string{"Cookie": "session=123"})
	k, v := extractJWT(client)
	if k != "" || v != "" {
		t.Errorf("Expected empty result, got (%q, %q)", k, v)
	}
}

func TestJWTManipulation_EmitsInfoWhenNoToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	m := &AuthModule{Client: httpclient.DefaultClient, Config: DefaultAuthConfig} // Default client has no auth
	ep := crawler.Endpoint{Method: "GET", URL: ts.URL + "/api"}
	
	findings, _ := m.Run(context.Background(), []crawler.Endpoint{ep})
	foundInfo := false
	for _, f := range findings {
		if f.Title == "JWT Token Manipulation" && f.Severity == scanner.Info {
			foundInfo = true
			break
		}
	}
	if !foundInfo {
		t.Errorf("Expected Info-level finding for missing JWT token")
	}
}

// --- Helper ---

func hasFinding(findings []scanner.Finding, title string) bool {
	for _, f := range findings {
		if f.Title == title {
			return true
		}
	}
	return false
}
