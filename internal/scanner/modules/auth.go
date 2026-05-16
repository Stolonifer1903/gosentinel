package modules

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Stolonifer1903/gosentinel/internal/crawler"
	"github.com/Stolonifer1903/gosentinel/internal/httpclient"
	"github.com/Stolonifer1903/gosentinel/internal/scanner"
	"github.com/Stolonifer1903/gosentinel/internal/scanner/descriptions"
)

// AuthContext represents a set of credentials (headers/cookies) for a specific role.
type AuthContext struct {
	RoleName string
	Headers  map[string]string
	Cookies  []*http.Cookie
}

// DefaultAdminPatterns is the list of URL path patterns that suggest
// a high-privilege endpoint. Checked case-insensitively.
var DefaultAdminPatterns = []string{
	"/admin", "/manage", "/dashboard", "/backoffice",
	"/control", "/moderator", "/staff", "/superuser",
	"/system", "/config", "/settings", "/api/admin",
}

// AuthModuleConfig defines the detection parameters for the Access Control module.
type AuthModuleConfig struct {
	// Roles provides the authentication contexts for multi-role testing.
	Roles []AuthContext
	// JWTFuzzing enables automated manipulation of JWT tokens.
	JWTFuzzing bool
	// PathTraversalPayloads defines the bypass sequences to test.
	PathTraversalPayloads []string
	// SimilarityThreshold is the Jaccard ratio below which responses are considered different.
	SimilarityThreshold float64
	// AdminPatterns are used to heuristically identify privileged endpoints.
	AdminPatterns []string
}

// DefaultAuthConfig provides sensible defaults for access control scanning.
var DefaultAuthConfig = AuthModuleConfig{
	JWTFuzzing:          true,
	SimilarityThreshold: 0.8,
	PathTraversalPayloads: []string{
		"/..;/",
		"//",
		"/%2e%2e/",
		"/./",
	},
	AdminPatterns: DefaultAdminPatterns,
}

// AuthModule implements scanner.Module for comprehensive Broken Access Control detection.
type AuthModule struct {
	Client *httpclient.Client
	Config AuthModuleConfig
}

func (m *AuthModule) Name() string { return "Access Control" }

func (m *AuthModule) Type() scanner.ModuleType { return scanner.TypeActive }

func (m *AuthModule) Run(ctx context.Context, endpoints []crawler.Endpoint) ([]scanner.Finding, error) {
	client := m.Client
	if client == nil {
		client = httpclient.DefaultClient
	}

	var findings []scanner.Finding
	for _, ep := range endpoints {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		// Single baseline fetch per endpoint, shared by sub-checks
		baseline, baselineErr := client.Submit(httpclient.SubmitRequest{
			Method: ep.Method, URL: ep.URL, Params: ep.Params, Ctx: ctx,
		})

		// Vector 4: Forced Browsing (Missing Auth)
		if f := m.checkForcedBrowsing(ctx, ep, client); f != nil {
			findings = append(findings, *f)
		}

		// Vector 5: HTTP Method Tampering
		if f := m.checkMethodTampering(ctx, ep, client); f != nil {
			findings = append(findings, *f)
		}

		// Vector 8: CORS Misconfiguration
		if f := m.checkCORSMisconfiguration(ctx, ep, client); f != nil {
			findings = append(findings, *f)
		}

		// Vector 7: Path Traversal Bypass
		if f := m.checkPathBypass(ctx, ep, client, baseline, baselineErr); f != nil {
			findings = append(findings, *f)
		}

		// Vector 6: JWT Manipulation
		if fs := m.checkJWTManipulation(ctx, ep, client); len(fs) > 0 {
			findings = append(findings, fs...)
		}

		// Vector 1 & 2: Privilege Escalation
		if fs := m.checkPrivilegeEscalation(ctx, ep, client, baseline, baselineErr); len(fs) > 0 {
			findings = append(findings, fs...)
		}
	}

	return findings, nil
}

func (m *AuthModule) checkPrivilegeEscalation(ctx context.Context, ep crawler.Endpoint, client *httpclient.Client, baseline *httpclient.ResponseResult, baselineErr error) []scanner.Finding {
	if len(m.Config.Roles) < 2 {
		return []scanner.Finding{*m.buildFinding(ep, descriptions.AuthVerticalPrivilegeEscalation,
			scanner.Info, scanner.LowConfidence,
			"Privilege escalation checks require at least 2 roles configured. Provide a low-privilege role via AuthModuleConfig.Roles to enable this check.",
			ep.URL)}
	}

	var findings []scanner.Finding
	user := m.Config.Roles[1]

	headers := make(map[string]string)
	for k, v := range user.Headers {
		headers[k] = v
	}
	if len(user.Cookies) > 0 {
		var cookieParts []string
		for _, c := range user.Cookies {
			cookieParts = append(cookieParts, c.String())
		}
		headers["Cookie"] = strings.Join(cookieParts, "; ")
	}

	resp, err := client.Submit(httpclient.SubmitRequest{
		Method:  ep.Method,
		URL:     ep.URL,
		Params:  ep.Params,
		Headers: headers,
		Ctx:     ctx,
	})
	if err == nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if m.isAdminEndpoint(ep.URL) {
			findings = append(findings, *m.buildFinding(ep, descriptions.AuthVerticalPrivilegeEscalation, scanner.High, scanner.MediumConfidence, fmt.Sprintf("User %q successfully accessed %q.", user.RoleName, ep.URL), ep.URL))
		}
	}

	return findings
}

func (m *AuthModule) checkPathBypass(ctx context.Context, ep crawler.Endpoint, client *httpclient.Client, baseline *httpclient.ResponseResult, baselineErr error) *scanner.Finding {
	parsed, err := url.Parse(ep.URL)
	if err != nil {
		return nil
	}
	originalPath := parsed.Path

	for _, payload := range m.Config.PathTraversalPayloads {
		var bypassPath string
		switch {
		case strings.HasSuffix(payload, "/"):
			bypassPath = strings.TrimRight(originalPath, "/") + payload + strings.TrimLeft(originalPath, "/")
		case strings.HasPrefix(payload, "/") && !strings.Contains(payload, "."):
			segments := strings.Split(strings.TrimRight(originalPath, "/"), "/")
			if len(segments) > 0 {
				segments[len(segments)-1] = strings.TrimLeft(payload, "/")
			}
			bypassPath = strings.Join(segments, "/")
		default:
			bypassPath = strings.TrimRight(originalPath, "/") + payload
		}

		bypassParsed := *parsed
		bypassParsed.Path = bypassPath
		bypassURL := bypassParsed.String()

		resp, err := client.Submit(httpclient.SubmitRequest{
			Method: ep.Method, URL: bypassURL, Params: ep.Params, Ctx: ctx,
		})
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 && (baselineErr != nil || baseline.StatusCode != 200) {
			return m.buildFinding(ep, descriptions.AuthPathTraversalBypass,
				scanner.Medium, scanner.MediumConfidence,
				fmt.Sprintf("Path bypass payload %q succeeded (200). Original path returned %d.", payload, baseline.StatusCode),
				bypassURL)
		}
	}
	return nil
}

func extractJWT(client *httpclient.Client) (string, string) {
	if client == nil || client.DefaultHeaders == nil {
		return "", ""
	}
	for k, v := range client.DefaultHeaders {
		if strings.HasPrefix(strings.ToLower(v), "bearer ") {
			return k, v[7:]
		}
		if strings.EqualFold(k, "cookie") {
			for _, part := range strings.Split(v, ";") {
				part = strings.TrimSpace(part)
				lower := strings.ToLower(part)
				if strings.HasPrefix(lower, "jwt=") || strings.HasPrefix(lower, "token=") || strings.HasPrefix(lower, "access_token=") {
					idx := strings.Index(part, "=")
					return "Cookie", part[idx+1:]
				}
			}
		}
	}
	return "", ""
}

func (m *AuthModule) checkJWTManipulation(ctx context.Context, ep crawler.Endpoint, client *httpclient.Client) []scanner.Finding {
	if !m.Config.JWTFuzzing {
		return nil
	}

	authHeader, jwt := extractJWT(client)
	if jwt == "" {
		// Dedup will take care of emitting this once
		return []scanner.Finding{*m.buildFinding(ep, descriptions.AuthJWTManipulation, scanner.Info, scanner.LowConfidence, "JWT fuzzing enabled but no Bearer token or JWT cookie found in session headers. Configure --header or --cookie with a valid token to enable this check.", ep.URL)}
	}

	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil // Not a standard JWT
	}

	noneHeader := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
	tamperedJWT := noneHeader + "." + parts[1] + "."

	headers := make(map[string]string)
	if strings.EqualFold(authHeader, "cookie") {
		// Replace the specific cookie value in the header
		oldCookie := client.DefaultHeaders[authHeader]
		var newCookieParts []string
		for _, part := range strings.Split(oldCookie, ";") {
			part = strings.TrimSpace(part)
			lower := strings.ToLower(part)
			if strings.HasPrefix(lower, "jwt=") || strings.HasPrefix(lower, "token=") || strings.HasPrefix(lower, "access_token=") {
				idx := strings.Index(part, "=")
				newCookieParts = append(newCookieParts, part[:idx+1]+tamperedJWT)
			} else {
				newCookieParts = append(newCookieParts, part)
			}
		}
		headers[authHeader] = strings.Join(newCookieParts, "; ")
	} else {
		headers[authHeader] = "Bearer " + tamperedJWT
	}

	resp, err := client.Submit(httpclient.SubmitRequest{
		Method: ep.Method, URL: ep.URL, Params: ep.Params, Headers: headers, Ctx: ctx,
	})

	if err == nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if !m.isPublicResource(ep.URL) {
			return []scanner.Finding{*m.buildFinding(ep, descriptions.AuthJWTManipulation, scanner.Critical, scanner.HighConfidence, "Server accepted JWT with 'alg: none'.", ep.URL)}
		}
	}

	return nil
}

func (m *AuthModule) checkForcedBrowsing(ctx context.Context, ep crawler.Endpoint, client *httpclient.Client) *scanner.Finding {
	anonClient := client.AnonClient()
	resp, err := anonClient.Submit(httpclient.SubmitRequest{
		Method: ep.Method, URL: ep.URL, Params: ep.Params, Ctx: ctx,
	})
	if err != nil {
		return nil
	}

	if resp.StatusCode == 200 && !m.isPublicResource(ep.URL) {
		body := strings.ToLower(resp.Body)
		if strings.Contains(body, "login") || strings.Contains(body, "unauthorized") || strings.Contains(body, "access denied") || strings.Contains(body, "sign in") {
			return nil
		}
		return m.buildFinding(ep, descriptions.AuthForcedBrowsing, scanner.High, scanner.MediumConfidence, "Endpoint accessible without authentication credentials.", resp.URL)
	}
	return nil
}

func (m *AuthModule) checkMethodTampering(ctx context.Context, ep crawler.Endpoint, client *httpclient.Client) *scanner.Finding {
	sensitiveMethods := []string{"PUT", "DELETE", "PATCH"}
	if ep.Method == "POST" {
		sensitiveMethods = []string{"PUT", "DELETE"}
	}
	anonClient := client.AnonClient()

	for _, method := range sensitiveMethods {
		anonResp, err := anonClient.Submit(httpclient.SubmitRequest{
			Method: method, URL: ep.URL, Params: ep.Params, Ctx: ctx,
		})
		if err != nil || anonResp.StatusCode < 400 {
			continue
		}

		authResp, err := client.Submit(httpclient.SubmitRequest{
			Method: method, URL: ep.URL, Params: ep.Params, Ctx: ctx,
		})
		if err != nil {
			continue
		}

		if authResp.StatusCode >= 200 && authResp.StatusCode < 300 {
			return m.buildFinding(ep, descriptions.AuthMethodTampering, scanner.High, scanner.HighConfidence, fmt.Sprintf("Method %s returned %d (authenticated) vs %d (unauthenticated).", method, authResp.StatusCode, anonResp.StatusCode), authResp.URL)
		}
	}
	return nil
}

func (m *AuthModule) checkCORSMisconfiguration(ctx context.Context, ep crawler.Endpoint, client *httpclient.Client) *scanner.Finding {
	attackerOrigin := "https://attacker-sentinel.com"
	resp, err := client.Submit(httpclient.SubmitRequest{
		Method: ep.Method, URL: ep.URL, Params: ep.Params, Headers: map[string]string{"Origin": attackerOrigin}, Ctx: ctx,
	})
	if err != nil {
		return nil
	}

	acao := resp.Headers.Get("Access-Control-Allow-Origin")
	acac := resp.Headers.Get("Access-Control-Allow-Credentials")

	if acao == "*" || acao == attackerOrigin {
		if acac == "true" {
			return m.buildFinding(ep, descriptions.AuthCORSMisconfiguration, scanner.High, scanner.HighConfidence, fmt.Sprintf("Overly permissive CORS policy detected with credentials allowed: Access-Control-Allow-Origin: %s", acao), resp.URL)
		} else if acao == "*" {
			return m.buildFinding(ep, descriptions.AuthCORSMisconfiguration, scanner.Medium, scanner.HighConfidence, "Overly permissive CORS policy detected (no credentials): Access-Control-Allow-Origin: *", resp.URL)
		}
	}
	return nil
}

func (m *AuthModule) isAdminEndpoint(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	for _, pattern := range m.Config.AdminPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func (m *AuthModule) isPublicResource(urlStr string) bool {
	publicPatterns := []string{"/login", "/signup", "/public", "/static", "/favicon", ".js", ".css", ".png", ".jpg"}
	for _, p := range publicPatterns {
		if strings.Contains(strings.ToLower(urlStr), p) {
			return true
		}
	}
	return false
}

func (m *AuthModule) buildFinding(ep crawler.Endpoint, checkID descriptions.CheckID, severity scanner.Severity, confidence scanner.Confidence, evidence string, url string) *scanner.Finding {
	return &scanner.Finding{
		Title:          m.getFindingTitle(checkID),
		Severity:       severity,
		OWASP:          descriptions.GetCategory(checkID),
		Confidence:     confidence,
		Description:    descriptions.GetDescription(checkID),
		URL:            url,
		Method:         ep.Method,
		Parameter:      "",
		EndpointDetail: fmt.Sprintf("%s via %s", ep.Method, ep.Source),
		Evidence:       evidence,
		Remediation:    "Implement strict server-side access control checks. Ensure all sensitive endpoints require a valid session and proper authorization for the requested resource and method.",
	}
}

func (m *AuthModule) getFindingTitle(id descriptions.CheckID) string {
	switch id {
	case descriptions.AuthForcedBrowsing:
		return "Forced Browsing / Missing Authentication"
	case descriptions.AuthMethodTampering:
		return "HTTP Method Tampering"
	case descriptions.AuthCORSMisconfiguration:
		return "CORS Misconfiguration"
	case descriptions.AuthJWTManipulation:
		return "JWT Token Manipulation"
	case descriptions.AuthPathTraversalBypass:
		return "Path Traversal Auth Bypass"
	case descriptions.AuthHorizontalPrivilegeEscalation:
		return "Horizontal Privilege Escalation"
	case descriptions.AuthVerticalPrivilegeEscalation:
		return "Vertical Privilege Escalation"
	default:
		return "Broken Access Control"
	}
}
