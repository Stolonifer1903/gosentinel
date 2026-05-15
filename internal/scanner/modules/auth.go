package modules

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
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

// AuthModuleConfig defines the detection parameters for the Access Control module.
type AuthModuleConfig struct {
	// Roles provides the authentication contexts for multi-role testing.
	Roles []AuthContext
	// IDORRange is the number of adjacent IDs to probe.
	IDORRange int
	// JWTFuzzing enables automated manipulation of JWT tokens.
	JWTFuzzing bool
	// PathTraversalPayloads defines the bypass sequences to test.
	PathTraversalPayloads []string
	// SimilarityThreshold is the Jaccard ratio below which responses are considered different.
	SimilarityThreshold float64
}

// DefaultAuthConfig provides sensible defaults for access control scanning.
var DefaultAuthConfig = AuthModuleConfig{
	IDORRange:           5,
	JWTFuzzing:          true,
	SimilarityThreshold: 0.8,
	PathTraversalPayloads: []string{
		"/..;/",
		"//",
		"/%2e%2e/",
		"/./",
		"/ADMIN", // Case sensitivity
	},
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
		if f := m.checkPathBypass(ctx, ep, client); f != nil {
			findings = append(findings, *f)
		}

		// Vector 6: JWT Manipulation
		if f := m.checkJWTManipulation(ctx, ep, client); f != nil {
			findings = append(findings, *f)
		}

		// Vector 1 & 2: Privilege Escalation
		if fs := m.checkPrivilegeEscalation(ctx, ep, client); len(fs) > 0 {
			findings = append(findings, fs...)
		}

		// Vector 3: IDOR
		if fs := m.checkIDOR(ctx, ep, client); len(fs) > 0 {
			findings = append(findings, fs...)
		}
	}

	return findings, nil
}

func (m *AuthModule) checkPrivilegeEscalation(ctx context.Context, ep crawler.Endpoint, client *httpclient.Client) []scanner.Finding {
	if len(m.Config.Roles) < 2 {
		return nil
	}

	var findings []scanner.Finding
	// We assume the first role in Config.Roles is the 'higher' privilege one if we have only 2.
	// In a real scenario, we'd need metadata about roles.
	user := m.Config.Roles[1]

	// Vertical: Try to access endpoint with low-priv token
	headers := make(map[string]string)
	for k, v := range user.Headers {
		headers[k] = v
	}
	// Note: Cookies should be converted to string if we use Headers map
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
	if err == nil && resp.StatusCode == 200 {
		// If it's an admin endpoint (e.g. /admin), it's a vertical escalation
		if strings.Contains(strings.ToLower(ep.URL), "/admin") || strings.Contains(strings.ToLower(ep.URL), "/manage") {
			findings = append(findings, *m.buildFinding(ep, descriptions.AuthVerticalPrivilegeEscalation, fmt.Sprintf("User %q successfully accessed %q.", user.RoleName, ep.URL), ep.URL))
		}
	}

	return findings
}

func (m *AuthModule) checkIDOR(ctx context.Context, ep crawler.Endpoint, client *httpclient.Client) []scanner.Finding {
	var findings []scanner.Finding
	for param, value := range ep.Params {
		if !m.isIDORCandidate(param, value) {
			continue
		}

		// Baseline
		baseline, err := client.Submit(httpclient.SubmitRequest{
			Method: ep.Method,
			URL:    ep.URL,
			Params: ep.Params,
			Ctx:    ctx,
		})
		if err != nil || baseline.StatusCode != 200 {
			continue
		}
		baselineTokens := Tokenise(NormaliseBody(baseline.Body))

		// Probes
		id, _ := strconv.Atoi(value)
		for i := 1; i <= m.Config.IDORRange; i++ {
			probeID := strconv.Itoa(id + i)
			params := make(map[string]string)
			for k, v := range ep.Params {
				if k == param {
					params[k] = probeID
				} else {
					params[k] = v
				}
			}

			resp, err := client.Submit(httpclient.SubmitRequest{
				Method: ep.Method,
				URL:    ep.URL,
				Params: params,
				Ctx:    ctx,
			})
			if err != nil || resp.StatusCode != 200 {
				continue
			}

			probeTokens := Tokenise(NormaliseBody(resp.Body))
			ratio := JaccardSimilarity(baselineTokens, probeTokens)

			// If ratio is between 0.15 and 0.95, it's likely a different record (IDOR)
			if ratio >= 0.15 && ratio < m.Config.SimilarityThreshold {
				findings = append(findings, *m.buildFinding(ep, descriptions.IDORNumericIDAccess, fmt.Sprintf("IDOR detected on parameter %q. Adjacent value %q returned a successful but distinct response (Similarity: %.1f%%).", param, probeID, ratio*100), ep.URL))
				break
			}
		}
	}
	return findings
}

func (m *AuthModule) isIDORCandidate(name, value string) bool {
	pattern := regexp.MustCompile(`(?i)(^id$|_id$|^id_|uid|pid|cid|ref|record|account|order|ticket|invoice)`)
	if !pattern.MatchString(name) {
		return false
	}
	_, err := strconv.Atoi(value)
	return err == nil
}

func (m *AuthModule) checkPathBypass(ctx context.Context, ep crawler.Endpoint, client *httpclient.Client) *scanner.Finding {
	for _, payload := range m.Config.PathTraversalPayloads {
		// Construct bypass URL
		// e.g. /admin -> /admin/../admin
		bypassURL := strings.TrimRight(ep.URL, "/") + payload
		if strings.HasSuffix(payload, "/") {
			bypassURL = strings.TrimRight(ep.URL, "/") + payload + strings.TrimLeft(ep.URL, "/")
		}

		resp, err := client.Submit(httpclient.SubmitRequest{
			Method: ep.Method,
			URL:    bypassURL,
			Params: ep.Params,
			Ctx:    ctx,
		})
		if err != nil {
			continue
		}

		// If the original URL was protected (we assume if it's in endpoints it might have been)
		// but the bypass works, it's a finding.
		// For a more robust check, we'd compare Response(Original) vs Response(Bypass)
		if resp.StatusCode == 200 && !m.isPublicResource(ep.URL) {
			return m.buildFinding(ep, descriptions.AuthPathTraversalBypass, fmt.Sprintf("Path bypass detected using payload %q. URL: %s", payload, bypassURL), bypassURL)
		}
	}
	return nil
}

func (m *AuthModule) checkJWTManipulation(ctx context.Context, ep crawler.Endpoint, client *httpclient.Client) *scanner.Finding {
	if !m.Config.JWTFuzzing {
		return nil
	}

	// 1. Try to find a JWT in headers (Authorization: Bearer <jwt>)
	// First check client default headers
	jwt := ""
	authHeader := ""
	if client != nil {
		for k, v := range client.DefaultHeaders {
			if strings.HasPrefix(strings.ToLower(v), "bearer ") {
				jwt = v[7:]
				authHeader = k
				break
			}
		}
	}

	// Then check per-request headers (if they were discovered)
	// But crawler.Endpoint doesn't have headers yet.

	if jwt == "" {
		return nil
	}

	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil // Not a standard JWT
	}

	// Attempt 1: "alg": "none"
	// Header: {"alg":"none","typ":"JWT"} -> eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
	noneHeader := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
	tamperedJWT := noneHeader + "." + parts[1] + "."

	resp, err := client.Submit(httpclient.SubmitRequest{
		Method: ep.Method,
		URL:    ep.URL,
		Params: ep.Params,
		Headers: map[string]string{
			authHeader: "Bearer " + tamperedJWT,
		},
		Ctx: ctx,
	})

	if err == nil && resp.StatusCode == 200 {
		// If it's a private endpoint and accepted alg:none, it's a finding
		if !m.isPublicResource(ep.URL) {
			return m.buildFinding(ep, descriptions.AuthJWTManipulation, "Server accepted JWT with 'alg: none'.", ep.URL)
		}
	}

	return nil
}

func (m *AuthModule) checkForcedBrowsing(ctx context.Context, ep crawler.Endpoint, client *httpclient.Client) *scanner.Finding {
	// Request without any auth context
	resp, err := client.Submit(httpclient.SubmitRequest{
		Method: ep.Method,
		URL:    ep.URL,
		Params: ep.Params,
		Ctx:    ctx,
	})
	if err != nil {
		return nil
	}

	// If 200 OK and it's an admin/private looking URL, it might be forced browsing
	// We need a way to know if it SHOULD have auth. Usually, if the crawler found it with auth,
	// but it works without, it's a finding.
	if resp.StatusCode == 200 && !m.isPublicResource(ep.URL) {
		// Heuristic: Check if response contains login forms or "Unauthorized" text
		body := strings.ToLower(resp.Body)
		if strings.Contains(body, "login") || strings.Contains(body, "unauthorized") || strings.Contains(body, "access denied") {
			return nil
		}

		return m.buildFinding(ep, descriptions.AuthForcedBrowsing, "Endpoint accessible without authentication.", resp.URL)
	}
	return nil
}

func (m *AuthModule) checkMethodTampering(ctx context.Context, ep crawler.Endpoint, client *httpclient.Client) *scanner.Finding {
	methods := []string{"POST", "PUT", "DELETE", "PATCH"}
	if ep.Method == "POST" {
		methods = []string{"GET", "PUT", "DELETE"}
	}

	for _, method := range methods {
		resp, err := client.Submit(httpclient.SubmitRequest{
			Method: method,
			URL:    ep.URL,
			Params: ep.Params,
			Ctx:    ctx,
		})
		if err != nil {
			continue
		}

		// If a sensitive method returns 200/204, it might be a bypass or unintended action
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			// If we tried DELETE and got 200, it's highly suspicious
			if method == "DELETE" || method == "PUT" || method == "PATCH" {
				return m.buildFinding(ep, descriptions.AuthMethodTampering, fmt.Sprintf("Endpoint accepted %s method which may bypass access controls.", method), resp.URL)
			}
		}
	}
	return nil
}

func (m *AuthModule) checkCORSMisconfiguration(ctx context.Context, ep crawler.Endpoint, client *httpclient.Client) *scanner.Finding {
	attackerOrigin := "https://attacker-sentinel.com"
	resp, err := client.Submit(httpclient.SubmitRequest{
		Method: ep.Method,
		URL:    ep.URL,
		Params: ep.Params,
		Headers: map[string]string{
			"Origin": attackerOrigin,
		},
		Ctx: ctx,
	})
	if err != nil {
		return nil
	}

	acao := resp.Headers.Get("Access-Control-Allow-Origin")
	acac := resp.Headers.Get("Access-Control-Allow-Credentials")

	if acao == "*" || acao == attackerOrigin {
		if acac == "true" || acao == "*" {
			return m.buildFinding(ep, descriptions.AuthCORSMisconfiguration, fmt.Sprintf("Overly permissive CORS policy detected: Access-Control-Allow-Origin: %s", acao), resp.URL)
		}
	}
	return nil
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

func (m *AuthModule) buildFinding(ep crawler.Endpoint, checkID descriptions.CheckID, evidence string, url string) *scanner.Finding {
	return &scanner.Finding{
		Title:          m.getFindingTitle(checkID),
		Severity:       scanner.High,
		OWASP:          descriptions.GetCategory(checkID),
		Confidence:     scanner.MediumConfidence,
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
