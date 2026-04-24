package modules

import (
	"context"
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/Stolonifer1903/gosentinel/internal/crawler"
	"github.com/Stolonifer1903/gosentinel/internal/httpclient"
	"github.com/Stolonifer1903/gosentinel/internal/scanner"
	"github.com/Stolonifer1903/gosentinel/internal/scanner/descriptions"
)

// xssPayload defines a single probe payload and the context it targets.
type xssPayload struct {
	Template                string
	Context                 string
	Tier                    int
	RequiresUserInteraction bool
}

var xssPayloads = []xssPayload{
	{
		Tier:     1,
		Template: `"><script>alert('gosentinel_{PARAM}')</script>`,
		Context:  "HTML body breakout",
	},
	{
		Tier:     1,
		Template: `<svg/onload=alert('gosentinel_{PARAM}')>`,
		Context:  "SVG onload execution",
	},
	{
		Tier:                    1,
		Template:                `" onmouseover="alert('gosentinel_{PARAM}')`,
		Context:                 "HTML attribute breakout",
		RequiresUserInteraction: true,
	},
	{
		Tier:     1,
		Template: `';alert('gosentinel_{PARAM}');//`,
		Context:  "JavaScript string breakout",
	},
	{
		Tier:     2,
		Template: `<a href="jav&#x61;script:alert('gosentinel_{PARAM}')">x</a>`,
		Context:  "Encoded javascript URI anchor",
	},
	{
		Tier:     2,
		Template: `<iframe src="data:text/html,<svg onload=alert('gosentinel_{PARAM}')>"></iframe>`,
		Context:  "Iframe data URI execution",
	},
}

// XSSModule implements scanner.Module for active reflected XSS detection.
type XSSModule struct {
	Client *httpclient.Client
}

// xssCanaryResult holds the outcome of a single parameter probe.
type xssCanaryResult struct {
	Param      string
	Payload    string
	Context    string
	Reflected  bool
	Escaped    bool
	CtxType    string
	FinalURL   string
	StatusCode int
}

func (m *XSSModule) Name() string { return "Reflected XSS" }

func (m *XSSModule) Type() scanner.ModuleType { return scanner.TypeActive }

// Run actively injects payloads into form parameters and checks for reflection.
func (m *XSSModule) Run(ctx context.Context, endpoints []crawler.Endpoint) ([]scanner.Finding, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	client := m.Client
	if client == nil {
		client = httpclient.DefaultClient
	}

	var findings []scanner.Finding
	seen := make(map[string]struct{})

	for _, ep := range endpoints {
		if ep.Source != "Form" || len(ep.Params) == 0 {
			continue
		}

		for _, param := range ep.Params {
			analysis, ok, err := runTieredXSSProbe(ctx, client, ep, param)
			if err != nil {
				return findings, err
			}
			if !ok {
				continue
			}

			dedupKey := strings.Join([]string{ep.URL, strings.ToUpper(ep.Method), param, analysis.Context}, "|")
			if _, exists := seen[dedupKey]; exists {
				continue
			}
			seen[dedupKey] = struct{}{}

			findings = append(findings, buildXSSFinding(ep, analysis))
		}
	}

	return findings, nil
}

// analyseResponse inspects the HTTP response for canary reflection and escaping.
func analyseResponse(res *httpclient.ResponseResult, canary, param string, probe xssPayload) xssCanaryResult {
	injected := strings.ReplaceAll(probe.Template, "{PARAM}", param)
	escaped := html.EscapeString(injected)

	result := xssCanaryResult{
		Param:      param,
		Payload:    injected,
		Context:    probe.Context,
		CtxType:    res.ContentType,
		FinalURL:   res.FinalURL,
		StatusCode: res.StatusCode,
	}

	switch {
	case strings.Contains(res.Body, injected):
		result.Reflected = true
	case strings.Contains(res.Body, escaped):
		result.Reflected = true
		result.Escaped = true
	case strings.Contains(res.Body, canary):
		result.Reflected = true
	}

	return result
}

func runTieredXSSProbe(ctx context.Context, client *httpclient.Client, ep crawler.Endpoint, param string) (xssCanaryResult, bool, error) {
	for tier := 1; tier <= 2; tier++ {
		for _, probe := range xssPayloads {
			if probe.Tier != tier {
				continue
			}

			select {
			case <-ctx.Done():
				return xssCanaryResult{}, false, ctx.Err()
			default:
			}

			params := make(map[string]string, len(ep.Params))
			for _, p := range ep.Params {
				if p == param {
					params[p] = strings.ReplaceAll(probe.Template, "{PARAM}", param)
					continue
				}
				params[p] = "test"
			}

			result, err := client.Submit(httpclient.SubmitRequest{
				Method: ep.Method,
				URL:    ep.URL,
				Params: params,
				Ctx:    ctx,
			})
			if err != nil {
				continue
			}

			canary := fmt.Sprintf("gosentinel_%s", param)
			analysis := analyseResponse(result, canary, param, probe)
			if analysis.Reflected && !analysis.Escaped {
				return analysis, true, nil
			}
		}
	}

	return xssCanaryResult{}, false, nil
}

func buildXSSFinding(ep crawler.Endpoint, cr xssCanaryResult) scanner.Finding {
	severity, confidence := gradeXSSFinding(cr)

	return scanner.Finding{
		Title:          "Reflected Cross-Site Scripting (XSS)",
		Severity:       severity,
		OWASP:          descriptions.GetCategory(descriptions.XSSReflected),
		Confidence:     confidence,
		Description:    descriptions.GetDescription(descriptions.XSSReflected),
		URL:            ep.URL,
		Method:         strings.ToUpper(ep.Method),
		Parameter:      cr.Param,
		EndpointDetail: fmt.Sprintf("%s parameter=%s", strings.ToUpper(ep.Method), cr.Param),
		Evidence:       fmt.Sprintf("Parameter reflected unescaped in %s response (%s)", contentTypeLabel(cr.CtxType), cr.Context),
		Remediation:    "Encode all user-supplied output using context-aware escaping. Apply a Content-Security-Policy header to restrict script execution.",
		Timestamp:      time.Now(),
	}
}

func gradeXSSFinding(cr xssCanaryResult) (scanner.Severity, scanner.Confidence) {
	switch cr.CtxType {
	case "text/html":
		return scanner.High, scanner.ConfirmedConfidence
	case "application/json":
		return scanner.Medium, scanner.MediumConfidence
	default:
		return scanner.Low, scanner.InformationalConfidence
	}
}

func contentTypeLabel(contentType string) string {
	if contentType == "" {
		return "unknown"
	}
	return contentType
}
