package modules

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Stolonifer1903/gosentinel/internal/crawler"
	"github.com/Stolonifer1903/gosentinel/internal/httpclient"
	"github.com/Stolonifer1903/gosentinel/internal/scanner"
	"github.com/Stolonifer1903/gosentinel/internal/scanner/descriptions"
)

// SSRFModuleConfig allows fine-tuning the SSRF detection behavior.
type SSRFModuleConfig struct {
	ProbeTimeout        time.Duration // Max time to wait for a probe request (default: 10s)
	EnableHeaderProbes  bool          // Enable injection into headers (default: false)
	EnableCloudMetadata bool          // Probe for cloud metadata endpoints (default: false)
}

// DefaultSSRFConfig provides sensible defaults for SSRF detection.
var DefaultSSRFConfig = SSRFModuleConfig{
	ProbeTimeout:        10 * time.Second,
	EnableHeaderProbes:  false,
	EnableCloudMetadata: false,
}

var ssrfParamNames = map[string]bool{
	"url": true, "uri": true, "redirect": true, "next": true,
	"callback": true, "endpoint": true, "host": true, "link": true,
	"path": true, "file": true, "src": true, "dest": true,
	"target": true, "return": true, "return_url": true, "fetch": true,
	"load": true, "proxy": true, "page": true, "api": true,
	"feed": true, "ref": true, "data": true, "resource": true,
	"continue": true, "image": true, "document": true,
}

var ssrfHeaders = []string{
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"Host",
	"Referer",
}

// Target definitions
type ssrfTarget struct {
	ip          string
	path        string
	isCloudMeta bool
}

var coreTargets = []ssrfTarget{
	{"127.0.0.1", "/", false},
	{"[::1]", "/", false},
	{"0.0.0.0", "/", false},
	{"localhost", "/", false},
	{"10.0.0.1", "/", false},
	{"192.168.0.1", "/", false},
	{"172.16.0.1", "/", false},
}

var cloudMetadataTargets = []ssrfTarget{
	{"169.254.169.254", "/latest/meta-data/", true}, // AWS
}

// Bypass encodings
func identity(host string) string         { return host }
func decimalIP(host string) string        { return "2130706433" } // 127.0.0.1
func octalIP(host string) string          { return "0177.0.0.1" }
func hexIP(host string) string            { return "0x7f.0x0.0x0.0x1" }
func urlEncode(host string) string        { return "%31%32%37.0.0.1" } // 127.0.0.1
func atSignBypass(host string) string     { return "attacker.com@" + host }
func dnsRebindAlias(host string) string   { return "localtest.me" }

var bypassVariants = []func(string) string{
	identity,
	decimalIP,
	octalIP,
	hexIP,
	urlEncode,
	atSignBypass,
	dnsRebindAlias,
}

// Markers for content reflection detection
var internalContentMarkers = []string{
	"<title>apache", "welcome to nginx", "it works!", "index of /",
}
var cloudMetadataMarkers = []string{
	"ami-id", "instance-id", "iam/security-credentials", "computeMetadata",
}

// SSRFModule implements scanner.Module for Server-Side Request Forgery detection.
type SSRFModule struct {
	Client *httpclient.Client
	Config SSRFModuleConfig
}

func (m *SSRFModule) Name() string { return "SSRF" }

func (m *SSRFModule) Type() scanner.ModuleType { return scanner.TypeActive }

func (m *SSRFModule) Run(ctx context.Context, endpoints []crawler.Endpoint) ([]scanner.Finding, error) {
	client := m.Client
	if client == nil {
		client = httpclient.DefaultClient
	}

	// Create a dedicated client for probes if timeout differs
	probeClient := httpclient.NewClient(&http.Client{
		Timeout: m.Config.ProbeTimeout,
	})

	var findings []scanner.Finding
	seen := make(map[string]struct{})

	for _, ep := range endpoints {
		if ep.IsDestructive {
			continue
		}
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		if len(ep.Params) == 0 && !m.Config.EnableHeaderProbes {
			continue
		}

		// Baseline
		baseline, err := m.getBaseline(ctx, client, ep)
		if err != nil {
			if ctx.Err() != nil {
				return findings, ctx.Err()
			}
			continue
		}

		for param := range ep.Params {
			found, err := m.probeTarget(ctx, probeClient, ep, param, "Param", seen, baseline)
			if err != nil && ctx.Err() != nil {
				return findings, ctx.Err()
			}
			findings = append(findings, found...)
		}

		if m.Config.EnableHeaderProbes {
			for _, header := range ssrfHeaders {
				found, err := m.probeTarget(ctx, probeClient, ep, header, "Header", seen, baseline)
				if err != nil && ctx.Err() != nil {
					return findings, ctx.Err()
				}
				findings = append(findings, found...)
			}
		}
	}

	return findings, nil
}

func (m *SSRFModule) probeTarget(ctx context.Context, client *httpclient.Client, ep crawler.Endpoint, target, targetType string, seen map[string]struct{}, baseline *httpclient.ResponseResult) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	isPriority := false
	if targetType == "Param" {
		isPriority = ssrfParamNames[strings.ToLower(target)]
	}

	var targetsToTest []ssrfTarget
	if isPriority || targetType == "Header" {
		targetsToTest = append(targetsToTest, coreTargets...)
	} else {
		// Non-priority params get just localhost to save time
		targetsToTest = append(targetsToTest, coreTargets[0]) 
	}

	if m.Config.EnableCloudMetadata {
		targetsToTest = append(targetsToTest, cloudMetadataTargets...)
	}

	for _, t := range targetsToTest {
		for _, variant := range bypassVariants {
			// Some variants only make sense for 127.0.0.1
			if t.ip != "127.0.0.1" && (fmt.Sprintf("%p", variant) == fmt.Sprintf("%p", decimalIP) ||
				fmt.Sprintf("%p", variant) == fmt.Sprintf("%p", octalIP) ||
				fmt.Sprintf("%p", variant) == fmt.Sprintf("%p", hexIP) ||
				fmt.Sprintf("%p", variant) == fmt.Sprintf("%p", urlEncode) ||
				fmt.Sprintf("%p", variant) == fmt.Sprintf("%p", dnsRebindAlias)) {
				continue
			}

			host := variant(t.ip)
			payload := fmt.Sprintf("http://%s%s", host, t.path)

			probeCtx, cancel := context.WithTimeout(ctx, m.Config.ProbeTimeout)
			result, err := m.submitProbe(probeCtx, client, ep, target, targetType, payload)
			cancel()

			if err != nil {
				continue
			}

			// 1. Content Reflection
			finding, ok := m.detectContentReflection(result.Body, baseline.Body, ep, target, targetType, payload, t.isCloudMeta)
			if ok {
				dedupKey := fmt.Sprintf("%s|%s|%s|CONTENT|%t", ep.URL, target, targetType, t.isCloudMeta)
				if _, exists := seen[dedupKey]; !exists {
					seen[dedupKey] = struct{}{}
					findings = append(findings, finding)
				}
				break // Stop probing this target if we got full SSRF
			}
		}
	}

	// If no full SSRF found, try partial/blind if it's a priority target
	if len(findings) == 0 && (isPriority || targetType == "Header") {
		// 2. Status Differential
		openPortPayload := "http://127.0.0.1:22"
		closedPortPayload := "http://127.0.0.1:65534"

		openCtx, cancelOpen := context.WithTimeout(ctx, m.Config.ProbeTimeout)
		resOpen, errOpen := m.submitProbe(openCtx, client, ep, target, targetType, openPortPayload)
		cancelOpen()

		closedCtx, cancelClosed := context.WithTimeout(ctx, m.Config.ProbeTimeout)
		resClosed, errClosed := m.submitProbe(closedCtx, client, ep, target, targetType, closedPortPayload)
		cancelClosed()

		if errOpen == nil && errClosed == nil {
			if resOpen.StatusCode != resClosed.StatusCode {
				dedupKey := fmt.Sprintf("%s|%s|%s|STATUS", ep.URL, target, targetType)
				if _, exists := seen[dedupKey]; !exists {
					seen[dedupKey] = struct{}{}
					evidence := fmt.Sprintf("Injected payload %q returned status %d, but payload %q returned status %d. Differential indicates server-side request execution.", openPortPayload, resOpen.StatusCode, closedPortPayload, resClosed.StatusCode)
					findings = append(findings, m.buildFinding(ep, target, targetType, "Server-Side Request Forgery (Partial)", descriptions.SSRFPartialBlind, scanner.High, scanner.MediumConfidence, evidence))
				}
			}
		}

		// 3. Timing Differential (Only if no status diff)
		dedupStatusKey := fmt.Sprintf("%s|%s|%s|STATUS", ep.URL, target, targetType)
		if _, exists := seen[dedupStatusKey]; !exists {
			unroutablePayload := "http://192.0.2.1/" // TEST-NET-1
			timeCtx, cancelTime := context.WithTimeout(ctx, m.Config.ProbeTimeout)
			resTime, errTime := m.submitProbe(timeCtx, client, ep, target, targetType, unroutablePayload)
			cancelTime()

			if errTime == nil {
				// threshold: baseline + 3 seconds
				threshold := baseline.Duration + (3 * time.Second)
				if resTime.Duration >= threshold {
					dedupKey := fmt.Sprintf("%s|%s|%s|TIME", ep.URL, target, targetType)
					if _, exists := seen[dedupKey]; !exists {
						seen[dedupKey] = struct{}{}
						evidence := fmt.Sprintf("Injected unroutable payload %q caused significant delay (%s vs baseline %s). Timing indicates server-side request execution.", unroutablePayload, resTime.Duration.Round(time.Millisecond), baseline.Duration.Round(time.Millisecond))
						findings = append(findings, m.buildFinding(ep, target, targetType, "Server-Side Request Forgery (Timing Indicator)", descriptions.SSRFPartialBlind, scanner.Medium, scanner.LowConfidence, evidence))
					}
				}
			}
		}
	}

	return findings, nil
}

func (m *SSRFModule) detectContentReflection(body, baselineBody string, ep crawler.Endpoint, target, targetType, payload string, isCloudMeta bool) (scanner.Finding, bool) {
	bodyLower := strings.ToLower(body)
	baselineLower := strings.ToLower(baselineBody)

	if isCloudMeta {
		for _, marker := range cloudMetadataMarkers {
			if strings.Contains(bodyLower, marker) && !strings.Contains(baselineLower, marker) {
				evidence := fmt.Sprintf("Injected payload %q into %s %q. Response contained cloud metadata marker %q.", payload, strings.ToLower(targetType), target, marker)
				return m.buildFinding(ep, target, targetType, "Server-Side Request Forgery (Cloud Metadata)", descriptions.SSRFCloudMetadata, scanner.Critical, scanner.ConfirmedConfidence, evidence), true
			}
		}
	} else {
		for _, marker := range internalContentMarkers {
			if strings.Contains(bodyLower, marker) && !strings.Contains(baselineLower, marker) {
				evidence := fmt.Sprintf("Injected payload %q into %s %q. Response contained internal content marker %q.", payload, strings.ToLower(targetType), target, marker)
				return m.buildFinding(ep, target, targetType, "Server-Side Request Forgery (Internal IP Disclosure)", descriptions.SSRFInternalIPDisclosure, scanner.High, scanner.ConfirmedConfidence, evidence), true
			}
		}
	}

	return scanner.Finding{}, false
}

func (m *SSRFModule) getBaseline(ctx context.Context, client *httpclient.Client, ep crawler.Endpoint) (*httpclient.ResponseResult, error) {
	return client.Submit(httpclient.SubmitRequest{
		Method: ep.Method,
		URL:    ep.URL,
		Params: m.prepareParams(ep, "", ""),
		Ctx:    ctx,
	})
}

func (m *SSRFModule) submitProbe(ctx context.Context, client *httpclient.Client, ep crawler.Endpoint, target, targetType, payload string) (*httpclient.ResponseResult, error) {
	req := httpclient.SubmitRequest{
		Method: ep.Method,
		URL:    ep.URL,
		Ctx:    ctx,
	}

	if targetType == "Param" {
		req.Params = m.prepareParams(ep, target, payload)
	} else if targetType == "Header" {
		req.Params = m.prepareParams(ep, "", "")
		req.Headers = map[string]string{target: payload}
	}

	return client.Submit(req)
}

func (m *SSRFModule) prepareParams(ep crawler.Endpoint, target, payload string) map[string]string {
	params := make(map[string]string, len(ep.Params))
	for p, originalValue := range ep.Params {
		if p == target {
			params[p] = payload
		} else {
			if originalValue != "" {
				params[p] = originalValue
			} else {
				params[p] = "http://example.com" // Default benign URL value
			}
		}
	}
	return params
}

func (m *SSRFModule) buildFinding(ep crawler.Endpoint, target, targetType, title string, checkID descriptions.CheckID, severity scanner.Severity, confidence scanner.Confidence, evidence string) scanner.Finding {
	return scanner.Finding{
		Title:          title,
		Severity:       severity,
		OWASP:          descriptions.GetCategory(checkID),
		Confidence:     confidence,
		Description:    descriptions.GetDescription(checkID),
		URL:            ep.URL,
		Method:         strings.ToUpper(ep.Method),
		Parameter:      target,
		EndpointDetail: fmt.Sprintf("%s via %s %s", strings.ToUpper(ep.Method), strings.ToLower(targetType), target),
		Evidence:       evidence,
		Remediation:    "Validate all user-supplied URLs against a strict allowlist of permitted hosts. Do not allow internal IP addresses, loopback addresses, or cloud metadata endpoints. Resolve DNS before fetching and verify the resolved IP is not in a private/internal range.",
		Timestamp:      time.Now(),
	}
}
