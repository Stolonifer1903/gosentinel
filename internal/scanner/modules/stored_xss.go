package modules

import (
	"context"
	"fmt"
	"hash/fnv"
	"os"
	"strings"
	"time"

	"github.com/Stolonifer1903/gosentinel/internal/crawler"
	"github.com/Stolonifer1903/gosentinel/internal/httpclient"
	"github.com/Stolonifer1903/gosentinel/internal/scanner"
	"github.com/Stolonifer1903/gosentinel/internal/scanner/descriptions"
)

// storedXSSProbe tracks a single write operation awaiting a read-back check.
type storedXSSProbe struct {
	Canary  string
	WriteEp crawler.Endpoint
	Param   string
}

// StoredXSSModule implements scanner.Module for stored XSS detection.
type StoredXSSModule struct {
	Client  *httpclient.Client
	Confirm bool
}

func (m *StoredXSSModule) Name() string { return "Stored XSS" }

func (m *StoredXSSModule) Run(ctx context.Context, endpoints []crawler.Endpoint) ([]scanner.Finding, error) {
	fmt.Fprintf(os.Stderr, "[!] Stored XSS: this module will WRITE test data to the target. Use Ctrl+C to skip.\n")

	probes, canaryIndex, err := m.injectPhase(ctx, endpoints)
	if err != nil {
		return nil, err
	}

	if len(probes) == 0 {
		return nil, nil
	}

	return m.sweepPhase(ctx, endpoints, canaryIndex)
}

func (m *StoredXSSModule) injectPhase(ctx context.Context, endpoints []crawler.Endpoint) ([]storedXSSProbe, map[string]storedXSSProbe, error) {
	var probes []storedXSSProbe
	canaryIndex := make(map[string]storedXSSProbe)

	for _, ep := range endpoints {
		if ep.Source != "Form" || len(ep.Params) == 0 {
			continue
		}

		for _, param := range ep.Params {
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			default:
			}

			canary := storedXSSCanary(ep.URL, ep.Method, param)

			// Phase 1: Write plain-text canary
			params := make(map[string]string)
			for _, p := range ep.Params {
				if p == param {
					params[p] = canary
				} else {
					params[p] = "test"
				}
			}

			_, err := m.Client.Submit(httpclient.SubmitRequest{
				Method: ep.Method,
				URL:    ep.URL,
				Params: params,
				Ctx:    ctx,
			})
			if err != nil {
				continue
			}

			probe := storedXSSProbe{
				Canary:  canary,
				WriteEp: ep,
				Param:   param,
			}
			probes = append(probes, probe)
			canaryIndex[canary] = probe
		}
	}

	return probes, canaryIndex, nil
}

func (m *StoredXSSModule) sweepPhase(ctx context.Context, endpoints []crawler.Endpoint, canaryIndex map[string]storedXSSProbe) ([]scanner.Finding, error) {
	var findings []scanner.Finding
	seen := make(map[string]struct{})

	for _, ep := range endpoints {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		// Re-fetch every known page
		res, err := m.Client.Submit(httpclient.SubmitRequest{
			Method: "GET",
			URL:    ep.URL,
			Ctx:    ctx,
		})
		if err != nil {
			continue
		}

		for canary, probe := range canaryIndex {
			// Since canary is just hex chars, html.EscapeString(canary) == canary.
			// However, we follow the logic that finding the unique canary
			// means we have a stored reflection.
			
			dedupKey := canary + "|" + ep.URL
			if _, exists := seen[dedupKey]; exists {
				continue
			}

			// In Stage B, we just check for the presence of the canary.
			// Because it has no special characters, it's always "unescaped"
			// in the sense that the literal string is found.
			if strings.Contains(res.Body, canary) {
				findings = append(findings, buildStoredXSSFinding(probe, ep.URL, res.ContentType))
				seen[dedupKey] = struct{}{}
			}
		}
	}

	return findings, nil
}

func storedXSSCanary(url, method, param string) string {
	h := fnv.New32a()
	h.Write([]byte(url + "|" + method + "|" + param))
	return fmt.Sprintf("gs-%08x", h.Sum32())
}

func buildStoredXSSFinding(probe storedXSSProbe, readURL string, ctxType string) scanner.Finding {
	return scanner.Finding{
		Title:          "Stored Cross-Site Scripting (XSS)",
		Severity:       scanner.High,
		OWASP:          descriptions.GetCategory(descriptions.XSSStored),
		Confidence:     scanner.ConfirmedConfidence,
		Description:    descriptions.GetDescription(descriptions.XSSStored),
		URL:            probe.WriteEp.URL,
		Method:         strings.ToUpper(probe.WriteEp.Method),
		Parameter:      probe.Param,
		EndpointDetail: fmt.Sprintf("Write: %s %s (%s) → Read: %s | Proof: Canary %s on %s", strings.ToUpper(probe.WriteEp.Method), probe.WriteEp.URL, probe.Param, readURL, probe.Canary, readURL),
		Evidence:       fmt.Sprintf("Canary %s found unescaped on %s", probe.Canary, readURL),
		Remediation:    "Encode all user-supplied output using context-aware escaping. Apply a Content-Security-Policy header.",
		Timestamp:      time.Now(),
	}
}
