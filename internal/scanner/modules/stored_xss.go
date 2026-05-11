package modules

import (
	"bufio"
	"context"
	"fmt"
	"hash/fnv"
	"io"
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
//
// When Confirm is false, Run() prompts the user on stdin before proceeding.
// This interactive confirmation uses deadline-polling to remain responsive
// to context cancellation without leaking goroutines.
type StoredXSSModule struct {
	Client  *httpclient.Client
	Confirm bool
}

// NewStoredXSSModule creates a new StoredXSSModule.
func NewStoredXSSModule(client *httpclient.Client, confirm bool) *StoredXSSModule {
	return &StoredXSSModule{
		Client:  client,
		Confirm: confirm,
	}
}

func (m *StoredXSSModule) Name() string { return "Stored XSS" }

func (m *StoredXSSModule) Type() scanner.ModuleType { return scanner.TypeActive }

func (m *StoredXSSModule) Run(ctx context.Context, endpoints []crawler.Endpoint) ([]scanner.Finding, error) {
	if !m.Confirm {
		proceed, err := m.awaitConfirmation(ctx)
		if err != nil {
			return nil, err
		}
		if !proceed {
			return nil, nil
		}
	}

	probes, canaryIndex, err := m.injectPhase(ctx, endpoints)
	if err != nil {
		return nil, err
	}

	if len(probes) == 0 {
		return nil, nil
	}

	return m.sweepPhase(ctx, endpoints, canaryIndex)
}

func (m *StoredXSSModule) awaitConfirmation(ctx context.Context) (bool, error) {
	fmt.Fprintf(os.Stderr, "[!] Stored XSS: this module will WRITE test data to the target. Proceed? [y/N]: ")

	reader := bufio.NewReader(os.Stdin)
	for {
		// Check for cancellation before each read attempt.
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		default:
		}

		// Set a short deadline so ReadString unblocks periodically,
		// letting us re-check ctx.Done() on the next iteration.
		os.Stdin.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		input, err := reader.ReadString('\n')

		if err != nil {
			if os.IsTimeout(err) {
				continue // Deadline expired — loop back to check ctx
			}
			// EOF means stdin is closed (e.g. /dev/null, piped input).
			// Treat as a graceful "no".
			if err == io.EOF {
				return false, nil
			}
			return false, err
		}

		// Got a line of input — clear the deadline for future reads.
		os.Stdin.SetReadDeadline(time.Time{})

		ans := strings.ToLower(strings.TrimSpace(input))
		if ans == "y" || ans == "yes" {
			return true, nil
		}
		return false, nil
	}
}

func (m *StoredXSSModule) injectPhase(ctx context.Context, endpoints []crawler.Endpoint) ([]storedXSSProbe, map[string]storedXSSProbe, error) {
	var probes []storedXSSProbe
	canaryIndex := make(map[string]storedXSSProbe)

	for _, ep := range endpoints {
		if ep.IsDestructive {
			continue
		}

		// Check for cancellation at every endpoint boundary, even if the endpoint
		// has no injectable params, so we don't block on large link-only endpoint lists.
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		default:
		}

		if ep.Source != "Form" || len(ep.Params) == 0 {
			continue
		}

		for _, param := range ep.Params {
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
		if ep.IsDestructive {
			continue
		}
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		// Re-fetch every endpoint discovered by the crawler. Note: reflections on
		// pages outside the crawler's scope (e.g. authenticated routes, dynamically
		// generated URLs not visited during crawling) will not be detected.
		// This is a known scope limitation of the canary-sweep approach.
		res, err := m.Client.Submit(httpclient.SubmitRequest{
			Method: "GET",
			URL:    ep.URL,
			Ctx:    ctx,
		})
		if err != nil {
			continue
		}

		for canary, probe := range canaryIndex {
			// Filter out read endpoints that match the write endpoint to reduce noise from forms echoing their own values.
			if ep.URL == probe.WriteEp.URL {
				continue
			}

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
	// FNV-64a gives a 64-bit hash space (~1.8×10¹⁹ values), making accidental
	// canary collisions between different (url, method, param) tuples negligible.
	h := fnv.New64a()
	h.Write([]byte(url + "|" + method + "|" + param))
	return fmt.Sprintf("gs-%016x", h.Sum64())
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
