package modules

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/Stolonifer1903/gosentinel/internal/crawler"
	"github.com/Stolonifer1903/gosentinel/internal/httpclient"
	"github.com/Stolonifer1903/gosentinel/internal/scanner"
	"github.com/Stolonifer1903/gosentinel/internal/scanner/descriptions"
)

// IDORModuleConfig defines the detection parameters for the IDOR module.
type IDORModuleConfig struct {
	// Adjacency is the number of IDs to probe above and below the baseline.
	Adjacency int
	// SimilarityLow is the minimum ratio below which we consider the response
	// too different (likely an error page).
	SimilarityLow float64
	// SimilarityHigh is the ratio above which the response is considered
	// the same resource (no IDOR signal).
	SimilarityHigh float64
}

// DefaultIDORConfig provides sensible defaults for IDOR detection.
var DefaultIDORConfig = IDORModuleConfig{
	Adjacency:      2,
	SimilarityLow:  0.15,
	SimilarityHigh: 0.95,
}

// IDORModule implements scanner.Module for Insecure Direct Object Reference detection.
type IDORModule struct {
	Client *httpclient.Client
	Config IDORModuleConfig
}

func (m *IDORModule) Name() string { return "IDOR" }

func (m *IDORModule) Type() scanner.ModuleType { return scanner.TypeActive }

// --- Phase 2: Utility Functions ---

var idorParamBlocklist = map[string]bool{
	"page":     true,
	"limit":    true,
	"offset":   true,
	"per_page": true,
	"pagesize": true,
	"start":    true,
	"count":    true,
	"num":      true,
	"size":     true,
	"rows":     true,
	"max":      true,
	"p":        true,
}

var idorParamPattern = regexp.MustCompile(`(?i)(^id$|_id$|^id_|uid|pid|cid|ref|record|account|order|ticket|invoice)`)

func isIDORCandidate(name, value string) bool {
	if idorParamBlocklist[strings.ToLower(name)] {
		return false
	}
	if !idorParamPattern.MatchString(name) {
		return false
	}
	id, err := strconv.Atoi(value)
	if err != nil || id <= 0 {
		return false
	}
	return true
}

func adjacentIDs(base, adjacency int) []int {
	var ids []int
	// Probes below
	for i := adjacency; i >= 1; i-- {
		probe := base - i
		if probe > 0 {
			ids = append(ids, probe)
		}
	}
	// Probes above
	for i := 1; i <= adjacency; i++ {
		ids = append(ids, base+i)
	}
	return ids
}

var (
	reHexToken    = regexp.MustCompile(`[0-9a-fA-F]{32,}`)
	reISO8601     = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?`)
	reUnixEpoch   = regexp.MustCompile(`\b\d{10,}\b`)
	reHTMLComment = regexp.MustCompile(`(?s)<!--.*?-->`)
)

func normaliseBody(body string) string {
	body = reHTMLComment.ReplaceAllString(body, "")
	body = reHexToken.ReplaceAllString(body, " TOKEN ")
	body = reISO8601.ReplaceAllString(body, " TIMESTAMP ")
	body = reUnixEpoch.ReplaceAllString(body, " TIMESTAMP ")
	return strings.ToLower(body)
}

func tokenise(body string) map[string]struct{} {
	tokens := make(map[string]struct{})
	f := func(c rune) bool {
		return unicode.IsSpace(c) || unicode.IsPunct(c)
	}
	words := strings.FieldsFunc(body, f)
	for _, w := range words {
		if len(w) >= 2 {
			tokens[w] = struct{}{}
		}
	}
	return tokens
}

func jaccardSimilarity(a, b map[string]struct{}) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}
	intersection := 0
	for k := range a {
		if _, ok := b[k]; ok {
			intersection++
		}
	}
	union := len(a) + len(b) - intersection
	if union == 0 {
		return 0
	}
	return float64(intersection) / float64(union)
}

// --- Phase 3: Run Logic ---

func (m *IDORModule) Run(ctx context.Context, endpoints []crawler.Endpoint) ([]scanner.Finding, error) {
	client := m.Client
	if client == nil {
		client = httpclient.DefaultClient
	}

	var findings []scanner.Finding
	seen := make(map[string]bool)

	for _, ep := range endpoints {
		if ep.IsDestructive {
			continue
		}

		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		for param, value := range ep.Params {
			if !isIDORCandidate(param, value) {
				continue
			}

			// Key for deduplication
			findingKey := fmt.Sprintf("%s|%s", ep.URL, param)
			if seen[findingKey] {
				continue
			}

			baselineID, _ := strconv.Atoi(value)
			baseline, err := client.Submit(httpclient.SubmitRequest{
				Method: ep.Method,
				URL:    ep.URL,
				Params: ep.Params,
				Ctx:    ctx,
			})
			if err != nil || baseline.StatusCode != 200 {
				continue
			}

			baselineTokens := tokenise(normaliseBody(baseline.Body))

			for _, probeID := range adjacentIDs(baselineID, m.Config.Adjacency) {
				select {
				case <-ctx.Done():
					return findings, ctx.Err()
				default:
				}

				payload := strconv.Itoa(probeID)
				params := m.prepareParams(ep, param, payload)

				resp, err := client.Submit(httpclient.SubmitRequest{
					Method: ep.Method,
					URL:    ep.URL,
					Params: params,
					Ctx:    ctx,
				})

				if err != nil || resp.StatusCode != 200 {
					continue
				}

				probeTokens := tokenise(normaliseBody(resp.Body))
				ratio := jaccardSimilarity(baselineTokens, probeTokens)

				if ratio >= m.Config.SimilarityLow && ratio < m.Config.SimilarityHigh {
					findings = append(findings, m.buildFinding(ep, param, value, payload, ratio))
					seen[findingKey] = true
					break // Found IDOR for this param
				}
			}
		}
	}

	return findings, nil
}

func (m *IDORModule) prepareParams(ep crawler.Endpoint, target, payload string) map[string]string {
	params := make(map[string]string, len(ep.Params))
	for p, val := range ep.Params {
		if p == target {
			params[p] = payload
		} else {
			params[p] = val
		}
	}
	return params
}

func (m *IDORModule) buildFinding(ep crawler.Endpoint, param, baselineID, probeID string, ratio float64) scanner.Finding {
	checkID := descriptions.IDORNumericIDAccess
	similarity := fmt.Sprintf("%.1f%%", ratio*100)

	evidence := fmt.Sprintf("Parameter %q with original value %q was probed with adjacent value %q. The probe returned HTTP 200 with a response body %s similar to the baseline, suggesting a different data record was returned without an access control error.",
		param, baselineID, probeID, similarity)

	return scanner.Finding{
		Title:          "Insecure Direct Object Reference (IDOR)",
		Severity:       scanner.High,
		OWASP:          descriptions.GetCategory(checkID),
		Confidence:     scanner.MediumConfidence,
		Description:    descriptions.GetDescription(checkID),
		URL:            ep.URL,
		Method:         strings.ToUpper(ep.Method),
		Parameter:      param,
		EndpointDetail: fmt.Sprintf("%s via %s %s", strings.ToUpper(ep.Method), strings.ToLower(ep.Source), param),
		Evidence:       evidence,
		Remediation:    "Implement strict access control checks for every resource request. Do not rely on the presence of a valid object ID. Use indirect, non-sequential references (e.g., UUIDs) where possible to make enumeration difficult.",
	}
}
