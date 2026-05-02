package modules

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Stolonifer1903/gosentinel/internal/crawler"
	"github.com/Stolonifer1903/gosentinel/internal/httpclient"
	"github.com/Stolonifer1903/gosentinel/internal/scanner"
	"github.com/Stolonifer1903/gosentinel/internal/scanner/descriptions"
)

// SQLiModuleConfig allows fine-tuning the SQLi detection behavior.
type SQLiModuleConfig struct {
	TimeBasedDelay        time.Duration // Duration to sleep in time-based probes (default: 5s)
	TimeBasedTimeout      time.Duration // Max time to wait for a time-based probe (default: 12s)
	ConfirmTimeBased      bool          // Whether to re-probe to confirm time-based findings (default: true)
	EnableHeaderInjection bool          // If true, test injection via HTTP headers (experimental, high FP rate)
}

// DefaultSQLiConfig provides sensible defaults for SQLi detection.
var DefaultSQLiConfig = SQLiModuleConfig{
	TimeBasedDelay:        5 * time.Second,
	TimeBasedTimeout:      12 * time.Second,
	ConfirmTimeBased:      true,
	EnableHeaderInjection: false, // Disabled: bare SQL fragments in headers are ineffective
}

var sqlErrorSignatures = []string{
	"you have an error in your sql syntax",
	"mysql_fetch_array()",
	"mysql_fetch_assoc()",
	"mysql_num_rows()",
	"is not a valid mysql result resource",
	"postgresql query failed",
	"pg_query()",
	"pg_exec()",
	"unclosed quotation mark after the character string",
	"microsoft ole db provider for sql server",
	"sqlite3::query():",
	"sqlite3::prepare():",
	"java.sql.sqlexception",
	"oracle error",
	"ora-00933",
	"ora-00936",
}

var errorPayloads = []string{"'", "\"", "\\", ";'"}

func timePayloads(delaySeconds int) []string {
	return []string{
		fmt.Sprintf("SLEEP(%d)", delaySeconds),                                     // MySQL
		fmt.Sprintf("pg_sleep(%d)", delaySeconds),                                  // PostgreSQL
		fmt.Sprintf("WAITFOR DELAY '0:0:%d'", delaySeconds),                        // MSSQL
		fmt.Sprintf("dbms_pipe.receive_message(chr(99),%d)", delaySeconds),          // Oracle
		fmt.Sprintf("BEGIN DBMS_LOCK.SLEEP(%d); END;", delaySeconds),               // Oracle alternative
	}
}

var injectionHeaders = []string{
	"X-Forwarded-For",
	"User-Agent",
	"Referer",
	"Cookie",
}

// SQLiModule implements scanner.Module for SQL Injection detection.
type SQLiModule struct {
	Client *httpclient.Client
	Config SQLiModuleConfig
}

func (m *SQLiModule) Name() string { return "SQL Injection" }

func (m *SQLiModule) Type() scanner.ModuleType { return scanner.TypeActive }

func (m *SQLiModule) Run(ctx context.Context, endpoints []crawler.Endpoint) ([]scanner.Finding, error) {
	client := m.Client
	if client == nil {
		client = httpclient.DefaultClient
	}

	var findings []scanner.Finding
	seen := make(map[string]struct{})

	for _, ep := range endpoints {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		// Skip endpoints with no injectable parameters.
		if len(ep.Params) == 0 {
			continue
		}

		// Fetch baseline once per endpoint, shared by all probes.
		baseline, err := m.getBaseline(ctx, client, ep)
		if err != nil {
			// Propagate context cancellation instead of swallowing it.
			if ctx.Err() != nil {
				return findings, ctx.Err()
			}
			continue // Transient network error — skip this endpoint
		}

		// 1. Probe URL parameters / form fields
		for _, param := range ep.Params {
			found, err := m.probeEndpoint(ctx, client, ep, param, "Param", seen, baseline)
			if err != nil && ctx.Err() != nil {
				return findings, ctx.Err()
			}
			findings = append(findings, found...)
		}

		// 2. Header-based injection (experimental, disabled by default).
		if m.Config.EnableHeaderInjection {
			for _, header := range injectionHeaders {
				found, err := m.probeEndpoint(ctx, client, ep, header, "Header", seen, baseline)
				if err != nil && ctx.Err() != nil {
					return findings, ctx.Err()
				}
				findings = append(findings, found...)
			}
		}
	}

	return findings, nil
}

func (m *SQLiModule) probeEndpoint(ctx context.Context, client *httpclient.Client, ep crawler.Endpoint, target, targetType string, seen map[string]struct{}, baseline *httpclient.ResponseResult) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	// 1. Error-Based SQLi
	for _, payload := range errorPayloads {
		result, err := m.submitProbe(ctx, client, ep, target, targetType, payload)
		if err != nil {
			continue
		}

		if m.detectError(result.Body, baseline.Body) {
			dedupKey := fmt.Sprintf("%s|%s|%s|ERROR", ep.URL, target, targetType)
			seen[dedupKey] = struct{}{}
			findings = append(findings, m.buildFinding(ep, target, targetType, payload, "Error-Based SQL Injection", descriptions.SQLiErrorBased, scanner.High, scanner.ConfirmedConfidence))
			break // One error payload is enough per target
		}
	}

	// 2. Time-Based SQLi
	delay := m.Config.TimeBasedDelay
	if delay == 0 {
		delay = DefaultSQLiConfig.TimeBasedDelay
	}
	delaySec := int(delay.Seconds())

	for _, payload := range timePayloads(delaySec) {
		// Use a context with the configured timeout for time-based probes
		timeout := m.Config.TimeBasedTimeout
		if timeout == 0 {
			timeout = DefaultSQLiConfig.TimeBasedTimeout
		}
		probeCtx, cancel := context.WithTimeout(ctx, timeout)
		
		result, err := m.submitProbe(probeCtx, client, ep, target, targetType, payload)
		cancel()
		if err != nil {
			continue
		}

		if m.detectTimeDelay(result.Duration, baseline.Duration, delay) {
			// Confirmation re-probe if configured
			confirmed := true
			if m.Config.ConfirmTimeBased {
				confirmed = false
				// Short delay for confirmation
				confirmCtx, cancel := context.WithTimeout(ctx, timeout)
				result2, err := m.submitProbe(confirmCtx, client, ep, target, targetType, payload)
				cancel()
				if err == nil && m.detectTimeDelay(result2.Duration, baseline.Duration, delay) {
					confirmed = true
				}
			}

			if confirmed {
				dedupKey := fmt.Sprintf("%s|%s|%s|TIME", ep.URL, target, targetType)
				seen[dedupKey] = struct{}{}
				findings = append(findings, m.buildFinding(ep, target, targetType, payload, "Time-Based SQL Injection (Blind)", descriptions.SQLiTimeBased, scanner.Critical, scanner.ConfirmedConfidence))
				break // One time payload is enough per target
			}
		}
	}

	return findings, nil
}

func (m *SQLiModule) getBaseline(ctx context.Context, client *httpclient.Client, ep crawler.Endpoint) (*httpclient.ResponseResult, error) {
	return client.Submit(httpclient.SubmitRequest{
		Method: ep.Method,
		URL:    ep.URL,
		Params: m.prepareParams(ep, "", ""),
		Ctx:    ctx,
	})
}

func (m *SQLiModule) submitProbe(ctx context.Context, client *httpclient.Client, ep crawler.Endpoint, target, targetType, payload string) (*httpclient.ResponseResult, error) {
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

func (m *SQLiModule) prepareParams(ep crawler.Endpoint, target, payload string) map[string]string {
	params := make(map[string]string, len(ep.Params))
	for _, p := range ep.Params {
		if p == target {
			params[p] = payload
		} else {
			params[p] = "1" // Default value
		}
	}
	return params
}

func (m *SQLiModule) detectError(body, baseline string) bool {
	bodyLower := strings.ToLower(body)
	baselineLower := strings.ToLower(baseline)

	for _, sig := range sqlErrorSignatures {
		// Only flag if the signature is in the probe response but NOT in the baseline
		if strings.Contains(bodyLower, sig) && !strings.Contains(baselineLower, sig) {
			return true
		}
	}
	return false
}

func (m *SQLiModule) detectTimeDelay(duration, baseline, delay time.Duration) bool {
	// Flag if duration >= baseline + (delay * 0.9)
	// We use 0.9 to allow for some network jitter
	threshold := baseline + time.Duration(float64(delay)*0.9)
	return duration >= threshold
}

func (m *SQLiModule) buildFinding(ep crawler.Endpoint, target, targetType, payload, title string, checkID descriptions.CheckID, severity scanner.Severity, confidence scanner.Confidence) scanner.Finding {
	evidence := fmt.Sprintf("Injected payload %q into %s %q caused a detectable response change.", payload, strings.ToLower(targetType), target)
	if checkID == descriptions.SQLiTimeBased {
		evidence = fmt.Sprintf("Injected time-delay payload %q into %s %q caused a measurable response delay.", payload, strings.ToLower(targetType), target)
	}

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
		Remediation:    "Use parameterized queries (prepared statements) for all database access. Never concatenate user-supplied input into SQL strings. Implement a robust web application firewall (WAF).",
		Timestamp:      time.Now(),
	}
}
