package cmd

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/Stolonifer1903/gosentinel/internal/httpclient"
	"github.com/Stolonifer1903/gosentinel/internal/report"
	"github.com/Stolonifer1903/gosentinel/internal/crawler"
	"github.com/spf13/cobra"
)

// ── colour helpers ────────────────────────────────────────────────────────────

var (
	cyan    = color.New(color.FgCyan, color.Bold).SprintfFunc()
	green   = color.New(color.FgGreen, color.Bold).SprintfFunc()
	yellow  = color.New(color.FgYellow, color.Bold).SprintfFunc()
	red     = color.New(color.FgRed, color.Bold).SprintfFunc()
	white   = color.New(color.FgWhite).SprintfFunc()
	hiWhite = color.New(color.FgHiWhite, color.Bold).SprintfFunc()
	dim     = color.New(color.Faint).SprintfFunc()
)

// securityHeaders lists headers that are security-relevant so we can highlight
// missing ones during the headers-only phase. Full checks will live in the
// scanner/headers module later.
var securityHeaders = map[string]string{
	"strict-transport-security": "HSTS — enforces HTTPS",
	"content-security-policy":   "CSP — mitigates XSS",
	"x-frame-options":           "Clickjacking protection",
	"x-content-type-options":    "MIME-sniffing protection",
	"referrer-policy":           "Controls referrer leakage",
	"permissions-policy":        "Feature/permission control",
}

// ── scan command ──────────────────────────────────────────────────────────────

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a target URL for vulnerabilities",
	Long: hiWhite("Usage:\n") +
		white("  gosentinel scan --url <target> [flags]\n\n") +
		hiWhite("Examples:\n") +
		white("  gosentinel scan --url https://example.com\n") +
		white("  gosentinel scan --url https://example.com --depth 3 -v\n"),
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringP("url", "u", "", "Target URL to scan (required)")
	scanCmd.Flags().IntP("depth", "d", 2, "Crawler depth limit (pages to follow from the root)")
	scanCmd.Flags().IntP("concurrency", "c", 10, "Number of concurrent crawler requests")
	scanCmd.Flags().StringP("output", "o", "", "Write report to file (e.g. report.html)")

	// Mark --url as required so Cobra validates it before RunE is called.
	_ = scanCmd.MarkFlagRequired("url")

	rootCmd.AddCommand(scanCmd)
}

// ── handler ───────────────────────────────────────────────────────────────────

func runScan(cmd *cobra.Command, _ []string) error {
	target, _ := cmd.Flags().GetString("url")
	depth, _ := cmd.Flags().GetInt("depth")
	concurrency, _ := cmd.Flags().GetInt("concurrency")
	output, _ := cmd.Flags().GetString("output")
	verbose, _ := cmd.Root().PersistentFlags().GetBool("verbose")

	// ── 1. Validate URL ───────────────────────────────────────────────────────
	parsedURL, err := validateURL(target)
	if err != nil {
		return err
	}

	printScanHeader(parsedURL.String(), depth)

	// ── 2. Fetch headers ──────────────────────────────────────────────────────
	fmt.Printf("\n%s Fetching response headers…\n\n", cyan("[~]"))

	httpResult, err := httpclient.FetchHeaders(parsedURL.String())
	if err != nil {
		return fmt.Errorf("could not reach target: %w", err)
	}

	printStatusLine(httpResult)
	printHeaders(httpResult, verbose)

	// ── 3. Spidering ──────────────────────────────────────────────────────────
	fmt.Printf("%s Spidering target (depth %d, concurrency %d)…\n", cyan("[~]"), depth, concurrency)
	spider, err := crawler.NewSpider(parsedURL.String(), depth, concurrency)
	if err != nil {
		return fmt.Errorf("initializing spider: %w", err)
	}

	endpoints, err := spider.Crawl()
	if err != nil {
		fmt.Printf(" %s Spidering failed: %v\n\n", red("[!]"), err)
	} else {
		fmt.Printf(" %s Discovered %d endpoints\n\n", green("[✔]"), len(endpoints))
		if len(endpoints) > 0 {
			printEndpoints(endpoints, verbose)
		}
	}

	// ── 4. Build security audit findings ─────────────────────────────────────
	audit := buildSecurityAudit(httpResult)
	printSecuritySummary(audit)

	// ── 5. Write report file if --output was given ────────────────────────────
	if output != "" {
		if err := writeReport(output, parsedURL.String(), httpResult, audit, endpoints); err != nil {
			return fmt.Errorf("writing report: %w", err)
		}
	}

	return nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func validateURL(raw string) (*url.URL, error) {
	// Prepend scheme if absent so the user doesn't have to.
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "https://" + raw
	}

	parsed, err := url.ParseRequestURI(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid URL %q: %w", raw, err)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("invalid URL %q: missing host", raw)
	}
	return parsed, nil
}

func printScanHeader(target string, depth int) {
	line := strings.Repeat("─", 60)
	fmt.Println(cyan(line))
	fmt.Printf(" %s  %s\n", hiWhite("Target:"), green(target))
	fmt.Printf(" %s   %s\n", hiWhite("Depth:"), yellow("%d", depth))
	fmt.Printf(" %s %s\n", hiWhite("Started:"), dim(time.Now().Format("2006-01-02 15:04:05")))
	fmt.Println(cyan(line))
}

func printStatusLine(r *httpclient.HeaderResult) {
	statusColor := green
	switch {
	case r.StatusCode >= 500:
		statusColor = red
	case r.StatusCode >= 400:
		statusColor = yellow
	case r.StatusCode >= 300:
		statusColor = color.New(color.FgMagenta, color.Bold).SprintfFunc()
	}

	fmt.Printf(" %s %s   %s %s\n\n",
		hiWhite("Status:"), statusColor("%s", r.Status),
		hiWhite("Time:"), dim("%.0fms", float64(r.Duration.Microseconds())/1000),
	)
}

func printHeaders(r *httpclient.HeaderResult, verbose bool) {
	// Sort header names for deterministic, readable output.
	names := make([]string, 0, len(r.Headers))
	for name := range r.Headers {
		names = append(names, name)
	}
	sort.Strings(names)

	fmt.Printf("%s\n", hiWhite("  ┌─ Response Headers "))
	for _, name := range names {
		values := strings.Join(r.Headers[name], "; ")

		// Truncate very long values unless verbose mode is on.
		if !verbose && len(values) > 80 {
			values = values[:77] + "…"
		}

		// Highlight security-relevant headers.
		if _, isSec := securityHeaders[strings.ToLower(name)]; isSec {
			fmt.Printf("  %s %-36s %s\n",
				green("│"), green("%-36s", name), green(values))
		} else {
			fmt.Printf("  %s %-36s %s\n",
				dim("│"), cyan("%-36s", name), white(values))
		}
	}
	fmt.Printf("%s\n\n", hiWhite("  └─"))
}

// buildSecurityAudit checks the response headers against the known security
// header list and returns a slice of HeaderFinding for both console and report.
func buildSecurityAudit(r *httpclient.HeaderResult) []report.HeaderFinding {
	findings := make([]report.HeaderFinding, 0, len(securityHeaders))
	for header, description := range securityHeaders {
		var val string
		found := false
		for name, vals := range r.Headers {
			if strings.EqualFold(name, header) {
				found = true
				val = strings.Join(vals, "; ")
				break
			}
		}
		findings = append(findings, report.HeaderFinding{
			Header:      canonicalHeader(header),
			Present:     found,
			Value:       val,
			Description: description,
		})
	}
	// Sort: present first, then alphabetical — deterministic output.
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Present != findings[j].Present {
			return findings[i].Present
		}
		return findings[i].Header < findings[j].Header
	})
	return findings
}

func printSecuritySummary(findings []report.HeaderFinding) {
	fmt.Printf("%s\n", hiWhite("  ┌─ Security Header Audit "))

	missing := []string{}
	for _, f := range findings {
		if f.Present {
			fmt.Printf("  %s %s %s\n",
				green("│"), green("✔ PRESENT  "), white("%-36s %s", f.Header, dim(f.Description)))
		} else {
			fmt.Printf("  %s %s %s\n",
				red("│"), red("✘ MISSING  "), white("%-36s %s", f.Header, dim(f.Description)))
			missing = append(missing, f.Header)
		}
	}

	fmt.Printf("%s\n\n", hiWhite("  └─"))

	switch {
	case len(missing) == 0:
		fmt.Printf(" %s All security headers present.\n\n", green("[✔]"))
	case len(missing) <= 2:
		fmt.Printf(" %s %d security header(s) missing — low risk.\n\n", yellow("[!]"), len(missing))
	default:
		fmt.Printf(" %s %d security headers missing — review recommended.\n\n", red("[✘]"), len(missing))
		fmt.Printf("   %s %s\n\n", dim("Missing:"), dim(strings.Join(missing, ", ")))
	}

	fmt.Fprintf(os.Stdout, " %s Deep vulnerability scanning coming soon — run with --help for all options.\n\n",
		cyan("[i]"))
}

// writeReport dispatches to the right renderer based on the file extension.
func writeReport(outPath, target string, r *httpclient.HeaderResult, audit []report.HeaderFinding, endpoints []crawler.Endpoint) error {
	// Count missing headers for the summary banner.
	missingCount := 0
	for _, f := range audit {
		if !f.Present {
			missingCount++
		}
	}

	result := &report.ScanResult{
		Target:        target,
		ScannedAt:     time.Now(),
		Duration:      r.Duration,
		StatusCode:    r.StatusCode,
		Status:        r.Status,
		AllHeaders:    r.Headers,
		SecurityAudit: audit,
		Endpoints:     endpoints,
		MissingCount:  missingCount,
	}

	ext := strings.ToLower(filepath.Ext(outPath))
	switch ext {
	case ".html", ".htm", "":
		// Default to HTML when no extension given.
		if ext == "" {
			outPath += ".html"
		}
		if err := report.WriteHTML(result, outPath); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported output format %q — only .html is supported right now", ext)
	}

	abs, _ := filepath.Abs(outPath)
	fmt.Printf(" %s Report saved → %s\n\n", green("[✔]"), cyan(abs))
	return nil
}

// canonicalHeader converts "content-security-policy" → "Content-Security-Policy".
func canonicalHeader(s string) string {
	parts := strings.Split(s, "-")
	for i, p := range parts {
		if len(p) > 0 {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, "-")
}

func printEndpoints(endpoints []crawler.Endpoint, verbose bool) {
	fmt.Printf("%s\n", hiWhite("  ┌─ Discovered Attack Surface "))

	for _, e := range endpoints {
		methodColor := green
		if e.Method == "POST" {
			methodColor = yellow
		} else if e.Method != "GET" {
			methodColor = red
		}

		paramsOutput := ""
		if len(e.Params) > 0 {
			paramsOutput = dim(" [%s]", strings.Join(e.Params, ", "))
		}

		// Truncate long URLs unless verbose
		displayURL := e.URL
		if !verbose && len(displayURL) > 80 {
			displayURL = displayURL[:77] + "…"
		}

		fmt.Printf("  %s %-6s %s%s\n",
			cyan("│"), methodColor("%s", e.Method), white("%s", displayURL), paramsOutput)
	}
	fmt.Printf("%s\n\n", hiWhite("  └─"))
}
