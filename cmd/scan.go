package cmd

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Stolonifer1903/gosentinel/internal/crawler"
	"github.com/Stolonifer1903/gosentinel/internal/httpclient"
	"github.com/Stolonifer1903/gosentinel/internal/logger"
	"github.com/Stolonifer1903/gosentinel/internal/report"
	"github.com/Stolonifer1903/gosentinel/internal/scanner"
	"github.com/Stolonifer1903/gosentinel/internal/scanner/modules"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var out io.Writer = os.Stdout

func printf(format string, a ...interface{}) {
	fmt.Fprintf(out, format, a...)
}

func println(a ...interface{}) {
	fmt.Fprintln(out, a...)
}

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

// ── scan command ──────────────────────────────────────────────────────────────

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a target URL for vulnerabilities",
	Long: hiWhite("The scan command launches the core security engine against a target URL.\n") +
		white("It coordinates crawling, header analysis, and active injection payloads.\n\n") +
		hiWhite("Active Modules:\n") +
		cyan("  • Security Headers ") + dim("(Passive)") + white(" — Audits CSP, HSTS, X-Frame-Options, etc.\n") +
		cyan("  • Sensitive Data   ") + dim("(Passive)") + white(" — Scans for secrets, keys, and debug leaks.\n") +
		cyan("  • CSRF Protection  ") + dim("(Passive)") + white(" — Detects state-changing forms without tokens.\n") +
		cyan("  • Reflected XSS    ") + dim("(Active) ") + white(" — Tests parameters for immediate reflection.\n") +
		cyan("  • Stored XSS       ") + dim("(Active) ") + white(" — 2-phase canary detection for persisted data.\n") +
		cyan("  • SQL Injection    ") + dim("(Active) ") + white(" — Tests for error-based and time-based SQLi.\n") +
		cyan("  • SSRF             ") + dim("(Active) ") + white(" — Tests for in-band, partial, and timing-based SSRF.\n\n") +
		hiWhite("Usage:\n") +
		white("  gosentinel scan --url <target> [flags]\n\n") +
		hiWhite("Examples:\n") +
		white("  gosentinel scan --url https://example.com\n") +
		white("  gosentinel scan --url https://example.com --depth 3 -o report.html\n") +
		white("  gosentinel scan --url https://example.com --confirm-stored-xss\n") +
		white("  gosentinel scan --url https://example.com --cookie \"PHPSESSID=abc123\"\n") +
		white("  gosentinel scan --url https://example.com -H \"Authorization: Bearer token\"\n"),
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringP("url", "u", "", "Target URL to scan (e.g. https://example.com)")
	scanCmd.Flags().IntP("depth", "d", 2, "Crawler depth limit (how many links deep to follow)")
	scanCmd.Flags().IntP("concurrency", "c", 10, "Number of concurrent network requests")
	scanCmd.Flags().StringP("output", "o", "", "Write results to a file (.html or .json)")
	scanCmd.Flags().BoolP("confirm-stored-xss", "x", false, "Enable 2-phase verification of stored XSS via automated script injection")
	scanCmd.Flags().Bool("ssrf-cloud-metadata", false, "Enable probing for AWS/GCP/Azure cloud metadata endpoints (default: false)")
	scanCmd.Flags().StringP("cookie", "b", "", `Cookies to attach to all requests (e.g. "session=abc123; token=xyz")`)
	scanCmd.Flags().StringArrayP("header", "H", nil, `Custom header to attach to all requests (repeatable, e.g. -H "Authorization: Bearer token")`)
	scanCmd.Flags().Bool("log", false, "Enable session logging to a local file")

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
	confirmStored, _ := cmd.Flags().GetBool("confirm-stored-xss")
	enableCloudMeta, _ := cmd.Flags().GetBool("ssrf-cloud-metadata")
	cookieStr, _ := cmd.Flags().GetString("cookie")
	customHeaders, _ := cmd.Flags().GetStringArray("header")
	enableLog, _ := cmd.Flags().GetBool("log")

	if enableLog {
		session, err := logger.StartSession()
		if err != nil {
			return fmt.Errorf("failed to start logging session: %w", err)
		}
		defer session.Close()
		out = session.Writer()
	}

	// ── 1. Validate URL ───────────────────────────────────────────────────────
	parsedURL, err := validateURL(target)
	if err != nil {
		return err
	}

	// ── 2. Build auth headers ────────────────────────────────────────────────
	defaultHeaders := make(map[string]string)
	if cookieStr != "" {
		if warning := validateCookie(cookieStr); warning != "" {
			printf(" %s %s\n", yellow("[!]"), warning)
		}
		defaultHeaders["Cookie"] = cookieStr
	}
	for _, h := range customHeaders {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			defaultHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		} else {
			printf(" %s Ignoring malformed header %q (expected \"Key: Value\")\n", yellow("[!]"), h)
		}
	}

	// Create an auth-aware client and update the global default so the crawler
	// and FetchHeaders also send auth headers automatically.
	sharedClient := httpclient.NewClientWithAuth(httpclient.DefaultClient.HTTPClient(), defaultHeaders)
	httpclient.SetDefaultClient(sharedClient)

	authMode := describeAuthMode(defaultHeaders)
	printScanHeader(parsedURL.String(), depth, authMode)

	// ── 2. Fetch headers ──────────────────────────────────────────────────────
	printf("\n%s Fetching response headers…\n\n", cyan("[~]"))

	httpResult, err := httpclient.FetchHeadersWithContext(cmd.Context(), parsedURL.String())
	if err != nil {
		return fmt.Errorf("could not reach target: %w", err)
	}

	printStatusLine(httpResult)
	printHeaders(httpResult, verbose)

	// ── 3. Spidering ──────────────────────────────────────────────────────────
	printf("%s Spidering target (depth %d, concurrency %d)…\n", cyan("[~]"), depth, concurrency)
	spider, err := crawler.NewSpider(parsedURL.String(), depth, concurrency)
	if err != nil {
		return fmt.Errorf("initializing spider: %w", err)
	}

	endpoints, err := spider.Crawl(cmd.Context())
	if err != nil {
		printf(" %s Spidering failed: %v\n\n", red("[!]"), err)
	} else {
		printf(" %s Discovered %d endpoints\n\n", green("[✔]"), len(endpoints))
		if len(endpoints) > 0 {
			printEndpoints(endpoints, verbose)
		}
	}

	// ── 4. Run scanner engine ─────────────────────────────────────────────────────
	printf("%s Running vulnerability checks…\n", cyan("[~]"))

	ssrfConfig := modules.DefaultSSRFConfig
	ssrfConfig.EnableCloudMetadata = enableCloudMeta

	activeModules := []scanner.Module{
		&modules.HeadersModule{},
		&modules.SensitiveModule{},
		&modules.CSRFModule{},
		&modules.XSSModule{Client: sharedClient},
		modules.NewStoredXSSModule(sharedClient, confirmStored),
		&modules.SQLiModule{Client: sharedClient, Config: modules.DefaultSQLiConfig},
		&modules.SSRFModule{Client: sharedClient, Config: ssrfConfig},
	}
	engine := scanner.NewEngine(activeModules)

	// ── Progress printer ────────────────────────────────────────────────────────
	// Passive modules fire concurrently, so their prints must be serialised.
	var progressMu sync.Mutex
	engine.OnProgress = func(ev scanner.ProgressEvent) {
		progressMu.Lock()
		defer progressMu.Unlock()

		phase := dim("passive")
		if ev.ModuleType == scanner.TypeActive {
			phase = dim("active ")
		}

		switch ev.Stage {
		case scanner.StageStart:
			printf("   %s  %-22s  %s\n",
				cyan("[~]"),
				ev.ModuleName,
				phase,
			)
		case scanner.StageDone:
			elapsed := fmt.Sprintf("%dms", ev.Elapsed.Milliseconds())
			if ev.FindCount > 0 {
				printf("   %s  %-22s  %s  %s  %s\n",
					green("[✔]"),
					ev.ModuleName,
					phase,
					dim(elapsed),
					yellow(fmt.Sprintf("%d finding(s)", ev.FindCount)),
				)
			} else {
				printf("   %s  %-22s  %s  %s\n",
					green("[✔]"),
					ev.ModuleName,
					phase,
					dim(elapsed),
				)
			}
		}
	}

	scanResult, err := engine.Run(cmd.Context(), endpoints)
	if err != nil {
		printf(" %s Scanner failed: %v\n\n", red("[!]"), err)
	} else {
		groupedFindings := scanResult.Group()
		printf(" %s %d unique finding(s) detected (%d instances)\n\n",
			green("[✔]"), len(groupedFindings), len(scanResult.Findings))

		var hasErrors bool
		for _, mr := range scanResult.ModuleResults {
			if mr.Error != nil {
				if !hasErrors {
					printf("%s\n", hiWhite("  ┌─ Module Errors "))
					hasErrors = true
				}
				printf("  %s %s: %s\n", red("│"), cyan(mr.ModuleName), mr.Error.Error())
			}
		}
		if hasErrors {
			printf("%s\n\n", hiWhite("  └─"))
		}

		if len(groupedFindings) > 0 {
			printFindings(groupedFindings, verbose)
		}
	}

	// ── 5. Write report file if --output was given ────────────────────────────
	if output != "" && scanResult != nil {
		modErrors := make(map[string]string)
		for _, mr := range scanResult.ModuleResults {
			if mr.Error != nil {
				modErrors[mr.ModuleName] = mr.Error.Error()
			}
		}
		if err := writeReport(output, parsedURL.String(), httpResult, scanResult.Group(), endpoints, modErrors); err != nil {
			return fmt.Errorf("writing report: %w", err)
		}
	} else if output != "" {
		printf(" %s Skipping report — scanner did not produce results.\n\n", yellow("[!]"))
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

func printScanHeader(target string, depth int, authMode string) {
	line := strings.Repeat("─", 60)
	println(cyan(line))
	printf(" %s  %s\n", hiWhite("Target:"), green(target))
	printf(" %s   %s\n", hiWhite("Depth:"), yellow("%d", depth))
	if authMode != "" {
		printf(" %s    %s\n", hiWhite("Auth:"), dim(authMode))
	}
	printf(" %s %s\n", hiWhite("Started:"), dim(time.Now().Format("2006-01-02 15:04:05")))
	println(cyan(line))
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

	printf(" %s %s   %s %s\n\n",
		hiWhite("Status:"), statusColor("%s", r.Status),
		hiWhite("Time:"), dim("%.0fms", float64(r.Duration.Microseconds())/1000),
	)
}

// printHeaders displays all response headers in the terminal.
func printHeaders(r *httpclient.HeaderResult, verbose bool) {
	// Sort header names for deterministic, readable output.
	names := make([]string, 0, len(r.Headers))
	for name := range r.Headers {
		names = append(names, name)
	}
	sort.Strings(names)

	printf("%s\n", hiWhite("  ┌─ Response Headers "))
	for _, name := range names {
		values := strings.Join(r.Headers[name], "; ")

		// Truncate very long values unless verbose mode is on.
		if !verbose && len(values) > 80 {
			values = values[:77] + "…"
		}

		printf("  %s %-36s %s\n",
			dim("│"), cyan("%-36s", name), white(values))
	}
	printf("%s\n\n", hiWhite("  └─"))
}

// writeReport dispatches to the right renderer based on the file extension.
// It also ensures reports are saved in an organized directory structure.
func writeReport(outPath, target string, r *httpclient.HeaderResult, findings []scanner.GroupedFinding, endpoints []crawler.Endpoint, modErrors map[string]string) error {
	result := &report.ScanResult{
		Target:       target,
		ScannedAt:    time.Now(),
		Duration:     r.Duration,
		StatusCode:   r.StatusCode,
		Status:       r.Status,
		SeedURLHeaders: r.Headers,
		Findings:     findings,
		Endpoints:    endpoints,
		ModuleErrors: modErrors,
	}

	ext := strings.ToLower(filepath.Ext(outPath))
	filename := filepath.Base(outPath)

	// If no extension, default to .json as requested.
	if ext == "" {
		ext = ".json"
		outPath += ".json"
		filename += ".json"
	}

	var finalPath string
	switch ext {
	case ".json":
		finalPath = filepath.Join("reports", "json", filename)
		if err := report.WriteJSON(result, finalPath); err != nil {
			return err
		}
	case ".html", ".htm":
		finalPath = filepath.Join("reports", "html", filename)
		if err := report.WriteHTML(result, finalPath); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported output format %q — only .html and .json are supported", ext)
	}

	abs, _ := filepath.Abs(finalPath)
	printf(" %s Report saved → %s\n\n", green("[✔]"), cyan(abs))
	return nil
}

// printFindings renders scanner findings in a structured terminal block.
func printFindings(findings []scanner.GroupedFinding, verbose bool) {
	severityColor := map[scanner.Severity]func(string, ...interface{}) string{
		scanner.Critical: red,
		scanner.High:     red,
		scanner.Medium:   yellow,
		scanner.Low:      cyan,
		scanner.Info:     dim,
	}

	printf("%s\n", hiWhite("  ┌─ Findings Summary "))
	for _, f := range findings {
		sevFn, ok := severityColor[f.Severity]
		if !ok {
			sevFn = white
		}

		countSuffix := ""
		if len(f.Endpoints) > 1 {
			countSuffix = dim(" (%d endpoints)", len(f.Endpoints))
		}

		printf("  %s %s %s%s\n",
			sevFn("│"), sevFn("%-10s", string(f.Severity)), white("%s", f.Title), countSuffix)
		printf("  %s         %s\n", dim("│"), dim("%s", f.OWASP))

		if verbose {
			for _, u := range f.Endpoints {
				if u.Detail != "" {
					printf("  %s           %s %s\n", dim("│"), dim("→ %s", u.URL), dim("[%s]", u.Detail))
				} else {
					printf("  %s           %s\n", dim("│"), dim("→ %s", u.URL))
				}
			}
		}
	}
	printf("%s\n\n", hiWhite("  └─"))
}

func printEndpoints(endpoints []crawler.Endpoint, verbose bool) {
	printf("%s\n", hiWhite("  ┌─ Discovered Attack Surface "))

	for _, e := range endpoints {
		methodColor := green
		if e.Method == "POST" {
			methodColor = yellow
		} else if e.Method != "GET" {
			methodColor = red
		}

		paramsOutput := ""
		if len(e.Params) > 0 {
			var paramKeys []string
			for p := range e.Params {
				paramKeys = append(paramKeys, p)
			}
			sort.Strings(paramKeys)
			paramsOutput = dim(" [%s]", strings.Join(paramKeys, ", "))
		}

		// Truncate long URLs unless verbose
		displayURL := e.URL
		if !verbose && len(displayURL) > 80 {
			displayURL = displayURL[:77] + "…"
		}

		printf("  %s %-6s %s%s\n",
			cyan("│"), methodColor("%s", e.Method), white("%s", displayURL), paramsOutput)
	}
	printf("%s\n\n", hiWhite("  └─"))
}

// validateCookie checks that a raw cookie string contains at least one valid
// key=value pair. Returns a warning message if the format looks wrong, or ""
// if it looks acceptable. The scan still proceeds — this is a best-effort guard.
func validateCookie(raw string) string {
	parts := strings.Split(raw, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "=") {
			return fmt.Sprintf("Cookie fragment %q has no '=' separator — the server may ignore it. "+
				"Expected format: \"name=value; name2=value2\"", part)
		}
	}
	return ""
}

// describeAuthMode returns a human-readable summary of the auth configuration
// for display in the scan header. Returns "" when no auth is configured.
func describeAuthMode(headers map[string]string) string {
	if len(headers) == 0 {
		return ""
	}

	var parts []string
	if _, ok := headers["Cookie"]; ok {
		parts = append(parts, "Cookie")
	}

	customCount := 0
	for key := range headers {
		if key != "Cookie" {
			customCount++
		}
	}
	if customCount == 1 {
		parts = append(parts, "1 custom header")
	} else if customCount > 1 {
		parts = append(parts, fmt.Sprintf("%d custom headers", customCount))
	}

	return strings.Join(parts, " + ")
}
