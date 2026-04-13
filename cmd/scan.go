package cmd

import (
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/Stolonifer1903/gosentinel/internal/crawler"
	"github.com/Stolonifer1903/gosentinel/internal/httpclient"
	"github.com/Stolonifer1903/gosentinel/internal/report"
	"github.com/Stolonifer1903/gosentinel/internal/scanner"
	"github.com/Stolonifer1903/gosentinel/internal/scanner/modules"
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

	// ── 4. Run scanner engine ─────────────────────────────────────────────────────
	fmt.Printf("%s Running vulnerability checks…\n", cyan("[~]"))
	activeModules := []scanner.Module{
		&modules.HeadersModule{},
	}
	engine := scanner.NewEngine(activeModules)
	scanResult, err := engine.Run(cmd.Context(), endpoints)
	if err != nil {
		fmt.Printf(" %s Scanner failed: %v\n\n", red("[!]"), err)
	} else {
		groupedFindings := scanResult.Group()
		fmt.Printf(" %s %d unique finding(s) detected (%d instances)\n\n",
			green("[✔]"), len(groupedFindings), len(scanResult.Findings))

		if len(groupedFindings) > 0 {
			printFindings(groupedFindings, verbose)
		}
	}

	// ── 5. Write report file if --output was given ────────────────────────────
	if output != "" {
		if err := writeReport(output, parsedURL.String(), httpResult, scanResult.Group(), endpoints); err != nil {
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

// printHeaders displays all response headers in the terminal.
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

		fmt.Printf("  %s %-36s %s\n",
			dim("│"), cyan("%-36s", name), white(values))
	}
	fmt.Printf("%s\n\n", hiWhite("  └─"))
}



// writeReport dispatches to the right renderer based on the file extension.
// It also ensures reports are saved in an organized directory structure.
func writeReport(outPath, target string, r *httpclient.HeaderResult, findings []scanner.GroupedFinding, endpoints []crawler.Endpoint) error {
	result := &report.ScanResult{
		Target:     target,
		ScannedAt:  time.Now(),
		Duration:   r.Duration,
		StatusCode: r.StatusCode,
		Status:     r.Status,
		AllHeaders: r.Headers,
		Findings:   findings,
		Endpoints:  endpoints,
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
	fmt.Printf(" %s Report saved → %s\n\n", green("[✔]"), cyan(abs))
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

	fmt.Printf("%s\n", hiWhite("  ┌─ Findings Summary "))
	for _, f := range findings {
		sevFn, ok := severityColor[f.Severity]
		if !ok {
			sevFn = white
		}

		countSuffix := ""
		if len(f.Endpoints) > 1 {
			countSuffix = dim(" (%d endpoints)", len(f.Endpoints))
		}

		fmt.Printf("  %s %s %s%s\n",
			sevFn("│"), sevFn("%-10s", string(f.Severity)), white("%s", f.Title), countSuffix)
		fmt.Printf("  %s         %s\n", dim("│"), dim("%s", f.OWASP))

		if verbose {
			for _, u := range f.Endpoints {
				fmt.Printf("  %s           %s\n", dim("│"), dim("→ %s", u))
			}
		}
	}
	fmt.Printf("%s\n\n", hiWhite("  └─"))
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
