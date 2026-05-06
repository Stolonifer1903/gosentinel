# GoSentinel

GoSentinel is a concurrent web vulnerability scanner designed for reconnaissance and security auditing. It combines a host-scoped BFS crawler with a pluggable scanning engine to identify common security misconfigurations and sensitive data exposure.

## Core Functionality

- **Concurrent BFS Crawler**: A high-performance, thread-safe spider that recursively maps the target attack surface. It intelligently parses DOMs for links and forms, extracts query parameters, normalizes URLs, and strictly enforces scope boundaries while handling HTTP redirects efficiently.
- **Phased Scanner Engine**: Orchestrates modules using a highly efficient two-phase execution strategy:
  - **Passive Phase**: Modules that analyze responses safely (without mutation) run concurrently, maximizing throughput.
  - **Active Phase**: Modules that inject malicious payloads run sequentially to prevent data races, maintain target state integrity, and minimize aggressive traffic bursts.
- **Attack Surface Mapping**: Automatically catalogs all discovered endpoints, form fields, and URL query parameters during the reconnaissance phase, exposing them systematically to active modules.
- **Intelligent Deduplication & Grouping**: Automatically groups identical findings across multiple endpoints. It promotes findings based on **Confidence Levels** (Certain, Firm, Tentative) and deduplicates based on normalized URLs and parameter structures.
- **Multi-format Reporting**: Outputs results dynamically via CLI progress hooks, generating structured JSON for CI/CD integrations or an interactive, dark-mode-enabled HTML dashboard for visual analysis.

## Security Modules

| Module         | Type    | Details                                                                                                                                           |
| :------------- | :------ | :------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Headers**    | Passive | Audits HTTP responses for missing or misconfigured security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options).                         |
| **Sensitive**  | Passive | Uses high-confidence regex patterns to detect exposed AWS keys, private PEM keys, GitHub tokens, stack traces, and enabled directory indexing.    |
| **CSRF**       | Passive | Detects missing or weak CSRF tokens in state-changing HTML forms (e.g., POST, PUT, DELETE operations).                                            |
| **Reflected XSS**| Active  | Injects safe polyglot payloads into URL parameters and form fields, evaluating the DOM to detect unescaped HTML body breakouts.                   |
| **Stored XSS** | Active  | Employs a 2-phase canary injection mechanism to detect persistent XSS. Safely prompts for user confirmation before writing data to target routes. |
| **SQLi**       | Active  | Detects SQL Injection via error-based heuristics and time-based (blind) payload delays, validating against dynamic baseline response profiles.    |
| **SSRF**       | Active  | Tests parameters for Server-Side Request Forgery using in-band reflection, cloud metadata endpoints, and partial-blind port scanning heuristics.  |

## Quick Start

### Build from source

```bash
go build -o gosentinel .
```

### Basic Usage

```bash
# Scan a target with default depth (2)
./gosentinel scan --url https://example.com

# Map attack surface with custom depth and output report
./gosentinel scan --url https://example.com --depth 4 --output report.html
```

### Flags

- `--url`: The target URL to scan (required).
- `--depth`: Maximum crawl depth (default 2).
- `--concurrency`: Number of concurrent workers (default 10).
- `--output`: Path to save the HTML or JSON report.
- `--confirm-stored-xss`: Enable 2-phase verification of stored XSS via automated script injection.
- `--ssrf-cloud-metadata`: Enable probing for AWS/GCP/Azure cloud metadata endpoints.
- `-v, --verbose`: Show detailed URLs and technical evidence in terminal output.

## Developer Guide

### Project Architecture

- `cmd/`: CLI interface, progress rendering, and command definitions (Cobra).
- `internal/scanner/`: Core orchestration logic, finding models, module registry, and descriptions.
- `internal/crawler/`: High-performance BFS spider, DOM parsing, and reconnaissance logic.
- `internal/report/`: HTML and JSON reporting logic.
- `internal/httpclient/`: Shared intelligent networking layer with timeout and redirect tracking.

### Web Dashboard

A premium React + Vite dashboard for visualizing security datasets. Features include:
- **Universal Theme Support**: Seamless switching between high-contrast Dark and Light modes.
- **Finding Inspector**: A deep-dive modal with tabbed views (Description, Evidence, Remediation) and **intra-vulnerability navigation** to cycle through affected endpoints.
- **Attack Surface Mapping**: Comprehensive catalog of discovered assets, endpoints, and form parameters.
- **Scan Overview**: Real-time summary of security posture and severity distribution.

To start the development server:

```bash
cd web
npm install
npm run dev
```

### How to Build a Module

1. Create a new file in `internal/scanner/modules/`.
2. Implement the `Module` interface:
   ```go
   type Module interface {
       Name() string
       Type() ModuleType // Returns scanner.TypePassive or scanner.TypeActive
       Run(ctx context.Context, endpoints []crawler.Endpoint) ([]scanner.Finding, error)
   }
   ```
3. Register your module in `cmd/scan.go` inside the `runScan` function.

## License

[MIT](LICENSE)
