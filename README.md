# GoSentinel

GoSentinel is a concurrent web vulnerability scanner designed for reconnaissance and security auditing. It combines a host-scoped BFS crawler with a pluggable scanning engine to identify common security misconfigurations and sensitive data exposure.

## Core Functionality

- **Concurrent BFS Crawler**: A thread-safe spider that recursively discovers links and forms while enforcing strict host-scoped protection. Now includes improved URL resolution, context propagation, and centralized HTTP client management.
- **Phased Scanner Engine**: Orchestrates modules using a two-phase execution strategy: **Passive** modules run concurrently for speed, while **Active** modules run sequentially to prevent data races and ensure target state integrity.
- **Attack Surface Mapping**: Automatically catalog discovered endpoints, forms, and technical assets during the reconnaissance phase.
- **Confidence-Aware Aggregation**: Automatically groups identical findings across multiple endpoints. Promotes findings based on **Confidence Levels** (Certain, Firm, Tentative) and deduplicates based on normalized URLs.
- **Multi-format Reporting**: Generates scannable, dark-mode HTML dashboards and structured JSON output for CI/CD integration.

## Security Modules

| Module        | Detection Type | Details                                                                 |
| :------------ | :------------- | :---------------------------------------------------------------------- |
| **Headers**    | Passive        | Audits CSP, HSTS, X-Frame-Options, and other security headers with origin caching. |
| **Sensitive**  | Passive        | Scans for AWS keys, private keys, tokens, and secrets with an improved ruleset.   |
| **CSRF**       | Passive        | Detects missing CSRF tokens in state-changing HTML forms.                         |
| **XSS**        | Active         | Injects payloads into parameters and forms; supports escaped reflection detection. |
| **Stored XSS** | Active         | 2-phase canary detection for payloads persisted in databases or files.            |
| **Leakage**    | Passive        | Identifies stack traces, debug error messages, and directory listings.            |

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
- `-v, --verbose`: Show detailed URLs and technical evidence in terminal output.

## Developer Guide

### Project Architecture

- `cmd/`: CLI interface and command definitions (Cobra).
- `internal/scanner/`: Core orchestration logic, finding models, and module registry.
- `internal/crawler/`: High-performance BFS spider and reconnaissance logic.
- `internal/report/`: HTML and JSON reporting logic.
- `internal/httpclient/`: Shared intelligent networking layer with redirect tracking.

### Web Dashboard (Experimental)

A React + Vite based dashboard for visualizing scan datasets. Includes a comprehensive **Scan Overview**, **Attack Surface** mapping (with dedicated analysis tabs), and a **Detailed Finding Inspector**.

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
