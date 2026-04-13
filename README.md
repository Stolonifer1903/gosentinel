# GoSentinel

GoSentinel is a concurrent web vulnerability scanner designed for reconnaissance and security auditing. It combines a host-scoped BFS crawler with a pluggable scanning engine to identify common security misconfigurations and sensitive data exposure.

## Core Functionality

- **BFS Crawler**: A thread-safe spider that recursively discovers links and forms. It is restricted to the target host and its subdomains by default.
- **Concurrent Engine**: Orchestrates multiple vulnerability modules in parallel using Go's concurrency primitives.
- **Finding Aggregation**: Groups identical findings (e.g., missing headers on multiple pages) into single reports to reduce output noise.
- **Aggregated HTML Reports**: Generates a scannable, dark-mode dashboard with expandable technical evidence.

## Security Modules

| Module | Detection Type | Details |
| :--- | :--- | :--- |
| **Headers** | Passive | Audits CSP, HSTS, X-Frame-Options, and other security headers. |
| **Sensitive** | Passive | Scans for AWS keys, private keys, tokens, and hardcoded secrets. |
| **Leakage** | Passive | Identifies stack traces, debug error messages, and directory listings. |

## Quick Start

### Build from source
```bash
go build -o gosentinel .
```

### Basic usage
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
- `--output`: Path to save the HTML report.
- `-v, --verbose`: Show detailed URLs and evidence in terminal output.

## Developer Guide

### Project Architecture
- `cmd/`: CLI interface and command definitions.
- `internal/scanner/`: Core orchestration logic and finding models.
- `internal/crawler/`: BFS spider and reconnaissance logic.
- `internal/report/`: HTML template and reporting logic.

### How to Build a Module
1. Create a new file in `internal/scanner/modules/`.
2. Implement the `Module` interface:
   ```go
   type Module interface {
       Name() string
       Run(ctx context.Context, endpoints []crawler.Endpoint) ([]scanner.Finding, error)
   }
   ```
3. Register your module in `cmd/scan.go` inside the `runScan` function:
   ```go
   engine.RegisterModule(&modules.YourNewModule{})
   ```

## License
[MIT](LICENSE)
