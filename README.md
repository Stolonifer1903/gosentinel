# GoSentinel

GoSentinel is a concurrent web vulnerability scanner designed for reconnaissance and security auditing. It combines a host-scoped BFS crawler with a pluggable scanning engine to identify common security misconfigurations and sensitive data exposure.

## Core Functionality

- **Concurrent BFS Crawler**: A high-performance, thread-safe spider that recursively maps the target attack surface. It intelligently parses DOMs for links and forms, extracts query parameters, normalizes URLs, and strictly enforces scope boundaries while handling HTTP redirects efficiently.
- **Phased Scanner Engine**: Orchestrates modules using a highly efficient two-phase execution strategy:
  - **Passive Phase**: Modules that analyze responses safely (without mutation) run concurrently, maximizing throughput.
  - **Active Phase**: Modules that inject malicious payloads run sequentially to prevent data races, maintain target state integrity, and minimize aggressive traffic bursts.
- **Attack Surface Mapping**: Automatically catalogs all discovered endpoints, form fields, and URL query parameters during the reconnaissance phase, exposing them systematically to active modules.
- **Session Safety & Destructive Path Skipping**: Automatically identifies and flags "destructive" paths (e.g., `/logout`, `/signout`, `/logoff`) during crawling. The engine skips these endpoints for all active and passive modules by default to prevent accidental session termination during authenticated scans.
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
| **IDOR**       | Active  | Detects Insecure Direct Object Reference via numeric ID enumeration and Jaccard similarity-based response analysis.                               |
| **Access Control**| Active  | Performs comprehensive checks for Broken Access Control (BAC) including Privilege Escalation, Forced Browsing, HTTP Method Tampering, and JWT Manipulation. |

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

GoSentinel offers a rich set of CLI flags to customize your web security audits, adjust network performance, and supply authentication credentials.

---

#### ` -u, --url ` *(string, required)*
The target endpoint URL to scan and audit.
- **Behavior & Validation**: GoSentinel automatically validates the URL format. If the scheme (e.g., `https://`) is omitted (e.g., `example.com`), `https://` is prepended by default to ensure safe, secure transport. GoSentinel strictly limits all crawling and active scanning payloads to the host and port of the target URL to prevent unintended out-of-scope auditing of external sites.
- **Example Usage**:
  ```bash
  # Standard scan
  ./gosentinel scan --url https://example.com

  # Short option (omitting scheme defaults to https://)
  ./gosentinel scan -u example.com
  ```

---

#### ` -d, --depth ` *(int, default: `2`)*
The maximum depth limit for the Breadth-First Search (BFS) spider.
- **Behavior**: Controls how deep the crawler follows links discovered on the target site. 
  - A depth of `1` crawls only the root target URL.
  - A depth of `2` crawls the root target URL and any links found on that page.
  - Higher depths will dramatically expand the attack surface mapping but will increase scan times proportionally.
- **Example Usage**:
  ```bash
  # Deep crawl (depth 4)
  ./gosentinel scan --url https://example.com --depth 4

  # Short option
  ./gosentinel scan -u example.com -d 3
  ```

---

#### ` -c, --concurrency ` *(int, default: `10`)*
The maximum number of concurrent HTTP request workers.
- **Behavior**: Controls the concurrency of the BFS crawling phase and the passive security scanning phase. Active scanning modules run sequentially to prevent aggressive traffic spikes and race conditions on the target. Adjust this flag to scale performance based on target server capabilities and network conditions.
- **Example Usage**:
  ```bash
  # High-performance crawl (concurrency 25)
  ./gosentinel scan --url https://example.com --concurrency 25

  # Low-rate crawl (concurrency 3) for fragile endpoints
  ./gosentinel scan -u example.com -c 3
  ```

---

#### ` -o, --output ` *(string)*
The file path to export the audit findings.
- **Behavior**: Saves findings to the specified file path. The engine automatically detects the format from the file extension:
  - **HTML (`.html` / `.htm`)**: Generates a premium interactive single-page dashboard with a dark-mode theme, finding inspector, evidence display, and attack surface mappings. Saved in `reports/html/`.
  - **JSON (`.json` or no extension)**: Outputs raw structured audit logs, ideal for automated parsing, CI/CD pipes, and dashboard ingestion. Saved in `reports/json/`.
- **Example Usage**:
  ```bash
  # Generate visual interactive HTML dashboard
  ./gosentinel scan --url https://example.com --output report.html

  # Generate structured JSON data
  ./gosentinel scan -u example.com -o results.json
  ```

---

#### ` -b, --cookie ` *(string)*
Raw Cookie header string used to authenticate scan requests.
- **Behavior**: Sets the `Cookie` header on all crawler requests and scanning payloads. Allows auditing of authenticated dashboards, user profiles, and session-locked paths. GoSentinel parses the cookie string to verify that it matches standard `key=value` pairs and emits a helpful CLI warning if the format is invalid.
- **Example Usage**:
  ```bash
  # Crawl and audit authenticated session
  ./gosentinel scan --url https://example.com --cookie "PHPSESSID=abc123xyz; user=admin"

  # Short option
  ./gosentinel scan -u example.com -b "session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  ```

---

#### ` -H, --header ` *(stringArray, repeatable)*
Attach custom HTTP headers to every request.
- **Behavior**: Useful for providing custom HTTP authorization headers (e.g., Bearer tokens), overriding `User-Agent` strings, or passing anti-CSRF or client-identifying headers. This option is repeatable to attach multiple custom headers.
- **Example Usage**:
  ```bash
  # Scan with JWT Authorization bearer token
  ./gosentinel scan --url https://example.com --header "Authorization: Bearer eyJ..."

  # Attach multiple headers with short option
  ./gosentinel scan -u example.com -H "Authorization: Bearer eyJ..." -H "X-Scanner: GoSentinel"
  ```

---

#### ` -x, --confirm-stored-xss ` *(boolean, default: `false`)*
Enables a two-phase active verification routine for Stored XSS.
- **Behavior**: When enabled, the Stored XSS module actively attempts to confirm that payload injections persist and execute on remote endpoints. It injects a unique, non-destructive canary payload on input pathways, then makes automated follow-up requests to corresponding read endpoints to check if the exact DOM payload gets rendered back raw.
- **Example Usage**:
  ```bash
  # Enable active 2-phase Stored XSS confirmation
  ./gosentinel scan --url https://example.com --confirm-stored-xss

  # Short option
  ./gosentinel scan -u example.com -x
  ```

---

#### ` --ssrf-cloud-metadata ` *(boolean, default: `false`)*
Enables active SSRF probes targeted at cloud metadata endpoints.
- **Behavior**: Instructs the Server-Side Request Forgery (SSRF) module to actively include sensitive internal IP space and cloud provider metadata APIs (such as AWS, GCP, and Azure IMDS endpoints at `169.254.169.254`) in active injection parameter payloads to detect critical cloud credential leaks.
- **Example Usage**:
  ```bash
  # Test target parameters for SSRF to cloud metadata
  ./gosentinel scan --url https://example.com --ssrf-cloud-metadata
  ```

---

#### ` --log ` *(boolean, default: `false`)*
Activates real-time scanner execution logging to a local file.
- **Behavior**: Starts an intelligent logging session that logs the identical colorized CLI terminal output directly to a persistent, timestamped text file inside the workspace for debugging, auditing, or record-keeping.
- **Example Usage**:
  ```bash
  # Scan with logging enabled
  ./gosentinel scan --url https://example.com --log
  ```

---

#### ` -v, --verbose ` *(boolean, default: `false`, Global Flag)*
Enables deep verbosity and technical tracing in the CLI output.
- **Behavior**: Displays full technical breakdowns of the target's responsive states. Enabling verbosity outputs:
  - Complete, raw HTTP response headers.
  - Complete, un-truncated lists of crawled URLs, HTTP methods, and query parameters.
  - Granular vulnerability findings, showing exact endpoint matches and payload-reflection traces.
- **Example Usage**:
  ```bash
  # View verbose scanning traces
  ./gosentinel scan --url https://example.com --verbose

  # Combine short option
  ./gosentinel scan -u example.com -v
  ```


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
