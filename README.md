# GoSentinel

> A fast, concurrent OWASP Top 10 web vulnerability scanner built in Go.

GoSentinel is a CLI tool that scans a target web application for common security vulnerabilities and generates detailed HTML reports — powered by Go's concurrency model.

---

## Features

- 🕵️ **BFS Web Crawler** — Recursively discovers links and forms while respecting `--depth`
- 🛡️ **Security Header Audit** — Detects missing HSTS, CSP, X-Frame-Options, and more
- 🔍 **Attack Surface Mapping** — Automatically extracts form inputs and parameters
- 📄 **HTML Report Generation** — Self-contained dark-mode reports with full discovery logs
- 🔒 **Domain Locking** — Safety controls to ensure the scanner stays within target boundaries
- 🎨 **Premium Terminal UI** — Colour-coded, formatted output for clear reconnaissance

> **OWASP scanner modules** (SQLi, XSS, CSRF, etc.) are currently being integrated into the engine.

---

## Installation

**Requires Go 1.22+**

```bash
go install github.com/Stolonifer1903/gosentinel@latest
```

Or build from source:

```bash
git clone https://github.com/Stolonifer1903/gosentinel.git
cd gosentinel
go build -o gosentinel .
```

---

## Usage

```bash
# Basic scan + spidering (default depth 2)
gosentinel scan --url https://example.com

# Map deep attack surface (depth 5)
gosentinel scan --url https://example.com --depth 5

# Save discovery and audit results to an HTML report
gosentinel scan --url https://example.com --output results.html

# Verbose mode (shows full URLs and headers)
gosentinel scan --url https://example.com -v
```

---

## Example Output

```text
────────────────────────────────────────────────────────────
 Target:  https://example.com
 Depth:   2
 Started: 2026-04-09 03:27:09
────────────────────────────────────────────────────────────

[~] Fetching response headers…
 Status: 200 OK   Time: 56ms

[~] Spidering target (depth 2)…
 [✔] Discovered 3 endpoints

  ┌─ Discovered Attack Surface 
  │ GET    https://example.com
  │ GET    https://example.com/about
  │ POST   https://example.com/login [user, password]
  └─

  ┌─ Security Header Audit 
  │ ✘ MISSING   Content-Security-Policy              CSP — mitigates XSS
  │ ✘ MISSING   Strict-Transport-Security            HSTS — enforces HTTPS
  │ ✘ MISSING   X-Frame-Options                      Clickjacking protection
  └─

 [✘] 6 security headers missing — review recommended.

 [✔] Report saved → /Users/shreyyadav/GoSentinel/results.html
```

---

## Project Structure

```
gosentinel/
├── cmd/
│   ├── root.go          # CLI entry points and banners
│   └── scan.go          # Core scan logic and output formatting
├── internal/
│   ├── crawler/
│   │   └── crawler.go   # BFS spider, link & form extraction
│   ├── httpclient/
│   │   └── client.go    # Persistent HTTP client & header utilities
│   └── report/
│       └── html.go      # HTML template and report generation
├── main.go
└── go.mod
```

---

## Roadmap

- [x] CLI scaffold (Cobra)
- [x] HTTP header fetching
- [x] Security header audit
- [x] HTML report generation
- [x] BFS web crawler (Spider) with `--depth`
- [ ] SQLi detection module
- [ ] XSS detection module
- [ ] CSRF detection module
- [ ] SSRF detection module
- [ ] IDOR detection module
- [ ] React dashboard (Web UI)

---

## License

[MIT](LICENSE)
