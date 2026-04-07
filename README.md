# GoSentinel

> A fast, concurrent OWASP Top 10 web vulnerability scanner built in Go.

GoSentinel is a CLI tool that scans a target web application for common security vulnerabilities and generates detailed HTML reports — powered by Go's concurrency model.

---

## Features

- 🔍 **HTTP header fetching** — full response header inspection with timing
- 🛡️ **Security header audit** — detects missing HSTS, CSP, X-Frame-Options, and more
- 📄 **HTML report generation** — self-contained dark-mode report saved locally
- ⚙️ **Configurable crawler depth** — controls how many pages deep the scanner crawls
- 🎨 **Colour-coded terminal output** — clear, readable CLI output

> **OWASP scanner modules** (SQLi, XSS, CSRF, SSRF, IDOR, etc.) are actively in development.

---

## Installation

**Requires Go 1.21+**

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
# Basic scan — prints headers + security audit to terminal
gosentinel scan --url https://example.com

# Save results as an HTML report
gosentinel scan --url https://example.com --output report.html

# Set crawler depth (default: 2)
gosentinel scan --url https://example.com --depth 3

# Verbose output — shows full header values
gosentinel scan --url https://example.com -v

# Show all available flags
gosentinel scan --help
```

---

## Example Output

```
────────────────────────────────────────────────────────────
 Target:  https://example.com
 Depth:   2
 Started: 2026-04-07 06:02:01
────────────────────────────────────────────────────────────

[~] Fetching response headers…

 Status: 200 OK   Time: 49ms

  ┌─ Response Headers
  │ Content-Type    text/html
  │ Server          cloudflare
  └─

  ┌─ Security Header Audit
  │ ✘ MISSING   Content-Security-Policy     CSP — mitigates XSS
  │ ✘ MISSING   Strict-Transport-Security   HSTS — enforces HTTPS
  │ ✘ MISSING   X-Frame-Options             Clickjacking protection
  └─

 [✘] 6 security headers missing — review recommended.

 [✔] Report saved → /Users/.../report.html
```

---

## Project Structure

```
gosentinel/
├── cmd/
│   ├── root.go          # Root Cobra command + banner
│   └── scan.go          # scan subcommand
├── internal/
│   ├── httpclient/
│   │   └── client.go    # Shared HTTP client (all modules use this)
│   └── report/
│       └── html.go      # HTML report renderer
├── main.go
└── go.mod
```

---

## Roadmap

- [x] CLI scaffold (Cobra)
- [x] HTTP header fetching
- [x] Security header audit
- [x] HTML report generation
- [ ] BFS web crawler with `--depth` support
- [ ] SQLi detection module
- [ ] XSS detection module
- [ ] CSRF detection module
- [ ] SSRF detection module
- [ ] IDOR detection module
- [ ] React dashboard

---

## License

[MIT](LICENSE)
