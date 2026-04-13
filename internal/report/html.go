// Package report handles rendering scan results into files.
// Currently supports HTML output. PDF and JSON will be added later.
package report

import (
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Stolonifer1903/gosentinel/internal/crawler"
	"github.com/Stolonifer1903/gosentinel/internal/scanner"
)

// ScanResult is the data model passed to report renderers.
type ScanResult struct {
	Target         string
	ScannedAt      time.Time
	Duration       time.Duration
	StatusCode     int
	Status         string
	AllHeaders     http.Header
	Findings       []scanner.GroupedFinding
	Endpoints      []crawler.Endpoint
	SeverityCounts map[string]int
}

// WriteHTML renders the scan result as a self-contained HTML file to outPath.
func WriteHTML(result *ScanResult, outPath string) error {
	// Pre-calculate severity counts if not already done
	if result.SeverityCounts == nil {
		result.SeverityCounts = make(map[string]int)
		for _, f := range result.Findings {
			result.SeverityCounts[string(f.Severity)]++
		}
	}

	// Ensure the output directory exists.
	if dir := filepath.Dir(outPath); dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("creating output directory: %w", err)
		}
	}

	f, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("creating report file: %w", err)
	}
	defer f.Close()

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"lower": strings.ToLower,
		"join":  strings.Join,
		"sortedHeaders": func(h http.Header) []string {
			keys := make([]string, 0, len(h))
			for k := range h {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			return keys
		},
		"headerVal": func(h http.Header, key string) string {
			return strings.Join(h[key], "; ")
		},
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("parsing template: %w", err)
	}

	if err := tmpl.Execute(f, result); err != nil {
		return fmt.Errorf("rendering template: %w", err)
	}
	return nil
}

// ── HTML template ─────────────────────────────────────────────────────────────

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>GoSentinel Pro Report — {{.Target}}</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

    :root {
      --bg:           #09090b; /* Slate 950 */
      --surface:      #18181b; /* Zinc 900 */
      --border:       #27272a; /* Zinc 800 */
      --text:         #fafafa; /* Zinc 50 */
      --text-muted:   #71717a; /* Zinc 500 */
      --cyan:         #2dd4bf; /* Teal 400 */
      
      --critical:     #ef4444; /* Red 500 */
      --high:         #f97316; /* Orange 500 */
      --medium:       #f59e0b; /* Amber 500 */
      --low:          #38bdf8; /* Sky 400 */
      --safe:         #10b981; /* Emerald 500 */
      
      --radius-lg:    8px;
      --radius-md:    6px;
      --font-sans:    'Inter', system-ui, sans-serif;
      --font-mono:    'JetBrains Mono', monospace;
    }

    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: var(--font-sans);
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 2rem 1rem;
      max-width: 1000px;
      margin: 0 auto;
      -webkit-font-smoothing: antialiased;
    }

    /* ── Header ── */
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 2.5rem;
      padding-bottom: 1.5rem;
      border-bottom: 1px solid var(--border);
    }
    .brand { font-size: 1.5rem; font-weight: 800; letter-spacing: -1px; }
    .brand span { color: var(--cyan); }
    .scan-meta { text-align: right; color: var(--text-muted); font-size: 0.75rem; font-family: var(--font-mono); }

    /* ── Executive Summary ── */
    .summary-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 1rem;
      margin-bottom: 3rem;
    }
    .summary-card {
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: var(--radius-lg);
      padding: 1.25rem;
      display: flex;
      flex-direction: column;
      gap: 0.25rem;
    }
    .summary-card .label { font-size: 0.65rem; font-weight: 700; text-transform: uppercase; color: var(--text-muted); letter-spacing: 1px; }
    .summary-card .value { font-size: 1.75rem; font-weight: 800; font-family: var(--font-mono); letter-spacing: -1px; }
    
    .summary-card.critical .value { color: var(--critical); }
    .summary-card.high .value     { color: var(--high); }
    .summary-card.medium .value   { color: var(--medium); }
    .summary-card.low .value      { color: var(--low); }

    /* ── Vulnerability Card ── */
    .finding-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius-lg);
      margin-bottom: 1rem;
      overflow: hidden;
    }
    
    .card-header {
      padding: 1rem 1.25rem;
      display: flex;
      align-items: center;
      gap: 1rem;
      background: rgba(255,255,255,0.02);
      border-bottom: 1px solid var(--border);
    }
    
    .severity-pill {
      padding: 0.25rem 0.5rem;
      border-radius: 4px;
      font-size: 0.65rem;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      border: 1px solid transparent;
      min-width: 80px;
      text-align: center;
    }
    .pill-critical { background: rgba(239, 68, 68, 0.1); color: var(--critical); border-color: rgba(239, 68, 68, 0.2); }
    .pill-high     { background: rgba(249, 115, 22, 0.1); color: var(--high); border-color: rgba(249, 115, 22, 0.2); }
    .pill-medium   { background: rgba(245, 158, 11, 0.1); color: var(--medium); border-color: rgba(245, 158, 11, 0.2); }
    .pill-low      { background: rgba(56, 189, 248, 0.1); color: var(--low); border-color: rgba(56, 189, 248, 0.2); }

    .finding-info { flex: 1; }
    .finding-title { font-size: 0.95rem; font-weight: 700; color: var(--text); }
    .finding-owasp { font-size: 0.65rem; color: var(--text-muted); font-weight: 700; text-transform: uppercase; letter-spacing: 1px; margin-top: 1px; }

    .card-body { padding: 1.25rem; }
    .finding-description { font-size: 0.85rem; color: var(--text-muted); margin-bottom: 1rem; }
    
    .evidence-block {
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: var(--radius-md);
      padding: 0.75rem;
      font-family: var(--font-mono);
      font-size: 0.75rem;
      margin-bottom: 1rem;
      color: var(--cyan);
      overflow-x: auto;
    }
    .remediation-box {
      padding: 0.75rem;
      background: rgba(45, 212, 191, 0.05);
      border: 1px solid rgba(45, 212, 191, 0.1);
      border-radius: var(--radius-md);
      font-size: 0.8rem;
    }
    .remediation-box strong { color: var(--cyan); text-transform: uppercase; font-size: 0.65rem; letter-spacing: 1px; display: block; margin-bottom: 2px; }

    /* ── Affected Endpoints ── */
    details.endpoints-drawer { margin-top: 1rem; }
    summary.drawer-trigger {
      cursor: pointer;
      font-size: 0.65rem;
      font-weight: 800;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 1px;
      padding: 0.5rem 0;
      user-select: none;
      list-style: none;
    }
    summary.drawer-trigger:hover { color: var(--cyan); }
    .url-list { 
      padding: 0.5rem 0;
      display: flex;
      flex-direction: column;
      gap: 0.25rem;
    }
    .url-item {
      font-family: var(--font-mono);
      font-size: 0.7rem;
      color: var(--text-muted);
      background: rgba(255,255,255,0.02);
      padding: 0.25rem 0.5rem;
      border-radius: 4px;
    }

    /* ── Sections ── */
    .section-title {
      font-size: 0.7rem;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 2px;
      color: var(--text-muted);
      margin: 3rem 0 1rem 0;
      display: flex;
      align-items: center;
      gap: 1rem;
    }
    .section-title::after { content: ''; flex: 1; height: 1px; background: var(--border); }

    footer {
      margin-top: 4rem;
      padding-top: 2rem;
      border-top: 1px solid var(--border);
      text-align: center;
      font-size: 0.7rem;
      color: var(--text-muted);
      font-family: var(--font-mono);
    }
  </style>
</head>
<body>

  <header>
    <div class="brand">Go<span>Sentinel</span></div>
    <div class="scan-meta">
      <div>TARGET: <strong>{{.Target}}</strong></div>
      <div style="margin-top:4px">{{.ScannedAt.Format "2006.01.02 — 15:04:05 MST"}}</div>
    </div>
  </header>

  <div class="summary-grid">
    <div class="summary-card critical">
      <div class="label">Critical</div>
      <div class="value">{{index .SeverityCounts "Critical"}}</div>
    </div>
    <div class="summary-card high">
      <div class="label">High</div>
      <div class="value">{{index .SeverityCounts "High"}}</div>
    </div>
    <div class="summary-card medium">
      <div class="label">Medium</div>
      <div class="value">{{index .SeverityCounts "Medium"}}</div>
    </div>
    <div class="summary-card low">
      <div class="label">Low/Info</div>
      <div class="value">{{index .SeverityCounts "Low"}}</div>
    </div>
  </div>

  <div class="section-title">Security Finding Log</div>
  <div class="findings-container">
    {{range .Findings}}
    <div class="finding-card">
      <div class="card-header">
        <div class="severity-pill pill-{{lower (print .Severity)}}">{{.Severity}}</div>
        <div class="finding-info">
          <div class="finding-title">{{.Title}}</div>
          <div class="finding-owasp">{{.OWASP}}</div>
        </div>
      </div>
      <div class="card-body">
        {{if .Description}}
        <div class="finding-description">
          {{.Description}}
        </div>
        {{end}}

        <div class="evidence-block">
          {{.Evidence}}
        </div>

        {{if .Remediation}}
        <div class="remediation-box">
          <strong>Recommended Fix</strong>
          {{.Remediation}}
        </div>
        {{end}}

        <details class="endpoints-drawer">
          <summary class="drawer-trigger">
            {{len .Endpoints}} Affected Endpoints ↓
          </summary>
          <div class="url-list">
            {{range .Endpoints}}
            <div class="url-item">{{.}}</div>
            {{end}}
          </div>
        </details>
      </div>
    </div>
    {{else}}
    <div style="text-align:center; padding: 4rem; background: var(--surface); border-radius: var(--radius-lg); border: 1px dashed var(--border);">
      <div style="font-size: 2rem; margin-bottom: 0.5rem;">🛡️</div>
      <div style="font-weight: 700; font-size: 0.95rem; color: var(--safe);">Clean Posture Detected</div>
      <div style="color: var(--text-muted); font-size: 0.75rem; margin-top: 4px;">No security vulnerabilities found in this audit.</div>
    </div>
    {{end}}
  </div>

  <div class="section-title">Session Diagnostics</div>
  <div class="summary-grid" style="grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));">
    <div class="summary-card">
      <div class="label">Network Signature</div>
      <div class="value" style="font-size: 1.1rem; margin-top:0.5rem; display:flex; align-items:center; gap:0.5rem;">
        <span style="padding: 0.2rem 0.4rem; background: rgba(45, 212, 191, 0.1); color: var(--cyan); border: 1px solid rgba(45, 212, 191, 0.2); border-radius: 4px; font-size: 0.7rem; font-weight: 800;">{{.Status}}</span>
        <span style="font-size: 0.75rem; color: var(--text-muted); font-family: var(--font-mono);">latency: {{.Duration.Milliseconds}}ms</span>
      </div>
    </div>
    <div class="summary-card">
      <div class="label">Attack Surface</div>
      <div class="value" style="font-size: 1.1rem; margin-top:0.5rem;">
        {{len .Endpoints}} <span style="font-size: 0.75rem; color: var(--text-muted); font-weight: 400;">Discovered Endpoints</span>
      </div>
    </div>
  </div>

  <footer>
    GoSentinel Security &bull; Engine v1.1.0 &bull; &copy; {{.ScannedAt.Format "2006"}}
  </footer>

</body>
</html>`

