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
	// Pre-calculate severity counts for the executive dashboard
	result.SeverityCounts = make(map[string]int)
	for _, f := range result.Findings {
		result.SeverityCounts[string(f.Severity)]++
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
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

    :root {
      --bg:           #08090d;
      --surface:      #0f121a;
      --surface-alt:  #161b26;
      --border:       rgba(255, 255, 255, 0.08);
      --cyan:         #00f2ff;
      --green:        #00ff95;
      --yellow:       #ffea00;
      --red:          #ff2e5b;
      --critical:     linear-gradient(135deg, #ff2e5b 0%, #ff708d 100%);
      --high:         linear-gradient(135deg, #ff6b00 0%, #ffae00 100%);
      --medium:       linear-gradient(135deg, #ffea00 0%, #fffd8d 100%);
      --low:          linear-gradient(135deg, #00f2ff 0%, #87f9ff 100%);
      --text:         #f1f5f9;
      --text-muted:    #94a3b8;
      --radius-lg:    16px;
      --radius-md:    12px;
      --shadow:       0 12px 24px -8px rgba(0, 0, 0, 0.5);
    }

    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: 'Plus Jakarta Sans', sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 3rem 1rem;
      max-width: 1100px;
      margin: 0 auto;
    }

    /* ── Header ── */
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 3rem;
    }
    .brand { font-size: 1.8rem; font-weight: 800; letter-spacing: -1px; }
    .brand span { color: var(--cyan); }
    .scan-meta { text-align: right; color: var(--text-muted); font-size: 0.85rem; }

    /* ── Executive Summary ── */
    .summary-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1.5rem;
      margin-bottom: 4rem;
    }
    .summary-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius-lg);
      padding: 1.5rem;
      box-shadow: var(--shadow);
      position: relative;
      overflow: hidden;
    }
    .summary-card::after {
      content: ''; position: absolute; top: 0; left: 0; width: 4px; height: 100%;
    }
    .summary-card.critical::after { background: var(--critical); }
    .summary-card.high::after     { background: var(--high); }
    .summary-card.medium::after   { background: var(--medium); }
    .summary-card.low::after      { background: var(--low); }

    .summary-card .label { font-size: 0.7rem; font-weight: 700; text-transform: uppercase; color: var(--text-muted); letter-spacing: 1px; }
    .summary-card .value { font-size: 2.2rem; font-weight: 800; margin: 0.25rem 0; line-height: 1; }
    .summary-card.critical .value { color: #ff2e5b; }
    .summary-card.high .value     { color: #ff6b00; }

    /* ── Vulnerability Card ── */
    .findings-container { display: flex; flex-direction: column; gap: 1.25rem; }
    .finding-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius-lg);
      overflow: hidden;
      box-shadow: var(--shadow);
      transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .finding-card:hover { border-color: rgba(255,255,255,0.15); }
    
    .card-header {
      padding: 1.5rem;
      display: flex;
      align-items: flex-start;
      gap: 1.5rem;
    }
    
    .severity-pill {
      padding: 0.4rem 0.8rem;
      border-radius: 8px;
      font-size: 0.65rem;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: #000;
      min-width: 90px;
      text-align: center;
    }
    .pill-critical { background: var(--critical); }
    .pill-high     { background: var(--high); }
    .pill-medium   { background: var(--medium); color: #000; }
    .pill-low      { background: var(--low); color: #000; }

    .finding-info { flex: 1; }
    .finding-title { font-size: 1.1rem; font-weight: 700; margin-bottom: 0.25rem; color: #fff; }
    .finding-owasp { font-size: 0.75rem; color: var(--text-muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }

    .card-body {
      padding: 0 1.5rem 1.5rem 1.5rem;
    }
    .evidence-block {
      background: rgba(255,255,255,0.03);
      border-radius: var(--radius-md);
      padding: 1rem;
      font-size: 0.85rem;
      margin-top: 1rem;
      border-left: 2px solid var(--border);
    }
    .remediation-box {
      margin-top: 1.25rem;
      padding: 1rem;
      background: rgba(0, 242, 255, 0.04);
      border: 1px solid rgba(0, 242, 255, 0.1);
      border-radius: var(--radius-md);
      font-size: 0.85rem;
    }
    .remediation-box strong { color: var(--cyan); text-transform: uppercase; font-size: 0.7rem; letter-spacing: 1px; display: block; margin-bottom: 0.4rem; }

    /* ── Affected Endpoints Drawer ── */
    details.endpoints-drawer {
      margin-top: 1.5rem;
      border-top: 1px solid var(--border);
    }
    summary.drawer-trigger {
      padding: 1rem 0;
      list-style: none;
      cursor: pointer;
      font-size: 0.75rem;
      font-weight: 700;
      color: var(--cyan);
      display: flex;
      align-items: center;
      gap: 0.5rem;
      user-select: none;
    }
    summary.drawer-trigger::before {
      content: '⊞';
      font-size: 1.1rem;
    }
    details[open] summary.drawer-trigger::before { content: '⊟'; }
    
    .url-list {
      max-height: 250px;
      overflow-y: auto;
      padding: 0.5rem 1rem 1.5rem 1rem;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
    }
    .url-list::-webkit-scrollbar { width: 5px; }
    .url-list::-webkit-scrollbar-thumb { background: var(--border); border-radius: 10px; }
    
    .url-item {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.75rem;
      color: var(--text-muted);
      word-break: break-all;
      background: rgba(255,255,255,0.02);
      padding: 0.4rem 0.75rem;
      border-radius: 6px;
    }
    .url-item:hover { color: var(--text); background: rgba(255,255,255,0.05); }

    /* ── Sections ── */
    .section-title {
      font-size: 0.85rem;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 1.5px;
      color: var(--text-muted);
      margin: 4rem 0 1.5rem 0;
      display: flex;
      align-items: center;
      gap: 1rem;
    }
    .section-title::after { content: ''; flex: 1; height: 1px; background: var(--border); }

    /* ── Table Styling ── */
    .table-container {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius-lg);
      overflow: hidden;
    }
    table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
    th { text-align: left; padding: 1rem; color: var(--text-muted); font-size: 0.7rem; text-transform: uppercase; font-weight: 800; border-bottom: 1px solid var(--border); }
    td { padding: 1rem; border-bottom: 1px solid var(--border); vertical-align: middle; }
    tr:last-child td { border-bottom: none; }
    .mono { font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: var(--cyan); }

    footer {
      margin-top: 5rem;
      padding-top: 2rem;
      border-top: 1px solid var(--border);
      text-align: center;
      font-size: 0.75rem;
      color: var(--text-muted);
    }
  </style>
</head>
<body>

  <header>
    <div class="brand">Go<span>Sentinel</span></div>
    <div class="scan-meta">
      <div>Target: <strong>{{.Target}}</strong></div>
      <div style="margin-top:2px">{{.ScannedAt.Format "Jan 02, 2006 • 15:04:05 MST"}}</div>
    </div>
  </header>

  <div class="summary-grid">
    <div class="summary-card critical">
      <div class="label">Critical</div>
      <div class="value">{{index .SeverityCounts "Critical"}}</div>
    </div>
    <div class="summary-card high">
      <div class="label">High Risk</div>
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

  <div class="section-title">Security Vulnerabilities</div>
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
            {{len .Endpoints}} AFFECTED ENDPOINTS
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
      <div style="font-size: 3rem; margin-bottom: 1rem;">🛡️</div>
      <div style="font-weight: 700; font-size: 1.2rem; color: var(--green);">Zero Vulnerabilities Detected</div>
      <div style="color: var(--text-muted); font-size: 0.9rem;">The target application appears to follow security best-practices.</div>
    </div>
    {{end}}
  </div>

  <div class="section-title">Surface Information</div>
  <div class="summary-grid" style="grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));">
    <div class="summary-card" style="padding: 1.25rem;">
      <div class="label">Network Signature</div>
      <div class="value" style="font-size: 1.2rem; margin-top:0.5rem; display:flex; align-items:center; gap:0.5rem;">
        <span style="padding: 0.2rem 0.5rem; background: rgba(0,242,255,0.1); color: var(--cyan); border-radius: 4px; font-size: 0.8rem; font-weight: 800;">{{.Status}}</span>
        <span style="font-size: 0.85rem; color: var(--text-muted); font-weight: 400;">in {{.Duration.Milliseconds}}ms</span>
      </div>
    </div>
    <div class="summary-card" style="padding: 1.25rem;">
      <div class="label">Attack Surface</div>
      <div class="value" style="font-size: 1.2rem; margin-top:0.5rem; color: var(--text);">
        {{len .Endpoints}} <span style="font-size: 0.85rem; color: var(--text-muted); font-weight: 400;">Total Endpoints Discovered</span>
      </div>
    </div>
  </div>

  <footer>
    GoSentinel Security Audit &bull; Generated by Engine v1.0.0 &bull; &copy; {{.ScannedAt.Format "2006"}}
  </footer>

</body>
</html>`

