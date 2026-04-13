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
      --info:         #71717a; /* Zinc 500 */
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
      line-height: 1.6;
      padding: 2.5rem 1.5rem;
      max-width: 1200px;
      margin: 0 auto;
      -webkit-font-smoothing: antialiased;
    }

    /* ── Header ── */
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 3rem;
      padding-bottom: 2rem;
      border-bottom: 1px solid var(--border);
    }
    .brand { 
      font-size: 1.75rem; 
      font-weight: 800; 
      letter-spacing: -1px;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .brand span { color: var(--cyan); }
    .scan-meta { 
      text-align: right; 
      color: var(--text-muted); 
      font-size: 0.8rem; 
      font-family: var(--font-mono);
      line-height: 1.6;
    }

    /* ── Executive Summary Grid ── */
    .summary-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1.25rem;
      margin-bottom: 3.5rem;
    }
    .summary-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius-lg);
      padding: 1.5rem;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
      transition: border-color 0.2s ease;
    }
    .summary-card:hover {
      border-color: rgba(45, 212, 191, 0.3);
    }
    .summary-card .label { 
      font-size: 0.7rem; 
      font-weight: 700; 
      text-transform: uppercase; 
      color: var(--text-muted); 
      letter-spacing: 1px;
    }
    .summary-card .value { 
      font-size: 2rem; 
      font-weight: 800; 
      font-family: var(--font-mono); 
      letter-spacing: -1px;
    }
    
    .summary-card.critical .value { color: var(--critical); }
    .summary-card.high .value     { color: var(--high); }
    .summary-card.medium .value   { color: var(--medium); }
    .summary-card.low .value      { color: var(--low); }

    /* ── Table Wrapper ── */
    .findings-table-wrapper {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius-lg);
      overflow: hidden;
    }
    
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.9rem;
    }

    thead {
      background: rgba(255, 255, 255, 0.02);
      border-bottom: 1px solid var(--border);
    }

    th {
      padding: 1rem 1.25rem;
      text-align: left;
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
      color: var(--text-muted);
      letter-spacing: 0.8px;
      font-family: var(--font-sans);
    }

    th:nth-child(1) { width: 140px; }
    th:nth-child(3) { width: 120px; text-align: center; }
    th:nth-child(4) { width: 100px; text-align: right; }

    tbody tr {
      border-bottom: 1px solid rgba(39, 39, 42, 0.3);
      transition: background-color 0.15s ease;
    }

    tbody tr:hover {
      background: rgba(255, 255, 255, 0.01);
    }

    tbody tr:last-child {
      border-bottom: none;
    }

    td {
      padding: 1rem 1.25rem;
      vertical-align: top;
    }

    /* ── Severity Badge (Table Cell) ── */
    .severity-badge {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.35rem 0.75rem;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      border: 1px solid;
      white-space: nowrap;
      width: fit-content;
    }

    .severity-dot {
      width: 0.4rem;
      height: 0.4rem;
      border-radius: 50%;
      flex-shrink: 0;
    }

    .badge-critical { 
      background: rgba(239, 68, 68, 0.1); 
      color: var(--critical); 
      border-color: rgba(239, 68, 68, 0.2);
    }
    .badge-critical .severity-dot { background: var(--critical); }

    .badge-high { 
      background: rgba(249, 115, 22, 0.1); 
      color: var(--high); 
      border-color: rgba(249, 115, 22, 0.2);
    }
    .badge-high .severity-dot { background: var(--high); }

    .badge-medium { 
      background: rgba(245, 158, 11, 0.1); 
      color: var(--medium); 
      border-color: rgba(245, 158, 11, 0.2);
    }
    .badge-medium .severity-dot { background: var(--medium); }

    .badge-low { 
      background: rgba(56, 189, 248, 0.1); 
      color: var(--low); 
      border-color: rgba(56, 189, 248, 0.2);
    }
    .badge-low .severity-dot { background: var(--low); }

    .badge-info { 
      background: rgba(113, 113, 122, 0.1); 
      color: var(--info); 
      border-color: rgba(113, 113, 122, 0.2);
    }
    .badge-info .severity-dot { background: var(--info); }

    /* ── Finding Title Column ── */
    .finding-cell {
      display: flex;
      flex-direction: column;
      gap: 0.25rem;
    }

    .finding-title {
      font-size: 0.95rem;
      font-weight: 600;
      color: var(--text);
      line-height: 1.4;
    }

    .finding-owasp {
      font-size: 0.7rem;
      font-weight: 600;
      text-transform: uppercase;
      color: var(--text-muted);
      letter-spacing: 0.6px;
    }

    .finding-description {
      font-size: 0.8rem;
      color: var(--text-muted);
      margin-top: 0.4rem;
      line-height: 1.4;
    }

    /* ── Endpoint Count ── */
    .endpoint-count {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 0.3rem 0.55rem;
      background: var(--border);
      border: 1px solid rgba(45, 212, 191, 0.1);
      border-radius: 3px;
      font-size: 0.75rem;
      font-weight: 600;
      font-family: var(--font-mono);
      color: var(--text-muted);
    }

    /* ── Expand Toggle ── */
    .expand-button {
      background: none;
      border: none;
      color: var(--cyan);
      font-weight: 700;
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.6px;
      cursor: pointer;
      padding: 0.3rem 0.5rem;
      border-radius: 3px;
      transition: all 0.15s ease;
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
    }

    .expand-button:hover {
      background: rgba(45, 212, 191, 0.1);
      color: var(--text);
    }

    /* ── Details Drawer (Expandable Content) ── */
    .details-content {
      padding: 1.5rem;
      background: rgba(255, 255, 255, 0.01);
      border-top: 1px solid var(--border);
      display: none;
    }

    .details-content.open {
      display: block;
    }

    .details-section {
      margin-bottom: 1.5rem;
    }

    .details-section:last-child {
      margin-bottom: 0;
    }

    .section-label {
      font-size: 0.65rem;
      font-weight: 800;
      text-transform: uppercase;
      color: var(--text-muted);
      letter-spacing: 1px;
      margin-bottom: 0.6rem;
      display: block;
    }

    .evidence-block {
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: var(--radius-md);
      padding: 0.85rem;
      font-family: var(--font-mono);
      font-size: 0.75rem;
      color: var(--cyan);
      overflow-x: auto;
      line-height: 1.5;
      word-break: break-word;
    }

    .remediation-box {
      padding: 0.85rem;
      background: rgba(45, 212, 191, 0.05);
      border: 1px solid rgba(45, 212, 191, 0.15);
      border-radius: var(--radius-md);
      font-size: 0.8rem;
      color: var(--text);
      line-height: 1.6;
    }

    .remediation-box strong { 
      color: var(--cyan); 
      text-transform: uppercase; 
      font-size: 0.65rem; 
      letter-spacing: 0.8px; 
      display: block; 
      margin-bottom: 0.6rem;
      font-weight: 700;
    }

    .endpoint-list {
      display: flex;
      flex-direction: column;
      gap: 0.4rem;
    }

    .endpoint-item {
      font-family: var(--font-mono);
      font-size: 0.75rem;
      color: var(--text-muted);
      background: rgba(255, 255, 255, 0.02);
      padding: 0.4rem 0.6rem;
      border-radius: 3px;
      border-left: 2px solid rgba(45, 212, 191, 0.15);
      word-break: break-all;
    }

    /* ── Empty State ── */
    .empty-state {
      text-align: center;
      padding: 4rem 2rem;
      background: var(--surface);
      border-radius: var(--radius-lg);
      border: 1px dashed var(--border);
    }

    .empty-state-icon {
      font-size: 2.5rem;
      margin-bottom: 1rem;
    }

    .empty-state-title {
      font-weight: 700;
      font-size: 1rem;
      color: var(--safe);
      margin-bottom: 0.5rem;
    }

    .empty-state-text {
      color: var(--text-muted);
      font-size: 0.8rem;
      line-height: 1.5;
    }

    /* ── Section Title ── */
    .section-title {
      font-size: 0.75rem;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 1.2px;
      color: var(--text-muted);
      margin: 3.5rem 0 1.5rem 0;
      display: flex;
      align-items: center;
      gap: 1rem;
    }
    .section-title::after { 
      content: ''; 
      flex: 1; 
      height: 1px; 
      background: var(--border);
    }

    footer {
      margin-top: 4rem;
      padding-top: 2.5rem;
      border-top: 1px solid var(--border);
      text-align: center;
      font-size: 0.75rem;
      color: var(--text-muted);
      font-family: var(--font-mono);
      line-height: 1.6;
    }
  </style>
</head>
<body>

  <header>
    <div class="brand">Go<span>Sentinel</span></div>
    <div class="scan-meta">
      <div>TARGET: <strong>{{.Target}}</strong></div>
      <div>{{.ScannedAt.Format "2006.01.02 — 15:04:05 MST"}}</div>
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
  
  {{if .Findings}}
  <div class="findings-table-wrapper">
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Vulnerability & Context</th>
          <th>Surface</th>
          <th style="text-align: right;">Details</th>
        </tr>
      </thead>
      <tbody>
        {{range $idx, $finding := .Findings}}
        <tr data-finding="{{$idx}}">
          <td>
            <div class="severity-badge badge-{{lower (print $finding.Severity)}}">
              <div class="severity-dot"></div>
              <span>{{$finding.Severity}}</span>
            </div>
          </td>
          <td>
            <div class="finding-cell">
              <span class="finding-title">{{$finding.Title}}</span>
              <span class="finding-owasp">{{$finding.OWASP}}</span>
              {{if $finding.Description}}
              <span class="finding-description">{{$finding.Description}}</span>
              {{end}}
            </div>
          </td>
          <td>
            <div class="endpoint-count">{{len $finding.Endpoints}} EP</div>
          </td>
          <td style="text-align: right;">
            <button class="expand-button" onclick="toggleDetails(event, {{$idx}})">
              <span>Inspect</span>
              <span style="font-size: 0.6rem;">→</span>
            </button>
          </td>
        </tr>
        <tr class="details-row" id="details-{{$idx}}" style="display: none;">
          <td colspan="4">
            <div class="details-content" id="content-{{$idx}}">
              {{if $finding.Evidence}}
              <div class="details-section">
                <span class="section-label">Evidence</span>
                <div class="evidence-block">{{$finding.Evidence}}</div>
              </div>
              {{end}}

              {{if $finding.Remediation}}
              <div class="details-section">
                <span class="section-label">Remediation</span>
                <div class="remediation-box">
                  <strong>Recommended Fix</strong>
                  {{$finding.Remediation}}
                </div>
              </div>
              {{end}}

              {{if $finding.Endpoints}}
              <div class="details-section">
                <span class="section-label">{{len $finding.Endpoints}} Affected Endpoints</span>
                <div class="endpoint-list">
                  {{range $finding.Endpoints}}
                  <div class="endpoint-item">{{.}}</div>
                  {{end}}
                </div>
              </div>
              {{end}}
            </div>
          </td>
        </tr>
        {{end}}
      </tbody>
    </table>
  </div>
  {{else}}
  <div class="empty-state">
    <div class="empty-state-icon">🛡️</div>
    <div class="empty-state-title">Clean Posture Detected</div>
    <div class="empty-state-text">No security vulnerabilities found in this audit.</div>
  </div>
  {{end}}

  <div class="section-title">Session Diagnostics</div>
  <div class="summary-grid">
    <div class="summary-card">
      <div class="label">Network Signature</div>
      <div style="font-size: 1.1rem; margin-top: 0.4rem; display: flex; align-items: center; gap: 0.75rem;">
        <span style="padding: 0.3rem 0.6rem; background: rgba(45, 212, 191, 0.1); color: var(--cyan); border: 1px solid rgba(45, 212, 191, 0.15); border-radius: 4px; font-size: 0.7rem; font-weight: 700;">{{.Status}}</span>
        <span style="font-size: 0.8rem; color: var(--text-muted); font-family: var(--font-mono);">{{.Duration.Milliseconds}}ms</span>
      </div>
    </div>
    <div class="summary-card">
      <div class="label">Attack Surface</div>
      <div style="font-size: 1.1rem; margin-top: 0.4rem;">
        {{len .Endpoints}} <span style="font-size: 0.8rem; color: var(--text-muted); font-weight: 400;">Discovered Endpoints</span>
      </div>
    </div>
  </div>

  <footer>
    GoSentinel Security &bull; Engine v1.1.0 &bull; &copy; {{.ScannedAt.Format "2006"}}
  </footer>

  <script>
    function toggleDetails(event, index) {
      event.preventDefault();
      event.stopPropagation();
      const detailsRow = document.getElementById('details-' + index);
      const content = document.getElementById('content-' + index);
      const button = event.currentTarget;
      
      if (detailsRow.style.display === 'none' || !detailsRow.style.display) {
        detailsRow.style.display = 'table-row';
        content.classList.add('open');
        button.textContent = 'Close ←';
      } else {
        detailsRow.style.display = 'none';
        content.classList.remove('open');
        button.innerHTML = '<span>Inspect</span><span style="font-size: 0.6rem;">→</span>';
      }
    }
  </script>

</body>
</html>`
