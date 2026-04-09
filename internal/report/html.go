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
)

// HeaderFinding represents a single security header check result.
type HeaderFinding struct {
	Header      string
	Present     bool
	Value       string
	Description string
}

// ScanResult is the data model passed to report renderers.
type ScanResult struct {
	Target         string
	ScannedAt      time.Time
	Duration       time.Duration
	StatusCode     int
	Status         string
	AllHeaders     http.Header
	SecurityAudit  []HeaderFinding
	Endpoints      []crawler.Endpoint
	MissingCount   int
}

// WriteHTML renders the scan result as a self-contained HTML file to outPath.
func WriteHTML(result *ScanResult, outPath string) error {
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
  <title>GoSentinel Report — {{.Target}}</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

    :root {
      --bg:       #0d0f14;
      --surface:  #13161e;
      --border:   #1e2330;
      --cyan:     #00e5ff;
      --green:    #00e676;
      --yellow:   #ffea00;
      --red:      #ff1744;
      --text:     #e2e8f0;
      --muted:    #64748b;
      --radius:   10px;
    }

    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: 'Inter', sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      padding: 2rem;
    }

    /* ── header bar ── */
    .report-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      border-bottom: 1px solid var(--border);
      padding-bottom: 1.5rem;
      margin-bottom: 2rem;
    }
    .logo { font-size: 1.6rem; font-weight: 700; color: var(--cyan); letter-spacing: -.5px; }
    .logo span { color: var(--text); }
    .meta { text-align: right; font-size: .8rem; color: var(--muted); line-height: 1.7; }

    /* ── target card ── */
    .target-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-left: 4px solid var(--cyan);
      border-radius: var(--radius);
      padding: 1.25rem 1.5rem;
      margin-bottom: 2rem;
      display: flex;
      gap: 2rem;
      flex-wrap: wrap;
    }
    .target-card .label { font-size: .7rem; text-transform: uppercase; letter-spacing: 1px; color: var(--muted); margin-bottom: .25rem; }
    .target-card .value { font-size: .95rem; font-weight: 600; }
    .target-card .value.url  { color: var(--cyan); font-family: 'JetBrains Mono', monospace; }
    .status-badge {
      display: inline-flex; align-items: center; gap: .4rem;
      padding: .2rem .7rem; border-radius: 999px; font-size: .8rem; font-weight: 600;
    }
    .status-2xx { background: rgba(0,230,118,.15); color: var(--green); border: 1px solid rgba(0,230,118,.3); }
    .status-3xx { background: rgba(179,136,255,.15); color: #b388ff; border: 1px solid rgba(179,136,255,.3); }
    .status-4xx { background: rgba(255,234,0,.15); color: var(--yellow); border: 1px solid rgba(255,234,0,.3); }
    .status-5xx { background: rgba(255,23,68,.15); color: var(--red); border: 1px solid rgba(255,23,68,.3); }

    /* ── section ── */
    .section { margin-bottom: 2.5rem; }
    .section-title {
      font-size: .7rem; font-weight: 600; text-transform: uppercase;
      letter-spacing: 1.5px; color: var(--muted);
      margin-bottom: 1rem; display: flex; align-items: center; gap: .5rem;
    }
    .section-title::after { content: ''; flex: 1; height: 1px; background: var(--border); }

    /* ── security audit table ── */
    .audit-grid {
      display: grid;
      gap: .5rem;
    }
    .audit-row {
      display: grid;
      grid-template-columns: 1.5rem 14rem 1fr;
      align-items: start;
      gap: .75rem;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: .75rem 1rem;
      transition: border-color .15s;
    }
    .audit-row:hover { border-color: #2a3050; }
    .audit-row.present { border-left: 3px solid var(--green); }
    .audit-row.missing { border-left: 3px solid var(--red); }
    .audit-icon { font-size: 1rem; margin-top: .05rem; }
    .audit-name { font-family: 'JetBrains Mono', monospace; font-size: .8rem; font-weight: 500; color: var(--text); }
    .audit-detail { font-size: .8rem; }
    .audit-detail .desc { color: var(--muted); margin-bottom: .2rem; }
    .audit-detail .val  { font-family: 'JetBrains Mono', monospace; color: var(--cyan); font-size: .75rem; word-break: break-all; }

    /* ── summary banner ── */
    .summary-banner {
      border-radius: var(--radius); padding: 1rem 1.5rem;
      display: flex; align-items: center; gap: 1rem;
      margin-bottom: 2rem; font-weight: 500;
    }
    .summary-banner.ok      { background: rgba(0,230,118,.08); border: 1px solid rgba(0,230,118,.25); color: var(--green); }
    .summary-banner.warn    { background: rgba(255,234,0,.08); border: 1px solid rgba(255,234,0,.25); color: var(--yellow); }
    .summary-banner.danger  { background: rgba(255,23,68,.08); border: 1px solid rgba(255,23,68,.25); color: var(--red); }
    .summary-banner .icon   { font-size: 1.4rem; }

    /* ── all headers table ── */
    table { width: 100%; border-collapse: collapse; font-size: .82rem; }
    thead th {
      text-align: left; padding: .5rem .75rem;
      font-size: .65rem; font-weight: 600; text-transform: uppercase;
      letter-spacing: 1px; color: var(--muted);
      border-bottom: 1px solid var(--border);
    }
    tbody tr { border-bottom: 1px solid var(--border); transition: background .12s; }
    tbody tr:hover { background: var(--surface); }
    tbody td { padding: .55rem .75rem; vertical-align: top; }
    .h-name { font-family: 'JetBrains Mono', monospace; color: var(--cyan); }
    .h-val  { color: var(--text); word-break: break-all; }
    .h-sec  { color: var(--green); }

    /* ── footer ── */
    footer { text-align: center; font-size: .75rem; color: var(--muted); margin-top: 3rem; padding-top: 1.5rem; border-top: 1px solid var(--border); }
  </style>
</head>
<body>

  <!-- ── Report header ── -->
  <header class="report-header">
    <div class="logo">Go<span>Sentinel</span></div>
    <div class="meta">
      <div>Generated: {{.ScannedAt.Format "2006-01-02 15:04:05 MST"}}</div>
      <div>Scan duration: {{.Duration.Milliseconds}}ms</div>
    </div>
  </header>

  <!-- ── Target card ── -->
  <div class="target-card">
    <div>
      <div class="label">Target</div>
      <div class="value url">{{.Target}}</div>
    </div>
    <div>
      <div class="label">HTTP Status</div>
      <div class="value">
        {{if ge .StatusCode 500}}<span class="status-badge status-5xx">{{.Status}}</span>
        {{else if ge .StatusCode 400}}<span class="status-badge status-4xx">{{.Status}}</span>
        {{else if ge .StatusCode 300}}<span class="status-badge status-3xx">{{.Status}}</span>
        {{else}}<span class="status-badge status-2xx">{{.Status}}</span>{{end}}
      </div>
    </div>
    <div>
      <div class="label">Response Time</div>
      <div class="value">{{.Duration.Milliseconds}}ms</div>
    </div>
    <div>
      <div class="label">Headers Found</div>
      <div class="value">{{len .AllHeaders}}</div>
    </div>
  </div>

  <!-- ── Summary banner ── -->
  {{if eq .MissingCount 0}}
  <div class="summary-banner ok"><span class="icon">✔</span> All security headers are present.</div>
  {{else if le .MissingCount 2}}
  <div class="summary-banner warn"><span class="icon">⚠</span> {{.MissingCount}} security header(s) missing — low risk.</div>
  {{else}}
  <div class="summary-banner danger"><span class="icon">✘</span> {{.MissingCount}} security headers missing — review recommended.</div>
  {{end}}

  <!-- ── Security header audit ── -->
  <div class="section">
    <div class="section-title">Security Header Audit</div>
    <div class="audit-grid">
      {{range .SecurityAudit}}
      <div class="audit-row {{if .Present}}present{{else}}missing{{end}}">
        <div class="audit-icon">{{if .Present}}✔{{else}}✘{{end}}</div>
        <div class="audit-name">{{.Header}}</div>
        <div class="audit-detail">
          <div class="desc">{{.Description}}</div>
          {{if .Present}}<div class="val">{{.Value}}</div>{{end}}
        </div>
      </div>
      {{end}}
    </div>
  </div>

  <!-- ── Discovered Endpoints ── -->
  <div class="section">
    <div class="section-title">Discovered Endpoints</div>
    <table>
      <thead>
        <tr><th>Method</th><th>Source</th><th>URL</th><th>Parameters</th></tr>
      </thead>
      <tbody>
        {{range .Endpoints}}
        <tr>
          <td><span class="status-badge {{if eq .Method "POST"}}status-5xx{{else}}status-2xx{{end}}">{{.Method}}</span></td>
          <td>{{.Source}}</td>
          <td class="h-name">{{.URL}}</td>
          <td class="dim">{{if .Params}}{{join .Params ", "}}{{else}}—{{end}}</td>
        </tr>
        {{end}}
      </tbody>
    </table>
  </div>

  <!-- ── All response headers ── -->
  <div class="section">
    <div class="section-title">All Response Headers</div>
    <table>
      <thead>
        <tr><th>Header</th><th>Value</th></tr>
      </thead>
      <tbody>
        {{$h := .AllHeaders}}
        {{range (sortedHeaders $h)}}
        <tr>
          <td class="h-name {{if headerVal $h .}}h-sec{{end}}">{{.}}</td>
          <td class="h-val">{{headerVal $h .}}</td>
        </tr>
        {{end}}
      </tbody>
    </table>
  </div>

  <footer>
    GoSentinel &mdash; OWASP Top 10 Scanner &mdash; Report for <strong>{{.Target}}</strong>
  </footer>

</body>
</html>`
