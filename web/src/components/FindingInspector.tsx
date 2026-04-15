import { useState } from "react";
import { X, ExternalLink, ShieldAlert, Award, Terminal, Copy, Check } from "lucide-react";
import type { GroupedFinding } from "../types/scan";
import { SeverityIndicator } from "./VulnerabilityTable";

interface Props {
  finding: GroupedFinding | null;
  onClose: () => void;
}

function FindingInspector({ finding, onClose }: Props) {
  const [copied, setCopied] = useState(false);

  if (!finding) return null;

  const handleCopyAll = () => {
    const urls = finding.Endpoints.map((e) => e.URL).join("\n");
    navigator.clipboard.writeText(urls);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-brand-bg/80 backdrop-blur-md z-40 transition-opacity"
        onClick={onClose}
      />

      {/* Centered Modal */}
      <div className="fixed inset-4 md:inset-10 lg:inset-20 max-w-6xl mx-auto bg-brand-bg border border-brand-border z-50 flex flex-col shadow-2xl rounded-xl overflow-hidden animate-in zoom-in-95 duration-200">
        {/* Header */}
        <div className="px-6 py-4 border-b border-brand-border flex items-center justify-between bg-brand-surface/30">
          <div className="flex items-center gap-4">
            <SeverityIndicator severity={finding.Severity} />
            <h2 className="text-xl font-bold tracking-tight text-brand-text">
              {finding.Title}
            </h2>
            <div className="flex items-center gap-2 px-3 py-1 bg-brand-surface border border-brand-border rounded-full text-[11px] font-mono text-brand-muted uppercase tracking-widest">
              <ShieldAlert size={12} className="text-brand-cyan" />
              {finding.OWASP}
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-brand-surface rounded-full text-brand-muted hover:text-brand-text transition-colors"
          >
            <X size={20} />
          </button>
        </div>

        {/* Content - Split View */}
        <div className="flex-1 overflow-hidden flex flex-col md:flex-row">
          {/* Left Pane: Context */}
          <div className="w-full md:w-2/5 border-r border-brand-border overflow-y-auto p-6 md:p-8 space-y-8 bg-brand-bg/50 custom-scrollbar">
            {/* Description */}
            <section className="space-y-3">
              <h3 className="text-xs font-bold uppercase tracking-widest text-brand-muted flex items-center gap-2">
                <InfoIcon size={14} /> Description
              </h3>
              <p className="text-sm text-brand-text leading-relaxed opacity-90">
                {finding.Description ||
                  "Detailed analysis of the security finding goes here. This vulnerability was identified during an automated scan of the target endpoints."}
              </p>
            </section>

            {/* Remediation */}
            <section className="space-y-4">
              <h3 className="text-xs font-bold uppercase tracking-widest text-brand-muted flex items-center gap-2">
                <Award size={14} /> Remediation Strategy
              </h3>
              <div className="p-4 bg-severity-safe/5 border border-severity-safe/20 rounded-lg">
                <p className="text-sm text-brand-text leading-relaxed">
                  {finding.Remediation}
                </p>
              </div>
            </section>
          </div>

          {/* Right Pane: Affected Resources */}
          <div className="w-full md:w-3/5 overflow-y-auto p-6 md:p-8 custom-scrollbar">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xs font-bold uppercase tracking-widest text-brand-muted flex items-center gap-2">
                <Terminal size={14} /> Affected Resources ({finding.Endpoints.length})
              </h3>
              <button
                onClick={handleCopyAll}
                className="flex items-center gap-2 px-3 py-1.5 bg-brand-surface hover:bg-brand-border border border-brand-border rounded text-[11px] font-bold uppercase tracking-wider text-brand-muted hover:text-brand-text transition-all"
              >
                {copied ? (
                  <Check size={14} className="text-severity-safe" />
                ) : (
                  <Copy size={14} />
                )}
                {copied ? "Copied!" : "Copy URLs"}
              </button>
            </div>

            <div className="space-y-4">
              {finding.Endpoints.map((endpoint, i) => (
                <div
                  key={i}
                  className="flex flex-col border border-brand-border rounded overflow-hidden bg-brand-bg group transition-colors hover:border-brand-cyan/50"
                >
                  {/* URL Header */}
                  <div className="flex items-center justify-between p-3 bg-brand-surface/50 border-b border-brand-border">
                    <span className="font-mono text-[13px] text-brand-cyan break-all pr-4">
                      {endpoint.URL}
                    </span>
                    <a
                      href={endpoint.URL}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-brand-muted hover:text-brand-cyan transition-colors"
                      title="Open URL"
                    >
                      <ExternalLink size={14} />
                    </a>
                  </div>

                  {/* Evidence Block */}
                  {endpoint.Detail && (
                    <div className="p-4 bg-black/40 font-mono text-[11px] leading-relaxed text-brand-muted">
                      <div className="mb-2 text-[9px] uppercase tracking-widest text-brand-muted/50 border-b border-brand-border/50 pb-1">
                        Evidence / Pattern Match
                      </div>
                      <pre className="whitespace-pre-wrap break-all text-brand-text/90">
                        {endpoint.Detail}
                      </pre>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-6 border-t border-brand-border bg-brand-surface/20 flex items-center justify-end">
          <button
            onClick={onClose}
            className="px-6 py-2 bg-brand-cyan text-brand-bg text-xs font-bold uppercase tracking-widest rounded hover:bg-brand-cyan/90 transition-all"
          >
            Acknowledge & Close
          </button>
        </div>
      </div>
    </>
  );
}

function InfoIcon({ size }: { size: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx="12" cy="12" r="10" />
      <path d="M12 16v-4" />
      <path d="M12 8h.01" />
    </svg>
  );
}

export default FindingInspector;
