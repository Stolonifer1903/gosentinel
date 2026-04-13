import { X, ExternalLink, ShieldAlert, Award, Terminal } from "lucide-react";
import type { GroupedFinding } from "../types/scan";
import { SeverityIndicator } from "./VulnerabilityTable";

interface Props {
  finding: GroupedFinding | null;
  onClose: () => void;
}

function FindingInspector({ finding, onClose }: Props) {
  if (!finding) return null;

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-brand-bg/60 backdrop-blur-sm z-40 transition-opacity"
        onClick={onClose}
      />

      {/* Drawer */}
      <div className="fixed inset-y-0 right-0 w-full max-w-xl bg-brand-bg border-l border-brand-border z-50 flex flex-col shadow-2xl animate-in slide-in-from-right duration-300">
        {/* Header */}
        <div className="p-6 border-b border-brand-border flex items-start justify-between bg-brand-surface/30">
          <div className="flex flex-col gap-3">
            <SeverityIndicator severity={finding.Severity} />
            <h2 className="text-xl font-bold tracking-tight text-brand-text">
              {finding.Title}
            </h2>
            <div className="flex items-center gap-2 text-[12px] font-mono text-brand-muted uppercase tracking-widest">
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

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-8 space-y-10 custom-scrollbar">
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

          {/* Endpoints */}
          <section className="space-y-4">
            <h3 className="text-xs font-bold uppercase tracking-widest text-brand-muted flex items-center gap-2">
              <Terminal size={14} /> Affected Resources (
              {finding.Endpoints.length})
            </h3>
            <div className="space-y-2">
              {finding.Endpoints.map((url, i) => (
                <div
                  key={i}
                  className="group flex items-center justify-between p-3 bg-brand-surface border border-brand-border rounded hover:border-brand-cyan/30 transition-all font-mono text-xs"
                >
                  <span className="text-brand-cyan truncate max-w-[400px]">
                    {url}
                  </span>
                  <ExternalLink
                    size={12}
                    className="text-brand-muted opacity-0 group-hover:opacity-100 transition-opacity cursor-pointer flex-shrink-0"
                  />
                </div>
              ))}
            </div>
          </section>
        </div>

        {/* Footer */}
        <div className="p-6 border-t border-brand-border bg-brand-surface/20 flex items-center justify-end">
          <button
            onClick={onClose}
            className="px-6 py-2 bg-brand-cyan text-brand-bg text-xs font-bold uppercase tracking-widest rounded hover:bg-brand-cyan/90 transition-all"
          >
            Acknowledged
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
