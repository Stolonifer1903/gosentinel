import { useState, useEffect } from "react";
import { X, ExternalLink, ShieldAlert, Award, Terminal, Copy, Check, CheckCircle, ChevronLeft, ChevronRight } from "lucide-react";
import type { GroupedFinding } from "../types/scan";
import { SeverityIndicator } from "./VulnerabilityTable";

interface Props {
  finding: GroupedFinding | null;
  totalFindings?: number;
  currentIndex?: number;
  onClose: () => void;
  onNavigate?: (direction: "prev" | "next") => void;
}

function middleTruncate(str: string, maxLength: number = 60) {
  if (str.length <= maxLength) return str;
  const charsToShow = maxLength - 3;
  const frontChars = Math.ceil(charsToShow / 2);
  const backChars = Math.floor(charsToShow / 2);
  return str.substring(0, frontChars) + "..." + str.substring(str.length - backChars);
}

function SeverityScale({ severity }: { severity: string }) {
  const levels = ["Info", "Low", "Medium", "High", "Critical"];
  const currentIndex = levels.indexOf(severity);
  
  return (
    <div className="flex gap-1 mr-4 ml-2">
      {levels.map((level, idx) => (
        <div 
          key={level}
          className={`h-1.5 w-4 rounded-full ${idx <= currentIndex ? (
             severity === "Critical" ? "bg-severity-critical" :
             severity === "High" ? "bg-severity-high" :
             severity === "Medium" ? "bg-severity-medium" :
             severity === "Low" ? "bg-severity-low" :
             "bg-severity-info"
          ) : "bg-brand-surface border border-brand-border"}`}
          title={level}
        />
      ))}
    </div>
  );
}

function FindingInspector({ finding, totalFindings, currentIndex, onClose, onNavigate }: Props) {
  const [copied, setCopied] = useState(false);
  const [copiedUrlIndex, setCopiedUrlIndex] = useState<number | null>(null);
  const [activeTab, setActiveTab] = useState<"description" | "remediation">("description");
  const [showAllEndpoints, setShowAllEndpoints] = useState(false);

  // Reset state when finding changes
  useEffect(() => {
    setActiveTab("description");
    setShowAllEndpoints(false);
  }, [finding]);

  if (!finding) return null;

  const handleCopyAll = () => {
    const urls = finding.Endpoints.map((e) => e.URL).join("\n");
    navigator.clipboard.writeText(urls);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleCopyUrl = (url: string, index: number) => {
    navigator.clipboard.writeText(url);
    setCopiedUrlIndex(index);
    setTimeout(() => setCopiedUrlIndex(null), 2000);
  };

  const endpointsToDisplay = showAllEndpoints 
    ? finding.Endpoints 
    : finding.Endpoints.slice(0, 10);

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
          <div className="flex items-center flex-wrap gap-y-3">
            
            {onNavigate && (
              <div className="flex items-center gap-2 border-r border-brand-border pr-4 mr-2">
                <button 
                  onClick={() => onNavigate("prev")}
                  disabled={currentIndex === 0}
                  className="p-1.5 rounded hover:bg-brand-surface disabled:opacity-30 disabled:hover:bg-transparent transition-colors text-brand-muted hover:text-brand-text"
                >
                  <ChevronLeft size={16} />
                </button>
                <span className="text-[11px] font-mono text-brand-muted select-none">
                  {currentIndex !== undefined && totalFindings ? `${currentIndex + 1} / ${totalFindings}` : ""}
                </span>
                <button 
                  onClick={() => onNavigate("next")}
                  disabled={currentIndex !== undefined && totalFindings ? currentIndex === totalFindings - 1 : true}
                  className="p-1.5 rounded hover:bg-brand-surface disabled:opacity-30 disabled:hover:bg-transparent transition-colors text-brand-muted hover:text-brand-text"
                >
                  <ChevronRight size={16} />
                </button>
              </div>
            )}

            <div className="flex items-center gap-3">
              <SeverityIndicator severity={finding.Severity} />
              <h2 className="text-xl font-bold tracking-tight text-brand-text">
                {finding.Title}
              </h2>
            </div>
            
            <SeverityScale severity={finding.Severity} />
            
            <div className="flex items-center gap-2 px-3 py-1 bg-brand-surface border border-brand-border rounded-full text-[11px] font-mono text-brand-muted tracking-wide">
              <ShieldAlert size={12} className="text-brand-cyan" />
              {finding.OWASP}
            </div>

            {finding.Confidence === "Confirmed" ? (
              <div className="ml-2 flex items-center gap-1.5 px-3 py-1 bg-severity-safe/20 border border-severity-safe/30 text-severity-safe rounded-full text-[11px] font-bold tracking-wide">
                <CheckCircle size={12} />
                CONFIRMED
              </div>
            ) : (
              <div className="ml-2 px-3 py-1 bg-brand-surface border border-brand-border rounded-full text-[11px] font-mono text-brand-muted uppercase tracking-wide">
                {finding.Confidence}
              </div>
            )}
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-brand-surface rounded-full text-brand-muted hover:text-brand-text transition-colors flex-shrink-0 ml-4"
          >
            <X size={20} />
          </button>
        </div>

        {/* Content - Split View */}
        <div className="flex-1 overflow-hidden flex flex-col md:flex-row">
          {/* Left Pane: Context (Tabs) */}
          <div className="w-full md:w-2/5 border-r border-brand-border flex flex-col bg-brand-bg/50">
             {/* Tabs Header */}
             <div className="flex border-b border-brand-border">
               <button 
                 onClick={() => setActiveTab("description")}
                 className={`flex-1 py-3 text-xs font-bold capitalize tracking-wide border-b-2 transition-colors ${activeTab === "description" ? "border-brand-cyan text-brand-text" : "border-transparent text-brand-muted hover:text-brand-text hover:bg-brand-surface/30"}`}
               >
                 Description
               </button>
               <button 
                 onClick={() => setActiveTab("remediation")}
                 className={`flex-1 py-3 text-xs font-bold capitalize tracking-wide border-b-2 transition-colors ${activeTab === "remediation" ? "border-brand-cyan text-brand-text" : "border-transparent text-brand-muted hover:text-brand-text hover:bg-brand-surface/30"}`}
               >
                 Remediation
               </button>
             </div>

             {/* Tab Content */}
             <div className="flex-1 overflow-y-auto p-6 md:p-8 custom-scrollbar space-y-6">
                {activeTab === "description" && (
                  <>
                    <p className="text-sm text-brand-text leading-relaxed opacity-90">
                      {finding.Description || "Detailed analysis of the security finding goes here. This vulnerability was identified during an automated scan of the target endpoints."}
                    </p>
                    {finding.Evidence && (
                      <section className="space-y-3 mt-6">
                        <h3 className="text-xs font-bold capitalize tracking-wide text-brand-muted flex items-center gap-2">
                          <ShieldAlert size={14} /> Global evidence
                        </h3>
                        <div className="p-4 bg-brand-surface/50 border border-brand-border rounded-lg font-mono text-[11px] text-brand-cyan leading-relaxed break-all">
                          {finding.Evidence}
                        </div>
                      </section>
                    )}
                  </>
                )}
                {activeTab === "remediation" && (
                  <div className="p-5 bg-severity-safe/5 border border-severity-safe/20 rounded-lg">
                    <p className="text-sm text-brand-text leading-relaxed">
                      {finding.Remediation}
                    </p>
                  </div>
                )}
             </div>
          </div>

          {/* Right Pane: Affected Resources */}
          <div className="w-full md:w-3/5 overflow-y-auto p-6 md:p-8 custom-scrollbar">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xs font-bold capitalize tracking-wide text-brand-muted flex items-center gap-2">
                <Terminal size={14} /> Affected resources ({finding.Endpoints.length})
              </h3>
              <button
                onClick={handleCopyAll}
                className="flex items-center gap-2 px-3 py-1.5 bg-brand-surface hover:bg-brand-border border border-brand-border rounded text-[11px] font-bold tracking-wide text-brand-muted hover:text-brand-text transition-all"
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
              {endpointsToDisplay.map((endpoint, i) => (
                <div
                  key={i}
                  className="flex flex-col border border-brand-border rounded overflow-hidden bg-brand-bg group transition-colors hover:border-brand-cyan/50"
                >
                  {/* URL Header */}
                  <div className="flex items-center justify-between p-3 bg-brand-surface/50 border-b border-brand-border">
                    <span 
                      className="font-mono text-[13px] text-brand-cyan pr-4 cursor-help border-b border-transparent hover:border-brand-cyan/30" 
                      title={endpoint.URL}
                    >
                      {middleTruncate(endpoint.URL, 65)}
                    </span>
                    <div className="flex items-center gap-3">
                      <button 
                        onClick={() => handleCopyUrl(endpoint.URL, i)}
                        className="text-brand-muted hover:text-brand-text transition-colors"
                        title="Copy this URL"
                      >
                        {copiedUrlIndex === i ? <Check size={14} className="text-severity-safe" /> : <Copy size={14} />}
                      </button>
                      <a
                        href={endpoint.URL}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-brand-muted hover:text-brand-cyan transition-colors"
                        title="Open URL in new tab"
                      >
                        <ExternalLink size={14} />
                      </a>
                    </div>
                  </div>

                  {/* Evidence Block */}
                  {endpoint.Detail && (
                    <div className="p-4 bg-brand-surface/40 font-mono text-[11px] leading-relaxed text-brand-muted">
                      <div className="mb-2 text-[9px] capitalize tracking-wide text-brand-muted/50 border-b border-brand-border/50 pb-1">
                        Evidence / Pattern match
                      </div>
                      <pre className="whitespace-pre-wrap break-all text-brand-text/90">
                        {endpoint.Detail}
                      </pre>
                    </div>
                  )}
                </div>
              ))}
              
              {finding.Endpoints.length > 10 && !showAllEndpoints && (
                <button
                  onClick={() => setShowAllEndpoints(true)}
                  className="w-full py-3 mt-4 border border-dashed border-brand-border rounded text-xs font-bold tracking-wide text-brand-muted hover:text-brand-text hover:bg-brand-surface/50 transition-all"
                >
                  View all {finding.Endpoints.length} resources
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-6 border-t border-brand-border bg-brand-surface/20 flex items-center justify-end">
          <button
            onClick={onClose}
            className="px-6 py-2 bg-brand-cyan text-brand-bg text-xs font-bold tracking-wide rounded hover:bg-brand-cyan/90 transition-all"
          >
            Acknowledge & Close
          </button>
        </div>
      </div>
    </>
  );
}

export default FindingInspector;
