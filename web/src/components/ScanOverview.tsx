import { Info, AlertCircle, Server } from "lucide-react";
import type { ScanResult } from "../types/scan";

interface Props {
  report: ScanResult;
}

function ScanOverview({ report }: Props) {
  return (
    <div className="p-8 space-y-8 animate-in fade-in duration-500">
      {/* Module Errors if any */}
      {report.ModuleErrors && Object.keys(report.ModuleErrors).length > 0 && (
        <section className="space-y-3">
          <h3 className="text-xs font-bold uppercase tracking-widest text-severity-high flex items-center gap-2">
            <AlertCircle size={14} /> Module Interruptions
          </h3>
          <div className="grid gap-2">
            {Object.entries(report.ModuleErrors).map(([module, error]) => (
              <div key={module} className="p-4 bg-severity-high/5 border border-severity-high/20 rounded-lg flex items-start gap-4">
                <div className="mt-1 w-2 h-2 rounded-full bg-severity-high shadow-[0_0_8px_rgba(239,68,68,0.5)]" />
                <div className="flex flex-col gap-1">
                  <span className="text-xs font-bold text-brand-text uppercase">{module}</span>
                  <span className="text-sm text-brand-muted font-mono">{error}</span>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Connection Details */}
        <section className="space-y-4">
          <h3 className="text-xs font-bold uppercase tracking-widest text-brand-muted flex items-center gap-2">
            <Info size={14} /> Connection Metadata
          </h3>
          <div className="bg-brand-surface/30 border border-brand-border rounded-xl overflow-hidden">
            <div className="grid grid-cols-2 divide-x divide-brand-border border-b border-brand-border">
              <div className="p-4 flex flex-col gap-1">
                <span className="text-[10px] font-bold text-brand-muted uppercase">Status Code</span>
                <div className="flex items-center gap-2">
                  <span className={`w-2 h-2 rounded-full ${report.StatusCode >= 200 && report.StatusCode < 300 ? 'bg-severity-safe' : 'bg-severity-medium'}`} />
                  <span className="text-lg font-mono font-bold">{report.StatusCode}</span>
                </div>
              </div>
              <div className="p-4 flex flex-col gap-1">
                <span className="text-[10px] font-bold text-brand-muted uppercase">Latency</span>
                <span className="text-lg font-mono font-bold text-brand-cyan">{(report.Duration / 1000000).toFixed(2)}ms</span>
              </div>
            </div>
            <div className="p-4 flex flex-col gap-1">
              <span className="text-[10px] font-bold text-brand-muted uppercase">Server Status</span>
              <span className="text-sm font-medium text-brand-text">{report.Status}</span>
            </div>
          </div>
        </section>

        {/* Server Fingerprint */}
        <section className="space-y-4">
          <h3 className="text-xs font-bold uppercase tracking-widest text-brand-muted flex items-center gap-2">
            <Server size={14} /> Target Headers
          </h3>
          <div className="bg-brand-bg border border-brand-border rounded-xl overflow-hidden max-h-[400px] overflow-y-auto custom-scrollbar">
            <table className="w-full text-left border-collapse">
              <thead className="bg-brand-surface text-[10px] font-bold text-brand-muted sticky top-0 uppercase">
                <tr>
                  <th className="px-4 py-2 border-b border-brand-border">Header Field</th>
                  <th className="px-4 py-2 border-b border-brand-border">Value</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-brand-border/50">
                {Object.entries(report.AllHeaders).map(([key, values]) => (
                  <tr key={key} className="group hover:bg-brand-surface/30">
                    <td className="px-4 py-2 align-top text-xs font-bold text-brand-cyan font-mono group-hover:text-brand-text transition-colors">{key}</td>
                    <td className="px-4 py-2 align-top text-xs text-brand-muted font-mono break-all">{values.join(', ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </div>
  );
}

export default ScanOverview;
