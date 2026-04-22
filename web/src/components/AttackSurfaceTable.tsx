import { Globe, Hash, Zap } from "lucide-react";
import type { Endpoint } from "../types/scan";

interface Props {
  endpoints: Endpoint[];
}

function AttackSurfaceTable({ endpoints }: Props) {
  if (!endpoints || endpoints.length === 0) {
    return (
      <div className="p-16 text-center text-brand-muted border border-dashed border-brand-border rounded">
        <Globe size={40} className="mx-auto mb-4 opacity-10" />
        <p className="text-xs uppercase tracking-widest font-bold">
          No endpoints discovered
        </p>
      </div>
    );
  }

  return (
    <table className="w-full text-left border-collapse table-fixed">
      <thead className="bg-brand-surface/50 text-brand-muted uppercase text-[10px] font-bold tracking-widest">
        <tr>
          <th className="px-5 py-3 w-20">Method</th>
          <th className="px-5 py-3">Endpoint URL</th>
          <th className="px-5 py-3">Parameters</th>
          <th className="px-5 py-3 w-24 text-right">Source</th>
        </tr>
      </thead>
      <tbody className="divide-y divide-brand-border/50">
        {endpoints.map((endpoint, idx) => (
          <tr key={idx} className="transition-colors hover:bg-brand-surface/50 group">
            <td className="px-5 py-4 align-top">
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono border ${
                endpoint.Method === 'POST' 
                  ? 'bg-brand-cyan/10 text-brand-cyan border-brand-cyan/20' 
                  : 'bg-brand-surface text-brand-muted border-brand-border'
              }`}>
                {endpoint.Method}
              </span>
            </td>
            <td className="px-5 py-4 align-top">
              <div className="flex flex-col gap-0.5">
                <span className="text-sm font-mono text-brand-text truncate" title={endpoint.URL}>
                  {endpoint.URL}
                </span>
              </div>
            </td>
            <td className="px-5 py-4 align-top">
              <div className="flex flex-wrap gap-1">
                {endpoint.Params && endpoint.Params.length > 0 ? (
                  endpoint.Params.map((param, pIdx) => (
                    <span key={pIdx} className="px-1.5 py-0.5 bg-brand-surface border border-brand-border rounded text-[10px] font-mono text-brand-muted">
                      {param}
                    </span>
                  ))
                ) : (
                  <span className="text-[10px] text-brand-muted/40 italic">—</span>
                )}
              </div>
            </td>
            <td className="px-5 py-4 text-right align-top">
              <div className="flex items-center justify-end gap-1.5 text-brand-muted">
                {endpoint.Source === 'Form' ? (
                  <Zap size={10} className="text-brand-cyan" />
                ) : (
                  <Hash size={10} />
                )}
                <span className="text-[10px] font-bold uppercase tracking-tight">
                  {endpoint.Source || 'Seed'}
                </span>
              </div>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default AttackSurfaceTable;
