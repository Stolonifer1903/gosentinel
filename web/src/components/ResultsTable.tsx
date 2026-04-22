import {
  ExternalLink,
  Clock,
  Zap,
} from "lucide-react";

interface ScanResult {
  id: string;
  Target: string;
  Status: number;
  StatusText: string;
  HeaderCount: number;
  TotalHeaders: number;
  Duration: number;
  ScannedAt: string;
}

const mockData: ScanResult[] = [
  {
    id: "1",
    Target: "https://owasp.org",
    Status: 200,
    StatusText: "OK",
    HeaderCount: 8,
    TotalHeaders: 8,
    Duration: 142,
    ScannedAt: "2 mins ago",
  },
  {
    id: "2",
    Target: "https://google.com",
    Status: 301,
    StatusText: "Moved",
    HeaderCount: 6,
    TotalHeaders: 8,
    Duration: 89,
    ScannedAt: "12 mins ago",
  },
  {
    id: "3",
    Target: "https://vulnerable-site.io",
    Status: 200,
    StatusText: "OK",
    HeaderCount: 2,
    TotalHeaders: 8,
    Duration: 310,
    ScannedAt: "45 mins ago",
  },
  {
    id: "4",
    Target: "https://api.github.com",
    Status: 200,
    StatusText: "OK",
    HeaderCount: 7,
    TotalHeaders: 8,
    Duration: 156,
    ScannedAt: "1 hour ago",
  },
  {
    id: "5",
    Target: "https://developer.mozilla.org",
    Status: 200,
    StatusText: "OK",
    HeaderCount: 8,
    TotalHeaders: 8,
    Duration: 210,
    ScannedAt: "3 hours ago",
  },
];

function ResultsTable() {
  return (
    <table className="w-full text-left border-collapse table-fixed">
      <thead className="bg-brand-surface/50 text-brand-muted uppercase text-[10px] font-bold tracking-widest">
        <tr>
          <th className="px-5 py-3 w-1/3">Endpoint</th>
          <th className="px-5 py-3 w-32 text-center">Status</th>
          <th className="px-5 py-3 text-center">Security Health</th>
          <th className="px-5 py-3 w-32 text-right">Activity</th>
        </tr>
      </thead>
      <tbody className="divide-y divide-brand-border/50">
        {mockData.map((scan) => (
          <tr
            key={scan.id}
            className="hover:bg-brand-surface transition-colors group"
          >
            <td className="px-5 py-3">
              <div className="flex items-center gap-2 overflow-hidden">
                <span className="font-mono text-xs text-brand-cyan truncate">
                  {scan.Target}
                </span>
                <ExternalLink
                  size={10}
                  className="text-brand-muted opacity-0 group-hover:opacity-100 transition-opacity cursor-pointer flex-shrink-0"
                />
              </div>
            </td>
            <td className="px-5 py-3">
              <div className="flex justify-center">
                <StatusBadge code={scan.Status} text={scan.StatusText} />
              </div>
            </td>
            <td className="px-5 py-3">
              <div className="flex justify-center">
                <HealthIndicator
                  current={scan.HeaderCount}
                  total={scan.TotalHeaders}
                />
              </div>
            </td>
            <td className="px-5 py-3">
              <div className="flex flex-col items-end gap-0.5 text-[10px] font-mono text-brand-muted">
                <div className="flex items-center gap-1">
                  <Zap size={10} className="text-brand-cyan/60" />
                  <span>{scan.Duration}ms</span>
                </div>
                <div className="flex items-center gap-1 opacity-60">
                  <Clock size={10} />
                  <span>{scan.ScannedAt}</span>
                </div>
              </div>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function StatusBadge({ code, text }: { code: number; text: string }) {
  let colorClass = "text-brand-cyan border-brand-cyan/20 bg-brand-cyan/5";
  if (code >= 200 && code < 300)
    colorClass =
      "text-severity-safe border-severity-safe/20 bg-severity-safe/5";
  if (code >= 300 && code < 400)
    colorClass = "text-brand-muted border-brand-border bg-brand-surface";
  if (code >= 400 && code < 500)
    colorClass =
      "text-severity-medium border-severity-medium/20 bg-severity-medium/5";
  if (code >= 500)
    colorClass =
      "text-severity-critical border-severity-critical/20 bg-severity-critical/5";

  return (
    <span
      className={`px-2 py-0.5 rounded border ${colorClass} text-[10px] font-bold uppercase tracking-wide`}
    >
      {code} {text}
    </span>
  );
}

function HealthIndicator({
  current,
  total,
}: {
  current: number;
  total: number;
}) {
  const percentage = (current / total) * 100;
  let colorClass = "bg-brand-cyan";

  if (percentage < 50) {
    colorClass = "bg-severity-critical";
  } else if (percentage < 100) {
    colorClass = "bg-severity-medium";
  }

  return (
    <div className="flex items-center justify-center gap-3">
      <div className="w-20 h-1 bg-brand-border rounded-full overflow-hidden flex-shrink-0">
        <div
          className={`h-full transition-all duration-500 ${colorClass}`}
          style={{ width: `${percentage}%` }}
        ></div>
      </div>
      <span className="text-[10px] font-mono font-bold text-brand-muted min-w-[32px]">
        {current}/{total}
      </span>
    </div>
  );
}

export default ResultsTable;
