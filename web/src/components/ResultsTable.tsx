
import { 
  CheckCircle2, 
  XCircle, 
  AlertTriangle, 
  ExternalLink, 
  Clock, 
  Zap 
} from 'lucide-react'

interface ScanResult {
  id: string;
  target: string;
  status: number;
  statusText: string;
  headerCount: number;
  totalHeaders: number;
  duration: number;
  scannedAt: string;
}

const mockData: ScanResult[] = [
  {
    id: '1',
    target: 'https://owasp.org',
    status: 200,
    statusText: 'OK',
    headerCount: 8,
    totalHeaders: 8,
    duration: 142,
    scannedAt: '2 mins ago'
  },
  {
    id: '2',
    target: 'https://google.com',
    status: 301,
    statusText: 'Moved',
    headerCount: 6,
    totalHeaders: 8,
    duration: 89,
    scannedAt: '12 mins ago'
  },
  {
    id: '3',
    target: 'https://vulnerable-site.io',
    status: 200,
    statusText: 'OK',
    headerCount: 2,
    totalHeaders: 8,
    duration: 310,
    scannedAt: '45 mins ago'
  },
  {
    id: '4',
    target: 'https://api.github.com',
    status: 200,
    statusText: 'OK',
    headerCount: 7,
    totalHeaders: 8,
    duration: 156,
    scannedAt: '1 hour ago'
  },
  {
    id: '5',
    target: 'https://developer.mozilla.org',
    status: 200,
    statusText: 'OK',
    headerCount: 8,
    totalHeaders: 8,
    duration: 210,
    scannedAt: '3 hours ago'
  }
]

function ResultsTable() {
  return (
    <table className="w-full text-sm text-left border-collapse">
      <thead className="bg-brand-bg/50 text-brand-muted uppercase text-xs tracking-wider">
        <tr>
          <th className="px-6 py-4 font-semibold">Target URL</th>
          <th className="px-6 py-4 font-semibold text-center">HTTP Status</th>
          <th className="px-6 py-4 font-semibold text-center">Security Health</th>
          <th className="px-6 py-4 font-semibold text-center">Duration</th>
          <th className="px-6 py-4 font-semibold text-right">Scanned</th>
        </tr>
      </thead>
      <tbody className="divide-y divide-brand-border/50">
        {mockData.map((scan) => (
          <tr key={scan.id} className="hover:bg-brand-cyan/5 transition-colors group">
            <td className="px-6 py-4">
              <div className="flex items-center gap-2">
                <span className="font-mono text-brand-cyan truncate max-w-[240px]">{scan.target}</span>
                <ExternalLink size={14} className="text-brand-muted opacity-0 group-hover:opacity-100 transition-opacity cursor-pointer" />
              </div>
            </td>
            <td className="px-6 py-4">
              <div className="flex justify-center">
                <StatusBadge code={scan.status} text={scan.statusText} />
              </div>
            </td>
            <td className="px-6 py-4">
              <div className="flex justify-center">
                <HealthIndicator current={scan.headerCount} total={scan.totalHeaders} />
              </div>
            </td>
            <td className="px-6 py-4">
              <div className="flex items-center justify-center gap-1.5 text-brand-muted">
                <Zap size={14} className="text-brand-cyan/70" />
                <span>{scan.duration}ms</span>
              </div>
            </td>
            <td className="px-6 py-4 text-right text-brand-muted font-medium">
              <div className="flex items-center justify-end gap-1.5">
                <Clock size={14} />
                <span>{scan.scannedAt}</span>
              </div>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function StatusBadge({ code, text }: { code: number; text: string }) {
  let colorClass = 'bg-brand-cyan/10 text-brand-cyan border-brand-cyan/20';
  if (code >= 200 && code < 300) colorClass = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
  if (code >= 300 && code < 400) colorClass = 'bg-blue-500/10 text-blue-400 border-blue-500/20';
  if (code >= 400 && code < 500) colorClass = 'bg-amber-500/10 text-amber-400 border-amber-500/20';
  if (code >= 500) colorClass = 'bg-red-500/10 text-red-500 border-red-500/20';

  return (
    <span className={`px-2.5 py-1 rounded-full text-xs font-bold border ${colorClass} flex items-center gap-1 w-fit`}>
      <span className={`w-1.5 h-1.5 rounded-full ${code >= 200 && code < 300 ? 'bg-emerald-400' : 'bg-current'}`}></span>
      {code} {text}
    </span>
  )
}

function HealthIndicator({ current, total }: { current: number; total: number }) {
  const percentage = (current / total) * 100;
  let colorClass = 'text-brand-cyan';
  let Icon = CheckCircle2;
  
  if (percentage < 50) {
    colorClass = 'text-red-400';
    Icon = XCircle;
  } else if (percentage < 100) {
    colorClass = 'text-amber-400';
    Icon = AlertTriangle;
  }

  return (
    <div className="flex items-center gap-2">
      <Icon size={16} className={colorClass} />
      <div className="w-24 h-1.5 bg-brand-border rounded-full overflow-hidden">
        <div 
          className={`h-full transition-all duration-500 ${
            percentage === 100 ? 'bg-brand-cyan' : percentage < 50 ? 'bg-red-400' : 'bg-amber-400'
          }`} 
          style={{ width: `${percentage}%` }}
        ></div>
      </div>
      <span className="text-xs font-bold text-brand-muted w-8">{current}/{total}</span>
    </div>
  )
}

export default ResultsTable
