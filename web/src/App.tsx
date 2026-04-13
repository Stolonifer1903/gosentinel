import { useState, useRef } from "react";
import {
  LayoutDashboard,
  ShieldCheck,
  History,
  Settings,
  Search,
  Bell,
  Menu,
  Activity,
  Upload,
  X,
  Plus,
} from "lucide-react";
import ResultsTable from "./components/ResultsTable";
import VulnerabilityTable from "./components/VulnerabilityTable";
import FindingInspector from "./components/FindingInspector";
import type { ScanResult, GroupedFinding } from "./types/scan";

function App() {
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);
  const [activeReport, setActiveReport] = useState<ScanResult | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<GroupedFinding | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const json = JSON.parse(e.target?.result as string);
        setActiveReport(json);
      } catch (err) {
        alert(
          "Invalid report file. Please import a valid GoSentinel .json report.",
        );
        console.error("Parse error:", err);
      }
    };
    reader.readAsText(file);
  };

  const resetReport = () => {
    setActiveReport(null);
    setSelectedFinding(null);
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  return (
    <div className="flex h-screen bg-brand-bg text-brand-text font-sans overflow-hidden relative">
      {/* Sidebar - Vercel style slim & minimal */}
      <aside
        className={`bg-brand-bg border-r border-brand-border transition-all duration-300 flex flex-col ${isSidebarOpen ? "w-64" : "w-16"}`}
      >
        <div className="p-4 flex items-center gap-3">
          <div className="w-6 h-6 rounded flex items-center justify-center text-brand-cyan">
            <ShieldCheck size={18} />
          </div>
          {isSidebarOpen && (
            <h1 className="text-sm font-bold tracking-tight uppercase">
              Go<span className="text-brand-cyan">Sentinel</span>
            </h1>
          )}
        </div>

        <nav className="flex-1 px-3 py-4 space-y-1">
          <NavItem
            icon={<LayoutDashboard size={18} />}
            label="Dashboard"
            active={!activeReport}
            isOpen={isSidebarOpen}
            onClick={resetReport}
          />
          <NavItem
            icon={<Activity size={18} />}
            label="Live Scan"
            isOpen={isSidebarOpen}
          />
          <NavItem
            icon={<History size={18} />}
            label="Scan History"
            isOpen={isSidebarOpen}
          />
          <div className="pt-4 mt-4 border-t border-brand-border">
            <NavItem
              icon={<Plus size={18} />}
              label="New Scan"
              isOpen={isSidebarOpen}
              highlight
            />
            <NavItem
              icon={<Upload size={18} />}
              label="Import Report"
              isOpen={isSidebarOpen}
              onClick={() => fileInputRef.current?.click()}
            />
            <NavItem
              icon={<Settings size={18} />}
              label="Settings"
              isOpen={isSidebarOpen}
            />
          </div>
        </nav>

        <input
          type="file"
          ref={fileInputRef}
          onChange={handleFileUpload}
          accept=".json"
          className="hidden"
        />

        <div className="p-3 border-t border-brand-border">
          <button
            onClick={() => setIsSidebarOpen(!isSidebarOpen)}
            className="w-full h-8 flex items-center justify-center rounded hover:bg-brand-surface text-brand-muted hover:text-brand-text transition-colors"
          >
            <Menu size={16} />
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Header - Transparent & Integrated */}
        <header className="h-14 border-b border-brand-border px-6 flex items-center justify-between">
          <div className="flex items-center gap-4 flex-1 max-w-lg">
            <div className="relative w-full">
              <Search
                className="absolute left-2.5 top-1/2 -translate-y-1/2 text-brand-muted"
                size={14}
              />
              <input
                type="text"
                placeholder="Search resources..."
                className="w-full bg-transparent border-none text-xs focus:ring-0 placeholder:text-brand-muted/50"
              />
            </div>
          </div>

          <div className="flex items-center gap-4 pl-4">
            <button className="text-brand-muted hover:text-brand-text relative">
              <Bell size={18} />
              <span className="absolute top-0 right-0 w-1.5 h-1.5 bg-brand-cyan rounded-full border-2 border-brand-bg"></span>
            </button>
            <div className="flex items-center gap-2 border-l border-brand-border pl-4">
              <div className="w-6 h-6 rounded-full bg-brand-surface border border-brand-border flex items-center justify-center text-[10px] font-bold text-brand-muted">
                SY
              </div>
            </div>
          </div>
        </header>

        {/* Dashboard Area */}
        <div className="flex-1 overflow-y-auto p-8 custom-scrollbar">
          <div className="mb-6 flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold tracking-tight text-brand-text">
                {activeReport ? activeReport.Target : "System Overview"}
              </h2>
              <p className="text-xs text-brand-muted">
                {activeReport
                  ? `Security session started at ${new Date(activeReport.ScannedAt).toLocaleString()}`
                  : "Aggregate security posture across all clusters."}
              </p>
            </div>
            {activeReport && (
              <button
                onClick={resetReport}
                className="flex items-center gap-2 px-3 py-1.5 bg-brand-surface border border-brand-border hover:bg-brand-border rounded text-xs font-medium transition-all"
              >
                <X size={14} /> Dismiss
              </button>
            )}
          </div>

          {/* Stats Cards - Precise & Monospaced */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
            <StatCard
              label="Total Scans"
              value={activeReport ? "1" : "1,284"}
              trend={activeReport ? "" : "+12%"}
            />
            <StatCard
              label="Vulnerabilities"
              value={
                activeReport
                  ? (activeReport.Findings?.length || 0).toString()
                  : "84"
              }
              trend={activeReport ? "" : "+3"}
              isWarning={
                !!activeReport && (activeReport.Findings?.length || 0) > 0
              }
            />
            <StatCard
              label="Severity Score"
              value={
                activeReport
                  ? (
                      (activeReport.SeverityCounts?.Critical || 0) +
                      (activeReport.SeverityCounts?.High || 0)
                    ).toString()
                  : "94.2"
              }
              trend={activeReport ? "Weighted" : "-1.5"}
            />
            <StatCard
              label="Endpoints"
              value={
                activeReport
                  ? (activeReport.Endpoints?.length || 0).toString()
                  : "12"
              }
              trend={activeReport ? "Active" : "0"}
            />
          </div>

          {/* Main Area: High Density Content */}
          <div className="bg-brand-bg border border-brand-border rounded overflow-hidden">
            <div className="px-5 py-3 border-b border-brand-border flex items-center justify-between bg-brand-surface/30">
              <div className="flex items-center gap-2">
                <Activity className="text-brand-muted" size={16} />
                <h3 className="text-xs font-bold uppercase tracking-widest text-brand-muted">
                  {activeReport ? "Finding Log" : "Event Stream"}
                </h3>
              </div>
              {!activeReport && (
                <button className="text-brand-cyan text-[11px] font-bold uppercase hover:underline">
                  View History
                </button>
              )}
            </div>
            <div className="overflow-x-auto">
              {activeReport ? (
                <VulnerabilityTable 
                  findings={activeReport.Findings} 
                  onInspect={setSelectedFinding}
                  selectedId={selectedFinding ? selectedFinding.Title + selectedFinding.OWASP : undefined}
                />
              ) : (
                <ResultsTable />
              )}
            </div>
          </div>
        </div>
      </main>

      {/* Finding Inspector - Side Drawer */}
      <FindingInspector 
        finding={selectedFinding} 
        onClose={() => setSelectedFinding(null)} 
      />
    </div>
  );
}

interface NavItemProps {
  icon: React.ReactNode;
  label: string;
  active?: boolean;
  isOpen: boolean;
  onClick?: () => void;
  highlight?: boolean;
}

function NavItem({
  icon,
  label,
  active,
  isOpen,
  onClick,
  highlight,
}: NavItemProps) {
  return (
    <button
      onClick={onClick}
      className={`w-full flex items-center h-9 px-3 rounded transition-all duration-200 group ${
        active
          ? "bg-brand-surface text-brand-cyan"
          : highlight
            ? "text-brand-cyan hover:bg-brand-cyan/10"
            : "text-brand-muted hover:bg-brand-surface hover:text-brand-text"
      }`}
    >
      <div className="flex-shrink-0">{icon}</div>
      {isOpen && <span className="text-xs font-medium ml-3">{label}</span>}
    </button>
  );
}

interface StatCardProps {
  label: string;
  value: string;
  trend: string;
  isWarning?: boolean;
}

function StatCard({ label, value, trend, isWarning }: StatCardProps) {
  return (
    <div className="bg-brand-bg border border-brand-border p-4 rounded flex flex-col gap-1 hover:border-brand-muted/30 transition-all group">
      <p className="text-brand-muted text-[10px] font-bold uppercase tracking-wider">
        {label}
      </p>
      <div className="flex items-baseline justify-between mt-1">
        <p
          className={`text-2xl font-mono font-bold tracking-tighter ${isWarning ? "text-severity-critical" : "text-brand-text"}`}
        >
          {value}
        </p>
        {trend && (
          <span
            className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${
              isWarning
                ? "bg-severity-critical/10 text-severity-critical border-severity-critical/20"
                : "bg-brand-surface text-brand-muted border-brand-border"
            }`}
          >
            {trend}
          </span>
        )}
      </div>
    </div>
  );
}

export default App;
