import { useState } from 'react'
import { 
  LayoutDashboard, 
  ShieldCheck, 
  History, 
  Settings, 
  Search, 
  Bell, 
  User, 
  Menu,
  Terminal,
  Activity
} from 'lucide-react'
import ResultsTable from './components/ResultsTable'

function App() {
  const [isSidebarOpen, setIsSidebarOpen] = useState(true)

  return (
    <div className="flex h-screen bg-brand-bg text-brand-text font-sans overflow-hidden">
      {/* Sidebar */}
      <aside className={`bg-brand-surface border-r border-brand-border transition-all duration-300 flex flex-col ${isSidebarOpen ? 'w-64' : 'w-20'}`}>
        <div className="p-6 flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-brand-cyan/20 flex items-center justify-center text-brand-cyan">
            <ShieldCheck size={20} />
          </div>
          {isSidebarOpen && (
            <h1 className="text-xl font-bold tracking-tight">
              Go<span className="text-brand-cyan">Sentinel</span>
            </h1>
          )}
        </div>

        <nav className="flex-1 px-4 py-4 space-y-2">
          <NavItem icon={<LayoutDashboard size={20} />} label="Dashboard" active isOpen={isSidebarOpen} />
          <NavItem icon={<Activity size={20} />} label="Live Scan" isOpen={isSidebarOpen} />
          <NavItem icon={<History size={20} />} label="Scan History" isOpen={isSidebarOpen} />
          <div className="pt-4 mt-4 border-t border-brand-border">
            <NavItem icon={<Settings size={20} />} label="Settings" isOpen={isSidebarOpen} />
            <NavItem icon={<Terminal size={20} />} label="CLI Docs" isOpen={isSidebarOpen} />
          </div>
        </nav>

        <div className="p-4 border-t border-brand-border">
          <button 
            onClick={() => setIsSidebarOpen(!isSidebarOpen)}
            className="w-full flex items-center justify-center p-2 rounded-lg hover:bg-brand-border/50 text-brand-muted hover:text-brand-text transition-colors"
          >
            <Menu size={20} />
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Header */}
        <header className="h-16 bg-brand-surface border-b border-brand-border px-8 flex items-center justify-between">
          <div className="flex items-center gap-4 flex-1 max-w-xl">
            <div className="relative w-full">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-brand-muted" size={18} />
              <input 
                type="text" 
                placeholder="Search scans, URLs, vulnerabilities..." 
                className="w-full bg-brand-bg border border-brand-border rounded-full py-2 pl-10 pr-4 text-sm focus:outline-none focus:border-brand-cyan/50 focus:ring-1 focus:ring-brand-cyan/50 transition-all"
              />
            </div>
          </div>

          <div className="flex items-center gap-6 pl-4">
            <button className="text-brand-muted hover:text-brand-text relative">
              <Bell size={20} />
              <span className="absolute -top-1 -right-1 w-2 h-2 bg-brand-cyan rounded-full"></span>
            </button>
            <div className="flex items-center gap-3 border-l border-brand-border pl-6">
              <div className="text-right hidden sm:block">
                <p className="text-sm font-medium">Security Auditor</p>
                <p className="text-xs text-brand-muted">admin@gosentinel.dev</p>
              </div>
              <div className="w-10 h-10 rounded-full bg-brand-border flex items-center justify-center text-brand-muted">
                <User size={20} />
              </div>
            </div>
          </div>
        </header>

        {/* Dashboard Area */}
        <div className="flex-1 overflow-y-auto p-12 custom-scrollbar">
          <div className="mb-8">
            <h2 className="text-2xl font-bold">Security Scan Dashboard</h2>
            <p className="text-brand-muted mt-1">Real-time overview of your target ecosystems.</p>
          </div>

          {/* Stats Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-10">
            <StatCard label="Total Scans" value="1,284" change="+12%" />
            <StatCard label="Vulnerabilities Found" value="84" change="+3" isWarning />
            <StatCard label="Average Health" value="94.2%" change="-1.5%" />
            <StatCard label="Active Targets" value="12" change="0" />
          </div>

          {/* Results Table Section */}
          <div className="bg-brand-surface border border-brand-border rounded-2xl overflow-hidden shadow-xl shadow-brand-bg/50">
            <div className="px-6 py-4 border-b border-brand-border flex items-center justify-between">
              <h3 className="font-semibold text-lg">Recent Scan Findings</h3>
              <button className="text-brand-cyan text-sm font-medium hover:underline">View All History</button>
            </div>
            <div className="overflow-x-auto">
              <ResultsTable />
            </div>
          </div>
        </div>
      </main>
    </div>
  )
}

interface NavItemProps {
  icon: React.ReactNode;
  label: string;
  active?: boolean;
  isOpen: boolean;
}

function NavItem({ icon, label, active, isOpen }: NavItemProps) {
  return (
    <a 
      href="#" 
      className={`flex items-center gap-3 px-4 py-3 rounded-xl transition-all duration-200 group ${
        active 
          ? 'bg-brand-cyan/10 text-brand-cyan shadow-[inset_0_0_0_1px_rgba(0,229,255,0.2)]' 
          : 'text-brand-muted hover:bg-brand-border/30 hover:text-brand-text'
      }`}
    >
      <div className={`${active ? 'text-brand-cyan' : 'group-hover:text-brand-cyan'} transition-colors`}>
        {icon}
      </div>
      {isOpen && <span className="text-sm font-medium">{label}</span>}
    </a>
  )
}

interface StatCardProps {
  label: string;
  value: string;
  change: string;
  isWarning?: boolean;
}

function StatCard({ label, value, change, isWarning }: StatCardProps) {
  const isPositive = change.startsWith('+');
  return (
    <div className="bg-brand-surface border border-brand-border p-6 rounded-2xl flex flex-col gap-2 hover:border-brand-cyan/30 transition-all group shadow-lg">
      <p className="text-brand-muted text-sm font-medium uppercase tracking-wider">{label}</p>
      <div className="flex items-end justify-between">
        <p className={`text-3xl font-bold ${isWarning && value !== "0" ? 'text-red-400' : ''}`}>{value}</p>
        <span className={`text-xs font-bold px-2 py-1 rounded-full ${
          isPositive ? 'bg-emerald-500/10 text-emerald-400' : 'bg-red-500/10 text-red-400'
        }`}>
          {change}
        </span>
      </div>
    </div>
  )
}

export default App
