/**
 * App.jsx — Cognitive Security Operations Center (CSOC)
 * Authentic, clean student dashboard for 2nd-year PBL-2 Project
 */
import { useState, useEffect } from 'react';
import {
  Shield, LayoutDashboard, ShieldAlert, Settings,
  LogOut, Clock, UserCheck, Activity, CheckCircle2
} from 'lucide-react';
import { MetricCards } from './components/MetricCards';
import { ModelEvaluationCard } from './components/ModelEvaluationCard';
import { ThreatChart } from './components/ThreatChart';
import { TerminalFeed } from './components/TerminalFeed';
import { AlertPanel } from './components/AlertPanel';
import { XaiAlertPanel } from './components/XaiAlertPanel';
import { SettingsDatabaseView } from './components/SettingsDatabaseView';
import { LoginPage } from './components/LoginPage';
import { useWebSocket } from './hooks/useWebSocket';

// ── Uptime counter ────────────────────────────────────────────────────────
function Uptime() {
  const [seconds, setSeconds] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setSeconds((s) => s + 1), 1000);
    return () => clearInterval(t);
  }, []);
  const h = String(Math.floor(seconds / 3600)).padStart(2, '0');
  const m = String(Math.floor((seconds % 3600) / 60)).padStart(2, '0');
  const s = String(seconds % 60).padStart(2, '0');
  return <span className="font-mono text-xs text-slate-700 font-semibold">{h}:{m}:{s}</span>;
}

// ── Threat status badge ───────────────────────────────────────────────────
function ThreatStatusBadge({ active }) {
  const level = active > 15 ? 'CRITICAL' : active > 8 ? 'HIGH' : active > 3 ? 'ELEVATED' : 'NOMINAL';
  const badgeClasses = {
    CRITICAL: 'bg-red-50 border-red-200 text-red-700',
    HIGH: 'bg-orange-50 border-orange-200 text-orange-700',
    ELEVATED: 'bg-amber-50 border-amber-200 text-amber-700',
    NOMINAL: 'bg-emerald-50 border-emerald-200 text-emerald-700',
  }[level];

  return (
    <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-semibold ${badgeClasses}`}>
      <span className="w-2 h-2 rounded-full bg-current animate-pulse" />
      <span>THREAT STATUS: {level}</span>
      <span className="text-[11px] text-slate-500 font-normal">({active} active)</span>
    </div>
  );
}

// ── Main Dashboard Layout ─────────────────────────────────────────────────
export default function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const { connected, logs, alerts, timeline, metrics, lastCritical } = useWebSocket();
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [activeTab, setActiveTab] = useState('monitoring'); // 'monitoring' | 'alerts' | 'settings'

  const handleSelectAlert = (alert) => {
    setSelectedAlert(alert);
    setActiveTab('alerts');
  };

  // Auto-select latest critical alert for the XAI panel
  useEffect(() => {
    if (lastCritical && !selectedAlert) {
      setSelectedAlert(lastCritical);
    }
  }, [lastCritical, selectedAlert]);

  if (!isLoggedIn) {
    return <LoginPage onLogin={() => setIsLoggedIn(true)} />;
  }

  const tabs = [
    { id: 'monitoring', label: 'Dashboard & Live Monitoring', icon: LayoutDashboard },
    {
      id: 'alerts',
      label: 'Threat Alerts & XAI Analysis',
      icon: ShieldAlert,
      count: alerts.length,
    },
    { id: 'settings', label: 'Model Config & Database', icon: Settings },
  ];

  return (
    <div className="min-h-screen flex flex-col bg-slate-50 text-slate-900 font-sans">
      {/* Top Navbar */}
      <header className="sticky top-0 z-30 px-6 py-3 bg-white border-b border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between shadow-xs gap-3">
        {/* Brand */}
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-blue-600 flex items-center justify-center text-white shadow-xs">
            <Shield size={22} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-bold text-slate-900 leading-tight">
                Cognitive Security Operations Center
              </h1>
              <span className="text-[11px] font-semibold text-blue-700 bg-blue-50 px-2 py-0.5 rounded border border-blue-200">
                PBL-2 Project
              </span>
            </div>
            <p className="text-xs text-slate-500 mt-0.5">
              Network Log Anomaly Detection System • Pune Institute / MIT
            </p>
          </div>
        </div>

        {/* Right Info Controls */}
        <div className="flex items-center flex-wrap gap-3">
          <ThreatStatusBadge active={metrics.active_threats} />

          {/* Connection status */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-50 border border-slate-200 text-xs">
            <div className={`w-2 h-2 rounded-full ${connected ? 'bg-emerald-500' : 'bg-amber-500 animate-pulse'}`} />
            <span className={`text-xs font-semibold ${connected ? 'text-emerald-700' : 'text-amber-700'}`}>
              {connected ? 'Pipeline Online' : 'Connecting...'}
            </span>
          </div>

          {/* Student Profile Pill */}
          <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-700">
            <UserCheck size={14} className="text-blue-600" />
            <span className="font-semibold">Soham Mokashi</span>
            <span className="text-slate-400 font-mono text-[11px]">(SY CSE)</span>
          </div>

          {/* Uptime clock */}
          <div className="hidden lg:flex items-center gap-1.5 text-xs text-slate-500 pl-2 border-l border-slate-200">
            <Clock size={13} className="text-slate-400" />
            <Uptime />
          </div>

          {/* Sign out */}
          <button
            onClick={() => setIsLoggedIn(false)}
            title="Sign out"
            className="flex items-center gap-1 px-3 py-1.5 rounded-lg border border-slate-200 text-xs font-medium text-slate-600 hover:text-red-600 hover:bg-red-50 transition-colors"
          >
            <LogOut size={13} />
            <span className="hidden sm:inline">Logout</span>
          </button>
        </div>
      </header>

      {/* Student Navigation Tab Bar */}
      <div className="px-6 bg-white border-b border-slate-200 flex items-center justify-between">
        <div className="flex items-center gap-1 pt-2">
          {tabs.map(({ id, label, icon: Icon, count }) => {
            const isActive = activeTab === id;
            return (
              <button
                key={id}
                onClick={() => setActiveTab(id)}
                className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold rounded-t-lg transition-colors border-b-2 ${
                  isActive
                    ? 'border-blue-600 text-blue-600 bg-blue-50/50'
                    : 'border-transparent text-slate-500 hover:text-slate-800 hover:bg-slate-50'
                }`}
                style={{ marginBottom: -1 }}
              >
                <Icon size={15} />
                <span>{label}</span>
                {typeof count === 'number' && count > 0 && (
                  <span className={`text-[10px] px-1.5 py-0.2 rounded-full font-bold ${
                    isActive ? 'bg-blue-600 text-white' : 'bg-slate-200 text-slate-700'
                  }`}>
                    {count}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {selectedAlert && (
          <div className="hidden sm:flex items-center gap-2 text-xs text-slate-500 pb-1">
            <span>Investigating Incident:</span>
            <span className="font-mono font-bold text-blue-700 bg-blue-50 px-2 py-0.5 rounded border border-blue-200">
              {selectedAlert.alert_id}
            </span>
          </div>
        )}
      </div>

      {/* Main Tab Content */}
      <main className="flex-1 p-5 max-w-7xl w-full mx-auto flex flex-col gap-4">
        {activeTab === 'monitoring' && (
          <>
            {/* Row 1: Metric KPI Cards */}
            <MetricCards metrics={metrics} connected={connected} />

            {/* Row 2: Model Performance Evaluation Card (Inspired by Video at 1:15) */}
            <ModelEvaluationCard />

            {/* Row 3: Threat Chart */}
            <div className="h-64">
              <ThreatChart timeline={timeline} />
            </div>

            {/* Row 4: Live Telemetry Data Table */}
            <div className="h-[480px]">
              <TerminalFeed logs={logs} onSelectAlert={handleSelectAlert} />
            </div>
          </>
        )}

        {activeTab === 'alerts' && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 h-[750px]">
            {/* Left: Flagged Incidents List (5 cols) */}
            <div className="lg:col-span-5 h-full">
              <AlertPanel
                alerts={alerts}
                connected={connected}
                lastCritical={lastCritical}
                onSelectAlert={setSelectedAlert}
                selectedAlertId={selectedAlert?.alert_id}
              />
            </div>

            {/* Right: XAI Incident Investigation Panel (7 cols) */}
            <div className="lg:col-span-7 h-full">
              <XaiAlertPanel alert={selectedAlert} />
            </div>
          </div>
        )}

        {activeTab === 'settings' && (
          <div className="flex-1">
            <SettingsDatabaseView />
          </div>
        )}
      </main>

      {/* Clean Light Footer */}
      <footer className="mt-auto px-6 py-3 bg-white border-t border-slate-200 text-xs text-slate-500 flex flex-col sm:flex-row items-center justify-between gap-2">
        <div className="flex items-center gap-3">
          <span className="font-semibold text-slate-700">Project:</span>
          <span>Cognitive Security Operations Center (CSOC)</span>
          <span>•</span>
          <span>SY B.Tech Semester-4 Capstone</span>
        </div>
        <div className="flex items-center gap-2 font-mono text-[11px] text-slate-400">
          <span>Engine: Scikit-learn (Isolation Forest)</span>
          <span>•</span>
          <span>Storage: SQLite ORM</span>
          <span>•</span>
          <span>Framework: React + FastAPI</span>
        </div>
      </footer>
    </div>
  );
}
