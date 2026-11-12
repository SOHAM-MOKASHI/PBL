/**
 * App.jsx — CSOC Enterprise Threat Detection & Incident Response Platform
 * Clean, production-grade layout orchestrator
 */
import { useState, useEffect } from 'react';
import { Shield, Activity, Network, LayoutDashboard, UserCheck, Clock } from 'lucide-react';
import { MetricCards } from './components/MetricCards';
import { ThreatChart } from './components/ThreatChart';
import { TerminalFeed } from './components/TerminalFeed';
import { AlertPanel } from './components/AlertPanel';
import { PipelineView } from './components/PipelineView';
import { KillChainGraph } from './components/KillChainGraph';
import { XaiAlertPanel } from './components/XaiAlertPanel';
import { MitreRadar } from './components/MitreRadar';
import { LoginPage } from './components/LoginPage';
import { useWebSocket } from './hooks/useWebSocket';

// ── Uptime clock ──────────────────────────────────────────────────────────
function Uptime() {
  const [seconds, setSeconds] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setSeconds(s => s + 1), 1000);
    return () => clearInterval(t);
  }, []);
  const h = String(Math.floor(seconds / 3600)).padStart(2, '0');
  const m = String(Math.floor((seconds % 3600) / 60)).padStart(2, '0');
  const s = String(seconds % 60).padStart(2, '0');
  return <span className="font-mono text-xs text-slate-300 font-medium">{h}:{m}:{s}</span>;
}

// ── Clean Enterprise Threat Status Badge ──────────────────────────────────
function ThreatStatusBadge({ active }) {
  const level = active > 15 ? 'CRITICAL' : active > 8 ? 'HIGH' : active > 3 ? 'ELEVATED' : 'NOMINAL';
  const badgeClasses = {
    CRITICAL: 'bg-red-950/60 border-red-800/80 text-red-400',
    HIGH: 'bg-orange-950/60 border-orange-800/80 text-orange-400',
    ELEVATED: 'bg-amber-950/60 border-amber-800/80 text-amber-400',
    NOMINAL: 'bg-emerald-950/60 border-emerald-800/80 text-emerald-400',
  }[level];

  return (
    <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-mono font-semibold ${badgeClasses}`}>
      <span className="w-2 h-2 rounded-full bg-current" />
      <span>THREAT STATUS: {level}</span>
      <span className="text-[10px] text-slate-400">({active} active)</span>
    </div>
  );
}

// ── Header ────────────────────────────────────────────────────────────────
function Header({ connected, active }) {
  return (
    <header className="shrink-0 px-6 py-3 bg-slate-900 border-b border-slate-800 flex items-center justify-between">
      {/* Brand */}
      <div className="flex items-center gap-3">
        <div className="w-9 h-9 rounded-lg bg-blue-600/10 border border-blue-500/30 flex items-center justify-center text-blue-400 shrink-0">
          <Shield size={20} />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-base font-bold text-white tracking-tight">
              CSOC Platform
            </h1>
            <span className="text-slate-600 font-mono text-xs">/</span>
            <span className="text-xs text-slate-300 font-medium tracking-wide">
              Security Operations Center
            </span>
          </div>
          <div className="flex items-center gap-2 mt-0.5 text-[11px] text-slate-400">
            <span>PBL-2 Capstone Prototype</span>
            <span>•</span>
            <span className="text-slate-400 font-mono">Stream Engine: Active Ingestion</span>
          </div>
        </div>
      </div>

      {/* Status & Session info */}
      <div className="flex items-center gap-4">
        <ThreatStatusBadge active={active} />

        {/* Live indicator */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs">
          <div className={`w-2 h-2 rounded-full ${connected ? 'bg-emerald-400' : 'bg-amber-400 animate-pulse'}`} />
          <span className={`font-mono text-xs font-medium ${connected ? 'text-emerald-400' : 'text-amber-400'}`}>
            {connected ? 'PIPELINE ONLINE' : 'RECONNECTING'}
          </span>
        </div>

        {/* User Pill */}
        <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300">
          <UserCheck size={14} className="text-blue-400" />
          <span className="font-medium">Soham Mokashi</span>
          <span className="text-[10px] text-slate-500 font-mono">Tier-2 Analyst</span>
        </div>

        {/* Uptime */}
        <div className="flex items-center gap-1.5 text-xs text-slate-400 pl-1 border-l border-slate-800">
          <Clock size={13} className="text-slate-500" />
          <Uptime />
        </div>
      </div>
    </header>
  );
}

// ── App Layout ────────────────────────────────────────────────────────────
export default function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const { connected, logs, alerts, timeline, metrics, lastCritical } = useWebSocket();
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [activeTab, setActiveTab] = useState('core'); // 'core' | 'research'

  const handleSelectAlert = (alert) => {
    setSelectedAlert(alert);
    setActiveTab('research');
  };

  // Auto-select latest critical alert for research panel
  useEffect(() => {
    if (lastCritical) setSelectedAlert(lastCritical);
  }, [lastCritical?.alert_id]);

  if (!isLoggedIn) {
    return <LoginPage onLogin={() => setIsLoggedIn(true)} />;
  }

  return (
    <div className="h-screen flex flex-col overflow-hidden bg-slate-950 text-slate-100 font-sans">
      {/* Top Header */}
      <Header connected={connected} active={metrics.active_threats} />

      {/* Enterprise Tab Bar */}
      <div className="shrink-0 px-6 pt-2 bg-slate-900/60 border-b border-slate-800 flex items-center justify-between">
        <div className="flex items-center gap-1">
          {[
            { id: 'core', label: 'Incident Monitoring & Telemetry', icon: LayoutDashboard },
            { id: 'research', label: 'Attack Investigation & MITRE ATT&CK®', icon: Network },
          ].map(({ id, label, icon: Icon }) => {
            const isActive = activeTab === id;
            return (
              <button
                key={id}
                onClick={() => setActiveTab(id)}
                className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium rounded-t-lg transition-colors border-b-2 ${
                  isActive
                    ? 'border-blue-500 text-blue-400 bg-slate-900 font-semibold'
                    : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/40'
                }`}
                style={{ marginBottom: -1 }}
              >
                <Icon size={14} />
                {label}
              </button>
            );
          })}
        </div>

        {selectedAlert && (
          <div className="flex items-center gap-2 text-xs font-mono text-slate-400 pb-1">
            <span className="text-slate-500">Active Investigation:</span>
            <span className="text-blue-400 font-semibold">{selectedAlert.alert_id}</span>
            <span className="text-slate-600">•</span>
            <span className="text-slate-300 font-semibold">{selectedAlert.attack_label || selectedAlert.protocol}</span>
          </div>
        )}
      </div>

      {/* Main Content Area */}
      <main className="flex-1 flex flex-col gap-3 p-4 overflow-hidden min-h-0 bg-slate-950">
        {activeTab === 'core' ? (
          <>
            {/* Row 1: KPI Metrics */}
            <MetricCards metrics={metrics} connected={connected} />

            {/* Row 2: Ingestion & Filter Pipeline */}
            <PipelineView metrics={metrics} />

            {/* Row 3: Live Feed + Threat Curve + Incident Queue */}
            <div className="flex gap-3 flex-1 min-h-0">
              {/* Left: Terminal stream (28%) */}
              <div className="w-[30%] min-h-0">
                <TerminalFeed logs={logs} />
              </div>
              {/* Center: Threat velocity chart (flex-1) */}
              <div className="flex-1 min-h-0">
                <ThreatChart timeline={timeline} />
              </div>
              {/* Right: Incident queue (28%) */}
              <div className="w-[30%] min-h-0">
                <AlertPanel
                  alerts={alerts}
                  connected={connected}
                  lastCritical={lastCritical}
                  onSelectAlert={handleSelectAlert}
                />
              </div>
            </div>
          </>
        ) : (
          <>
            {/* Research & Investigation Tab */}
            <MetricCards metrics={metrics} connected={connected} />

            <div className="flex gap-3 flex-1 min-h-0">
              {/* Kill Chain Attack Graph (45%) */}
              <div className="w-[45%] min-h-0">
                <KillChainGraph alert={selectedAlert} />
              </div>
              {/* XAI Narrative & Containment Playbook (32%) */}
              <div className="w-[32%] min-h-0">
                <XaiAlertPanel alert={selectedAlert} />
              </div>
              {/* Telemetry Visibility Radar (23%) */}
              <div className="flex-1 min-h-0">
                <MitreRadar />
              </div>
            </div>
          </>
        )}
      </main>

      {/* Enterprise Status Footer */}
      <footer className="shrink-0 px-6 py-2 bg-slate-900 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
        <div className="flex items-center gap-4 text-[11px] font-mono">
          <span className="flex items-center gap-1.5 text-slate-400">
            <span className="w-1.5 h-1.5 rounded-full bg-blue-500" />
            PIPELINE: 4-STAGE HEURISTIC + FEATURE ANOMALY ENGINE
          </span>
          <span className="text-slate-600">|</span>
          <span className="text-slate-400">
            DATA INTAKE: STREAMING WEBSOCKET (PORT 8000)
          </span>
          <span className="text-slate-600">|</span>
          <span className="text-slate-400">
            PERSISTENCE: SQLITE ORM
          </span>
        </div>
        <div className="text-[11px] text-slate-500 font-mono">
          CSOC Enterprise Console • Department of Computer Engineering
        </div>
      </footer>
    </div>
  );
}
