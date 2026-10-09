/**
 * App.jsx — CSOC Threat Detection Dashboard
 * Main layout orchestrator
 */
import { useState, useEffect } from 'react';
import { Shield, Cpu, Globe, Radio, AlertOctagon } from 'lucide-react';
import { MetricCards } from './components/MetricCards';
import { ThreatChart } from './components/ThreatChart';
import { TerminalFeed } from './components/TerminalFeed';
import { AlertPanel } from './components/AlertPanel';
import { PipelineView } from './components/PipelineView';
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
  return <span className="font-mono text-xs text-slate-500">{h}:{m}:{s}</span>;
}

// ── Threat level indicator ────────────────────────────────────────────────
function ThreatLevelBadge({ active }) {
  const level = active > 15 ? 'CRITICAL' : active > 8 ? 'HIGH' : active > 3 ? 'ELEVATED' : 'NORMAL';
  const color = active > 15 ? '#ff2d55' : active > 8 ? '#ff6b35' : active > 3 ? '#ffd700' : '#00ff88';
  return (
    <div
      className="flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-mono font-bold"
      style={{
        background: `${color}12`,
        borderColor: `${color}40`,
        color,
        boxShadow: `0 0 15px ${color}20`,
      }}
    >
      <span
        className="w-2 h-2 rounded-full animate-pulse"
        style={{ background: color, boxShadow: `0 0 6px ${color}` }}
      />
      DEFCON: {level}
    </div>
  );
}

// ── Header ────────────────────────────────────────────────────────────────
function Header({ connected, active }) {
  const now = new Date().toLocaleString('en-US', {
    weekday: 'short', year: 'numeric', month: 'short',
    day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: false,
  });

  return (
    <header className="shrink-0 px-6 py-3 border-b border-cyber-border flex items-center justify-between hex-grid">
      {/* Logo + title */}
      <div className="flex items-center gap-4">
        <div className="relative">
          <Shield size={32} className="text-cyan-400 animate-float" style={{ filter: 'drop-shadow(0 0 8px rgba(0,212,255,0.6))' }} />
          <div className="absolute -top-1 -right-1 w-3 h-3 bg-red-500 rounded-full animate-pulse-fast border border-cyber-bg" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-lg font-black tracking-tight text-white glow-text-accent">
              CSOC
            </h1>
            <span className="text-xs text-slate-500 font-mono">|</span>
            <span className="text-xs text-slate-400 font-semibold tracking-widest uppercase">
              Cognitive Security Operations Center
            </span>
          </div>
          <div className="flex items-center gap-3 mt-0.5">
            <span className="text-[9px] text-slate-600 font-mono">v1.0.0-alpha</span>
            <span className="text-[9px] text-slate-600 font-mono">•</span>
            <span className="text-[9px] text-slate-600 font-mono">AI THREAT DETECTION ENGINE</span>
          </div>
        </div>
      </div>

      {/* Status indicators */}
      <div className="flex items-center gap-4">
        <ThreatLevelBadge active={active} />

        <div className="text-right">
          <div className="flex items-center justify-end gap-2 mb-0.5">
            <div
              className={`w-1.5 h-1.5 rounded-full ${connected ? 'bg-green-400 animate-pulse' : 'bg-yellow-400 animate-bounce'}`}
            />
            <span className={`text-[10px] font-mono font-semibold ${connected ? 'text-green-400' : 'text-yellow-400'}`}>
              {connected ? 'PIPELINE ONLINE' : 'RECONNECTING...'}
            </span>
          </div>
          <div className="flex items-center justify-end gap-2">
            <span className="text-[9px] text-slate-600 font-mono">UPTIME</span>
            <Uptime />
          </div>
        </div>
      </div>
    </header>
  );
}

// ── App ───────────────────────────────────────────────────────────────────
export default function App() {
  const { connected, logs, alerts, timeline, metrics, lastCritical } = useWebSocket();

  // Global critical screen flash
  const [screenFlash, setScreenFlash] = useState(false);
  useEffect(() => {
    if (lastCritical) {
      setScreenFlash(true);
      const t = setTimeout(() => setScreenFlash(false), 400);
      return () => clearTimeout(t);
    }
  }, [lastCritical]);

  return (
    <div className="h-screen flex flex-col overflow-hidden bg-cyber-bg noise-bg">
      {/* Scanline effect */}
      <div className="scanline-overlay" />

      {/* Critical screen flash */}
      {screenFlash && (
        <div
          className="fixed inset-0 pointer-events-none z-50"
          style={{ background: 'rgba(255,45,85,0.06)', animation: 'none' }}
        />
      )}

      {/* Header */}
      <Header connected={connected} active={metrics.active_threats} />

      {/* Main content */}
      <main className="flex-1 flex flex-col gap-3 p-4 overflow-hidden min-h-0">

        {/* Row 1: Metric cards */}
        <MetricCards metrics={metrics} connected={connected} />

        {/* Row 2: Pipeline view */}
        <PipelineView metrics={metrics} />

        {/* Row 3: Chart + Alert panel (takes remaining space) */}
        <div className="flex gap-3 flex-1 min-h-0">

          {/* Left: Terminal feed (25%) */}
          <div className="w-[28%] min-h-0">
            <TerminalFeed logs={logs} />
          </div>

          {/* Center: Threat chart (45%) */}
          <div className="flex-1 min-h-0">
            <ThreatChart timeline={timeline} />
          </div>

          {/* Right: Alert panel (27%) */}
          <div className="w-[27%] min-h-0">
            <AlertPanel
              alerts={alerts}
              connected={connected}
              lastCritical={lastCritical}
            />
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="shrink-0 px-6 py-2 border-t border-cyber-border flex items-center justify-between">
        <div className="flex items-center gap-4 text-[9px] font-mono text-slate-700">
          <span className="flex items-center gap-1">
            <Cpu size={9} className="text-cyan-800" />
            PIPELINE: 4-STAGE HEURISTIC + ML SCORING
          </span>
          <span className="flex items-center gap-1">
            <Globe size={9} className="text-cyan-800" />
            WS: ws://localhost:8000/ws/alerts
          </span>
          <span className="flex items-center gap-1">
            <Radio size={9} className="text-cyan-800" />
            PROTOCOL: REAL-TIME WEBSOCKET STREAM
          </span>
        </div>
        <div className="text-[9px] font-mono text-slate-700">
          © 2026 CSOC — COGNITIVE SECURITY OPERATIONS CENTER — HACKATHON DEMO
        </div>
      </footer>
    </div>
  );
}
