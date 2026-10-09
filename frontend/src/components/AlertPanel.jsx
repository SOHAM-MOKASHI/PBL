/**
 * AlertPanel.jsx — Component 3: High-priority alert panel with red flash
 */
import { useState, useEffect } from 'react';
import { AlertTriangle, Wifi, WifiOff, X, ChevronRight } from 'lucide-react';

const SEVERITY_CONFIG = {
  CRITICAL: { color: '#ff2d55', bg: 'rgba(255,45,85,0.12)', label: '🔴 CRITICAL', flash: true },
  HIGH:     { color: '#ff6b35', bg: 'rgba(255,107,53,0.10)', label: '🟠 HIGH',     flash: false },
  MEDIUM:   { color: '#ffd700', bg: 'rgba(255,215,0,0.08)',  label: '🟡 MEDIUM',   flash: false },
  LOW:      { color: '#00ff88', bg: 'rgba(0,255,136,0.06)',  label: '🟢 LOW',      flash: false },
};

function formatTs(ts) {
  return new Date(ts * 1000).toLocaleTimeString('en-US', { hour12: false });
}

function formatBytes(b) {
  if (b >= 1_000_000) return `${(b / 1_000_000).toFixed(2)} MB`;
  if (b >= 1_000) return `${(b / 1_000).toFixed(1)} KB`;
  return `${b} B`;
}

function AlertCard({ alert, onDismiss }) {
  const cfg = SEVERITY_CONFIG[alert.severity] || SEVERITY_CONFIG.LOW;

  return (
    <div
      className={`rounded-lg p-3 mb-2 border transition-all duration-300 ${cfg.flash ? 'critical-flash' : ''}`}
      style={{
        background: cfg.bg,
        borderColor: `${cfg.color}33`,
      }}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-start gap-2 min-w-0">
          <AlertTriangle size={13} style={{ color: cfg.color, marginTop: 2, shrink: 0 }} />
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span
                className="text-[10px] font-bold font-mono"
                style={{ color: cfg.color }}
              >
                {cfg.label}
              </span>
              {alert.attack_label && (
                <span
                  className="text-[9px] px-1.5 py-0.5 rounded font-mono font-bold"
                  style={{
                    background: `${cfg.color}20`,
                    color: cfg.color,
                    border: `1px solid ${cfg.color}40`,
                  }}
                >
                  {alert.attack_label}
                </span>
              )}
              <span className="text-[9px] text-slate-600 font-mono ml-auto">{formatTs(alert.timestamp)}</span>
            </div>

            <div className="mt-1.5 space-y-0.5 text-[10px] font-mono">
              <div className="flex gap-1 text-slate-400">
                <span className="text-slate-600">SRC</span>
                <span style={{ color: cfg.color }}>{alert.src_ip}</span>
                <ChevronRight size={9} className="text-slate-600 mt-0.5" />
                <span className="text-slate-400">{alert.dst_ip}:{alert.dst_port}</span>
              </div>
              <div className="flex gap-3 text-slate-500">
                <span>Proto: <span className="text-slate-300">{alert.protocol}</span></span>
                <span>Out: <span className="text-slate-300">{formatBytes(alert.bytes_sent)}</span></span>
                <span>Pkts: <span className="text-slate-300">{alert.packet_count?.toLocaleString()}</span></span>
              </div>
            </div>
          </div>
        </div>

        {/* Threat score badge */}
        <div className="shrink-0 flex flex-col items-center">
          <div
            className="w-10 h-10 rounded-lg flex items-center justify-center font-bold font-mono text-sm"
            style={{
              background: `${cfg.color}20`,
              border: `1px solid ${cfg.color}50`,
              color: cfg.color,
              boxShadow: `0 0 10px ${cfg.color}30`,
            }}
          >
            {Math.round(alert.threat_score ?? 0)}
          </div>
          <span className="text-[8px] text-slate-600 mt-0.5 font-mono">SCORE</span>
        </div>
      </div>

      {/* Alert ID & Stage */}
      <div className="mt-1.5 flex items-center justify-between">
        <span className="text-[9px] text-slate-700 font-mono">{alert.alert_id}</span>
        <div className="flex gap-1">
          {[1, 2, 3, 4].map((s) => (
            <div
              key={s}
              className="w-4 h-1 rounded-full"
              style={{
                background: s <= (alert.stage ?? 4) ? cfg.color : 'rgba(61,90,128,0.3)',
                opacity: s <= (alert.stage ?? 4) ? 0.8 : 0.3,
              }}
            />
          ))}
          <span className="text-[9px] text-slate-700 font-mono ml-1">Stage {alert.stage ?? 4}</span>
        </div>
      </div>
    </div>
  );
}

export function AlertPanel({ alerts, connected, lastCritical }) {
  const [dismissed, setDismissed] = useState(new Set());
  const [criticalCount, setCriticalCount] = useState(0);
  const [showBanner, setShowBanner] = useState(false);

  useEffect(() => {
    if (lastCritical) {
      setCriticalCount(c => c + 1);
      setShowBanner(true);
      const t = setTimeout(() => setShowBanner(false), 5000);
      return () => clearTimeout(t);
    }
  }, [lastCritical]);

  const visible = alerts.filter(a => !dismissed.has(a.alert_id));

  return (
    <div className="panel flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-cyber-border shrink-0">
        <div className="flex items-center gap-2">
          <AlertTriangle size={14} className="text-red-500" />
          <span className="text-xs font-semibold text-slate-300 tracking-wide uppercase">
            Alert Panel
          </span>
          {criticalCount > 0 && (
            <span className="text-[9px] bg-red-500 text-white px-1.5 py-0.5 rounded-full font-bold font-mono animate-pulse">
              {criticalCount}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {connected ? (
            <span className="flex items-center gap-1 text-[10px] text-green-400 font-mono">
              <Wifi size={10} /> LIVE
            </span>
          ) : (
            <span className="flex items-center gap-1 text-[10px] text-yellow-400 font-mono">
              <WifiOff size={10} /> RECONNECTING
            </span>
          )}
          <span className="text-xs text-slate-600 font-mono">{visible.length} active</span>
        </div>
      </div>

      {/* Critical banner */}
      {showBanner && lastCritical && (
        <div
          className="mx-3 mt-2 px-3 py-2 rounded-lg border text-xs font-mono critical-flash shrink-0"
          style={{
            background: 'rgba(255,45,85,0.15)',
            borderColor: 'rgba(255,45,85,0.5)',
            color: '#ff2d55',
          }}
        >
          <div className="flex items-center gap-2">
            <span className="animate-pulse font-bold">⚡ CRITICAL ALERT</span>
            <span className="text-slate-400">
              {lastCritical.attack_label ?? lastCritical.protocol} detected from{' '}
              <span className="text-red-400">{lastCritical.src_ip}</span>
            </span>
            <span className="ml-auto font-bold text-red-400">
              {Math.round(lastCritical.threat_score ?? 0)} pts
            </span>
          </div>
        </div>
      )}

      {/* Alert list */}
      <div className="flex-1 overflow-y-auto p-3 min-h-0">
        {visible.length === 0 ? (
          <div className="flex items-center justify-center h-full">
            <div className="text-center">
              <div className="w-10 h-10 border-2 border-green-500/30 rounded-full flex items-center justify-center mx-auto mb-2">
                <span className="text-green-500 text-lg">✓</span>
              </div>
              <p className="text-xs text-slate-600 font-mono">No active alerts</p>
              <p className="text-xs text-slate-700 font-mono mt-1">System nominal</p>
            </div>
          </div>
        ) : (
          visible.map((alert) => (
            <AlertCard
              key={`${alert.alert_id}`}
              alert={alert}
              onDismiss={() => setDismissed(p => new Set([...p, alert.alert_id]))}
            />
          ))
        )}
      </div>
    </div>
  );
}
