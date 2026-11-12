/**
 * AlertPanel.jsx — Enterprise SOC Prioritized Incident Queue
 */
import { useState, useEffect } from 'react';
import { AlertCircle, ChevronRight, X, ExternalLink, ShieldCheck } from 'lucide-react';

const SEVERITY_CONFIG = {
  CRITICAL: { color: 'border-l-red-500', badge: 'bg-red-950/60 text-red-400 border-red-800/80', score: 'text-red-400' },
  HIGH:     { color: 'border-l-orange-500', badge: 'bg-orange-950/60 text-orange-400 border-orange-800/80', score: 'text-orange-400' },
  MEDIUM:   { color: 'border-l-amber-500', badge: 'bg-amber-950/60 text-amber-400 border-amber-800/80', score: 'text-amber-400' },
  LOW:      { color: 'border-l-emerald-500', badge: 'bg-emerald-950/60 text-emerald-400 border-emerald-800/80', score: 'text-emerald-400' },
};

function formatTs(ts) {
  return new Date(ts * 1000).toLocaleTimeString('en-US', { hour12: false });
}

function formatBytes(b) {
  if (b >= 1_000_000) return `${(b / 1_000_000).toFixed(1)} MB`;
  if (b >= 1_000) return `${(b / 1_000).toFixed(0)} KB`;
  return `${b} B`;
}

function AlertCard({ alert, onDismiss, onSelect }) {
  const cfg = SEVERITY_CONFIG[alert.severity] || SEVERITY_CONFIG.LOW;

  return (
    <div
      className={`bg-slate-900 border border-slate-800 border-l-4 ${cfg.color} rounded-lg p-3 mb-2 hover:border-slate-700 transition-colors shadow-sm`}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0 flex-1">
          {/* Header row: Severity + Attack Label + Timestamp */}
          <div className="flex items-center gap-2 flex-wrap mb-1.5">
            <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border ${cfg.badge}`}>
              {alert.severity}
            </span>

            {alert.attack_label && alert.attack_label !== 'DEFAULT' && (
              <span className="text-[10px] font-semibold text-slate-200 bg-slate-800 px-2 py-0.5 rounded border border-slate-700">
                {alert.attack_label}
              </span>
            )}

            <span className="text-[10px] text-slate-500 font-mono ml-auto">
              {formatTs(alert.timestamp)}
            </span>
          </div>

          {/* Flow details */}
          <div className="space-y-1 text-xs font-mono">
            <div className="flex items-center gap-1.5 text-slate-300">
              <span className="text-blue-300 font-medium">{alert.src_ip}</span>
              <span className="text-slate-600">→</span>
              <span className="text-slate-300">{alert.dst_ip}:{alert.dst_port}</span>
            </div>

            <div className="flex items-center gap-3 text-[11px] text-slate-400">
              <span>Proto: <strong className="text-slate-300">{alert.protocol}</strong></span>
              <span>Payload: <strong className="text-slate-300">{formatBytes(alert.bytes_sent)}</strong></span>
            </div>
          </div>
        </div>

        {/* Threat score pill */}
        <div className="shrink-0 flex flex-col items-center justify-center p-2 rounded-lg bg-slate-950 border border-slate-800 min-w-[50px]">
          <span className={`text-base font-bold font-mono ${cfg.score}`}>
            {Math.round(alert.threat_score ?? 0)}
          </span>
          <span className="text-[9px] text-slate-500 uppercase font-mono">Score</span>
        </div>
      </div>

      {/* Footer: ID + Investigate button */}
      <div className="mt-2.5 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] font-mono text-slate-500">
        <span>{alert.alert_id}</span>

        <div className="flex items-center gap-2">
          {onSelect && (
            <button
              onClick={() => onSelect(alert)}
              className="flex items-center gap-1 text-[11px] font-medium text-blue-400 hover:text-blue-300 bg-blue-950/40 hover:bg-blue-900/60 border border-blue-800/80 px-2 py-1 rounded transition-colors"
            >
              <span>Investigate</span>
              <ChevronRight size={12} />
            </button>
          )}

          <button
            onClick={() => onDismiss(alert.alert_id)}
            title="Acknowledge alert"
            className="text-slate-500 hover:text-slate-300 p-1 rounded hover:bg-slate-800 transition-colors"
          >
            <X size={12} />
          </button>
        </div>
      </div>
    </div>
  );
}

export function AlertPanel({ alerts, connected, lastCritical, onSelectAlert }) {
  const [dismissed, setDismissed] = useState(new Set());
  const [showNotification, setShowNotification] = useState(false);

  useEffect(() => {
    if (lastCritical) {
      setShowNotification(true);
      const t = setTimeout(() => setShowNotification(false), 4500);
      return () => clearTimeout(t);
    }
  }, [lastCritical]);

  const visible = alerts.filter(a => !dismissed.has(a.alert_id));

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg flex flex-col h-full overflow-hidden shadow-sm">
      {/* Header */}
      <div className="flex items-center justify-between px-3.5 py-2.5 border-b border-slate-800 bg-slate-900 shrink-0">
        <div className="flex items-center gap-2">
          <AlertCircle size={15} className="text-orange-400" />
          <span className="text-xs font-semibold text-slate-200">
            Incident Triage Queue
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
            {visible.length} active
          </span>
        </div>
      </div>

      {/* Critical Toast Banner */}
      {showNotification && lastCritical && (
        <div className="mx-3 mt-2 p-2.5 rounded-lg bg-red-950/60 border border-red-800/80 text-xs text-red-300 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2 min-w-0">
            <span className="font-bold text-red-400 shrink-0">CRITICAL INCIDENT</span>
            <span className="text-slate-300 truncate">
              {lastCritical.attack_label || 'Anomalous traffic'} from {lastCritical.src_ip}
            </span>
          </div>
          <button
            onClick={() => onSelectAlert && onSelectAlert(lastCritical)}
            className="text-[11px] font-medium text-white bg-red-600 hover:bg-red-500 px-2 py-0.5 rounded ml-2 shrink-0 transition-colors"
          >
            Review
          </button>
        </div>
      )}

      {/* Alerts list */}
      <div className="flex-1 overflow-y-auto p-3 min-h-0 bg-slate-950">
        {visible.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-slate-500 text-xs">
            <ShieldCheck size={28} className="text-emerald-500/60 mb-2" />
            <p className="font-medium text-slate-400">All incidents triaged</p>
            <p className="text-[11px] text-slate-500 mt-0.5">Monitoring incoming NetFlow stream...</p>
          </div>
        ) : (
          visible.map((alert, idx) => (
            <AlertCard
              key={`${alert.alert_id}-${idx}`}
              alert={alert}
              onDismiss={(id) => setDismissed(p => new Set([...p, id]))}
              onSelect={onSelectAlert}
            />
          ))
        )}
      </div>
    </div>
  );
}
