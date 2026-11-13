import { useState } from 'react';
import { AlertTriangle, ChevronRight, X, ShieldAlert, CheckCircle } from 'lucide-react';

const SEVERITY_CONFIG = {
  CRITICAL: {
    border: 'border-l-red-500',
    badge: 'bg-red-50 text-red-700 border-red-200',
    score: 'text-red-600',
  },
  HIGH: {
    border: 'border-l-orange-500',
    badge: 'bg-orange-50 text-orange-700 border-orange-200',
    score: 'text-orange-600',
  },
  MEDIUM: {
    border: 'border-l-amber-500',
    badge: 'bg-amber-50 text-amber-700 border-amber-200',
    score: 'text-amber-600',
  },
  LOW: {
    border: 'border-l-emerald-500',
    badge: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    score: 'text-emerald-600',
  },
};

function formatTs(ts) {
  if (!ts) return '';
  return new Date(ts * 1000).toLocaleTimeString('en-US', { hour12: false });
}

function formatBytes(b) {
  if (!b) return '0 B';
  if (b >= 1_000_000) return `${(b / 1_000_000).toFixed(1)} MB`;
  if (b >= 1_000) return `${(b / 1_000).toFixed(0)} KB`;
  return `${b} B`;
}

function AlertCard({ alert, onDismiss, onSelect, isSelected }) {
  const cfg = SEVERITY_CONFIG[alert.severity] || SEVERITY_CONFIG.LOW;

  return (
    <div
      onClick={() => onSelect && onSelect(alert)}
      className={`cursor-pointer bg-white border rounded-xl p-3.5 mb-2.5 transition-all shadow-xs border-l-4 ${cfg.border} ${
        isSelected ? 'ring-2 ring-blue-500 bg-blue-50/20' : 'hover:border-slate-300'
      }`}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0 flex-1">
          {/* Header row: Severity + Attack label + Timestamp */}
          <div className="flex items-center gap-2 flex-wrap mb-1">
            <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${cfg.badge}`}>
              {alert.severity}
            </span>

            {alert.attack_label && alert.attack_label !== 'DEFAULT' && (
              <span className="text-[11px] font-semibold text-slate-800 bg-slate-100 px-2 py-0.5 rounded border border-slate-200">
                {alert.attack_label}
              </span>
            )}

            <span className="text-[11px] text-slate-400 font-mono ml-auto">
              {formatTs(alert.timestamp)}
            </span>
          </div>

          {/* Flow details */}
          <div className="space-y-0.5 text-xs font-mono mt-1.5">
            <div className="flex items-center gap-1.5 text-slate-700">
              <span className="font-semibold text-blue-700">{alert.src_ip}</span>
              <span className="text-slate-400">→</span>
              <span className="text-slate-800">{alert.dst_ip}:{alert.dst_port}</span>
            </div>

            <div className="flex items-center gap-3 text-[11px] text-slate-500">
              <span>Proto: <strong className="text-slate-700 font-sans">{alert.protocol}</strong></span>
              <span>Payload: <strong className="text-slate-700 font-sans">{formatBytes(alert.bytes_sent)}</strong></span>
            </div>
          </div>
        </div>

        {/* Threat score pill */}
        <div className="shrink-0 flex flex-col items-center justify-center p-2 rounded-lg bg-slate-50 border border-slate-200 min-w-[52px]">
          <span className={`text-base font-bold font-mono ${cfg.score}`}>
            {Math.round(alert.threat_score ?? 0)}
          </span>
          <span className="text-[9px] text-slate-400 uppercase font-sans font-semibold">Score</span>
        </div>
      </div>

      {/* Footer */}
      <div className="mt-2.5 pt-2 border-t border-slate-100 flex items-center justify-between text-[11px] text-slate-500">
        <span className="font-mono text-slate-400">{alert.alert_id}</span>

        <div className="flex items-center gap-2">
          {onSelect && (
            <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-blue-600 hover:text-blue-800">
              <span>View Analysis</span>
              <ChevronRight size={13} />
            </span>
          )}

          {onDismiss && (
            <button
              onClick={(e) => {
                e.stopPropagation();
                onDismiss(alert.alert_id);
              }}
              title="Acknowledge Alert"
              className="text-slate-400 hover:text-slate-600 p-1 rounded hover:bg-slate-100"
            >
              <X size={12} />
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

export function AlertPanel({ alerts = [], connected, lastCritical, onSelectAlert, selectedAlertId }) {
  const [dismissed, setDismissed] = useState(new Set());
  const [filter, setFilter] = useState('ALL');

  const visibleAlerts = alerts
    .filter((a) => !dismissed.has(a.alert_id))
    .filter((a) => (filter === 'ALL' ? true : a.severity === filter));

  const handleDismiss = (id) => {
    setDismissed((prev) => new Set([...prev, id]));
  };

  return (
    <div className="bg-white border border-slate-200 rounded-xl shadow-sm flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="p-3.5 border-b border-slate-200 flex items-center justify-between bg-white shrink-0">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-orange-50 text-orange-600 border border-orange-100">
            <ShieldAlert size={16} />
          </div>
          <div>
            <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
              Flagged Threat Alerts ({visibleAlerts.length})
            </h3>
            <p className="text-[11px] text-slate-500">
              High priority network anomalies flagged by AI engine
            </p>
          </div>
        </div>

        {/* Severity filter pills */}
        <div className="inline-flex rounded-lg border border-slate-200 p-0.5 bg-slate-50 text-[10px]">
          {['ALL', 'CRITICAL', 'HIGH'].map((lvl) => (
            <button
              key={lvl}
              onClick={() => setFilter(lvl)}
              className={`px-2 py-0.5 rounded font-semibold transition-colors ${
                filter === lvl
                  ? 'bg-white text-slate-800 shadow-xs'
                  : 'text-slate-500 hover:text-slate-800'
              }`}
            >
              {lvl}
            </button>
          ))}
        </div>
      </div>

      {/* Alert list */}
      <div className="flex-1 overflow-y-auto p-3 bg-slate-50/50">
        {visibleAlerts.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-center p-6 text-slate-400">
            <CheckCircle size={32} className="text-emerald-500 mb-2" />
            <p className="text-xs font-semibold text-slate-600">No Elevated Incidents</p>
            <p className="text-[11px] text-slate-400 mt-1 max-w-xs">
              Incoming network telemetry is currently within normal statistical thresholds.
            </p>
          </div>
        ) : (
          visibleAlerts.map((alert) => (
            <AlertCard
              key={alert.alert_id}
              alert={alert}
              onDismiss={handleDismiss}
              onSelect={onSelectAlert}
              isSelected={selectedAlertId === alert.alert_id}
            />
          ))
        )}
      </div>
    </div>
  );
}
