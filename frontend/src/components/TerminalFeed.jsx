/**
 * TerminalFeed.jsx — Enterprise Real-Time Network Telemetry Stream
 */
import { useRef, useEffect, useState } from 'react';
import { Terminal, Pause, Play } from 'lucide-react';

const SEVERITY_CONFIG = {
  CRITICAL: { color: '#ef4444', text: 'text-red-400', bg: 'bg-red-950/40 border-red-800/80' },
  HIGH:     { color: '#f97316', text: 'text-orange-400', bg: 'bg-orange-950/40 border-orange-800/80' },
  MEDIUM:   { color: '#f59e0b', text: 'text-amber-400', bg: 'bg-amber-950/40 border-amber-800/80' },
  LOW:      { color: '#10b981', text: 'text-emerald-400', bg: 'bg-emerald-950/40 border-emerald-800/80' },
  NORMAL:   { color: '#64748b', text: 'text-slate-400', bg: 'bg-slate-900 border-slate-800' },
};

function formatBytes(b) {
  if (b >= 1_000_000) return `${(b / 1_000_000).toFixed(1)}MB`;
  if (b >= 1_000) return `${(b / 1_000).toFixed(0)}KB`;
  return `${b}B`;
}

function formatTs(ts) {
  return new Date(ts * 1000).toLocaleTimeString('en-US', {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function LogRow({ log }) {
  const severity = log.severity || 'LOW';
  const cfg = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.NORMAL;

  return (
    <div className="flex items-center gap-2 py-1 px-2 rounded hover:bg-slate-800/60 transition-colors text-[11px] font-mono border-b border-slate-900/60">
      {/* Timestamp */}
      <span className="text-slate-500 shrink-0 w-14">{formatTs(log.timestamp)}</span>

      {/* Stage */}
      <span className="shrink-0 text-[10px] px-1 py-0.2 rounded bg-slate-800 text-slate-400 border border-slate-700">
        S{log.stage}
      </span>

      {/* Severity Badge */}
      <span className={`shrink-0 text-[10px] font-semibold px-1.5 py-0.2 rounded border ${cfg.bg} ${cfg.text} w-16 text-center`}>
        {severity}
      </span>

      {/* IPs */}
      <span className="shrink-0 flex items-center gap-1 text-slate-300">
        <span className="text-blue-300">{log.src_ip}</span>
        <span className="text-slate-600">→</span>
        <span className="text-slate-300">{log.dst_ip}</span>
      </span>

      {/* Port & Protocol */}
      <span className="text-slate-500 shrink-0">
        :{log.dst_port}
        <span className="ml-1 text-slate-400 text-[10px]">[{log.protocol}]</span>
      </span>

      {/* Bytes Sent / Received */}
      <span className="text-slate-500 shrink-0 ml-auto text-[10px]">
        ↑{formatBytes(log.bytes_sent)}
      </span>

      {/* Score */}
      <span className={`shrink-0 font-bold text-[11px] w-12 text-right ${cfg.text}`}>
        {Math.round(log.threat_score ?? 0)} pts
      </span>

      {/* Attack Label Pill */}
      {log.attack_label && log.attack_label !== 'DEFAULT' && (
        <span className={`shrink-0 text-[10px] px-1.5 py-0.2 rounded border font-semibold ${cfg.bg} ${cfg.text}`}>
          {log.attack_label}
        </span>
      )}
    </div>
  );
}

export function TerminalFeed({ logs }) {
  const bottomRef = useRef(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const containerRef = useRef(null);

  useEffect(() => {
    if (autoScroll && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }, [logs, autoScroll]);

  const handleScroll = () => {
    const c = containerRef.current;
    if (!c) return;
    const atBottom = c.scrollHeight - c.scrollTop - c.clientHeight < 50;
    setAutoScroll(atBottom);
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg flex flex-col h-full overflow-hidden shadow-sm">
      {/* Header */}
      <div className="flex items-center justify-between px-3.5 py-2.5 border-b border-slate-800 bg-slate-900 shrink-0">
        <div className="flex items-center gap-2">
          <Terminal size={14} className="text-blue-400" />
          <span className="text-xs font-semibold text-slate-200">
            Live Telemetry Stream
          </span>
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[11px] text-slate-400 font-mono">{logs.length} flows</span>
          <button
            onClick={() => setAutoScroll(!autoScroll)}
            className="flex items-center gap-1 text-[11px] px-2 py-0.5 rounded border border-slate-700 bg-slate-800 text-slate-300 hover:bg-slate-700 transition-colors"
          >
            {autoScroll ? (
              <>
                <Pause size={10} /> Auto
              </>
            ) : (
              <>
                <Play size={10} /> Paused
              </>
            )}
          </button>
        </div>
      </div>

      {/* Column Headers */}
      <div className="flex items-center gap-2 px-3 py-1 bg-slate-950 border-b border-slate-800 text-[10px] text-slate-500 uppercase tracking-wider font-mono shrink-0">
        <span className="w-14">TIME</span>
        <span className="w-6">STG</span>
        <span className="w-16">SEVERITY</span>
        <span className="flex-1">FLOW (SRC → DST:PORT)</span>
        <span className="ml-auto">RISK SCORE</span>
      </div>

      {/* Log Rows */}
      <div
        ref={containerRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto p-1.5 space-y-0.5 min-h-0 bg-slate-950"
      >
        {logs.length === 0 ? (
          <div className="flex items-center justify-center h-full text-slate-500 text-xs font-mono">
            Waiting for telemetry packets...
          </div>
        ) : (
          logs.map((log, i) => (
            <LogRow key={`${log.alert_id || log.timestamp}-${i}`} log={log} />
          ))
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
