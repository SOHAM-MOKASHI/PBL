/**
 * TerminalFeed.jsx — Component 1: Real-time scrolling log terminal
 */
import { useRef, useEffect, useState } from 'react';
import { Terminal } from 'lucide-react';

const SEVERITY_COLORS = {
  CRITICAL: '#ff2d55',
  HIGH: '#ff6b35',
  MEDIUM: '#ffd700',
  LOW: '#00ff88',
  NORMAL: '#4a7a9b',
};

const TRAFFIC_COLORS = {
  ATTACK: '#ff2d55',
  SUSPICIOUS: '#ff6b35',
  NORMAL: '#3d5a80',
};

function formatBytes(b) {
  if (b >= 1_000_000) return `${(b / 1_000_000).toFixed(1)}MB`;
  if (b >= 1_000) return `${(b / 1_000).toFixed(1)}KB`;
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

function LogRow({ log, isNew }) {
  const severity = log.severity || 'LOW';
  const trafficType = log.traffic_type || 'NORMAL';
  const color = SEVERITY_COLORS[severity];
  const typeColor = TRAFFIC_COLORS[trafficType] || '#3d5a80';

  return (
    <div
      className={`flex items-start gap-2 py-1 px-2 rounded text-xs font-mono border-l-2 transition-all duration-300 ${
        isNew ? 'animate-slide-in bg-opacity-10' : ''
      }`}
      style={{
        borderLeftColor: color,
        backgroundColor: isNew ? `${color}08` : 'transparent',
      }}
    >
      {/* Timestamp */}
      <span className="text-slate-600 shrink-0 w-16">{formatTs(log.timestamp)}</span>

      {/* Stage badge */}
      <span
        className="shrink-0 text-[9px] px-1 rounded border font-bold"
        style={{ color: '#00d4ff', borderColor: 'rgba(0,212,255,0.3)', background: 'rgba(0,212,255,0.08)' }}
      >
        S{log.stage}
      </span>

      {/* Severity */}
      <span
        className="shrink-0 text-[10px] font-bold w-12"
        style={{ color }}
      >
        {severity}
      </span>

      {/* IPs */}
      <span className="shrink-0">
        <span className="ip-chip">{log.src_ip}</span>
        <span className="text-slate-600 mx-1">→</span>
        <span className="ip-chip">{log.dst_ip}</span>
      </span>

      {/* Port/Proto */}
      <span className="text-slate-500 shrink-0">
        :{log.dst_port}
        <span className="ml-1 text-slate-600">[{log.protocol}]</span>
      </span>

      {/* Bytes */}
      <span className="text-slate-500 shrink-0">
        ↑{formatBytes(log.bytes_sent)} ↓{formatBytes(log.bytes_recv)}
      </span>

      {/* Score */}
      <span
        className="shrink-0 font-bold text-[10px]"
        style={{ color }}
      >
        {log.threat_score?.toFixed(0) ?? '–'}pts
      </span>

      {/* Attack label */}
      {log.attack_label && (
        <span
          className="shrink-0 text-[9px] px-1.5 py-0.5 rounded font-bold"
          style={{ background: `${color}20`, color, border: `1px solid ${color}40` }}
        >
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
    <div className="panel flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-cyber-border shrink-0">
        <div className="flex items-center gap-2">
          <Terminal size={14} className="text-cyan-400" />
          <span className="text-xs font-semibold text-slate-300 tracking-wide uppercase">
            Live Traffic Feed
          </span>
          <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse inline-block" />
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-slate-600 font-mono">{logs.length} entries</span>
          <button
            onClick={() => setAutoScroll(!autoScroll)}
            className="text-xs px-2 py-0.5 rounded border transition-colors"
            style={{
              borderColor: autoScroll ? 'rgba(0,212,255,0.4)' : '#1a2744',
              color: autoScroll ? '#00d4ff' : '#3d5a80',
              background: autoScroll ? 'rgba(0,212,255,0.08)' : 'transparent',
            }}
          >
            {autoScroll ? '⏩ AUTO' : '⏸ PAUSED'}
          </button>
        </div>
      </div>

      {/* Column headers */}
      <div className="flex items-center gap-2 px-2 py-1 border-b border-cyber-border/50 text-[9px] text-slate-600 uppercase tracking-widest font-mono shrink-0">
        <span className="w-16">TIME</span>
        <span className="w-6">STG</span>
        <span className="w-12">SEV</span>
        <span className="flex-1">SRC → DST</span>
        <span>PORT</span>
        <span className="ml-auto">SCORE</span>
      </div>

      {/* Log rows */}
      <div
        ref={containerRef}
        onScroll={handleScroll}
        className="terminal-feed flex-1 overflow-y-auto py-1 space-y-0.5 min-h-0"
      >
        {logs.length === 0 ? (
          <div className="flex items-center justify-center h-full">
            <div className="text-center">
              <div className="text-slate-600 text-xs font-mono animate-pulse">
                ▮ Waiting for traffic stream...
              </div>
            </div>
          </div>
        ) : (
          logs.map((log, i) => (
            <LogRow key={`${log.alert_id}-${i}`} log={log} isNew={i === 0} />
          ))
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
