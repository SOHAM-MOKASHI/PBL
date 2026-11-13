import { useState, useRef, useEffect } from 'react';
import { Database, Search, ArrowRight, Play, Pause, Filter } from 'lucide-react';

function formatBytes(b) {
  if (!b) return '0 B';
  if (b >= 1_000_000) return `${(b / 1_000_000).toFixed(1)} MB`;
  if (b >= 1_000) return `${(b / 1_000).toFixed(0)} KB`;
  return `${b} B`;
}

function formatTs(ts) {
  if (!ts) return '';
  return new Date(ts * 1000).toLocaleTimeString('en-US', {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export function TerminalFeed({ logs = [], onSelectAlert }) {
  const [filter, setFilter] = useState('ALL'); // 'ALL' | 'ANOMALIES' | 'NORMAL'
  const [search, setSearch] = useState('');
  const [isPaused, setIsPaused] = useState(false);
  const [frozenLogs, setFrozenLogs] = useState([]);

  useEffect(() => {
    if (!isPaused) {
      setFrozenLogs(logs);
    }
  }, [logs, isPaused]);

  const activeLogs = isPaused ? frozenLogs : logs;

  const filteredLogs = activeLogs.filter((log) => {
    const isAnomaly = log.severity === 'CRITICAL' || log.severity === 'HIGH' || (log.threat_score >= 60);
    if (filter === 'ANOMALIES' && !isAnomaly) return false;
    if (filter === 'NORMAL' && isAnomaly) return false;

    if (search.trim()) {
      const q = search.toLowerCase();
      const matchIp = log.src_ip?.toLowerCase().includes(q) || log.dst_ip?.toLowerCase().includes(q);
      const matchProto = log.protocol?.toLowerCase().includes(q);
      const matchPort = String(log.dst_port).includes(q);
      const matchLabel = log.attack_label?.toLowerCase().includes(q);
      return matchIp || matchProto || matchPort || matchLabel;
    }
    return true;
  });

  return (
    <div className="bg-white border border-slate-200 rounded-xl shadow-sm flex flex-col h-full overflow-hidden">
      {/* Table Header Controls */}
      <div className="p-3.5 border-b border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-white">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-blue-50 text-blue-600 border border-blue-100">
            <Database size={16} />
          </div>
          <div>
            <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
              Live Network Traffic Telemetry Stream
            </h3>
            <p className="text-[11px] text-slate-500">
              Real-time packet inspection &amp; classification table
            </p>
          </div>
        </div>

        {/* Filters and Search */}
        <div className="flex items-center flex-wrap gap-2 text-xs">
          {/* Search box */}
          <div className="relative">
            <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              placeholder="Search IP, port, protocol..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-8 pr-3 py-1 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-700 focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
          </div>

          {/* Filter Pills */}
          <div className="inline-flex rounded-lg border border-slate-200 p-0.5 bg-slate-50">
            <button
              onClick={() => setFilter('ALL')}
              className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors ${
                filter === 'ALL' ? 'bg-white text-slate-800 shadow-xs' : 'text-slate-500 hover:text-slate-800'
              }`}
            >
              All ({activeLogs.length})
            </button>
            <button
              onClick={() => setFilter('ANOMALIES')}
              className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors ${
                filter === 'ANOMALIES' ? 'bg-red-50 text-red-700 font-semibold shadow-xs' : 'text-slate-500 hover:text-slate-800'
              }`}
            >
              Anomalies
            </button>
            <button
              onClick={() => setFilter('NORMAL')}
              className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors ${
                filter === 'NORMAL' ? 'bg-emerald-50 text-emerald-700 font-semibold shadow-xs' : 'text-slate-500 hover:text-slate-800'
              }`}
            >
              Normal
            </button>
          </div>

          {/* Pause / Resume Button */}
          <button
            onClick={() => setIsPaused(!isPaused)}
            className={`flex items-center gap-1 px-2.5 py-1 rounded-lg border text-[11px] font-medium transition-colors ${
              isPaused
                ? 'bg-amber-50 text-amber-700 border-amber-200 hover:bg-amber-100'
                : 'bg-slate-50 text-slate-600 border-slate-200 hover:bg-slate-100'
            }`}
          >
            {isPaused ? <Play size={12} /> : <Pause size={12} />}
            <span>{isPaused ? 'Resume Feed' : 'Pause'}</span>
          </button>
        </div>
      </div>

      {/* Table Container */}
      <div className="flex-1 overflow-auto">
        <table className="w-full text-left border-collapse text-xs">
          <thead className="bg-slate-50 text-slate-600 font-semibold border-b border-slate-200 sticky top-0 z-10">
            <tr>
              <th className="py-2.5 px-3">Time</th>
              <th className="py-2.5 px-3">Source IP</th>
              <th className="py-2.5 px-3">Destination : Port</th>
              <th className="py-2.5 px-3">Protocol</th>
              <th className="py-2.5 px-3">Payload</th>
              <th className="py-2.5 px-3">Threat Score</th>
              <th className="py-2.5 px-3">Detection Status</th>
              <th className="py-2.5 px-3 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 font-mono">
            {filteredLogs.length === 0 ? (
              <tr>
                <td colSpan="8" className="text-center py-8 text-slate-400 font-sans">
                  No matching log packets found
                </td>
              </tr>
            ) : (
              filteredLogs.slice(0, 100).map((log, idx) => {
                const isAnomaly = log.severity === 'CRITICAL' || log.severity === 'HIGH' || (log.threat_score >= 60);
                return (
                  <tr
                    key={log.alert_id || idx}
                    className={`hover:bg-slate-50/80 transition-colors ${
                      isAnomaly ? 'bg-red-50/20' : ''
                    }`}
                  >
                    <td className="py-2 px-3 text-slate-500 text-[11px] whitespace-nowrap">
                      {formatTs(log.timestamp)}
                    </td>
                    <td className="py-2 px-3 font-semibold text-slate-800">
                      {log.src_ip}
                    </td>
                    <td className="py-2 px-3 text-slate-600">
                      <span>{log.dst_ip}</span>
                      <span className="text-slate-400 font-normal">:{log.dst_port}</span>
                    </td>
                    <td className="py-2 px-3">
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 font-semibold border border-slate-200">
                        {log.protocol}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-slate-500 text-[11px]">
                      {formatBytes(log.bytes_sent)}
                    </td>
                    <td className="py-2 px-3">
                      <span
                        className={`font-bold ${
                          log.threat_score >= 85
                            ? 'text-red-600'
                            : log.threat_score >= 60
                            ? 'text-orange-600'
                            : 'text-slate-600'
                        }`}
                      >
                        {Math.round(log.threat_score ?? 0)} pts
                      </span>
                    </td>
                    <td className="py-2 px-3">
                      {isAnomaly ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-red-50 text-red-700 border border-red-200">
                          <span className="w-1.5 h-1.5 rounded-full bg-red-600"></span>
                          <span>ANOMALY: {log.attack_label || 'Suspicious Flow'}</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                          <span className="w-1.5 h-1.5 rounded-full bg-emerald-600"></span>
                          <span>Normal</span>
                        </span>
                      )}
                    </td>
                    <td className="py-2 px-3 text-right">
                      {isAnomaly && onSelectAlert ? (
                        <button
                          onClick={() => onSelectAlert(log)}
                          className="inline-flex items-center gap-1 px-2 py-1 text-[11px] font-semibold text-blue-600 hover:text-blue-800 bg-blue-50 hover:bg-blue-100 rounded border border-blue-200 transition-colors font-sans"
                        >
                          <span>Analyze</span>
                          <ArrowRight size={11} />
                        </button>
                      ) : (
                        <span className="text-[11px] text-slate-300 font-sans">—</span>
                      )}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
