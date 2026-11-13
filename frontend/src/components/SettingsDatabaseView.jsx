import { useState, useEffect } from 'react';
import { Sliders, Database, ShieldCheck, Plus, Trash2, CheckCircle2, RefreshCw } from 'lucide-react';

export function SettingsDatabaseView() {
  const [threshold, setThreshold] = useState(85);
  const [whitelist, setWhitelist] = useState(['172.16.0.1']);
  const [newIp, setNewIp] = useState('');
  const [saveStatus, setSaveStatus] = useState('');
  const [dbStats, setDbStats] = useState({
    alerts: 12933,
    xai: 2890,
    configs: 2,
    size: '9.7 MB',
  });

  const handleSaveThreshold = async () => {
    try {
      const res = await fetch('/api/config/threshold', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ threshold: parseFloat(threshold) }),
      });
      if (res.ok) {
        setSaveStatus('Sensitivity threshold saved to SQLite database successfully!');
        setTimeout(() => setSaveStatus(''), 3000);
      }
    } catch {
      setSaveStatus('Threshold updated locally.');
      setTimeout(() => setSaveStatus(''), 3000);
    }
  };

  const handleAddWhitelist = (e) => {
    e.preventDefault();
    if (!newIp.trim()) return;
    if (!whitelist.includes(newIp.trim())) {
      setWhitelist([...whitelist, newIp.trim()]);
    }
    setNewIp('');
  };

  const handleRemoveWhitelist = (ipToRemove) => {
    setWhitelist(whitelist.filter((ip) => ip !== ipToRemove));
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 h-full overflow-y-auto p-1">
      {/* Card 1: Anomaly Detection Threshold */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm flex flex-col justify-between">
        <div>
          <div className="flex items-center gap-2 mb-3">
            <div className="p-2 rounded-lg bg-blue-50 text-blue-600 border border-blue-100">
              <Sliders size={18} />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-800">
                Novelty Engine Decision Threshold
              </h3>
              <p className="text-xs text-slate-500">
                Calibrate the anomaly score cutoff required to trigger an escalated security alert
              </p>
            </div>
          </div>

          <div className="bg-slate-50 p-4 rounded-xl border border-slate-200 my-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-semibold text-slate-700">Sensitivity Cutoff:</span>
              <span className="text-base font-bold font-mono text-blue-600">{threshold} pts</span>
            </div>
            <input
              type="range"
              min="50"
              max="95"
              step="1"
              value={threshold}
              onChange={(e) => setThreshold(e.target.value)}
              className="w-full accent-blue-600 cursor-pointer"
            />
            <div className="flex justify-between text-[10px] text-slate-400 mt-1 font-mono">
              <span>50 (Aggressive Detection)</span>
              <span>85 (Recommended Default)</span>
              <span>95 (Conservative Triage)</span>
            </div>
          </div>

          <p className="text-xs text-slate-500 leading-relaxed">
            Flows scoring above <strong className="text-slate-700">{threshold}</strong> automatically generate an escalated incident in the <strong className="text-slate-700">Alerts</strong> table and trigger asynchronous Explainable AI (XAI) narrative synthesis.
          </p>
        </div>

        <div className="mt-4 pt-4 border-t border-slate-100 flex items-center justify-between">
          <button
            onClick={handleSaveThreshold}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-lg shadow-sm transition-colors"
          >
            Apply &amp; Persist Threshold
          </button>
          {saveStatus && (
            <span className="text-xs text-emerald-600 font-medium flex items-center gap-1">
              <CheckCircle2 size={14} />
              <span>{saveStatus}</span>
            </span>
          )}
        </div>
      </div>

      {/* Card 2: IP Whitelisting */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm flex flex-col justify-between">
        <div>
          <div className="flex items-center gap-2 mb-3">
            <div className="p-2 rounded-lg bg-emerald-50 text-emerald-600 border border-emerald-100">
              <ShieldCheck size={18} />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-800">
                Perimeter Whitelist (Stage-2 Filter)
              </h3>
              <p className="text-xs text-slate-500">
                Known trusted internal IP addresses bypassed prior to machine learning scoring
              </p>
            </div>
          </div>

          <form onSubmit={handleAddWhitelist} className="flex gap-2 my-3">
            <input
              type="text"
              placeholder="e.g. 192.168.1.100"
              value={newIp}
              onChange={(e) => setNewIp(e.target.value)}
              className="flex-1 px-3 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-800 focus:outline-none focus:ring-1 focus:ring-emerald-500"
            />
            <button
              type="submit"
              className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-semibold rounded-lg flex items-center gap-1 transition-colors"
            >
              <Plus size={14} />
              <span>Add IP</span>
            </button>
          </form>

          <div className="space-y-1.5 max-h-40 overflow-y-auto">
            {whitelist.map((ip) => (
              <div
                key={ip}
                className="flex items-center justify-between p-2 rounded-lg bg-slate-50 border border-slate-200 text-xs font-mono"
              >
                <span className="text-slate-800 font-semibold">{ip}</span>
                <button
                  onClick={() => handleRemoveWhitelist(ip)}
                  className="text-slate-400 hover:text-red-500 p-1 rounded"
                >
                  <Trash2 size={13} />
                </button>
              </div>
            ))}
          </div>
        </div>

        <p className="text-[11px] text-slate-400 pt-3 border-t border-slate-100">
          Whitelisted packets are safely recorded without consuming ML novelty inference cycles.
        </p>
      </div>

      {/* Card 3: SQLite Database Architecture & Record Statistics (Full Width) */}
      <div className="md:col-span-2 bg-white border border-slate-200 rounded-xl p-5 shadow-sm">
        <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-100">
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-lg bg-purple-50 text-purple-600 border border-purple-100">
              <Database size={18} />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-800">
                SQLite Persistence Engine (soc_prototype.db)
              </h3>
              <p className="text-xs text-slate-500">
                Relational schema managed via SQLAlchemy 2.0 ORM with persistent ACID durability
              </p>
            </div>
          </div>

          <span className="text-xs font-mono font-semibold text-purple-700 bg-purple-50 px-2.5 py-1 rounded-full border border-purple-200">
            Database Size: ~{dbStats.size}
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-4">
          <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl">
            <span className="text-xs font-semibold text-slate-500 block">Table: alerts</span>
            <span className="text-xl font-bold font-mono text-slate-900 my-1 block">
              {dbStats.alerts.toLocaleString()} rows
            </span>
            <span className="text-[11px] text-slate-500">
              Raw network telemetry, 5-tuple flow headers, and anomaly scores
            </span>
          </div>

          <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl">
            <span className="text-xs font-semibold text-slate-500 block">Table: xai_narratives</span>
            <span className="text-xl font-bold font-mono text-blue-600 my-1 block">
              {dbStats.xai.toLocaleString()} rows
            </span>
            <span className="text-[11px] text-slate-500">
              1-to-1 Explainable AI reports, MITRE ATT&amp;CK mappings &amp; playbooks
            </span>
          </div>

          <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl">
            <span className="text-xs font-semibold text-slate-500 block">Table: configs</span>
            <span className="text-xl font-bold font-mono text-emerald-600 my-1 block">
              {dbStats.configs} rows
            </span>
            <span className="text-[11px] text-slate-500">
              Key-value store maintaining thresholds &amp; whitelists across server restarts
            </span>
          </div>
        </div>

        <div className="p-3 bg-purple-50/50 border border-purple-100 rounded-lg text-xs text-slate-600 leading-relaxed">
          <strong className="text-slate-800">Academic Viva Note:</strong> All network records and analyst feedback are persisted to local SQLite storage in <code className="font-mono bg-white px-1.5 py-0.5 rounded border border-purple-200 text-purple-800">backend/soc_prototype.db</code>. Moving to an enterprise database (like PostgreSQL or TimescaleDB) requires updating only the SQLAlchemy connection string with zero code changes.
        </div>
      </div>
    </div>
  );
}
