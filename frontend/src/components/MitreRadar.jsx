/**
 * MitreRadar.jsx — Enterprise SOC Visibility & Telemetry Coverage Audit
 */
import { useState, useEffect } from 'react';
import { Eye, EyeOff, AlertTriangle, ShieldCheck, Activity } from 'lucide-react';

const TELEMETRY_API = typeof window !== 'undefined' && window.location.port === '5173'
  ? `http://${window.location.hostname}:8000/api/telemetry`
  : '/api/telemetry';

function CoverageRow({ name, coverage, active }) {
  const shortName = name.length > 28 ? name.slice(0, 27) + '…' : name;

  return (
    <div className="flex items-center gap-2 py-1.5 border-b border-slate-900/80 text-xs">
      <div className="shrink-0">
        {active ? (
          <span className="w-2 h-2 rounded-full bg-emerald-400 inline-block" />
        ) : (
          <span className="w-2 h-2 rounded-full bg-slate-600 inline-block" />
        )}
      </div>

      <span className={`flex-1 truncate font-mono text-[11px] ${active ? 'text-slate-300' : 'text-slate-500'}`}>
        {shortName}
      </span>

      <div className="w-16 h-1 rounded-full bg-slate-800 shrink-0 overflow-hidden">
        <div
          className={`h-full ${active ? (coverage >= 80 ? 'bg-emerald-500' : 'bg-amber-500') : 'bg-slate-700'}`}
          style={{ width: `${coverage}%` }}
        />
      </div>

      <span className={`text-[10px] font-mono w-7 text-right shrink-0 ${active ? 'text-slate-300 font-semibold' : 'text-slate-600'}`}>
        {coverage}%
      </span>
    </div>
  );
}

function BlindSpotGauge({ index }) {
  const pct = Math.round(index * 100);
  const color = pct >= 60 ? '#ef4444' : pct >= 30 ? '#f97316' : '#10b981';
  const circumference = 2 * Math.PI * 26;
  const dash = (pct / 100) * circumference;

  return (
    <div className="flex flex-col items-center">
      <div className="relative w-16 h-16">
        <svg viewBox="0 0 64 64" className="w-full h-full -rotate-90">
          <circle cx="32" cy="32" r="26" fill="none" stroke="#1e293b" strokeWidth="5" />
          <circle
            cx="32" cy="32" r="26" fill="none"
            stroke={color} strokeWidth="5"
            strokeDasharray={`${dash} ${circumference}`}
            strokeLinecap="round"
            className="transition-all duration-700"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-sm font-bold font-mono text-slate-100">{pct}%</span>
        </div>
      </div>
      <span className="text-[10px] text-slate-400 font-mono mt-1">Blind Spot</span>
    </div>
  );
}

export function MitreRadar() {
  const [data, setData] = useState(null);

  const fetchTelemetry = async () => {
    try {
      const res = await fetch(TELEMETRY_API);
      const json = await res.json();
      setData(json);
    } catch {
      // Backend fallback
    }
  };

  useEffect(() => {
    fetchTelemetry();
    const t = setInterval(fetchTelemetry, 30_000);
    return () => clearInterval(t);
  }, []);

  const fallback = {
    sources: [
      { name: 'Network Flows (NetFlow/IPFIX)', coverage: 100, active: true },
      { name: 'DNS Query Logs', coverage: 100, active: true },
      { name: 'HTTP/TLS Proxy Logs', coverage: 85, active: true },
      { name: 'Endpoint Process Execution (EDR)', coverage: 0, active: false },
      { name: 'Windows Event Logs (SIEM)', coverage: 0, active: false },
      { name: 'Cloud Trail / API Logs', coverage: 0, active: false },
      { name: 'Email Gateway Logs', coverage: 0, active: false },
      { name: 'Identity Provider (IdP) Logs', coverage: 0, active: false },
    ],
    blind_spot_index: 0.63,
    active_sources: 3,
    total_sources: 8,
    missing_sources: 5,
    risk_note: 'Host endpoint and identity telemetry absent. Lateral movement and memory-resident malware cannot be observed from network flows alone.',
  };

  const d = data ?? fallback;

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg flex flex-col h-full overflow-hidden shadow-sm">
      {/* Header */}
      <div className="px-3.5 py-2.5 border-b border-slate-800 flex items-center justify-between shrink-0 bg-slate-900">
        <div className="flex items-center gap-2">
          <Activity size={14} className="text-blue-400" />
          <span className="text-xs font-semibold text-slate-200">
            Telemetry Visibility Audit
          </span>
        </div>
        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
          {d.active_sources} / {d.total_sources} Feeds Active
        </span>
      </div>

      <div className="flex-1 overflow-y-auto p-3.5 min-h-0 bg-slate-950 space-y-3">
        {/* Blind Spot Gauge & Audit Warning */}
        <div className="p-3 rounded-lg border border-slate-800 bg-slate-900 flex items-center gap-3.5">
          <BlindSpotGauge index={d.blind_spot_index} />
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-1.5 text-[11px] font-semibold text-amber-400 mb-1">
              <AlertTriangle size={13} />
              <span>Visibility Gap Warning</span>
            </div>
            <p className="text-[11px] text-slate-400 leading-snug">
              {d.risk_note}
            </p>
          </div>
        </div>

        {/* Telemetry Sources List */}
        <div>
          <label className="text-[11px] font-semibold text-slate-400 uppercase tracking-wide block mb-1">
            Data Source Ingestion Status
          </label>
          <div className="divide-y divide-slate-900">
            {d.sources.map((src) => (
              <CoverageRow key={src.name} {...src} />
            ))}
          </div>
        </div>

        {/* Blind Spot Warning Chips */}
        <div className="pt-2 border-t border-slate-800">
          <label className="text-[11px] font-semibold text-slate-400 uppercase tracking-wide block mb-1.5">
            Undetectable Technique Vulnerabilities
          </label>
          <div className="flex flex-wrap gap-1.5">
            {['Fileless Malware', 'Living-off-the-Land (LotL)', 'Host Memory Injection', 'Credential Dumping'].map((item) => (
              <span
                key={item}
                className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-950/40 border border-red-800/60 text-red-300"
              >
                {item}
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
