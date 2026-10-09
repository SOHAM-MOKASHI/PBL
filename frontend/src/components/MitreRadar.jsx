/**
 * MitreRadar.jsx — Telemetry coverage HUD with Blind Spot Index
 * Compact card showing which data sources are active/missing.
 */
import { useState, useEffect } from 'react';
import { Eye, EyeOff, AlertTriangle, Wifi, Activity } from 'lucide-react';

const TELEMETRY_API = 'http://localhost:8000/api/telemetry';

function CoverageRow({ name, coverage, active }) {
  const color = active ? (coverage >= 85 ? '#00ff88' : '#ffd700') : '#3d5a80';
  const shortName = name.length > 28 ? name.slice(0, 27) + '…' : name;

  return (
    <div className="flex items-center gap-2 py-1">
      <div className="shrink-0">
        {active
          ? <Eye size={10} style={{ color: '#00ff88' }} />
          : <EyeOff size={10} style={{ color: '#3d5a80' }} />}
      </div>
      <span className="flex-1 text-[10px] font-mono truncate" style={{ color: active ? '#94a3b8' : '#475569' }}>
        {shortName}
      </span>
      <div className="w-20 h-1 rounded-full shrink-0" style={{ background: 'rgba(26,39,68,0.8)' }}>
        <div
          className="h-full rounded-full transition-all duration-700"
          style={{
            width: `${coverage}%`,
            background: active
              ? `linear-gradient(90deg, ${color}80, ${color})`
              : 'rgba(61,90,128,0.3)',
          }}
        />
      </div>
      <span className="text-[9px] font-mono w-7 text-right shrink-0" style={{ color }}>
        {coverage}%
      </span>
    </div>
  );
}

function BlindSpotGauge({ index }) {
  const pct = Math.round(index * 100);
  const color = pct >= 60 ? '#ff2d55' : pct >= 30 ? '#ff6b35' : '#ffd700';
  const circumference = 2 * Math.PI * 28;
  const dash = (pct / 100) * circumference;

  return (
    <div className="flex flex-col items-center">
      <div className="relative w-20 h-20">
        <svg viewBox="0 0 64 64" className="w-full h-full -rotate-90">
          <circle cx="32" cy="32" r="28" fill="none" stroke="rgba(26,39,68,0.8)" strokeWidth="6" />
          <circle
            cx="32" cy="32" r="28" fill="none"
            stroke={color} strokeWidth="6"
            strokeDasharray={`${dash} ${circumference}`}
            strokeLinecap="round"
            style={{ transition: 'stroke-dasharray 1s ease', filter: `drop-shadow(0 0 4px ${color})` }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-lg font-black font-mono" style={{ color }}>{pct}%</span>
        </div>
      </div>
      <span className="text-[9px] text-slate-600 font-mono uppercase tracking-widest mt-1">Blind Spot</span>
    </div>
  );
}

export function MitreRadar() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchTelemetry = async () => {
    try {
      const res = await fetch(TELEMETRY_API);
      const json = await res.json();
      setData(json);
    } catch {
      // Backend may not be ready yet
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTelemetry();
    const t = setInterval(fetchTelemetry, 30_000); // refresh every 30s
    return () => clearInterval(t);
  }, []);

  const mockData = {
    sources: [
      { name: 'Network Flows (NetFlow/IPFIX)', coverage: 100, active: true },
      { name: 'DNS Query Logs', coverage: 100, active: true },
      { name: 'HTTP/TLS Proxy Logs', coverage: 85, active: true },
      { name: 'Endpoint Process Execution', coverage: 0, active: false },
      { name: 'Windows Event Logs (SIEM)', coverage: 0, active: false },
      { name: 'Cloud Trail / API Logs', coverage: 0, active: false },
      { name: 'Email Gateway Logs', coverage: 0, active: false },
      { name: 'Identity Provider (IdP) Logs', coverage: 0, active: false },
    ],
    blind_spot_index: 0.63,
    blind_spot_pct: 63,
    active_sources: 3,
    total_sources: 8,
    missing_sources: 5,
    risk_note: 'HOST/PROCESS TELEMETRY ABSENT — lateral movement and fileless attacks cannot be detected.',
  };

  const d = data ?? mockData;

  return (
    <div className="panel flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-cyber-border shrink-0">
        <div className="flex items-center gap-2">
          <Activity size={13} className="text-yellow-400" />
          <span className="text-xs font-semibold text-slate-300 uppercase tracking-wide">Telemetry Coverage</span>
        </div>
        <span className="text-[9px] font-mono text-slate-600">
          {d.active_sources}/{d.total_sources} active
        </span>
      </div>

      <div className="flex-1 overflow-y-auto p-3 min-h-0">

        {/* Gauge + summary */}
        <div className="flex items-center gap-4 mb-3 p-3 rounded-lg border"
          style={{
            background: 'rgba(255,45,85,0.05)',
            borderColor: 'rgba(255,45,85,0.2)',
          }}
        >
          <BlindSpotGauge index={d.blind_spot_index} />
          <div className="flex-1 min-w-0">
            <div className="text-[10px] font-bold text-red-400 font-mono uppercase tracking-wide mb-1.5 flex items-center gap-1">
              <AlertTriangle size={9} /> Coverage Warning
            </div>
            <p className="text-[10px] text-slate-400 leading-relaxed">{d.risk_note}</p>
            <div className="flex gap-3 mt-2">
              <div className="text-center">
                <div className="text-sm font-black text-green-400 font-mono">{d.active_sources}</div>
                <div className="text-[8px] text-slate-600 uppercase">Active</div>
              </div>
              <div className="text-center">
                <div className="text-sm font-black text-red-400 font-mono">{d.missing_sources}</div>
                <div className="text-[8px] text-slate-600 uppercase">Missing</div>
              </div>
            </div>
          </div>
        </div>

        {/* Coverage rows */}
        <div className="space-y-0.5">
          <div className="text-[9px] text-slate-600 font-mono uppercase tracking-widest mb-2">
            Data Source Coverage
          </div>
          {d.sources.map((src) => (
            <CoverageRow key={src.name} {...src} />
          ))}
        </div>

        {/* Missing coverage warning chips */}
        <div className="mt-3 pt-3 border-t border-cyber-border">
          <div className="text-[9px] text-slate-600 font-mono uppercase tracking-widest mb-2">
            Undetectable Attack Techniques
          </div>
          <div className="flex flex-wrap gap-1.5">
            {['Fileless Malware', 'Living-off-the-Land', 'Lateral Movement', 'Memory Injection', 'Insider Threat'].map(t => (
              <span
                key={t}
                className="text-[9px] font-mono px-2 py-0.5 rounded border"
                style={{
                  background: 'rgba(255,45,85,0.08)',
                  color: '#ff2d55',
                  borderColor: 'rgba(255,45,85,0.2)',
                }}
              >
                {t}
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
