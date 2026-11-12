/**
 * MetricCards.jsx — Enterprise SOC KPI Telemetry Cards
 */
import { ShieldAlert, Activity, AlertTriangle, Cpu } from 'lucide-react';
import { useEffect, useState } from 'react';

function AnimatedNumber({ value }) {
  const [displayed, setDisplayed] = useState(value);

  useEffect(() => {
    const diff = value - displayed;
    if (Math.abs(diff) < 1) { setDisplayed(value); return; }
    const step = Math.ceil(Math.abs(diff) / 6);
    const t = setTimeout(() => setDisplayed(prev => {
      const next = diff > 0 ? prev + step : prev - step;
      return diff > 0 ? Math.min(next, value) : Math.max(next, value);
    }), 20);
    return () => clearTimeout(t);
  }, [value, displayed]);

  return <span>{displayed.toLocaleString()}</span>;
}

export function MetricCards({ metrics, connected }) {
  const {
    total_ingested = 0,
    total_dropped = 0,
    total_scored = 0,
    total_alerts = 0,
    active_threats = 0,
  } = metrics;

  const filterRate = total_ingested > 0 ? Math.round((total_dropped / total_ingested) * 100) : 0;
  const alertRate = total_scored > 0 ? ((total_alerts / total_scored) * 100).toFixed(1) : '0.0';

  const cards = [
    {
      icon: Activity,
      label: 'Telemetry Ingested',
      value: total_ingested,
      sub: `${total_dropped.toLocaleString()} dropped via Stage 2 (${filterRate}% noise cut)`,
      badge: `${filterRate}% Filtered`,
      badgeColor: 'text-blue-400 bg-blue-950/60 border-blue-800/80',
      iconColor: 'text-blue-400 bg-blue-950/40 border-blue-900/60',
      progress: Math.min(total_ingested % 100, 100),
      progressBarColor: 'bg-blue-500',
    },
    {
      icon: ShieldAlert,
      label: 'Active Incident Threats',
      value: active_threats,
      sub: active_threats > 8 ? 'Elevated incident rate detected' : 'Operational threat status nominal',
      badge: active_threats > 8 ? 'High Priority' : 'Normal',
      badgeColor: active_threats > 8
        ? 'text-red-400 bg-red-950/60 border-red-800/80'
        : 'text-emerald-400 bg-emerald-950/60 border-emerald-800/80',
      iconColor: active_threats > 8
        ? 'text-red-400 bg-red-950/40 border-red-900/60'
        : 'text-emerald-400 bg-emerald-950/40 border-emerald-900/60',
      progress: Math.min(active_threats * 6, 100),
      progressBarColor: active_threats > 8 ? 'bg-red-500' : 'bg-emerald-500',
    },
    {
      icon: AlertTriangle,
      label: 'Prioritized Alerts',
      value: total_alerts,
      sub: `${alertRate}% of scored packets elevated to incident`,
      badge: `${alertRate}% Alert Ratio`,
      badgeColor: 'text-orange-400 bg-orange-950/60 border-orange-800/80',
      iconColor: 'text-orange-400 bg-orange-950/40 border-orange-900/60',
      progress: Math.min(parseFloat(alertRate) * 4, 100),
      progressBarColor: 'bg-orange-500',
    },
    {
      icon: Cpu,
      label: 'Feature Scored Flows',
      value: total_scored,
      sub: connected ? 'Real-time feature extraction active' : 'Connecting to ingestion hub...',
      badge: connected ? 'Stream Live' : 'Offline',
      badgeColor: connected
        ? 'text-emerald-400 bg-emerald-950/60 border-emerald-800/80'
        : 'text-amber-400 bg-amber-950/60 border-amber-800/80',
      iconColor: connected
        ? 'text-emerald-400 bg-emerald-950/40 border-emerald-900/60'
        : 'text-amber-400 bg-amber-950/40 border-amber-900/60',
      progress: 100,
      progressBarColor: 'bg-emerald-500',
    },
  ];

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
      {cards.map((card) => {
        const Icon = card.icon;
        return (
          <div
            key={card.label}
            className="bg-slate-900 border border-slate-800 rounded-lg p-3.5 flex flex-col justify-between hover:border-slate-700 transition-colors shadow-sm"
          >
            <div className="flex items-start justify-between">
              <div>
                <p className="text-[11px] font-medium text-slate-400 tracking-wide">
                  {card.label}
                </p>
                <p className="text-2xl font-bold font-mono text-white mt-1">
                  <AnimatedNumber value={card.value} />
                </p>
              </div>
              <div className={`p-2 rounded-lg border ${card.iconColor}`}>
                <Icon size={18} />
              </div>
            </div>

            <div className="mt-3">
              <div className="flex items-center justify-between text-[11px] mb-1.5">
                <span className="text-slate-400 truncate max-w-[70%]">
                  {card.sub}
                </span>
                <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${card.badgeColor}`}>
                  {card.badge}
                </span>
              </div>
              <div className="h-1 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className={`h-full ${card.progressBarColor} transition-all duration-500`}
                  style={{ width: `${card.progress}%` }}
                />
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
