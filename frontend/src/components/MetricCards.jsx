import { Activity, ShieldAlert, AlertTriangle, Layers } from 'lucide-react';
import { useEffect, useState } from 'react';

function AnimatedNumber({ value }) {
  const [displayed, setDisplayed] = useState(value);

  useEffect(() => {
    const diff = value - displayed;
    if (Math.abs(diff) < 1) { setDisplayed(value); return; }
    const step = Math.ceil(Math.abs(diff) / 5);
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

  const normalCount = Math.max(0, total_ingested - total_alerts);
  const filterRate = total_ingested > 0 ? Math.round((total_dropped / total_ingested) * 100) : 0;

  const cards = [
    {
      icon: Layers,
      label: 'Total Logs Analyzed',
      value: total_ingested,
      sub: `${normalCount.toLocaleString()} benign packets verified`,
      badge: connected ? 'Live Stream' : 'Disconnected',
      badgeClass: connected ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-amber-50 text-amber-700 border-amber-200',
      iconClass: 'bg-blue-50 text-blue-600 border-blue-100',
      barColor: 'bg-blue-500',
      progress: Math.min((total_ingested % 100), 100),
    },
    {
      icon: Activity,
      label: 'Stage-2 Filtered Noise',
      value: total_dropped,
      sub: `${filterRate}% benign traffic cut at perimeter`,
      badge: `${filterRate}% Cut Rate`,
      badgeClass: 'bg-slate-100 text-slate-700 border-slate-200',
      iconClass: 'bg-indigo-50 text-indigo-600 border-indigo-100',
      barColor: 'bg-indigo-500',
      progress: filterRate,
    },
    {
      icon: AlertTriangle,
      label: 'Security Alerts Flagged',
      value: total_alerts,
      sub: `${total_scored.toLocaleString()} packets scored by ML model`,
      badge: total_alerts > 0 ? 'Incidents Active' : 'Zero Incidents',
      badgeClass: total_alerts > 0 ? 'bg-orange-50 text-orange-700 border-orange-200' : 'bg-slate-100 text-slate-600 border-slate-200',
      iconClass: 'bg-orange-50 text-orange-600 border-orange-100',
      barColor: 'bg-orange-500',
      progress: Math.min(total_alerts * 3, 100),
    },
    {
      icon: ShieldAlert,
      label: 'Elevated Active Threats',
      value: active_threats,
      sub: active_threats > 5 ? 'High priority attacks in queue' : 'Threat velocity nominal',
      badge: active_threats > 5 ? 'Elevated' : 'Normal',
      badgeClass: active_threats > 5 ? 'bg-red-50 text-red-700 border-red-200' : 'bg-emerald-50 text-emerald-700 border-emerald-200',
      iconClass: active_threats > 5 ? 'bg-red-50 text-red-600 border-red-100' : 'bg-emerald-50 text-emerald-600 border-emerald-100',
      barColor: active_threats > 5 ? 'bg-red-500' : 'bg-emerald-500',
      progress: Math.min(active_threats * 10, 100),
    },
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
      {cards.map((c) => {
        const Icon = c.icon;
        return (
          <div
            key={c.label}
            className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm flex flex-col justify-between"
          >
            <div className="flex items-start justify-between">
              <div className={`p-2 rounded-lg border ${c.iconClass}`}>
                <Icon size={18} />
              </div>
              <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${c.badgeClass}`}>
                {c.badge}
              </span>
            </div>

            <div className="my-2">
              <span className="text-2xl font-bold font-mono text-slate-900">
                <AnimatedNumber value={c.value} />
              </span>
              <p className="text-xs font-medium text-slate-500 mt-0.5">{c.label}</p>
            </div>

            <div>
              <div className="w-full bg-slate-100 h-1.5 rounded-full overflow-hidden mb-1.5">
                <div
                  className={`h-full ${c.barColor} rounded-full transition-all duration-300`}
                  style={{ width: `${c.progress}%` }}
                />
              </div>
              <p className="text-[10px] text-slate-400 truncate">{c.sub}</p>
            </div>
          </div>
        );
      })}
    </div>
  );
}
