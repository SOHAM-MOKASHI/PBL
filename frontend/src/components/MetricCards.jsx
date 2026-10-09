/**
 * MetricCards.jsx — Component 4: KPI metric cards
 */
import { Shield, Zap, Activity, TrendingUp, AlertTriangle, Eye } from 'lucide-react';
import { useEffect, useState } from 'react';

function AnimatedNumber({ value, suffix = '' }) {
  const [displayed, setDisplayed] = useState(value);

  useEffect(() => {
    const diff = value - displayed;
    if (Math.abs(diff) < 1) { setDisplayed(value); return; }
    const step = Math.ceil(Math.abs(diff) / 8);
    const t = setTimeout(() => setDisplayed(prev => {
      const next = diff > 0 ? prev + step : prev - step;
      return diff > 0 ? Math.min(next, value) : Math.max(next, value);
    }), 16);
    return () => clearTimeout(t);
  }, [value, displayed]);

  return <span>{displayed.toLocaleString()}{suffix}</span>;
}

function SparkBar({ value, max = 100, color }) {
  const pct = Math.min((value / max) * 100, 100);
  return (
    <div className="progress-bar mt-2">
      <div
        className="progress-fill transition-all duration-500"
        style={{ width: `${pct}%`, background: color }}
      />
    </div>
  );
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
      label: 'Packets Analyzed',
      value: total_ingested,
      sub: `${total_dropped.toLocaleString()} filtered out`,
      color: '#00d4ff',
      glow: 'rgba(0,212,255,0.2)',
      bar: filterRate,
      barColor: 'linear-gradient(90deg, #00d4ff, #0077ff)',
    },
    {
      icon: Shield,
      label: 'Active Threats',
      value: active_threats,
      sub: active_threats > 10 ? '⚠ HIGH THREAT LEVEL' : active_threats > 5 ? 'ELEVATED' : 'NORMAL',
      color: active_threats > 10 ? '#ff2d55' : active_threats > 5 ? '#ff6b35' : '#00ff88',
      glow: active_threats > 10 ? 'rgba(255,45,85,0.25)' : 'rgba(0,255,136,0.15)',
      bar: Math.min(active_threats * 2, 100),
      barColor: active_threats > 10
        ? 'linear-gradient(90deg, #ff2d55, #ff0040)'
        : 'linear-gradient(90deg, #00ff88, #00cc70)',
      flash: active_threats > 10,
    },
    {
      icon: AlertTriangle,
      label: 'Total Alerts',
      value: total_alerts,
      sub: `${alertRate}% alert rate`,
      color: '#ff6b35',
      glow: 'rgba(255,107,53,0.2)',
      bar: Math.min(parseFloat(alertRate) * 5, 100),
      barColor: 'linear-gradient(90deg, #ff6b35, #ff2d55)',
    },
    {
      icon: Eye,
      label: 'Logs Scored',
      value: total_scored,
      sub: `${connected ? '● LIVE PIPELINE' : '○ CONNECTING...'}`,
      color: connected ? '#00ff88' : '#ffd700',
      glow: connected ? 'rgba(0,255,136,0.15)' : 'rgba(255,215,0,0.15)',
      bar: connected ? 100 : 20,
      barColor: connected
        ? 'linear-gradient(90deg, #00ff88, #00d4ff)'
        : 'linear-gradient(90deg, #ffd700, #ff6b35)',
    },
  ];

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
      {cards.map((card) => {
        const Icon = card.icon;
        return (
          <div
            key={card.label}
            className={`panel p-4 shimmer ${card.flash ? 'border-l-4 border-l-red-500 bg-red-950/30 transition-all duration-700 ease-in-out' : 'transition-all duration-300'}`}
            style={{
              boxShadow: `0 0 20px ${card.glow}, inset 0 1px 0 rgba(255,255,255,0.05)`,
              borderColor: `${card.color}22`,
            }}
          >
            <div className="flex items-start justify-between mb-1">
              <div>
                <p className="text-xs text-slate-500 uppercase tracking-widest font-semibold mb-1">
                  {card.label}
                </p>
                <p
                  className="text-2xl font-bold font-mono"
                  style={{ color: card.color }}
                >
                  <AnimatedNumber value={card.value} />
                </p>
              </div>
              <div
                className="p-2 rounded-lg"
                style={{ background: `${card.color}18` }}
              >
                <Icon size={18} style={{ color: card.color }} />
              </div>
            </div>
            <p className="text-xs mt-1 font-mono" style={{ color: `${card.color}99` }}>
              {card.sub}
            </p>
            <SparkBar value={card.bar} color={card.barColor} />
          </div>
        );
      })}
    </div>
  );
}
