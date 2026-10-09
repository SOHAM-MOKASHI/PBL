/**
 * ThreatChart.jsx — Component 2: Live time-series threat score chart (Recharts)
 */
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, ReferenceLine, Legend
} from 'recharts';

const CRITICAL_LINE = 85;
const HIGH_LINE = 60;

function CustomTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="panel p-3 text-xs font-mono" style={{ minWidth: 160, border: '1px solid #1a2744' }}>
      <p className="text-slate-400 mb-2">{label}</p>
      {payload.map((p) => (
        <div key={p.dataKey} className="flex justify-between gap-4" style={{ color: p.color }}>
          <span>{p.name}</span>
          <span className="font-semibold">{p.value}</span>
        </div>
      ))}
      {payload[0]?.payload?.count && (
        <p className="text-slate-500 mt-1">{payload[0].payload.count} events</p>
      )}
    </div>
  );
}

function GradientDef() {
  return (
    <defs>
      <linearGradient id="scoreGrad" x1="0" y1="0" x2="0" y2="1">
        <stop offset="5%" stopColor="#ff2d55" stopOpacity={0.3} />
        <stop offset="50%" stopColor="#ff6b35" stopOpacity={0.15} />
        <stop offset="95%" stopColor="#00d4ff" stopOpacity={0.05} />
      </linearGradient>
      <linearGradient id="maxGrad" x1="0" y1="0" x2="0" y2="1">
        <stop offset="5%" stopColor="#ff2d55" stopOpacity={0.15} />
        <stop offset="95%" stopColor="#ff2d55" stopOpacity={0} />
      </linearGradient>
      <filter id="glow">
        <feGaussianBlur stdDeviation="3" result="coloredBlur" />
        <feMerge>
          <feMergeNode in="coloredBlur" />
          <feMergeNode in="SourceGraphic" />
        </feMerge>
      </filter>
    </defs>
  );
}

export function ThreatChart({ timeline }) {
  const data = timeline.slice(-60);

  return (
    <div className="panel p-4 h-full flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div>
          <h3 className="text-sm font-semibold text-slate-200 tracking-wide">
            Threat Score Timeline
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">Real-time AI anomaly scoring (0–100)</p>
        </div>
        <div className="flex gap-3 text-xs font-mono">
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-red-500 inline-block" />
            <span className="text-slate-400">CRITICAL &gt;85</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-orange-500 inline-block" />
            <span className="text-slate-400">HIGH &gt;60</span>
          </span>
        </div>
      </div>

      {data.length === 0 ? (
        <div className="flex-1 flex items-center justify-center">
          <div className="text-center">
            <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
            <p className="text-slate-500 text-xs font-mono">Awaiting data stream...</p>
          </div>
        </div>
      ) : (
        <div className="flex-1 min-h-0">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
              <GradientDef />
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(26,39,68,0.8)" />
              <XAxis
                dataKey="time"
                tick={{ fill: '#475569', fontSize: 10, fontFamily: 'JetBrains Mono' }}
                tickLine={false}
                axisLine={{ stroke: '#1a2744' }}
                interval="preserveStartEnd"
              />
              <YAxis
                domain={[0, 100]}
                tick={{ fill: '#475569', fontSize: 10, fontFamily: 'JetBrains Mono' }}
                tickLine={false}
                axisLine={{ stroke: '#1a2744' }}
              />
              <Tooltip content={<CustomTooltip />} />
              <ReferenceLine
                y={CRITICAL_LINE}
                stroke="#ff2d55"
                strokeDasharray="6 3"
                strokeOpacity={0.6}
                label={{ value: 'CRITICAL', fill: '#ff2d55', fontSize: 9, fontFamily: 'JetBrains Mono' }}
              />
              <ReferenceLine
                y={HIGH_LINE}
                stroke="#ff6b35"
                strokeDasharray="4 4"
                strokeOpacity={0.4}
                label={{ value: 'HIGH', fill: '#ff6b35', fontSize: 9, fontFamily: 'JetBrains Mono' }}
              />
              <Area
                type="monotone"
                dataKey="max_score"
                name="Peak Score"
                stroke="#ff2d55"
                strokeWidth={1.5}
                fill="url(#maxGrad)"
                dot={false}
                activeDot={{ r: 4, fill: '#ff2d55', filter: 'url(#glow)' }}
              />
              <Area
                type="monotone"
                dataKey="avg_score"
                name="Avg Score"
                stroke="#00d4ff"
                strokeWidth={2}
                fill="url(#scoreGrad)"
                dot={false}
                activeDot={{ r: 4, fill: '#00d4ff', filter: 'url(#glow)' }}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}
