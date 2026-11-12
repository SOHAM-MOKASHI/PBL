/**
 * ThreatChart.jsx — Enterprise Real-Time Anomaly Intensity Timeline
 */
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, ReferenceLine
} from 'recharts';
import { TrendingUp } from 'lucide-react';

const CRITICAL_THRESHOLD = 85;
const HIGH_THRESHOLD = 60;

function CustomTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-slate-900 border border-slate-700 p-2.5 rounded-lg shadow-lg text-xs font-mono">
      <p className="text-slate-400 mb-1.5 font-medium">{label}</p>
      {payload.map((p) => (
        <div key={p.dataKey} className="flex items-center justify-between gap-4 text-[11px]" style={{ color: p.color }}>
          <span className="text-slate-400">{p.name}:</span>
          <span className="font-bold">{p.value} pts</span>
        </div>
      ))}
      {payload[0]?.payload?.count && (
        <p className="text-slate-500 mt-1 text-[10px] border-t border-slate-800 pt-1">
          {payload[0].payload.count} aggregated packets in window
        </p>
      )}
    </div>
  );
}

export function ThreatChart({ timeline }) {
  const data = timeline.slice(-60);

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-3.5 h-full flex flex-col shadow-sm">
      {/* Header */}
      <div className="flex items-center justify-between mb-2.5 shrink-0">
        <div>
          <div className="flex items-center gap-2">
            <TrendingUp size={15} className="text-blue-400" />
            <h3 className="text-xs font-semibold text-slate-200">
              Threat Intensity Velocity
            </h3>
          </div>
          <p className="text-[11px] text-slate-400 mt-0.5">
            Rolling 60-second window • Anomaly score distribution (0–100)
          </p>
        </div>

        <div className="flex items-center gap-3 text-[11px] font-mono">
          <span className="flex items-center gap-1.5 text-slate-400">
            <span className="w-2 h-2 rounded-full bg-red-500" />
            <span>Critical (&gt;85)</span>
          </span>
          <span className="flex items-center gap-1.5 text-slate-400">
            <span className="w-2 h-2 rounded-full bg-orange-500" />
            <span>High (&gt;60)</span>
          </span>
        </div>
      </div>

      {data.length === 0 ? (
        <div className="flex-1 flex items-center justify-center text-slate-500 text-xs font-mono">
          Accumulating time-series data...
        </div>
      ) : (
        <div className="flex-1 min-h-0">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data} margin={{ top: 8, right: 10, left: -22, bottom: 0 }}>
              <defs>
                <linearGradient id="avgGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.25} />
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="peakGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.2} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                </linearGradient>
              </defs>

              <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" vertical={false} />
              <XAxis
                dataKey="time"
                tick={{ fill: '#64748b', fontSize: 10, fontFamily: 'JetBrains Mono' }}
                tickLine={false}
                axisLine={{ stroke: '#1f2937' }}
                interval="preserveStartEnd"
              />
              <YAxis
                domain={[0, 100]}
                tick={{ fill: '#64748b', fontSize: 10, fontFamily: 'JetBrains Mono' }}
                tickLine={false}
                axisLine={{ stroke: '#1f2937' }}
              />
              <Tooltip content={<CustomTooltip />} />

              <ReferenceLine
                y={CRITICAL_THRESHOLD}
                stroke="#ef4444"
                strokeDasharray="4 4"
                strokeWidth={1}
                label={{ value: 'CRITICAL', fill: '#ef4444', fontSize: 9, fontFamily: 'JetBrains Mono', position: 'right' }}
              />
              <ReferenceLine
                y={HIGH_THRESHOLD}
                stroke="#f97316"
                strokeDasharray="4 4"
                strokeWidth={1}
                label={{ value: 'HIGH', fill: '#f97316', fontSize: 9, fontFamily: 'JetBrains Mono', position: 'right' }}
              />

              <Area
                type="monotone"
                dataKey="max_score"
                name="Peak Anomaly Score"
                stroke="#ef4444"
                strokeWidth={1.5}
                fill="url(#peakGrad)"
                dot={false}
              />
              <Area
                type="monotone"
                dataKey="avg_score"
                name="Mean Threat Score"
                stroke="#3b82f6"
                strokeWidth={2}
                fill="url(#avgGrad)"
                dot={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}
