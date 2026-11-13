import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, ReferenceLine
} from 'recharts';
import { TrendingUp, AlertCircle } from 'lucide-react';

const CRITICAL_THRESHOLD = 85;

function CustomTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-white border border-slate-200 p-2.5 rounded-lg shadow-md text-xs font-mono">
      <p className="text-slate-500 mb-1 font-semibold">{label}</p>
      {payload.map((p) => (
        <div key={p.dataKey} className="flex items-center justify-between gap-4 text-[11px]" style={{ color: p.color }}>
          <span className="text-slate-600 font-medium">{p.name}:</span>
          <span className="font-bold">{p.value} pts</span>
        </div>
      ))}
      {payload[0]?.payload?.count && (
        <p className="text-slate-400 mt-1 text-[10px] border-t border-slate-100 pt-1">
          {payload[0].payload.count} aggregated packets in window
        </p>
      )}
    </div>
  );
}

export function ThreatChart({ timeline }) {
  const data = timeline.slice(-50);

  return (
    <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm h-full flex flex-col">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between mb-3 shrink-0 gap-2">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-blue-50 text-blue-600 border border-blue-100">
            <TrendingUp size={16} />
          </div>
          <div>
            <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
              Real-Time Threat Score Velocity
            </h3>
            <p className="text-[11px] text-slate-500">
              Live anomaly intensity timeline (0–100 pts) across incoming network telemetry
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 text-xs font-medium">
          <div className="flex items-center gap-1.5 text-slate-600">
            <span className="w-2.5 h-2.5 rounded-full bg-blue-500"></span>
            <span>Average Score</span>
          </div>
          <div className="flex items-center gap-1.5 text-slate-600">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500"></span>
            <span>Peak Incident</span>
          </div>
        </div>
      </div>

      {data.length === 0 ? (
        <div className="flex-1 flex items-center justify-center text-slate-400 text-xs font-mono">
          Accumulating live time-series stream...
        </div>
      ) : (
        <div className="flex-1 min-h-[180px]">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data} margin={{ top: 8, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="lightAvgGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.2} />
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="lightPeakGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.15} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                </linearGradient>
              </defs>

              <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" vertical={false} />
              <XAxis
                dataKey="time"
                tick={{ fill: '#94a3b8', fontSize: 10, fontFamily: 'monospace' }}
                tickLine={false}
                axisLine={{ stroke: '#e2e8f0' }}
                interval="preserveStartEnd"
              />
              <YAxis
                domain={[0, 100]}
                tick={{ fill: '#94a3b8', fontSize: 10, fontFamily: 'monospace' }}
                tickLine={false}
                axisLine={{ stroke: '#e2e8f0' }}
              />
              <Tooltip content={<CustomTooltip />} />

              <ReferenceLine
                y={CRITICAL_THRESHOLD}
                stroke="#ef4444"
                strokeDasharray="4 4"
                label={{
                  value: 'Critical Threshold (85)',
                  position: 'insideTopRight',
                  fill: '#ef4444',
                  fontSize: 10,
                  fontWeight: 600,
                }}
              />

              <Area
                type="monotone"
                dataKey="avg_score"
                name="Avg Threat Score"
                stroke="#3b82f6"
                strokeWidth={2}
                fill="url(#lightAvgGrad)"
                isAnimationActive={false}
              />
              <Area
                type="monotone"
                dataKey="max_score"
                name="Peak Score"
                stroke="#ef4444"
                strokeWidth={1.5}
                strokeDasharray="3 3"
                fill="url(#lightPeakGrad)"
                isAnimationActive={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}
