/**
 * PipelineView.jsx — 4-stage AI pipeline status visualization
 */
export function PipelineView({ metrics }) {
  const { total_ingested = 0, total_dropped = 0, total_scored = 0, total_alerts = 0 } = metrics;

  const stages = [
    {
      id: 1,
      label: 'Ingest',
      sub: 'Raw log intake',
      count: total_ingested,
      color: '#00d4ff',
      icon: '⬇',
    },
    {
      id: 2,
      label: 'Heuristic Drop',
      sub: 'Trusted subnet filter',
      count: total_dropped,
      color: '#8b5cf6',
      icon: '⊘',
    },
    {
      id: 3,
      label: 'ML Score',
      sub: 'Anomaly detection',
      count: total_scored,
      color: '#ff6b35',
      icon: '◈',
    },
    {
      id: 4,
      label: 'Alert Gen',
      sub: 'Threat escalation',
      count: total_alerts,
      color: '#ff2d55',
      icon: '⚡',
    },
  ];

  return (
    <div className="panel p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-widest">
          AI Pipeline — 4 Stages
        </h3>
        <span className="text-[9px] text-slate-600 font-mono">PROCESSING</span>
      </div>
      <div className="flex items-stretch gap-1">
        {stages.map((stage, i) => (
          <div key={stage.id} className="flex items-center flex-1">
            <div
              className="flex-1 rounded-lg p-2.5 border relative"
              style={{
                background: `${stage.color}08`,
                borderColor: `${stage.color}25`,
                boxShadow: `0 0 12px ${stage.color}10`,
              }}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] font-mono" style={{ color: stage.color }}>
                  {stage.icon} S{stage.id}
                </span>
                <span
                  className="text-[10px] font-bold font-mono"
                  style={{ color: stage.color }}
                >
                  {stage.count.toLocaleString()}
                </span>
              </div>
              <p className="text-[10px] font-semibold text-slate-300">{stage.label}</p>
              <p className="text-[9px] text-slate-600 mt-0.5">{stage.sub}</p>

              {/* Animated processing dot */}
              <div
                className="absolute top-2 right-2 w-1.5 h-1.5 rounded-full animate-pulse"
                style={{ background: stage.color }}
              />
            </div>
            {i < stages.length - 1 && (
              <div className="flex flex-col items-center px-1 shrink-0">
                <div
                  className="w-4 h-[1px]"
                  style={{
                    background: `linear-gradient(90deg, ${stages[i].color}60, ${stages[i + 1].color}60)`,
                  }}
                />
                <span className="text-[8px] text-slate-700 mt-0.5">→</span>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
