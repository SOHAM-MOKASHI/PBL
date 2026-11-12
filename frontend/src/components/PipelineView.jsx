/**
 * PipelineView.jsx — Enterprise SIEM Ingestion & Detection Pipeline Stepper
 */
import { ArrowRight, CheckCircle2, Filter, Layers, AlertOctagon } from 'lucide-react';

export function PipelineView({ metrics }) {
  const { total_ingested = 0, total_dropped = 0, total_scored = 0, total_alerts = 0 } = metrics;

  const dropRate = total_ingested > 0 ? Math.round((total_dropped / total_ingested) * 100) : 0;

  const stages = [
    {
      step: '01',
      name: 'Flow Ingestion',
      desc: 'Raw NetFlow stream parsing',
      count: total_ingested,
      badge: 'Active Intake',
      icon: Layers,
      color: 'text-blue-400 bg-blue-950/40 border-blue-800/80',
    },
    {
      step: '02',
      name: 'Heuristic Filtering',
      desc: `Noise reduction (${dropRate}% dropped)`,
      count: total_dropped,
      badge: `${dropRate}% Filtered`,
      icon: Filter,
      color: 'text-purple-400 bg-purple-950/40 border-purple-800/80',
    },
    {
      step: '03',
      name: 'Feature Scoring',
      desc: '7-factor anomaly evaluation',
      count: total_scored,
      badge: 'Scoring Engine',
      icon: CheckCircle2,
      color: 'text-amber-400 bg-amber-950/40 border-amber-800/80',
    },
    {
      step: '04',
      name: 'Incident Escalation',
      desc: 'Alert triage & MITRE mapping',
      count: total_alerts,
      badge: 'Elevated Alerts',
      icon: AlertOctagon,
      color: 'text-red-400 bg-red-950/40 border-red-800/80',
    },
  ];

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-3.5 shadow-sm">
      <div className="flex items-center justify-between mb-2.5">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold text-slate-200">
            Real-Time Processing Pipeline
          </span>
          <span className="text-[11px] text-slate-400 font-mono">
            (4-Stage Sequential Ingestion & Filter Architecture)
          </span>
        </div>
        <div className="flex items-center gap-2 text-[11px] font-mono text-slate-400">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
          <span>LATENCY: &lt; 2.5ms PER FLOW</span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-2">
        {stages.map((stage, idx) => {
          const Icon = stage.icon;
          return (
            <div
              key={stage.step}
              className="bg-slate-950 border border-slate-800/90 rounded-md p-2.5 flex items-center justify-between relative group hover:border-slate-700 transition-colors"
            >
              <div className="flex items-center gap-2.5 min-w-0">
                <div className={`w-8 h-8 rounded border flex items-center justify-center shrink-0 ${stage.color}`}>
                  <Icon size={15} />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-1.5">
                    <span className="text-[10px] font-mono text-slate-500 font-semibold">{stage.step}</span>
                    <p className="text-xs font-semibold text-slate-200 truncate">{stage.name}</p>
                  </div>
                  <p className="text-[11px] text-slate-400 truncate">{stage.desc}</p>
                </div>
              </div>

              <div className="text-right shrink-0 pl-2">
                <p className="text-sm font-bold font-mono text-slate-200">
                  {stage.count.toLocaleString()}
                </p>
                <span className="text-[9px] font-mono text-slate-400">events</span>
              </div>

              {idx < stages.length - 1 && (
                <div className="hidden lg:flex absolute -right-3 top-1/2 -translate-y-1/2 z-10 text-slate-600 bg-slate-900 rounded-full p-0.5 border border-slate-800 pointer-events-none">
                  <ArrowRight size={10} />
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
