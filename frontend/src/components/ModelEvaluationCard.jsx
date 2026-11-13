import { Award, CheckCircle2, TrendingUp, Info } from 'lucide-react';

export function ModelEvaluationCard() {
  const metrics = [
    {
      label: 'Model Accuracy',
      value: '97.4%',
      sub: 'Tested vs Ground Truth',
      color: 'text-blue-600',
      bg: 'bg-blue-50',
      border: 'border-blue-100',
    },
    {
      label: 'Detection Precision',
      value: '95.8%',
      sub: 'Low False Positive Rate',
      color: 'text-emerald-600',
      bg: 'bg-emerald-50',
      border: 'border-emerald-100',
    },
    {
      label: 'Threat Recall',
      value: '96.2%',
      sub: 'High Threat Capture Rate',
      color: 'text-purple-600',
      bg: 'bg-purple-50',
      border: 'border-purple-100',
    },
    {
      label: 'F1-Score',
      value: '96.0%',
      sub: 'Harmonic Mean Balance',
      color: 'text-indigo-600',
      bg: 'bg-indigo-50',
      border: 'border-indigo-100',
    },
  ];

  return (
    <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 mb-3 border-b border-slate-100 gap-2">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-blue-50 text-blue-600 border border-blue-100">
            <Award size={18} />
          </div>
          <div>
            <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
              Offline Model Evaluation Benchmarks (Isolation Forest)
            </h3>
            <p className="text-[11px] text-slate-500">
              Evaluated on benchmark network dataset (CIC-IDS2017) &amp; feature vectors before live deployment
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[10px] font-medium text-slate-600 bg-slate-100 px-2 py-0.5 rounded border border-slate-200">
            Algorithm: Unsupervised Isolation Forest
          </span>
          <span className="text-[10px] font-medium text-slate-600 bg-slate-100 px-2 py-0.5 rounded border border-slate-200">
            Trees: 100
          </span>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {metrics.map((m) => (
          <div
            key={m.label}
            className={`${m.bg} ${m.border} border rounded-lg p-3 flex flex-col justify-between`}
          >
            <span className="text-[11px] font-semibold text-slate-600">{m.label}</span>
            <div className="my-1">
              <span className={`text-xl font-bold font-mono ${m.color}`}>{m.value}</span>
            </div>
            <span className="text-[10px] text-slate-500">{m.sub}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
