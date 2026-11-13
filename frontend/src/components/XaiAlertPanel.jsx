import { useState, useEffect, useRef } from 'react';
import {
  FileSearch, CheckCircle, XCircle, Shield, AlertTriangle,
  ExternalLink, Download, Printer, CheckCircle2, ChevronRight
} from 'lucide-react';

const getFeedbackWsUrl = () => {
  if (typeof window !== 'undefined') {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    if (window.location.port === '5173') {
      return `${proto}//${window.location.hostname}:8000/ws/feedback`;
    }
    return `${proto}//${window.location.host}/ws/feedback`;
  }
  return 'ws://localhost:8000/ws/feedback';
};

const WS_FEEDBACK_URL = getFeedbackWsUrl();

function MitreBadge({ techniqueId, techniqueName, tactic }) {
  if (!techniqueId) return null;
  return (
    <a
      href={`https://attack.mitre.org/techniques/${techniqueId?.replace('.', '/')}/`}
      target="_blank"
      rel="noreferrer"
      className="flex items-center justify-between p-3.5 rounded-xl border border-purple-200 bg-purple-50/70 hover:bg-purple-100/70 transition-colors group"
    >
      <div>
        <div className="flex items-center gap-2">
          <span className="text-xs font-bold font-mono text-purple-700">
            {techniqueId}
          </span>
          <span className="text-[10px] text-purple-600 font-semibold uppercase tracking-wider bg-purple-100 px-2 py-0.5 rounded">
            Tactic: {tactic}
          </span>
        </div>
        <div className="text-xs text-slate-800 font-bold mt-1">
          {techniqueName}
        </div>
      </div>
      <ExternalLink size={15} className="text-purple-600 group-hover:translate-x-0.5 transition-transform" />
    </a>
  );
}

function ConfidenceBar({ confidence }) {
  const pct = Math.round((confidence ?? 0) * 100);
  const color = pct >= 80 ? 'bg-red-500' : pct >= 50 ? 'bg-orange-500' : 'bg-emerald-500';

  return (
    <div className="flex items-center gap-3">
      <span className="text-xs text-slate-600 font-medium">Model Confidence</span>
      <div className="flex-1 h-2 rounded-full bg-slate-100 overflow-hidden border border-slate-200">
        <div
          className={`h-full ${color} rounded-full transition-all duration-500`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="text-xs font-bold font-mono text-slate-700">{pct}%</span>
    </div>
  );
}

function PlaybookSteps({ text }) {
  const steps = text?.split(/\d+\.\s+/).filter(Boolean) ?? [];
  if (steps.length === 0) return null;

  return (
    <div className="space-y-2 mt-2">
      {steps.map((step, i) => (
        <div key={i} className="flex items-start gap-2.5 text-xs text-slate-700 bg-slate-50 p-2.5 rounded-lg border border-slate-200">
          <span className="shrink-0 w-5 h-5 rounded-full bg-blue-600 text-white font-mono text-[11px] flex items-center justify-center font-bold">
            {i + 1}
          </span>
          <span className="leading-relaxed font-medium">{step.trim()}</span>
        </div>
      ))}
    </div>
  );
}

export function XaiAlertPanel({ alert }) {
  const [feedback, setFeedback] = useState(null);
  const [isEscalated, setIsEscalated] = useState(false);
  const wsRef = useRef(null);

  useEffect(() => {
    const ws = new WebSocket(WS_FEEDBACK_URL);
    wsRef.current = ws;
    return () => ws.close();
  }, []);

  const sendFeedback = (action) => {
    if (wsRef.current?.readyState === WebSocket.OPEN && alert) {
      wsRef.current.send(JSON.stringify({
        type: 'feedback',
        alert_id: alert.alert_id,
        action,
        timestamp: Date.now() / 1000,
      }));
      setFeedback(action);
    }
  };

  const handlePrint = () => {
    window.print();
  };

  if (!alert) {
    return (
      <div className="bg-white border border-slate-200 rounded-xl shadow-sm p-8 h-full flex flex-col items-center justify-center text-center">
        <FileSearch size={36} className="text-slate-300 mb-3" />
        <h4 className="text-sm font-bold text-slate-700">No Incident Selected</h4>
        <p className="text-xs text-slate-400 mt-1 max-w-sm">
          Click &quot;Analyze&quot; on any threat log in the Live Table or select an incident from the Flagged Alerts queue to inspect its Explainable AI breakdown.
        </p>
      </div>
    );
  }

  const xai = alert.xai || {};

  return (
    <div className="bg-white border border-slate-200 rounded-xl shadow-sm flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="p-4 border-b border-slate-200 flex items-center justify-between bg-white shrink-0">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-blue-50 text-blue-600 border border-blue-100">
            <FileSearch size={16} />
          </div>
          <div>
            <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
              Explainable AI (XAI) Incident Investigation
            </h3>
            <p className="text-[11px] text-slate-500">
              Automated cognitive triage and containment playbook
            </p>
          </div>
        </div>

        <button
          onClick={handlePrint}
          className="flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-slate-600 hover:text-slate-900 bg-slate-50 hover:bg-slate-100 border border-slate-200 rounded-lg transition-colors"
        >
          <Printer size={13} />
          <span>Print / Export</span>
        </button>
      </div>

      {/* Main Inspection Body */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* Incident Summary Card */}
        <div className="bg-slate-50 border border-slate-200 rounded-xl p-3.5">
          <div className="flex items-center justify-between flex-wrap gap-2 mb-2">
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs font-bold text-slate-800">
                {alert.alert_id}
              </span>
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                alert.severity === 'CRITICAL'
                  ? 'bg-red-50 text-red-700 border-red-200'
                  : 'bg-orange-50 text-orange-700 border-orange-200'
              }`}>
                {alert.severity}
              </span>
              <span className="text-xs font-bold text-slate-800 bg-white px-2 py-0.5 rounded border border-slate-200">
                {alert.attack_label || 'Anomalous Vector'}
              </span>
            </div>

            <div className="text-right">
              <span className="text-sm font-bold font-mono text-red-600">
                {Math.round(alert.threat_score ?? 0)}
              </span>
              <span className="text-xs text-slate-400 font-sans ml-1">/ 100 Risk Score</span>
            </div>
          </div>

          {/* Network Flow Tuple */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2 border-t border-slate-200 text-xs">
            <div>
              <span className="text-[10px] text-slate-400 block font-semibold uppercase">Source IP</span>
              <span className="font-mono font-bold text-blue-700">{alert.src_ip}</span>
            </div>
            <div>
              <span className="text-[10px] text-slate-400 block font-semibold uppercase">Target Host</span>
              <span className="font-mono font-bold text-slate-800">{alert.dst_ip}:{alert.dst_port}</span>
            </div>
            <div>
              <span className="text-[10px] text-slate-400 block font-semibold uppercase">Protocol</span>
              <span className="font-mono font-semibold text-slate-700">{alert.protocol}</span>
            </div>
            <div>
              <span className="text-[10px] text-slate-400 block font-semibold uppercase">Payload</span>
              <span className="font-mono text-slate-700">{alert.bytes_sent ? `${alert.bytes_sent} B` : 'Standard'}</span>
            </div>
          </div>
        </div>

        {/* MITRE ATT&CK Framework Mapping */}
        {xai.mitre_technique_id && (
          <div>
            <h4 className="text-xs font-bold text-slate-700 uppercase tracking-wider mb-1.5 flex items-center gap-1.5">
              <span>MITRE ATT&CK® Technique Correlation</span>
            </h4>
            <MitreBadge
              techniqueId={xai.mitre_technique_id}
              techniqueName={xai.mitre_technique_name}
              tactic={xai.mitre_tactic}
            />
          </div>
        )}

        {/* Explainable AI Narrative (Why the model flagged this) */}
        <div>
          <h4 className="text-xs font-bold text-slate-700 uppercase tracking-wider mb-1.5">
            Cognitive Explanation (Why AI Flagged This Threat)
          </h4>
          <div className="p-3.5 bg-blue-50/50 border border-blue-200/80 rounded-xl text-xs text-slate-800 leading-relaxed font-sans">
            <p>
              {xai.narrative ||
                `The Isolation Forest engine flagged this flow because its feature vector (packet size, connection frequency, and destination port ${alert.dst_port}) deviated significantly from the learned baseline profile.`}
            </p>
          </div>
        </div>

        {/* Model Confidence */}
        <div className="bg-slate-50 border border-slate-200 p-3 rounded-xl">
          <ConfidenceBar confidence={xai.confidence || 0.88} />
        </div>

        {/* Recommended Playbook Steps */}
        {xai.playbook && (
          <div>
            <h4 className="text-xs font-bold text-slate-700 uppercase tracking-wider mb-1.5">
              Actionable Containment Playbook
            </h4>
            <PlaybookSteps text={xai.playbook} />
          </div>
        )}

        {/* Analyst RLHF Feedback */}
        <div className="pt-2 border-t border-slate-200">
          <span className="text-xs font-bold text-slate-700 block mb-2">
            Analyst Review &amp; Reinforcement Feedback
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => sendFeedback('confirm')}
              disabled={feedback !== null}
              className={`flex-1 flex items-center justify-center gap-1.5 py-2 px-3 rounded-lg border text-xs font-semibold transition-colors ${
                feedback === 'confirm'
                  ? 'bg-emerald-600 text-white border-emerald-600'
                  : 'bg-emerald-50 text-emerald-700 border-emerald-200 hover:bg-emerald-100'
              }`}
            >
              <CheckCircle size={14} />
              <span>{feedback === 'confirm' ? 'Confirmed True Positive' : 'Confirm Threat (True Positive)'}</span>
            </button>

            <button
              onClick={() => sendFeedback('false_positive')}
              disabled={feedback !== null}
              className={`flex-1 flex items-center justify-center gap-1.5 py-2 px-3 rounded-lg border text-xs font-semibold transition-colors ${
                feedback === 'false_positive'
                  ? 'bg-slate-700 text-white border-slate-700'
                  : 'bg-slate-100 text-slate-700 border-slate-200 hover:bg-slate-200'
              }`}
            >
              <XCircle size={14} />
              <span>{feedback === 'false_positive' ? 'Marked False Positive' : 'Mark False Positive'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
