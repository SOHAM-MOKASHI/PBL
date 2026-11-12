/**
 * XaiAlertPanel.jsx — Incident Investigation, Explainable AI (XAI) & Containment Playbook
 */
import { useState, useEffect, useRef } from 'react';
import {
  FileSearch, CheckCircle, XCircle, ChevronDown, ChevronUp,
  Shield, AlertTriangle, ExternalLink, Download, FileText, CheckCircle2
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
  return (
    <a
      href={`https://attack.mitre.org/techniques/${techniqueId?.replace('.', '/')}/`}
      target="_blank"
      rel="noreferrer"
      className="flex items-center justify-between p-3 rounded-lg border border-purple-800/60 bg-purple-950/30 hover:bg-purple-900/40 transition-colors group"
    >
      <div>
        <div className="flex items-center gap-2">
          <span className="text-xs font-bold font-mono text-purple-400">
            {techniqueId}
          </span>
          <span className="text-[10px] text-purple-300 font-mono uppercase tracking-wider">
            Tactic: {tactic}
          </span>
        </div>
        <div className="text-xs text-slate-200 font-semibold mt-1">
          {techniqueName}
        </div>
      </div>
      <ExternalLink size={14} className="text-purple-400 group-hover:translate-x-0.5 transition-transform" />
    </a>
  );
}

function ConfidenceBar({ confidence }) {
  const pct = Math.round((confidence ?? 0) * 100);
  const color = pct >= 80 ? 'bg-red-500' : pct >= 50 ? 'bg-orange-500' : 'bg-amber-500';

  return (
    <div className="flex items-center gap-3">
      <span className="text-[11px] text-slate-400 font-medium">Model Confidence</span>
      <div className="flex-1 h-1.5 rounded-full bg-slate-800 overflow-hidden">
        <div
          className={`h-full ${color} rounded-full transition-all duration-500`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="text-xs font-bold font-mono text-slate-300">{pct}%</span>
    </div>
  );
}

function PlaybookSteps({ text }) {
  const steps = text?.split(/\d+\.\s+/).filter(Boolean) ?? [];
  return (
    <div className="space-y-2 mt-2">
      {steps.map((step, i) => (
        <div key={i} className="flex items-start gap-2.5 text-xs text-slate-300">
          <span className="shrink-0 w-5 h-5 rounded bg-slate-800 border border-slate-700 text-blue-400 font-mono text-[10px] flex items-center justify-center font-bold">
            {i + 1}
          </span>
          <span className="leading-relaxed">{step.trim()}</span>
        </div>
      ))}
    </div>
  );
}

export function XaiAlertPanel({ alert }) {
  const [threshold, setThreshold] = useState(85);
  const [whitelistSize, setWhitelistSize] = useState(0);
  const [feedback, setFeedback] = useState(null);
  const [playbookOpen, setPlaybookOpen] = useState(true);
  const [isEscalating, setIsEscalating] = useState(false);
  const [isEscalated, setIsEscalated] = useState(false);
  const wsRef = useRef(null);

  useEffect(() => {
    const connect = () => {
      const ws = new WebSocket(WS_FEEDBACK_URL);
      wsRef.current = ws;

      ws.onmessage = (evt) => {
        try {
          const msg = JSON.parse(evt.data);
          if (msg.type === 'threshold_update') {
            setThreshold(msg.threshold_value);
            setWhitelistSize(msg.whitelist_size ?? 0);
          }
        } catch {}
      };

      ws.onclose = () => setTimeout(connect, 3000);
    };
    connect();
    return () => wsRef.current?.close();
  }, []);

  useEffect(() => {
    setFeedback(null);
    setIsEscalated(false);
    setIsEscalating(false);
  }, [alert?.alert_id]);

  const sendFeedback = (type) => {
    if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) return;
    wsRef.current.send(JSON.stringify({ type, ip: alert?.src_ip ?? '' }));
    setFeedback(type === 'false_positive' ? 'benign' : 'confirmed');
  };

  const handleEscalate = () => {
    setIsEscalating(true);
    setTimeout(() => {
      const content = `INCIDENT REPORT - CSOC PLATFORM
=========================================
Generated At : ${new Date().toLocaleString()}
Alert ID     : ${alert?.alert_id || 'N/A'}
Severity     : ${alert?.severity || 'HIGH'}
Threat Score : ${alert?.threat_score || 0} / 100

INCIDENT PARTICULARS
--------------------
Source IP    : ${alert?.src_ip}:${alert?.src_port}
Target IP    : ${alert?.dst_ip}:${alert?.dst_port}
Protocol     : ${alert?.protocol}
Attack Label : ${alert?.attack_label || 'Anomalous Network Pattern'}

EXPLAINABLE AI (XAI) SUMMARY
----------------------------
${alert?.xai?.narrative || 'Automated feature scoring identified payload and rate anomalies.'}

MITRE ATT&CK FRAMEWORK MAPPING
------------------------------
Technique ID : ${alert?.xai?.mitre_technique_id || 'T1595'}
Technique    : ${alert?.xai?.mitre_technique_name || 'Active Scanning'}
Tactic       : ${alert?.xai?.mitre_tactic || 'Reconnaissance'}

RECOMMENDED RESPONSE PROCEDURE
------------------------------
${alert?.xai?.playbook || '1. Isolate target host.\n2. Review firewall logs.'}

=========================================
Lead Analyst : Soham Mokashi
CSOC Tier-2 Cyber Operations Center`;

      const blob = new Blob([content], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `Incident_${alert?.alert_id || 'CSOC'}.txt`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      setIsEscalating(false);
      setIsEscalated(true);
    }, 800);
  };

  if (!alert) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-lg flex flex-col h-full shadow-sm">
        <div className="px-3.5 py-2.5 border-b border-slate-800 flex items-center gap-2">
          <FileSearch size={15} className="text-blue-400" />
          <span className="text-xs font-semibold text-slate-200">Incident Investigation</span>
        </div>
        <div className="flex-1 flex flex-col items-center justify-center p-6 text-center text-slate-400">
          <FileSearch size={32} className="text-slate-600 mb-2" />
          <p className="text-xs font-medium text-slate-300">No active incident selected</p>
          <p className="text-[11px] text-slate-500 mt-1">Select an incident from the Incident Queue to review XAI telemetry</p>
        </div>
        <div className="p-3 border-t border-slate-800 bg-slate-950 text-xs">
          <div className="flex justify-between text-slate-400 mb-1">
            <span>Detection Sensitivity Threshold</span>
            <span className="font-mono text-blue-400 font-bold">{threshold.toFixed(1)} pts</span>
          </div>
          <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
            <div className="h-full bg-blue-500" style={{ width: `${threshold}%` }} />
          </div>
        </div>
      </div>
    );
  }

  const xai = alert.xai ?? {};
  const severity = alert.severity ?? 'HIGH';

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg flex flex-col h-full overflow-hidden shadow-sm">
      {/* Header */}
      <div className="px-3.5 py-2.5 border-b border-slate-800 flex items-center justify-between shrink-0 bg-slate-900">
        <div className="flex items-center gap-2">
          <FileSearch size={15} className="text-blue-400" />
          <span className="text-xs font-semibold text-slate-200">Incident Investigation</span>
        </div>
        <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
          {alert.alert_id}
        </span>
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto p-3.5 space-y-3 min-h-0 bg-slate-950">
        {/* Incident Summary strip */}
        <div className="grid grid-cols-3 gap-2 p-2 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono">
          <div>
            <span className="text-[10px] text-slate-500 block">SEVERITY</span>
            <span className="font-bold text-red-400">{severity}</span>
          </div>
          <div>
            <span className="text-[10px] text-slate-500 block">SCORE</span>
            <span className="font-bold text-slate-200">{Math.round(alert.threat_score ?? 0)} / 100</span>
          </div>
          <div>
            <span className="text-[10px] text-slate-500 block">PROTOCOL</span>
            <span className="font-bold text-slate-200">{alert.protocol}</span>
          </div>
        </div>

        {/* Confidence metric */}
        <ConfidenceBar confidence={xai.confidence} />

        {/* MITRE ATT&CK Card */}
        {xai.mitre_technique_id && (
          <div>
            <label className="text-[11px] font-semibold text-slate-400 uppercase tracking-wide block mb-1.5">
              MITRE ATT&CK® Classification
            </label>
            <MitreBadge
              techniqueId={xai.mitre_technique_id}
              techniqueName={xai.mitre_technique_name}
              tactic={xai.mitre_tactic}
            />
          </div>
        )}

        {/* Narrative */}
        <div>
          <label className="text-[11px] font-semibold text-slate-400 uppercase tracking-wide block mb-1.5">
            Automated Incident Explanation
          </label>
          <div className="p-3 rounded-lg border border-slate-800 bg-slate-900 text-xs text-slate-300 leading-relaxed">
            {xai.narrative ?? 'Analyzing packet attributes and historical baseline...'}
          </div>
        </div>

        {/* Containment Playbook */}
        {xai.playbook && (
          <div className="rounded-lg border border-slate-800 bg-slate-900 overflow-hidden">
            <button
              onClick={() => setPlaybookOpen(!playbookOpen)}
              className="w-full px-3 py-2 flex items-center justify-between text-xs font-semibold text-slate-300 hover:bg-slate-850 transition-colors"
            >
              <div className="flex items-center gap-1.5">
                <Shield size={13} className="text-orange-400" />
                <span>Containment Playbook</span>
              </div>
              {playbookOpen ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
            </button>
            {playbookOpen && (
              <div className="px-3 pb-3 border-t border-slate-800/80">
                <PlaybookSteps text={xai.playbook} />
              </div>
            )}
          </div>
        )}

        {/* Analyst Actions (RLHF Feedback) */}
        <div className="pt-2 border-t border-slate-800">
          <label className="text-[11px] font-semibold text-slate-400 uppercase tracking-wide block mb-2">
            Analyst Action & Threshold Tuning
          </label>
          {feedback ? (
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-center text-emerald-400 flex items-center justify-center gap-2">
              <CheckCircle2 size={14} />
              <span>{feedback === 'confirmed' ? 'Threat confirmed. Threshold adjusted (-1.0).' : 'Marked benign. IP whitelisted (+2.0).'}</span>
            </div>
          ) : (
            <div className="grid grid-cols-2 gap-2">
              <button
                onClick={() => sendFeedback('confirm_threat')}
                className="py-2 px-3 rounded-lg bg-emerald-950/40 hover:bg-emerald-900/60 border border-emerald-800/80 text-emerald-300 font-medium text-xs flex items-center justify-center gap-1.5 transition-colors"
              >
                <CheckCircle size={13} />
                <span>Confirm Threat</span>
              </button>
              <button
                onClick={() => sendFeedback('false_positive')}
                className="py-2 px-3 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 font-medium text-xs flex items-center justify-center gap-1.5 transition-colors"
              >
                <XCircle size={13} />
                <span>False Positive</span>
              </button>
            </div>
          )}

          {/* Export Report */}
          <button
            onClick={handleEscalate}
            disabled={isEscalating || isEscalated}
            className="w-full mt-2 py-2 px-3 rounded-lg bg-blue-600/10 hover:bg-blue-600/20 border border-blue-500/30 text-blue-400 text-xs font-medium flex items-center justify-center gap-1.5 transition-colors"
          >
            {isEscalating ? (
              <span>Exporting Report...</span>
            ) : isEscalated ? (
              <>
                <CheckCircle2 size={13} />
                <span>Report Exported Successfully</span>
              </>
            ) : (
              <>
                <FileText size={13} />
                <span>Generate Incident Report (.txt)</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Threshold Status bar */}
      <div className="p-3 border-t border-slate-800 bg-slate-900 shrink-0 text-xs">
        <div className="flex justify-between text-slate-400 mb-1 text-[11px] font-mono">
          <span>Active Alert Threshold</span>
          <span className="text-blue-400 font-bold">{threshold.toFixed(1)} pts</span>
        </div>
        <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
          <div className="h-full bg-blue-500 transition-all duration-300" style={{ width: `${threshold}%` }} />
        </div>
        <div className="flex justify-between text-[10px] text-slate-500 font-mono mt-1">
          <span>Tighten (50)</span>
          <span>{whitelistSize} Whitelisted IPs</span>
          <span>Relax (99)</span>
        </div>
      </div>
    </div>
  );
}
