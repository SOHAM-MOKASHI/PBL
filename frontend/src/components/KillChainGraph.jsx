/**
 * KillChainGraph.jsx — Enterprise Attack Vector & Cyber Kill Chain Graph (@xyflow/react)
 */
import { useMemo } from 'react';
import {
  ReactFlow,
  Background,
  Handle,
  Position,
  BaseEdge,
  EdgeLabelRenderer,
  getBezierPath,
  MarkerType,
  useNodesState,
  useEdgesState,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Network } from 'lucide-react';

// ── Custom node types ─────────────────────────────────────────────────────
function IpNode({ data }) {
  const isSource = data.role === 'source';
  const borderColor = isSource ? '#ef4444' : '#3b82f6';
  const textColor = isSource ? '#f87171' : '#60a5fa';

  return (
    <div
      style={{
        background: '#0f172a',
        border: `1.5px solid ${borderColor}`,
        borderRadius: 8,
        padding: '8px 14px',
        minWidth: 145,
        fontFamily: 'JetBrains Mono, monospace',
        boxShadow: '0 2px 4px rgba(0,0,0,0.4)',
      }}
    >
      <Handle type="source" position={Position.Right} style={{ background: borderColor, border: 'none', width: 7, height: 7 }} />
      <Handle type="target" position={Position.Left} style={{ background: borderColor, border: 'none', width: 7, height: 7 }} />
      <div style={{ fontSize: 9, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 2 }}>
        {isSource ? 'Threat Actor (Origin)' : 'Target Host (Internal)'}
      </div>
      <div style={{ fontSize: 12, color: textColor, fontWeight: 700 }}>{data.ip}</div>
      {data.country && (
        <div style={{ fontSize: 9, color: '#64748b', marginTop: 2 }}>Zone: {data.country}</div>
      )}
    </div>
  );
}

function ActionNode({ data }) {
  const colorMap = {
    'Reconnaissance': '#f59e0b',
    'Port Scan':      '#f59e0b',
    'Brute Force':    '#f97316',
    'DDoS':           '#ef4444',
    'Data Exfiltration': '#ef4444',
    'C2 Beacon':      '#a855f7',
    'Botnet C2':      '#ef4444',
  };
  const color = colorMap[data.label] || '#3b82f6';

  return (
    <div
      style={{
        background: '#0f172a',
        border: '1.5px solid #334155',
        borderTop: `3px solid ${color}`,
        borderRadius: 6,
        padding: '6px 12px',
        minWidth: 130,
        textAlign: 'center',
        fontFamily: 'JetBrains Mono, monospace',
        boxShadow: '0 2px 4px rgba(0,0,0,0.3)',
      }}
    >
      <Handle type="target" position={Position.Left} style={{ background: '#64748b', border: 'none', width: 6, height: 6 }} />
      <Handle type="source" position={Position.Right} style={{ background: '#64748b', border: 'none', width: 6, height: 6 }} />
      <div style={{ fontSize: 9, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
        {data.tactic || 'Attack Vector'}
      </div>
      <div style={{ fontSize: 11, color: '#f1f5f9', fontWeight: 600, marginTop: 2 }}>{data.label}</div>
      {data.mitre && (
        <div
          style={{
            fontSize: 8, color: '#cbd5e1', marginTop: 3,
            background: '#1e293b', borderRadius: 3, padding: '1px 5px', display: 'inline-block',
            border: '1px solid #475569',
          }}
        >
          {data.mitre}
        </div>
      )}
    </div>
  );
}

// ── Animated edge with label ──────────────────────────────────────────────
function AnimatedEdge({ id, sourceX, sourceY, targetX, targetY, label, markerEnd, style }) {
  const [edgePath, labelX, labelY] = getBezierPath({ sourceX, sourceY, targetX, targetY });
  return (
    <>
      <BaseEdge path={edgePath} markerEnd={markerEnd} style={style} />
      {label && (
        <EdgeLabelRenderer>
          <div
            style={{
              position: 'absolute',
              transform: `translate(-50%, -50%) translate(${labelX}px,${labelY}px)`,
              fontSize: 9,
              color: '#cbd5e1',
              background: '#0f172a',
              padding: '2px 6px',
              borderRadius: 4,
              fontFamily: 'JetBrains Mono, monospace',
              pointerEvents: 'none',
              border: '1px solid #334155',
            }}
            className="nodrag nopan"
          >
            {label}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
}

const nodeTypes = { ipNode: IpNode, actionNode: ActionNode };
const edgeTypes = { animatedEdge: AnimatedEdge };

// ── Build graph from alert data ───────────────────────────────────────────
function buildGraph(alert) {
  if (!alert) return { nodes: [], edges: [] };

  const label = alert.attack_label || 'Suspicious Activity';
  const srcIp = alert.src_ip || '?.?.?.?';
  const dstIp = alert.dst_ip || '?.?.?.?';
  const mitre = alert.xai?.mitre_technique_id || 'T????';

  const chainMap = {
    'DDoS':              [{ label: 'Botnet C2', tactic: 'C&C', mitre: 'T1583' }, { label: 'DDoS', tactic: 'Impact', mitre: 'T1498' }],
    'Port Scan':         [{ label: 'Reconnaissance', tactic: 'Recon', mitre: 'T1595' }, { label: 'Port Scan', tactic: 'Discovery', mitre: 'T1046' }],
    'PortScan':          [{ label: 'Reconnaissance', tactic: 'Recon', mitre: 'T1595' }, { label: 'Port Scan', tactic: 'Discovery', mitre: 'T1046' }],
    'Data Exfiltration': [{ label: 'Brute Force', tactic: 'Credential', mitre: 'T1110' }, { label: 'Data Exfiltration', tactic: 'Exfiltration', mitre: 'T1041' }],
    'Brute Force':       [{ label: 'Brute Force', tactic: 'Credential', mitre: 'T1110' }, { label: 'C2 Beacon', tactic: 'C&C', mitre: 'T1071' }],
  };
  const chain = chainMap[label] || [{ label, tactic: 'Attack Phase', mitre }];

  const nodes = [
    { id: 'src', type: 'ipNode', position: { x: 0, y: 80 }, data: { ip: srcIp, role: 'source', country: 'External WAN' } },
    ...chain.map((step, i) => ({
      id: `act-${i}`,
      type: 'actionNode',
      position: { x: 195 + i * 165, y: 80 },
      data: step,
    })),
    { id: 'dst', type: 'ipNode', position: { x: 195 + chain.length * 165, y: 80 }, data: { ip: dstIp, role: 'target' } },
  ];

  const edges = [];
  const allIds = ['src', ...chain.map((_, i) => `act-${i}`), 'dst'];
  const edgeColor = '#ef4444';

  for (let i = 0; i < allIds.length - 1; i++) {
    edges.push({
      id: `e-${i}`,
      source: allIds[i],
      target: allIds[i + 1],
      type: 'animatedEdge',
      animated: true,
      label: i === 0 ? `Risk: ${Math.round(alert.threat_score || 0)} pts` : '',
      markerEnd: { type: MarkerType.ArrowClosed, color: edgeColor, width: 14, height: 14 },
      style: { stroke: edgeColor, strokeWidth: 1.5 },
    });
  }

  return { nodes, edges };
}

export function KillChainGraph({ alert }) {
  const { nodes: initNodes, edges: initEdges } = useMemo(() => buildGraph(alert), [alert?.alert_id]);
  const [nodes, , onNodesChange] = useNodesState(initNodes);
  const [edges, , onEdgesChange] = useEdgesState(initEdges);

  if (!alert) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-lg flex flex-col items-center justify-center h-full p-6 text-center shadow-sm">
        <Network size={32} className="text-slate-600 mb-2" />
        <p className="text-xs font-medium text-slate-300">No attack vector to map</p>
        <p className="text-[11px] text-slate-500 mt-1">Select an incident from the Incident Queue to visualize its cyber kill chain</p>
      </div>
    );
  }

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg flex flex-col h-full overflow-hidden shadow-sm">
      {/* Header */}
      <div className="px-3.5 py-2.5 border-b border-slate-800 flex items-center justify-between shrink-0 bg-slate-900">
        <div className="flex items-center gap-2">
          <Network size={15} className="text-blue-400" />
          <span className="text-xs font-semibold text-slate-200">
            Adversary Kill Chain Progression
          </span>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-950/60 border border-red-800/80 text-red-400 font-semibold">
            {alert.attack_label || 'ATTACK VECTOR'}
          </span>
        </div>
        <span className="text-[11px] font-mono text-slate-400">
          {alert.src_ip} → {alert.dst_ip}
        </span>
      </div>

      {/* React Flow canvas */}
      <div className="flex-1 min-h-0 bg-slate-950">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          nodeTypes={nodeTypes}
          edgeTypes={edgeTypes}
          fitView
          fitViewOptions={{ padding: 0.25 }}
          proOptions={{ hideAttribution: true }}
        >
          <Background color="#1e293b" gap={20} size={1} />
        </ReactFlow>
      </div>
    </div>
  );
}
