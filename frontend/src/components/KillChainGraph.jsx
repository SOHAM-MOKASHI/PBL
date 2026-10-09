/**
 * KillChainGraph.jsx — React Flow kill-chain visualization
 * Shows the attack path: Source IP → Action nodes → Target IP
 */
import { useCallback, useMemo } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Handle,
  Position,
  BaseEdge,
  EdgeLabelRenderer,
  getStraightPath,
  getBezierPath,
  MarkerType,
  useNodesState,
  useEdgesState,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';

// ── Custom node types ─────────────────────────────────────────────────────

function IpNode({ data }) {
  const isSource = data.role === 'source';
  const color = isSource ? '#ff2d55' : '#00d4ff';
  return (
    <div
      style={{
        background: `${color}15`,
        border: `1.5px solid ${color}60`,
        borderRadius: 8,
        padding: '8px 14px',
        minWidth: 140,
        boxShadow: `0 0 14px ${color}30`,
        fontFamily: 'JetBrains Mono, monospace',
      }}
    >
      <Handle type="source" position={Position.Right} style={{ background: color, border: 'none', width: 8, height: 8 }} />
      <Handle type="target" position={Position.Left} style={{ background: color, border: 'none', width: 8, height: 8 }} />
      <div style={{ fontSize: 9, color: `${color}99`, textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 2 }}>
        {isSource ? 'Threat Actor' : 'Target Host'}
      </div>
      <div style={{ fontSize: 11, color, fontWeight: 700 }}>{data.ip}</div>
      {data.country && (
        <div style={{ fontSize: 9, color: '#64748b', marginTop: 2 }}>{data.country}</div>
      )}
    </div>
  );
}

function ActionNode({ data }) {
  const colorMap = {
    'Reconnaissance': '#ffd700',
    'Port Scan':      '#ffd700',
    'Brute Force':    '#ff6b35',
    'DDoS':           '#ff2d55',
    'Data Exfiltration': '#ff2d55',
    'C2 Beacon':      '#8b5cf6',
    'Lateral Move':   '#ff6b35',
  };
  const color = colorMap[data.label] || '#00d4ff';

  return (
    <div
      style={{
        background: `${color}12`,
        border: `1.5px solid ${color}50`,
        borderRadius: 6,
        padding: '6px 12px',
        minWidth: 120,
        textAlign: 'center',
        fontFamily: 'JetBrains Mono, monospace',
        boxShadow: `0 0 10px ${color}20`,
      }}
    >
      <Handle type="target" position={Position.Left} style={{ background: color, border: 'none', width: 6, height: 6 }} />
      <Handle type="source" position={Position.Right} style={{ background: color, border: 'none', width: 6, height: 6 }} />
      <div style={{ fontSize: 9, color: `${color}80`, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
        {data.tactic || 'Action'}
      </div>
      <div style={{ fontSize: 11, color, fontWeight: 600, marginTop: 2 }}>{data.label}</div>
      {data.mitre && (
        <div
          style={{
            fontSize: 8, color: `${color}70`, marginTop: 3,
            background: `${color}15`, borderRadius: 3, padding: '1px 4px', display: 'inline-block',
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
      <EdgeLabelRenderer>
        <div
          style={{
            position: 'absolute',
            transform: `translate(-50%, -50%) translate(${labelX}px,${labelY}px)`,
            fontSize: 9,
            color: '#94a3b8',
            background: '#0a0f1e',
            padding: '1px 5px',
            borderRadius: 3,
            fontFamily: 'JetBrains Mono, monospace',
            pointerEvents: 'none',
            border: '1px solid #1a2744',
          }}
          className="nodrag nopan"
        >
          {label}
        </div>
      </EdgeLabelRenderer>
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

  // Attack-specific kill chain steps
  const chainMap = {
    'DDoS':            [{ label: 'Botnet C2', tactic: 'C&C', mitre: 'T1583' }, { label: 'DDoS', tactic: 'Impact', mitre: 'T1498' }],
    'Port Scan':       [{ label: 'Reconnaissance', tactic: 'Recon', mitre: 'T1595' }, { label: 'Port Scan', tactic: 'Discovery', mitre: 'T1046' }],
    'Data Exfiltration': [{ label: 'Brute Force', tactic: 'Credential', mitre: 'T1110' }, { label: 'Data Exfiltration', tactic: 'Exfil', mitre: 'T1041' }],
    'Brute Force':     [{ label: 'Brute Force', tactic: 'Credential', mitre: 'T1110' }, { label: 'C2 Beacon', tactic: 'C&C', mitre: 'T1071' }],
  };
  const chain = chainMap[label] || [{ label, tactic: 'Attack', mitre }];

  const nodes = [
    { id: 'src', type: 'ipNode', position: { x: 0, y: 80 }, data: { ip: srcIp, role: 'source', country: 'External' } },
    ...chain.map((step, i) => ({
      id: `act-${i}`,
      type: 'actionNode',
      position: { x: 200 + i * 170, y: 80 },
      data: step,
    })),
    { id: 'dst', type: 'ipNode', position: { x: 200 + chain.length * 170, y: 80 }, data: { ip: dstIp, role: 'target' } },
  ];

  const edges = [];
  const allIds = ['src', ...chain.map((_, i) => `act-${i}`), 'dst'];
  const edgeColor = '#ff2d55';

  for (let i = 0; i < allIds.length - 1; i++) {
    edges.push({
      id: `e-${i}`,
      source: allIds[i],
      target: allIds[i + 1],
      type: 'animatedEdge',
      animated: true,
      label: i === 0 ? `Score: ${Math.round(alert.threat_score || 0)}` : '',
      markerEnd: { type: MarkerType.ArrowClosed, color: edgeColor, width: 16, height: 16 },
      style: { stroke: edgeColor, strokeWidth: 1.5 },
    });
  }

  return { nodes, edges };
}

// ── Main component ────────────────────────────────────────────────────────
export function KillChainGraph({ alert }) {
  const { nodes: initNodes, edges: initEdges } = useMemo(() => buildGraph(alert), [alert?.alert_id]);
  const [nodes, , onNodesChange] = useNodesState(initNodes);
  const [edges, , onEdgesChange] = useEdgesState(initEdges);

  if (!alert) {
    return (
      <div className="panel flex items-center justify-center h-full">
        <div className="text-center">
          <div className="text-slate-600 text-xs font-mono">Select a CRITICAL/HIGH alert</div>
          <div className="text-slate-700 text-[10px] font-mono mt-1">to visualize kill chain</div>
        </div>
      </div>
    );
  }

  return (
    <div className="panel flex flex-col h-full">
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-cyber-border shrink-0">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold text-slate-300 uppercase tracking-wide">Kill Chain Graph</span>
          <span
            className="text-[9px] px-1.5 py-0.5 rounded font-mono font-bold"
            style={{ background: 'rgba(255,45,85,0.15)', color: '#ff2d55', border: '1px solid rgba(255,45,85,0.3)' }}
          >
            {alert.attack_label || 'UNKNOWN'}
          </span>
        </div>
        <span className="text-[9px] text-slate-600 font-mono">{alert.src_ip} → {alert.dst_ip}</span>
      </div>
      <div className="flex-1 min-h-0" style={{ background: '#030712' }}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          nodeTypes={nodeTypes}
          edgeTypes={edgeTypes}
          fitView
          fitViewOptions={{ padding: 0.3 }}
          proOptions={{ hideAttribution: true }}
        >
          <Background color="#1a2744" gap={24} size={1} />
        </ReactFlow>
      </div>
    </div>
  );
}
