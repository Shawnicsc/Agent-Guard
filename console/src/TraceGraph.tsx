import { useMemo, useState } from 'react';
import { Background, Controls, MiniMap, ReactFlow, Position, MarkerType, type Edge, type Node } from '@xyflow/react';
import type { Incident, TraceNode } from './types';
import { Icon, JsonView, Note } from './components';
import { short, sourceNames } from './lib';

const kinds: Record<string, { title: string; color: string }> = {
  session: { title: '任务会话', color: '#648078' }, agent: { title: 'Agent', color: '#297f71' },
  tool_call: { title: '工具调用', color: '#5d7da5' }, source: { title: '内容来源', color: '#b19154' },
  decision: { title: '策略裁决', color: '#bd7473' }, resource: { title: '目标资源', color: '#8e7ba5' },
};
const edgeNames: Record<string, string> = { called: '调用', started: '启动', delegated: '委派', produced: '产生', derived_from: '来源继承', introduced: '输入', possibly_influenced: '疑似影响', judged: '裁决', spawned: '派发', targeted: '目标' };
function layout(incident: Incident): { nodes: Node[]; edges: Edge[] } {
  const ids = new Set(incident.nodes.map(node => node.id));
  const validEdges = incident.edges.filter(edge => ids.has(edge.source) && ids.has(edge.target));
  const incoming = new Map(incident.nodes.map(node => [node.id, 0]));
  const outgoing = new Map<string, string[]>();
  const ranks = new Map(incident.nodes.map(node => [node.id, 0]));
  validEdges.forEach(edge => { incoming.set(edge.target, (incoming.get(edge.target) ?? 0) + 1); outgoing.set(edge.source, [...outgoing.get(edge.source) ?? [], edge.target]); });
  const queue = incident.nodes.filter(node => incoming.get(node.id) === 0).map(node => node.id);
  for (let index = 0; index < queue.length; index++) {
    const current = queue[index];
    for (const target of outgoing.get(current) ?? []) {
      ranks.set(target, Math.max(ranks.get(target) ?? 0, (ranks.get(current) ?? 0) + 1));
      incoming.set(target, (incoming.get(target) ?? 1) - 1);
      if (incoming.get(target) === 0) queue.push(target);
    }
  }
  const columns = new Map<number, number>();
  return {
    nodes: incident.nodes.map(node => {
      const rank = ranks.get(node.id) ?? 0, row = columns.get(rank) ?? 0;
      columns.set(rank, row + 1);
      const kind = kinds[node.kind] ?? kinds.source;
      return { id: node.id, position: { x: rank * 245, y: row * 105 }, sourcePosition: Position.Right, targetPosition: Position.Left,
        data: { label: <div className="graph-node"><span style={{ color: kind.color }}>{node.kind === 'source' ? sourceNames[String(node.source_type)] ?? kind.title : kind.title}</span><strong>{short(node.label, 42)}</strong><small>{short(node.id.replace(/^[^:]+:/, ''), 23)}</small></div> },
        style: { borderColor: kind.color, background: node.label === 'BLOCK' ? '#fff3f1' : node.label === 'CONFIRM' ? '#fffaef' : '#fff' },
      } satisfies Node;
    }),
    edges: validEdges.map((edge, index) => ({ id: `edge-${index}`, source: edge.source, target: edge.target,
      label: edgeNames[edge.kind] ?? edge.kind, type: 'smoothstep', animated: edge.certainty === 'inferred',
      markerEnd: { type: MarkerType.ArrowClosed, color: edge.certainty === 'inferred' ? '#c09554' : '#aabcb5' },
      style: { stroke: edge.certainty === 'inferred' ? '#c09554' : '#aabcb5', strokeWidth: 1.4, strokeDasharray: edge.certainty === 'inferred' ? '5 4' : undefined },
    } satisfies Edge)),
  };
}
export function TraceGraph({ incident }: { incident: Incident }) {
  const graph = useMemo(() => layout(incident), [incident]);
  const [selected, setSelected] = useState<TraceNode | null>(null);
  return <><div className="graph-legend">{Object.entries(kinds).map(([key, kind]) => <span key={key}><i style={{ background: kind.color }} />{kind.title}</span>)}<span className="legend-end">虚线：推断关联 · 实线：观测关系</span></div>
    {incident.graph_error ? <Note tone="warning">链路图未能重建：{incident.graph_error}。下方保留原始审计事件。</Note> : <div className="graph-canvas"><ReactFlow key={incident.trace_id} nodes={graph.nodes} edges={graph.edges} fitView fitViewOptions={{ padding: .22 }} minZoom={.15} maxZoom={1.8} nodesDraggable={false} nodesConnectable={false} onNodeClick={(_, node) => setSelected(incident.nodes.find(item => item.id === node.id) ?? null)} onPaneClick={() => setSelected(null)} proOptions={{ hideAttribution: true }} aria-label="攻击路径有向无环图"><Background gap={22} color="#d9e3de" /><Controls showInteractive={false} /><MiniMap pannable zoomable nodeColor={node => String(node.style?.borderColor ?? '#16846f')} /></ReactFlow></div>}
    {selected && <div className="node-inspector"><div><span className="eyebrow">节点证据</span><strong>{selected.label}</strong></div><button className="icon-button" aria-label="关闭节点详情" onClick={() => setSelected(null)}><Icon name="close" size={18} /></button><JsonView value={{ ...selected, ...(selected.id.startsWith('call:') ? incident.calls.find(call => `call:${call.call_id}` === selected.id) : selected.id.startsWith('source:') ? incident.sources.find(source => `source:${source.source_id}` === selected.id) : {}) }} /></div>}
  </>;
}
