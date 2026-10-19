import { StrictMode, useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import ReactFlow, { Background, Controls, type Edge, type Node } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import './style.css';

type TraceSummary = {
  trace_id: string;
  session_id: string;
  started_at: string;
  last_event_at: string;
  event_count: number;
};
type TraceNode = {
  id: string;
  kind: string;
  label: string;
  [key: string]: unknown;
};
type TraceEdge = { source: string; target: string; kind: string; certainty: string };
type TimelineItem = {
  event_id: string;
  ts: string;
  type: string;
  call_id: string | null;
  source_id: string | null;
  payload: Record<string, unknown>;
};
type Incident = {
  trace_id: string;
  session_id: string;
  nodes: TraceNode[];
  edges: TraceEdge[];
  timeline: TimelineItem[];
  impacts: { tool: string; target: string; call_id: string }[];
};

const colors: Record<string, string> = {
  session: '#284b63', agent: '#3963a7', tool_call: '#6a61ab',
  source: '#ca8842', decision: '#b85260', resource: '#397c6c',
};

function graphLayout(incident: Incident): { nodes: Node[]; edges: Edge[] } {
  const children = new Map<string, string[]>();
  const indegree = new Map(incident.nodes.map((item) => [item.id, 0]));
  const rank = new Map(incident.nodes.map((item) => [item.id, 0]));
  for (const edge of incident.edges) {
    children.set(edge.source, [...(children.get(edge.source) ?? []), edge.target]);
    indegree.set(edge.target, (indegree.get(edge.target) ?? 0) + 1);
  }
  const queue = incident.nodes.filter((item) => indegree.get(item.id) === 0).map((item) => item.id);
  for (let i = 0; i < queue.length; i += 1) {
    const parent = queue[i];
    for (const child of children.get(parent) ?? []) {
      rank.set(child, Math.max(rank.get(child) ?? 0, (rank.get(parent) ?? 0) + 1));
      indegree.set(child, (indegree.get(child) ?? 1) - 1);
      if (indegree.get(child) === 0) queue.push(child);
    }
  }
  const rows = new Map<number, number>();
  const nodes = incident.nodes.map((item) => {
    const column = rank.get(item.id) ?? 0;
    const row = rows.get(column) ?? 0;
    rows.set(column, row + 1);
    return {
      id: item.id,
      position: { x: column * 235, y: row * 105 },
      data: { label: <><small>{item.kind}</small><span>{item.label}</span></> },
      style: { borderColor: colors[item.kind] ?? '#777', borderWidth: 2 },
    } satisfies Node;
  });
  const edges = incident.edges.map((item, index) => ({
    id: `edge-${index}`, source: item.source, target: item.target,
    label: item.kind, animated: item.certainty === 'inferred',
    style: { strokeDasharray: item.certainty === 'inferred' ? '5 5' : undefined },
  } satisfies Edge));
  return { nodes, edges };
}

function App() {
  const [traces, setTraces] = useState<TraceSummary[]>([]);
  const [selectedTrace, setSelectedTrace] = useState<string | null>(null);
  const [incident, setIncident] = useState<Incident | null>(null);
  const [selectedNode, setSelectedNode] = useState<TraceNode | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    fetch('/api/incidents').then((response) => {
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return response.json() as Promise<TraceSummary[]>;
    }).then((items) => {
      setTraces(items);
      setSelectedTrace((previous) => previous ?? items[0]?.trace_id ?? null);
    }).catch((reason: unknown) => setError(`读取事件列表失败：${String(reason)}`));
  }, []);

  useEffect(() => {
    if (!selectedTrace) return;
    fetch(`/api/incidents/${encodeURIComponent(selectedTrace)}`).then((response) => {
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return response.json() as Promise<Incident>;
    }).then((item) => { setIncident(item); setSelectedNode(null); setError(''); })
      .catch((reason: unknown) => setError(`读取链路失败：${String(reason)}`));
  }, [selectedTrace]);

  const graph = useMemo(() => incident ? graphLayout(incident) : { nodes: [], edges: [] }, [incident]);
  return <div className="shell">
    <aside className="sidebar">
      <div className="brand"><span className="brand-mark">◆</span> Agent Guard</div>
      <div className="eyebrow">事件溯源 / INCIDENTS</div>
      {traces.length === 0 && <p className="empty">暂无审计事件。运行验收场景后刷新页面。</p>}
      {traces.map((trace) => <button key={trace.trace_id}
        className={`trace-card ${selectedTrace === trace.trace_id ? 'active' : ''}`}
        onClick={() => setSelectedTrace(trace.trace_id)}>
        <strong>{trace.session_id}</strong>
        <span>{trace.event_count} 条事件 · {new Date(trace.last_event_at).toLocaleString()}</span>
        <code>{trace.trace_id.slice(0, 20)}…</code>
      </button>)}
    </aside>
    <main>
      <header className="topbar">
        <div><div className="eyebrow">调查工作台</div><h1>攻击路径与执行证据</h1></div>
        <span className="badge">DAG + TIMELINE</span>
      </header>
      {error && <div role="alert" className="error">{error}</div>}
      {!incident ? <section className="empty-state">选择左侧 Trace 查看事件链路。</section> : <>
        <div className="metrics">
          <div><strong>{incident.nodes.length}</strong><span>节点</span></div>
          <div><strong>{incident.edges.length}</strong><span>关系</span></div>
          <div><strong>{incident.timeline.length}</strong><span>审计事件</span></div>
          <div><strong>{incident.impacts.length}</strong><span>已执行目标</span></div>
        </div>
        <section className="panel graph-panel">
          <div className="panel-heading"><h2>执行路径</h2><span>虚线表示推断关联，实线表示观测关系</span></div>
          <div className="graph">
            <ReactFlow nodes={graph.nodes} edges={graph.edges} fitView
              onNodeClick={(_, node) => setSelectedNode(incident.nodes.find((item) => item.id === node.id) ?? null)}>
              <Background gap={20} color="#e8ecf0" /><Controls />
            </ReactFlow>
          </div>
        </section>
        <div className="bottom-grid">
          <section className="panel">
            <div className="panel-heading"><h2>时间轴</h2><span>按事件写入顺序</span></div>
            <div className="timeline">{incident.timeline.map((event) => <article key={event.event_id}>
              <time>{new Date(event.ts).toLocaleTimeString()}</time>
              <div><strong>{event.type}</strong><small>{event.call_id ?? event.source_id ?? '会话级事件'}</small>
                <pre>{JSON.stringify(event.payload, null, 2)}</pre></div>
            </article>)}</div>
          </section>
          <section className="panel details">
            <div className="panel-heading"><h2>证据与影响</h2></div>
            {selectedNode ? <><p className="eyebrow">选中节点</p><h3>{selectedNode.label}</h3>
              <pre>{JSON.stringify(selectedNode, null, 2)}</pre></> : <p className="empty">点击图中节点查看来源、规则或目标详情。</p>}
            <h3>已执行目标</h3>
            {incident.impacts.length === 0 ? <p className="empty">无已执行目标；被阻断调用不会出现在这里。</p> :
              incident.impacts.map((impact) => <div className="impact" key={impact.call_id}>
                <strong>{impact.tool}</strong><span>{impact.target}</span></div>)}
          </section>
        </div>
      </>}
    </main>
  </div>;
}

createRoot(document.getElementById('root')!).render(<StrictMode><App /></StrictMode>);
