import { useEffect, useMemo, useRef, useState } from 'react';
import { Background, Controls, MarkerType, Position, ReactFlow, type Edge, type Node, type ReactFlowInstance } from '@xyflow/react';
import { Badge, Empty, Icon, JsonView, Note, Panel } from './components';
import { downloadJson } from './lib';
import type { CveCase } from './types';
import { useTheme } from './Theme';
import './cve-trajectory.css';

type CveCall = CveCase['calls'][number];
function execution(call: CveCall) {
  if (call.executed === false) return { label: '未执行', tone: 'stopped', detail: 'executed=false' };
  if (call.executed === true && call.ok === true) return { label: '执行返回成功', tone: 'executed', detail: 'executed=true · ok=true' };
  if (call.executed === true && call.ok === false) return { label: '已执行 · 返回失败', tone: 'failed', detail: 'executed=true · ok=false' };
  return { label: '执行结果未知', tone: 'unknown', detail: '缺少明确的 executed / ok 字段' };
}
function trajectory(cve: CveCase, selected: number, accent: string) {
  const nodes: Node[] = [], edges: Edge[] = [];
  cve.calls.forEach((call, index) => {
    const result = execution(call), y = index * 155;
    const items = [
      { stage: 'call', x: 0, eyebrow: `调用 ${String(index + 1).padStart(2, '0')}`, label: call.tool, detail: '点击查看原始参数', color: accent, tone: 'candidate' },
      { stage: 'decision', x: 325, eyebrow: '安全裁决', label: call.decision || '未记录', detail: call.rule_ids?.join(' · ') || '未记录规则 ID', color: call.decision === 'BLOCK' ? '#be3455' : call.decision === 'CONFIRM' ? '#b7791f' : '#059669', tone: call.decision?.toLowerCase() || 'unknown' },
      { stage: 'result', x: 650, eyebrow: '执行记录', label: result.label, detail: result.detail, color: result.tone === 'stopped' ? '#be3455' : result.tone === 'executed' ? '#059669' : '#b7791f', tone: result.tone },
    ];
    items.forEach(item => nodes.push({
      id: `${item.stage}-${index}`, position: { x: item.x, y }, sourcePosition: Position.Right, targetPosition: Position.Left,
      data: { callIndex: index, stage: item.stage, label: <div className={`cve-graph-node ${item.tone}`}><span>{item.eyebrow}</span><strong>{item.label}</strong><small title={item.detail}>{item.detail}</small></div> },
      style: { width: 250, borderColor: item.color, borderWidth: selected === index ? 2 : 1, boxShadow: selected === index ? `0 0 0 3px ${item.color}22` : 'none', background: item.tone === 'block' || item.tone === 'stopped' ? '#fff1f2' : '#fff' },
    }));
    edges.push({ id: `judged-${index}`, source: `call-${index}`, target: `decision-${index}`, type: 'smoothstep', label: '同一调用', markerEnd: { type: MarkerType.ArrowClosed, color: '#a1aec8' }, style: { stroke: '#a1aec8', strokeWidth: 1.6 } });
    edges.push({ id: `result-${index}`, source: `decision-${index}`, target: `result-${index}`, type: 'smoothstep', label: call.executed === false ? '未执行记录' : '执行记录', markerEnd: { type: MarkerType.ArrowClosed, color: result.tone === 'stopped' ? '#e47791' : '#a1aec8' }, style: { stroke: result.tone === 'stopped' ? '#e47791' : '#a1aec8', strokeWidth: 1.6 } });
  });
  return { nodes, edges };
}
function CveGraph({ cve }: { cve: CveCase }) {
  const { palette } = useTheme();
  const [selected, setSelected] = useState(0);
  const container = useRef<HTMLDivElement>(null);
  const flow = useRef<ReactFlowInstance | null>(null);
  useEffect(() => {
    if (!container.current) return;
    const observer = new ResizeObserver(() => { void flow.current?.fitView({ padding: .15 }); });
    observer.observe(container.current);
    return () => observer.disconnect();
  }, []);
  const graph = useMemo(() => trajectory(cve, selected, palette.accent), [cve, selected, palette.accent]);
  const call = cve.calls[selected];
  if (!call) return <Empty title="该场景未保存工具调用记录" />;
  const result = execution(call);
  return <><div className="cve-graph-toolbar"><div className="cve-lane-labels"><span>01 候选工具调用</span><span>02 安全裁决</span><span>03 实际执行记录</span></div><div className="cve-step-controls"><button className="icon-button" aria-label="上一个 CVE 调用" disabled={!selected} onClick={() => setSelected(v => v - 1)}>←</button><span>调用 {selected + 1} / {cve.calls.length}</span><button className="icon-button" aria-label="下一个 CVE 调用" disabled={selected === cve.calls.length - 1} onClick={() => setSelected(v => v + 1)}>→</button></div></div>
    <div className="cve-graph-canvas" ref={container}><ReactFlow nodes={graph.nodes} edges={graph.edges} fitView fitViewOptions={{ padding: .15 }} minZoom={.2} maxZoom={1.8} nodesDraggable={false} nodesConnectable={false} onInit={instance => { flow.current = instance; }} onNodeClick={(_, node) => setSelected(Number(node.data.callIndex))} proOptions={{ hideAttribution: true }} aria-label={`${cve.cve.id} 工具调用攻击轨迹图`}><Background gap={22} color={palette.soft} /><Controls showInteractive={false} /></ReactFlow></div>
    <div className="cve-graph-explanation"><span><i />实线：同一调用记录中的裁决与执行结果</span><span>每行一条调用 · 自上而下为 JSON 记录顺序 · 不表示调用之间的因果关系</span></div>
    <div className="cve-evidence-inspector"><div className="cve-inspector-heading"><div><h3>调用 {selected + 1} · {call.tool}</h3></div><Badge action={call.decision} /></div><div className="cve-evidence-grid"><div><h4>工具参数</h4><JsonView value={call.arguments} /></div><div><h4>裁决依据与执行结果</h4><p>{call.reason || '未记录裁决原因'}</p><div className="tags">{call.rule_ids?.length ? call.rule_ids.map(rule => <span className="tag mono" key={rule}>{rule}</span>) : <span className="tag">无规则 ID · 可能在工具注册或能力边界拒绝</span>}</div><div className={`cve-execution ${result.tone}`}><strong>{result.label}</strong><small>{result.detail}</small></div></div></div><details><summary>查看本条完整原始记录</summary><JsonView value={call} /></details></div>
  </>;
}
export function CveTrajectory({ cases }: { cases: CveCase[] }) {
  const [selected, setSelected] = useState('');
  const cve = cases.find(item => item.id === selected) ?? cases[0];
  return <Panel title="CVE 攻击轨迹可视化" aside={<span className="tag">历史场景记录 · 工具调用层验证</span>}>
    {!cve ? <Empty title="暂无 CVE 场景记录">读取 docs/cve_reproduction.json 后显示；不使用合成轨迹填充。</Empty> : <><div className="cve-trajectory-picker"><label>选择 CVE 场景<select aria-label="选择 CVE 攻击轨迹" value={cve.id} onChange={event => setSelected(event.target.value)}>{cases.map(item => <option value={item.id} key={item.id}>{item.cve.id} · {item.cve.title.split('（')[0]}</option>)}</select></label><button className="button secondary" onClick={() => downloadJson(`${cve.cve.id}-trajectory.json`, { source: 'docs/cve_reproduction.json', evidence_kind: '历史工具调用层场景验证', ...cve })}><Icon name="download" size={15} />导出轨迹证据</button></div>
      <div className="cve-trajectory-intro"><div><h3>{cve.cve.title}</h3><p>{cve.cve.background}</p></div><div className="cve-record-counts"><span><strong>{cve.calls.length}</strong>调用记录</span><span><strong>{cve.calls.filter(call => call.decision === 'BLOCK').length}</strong>BLOCK 裁决</span><span><strong>{cve.calls.filter(call => call.executed === true).length}</strong>实际执行</span></div></div>
      <div className="cve-described-chain"><span className="eyebrow">场景描述中的攻击步骤 · 设计说明，非逐事件审计证据</span><ol>{cve.cve.attack_chain.map((step, index) => <li key={index}><b>{index + 1}</b><p>{step}</p></li>)}</ol></div>
      <CveGraph cve={cve} key={cve.id} />
      <div className="cve-trajectory-footnote"><Note>数据来自 docs/cve_reproduction.json，使用专用策略进行确定性工具调用验证，不经真实漏洞产品、LLM 或 Docker。图中执行成功仅指工具返回成功，不表示攻击达成；BLOCK、CONFIRM 和 executed 分开展示。该 JSON 未提供完整 DAG 节点、时间戳和来源关联，因此未补画来源影响边或真实时间轴。</Note></div></>}
  </Panel>;
}
