import { useMemo, useState } from 'react';
import { useTheme } from './Theme';
import type { Incident } from './types';
import { eventAction, short, text, time } from './lib';

type Message = { id: number; from: string; to: string; label: string; at: string; color: string; dashed?: boolean };

export function SequenceDiagram({ incident }: { incident: Incident }) {
  const { palette } = useTheme();
  const [limit, setLimit] = useState(24);
  const model = useMemo(() => {
    const laneNames = new Map<string, string>();
    const messages: Message[] = [];
    const agentLane = (id: string) => {
      const key = `agent:${id}`;
      laneNames.set(key, id === 'agent-main' ? '主 Agent' : id);
      return key;
    };
    for (const event of incident.timeline) {
      const call = incident.calls.find(item => item.call_id === event.call_id);
      if (!call) continue;
      const agent = agentLane(call.agent_id);
      laneNames.set('gateway', '检测 / 策略网关');
      if (event.type === 'call_received') {
        messages.push({ id: event.event_id, from: agent, to: 'gateway', label: call.tool, at: event.ts, color: palette.accent });
      } else if (event.type === 'decision_made') {
        const action = eventAction(event);
        messages.push({ id: event.event_id, from: 'gateway', to: agent, label: `${action ?? '未知裁决'} · ${short(text(event.payload.reason, ''), 32)}`, at: event.ts, color: action === 'BLOCK' ? '#be3455' : action === 'CONFIRM' ? '#a3620a' : '#047857', dashed: true });
      } else if (event.type === 'subagent_spawned' && event.agent_id) {
        const child = agentLane(event.agent_id);
        messages.push({ id: event.event_id, from: 'gateway', to: child, label: '签发子 Agent 身份', at: event.ts, color: palette.accent });
      } else if (event.type === 'tool_executed' || event.type === 'tool_refused') {
        const target = call.tool.startsWith('mcp.') ? `mcp:${text(call.arguments.server, '未知服务')}` : `tool:${call.tool.split('.')[0]}`;
        laneNames.set(target, call.tool.startsWith('mcp.') ? `MCP · ${text(call.arguments.server, '未知服务')}` : `${call.tool.split('.')[0]} 执行器`);
        messages.push({ id: event.event_id, from: 'gateway', to: target, label: `${call.tool} · ${event.type === 'tool_executed' ? '记录执行完成' : '执行失败 / 拒绝'}`, at: event.ts, color: event.type === 'tool_executed' ? '#059669' : '#b7791f' });
      }
    }
    return { lanes: [...laneNames], messages };
  }, [incident, palette.accent]);
  if (!model.messages.length) return <div className="sequence-empty">暂无可生成时序图的调用事件。</div>;
  const messages = model.messages.slice(0, limit);
  // Only render lifelines participating in the visible messages.
  const visible = new Set(messages.flatMap(message => [message.from, message.to]));
  const lanes = model.lanes.filter(([id]) => visible.has(id));
  const step = 210, left = 88, top = 86, row = 47;
  const width = Math.max(600, left + lanes.length * step), height = top + messages.length * row + 20;
  const x = (id: string) => left + lanes.findIndex(([key]) => key === id) * step + step / 2;
  return <><div className="sequence-scroll"><svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img" aria-label="按审计事件顺序绘制的 Agent、策略网关与执行器时序图"><title>观测调用时序；纵向间距不代表真实耗时</title><defs><marker id="sequence-arrow" markerWidth="7" markerHeight="7" refX="6" refY="3" orient="auto"><path d="M0 0 6 3 0 6" fill="none" stroke="context-stroke" strokeWidth="1.2" /></marker></defs>{lanes.map(([id, name]) => <g key={id}><rect x={x(id) - 82} y="15" width="164" height="37" rx="6" fill={id === 'gateway' ? palette.soft : palette.canvas} stroke="#dce3f4" /><text x={x(id)} y="38" textAnchor="middle" fill="#52668e" fontSize="10">{short(name, 25)}</text><line x1={x(id)} x2={x(id)} y1="53" y2={height - 10} stroke="#dce4f5" strokeDasharray="4 5" /></g>)}{messages.map((message, index) => { const y = top + index * row, a = x(message.from), b = x(message.to); return <g key={message.id}><title>{message.label}</title><text x="10" y={y + 3} fill="#7889a7" fontSize="8">{time(message.at)}</text><text x={(a + b) / 2} y={y - 9} fill={message.color} textAnchor="middle" fontSize="9">{short(message.label, Math.max(24, Math.floor(Math.abs(b - a) / 6)))}</text><line x1={a} x2={b > a ? b - 5 : b + 5} y1={y} y2={y} stroke={message.color} strokeWidth="1.3" strokeDasharray={message.dashed ? '4 3' : undefined} markerEnd="url(#sequence-arrow)" /><circle cx={a} cy={y} r="2.5" fill={message.color} /></g>; })}</svg></div><div className="table-footer"><span>显示 {messages.length}/{model.messages.length} 条观测消息 · 纵向间距不代表耗时</span>{limit < model.messages.length && <button className="text-button" onClick={() => setLimit(value => value + 30)}>展开更多</button>}</div></>;
}
