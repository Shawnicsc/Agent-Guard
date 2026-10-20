import type { Action, Incident, TimelineItem } from './types';

export const sourceNames: Record<string, string> = {
  user_message: '用户输入', web_page: '外部网页', file: '文件 / 文档',
  tool_result: '工具返回', tool_description: 'MCP 工具描述', mcp_response: 'MCP 返回', memory: '长期记忆',
};
export const eventNames: Record<string, string> = {
  session_created: '创建任务会话', mission_frozen: '冻结用户意图', agent_started: 'Agent 启动',
  call_received: '接收工具调用', decision_made: '完成策略裁决', semantic_analyzed: '语义研判',
  tool_executed: '工具执行完成', tool_refused: '执行失败 / 拒绝', source_recorded: '登记内容来源',
  label_attached: '标记敏感 / 注入内容', subagent_spawned: '派发子 Agent', mcp_relayed: 'MCP 代理转发',
  memory_read: '读取长期记忆', memory_written: '写入长期记忆', tripwire_hit: '绊网行为告警',
  rehearsal_run: '反事实彩排', rehearsal_step: '彩排过程', sandbox_started: '创建隔离沙箱',
  agent_done: 'Agent 任务结束', alert: '风险告警',
};
export const labelNames: Record<string, string> = {
  untrusted_instruction: '可疑指令', secret: '敏感信息', credential: '凭据信息', personal_data: '个人信息',
};
export const relationNames: Record<string, string> = { aligned: '符合任务', deviated: '偏离任务', uncertain: '证据不足' };
export const attemptNames: Record<string, string> = { direct: '直接输入', indirect: '间接注入', memory: '记忆污染', none: '未归类' };
export const approvalNames: Record<string, string> = { pending: '待确认', approved: '已批准', denied: '已拒绝' };
export const categoryNames: Record<string, string> = {
  normal: '良性业务', hard_rule: '工具硬规则', memory: '记忆污染', indirect: '间接注入',
  multilingual: '多语言 / Emoji', unicode: 'Unicode 变形', encoded: '编码伪装',
  multi_turn: '多轮诱导', split: '指令拆分', delimiter: '注释 / 分隔符',
  long_context: '上下文稀释', semantic: '语义伪装',
};
export const num = (value: number) => value.toLocaleString('zh-CN');
export const percent = (n: number, d: number) => d ? `${(n / d * 100).toFixed(1)}%` : '—';
export const short = (value: string, length = 18) => value.length > length ? `${value.slice(0, length)}…` : value;
export const time = (value?: string | null, full = false) => {
  if (!value) return '未记录';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : full ? date.toLocaleString('zh-CN', { hour12: false })
    : date.toLocaleTimeString('zh-CN', { hour12: false });
};
export const obj = (value: unknown): Record<string, unknown> => value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};
export const text = (value: unknown, fallback = '未记录') => typeof value === 'string' ? value : fallback;
export const stringList = (value: unknown): string[] => Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
export function eventAction(event: TimelineItem): Action | null {
  return ['ALLOW', 'CONFIRM', 'BLOCK'].includes(String(event.payload.action)) ? event.payload.action as Action : null;
}
export function semanticEvents(incident: Incident | null) {
  return incident?.timeline.filter(event => event.type === 'semantic_analyzed') ?? [];
}
export function traceAction(counts: Partial<Record<Action, number>>): Action {
  return counts.BLOCK ? 'BLOCK' : counts.CONFIRM ? 'CONFIRM' : 'ALLOW';
}
export async function getJson<T>(path: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(path, { signal, headers: { Accept: 'application/json' }, cache: 'no-store' });
  if (!response.ok) throw new Error(`数据服务返回 HTTP ${response.status}`);
  if (!response.headers.get('content-type')?.includes('application/json')) throw new Error('未连接只读数据服务，请启动 console/server.py');
  return response.json() as Promise<T>;
}
export function downloadJson(filename: string, data: unknown) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
  const anchor = document.createElement('a');
  anchor.href = url; anchor.download = filename; anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
