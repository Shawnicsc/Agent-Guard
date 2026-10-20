import type { ReactNode } from 'react';
import type { Action, Bootstrap, Incident, TraceSummary } from './types';
import { num, sourceNames, time } from './lib';

const paths: Record<string, ReactNode> = {
  shield: <><path d="M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6z" /><path d="m8 12 3 3 5-6" /></>,
  overview: <><rect x="3" y="3" width="7" height="7" rx="1.5" /><rect x="14" y="3" width="7" height="7" rx="1.5" /><rect x="3" y="14" width="7" height="7" rx="1.5" /><rect x="14" y="14" width="7" height="7" rx="1.5" /></>,
  sources: <><path d="M4 7h5l3 5h8M4 17h5l3-5" /><circle cx="3" cy="7" r="2" /><circle cx="3" cy="17" r="2" /><circle cx="21" cy="12" r="2" /></>,
  alignment: <><path d="M4 5h10M4 11h7M4 17h5m5 0 3 3 5-7" /><circle cx="19" cy="6" r="3" /></>,
  policies: <><path d="M4 5h16M4 12h16M4 19h16" /><circle cx="8" cy="5" r="2" /><circle cx="16" cy="12" r="2" /><circle cx="10" cy="19" r="2" /></>,
  trace: <><rect x="8" y="2" width="8" height="5" rx="1" /><rect x="2" y="17" width="7" height="5" rx="1" /><rect x="15" y="17" width="7" height="5" rx="1" /><path d="M12 7v5H5v5m7-5h7v5" /></>,
  robustness: <><path d="M12 2v4m0 12v4M2 12h4m12 0h4M5 5l3 3m8 8 3 3M5 19l3-3m8-8 3-3" /><circle cx="12" cy="12" r="5" /></>,
  refresh: <><path d="M20 7v5h-5M4 17v-5h5" /><path d="M6 6a8 8 0 0 1 13 3M5 15a8 8 0 0 0 13 3" /></>,
  arrow: <path d="M5 12h14m-5-5 5 5-5 5" />,
  chevron: <path d="m9 5 7 7-7 7" />,
  download: <><path d="M12 3v12m-5-5 5 5 5-5M4 16v5h16v-5" /></>,
  search: <><circle cx="10.5" cy="10.5" r="6.5" /><path d="m16 16 5 5" /></>,
  clock: <><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></>,
  check: <path d="m5 12 4 4L19 6" />,
  info: <><circle cx="12" cy="12" r="9" /><path d="M12 11v6m0-10v1" /></>,
  file: <><path d="M14 2H5v20h14V7zM14 2v5h5M8 12h8m-8 4h6" /></>,
  close: <path d="m6 6 12 12M6 18 18 6" />,
  link: <><path d="m9 15 6-6m-7 4-2 2a4 4 0 0 0 6 6l2-2m-4-14 2-2a4 4 0 0 1 6 6l-2 2" /></>,
};
export function Icon({ name, size = 20, className = '' }: { name: string; size?: number; className?: string }) {
  return <svg className={className} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.65" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name] ?? paths.file}</svg>;
}
export function Badge({ action, children, tone = 'muted' }: { action?: Action | null; children?: ReactNode; tone?: string }) {
  return <span className={`badge ${action?.toLowerCase() ?? tone}`}><i />{children ?? (action === 'BLOCK' ? '强制阻断' : action === 'CONFIRM' ? '需要确认' : action === 'ALLOW' ? '合规放行' : '未记录')}</span>;
}
export function Panel({ title, eyebrow, aside, children, className = '' }: { title: string; eyebrow?: string; aside?: ReactNode; children: ReactNode; className?: string }) {
  return <section className={`panel ${className}`}><div className="panel-heading"><div>{eyebrow && <span className="eyebrow">{eyebrow}</span>}<h2>{title}</h2></div>{aside}</div>{children}</section>;
}
export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return <div className="empty-state"><span className="empty-icon"><Icon name="sources" size={28} /></span><h3>{title}</h3><div>{children ?? '选择一条会话，查看已记录的检测证据。'}</div></div>;
}
export function Note({ children, tone = '' }: { children: ReactNode; tone?: string }) {
  return <div className={`note ${tone}`}><Icon name="info" size={16} /><div>{children}</div></div>;
}
export function Metric({ label, value, unit, detail, icon, tone = 'teal' }: { label: string; value: string | number; unit?: string; detail: string; icon: string; tone?: string }) {
  return <div className="metric"><div className="metric-top"><span>{label}</span><span className={`metric-icon ${tone}`}><Icon name={icon} size={18} /></span></div><div className="metric-value">{typeof value === 'number' ? num(value) : value}<small>{unit}</small></div><div className="metric-detail">{detail}</div></div>;
}
export function TracePicker({ traces, selected, onChange }: { traces: TraceSummary[]; selected: string; onChange: (id: string) => void }) {
  return <label className="trace-picker"><Icon name="trace" size={17} /><span>调查会话</span><select value={selected} onChange={event => onChange(event.target.value)} aria-label="选择调查会话"><option value="" disabled>{traces.length ? '选择任务会话' : '暂无审计会话'}</option>{traces.map(trace => <option key={trace.trace_id} value={trace.trace_id}>{trace.goal} · {trace.session_id}</option>)}</select></label>;
}
export function Mission({ incident }: { incident: Incident }) {
  return <div className="mission"><span className="mission-icon"><Icon name="shield" size={21} /></span><div><span className="eyebrow">冻结的原始用户意图 · V{incident.mission.version ?? '?'}</span><p>{incident.mission.goal ?? '此会话未记录任务意图'}</p></div><span className="mono muted">{incident.session_id}</span></div>;
}
export function Activity({ data }: { data: Bootstrap['summary']['activity'] }) {
  if (!data.length) return <Empty title="暂无活动记录" />;
  const max = Math.max(...data.map(item => item.total), 1);
  const width = 660, height = 172, gap = width / data.length;
  return <div className="activity-chart"><svg viewBox={`0 0 ${width} ${height + 35}`} role="img" aria-label="最近十二个有记录小时的审计事件和决策数量"><title>审计事件分布，小时以 UTC 表示</title>{[0, 1, 2, 3].map(index => <line key={index} x1="0" x2={width} y1={index * 48 + 12} y2={index * 48 + 12} stroke="#e9edf0" strokeDasharray="4 4" />)}{data.map((item, index) => {
    const h = item.total / max * 135, d = item.decisions / max * 135;
    return <g key={item.hour}><title>{item.hour}: {item.total} 条事件，{item.decisions} 次决策</title><rect x={index * gap + gap * .23} y={height - h} width={Math.min(36, gap * .54)} height={h} rx="4" fill="#d6e9e5" /><rect x={index * gap + gap * .23} y={height - d} width={Math.min(36, gap * .54)} height={d} rx="4" fill="#14816d" /><text x={index * gap + gap * .5} y={height + 24} textAnchor="middle" fill="#84918f" fontSize="11">{item.hour.slice(5, 10)} {item.hour.slice(11)}h</text></g>;
  })}</svg><div className="chart-legend"><span><i className="swatch pale" />审计事件</span><span><i className="swatch teal" />其中：策略决策</span><span className="muted">UTC · 最近 {data.length} 个有记录小时</span></div></div>;
}
export function SourceDistribution({ counts }: { counts: Record<string, number> }) {
  const entries = Object.entries(counts).filter(([, count]) => count > 0).sort((a, b) => b[1] - a[1]);
  const total = entries.reduce((sum, [, count]) => sum + count, 0);
  const colors = ['#16846f', '#70b6a4', '#a5cec1', '#d4a661', '#88a2be', '#b7c4d1', '#d8e4df'];
  let start = 0;
  const gradient = entries.map(([, count], index) => { const end = start + count / total * 100; const result = `${colors[index % colors.length]} ${start}% ${end}%`; start = end; return result; }).join(',');
  return <div className="distribution"><div className="donut" style={{ background: total ? `conic-gradient(${gradient})` : '#edf1ef' }}><div><strong>{num(total)}</strong><span>内容来源</span></div></div><div className="distribution-legend">{entries.length ? entries.map(([type, count], index) => <div key={type}><i style={{ background: colors[index % colors.length] }} /><span>{sourceNames[type] ?? type}</span><strong>{num(count)}</strong></div>) : <span className="muted">尚未记录来源</span>}</div></div>;
}
export function JsonView({ value }: { value: unknown }) {
  return <pre className="json-view">{JSON.stringify(value, null, 2)}</pre>;
}
export function Updated({ value }: { value: string }) { return <span className="updated"><Icon name="clock" size={13} />更新于 {time(value)}</span>; }
