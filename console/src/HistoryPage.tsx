import { useEffect, useState } from 'react';
import { Badge, Empty, Icon, Metric, Note, Panel } from './components';
import { downloadJson, getJson } from './lib';
import { PresentationPage } from './PresentationPage';
import type { Action } from './types';
import './history.css';

type RunContext = { origin: string; application?: string; dataset_id?: string; dataset_name?: string; dataset_version?: string; batch_id?: string; batch_name?: string; case_id?: string; attempt?: number; role?: string; parent_session_id?: string };
type Summary = { sessions: number; batches: number; calls: number; events: number; execution_records: number; decisions: Partial<Record<Action, number>> };
type HistoryItem = { session_id: string; trace_id: string | null; user_id: string; goal: string; period: string; started_at: string; last_event_at: string | null; run_context: RunContext; protection_mode: string | null; call_count: number; counts: Summary['decisions'] };
type History = { generated_at: string; timezone: string; scope: string; summary: Summary; periods: (Summary & { period: string })[]; items: HistoryItem[]; total: number; page: number; page_size: number; facets: { origins: string[]; applications: string[]; datasets: { id: string; name: string }[]; batches: { id: string; name: string }[] }; warnings: string[] };
type Filters = { group_by: string; timezone: string; start: string; end: string; period: string; origin: string; application: string; dataset_id: string; batch_id: string; search: string; page: string };
const originNames: Record<string, string> = { production: '生产运行', evaluation: '评测运行', demo: '真实 Demo', unknown: '来源未记录' };
const modeNames: Record<string, string> = { enforce: '强制防护', monitor: '仅监控', off: '关闭保护' };
const defaults: Filters = { group_by: 'day', timezone: 'Asia/Shanghai', start: '', end: '', period: '', origin: '', application: '', dataset_id: '', batch_id: '', search: '', page: '1' };
function initialFilters(): Filters {
  const params = new URLSearchParams(window.location.search);
  return Object.fromEntries(Object.entries(defaults).map(([key, value]) => [key, params.get(`history_${key}`) ?? value])) as Filters;
}
function RuntimeHistory({ openTrace }: { openTrace: (id: string) => void }) {
  const [filters, setFilters] = useState<Filters>(initialFilters);
  const [data, setData] = useState<History | null>(null), [error, setError] = useState(''), [loading, setLoading] = useState(true);
  const [exporting, setExporting] = useState(false), [exportError, setExportError] = useState('');
  const query = new URLSearchParams(Object.entries(filters).filter(([, value]) => Boolean(value))).toString();
  const update = (patch: Partial<Filters>) => {
    const next = { ...filters, page: '1', ...patch };
    if (patch.group_by || patch.start !== undefined || patch.end !== undefined || patch.timezone) next.period = '';
    setFilters(next);
    const url = new URL(window.location.href);
    Object.entries(next).forEach(([key, value]) => { if (value && value !== defaults[key as keyof Filters]) url.searchParams.set(`history_${key}`, value); else url.searchParams.delete(`history_${key}`); });
    window.history.replaceState(null, '', url);
  };
  useEffect(() => {
    const abort = new AbortController();
    setLoading(true); setData(null); setError(''); setExportError('');
    const timer = window.setTimeout(() => {
      getJson<History>(`/api/console/history?${query}`, abort.signal).then(setData)
        .catch(reason => { if (!abort.signal.aborted) setError(String(reason)); })
        .finally(() => { if (!abort.signal.aborted) setLoading(false); });
    }, 250);
    return () => { window.clearTimeout(timer); abort.abort(); };
  }, [query]);
  const exportReport = async () => {
    setExporting(true); setExportError('');
    try {
      const report = await getJson<History>(`/api/console/history?${query}&export_all=true`);
      downloadJson(`traceshield-history-${filters.group_by}-${filters.period || 'all'}.json`, report);
    } catch (reason) { setExportError(String(reason)); }
    finally { setExporting(false); }
  };
  const timestamp = (value: string | null) => value ? new Date(value).toLocaleString('zh-CN', { timeZone: filters.timezone, hour12: false }) : '未记录';
  return <div className="runtime-history">
    <Panel title="查询历史运行" aside={<span className="tag">当前审计库 · 所有真实运行</span>}><div className="history-filters">
      <label>时间分类<select aria-label="时间分类" value={filters.group_by} onChange={e => update({ group_by: e.target.value })}><option value="day">按日</option><option value="month">按月</option></select></label>
      <label>归档时区<select aria-label="归档时区" value={filters.timezone} onChange={e => update({ timezone: e.target.value })}><option value="Asia/Shanghai">北京时间</option><option value="UTC">UTC</option></select></label>
      <label>开始日期<input type="date" aria-label="开始日期" value={filters.start} onChange={e => update({ start: e.target.value })} /></label>
      <label>结束日期<input type="date" aria-label="结束日期" value={filters.end} onChange={e => update({ end: e.target.value })} /></label>
      <label>运行来源<select aria-label="运行来源" value={filters.origin} onChange={e => update({ origin: e.target.value, period: '' })}><option value="">全部来源</option>{Object.entries(originNames).map(([id, label]) => <option value={id} key={id}>{label}</option>)}</select></label>
      <label>应用<input aria-label="应用" placeholder="应用名称" value={filters.application} onChange={e => update({ application: e.target.value, period: '' })} list="history-applications" /><datalist id="history-applications">{data?.facets.applications.map(app => <option key={app} value={app} />)}</datalist></label>
      <label>数据集<input aria-label="数据集" placeholder="数据集 ID" value={filters.dataset_id} onChange={e => update({ dataset_id: e.target.value, period: '' })} list="history-datasets" /><datalist id="history-datasets">{data?.facets.datasets.map(dataset => <option key={dataset.id} value={dataset.id}>{dataset.name}</option>)}</datalist></label>
      <label>运行批次<input aria-label="运行批次" placeholder="批次 ID" value={filters.batch_id} onChange={e => update({ batch_id: e.target.value, period: '' })} list="history-batches" /><datalist id="history-batches">{data?.facets.batches.map(batch => <option key={batch.id} value={batch.id}>{batch.name}</option>)}</datalist></label>
      <label className="history-search">搜索<input type="search" aria-label="搜索历史运行" placeholder="任务、用户、会话、数据集名称或批次" value={filters.search} onChange={e => update({ search: e.target.value, period: '' })} /></label>
      <div className="history-filter-actions"><button className="text-button" onClick={() => update(defaults)}>重置条件</button><button className="button secondary" disabled={!data || loading || exporting} onClick={exportReport}><Icon name="download" size={15} />{exporting ? '正在导出…' : '导出筛选报告'}</button></div>
    </div></Panel>
    {error && <Note tone="warning">历史运行读取失败：{error}。请确认控制台连接了产生这些运行的审计库。</Note>}
    {exportError && <Note tone="warning">导出失败：{exportError}</Note>}
    {loading && <div className="loading-state" role="status">正在查询运行历史…</div>}
    {data && <>{data.warnings.map(warning => <Note tone="warning" key={warning}>{warning}</Note>)}
      <div className="metrics-grid"><Metric label="历史任务会话" value={data.summary.sessions} detail={`${data.summary.batches} 个已登记批次`} icon="trace" /><Metric label="工具调用" value={data.summary.calls} detail={`${data.summary.events} 条审计事件`} icon="file" /><Metric label="阻断裁决" value={data.summary.decisions.BLOCK ?? 0} detail="按裁决记录计数，不等于攻击次数" icon="shield" tone="rose" /><Metric label="需要确认裁决" value={data.summary.decisions.CONFIRM ?? 0} detail="历史裁决数，非当前待办数" icon="clock" tone="amber" /></div>
      <Note>{data.scope} 时区：{data.timezone}。来源与批次未记录的旧会话仍可查询；子 Agent 属于原任务，影子重跑不计入独立任务统计。统计不包含前端合成演示数据。</Note>
      <div className="history-results"><Panel title={filters.group_by === 'day' ? '日报目录' : '月报目录'}><div className="history-periods"><button className={!filters.period ? 'active' : ''} onClick={() => update({ period: '' })}>全部时间<span>{data.periods.reduce((sum, item) => sum + item.sessions, 0)} 个会话</span></button>{data.periods.map(item => <button key={item.period} className={filters.period === item.period ? 'active' : ''} onClick={() => update({ period: item.period })}><strong>{item.period}</strong><span>{item.sessions} 个会话 · {item.calls} 次调用</span></button>)}</div></Panel>
      <Panel title={filters.period ? `${filters.period} · 运行记录` : '历史运行记录'} aside={<span className="tag">共 {data.total} 个会话</span>}>
        {data.items.length ? <div className="table-scroll"><table className="history-table"><thead><tr><th>任务与时间</th><th>运行归属</th><th>批次与样例</th><th>调用与裁决</th><th>证据</th></tr></thead><tbody>{data.items.map(item => <tr key={item.session_id}><td><strong>{item.goal}</strong><span className="cell-sub">开始：{timestamp(item.started_at)}</span><span className="cell-sub">最近事件：{timestamp(item.last_event_at)}</span><span className="cell-sub mono">{item.session_id}</span></td><td><Badge tone={item.run_context.origin === 'production' ? 'blue' : item.run_context.origin === 'evaluation' ? 'violet' : item.run_context.origin === 'demo' ? 'cyan' : 'muted'}>{originNames[item.run_context.origin] ?? '来源未记录'}</Badge><span className="cell-sub">应用：{item.run_context.application || '未记录'}</span><span className="cell-sub">数据集：{item.run_context.dataset_name || item.run_context.dataset_id || '未记录'}{item.run_context.dataset_version ? ` · ${item.run_context.dataset_version}` : ''}</span><span className="cell-sub">{modeNames[item.protection_mode || ''] || '保护模式未记录'} · 用户 {item.user_id}</span></td><td>{item.run_context.batch_id ? <button className="text-button" onClick={() => update({ batch_id: item.run_context.batch_id, period: '' })}>{item.run_context.batch_name || item.run_context.batch_id}</button> : '批次未记录'}<span className="cell-sub mono">{item.run_context.batch_id}</span><span className="cell-sub">样例：{item.run_context.case_id || '未记录'} · 尝试：{item.run_context.attempt ?? '未记录'}</span></td><td><strong>{item.call_count} 次调用</strong><span className="cell-sub">放行 {item.counts.ALLOW ?? 0} · 阻断 {item.counts.BLOCK ?? 0}</span><span className="cell-sub">确认 {item.counts.CONFIRM ?? 0}</span></td><td><button className="text-button" disabled={!item.trace_id} onClick={() => { if (item.trace_id) openTrace(item.trace_id); }}>查看链路 <Icon name="arrow" size={14} /></button></td></tr>)}</tbody></table></div> : <Empty title="没有符合条件的运行记录">调整日期或筛选条件；新运行写入当前审计库后，点击页面上方刷新即可查看。</Empty>}
        <div className="table-footer"><span>第 {data.page} / {Math.max(1, Math.ceil(data.total / data.page_size))} 页 · 每页 {data.page_size} 条</span><div className="history-pagination"><button className="button secondary" disabled={data.page <= 1} onClick={() => update({ page: String(data.page - 1) })}>上一页</button><button className="button secondary" disabled={data.page * data.page_size >= data.total} onClick={() => update({ page: String(data.page + 1) })}>下一页</button></div></div>
      </Panel></div>
    </>}
  </div>;
}
export function HistoryPage({ openTrace }: { openTrace: (id: string) => void }) {
  const [archive, setArchive] = useState(() => new URLSearchParams(window.location.search).has('view'));
  const switchArchive = (next: boolean) => {
    setArchive(next);
    const url = new URL(window.location.href);
    if (next) url.searchParams.set('view', 'catalog'); else url.searchParams.delete('view');
    window.history.replaceState(null, '', url);
  };
  return <><div className="tabs history-mode-tabs" aria-label="报告来源"><button className={!archive ? 'active' : ''} onClick={() => switchArchive(false)}>运行历史 · 日报 / 月报</button><button className={archive ? 'active' : ''} onClick={() => switchArchive(true)}>评测存档</button></div>{archive ? <PresentationPage /> : <RuntimeHistory openTrace={openTrace} />}</>;
}
