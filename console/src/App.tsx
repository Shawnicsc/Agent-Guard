import { PresentationPage } from './PresentationPage';
import { useEffect, useRef, useState } from 'react';
import { Empty, Icon, Note, TracePicker, Updated } from './components';
import { demoBootstrap, demoIncident } from './demo';
import { downloadJson, getJson } from './lib';
import { AlignmentPage, Overview, PoliciesPage, RobustnessPage, SourcesPage, TracePage } from './pages';
import type { Bootstrap, Incident, Page } from './types';

const navigation: { id: Page; title: string; english: string; description: string; number?: string }[] = [
  { id: 'overview', title: '安全总览', english: 'SECURITY OVERVIEW', description: '聚合审计记录，快速了解 Agent 的工具行为与防护结果。' },
  { id: 'presentation', title: '报告展示', english: 'RESULTS & EVIDENCE', description: '从历史实验结果出发，查看效果、覆盖范围、真实案例与彩排证据。' },
  { id: 'sources', title: '多源注入识别', english: 'MULTI-SOURCE DETECTION', description: '追踪用户输入、外部资源与长期记忆中的可疑内容。', number: '01' },
  { id: 'alignment', title: '意图与工具对齐', english: 'INTENT ALIGNMENT', description: '对照冻结的用户目标与实际工具动作，查看语义偏离依据。', number: '02' },
  { id: 'policies', title: '策略与三态裁决', english: 'POLICY & DECISIONS', description: '查看工具语义策略，以及放行、确认、阻断的具体原因。', number: '03' },
  { id: 'trace', title: '攻击链路溯源', english: 'ATTACK INVESTIGATION', description: '沿来源、Agent 与工具调用，调查完整审计链路。', number: '04' },
  { id: 'robustness', title: '对抗鲁棒性', english: 'ADVERSARIAL EVALUATION', description: '对照历史攻防数据，观察检测覆盖与正常任务完成情况。', number: '05' },
];
function initialPage(): Page {
  return navigation.find(item => item.id === window.location.hash.slice(1))?.id ?? 'presentation';
}
export default function App() {
  const [page, setPage] = useState<Page>(initialPage);
  const [mode, setMode] = useState<'audit' | 'demo'>('audit');
  const [live, setLive] = useState<Bootstrap | null>(null);
  const [selected, setSelected] = useState('');
  const [detail, setDetail] = useState<Incident | null>(null);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [error, setError] = useState('');
  const [detailError, setDetailError] = useState('');
  const [refresh, setRefresh] = useState(0);
  const [automatic, setAutomatic] = useState(false);
  const [report, setReport] = useState<{ name: string; body: string } | null>(null);
  const dialogRef = useRef<HTMLDialogElement>(null);
  const current = navigation.find(item => item.id === page)!;
  const data = mode === 'demo' ? { ...demoBootstrap, evaluations: live?.evaluations ?? demoBootstrap.evaluations } : live;
  const incident = mode === 'demo' ? demoIncident : detail;

  useEffect(() => {
    const update = () => setPage(initialPage());
    window.addEventListener('hashchange', update);
    return () => window.removeEventListener('hashchange', update);
  }, []);
  useEffect(() => {
    const abort = new AbortController();
    setLoading(true);
    getJson<Bootstrap>('/api/console/bootstrap', abort.signal).then(result => {
      setLive(result); setError('');
      setSelected(previous => result.traces.some(trace => trace.trace_id === previous) ? previous : result.traces[0]?.trace_id ?? '');
    }).catch((reason: unknown) => {
      if (!abort.signal.aborted) setError(String(reason instanceof Error ? reason.message : reason));
    }).finally(() => { if (!abort.signal.aborted) setLoading(false); });
    return () => abort.abort();
  }, [refresh]);
  useEffect(() => {
    if (!automatic || mode === 'demo') return;
    const timer = window.setInterval(() => setRefresh(value => value + 1), 15000);
    return () => window.clearInterval(timer);
  }, [automatic, mode]);
  useEffect(() => {
    if (mode !== 'audit' || !selected) { setDetail(null); setDetailError(''); return; }
    const abort = new AbortController();
    setDetail(previous => previous?.trace_id === selected ? previous : null);
    setDetailLoading(true); setDetailError('');
    getJson<Incident>(`/api/incidents/${encodeURIComponent(selected)}`, abort.signal)
      .then(result => { setDetail(result); setDetailError(''); })
      .catch((reason: unknown) => { if (!abort.signal.aborted) setDetailError(String(reason instanceof Error ? reason.message : reason)); })
      .finally(() => { if (!abort.signal.aborted) setDetailLoading(false); });
    return () => abort.abort();
  }, [selected, refresh, mode]);
  useEffect(() => {
    if (report && !dialogRef.current?.open) dialogRef.current?.showModal();
  }, [report]);

  const navigate = (next: Page) => { setPage(next); window.location.hash = next; };
  const openTrace = (id: string, next: Page = 'trace') => { if (id) setSelected(id); navigate(next); };
  const openReport = async (name: string) => {
    setReport({ name, body: '正在读取报告…' });
    try {
      const response = await fetch(`/api/reports/${encodeURIComponent(name)}`);
      if (!response.ok || !response.headers.get('content-type')?.includes('text/plain')) throw new Error(`报告未能加载（HTTP ${response.status}），请连接只读数据服务。`);
      const body = await response.text();
      setReport(previous => previous?.name === name ? { name, body } : previous);
    } catch (reason) { setReport(previous => previous?.name === name ? { name, body: String(reason) } : previous); }
  };
  const props = data ? { data, incident, openTrace, openReport } : null;
  const connected = page === 'presentation' ? Boolean(live) && !error : mode === 'demo' || (Boolean(live?.database.connected) && !error);
  return <div className="app-shell">
    <aside className="sidebar">
      <a className="brand" href="#overview" onClick={() => navigate('overview')}><span className="brand-emblem"><Icon name="shield" size={25} /></span><div>Agent<span>Guard</span><small>AGENT SECURITY PLATFORM</small></div></a>
      <div className="workspace-switch"><span className="workspace-avatar">AG</span><div><strong>安全监测工作区</strong><small>本地审计 · 只读访问</small></div><Icon name="chevron" size={14} /></div>
      <nav aria-label="主导航"><span className="nav-label">工作台</span><button className={`nav-item ${page === 'overview' ? 'active' : ''}`} onClick={() => navigate('overview')}><Icon name="overview" size={19} /><span>安全总览</span></button><span className="nav-label capabilities-label">报告与防护能力 <small>6</small></span>{navigation.slice(1).map(item => <button className={`nav-item ${page === item.id ? 'active' : ''}`} key={item.id} onClick={() => navigate(item.id)}><Icon name={item.id} size={19} /><span>{item.title}</span><small>{item.number}</small></button>)}</nav>
      <div className="sidebar-bottom"><div className="sidebar-note"><Icon name="shield" size={20} /><p>每次裁决，都有迹可循。<small>从内容来源追踪到执行边界</small></p></div><div className="sidebar-version"><span className="status-dot" />Agent Guard <span>v0.1.0</span></div></div>
    </aside>
    <div className="app-content"><header className="topbar"><div className="breadcrumb"><span>工作台</span><Icon name="chevron" size={13} /><strong>{current.title}</strong></div><div className="topbar-right"><span className={`connection ${connected ? '' : 'offline'}`}><i />{page === 'presentation' ? connected ? '历史报告已连接' : '历史报告未连接' : mode === 'demo' ? '演示场景' : connected ? '审计数据已连接' : '审计数据未连接'}</span><span className="header-divider" /><span className="readonly-label"><Icon name="shield" size={14} />只读控制台</span><span className="user-avatar">G</span></div></header>
      <main><div className="page-heading"><div><span className="eyebrow">{current.english}</span><h1>{current.title}{current.number && <span>CAPABILITY {current.number}</span>}</h1><p>{current.description}</p></div><div className="heading-actions"><div className="tabs mode-tabs" aria-label="选择数据来源" hidden={page === 'presentation'}><button className={mode === 'audit' ? 'active' : ''} onClick={() => setMode('audit')}>审计数据</button><button className={mode === 'demo' ? 'active' : ''} onClick={() => setMode('demo')}>演示场景</button></div><button className="button secondary refresh-button" disabled={loading} onClick={() => setRefresh(value => value + 1)}><Icon name="refresh" size={16} className={loading ? 'spinning' : ''} />刷新</button></div></div>
        {mode === 'demo' && page !== 'presentation' && <Note tone="warning">正在查看预设演示场景，用于说明五项能力的展示方式，不是真实检测结果。对抗验证页中若有历史报告，仍单独按实际存档展示。</Note>}
        {mode === 'audit' && error && <div className="error-banner" role="alert"><Icon name="info" size={19} /><div><strong>{live ? '刷新失败，保留上次读取的数据' : '尚未连接只读控制台服务'}</strong><p>{error}</p><code>uv run python console/server.py</code></div><button className="button secondary" onClick={() => setMode('demo')}>查看演示场景</button></div>}
        {page !== 'presentation' && mode === 'audit' && live && !live.database.connected && <Note tone="warning">{live.database.message} 历史对抗报告仍可在“对抗鲁棒性”页面查看。</Note>}
        {data && <><div className="context-bar"><div>{page !== 'overview' && page !== 'robustness' && page !== 'presentation' ? <TracePicker traces={data.traces} selected={mode === 'demo' ? demoIncident.trace_id : selected} onChange={setSelected} /> : <span className="context-source"><Icon name="file" size={15} />{page === 'presentation' ? '仓库历史真实实验 · 独立于审计库与演示场景' : mode === 'demo' ? '演示场景 · 合成数据' : `${data.database.name} · 全库汇总`}</span>}</div><div className="context-actions">{mode === 'audit' && page !== 'presentation' && <label className="auto-refresh"><input type="checkbox" checked={automatic} onChange={event => setAutomatic(event.target.checked)} />每 15 秒更新</label>}{incident && page !== 'overview' && page !== 'robustness' && page !== 'presentation' && <button className="text-button" onClick={() => downloadJson(`${mode === 'demo' ? 'demo-' : ''}${incident.trace_id}.json`, { data_mode: mode, exported_at: new Date().toISOString(), ...incident })}><Icon name="download" size={15} />导出证据</button>}<Updated value={data.generated_at} /></div></div>
          {detailError && mode === 'audit' && page !== 'overview' && page !== 'robustness' && page !== 'presentation' && <Note tone="warning">链路读取失败：{detailError}</Note>}
          {detailLoading && !detail && mode === 'audit' && page !== 'overview' && page !== 'robustness' && page !== 'presentation' ? <div className="loading-state" role="status"><Icon name="refresh" className="spinning" />正在读取审计证据…</div> : props && <div className="page-body" key={`${mode}-${page}-${page === 'overview' || page === 'robustness' || page === 'presentation' ? '' : selected}`}>{page === 'presentation' ? <PresentationPage key={refresh} /> : page === 'overview' ? <Overview {...props} /> : page === 'sources' ? <SourcesPage {...props} /> : page === 'alignment' ? <AlignmentPage {...props} /> : page === 'policies' ? <PoliciesPage {...props} /> : page === 'trace' ? <TracePage {...props} /> : <RobustnessPage {...props} />}</div>}
        </>}
        {!data && (loading ? <div className="loading-state" role="status"><Icon name="refresh" className="spinning" />正在连接审计数据…</div> : <div className="panel onboarding"><Empty title="让检测结果变得清晰可见"><p>启动独立控制台服务即可读取已有审计库与对抗报告。</p><p>也可以切换演示场景，浏览五项核心能力的可视化。</p><button className="button primary" onClick={() => setMode('demo')}>浏览演示场景 <Icon name="arrow" size={16} /></button></Empty></div>)}
        <footer className="footer"><span>AGENT GUARD <span> / </span>检测有据 · 执行有界</span><span>只读展示 · 不触发 Agent 操作</span></footer>
      </main>
    </div>
    <dialog className="report-dialog" ref={dialogRef} aria-label="历史报告" onCancel={() => setReport(null)} onClose={() => setReport(null)}><header><div><span className="eyebrow">ARCHIVED REPORT</span><h2>{report?.name}</h2></div><button className="icon-button" autoFocus aria-label="关闭报告" onClick={() => { dialogRef.current?.close(); setReport(null); }}><Icon name="close" /></button></header><pre>{report?.body}</pre><div className="dialog-footer"><span className="muted small">仓库存档 · 非本次新运行</span><button className="button secondary" onClick={() => { if (report) downloadJson(report.name.replace('.md', '.json'), { report: report.name, content: report.body }); }}><Icon name="download" size={16} />导出报告</button></div></dialog>
  </div>;
}
