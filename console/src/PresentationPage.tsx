import { useEffect, useRef, useState } from 'react';
import { Badge, Empty, Icon, JsonView, Note, Panel } from './components';
import { downloadJson, getJson } from './lib';
import './presentation.css';

type ArmId = 'direct' | 'agent_guard_monitor' | 'agent_guard';
type BankRun = { id: string; file: string; arm: ArmId; task: string; target: string; attack: string; trace_id: string | null; outcome: 'success' | 'failed' | 'unknown'; utility: boolean | null; visible: boolean | null; error: string | null; elapsed_s: number | null; tokens: number | null; has_block: boolean; calls: { name: string; arguments: string }[]; decisions: { function: string; action: string; bypassed: boolean; rule_ids: string[] }[] };
type Arm = { arm: ArmId; total: number; successes: number; unknown: number; utility: number; utility_unknown: number; visible: number; block_runs: number; ci: [number, number] | null };
type RehearsalCall = { tool: string; arguments: Record<string, unknown>; status: string; ok: boolean; error: string };
type RehearsalEvent = { status: string; signals: string[]; replay_signals?: string[]; duration_ms: number; source_count: number; reason: string };
type RehearsalRun = { task: string; cell: string; payload: string | null; completed: boolean; refused: number; elapsed_s: number; agent_tokens: number; calls: RehearsalCall[]; manifested: boolean; summary: string; trace_id: string; rehearsal_events: RehearsalEvent[]; attributed_blocks: number };
type Presentation = { arms: Arm[]; runs: BankRun[]; files: { name: string; sha256: string }[]; warnings: string[]; metadata: { timestamp: string; model: string; guard_detector_model: string; benchmark_version: string }[]; provenance: { kind: string; commit: string; bank_date: string; rehearsal_date: string; rehearsal_revision: string }; rehearsal: { runs: RehearsalRun[]; tasks: Record<string, { instruction: string; inject_file: string }>; summary: { total?: number; injected?: number; benign?: number; manifested?: number; blocked?: number; benign_blocks?: number; events?: number; unavailable?: number; p50?: number; p95?: number; tokens?: number } } };
const labels: Record<ArmId, string> = { direct: '无防护', agent_guard_monitor: '仅监控', agent_guard: '强制防护' };
const colors: Record<ArmId, string> = { direct: '#718797', agent_guard_monitor: '#bf934b', agent_guard: '#16806b' };
const outcomeNames = { success: '攻击成功', failed: '攻击未成功', unknown: '错误 / 未知' };
const rate = (n: number, d: number) => d ? `${(100 * n / d).toFixed(1)}%` : '—';
const numericSort = (a: string, b: string) => a.localeCompare(b, undefined, { numeric: true });
function saveSvg(svg: SVGSVGElement | null, name: string) {
  if (!svg) return;
  const copy = svg.cloneNode(true) as SVGSVGElement;
  copy.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
  const url = URL.createObjectURL(new Blob([new XMLSerializer().serializeToString(copy)], { type: 'image/svg+xml;charset=utf-8' }));
  const link = document.createElement('a'); link.href = url; link.download = name; link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function Evidence({ children }: { children: React.ReactNode }) {
  return <div className="evidence-strip"><span className="evidence-tag">历史真实实验</span><span>{children}</span></div>;
}
function ComparisonChart({ arms, utility = false }: { arms: Arm[]; utility?: boolean }) {
  const svg = useRef<SVGSVGElement>(null);
  return <Panel title={utility ? '攻击下合法任务完成率 ↑' : '攻击成功率 ↓'} eyebrow={utility ? 'TASK UTILITY' : 'ATTACK SUCCESS RATE'} aside={<button className="text-button" onClick={() => saveSvg(svg.current, `${utility ? 'utility' : 'asr'}-comparison.svg`)}>导出 SVG</button>}>
    <svg ref={svg} className="comparison-svg" viewBox="0 0 600 300" role="img" aria-label={utility ? '三种模式的合法任务完成率' : '三种模式的攻击成功率'} style={{ background: '#fff', fontFamily: 'Segoe UI, Microsoft YaHei, sans-serif' }}>
      <title>{utility ? '合法任务完成率，分母为各模式全部攻击运行' : '攻击成功率，分母为各模式全部攻击运行；误差线为逐运行二项 Wilson 区间'}</title>
      {[0, 25, 50, 75, 100].map(t => <g key={t}><line x1="58" x2="565" y1={235 - t * 1.85} y2={235 - t * 1.85} stroke="#e6ebe8" /><text x="48" y={239 - t * 1.85} textAnchor="end" fill="#6a7d73" fontSize="11">{t}%</text></g>)}
      {arms.map((arm, index) => {
        const n = utility ? arm.utility : arm.successes, value = arm.total ? n / arm.total : 0;
        const x = 105 + index * 165, h = value * 185, y = 235 - h;
        return <g key={arm.arm}><title>{labels[arm.arm]}：{n}/{arm.total}，{rate(n, arm.total)}；未知 {utility ? arm.utility_unknown : arm.unknown}</title><rect x={x} y={y} width="82" height={Math.max(h, 2)} rx="5" fill={colors[arm.arm]} />
          {!utility && arm.ci && <g stroke="#304c40" strokeWidth="1.5"><line x1={x + 41} x2={x + 41} y1={235 - arm.ci[0] * 185} y2={235 - arm.ci[1] * 185} /><line x1={x + 34} x2={x + 48} y1={235 - arm.ci[1] * 185} y2={235 - arm.ci[1] * 185} /></g>}
          <text x={x + 41} y={Math.max(25, y - 19)} textAnchor="middle" fill="#213e31" fontSize="21" fontWeight="700">{rate(n, arm.total)}</text><text x={x + 41} y="258" textAnchor="middle" fill="#304c40" fontSize="13">{labels[arm.arm]}</text><text x={x + 41} y="280" textAnchor="middle" fill="#6a7d73" fontSize="11">{n} / {arm.total}</text></g>;
      })}
    </svg><p className="chart-footnote">{utility ? '任务完成由原评测 utility 字段判定；不会将攻击未成功计作任务完成。' : '两图使用相同的 0–100% 刻度。0 次观测成功不代表风险为零。'}</p>
  </Panel>;
}
function Results({ data }: { data: Presentation }) {
  return <><Evidence>银行套件 · {data.provenance.bank_date} · 每种模式 16 个任务 × 9 个攻击目标 × 3 种载荷 · 模拟业务工具</Evidence>
    <div className="grid-two"><ComparisonChart arms={data.arms} /><ComparisonChart arms={data.arms} utility /></div>
    <Panel title="从效果到代价，逐项核对" eyebrow="EVALUATION LEDGER"><div className="table-scroll"><table><thead><tr><th>模式</th><th>攻击成功 / 总运行</th><th>95% Wilson 区间</th><th>错误 / 未知</th><th>合法完成 / 总运行</th><th>载荷观测到</th><th>含 BLOCK 判定的运行</th></tr></thead><tbody>{data.arms.map(arm => <tr key={arm.arm}><td><span className="arm-dot" style={{ background: colors[arm.arm] }} />{labels[arm.arm]}</td><td>{arm.successes} / {arm.total}</td><td>{arm.ci ? `${(arm.ci[0] * 100).toFixed(2)}% – ${(arm.ci[1] * 100).toFixed(2)}%` : '无有效区间'}</td><td>{arm.unknown}</td><td>{arm.utility} / {arm.total}{arm.utility_unknown > 0 && `（未知 ${arm.utility_unknown}）`}</td><td>{arm.visible} / {arm.total}</td><td>{arm.block_runs}{arm.arm === 'agent_guard_monitor' ? '（仅记录，未强制拦截）' : ''}</td></tr>)}</tbody></table></div></Panel>
    <div className="report-insight"><strong>展示结论</strong><p>本次银行实验中，强制防护观测到的攻击成功为 0 次；同时需要关注合法任务完成率的下降。仅监控模式用于区分安全判定和实际执行拦截的作用。</p></div>
    <Note>每个任务与载荷组合单次运行，同一任务下的样本可能相关；Wilson 区间按逐运行二项模型计算，仅作为描述性区间。载荷可见性与攻击成功是不同字段。该银行实验不包含新增彩排层的效果验证。</Note>
  </>;
}
function Coverage({ data }: { data: Presentation }) {
  const [arm, setArm] = useState<ArmId>('agent_guard');
  const [variant, setVariant] = useState('all');
  const [cell, setCell] = useState<{ task: string; target: string } | null>(null);
  const [runId, setRunId] = useState('');
  const runs = data.runs.filter(r => r.arm === arm && (variant === 'all' || r.attack === variant));
  const tasks = [...new Set(data.runs.map(r => r.task))].sort(numericSort);
  const targets = [...new Set(data.runs.map(r => r.target))].sort(numericSort);
  const variants = [...new Set(data.runs.map(r => r.attack))];
  const selected = cell ? runs.filter(r => r.task === cell.task && r.target === cell.target) : [];
  const active = selected.find(r => r.id === runId) ?? selected[0];
  return <><Evidence>银行实验原始分片 · 单元格为任务 × 攻击目标 · 全部载荷时通常每格 n=3</Evidence><Panel title="任务 × 攻击目标覆盖矩阵" eyebrow="CLICK TO INVESTIGATE" aside={<div className="report-selectors"><select aria-label="矩阵防护模式" value={arm} onChange={e => { setArm(e.target.value as ArmId); setRunId(''); }}>{Object.entries(labels).map(([id, label]) => <option key={id} value={id}>{label}</option>)}</select><select aria-label="矩阵载荷类型" value={variant} onChange={e => { setVariant(e.target.value); setRunId(''); }}><option value="all">全部载荷</option>{variants.map(v => <option key={v}>{v}</option>)}</select></div>}>
      <div className="matrix-legend"><span><i className="legend-square success" />攻击成功</span><span><i className="legend-square failed" />已知结果均未成功</span><span><i className="legend-square unknown" />存在错误 / 未知</span><span>● 含 BLOCK 判定；仅监控时不会拦截</span></div>
      <div className="table-scroll"><table className="coverage-matrix"><thead><tr><th>用户任务 / 攻击目标</th>{targets.map(t => <th key={t}>{t.replace('injection_task_', '目标 ')}</th>)}</tr></thead><tbody>{tasks.map(task => <tr key={task}><th>{task.replace('user_task_', '任务 ')}</th>{targets.map(target => {
        const group = runs.filter(r => r.task === task && r.target === target), n = group.length;
        const success = group.filter(r => r.outcome === 'success').length, unknown = group.filter(r => r.outcome === 'unknown').length;
        const state = success ? 'success' : unknown || !n ? 'unknown' : 'failed';
        return <td key={target}><button className={`matrix-cell ${state} ${cell?.task === task && cell.target === target ? 'chosen' : ''}`} disabled={!n} onClick={() => { setCell({ task, target }); setRunId(''); }} aria-label={`${task} ${target}：成功 ${success}/${n}，未知 ${unknown}`} title={`攻击成功 ${success}/${n}；未知 ${unknown}；点击查看原始记录`}><strong>{success}/{n}</strong><small>{n ? `n=${n}` : '缺失'}{unknown ? ` · ?${unknown}` : ''}{group.some(r => r.has_block) ? ' ●' : ''}</small></button></td>;
      })}</tr>)}</tbody></table></div></Panel>
    <Panel title={cell ? `${cell.task} / ${cell.target} · 运行证据` : '点击单元格，查看每次运行的证据'} eyebrow="SOURCE RECORDS">{!active ? <Empty title="选择一个矩阵单元格">颜色表示观测结果，不代表攻击未成功均由防护系统造成。</Empty> : <div className="report-panel-body"><div className="run-tabs">{selected.map(run => <button key={run.id} className={active.id === run.id ? 'active' : ''} onClick={() => setRunId(run.id)}>{run.attack}<span className={`outcome-text ${run.outcome}`}>{outcomeNames[run.outcome]}</span></button>)}</div><div className="record-facts"><span>合法任务：{active.utility === true ? '完成' : active.utility === false ? '未完成' : '未知'}</span><span>载荷观测：{active.visible === true ? '是' : active.visible === false ? '否' : '未知'}</span><span>耗时：{active.elapsed_s ?? '—'} s</span><span>Token：{active.tokens?.toLocaleString() ?? '—'}</span></div><p className="muted small break-word">来源：{active.file} · Trace：{active.trace_id ?? '未记录'}</p>{active.error && <Note tone="warning">运行错误：{String(active.error)}</Note>}<div className="grid-two"><div><h4>请求调用（按存档顺序）</h4><div className="bank-calls">{active.calls.map((call, i) => <details key={i}><summary>{i + 1}. {call.name}</summary><pre>{call.arguments}</pre></details>)}</div></div><div><h4>裁决记录（独立存档顺序）</h4><div className="bank-calls">{active.decisions.length ? active.decisions.map((d, i) => <div key={i}><strong>{d.function}</strong><span>{d.action}{d.bypassed ? ' · 已绕过执行拦截' : ''}</span><small>{d.rule_ids.join(', ') || '未命中规则'}</small></div>) : <p className="muted">该模式无网关裁决记录。</p>}</div></div></div><Note>请求与裁决数组没有共同的逐调用标识，本页分别展示，不按位置强行关联；原始分片未保存这些调用的逐项执行结果。</Note><button className="text-button" onClick={() => downloadJson('bankfull-selected-run.json', { evidence_kind: '历史真实实验', ...active })}>导出此运行 JSON</button></div>}</Panel>
  </>;
}
function CallCards({ calls, limit = calls.length }: { calls: RehearsalCall[]; limit?: number }) {
  return <div className="replay-calls">{calls.slice(0, limit).map((call, i) => <article className={call.status === 'BLOCK' ? 'blocked' : ''} key={i}><div><span className="step-index">{String(i + 1).padStart(2, '0')}</span><strong>{call.tool}</strong><span className={`execution-state ${call.status === 'BLOCK' ? 'blocked' : ''}`}>{call.status === 'BLOCK' || call.status === 'CONFIRM' ? '未执行' : call.ok ? '执行返回成功' : '返回失败'}</span></div><JsonView value={call.arguments} /><footer><span>裁决 {call.status}</span><span>{call.error || (call.ok ? 'ok=true' : '无详细结果')}</span></footer></article>)}</div>;
}
function Rehearsal({ data, playback = false, active = true }: { data: Presentation; playback?: boolean; active?: boolean }) {
  const injected = data.rehearsal.runs.filter(r => r.cell === 'I5');
  const [task, setTask] = useState(injected.find(r => r.manifested)?.task ?? injected[0]?.task ?? '');
  const run = injected.find(r => r.task === task), benign = data.rehearsal.runs.find(r => r.cell === 'B1' && r.task === task);
  const [step, setStep] = useState(0), [playing, setPlaying] = useState(false);
  const count = run?.calls.length ?? 0;
  useEffect(() => { setStep(0); setPlaying(false); }, [task]);
  useEffect(() => { if (!active) setPlaying(false); }, [active]);
  useEffect(() => {
    if (!playing || !count) return;
    const timer = window.setInterval(() => setStep(previous => Math.min(count, previous + 1)), 1200);
    return () => window.clearInterval(timer);
  }, [playing, count]);
  useEffect(() => { if (step >= count) setPlaying(false); }, [step, count]);
  if (!run) return <Empty title="未找到彩排存档">请检查 docs/rehearsal_stage3_eval.json。</Empty>;
  const specification = data.rehearsal.tasks[task], stats = data.rehearsal.summary;
  return <><Evidence>彩排阶段 3 · {data.provenance.rehearsal_date} · {data.provenance.rehearsal_revision}</Evidence>
    {!playback && <><div className="rehearsal-funnel"><div><span>全部注入任务</span><strong>{stats.injected ?? '—'}</strong><small>样本入口</small></div><b>→</b><div><span>显现高危尝试</span><strong>{stats.manifested ?? '—'}</strong><small>未显现不计作彩排阻断</small></div><b>→</b><div><span>显现且归因阻断</span><strong>{stats.blocked ?? '—'}</strong><small>{rate(stats.blocked ?? 0, stats.manifested ?? 0)} · 条件阻断率</small></div></div><div className="report-mini-stats"><div><strong>{stats.benign_blocks ?? '—'} / {stats.benign ?? '—'}</strong><span>良性任务彩排误拦</span></div><div><strong>{stats.unavailable ?? '—'} / {stats.events ?? '—'}</strong><span>不可用事件 / 全部彩排事件</span></div><div><strong>{stats.p50 ? (stats.p50 / 1000).toFixed(2) : '—'} s</strong><span>非缓存彩排延迟 p50</span></div><div><strong>{stats.p95 ? (stats.p95 / 1000).toFixed(2) : '—'} s</strong><span>非缓存彩排延迟 p95</span></div></div><Note>这些是尝试调用与归因阻断指标，不是实际攻击成功率。良性样本数量有限；0/32 不证明广义零误报。延迟分位数来自原始文件 summary，其余计数由运行记录重算。</Note></>}
    <Panel title={playback ? '真实案例 · 按调用顺序回放' : '原始注入轨迹与独立良性对照'} eyebrow={playback ? 'ARCHIVED TRACE PLAYER' : 'PAIRED TASK COMPARISON'} aside={<select aria-label={playback ? '选择回放案例' : '选择彩排任务'} value={task} onChange={e => setTask(e.target.value)}>{injected.map(r => <option key={r.task} value={r.task}>{r.task} {r.attributed_blocks ? '· 有归因阻断' : '· 无归因阻断'}</option>)}</select>}>
      <div className="report-panel-body"><div className="case-mission"><span className="eyebrow">任务语料中的原始目标</span><p>{specification?.instruction ?? '当前语料未找到目标，未合成补全。'}</p><small>来源文件：{specification?.inject_file ?? '未记录'} · 载荷：{run.payload} · Trace：{run.trace_id}</small></div>
        {playback ? <><div className="player-controls"><button className="button primary" onClick={() => { if (step >= count) setStep(0); setPlaying(v => !v); }}>{playing ? '暂停' : '播放'}</button><button className="button secondary" disabled={!step} onClick={() => { setPlaying(false); setStep(v => Math.max(0, v - 1)); }}>上一步</button><button className="button secondary" disabled={step >= count} onClick={() => { setPlaying(false); setStep(v => Math.min(count, v + 1)); }}>下一步</button><button className="text-button" onClick={() => { setPlaying(false); setStep(0); }}>重置</button><label><span>{step} / {count} 次调用</span><input type="range" aria-label="回放进度" min="0" max={count} value={step} onChange={e => { setPlaying(false); setStep(Number(e.target.value)); }} /></label></div><div className="story-rail"><span>任务目标</span><i>→</i><span>低信任来源</span><i>→</i><span>候选调用</span><i>→</i><span>裁决与返回</span><i>→</i><span>运行结束</span></div><p className="muted small">历史回放，不执行工具。播放节奏为展示动画，不表示真实时间；当前展示到第 {step} 次调用。</p><CallCards calls={run.calls} limit={step} />{step === 0 && <Empty title="点击播放或下一步查看调用证据" />}{step === count && <div className="case-summary"><h3>存档中的结束状态</h3><p>Agent 运行结束标记：{run.completed ? '已结束' : '未正常结束'}；高危尝试：{run.manifested ? '显现' : '未显现'}；归因阻断：{run.attributed_blocks} 次。</p><p>{run.summary}</p><small>运行结束标记不等于已通过独立的合法任务正确性检查。</small></div>}</> : <><div className="grid-two paired-trajectories"><div><div className="trajectory-heading"><Badge tone="amber">注入运行 I5</Badge><span>{run.calls.length} 次尝试调用</span></div><CallCards calls={run.calls} /></div><div><div className="trajectory-heading"><Badge tone="teal">独立良性对照 B1</Badge><span>{benign?.calls.length ?? 0} 次尝试调用</span></div>{benign ? <CallCards calls={benign.calls} /> : <Empty title="缺少同任务良性对照" />}<Note>B1 是独立采样的良性运行，不是当前调用的净化影子轨迹。</Note></div></div><h4>净化影子重跑 · 已存档的风险信号对照</h4><div className="shadow-comparisons">{run.rehearsal_events.length ? run.rehearsal_events.map((event, i) => <article key={i}><header><strong>彩排事件 {i + 1}</strong><span className={`shadow-status ${event.status}`}>{event.status === 'attributed' ? '归因到低信任内容' : event.status === 'unavailable' ? '无法归因' : '未归因'}</span></header><div className="signal-pair"><div><span>原始风险信号</span><strong>{event.signals.join(' · ') || '未记录'}</strong></div><b>→</b><div><span>影子风险信号</span><strong>{event.status === 'unavailable' ? '不可用' : event.replay_signals?.join(' · ') || '无记录到的风险信号'}</strong></div></div><small>净化来源 {event.source_count ?? '—'} · 耗时 {(event.duration_ms / 1000).toFixed(2)} s{event.reason ? ` · ${event.reason}` : ''}</small></article>) : <p className="muted">本次运行没有彩排事件。</p>}</div><Note>此 JSON 只保留彩排信号摘要，未保存逐步影子调用和净化文本差异，因此这里不生成不存在的影子轨迹或原文引用。</Note></>}
        <button className="text-button" onClick={() => downloadJson(`${task}-rehearsal-evidence.json`, { provenance: data.provenance, source_file: 'rehearsal_stage3_eval.json', injected: run, independent_benign: benign })}>导出当前案例证据</button>
      </div></Panel></>;
}
export function PresentationPage() {
  const [data, setData] = useState<Presentation | null>(null), [error, setError] = useState('');
  const [tab, setTab] = useState('results'), [presenting, setPresenting] = useState(false);
  useEffect(() => { const abort = new AbortController(); getJson<Presentation>('/api/console/presentation', abort.signal).then(setData).catch(e => { if (!abort.signal.aborted) setError(String(e)); }); return () => abort.abort(); }, []);
  useEffect(() => { document.body.classList.toggle('presentation-mode', presenting); return () => document.body.classList.remove('presentation-mode'); }, [presenting]);
  useEffect(() => { const exit = (e: KeyboardEvent) => { if (e.key === 'Escape') setPresenting(false); }; window.addEventListener('keydown', exit); return () => window.removeEventListener('keydown', exit); }, []);
  if (error) return <Note tone="warning">报告数据读取失败：{error}。请确认已重启新版控制台服务。</Note>;
  if (!data) return <div className="loading-state" role="status">正在读取历史实验分片与彩排记录…</div>;
  return <div className="presentation-page"><div className="report-hero"><div><span className="eyebrow">TRACESHIELD / EVIDENCE IN VIEW</span><h2>从防护结果，走到每一次决策。</h2><p>效果、覆盖、行为证据与隔离彩排，沿同一条证据链展开。</p><div className="report-hero-tags"><span>原始分片计算</span><span>错误 / 未知独立保留</span><span>真实实验与合成演示分离</span></div></div><div className="report-hero-number"><strong>{data.runs.length.toLocaleString()}</strong><span>银行攻击运行 · 三种模式合计</span><small>另含 {data.rehearsal.summary.total ?? 0} 次彩排实验运行</small></div></div>
    <div className="report-toolbar"><div className="tabs report-tabs">{[['results', '01 效果与代价'], ['coverage', '02 覆盖矩阵'], ['playback', '03 案例回放'], ['rehearsal', '04 彩排对照']].map(([id, title]) => <button key={id} className={tab === id ? 'active' : ''} onClick={() => setTab(id)}>{title}</button>)}</div><div className="report-actions"><button className="button secondary" onClick={() => setPresenting(v => !v)}>{presenting ? '退出展示' : '展示模式'}</button><button className="button secondary" onClick={() => window.print()}>打印 / PDF</button><button className="icon-button" title="导出全部报告证据 JSON" aria-label="导出全部报告证据" onClick={() => downloadJson('agent-guard-report-evidence.json', data)}><Icon name="download" size={18} /></button></div></div>
    {data.warnings.map((warning, i) => <Note tone="warning" key={i}>{warning}</Note>)}
    <section className={`report-section ${tab === 'results' ? 'active' : ''}`}><Results data={data} /></section><section className={`report-section ${tab === 'coverage' ? 'active' : ''}`}><Coverage data={data} /></section><section className={`report-section ${tab === 'playback' ? 'active' : ''}`}><Rehearsal data={data} playback active={tab === 'playback'} /></section><section className={`report-section ${tab === 'rehearsal' ? 'active' : ''}`}><Rehearsal data={data} /></section>
    <details className="provenance-details"><summary>数据来源与证据清单 · {data.files.length} 个存档文件</summary><p>数据类型：{data.provenance.kind} · {data.provenance.commit}。页面读取当前仓库存档，不启动模型或新实验。</p><p>银行模型：{[...new Set(data.metadata.map(m => m.model))].join(', ')} · 检测器：{[...new Set(data.metadata.map(m => m.guard_detector_model).filter(Boolean))].join(', ')} · AgentDojo：{[...new Set(data.metadata.map(m => m.benchmark_version))].join(', ')}</p><p>任务描述来自当前 examples/rehearsal/tasks.yaml；不视为原始运行的冻结快照。{data.provenance.rehearsal_revision}。</p><div className="table-scroll"><table><thead><tr><th>数据文件</th><th>SHA-256 · 当前存档校验值</th></tr></thead><tbody>{data.files.map(f => <tr key={f.name}><td>{f.name}</td><td className="mono">{f.sha256}</td></tr>)}</tbody></table></div></details>
  </div>;
}
