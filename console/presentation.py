"""Read-only presentation data derived from archived experiments."""
from __future__ import annotations

import hashlib
import json
import math
from datetime import UTC, datetime
from pathlib import Path

import yaml

from guard.naming import archive_shards


def wilson(successes: int, total: int) -> list[float] | None:
    if not total:
        return None
    z = 1.959963984540054
    p = successes / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return [max(0, center - margin), min(1, center + margin)]


def build_presentation(root: Path) -> dict:
    files, runs, warnings, metadata = [], [], [], []

    def read(path: Path):
        raw = path.read_bytes()
        value = json.loads(raw.decode('utf-8'))
        files.append({'name': path.name, 'sha256': hashlib.sha256(raw).hexdigest(),
                      'updated_at': datetime.fromtimestamp(path.stat().st_mtime, UTC).isoformat()})
        return value

    for arm in ('direct', 'traceshield_monitor', 'traceshield'):
        for path in archive_shards(root / 'docs', arm):
            try:
                data = read(path)
                metadata.append({key: data.get(key) for key in (
                    'timestamp', 'model', 'guard_detector_model', 'benchmark_version')})
                for row_index, row in enumerate(data.get('rows', [])):
                    if not row.get('attack'):
                        continue
                    for run_index, run in enumerate(row.get('runs', [])):
                        decisions = run.get('decisions', [])
                        error = run.get('error') or None
                        success = run.get('attack_success')
                        runs.append({
                            'id': f'{path.stem}:{row_index}:{run_index}',
                            'file': path.name, 'arm': arm,
                            'task': row.get('user_task_id', 'unknown'),
                            'target': row.get('injection_task_id', 'unknown'),
                            'attack': row['attack'], 'trace_id': run.get('trace_id'),
                            'outcome': ('unknown' if error or not isinstance(success, bool)
                                        else 'success' if success else 'failed'),
                            'utility': run.get('utility'), 'visible': run.get('attack_observed'),
                            'error': error, 'elapsed_s': run.get('elapsed_s'),
                            'tokens': run.get('agent_tokens'),
                            'has_block': any(d.get('action') == 'BLOCK' for d in decisions),
                            'calls': run.get('requested_tool_calls', []), 'decisions': decisions,
                        })
            except (OSError, ValueError, TypeError, AttributeError) as exc:
                warnings.append(f'{path.name}: {exc}')

    arms = []
    for arm in ('direct', 'traceshield_monitor', 'traceshield'):
        selected = [run for run in runs if run['arm'] == arm]
        successes = sum(run['outcome'] == 'success' for run in selected)
        unknown = sum(run['outcome'] == 'unknown' for run in selected)
        arms.append({
            'arm': arm, 'total': len(selected), 'successes': successes, 'unknown': unknown,
            'utility': sum(run['utility'] is True for run in selected),
            'utility_unknown': sum(not isinstance(run['utility'], bool) for run in selected),
            'visible': sum(run['visible'] is True for run in selected),
            'block_runs': sum(run['has_block'] for run in selected),
            'ci': None if unknown else wilson(successes, len(selected)),
        })
    cves = []
    try:
        cases = read(root / 'docs/cve_reproduction.json')
        if not isinstance(cases, list) or not all(
                isinstance(case, dict) and isinstance(case.get('cve'), dict)
                and isinstance(case.get('calls'), list) for case in cases):
            raise ValueError('CVE 存档格式错误')
        cves = cases
    except (OSError, ValueError, TypeError) as exc:
        warnings.append(f'CVE 数据: {exc}')

    rehearsal = {'runs': [], 'summary': {}, 'tasks': {}}
    rehearsal_date = '原始运行未记录日期'
    try:
        data = read(root / 'docs/rehearsal_stage3_eval.json')
        rehearsal_date = data.get('timestamp') or rehearsal_date
        rehearsal['runs'] = [{key: run.get(key) for key in (
            'task', 'cell', 'payload', 'completed', 'refused', 'elapsed_s', 'agent_tokens',
            'calls', 'manifested', 'summary', 'trace_id', 'rehearsal_events', 'attributed_blocks',
        )} for run in data.get('runs', [])]
        injected = [r for r in rehearsal['runs'] if r['cell'] == 'I5']
        benign = [r for r in rehearsal['runs'] if r['cell'] == 'B1']
        events = [e for r in rehearsal['runs'] for e in (r['rehearsal_events'] or [])]
        rehearsal['summary'] = {
            'total': len(rehearsal['runs']), 'injected': len(injected), 'benign': len(benign),
            'manifested': sum(r['manifested'] is True for r in injected),
            'blocked': sum(r['manifested'] is True and bool(r['attributed_blocks'])
                           for r in injected),
            'benign_blocks': sum(bool(r['attributed_blocks']) for r in benign),
            'events': len(events),
            'unavailable': sum(e.get('status') == 'unavailable' for e in events),
            'p50': data.get('summary', {}).get('latency_ms_p50'),
            'p95': data.get('summary', {}).get('latency_ms_p95'),
            'tokens': sum(r['agent_tokens'] or 0 for r in rehearsal['runs']),
        }
        task_path = root / 'examples/rehearsal/tasks.yaml'
        task_data = yaml.safe_load(task_path.read_text(encoding='utf-8'))
        rehearsal['tasks'] = {t['id']: {'instruction': t.get('instruction'),
                                      'inject_file': t.get('inject_file')}
                              for t in task_data.get('tasks', [])}
    except (OSError, ValueError, TypeError, AttributeError, yaml.YAMLError) as exc:
        warnings.append(f'彩排数据: {exc}')
    bank_dates = sorted({str(item['timestamp'])[:10] for item in metadata if item['timestamp']})
    return {'arms': arms, 'runs': runs, 'rehearsal': rehearsal, 'cves': cves, 'files': files,
            'metadata': metadata, 'warnings': warnings,
            'provenance': {'kind': '历史报告存档', 'commit': '原始运行未记录提交 SHA',
                           'bank_date': ' 至 '.join(dict.fromkeys((bank_dates[0], bank_dates[-1])))
                           if bank_dates else '原始运行未记录日期',
                           'rehearsal_date': rehearsal_date,
                           'rehearsal_revision': '彩排统计来自存档，不代表当前代码的重新评测结果'}}
