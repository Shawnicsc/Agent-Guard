"""按会话开始时间查询审计历史；不创建或修改数据库。"""

from __future__ import annotations

import json
import sqlite3
from collections import Counter
from datetime import UTC, date, datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


def _object(value: str | None) -> dict:
    try:
        result = json.loads(value or "{}")
        return result if isinstance(result, dict) else {}
    except (ValueError, TypeError):
        return {}


def query_history(
    connection: sqlite3.Connection,
    *,
    group_by: str = "day",
    timezone: str = "Asia/Shanghai",
    start: str | None = None,
    end: str | None = None,
    period: str | None = None,
    origin: str | None = None,
    application: str | None = None,
    dataset_id: str | None = None,
    batch_id: str | None = None,
    search: str = "",
    include_shadow: bool = False,
    page: int = 1,
    page_size: int = 25,
    export_all: bool = False,
) -> dict:
    if group_by not in {"day", "month"}:
        raise ValueError("时间分类必须为 day 或 month")
    if origin and origin not in {"production", "evaluation", "demo", "unknown"}:
        raise ValueError("运行来源无效")
    try:
        zone = ZoneInfo(timezone)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError("无效时区") from exc
    try:
        start_date = date.fromisoformat(start) if start else None
        end_date = date.fromisoformat(end) if end else None
        if start_date and end_date and start_date > end_date:
            raise ValueError("开始日期不能晚于结束日期")
        if period:
            parsed = date.fromisoformat(period if group_by == "day" else period + "-01")
            if parsed.strftime("%Y-%m-%d" if group_by == "day" else "%Y-%m") != period:
                raise ValueError("时间分类格式错误")
    except ValueError as exc:
        raise ValueError(f"日期参数错误: {exc}") from exc
    if page < 1 or not 1 <= page_size <= 100:
        raise ValueError("分页参数无效")

    # 分别聚合再关联，避免调用、事件与多次裁决连接造成计数相乘。
    rows = connection.execute("""
        WITH ca AS (
            SELECT session_id, COUNT(*) call_count FROM calls GROUP BY session_id
        ), da AS (
            SELECT c.session_id,
                SUM(d.action = 'ALLOW') allowed, SUM(d.action = 'BLOCK') blocked,
                SUM(d.action = 'CONFIRM') confirmed
            FROM decisions d JOIN calls c ON c.call_id = d.call_id GROUP BY c.session_id
        ), ea AS (
            SELECT session_id, MIN(trace_id) trace_id, MAX(ts) last_event_at,
                COUNT(*) event_count,
                SUM(type IN ('tool_executed', 'tool_refused')) execution_records
            FROM events GROUP BY session_id
        ), ma AS (
            SELECT m.session_id, m.spec_json FROM mission_versions m
            WHERE m.version = (SELECT MAX(n.version) FROM mission_versions n
                               WHERE n.session_id = m.session_id)
        )
        SELECT s.*, ea.trace_id, ea.last_event_at, ea.event_count, ea.execution_records,
               ca.call_count, da.allowed, da.blocked, da.confirmed, ma.spec_json
        FROM sessions s LEFT JOIN ca ON ca.session_id = s.session_id
        LEFT JOIN da ON da.session_id = s.session_id
        LEFT JOIN ea ON ea.session_id = s.session_id
        LEFT JOIN ma ON ma.session_id = s.session_id
        ORDER BY s.created_at DESC, s.session_id
    """).fetchall()
    items, periods, facets = (
        [],
        {},
        {"origins": set(), "applications": set(), "datasets": {}, "batches": {}},
    )
    warnings = []
    for row in rows:
        record = dict(row)
        try:
            started = datetime.fromisoformat(record["created_at"])
            if started.tzinfo is None:
                started = started.replace(tzinfo=UTC)
            local_date = started.astimezone(zone).date()
        except (ValueError, TypeError):
            warnings.append(f"会话 {record['session_id']} 的开始时间无效，未计入日期统计")
            continue
        if start_date and local_date < start_date or end_date and local_date > end_date:
            continue
        meta = _object(record["meta_json"])
        context = meta.get("run_context") or {}
        if not isinstance(context, dict):
            context = {}
        context = {**context, "origin": context.get("origin") or "unknown"}
        if context.get("role") == "shadow" and not include_shadow:
            continue
        facets["origins"].add(context["origin"])
        if context.get("application"):
            facets["applications"].add(context["application"])
        if context.get("dataset_id"):
            facets["datasets"][context["dataset_id"]] = (
                context.get("dataset_name") or context["dataset_id"]
            )
        if context.get("batch_id"):
            facets["batches"][context["batch_id"]] = (
                context.get("batch_name") or context["batch_id"]
            )
        if any(
            value and context.get(key) != value
            for key, value in (
                ("origin", origin),
                ("application", application),
                ("dataset_id", dataset_id),
                ("batch_id", batch_id),
            )
        ):
            continue
        goal = _object(record["spec_json"]).get("goal", "未记录任务目标")
        if (
            search
            and search.casefold()
            not in " ".join(
                str(value or "")
                for value in (
                    record["session_id"],
                    record["trace_id"],
                    record["user_id"],
                    goal,
                    *context.values(),
                )
            ).casefold()
        ):
            continue
        key = local_date.strftime("%Y-%m-%d" if group_by == "day" else "%Y-%m")
        item = {
            "session_id": record["session_id"],
            "trace_id": record["trace_id"],
            "user_id": record["user_id"],
            "goal": goal,
            "period": key,
            "started_at": record["created_at"],
            "last_event_at": record["last_event_at"],
            "run_context": context,
            "protection_mode": meta.get("protection_mode"),
            "call_count": record["call_count"] or 0,
            "event_count": record["event_count"] or 0,
            "execution_records": record["execution_records"] or 0,
            "counts": {
                "ALLOW": record["allowed"] or 0,
                "BLOCK": record["blocked"] or 0,
                "CONFIRM": record["confirmed"] or 0,
            },
        }
        periods.setdefault(key, []).append(item)
        if not period or period == key:
            items.append(item)

    def summary(records: list[dict]) -> dict:
        decisions = Counter()
        for item in records:
            decisions.update(item["counts"])
        return {
            "sessions": len(records),
            "batches": len(
                {
                    item["run_context"]["batch_id"]
                    for item in records
                    if item["run_context"].get("batch_id")
                }
            ),
            "calls": sum(item["call_count"] for item in records),
            "events": sum(item["event_count"] for item in records),
            "execution_records": sum(item["execution_records"] for item in records),
            "decisions": dict(decisions),
        }

    total = len(items)
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "group_by": group_by,
        "timezone": timezone,
        "period": period,
        "scope": "按会话开始时间归档；计数为所选会话的累计审计记录，刷新后可更新。",
        "summary": summary(items),
        "periods": [
            {"period": key, **summary(records)}
            for key, records in sorted(periods.items(), reverse=True)
        ],
        "items": items if export_all else items[(page - 1) * page_size : page * page_size],
        "filters": {
            "start": start,
            "end": end,
            "origin": origin,
            "application": application,
            "dataset_id": dataset_id,
            "batch_id": batch_id,
            "search": search,
            "include_shadow": include_shadow,
        },
        "export_all": export_all,
        "page": page,
        "page_size": page_size,
        "total": total,
        "facets": {
            "origins": sorted(facets["origins"]),
            "applications": sorted(facets["applications"]),
            "datasets": [
                {"id": key, "name": value} for key, value in sorted(facets["datasets"].items())
            ],
            "batches": [
                {"id": key, "name": value} for key, value in sorted(facets["batches"].items())
            ],
        },
        "warnings": warnings,
    }
