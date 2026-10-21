"""Standalone, read-only console. Never creates or migrates an audit database.

Run from the repository: uv run python console/server.py
The guard package is used only for its existing redaction and DAG presentation helpers.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
from collections import Counter
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import uvicorn
import yaml
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from guard.audit.redact import redact_payload, redact_text  # noqa: E402
from guard.audit.trace import rebuild_dag  # noqa: E402
from console.presentation import build_presentation  # noqa: E402

REPORTS = {
    "report.md", "bankfull_banking_report.md", "cve_reproduction_report.md",
    "rehearsal_stage3_report.md", "agentdojo_kimi_k26_guard_deepseek_report.md",
}


def decode(value: str | None, default: Any = None) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return default


def sanitize(value: Any) -> Any:
    """Apply the existing redactor, also masking embedded URLs and bearer secrets."""
    value = redact_payload(value)
    if isinstance(value, str):
        value = re.sub(
            r"(?i)\b(api[_-]?(?:key|secret|token)|password|passwd|credential)"
            r"([\"']?\s*[:=]\s*[\"']?)[^\s\"',;}]+",
            r"\1\2[REDACTED]", value,
        )
        value = re.sub(r"\b(?:sk-|ghp_|github_pat_)[A-Za-z0-9_-]{12,}", "[REDACTED]", value)
        value = re.sub(r"(?i)Bearer\s+[A-Za-z0-9._~+/-]+=*", "Bearer [REDACTED]", value)
        return re.sub(r"(https?://[^\s/\"'<>?#]+)(/[^\s\"'<>]*)?", r"\1/[REDACTED:PATH]", value)
    if isinstance(value, dict):
        return {key: sanitize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    return value


class ReadOnlyAudit:
    """Read interface accepted by rebuild_dag; no AuditStore instance is created."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def events_by_trace(self, trace_id: str):
        return self.connection.execute(
            "SELECT * FROM events WHERE trace_id = ? ORDER BY event_id", (trace_id,)
        ).fetchall()

    def calls_by_trace(self, trace_id: str):
        return self.connection.execute(
            "SELECT * FROM calls WHERE trace_id = ? ORDER BY ts, call_id", (trace_id,)
        ).fetchall()

    def source_by_id(self, source_id: str):
        return self.connection.execute(
            "SELECT * FROM sources WHERE source_id = ?", (source_id,)
        ).fetchone()


@contextmanager
def database(path: Path):
    if not path.is_file():
        raise FileNotFoundError("审计库尚不存在；可先查看已有对抗报告或切换演示场景。")
    connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=3)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only = ON")
        connection.execute("BEGIN")
        yield connection
    finally:
        connection.close()


def traces(connection: sqlite3.Connection) -> list[dict]:
    rows = connection.execute("""
        SELECT e.trace_id, MIN(e.session_id) session_id, MIN(e.ts) started_at,
               MAX(e.ts) last_event_at, COUNT(*) event_count
        FROM events e GROUP BY e.trace_id ORDER BY last_event_at DESC LIMIT 200
    """).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        mission = connection.execute(
            "SELECT spec_json FROM mission_versions WHERE session_id = ? "
            "ORDER BY version DESC LIMIT 1", (row["session_id"],)
        ).fetchone()
        counts = dict(connection.execute(
            "SELECT d.action, COUNT(*) FROM decisions d JOIN calls c ON c.call_id = d.call_id "
            "WHERE c.trace_id = ? GROUP BY d.action", (row["trace_id"],)
        ).fetchall())
        item.update(goal=decode(mission[0], {}).get("goal", "未记录任务目标") if mission else "未记录任务目标",
                    counts=counts,
                    call_count=connection.execute(
                        "SELECT COUNT(*) FROM calls WHERE trace_id = ?", (row["trace_id"],)
                    ).fetchone()[0])
        result.append(item)
    return result


def incident(connection: sqlite3.Connection, trace_id: str) -> dict:
    store = ReadOnlyAudit(connection)
    events = store.events_by_trace(trace_id)
    if not events:
        raise HTTPException(404, "未找到该事件链路")
    try:
        # Reuse the presentation algorithm without opening a writable AuditStore.
        graph = rebuild_dag(store, trace_id)
    except (KeyError, ValueError) as exc:
        graph = {"trace_id": trace_id, "session_id": events[0]["session_id"],
                 "nodes": [], "edges": [], "impacts": [], "timeline": [],
                 "graph_error": str(exc)}
    graph["timeline"] = [
        {"event_id": row["event_id"], "ts": row["ts"], "type": row["type"],
         "call_id": row["call_id"], "agent_id": row["agent_id"],
         "source_id": row["source_id"],
         "payload": decode(row["redacted_payload_json"] or row["payload_json"], {})}
        for row in events
        if row["type"] not in {"llm_request", "llm_response"}
    ]
    graph["hidden_model_events"] = sum(
        row["type"] in {"llm_request", "llm_response"} for row in events
    )
    mission = connection.execute(
        "SELECT spec_json FROM mission_versions WHERE session_id = ? "
        "ORDER BY version DESC LIMIT 1", (graph["session_id"],)
    ).fetchone()
    graph["mission"] = decode(mission[0], {}) if mission else {}
    graph["calls"] = []
    for row in store.calls_by_trace(trace_id):
        decision = connection.execute(
            "SELECT * FROM decisions WHERE call_id = ? ORDER BY ts DESC LIMIT 1",
            (row["call_id"],),
        ).fetchone()
        item = {key: row[key] for key in row.keys() if key != "arguments_json"}
        item["arguments"] = decode(row["arguments_json"], {})
        item["decision"] = None
        if decision:
            item["decision"] = {
                key: decision[key] for key in decision.keys()
                if key not in {"rule_ids_json", "matched_fields_json"}
            }
            item["decision"]["rule_ids"] = decode(decision["rule_ids_json"], [])
            item["decision"]["matched_fields"] = decode(decision["matched_fields_json"], {})
        graph["calls"].append(item)
    source_ids = {row["source_id"] for row in events if row["source_id"]}
    # Preserve parent source references, including writes from a different trace.
    graph["sources"] = []
    for source_id in sorted(source_ids):
        row = store.source_by_id(source_id)
        if row is None:
            continue
        item = {key: row[key] for key in row.keys() if key != "span_json"}
        item["span"] = decode(row["span_json"])
        labels = connection.execute(
            "SELECT labels_json, propagation_basis, field_path FROM data_labels "
            "WHERE source_id = ? ORDER BY label_id", (source_id,)
        ).fetchall()
        item["labels"] = sorted({label for entry in labels
                                  for label in decode(entry["labels_json"], [])})
        item["propagation"] = [dict(basis=entry["propagation_basis"], field=entry["field_path"])
                               for entry in labels]
        graph["sources"].append(item)
    graph["approvals"] = [dict(row) for row in connection.execute(
        "SELECT a.approval_id, a.call_id, a.status, a.created_at, a.expires_at "
        "FROM approvals a JOIN calls c ON c.call_id = a.call_id WHERE c.trace_id = ?",
        (trace_id,),
    )]
    return sanitize(graph)


def evaluations() -> dict:
    """Aggregate checked-in artifacts only; never runs a model or an experiment."""
    arms = []
    warnings = []
    for arm in ("direct", "agent_guard", "agent_guard_monitor"):
        attacks, clean, files = [], [], []
        for path in sorted((ROOT / "docs").glob(f"bankfull_{arm}_shard*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                for row in data.get("rows", []):
                    for run in row.get("runs", []):
                        (attacks if row.get("attack") else clean).append(run)
                files.append(path.name)
            except (OSError, ValueError, TypeError) as exc:
                warnings.append(f"{path.name}: {exc}")
        arms.append({
            "arm": arm, "attacks": len(attacks),
            "successes": sum(run.get("attack_success") is True for run in attacks),
            "utility": sum(run.get("utility") is True for run in attacks),
            "visible": sum(run.get("attack_observed") is True for run in attacks),
            "clean": len(clean), "clean_utility": sum(run.get("utility") is True for run in clean),
            "files": files,
        })
    cve_path = ROOT / "docs/cve_reproduction.json"
    try:
        cves = json.loads(cve_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        cves = []
    corpus_path = ROOT / "examples/attack_corpus/cases.yaml"
    try:
        corpus = yaml.safe_load(corpus_path.read_text(encoding="utf-8")).get("cases", [])
    except (OSError, yaml.YAMLError):
        corpus = []
    try:
        report = (ROOT / "docs/report.md").read_text(encoding="utf-8")
    except OSError:
        report = ""
    recorded = {}
    for line in report.splitlines():
        fields = [part.strip() for part in line.strip().strip("|").split("|")]
        if len(fields) == 7 and fields[3] in {"ALLOW", "CONFIRM", "BLOCK"}:
            recorded[fields[0]] = {"action": fields[3], "rule_ids": fields[4], "latency": fields[6]}
    cases = [{"id": case["id"], "category": case["category"], "attack": case["attack"],
              "goal": case["goal"], "tool": case["tool"], "result": recorded.get(case["id"])}
             for case in corpus]
    return sanitize({"arms": arms, "cves": cves, "cases": cases, "warnings": warnings,
                     "report": "bankfull_banking_report.md", "case_report": "report.md",
                     "scope": "仓库历史报告；单格单次运行，模拟业务工具，不含真实执行隔离验证。"})


def create_console(db_path: Path, policy_path: Path) -> FastAPI:
    app = FastAPI(title="Agent Guard · Read-only Console", docs_url=None, redoc_url=None)
    dist = ROOT / "console/dist"

    @app.get("/api/console/bootstrap")
    def bootstrap():
        payload: dict = {
            "generated_at": datetime.now(UTC).isoformat(), "readonly": True,
            "database": {"name": db_path.name, "connected": False, "message": ""},
            "traces": [], "summary": {"sessions": 0, "calls": 0, "events": 0,
                                      "sources": 0, "decisions": {}, "source_types": {},
                                      "activity": [], "rules": []},
            "policy": {"version": "未知", "rules": [], "trusted_domains": []},
        }
        try:
            with database(db_path) as connection:
                payload["traces"] = traces(connection)
                summary = payload["summary"]
                for key, table in (("sessions", "sessions"), ("calls", "calls"),
                                   ("events", "events"), ("sources", "sources")):
                    summary[key] = connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                summary["decisions"] = dict(connection.execute(
                    "SELECT action, COUNT(*) FROM decisions GROUP BY action").fetchall())
                summary["source_types"] = dict(connection.execute(
                    "SELECT type, COUNT(*) FROM sources GROUP BY type").fetchall())
                summary["activity"] = [dict(row) for row in connection.execute("""
                    SELECT substr(ts, 1, 13) hour, COUNT(*) total,
                      SUM(CASE WHEN type = 'decision_made' THEN 1 ELSE 0 END) decisions
                    FROM events GROUP BY hour ORDER BY hour DESC LIMIT 12
                """).fetchall()][::-1]
                rule_ids = Counter()
                for row in connection.execute("SELECT rule_ids_json FROM decisions"):
                    rule_ids.update(decode(row[0], []))
                summary["rules"] = [{"id": key, "count": count}
                                    for key, count in rule_ids.most_common(8)]
                payload["database"]["connected"] = True
        except (OSError, sqlite3.Error) as exc:
            payload["database"]["message"] = str(exc)
        try:
            policy = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
            payload["policy"] = {"version": str(policy.get("version", "未知")),
                                 "rules": policy.get("rules", []),
                                 "trusted_domains": policy.get("trusted_domains", []),
                                 "file": policy_path.name}
        except (OSError, yaml.YAMLError, AttributeError) as exc:
            payload["policy"]["error"] = str(exc)
        payload["evaluations"] = evaluations()
        return sanitize(payload)

    @app.get("/api/console/presentation")
    def presentation():
        return sanitize(build_presentation(ROOT))

    @app.get("/api/incidents")
    def list_incidents():
        try:
            with database(db_path) as connection:
                return sanitize(traces(connection))
        except (OSError, sqlite3.Error) as exc:
            raise HTTPException(503, str(exc)) from exc

    @app.get("/api/incidents/{trace_id}")
    def get_incident(trace_id: str):
        try:
            with database(db_path) as connection:
                return incident(connection, trace_id)
        except (OSError, sqlite3.Error) as exc:
            raise HTTPException(503, str(exc)) from exc

    @app.get("/api/reports/{name}", response_class=PlainTextResponse)
    def get_report(name: str):
        if name not in REPORTS:
            raise HTTPException(404, "报告不存在")
        path = ROOT / "docs" / name
        if not path.is_file():
            raise HTTPException(404, "该报告尚未生成")
        return redact_text(path.read_text(encoding="utf-8"))

    @app.get("/{path:path}")
    def frontend(path: str):
        if path.startswith("api/"):
            raise HTTPException(404, "只读控制台未提供此接口")
        target = (dist / path).resolve()
        if target.is_relative_to(dist.resolve()) and target.is_file():
            return FileResponse(target)
        if Path(path).suffix:
            raise HTTPException(404, "静态资源不存在")
        if (dist / "index.html").is_file():
            return FileResponse(dist / "index.html")
        return PlainTextResponse("前端尚未构建。请在 console/ 运行 npm run build，或启动 npm run dev。", 503)

    return app


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8001)
    parser.add_argument("--db", type=Path,
                        default=Path(os.environ.get("AGENT_GUARD_DB_PATH", ROOT / "agent-guard.db")))
    parser.add_argument("--policy", type=Path,
                        default=Path(os.environ.get("AGENT_GUARD_POLICY_FILE", ROOT / "policies/default.yaml")))
    args = parser.parse_args()
    uvicorn.run(create_console(args.db, args.policy), host=args.host, port=args.port)
