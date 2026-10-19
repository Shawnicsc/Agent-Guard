"""审计存储：SQLite（WAL）建表 + 追加写入。

表结构一次定型（DESIGN.md 第 4 节：先 SQLite 单机，后期可平移 PostgreSQL）。
D 阶段 trace.py 只读重建，不改写历史。
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from guard.audit.redact import redact_payload
from guard.contracts import (
    AuditEvent,
    ContentSource,
    DataLabel,
    Decision,
    MissionSpec,
    ToolCallEnvelope,
    utcnow,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    meta_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS mission_versions (
    session_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    spec_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (session_id, version)
);
CREATE TABLE IF NOT EXISTS sources (
    source_id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    uri TEXT NOT NULL,
    trust_level TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    parent_source_id TEXT,
    span_json TEXT
);
CREATE TABLE IF NOT EXISTS events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    trace_id TEXT NOT NULL,
    type TEXT NOT NULL,
    session_id TEXT,
    call_id TEXT,
    parent_call_id TEXT,
    agent_id TEXT,
    source_id TEXT,
    decision_id TEXT,
    payload_json TEXT NOT NULL DEFAULT '{}',
    redacted_payload_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_trace ON events(trace_id);
CREATE INDEX IF NOT EXISTS idx_events_call ON events(call_id);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source_id);
CREATE TABLE IF NOT EXISTS calls (
    call_id TEXT PRIMARY KEY,
    trace_id TEXT NOT NULL,
    parent_call_id TEXT,
    session_id TEXT,
    agent_id TEXT,
    tool TEXT NOT NULL,
    arguments_json TEXT NOT NULL,
    arguments_hash TEXT NOT NULL,
    mission_version INTEGER NOT NULL,
    ts TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS decisions (
    decision_id TEXT PRIMARY KEY,
    call_id TEXT NOT NULL,
    action TEXT NOT NULL,
    rule_ids_json TEXT NOT NULL DEFAULT '[]',
    matched_fields_json TEXT NOT NULL DEFAULT '{}',
    reason TEXT NOT NULL DEFAULT '',
    policy_version TEXT NOT NULL DEFAULT '',
    arguments_hash TEXT NOT NULL,
    approval_id TEXT,
    degraded INTEGER NOT NULL DEFAULT 0,
    ts TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS data_labels (
    label_id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id TEXT NOT NULL,
    field_path TEXT NOT NULL,
    labels_json TEXT NOT NULL,
    propagation_basis TEXT NOT NULL,
    ts TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY,
    call_id TEXT NOT NULL,
    arguments_hash TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    user_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS policy_versions (
    version TEXT PRIMARY KEY,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


class AuditStore:
    """单进程 FastAPI + WAL 足够；写入经同一把锁串行化。"""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # ---- 写入 ----

    def save_session(self, session_id: str, user_id: str, meta: dict[str, Any] = None) -> None:
        if meta is None:
            meta = {}
        with self._lock:
            self._conn.execute(
                "INSERT INTO sessions VALUES (?,?,?,?)",
                (session_id, user_id, utcnow().isoformat(), json.dumps(meta, ensure_ascii=False)),
            )
            self._conn.commit()

    def save_mission(self, mission: MissionSpec) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO mission_versions VALUES (?,?,?,?)",
                (mission.session_id, mission.version,
                 mission.model_dump_json(), utcnow().isoformat()),
            )
            self._conn.commit()

    def save_source(self, source: ContentSource) -> None:
        with self._lock:
            span = source.span.model_dump_json() if source.span else None
            self._conn.execute(
                "INSERT OR REPLACE INTO sources VALUES (?,?,?,?,?,?,?)",
                (source.source_id, source.type.value, source.uri, source.trust_level.value,
                 source.content_hash, source.parent_source_id, span),
            )
            self._conn.commit()

    def save_call(self, envelope: ToolCallEnvelope) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO calls VALUES (?,?,?,?,?,?,?,?,?,?)",
                (envelope.call_id, envelope.trace_id, envelope.parent_call_id,
                 envelope.session_id, envelope.agent_id, envelope.tool,
                 json.dumps(envelope.arguments, ensure_ascii=False),
                 envelope.arguments_hash, envelope.mission_version,
                 envelope.ts.isoformat()),
            )
            self._conn.commit()

    def save_decision(self, decision: Decision) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO decisions VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (decision.decision_id, decision.call_id, decision.action.value,
                 json.dumps(decision.rule_ids),
                 json.dumps(decision.matched_fields, ensure_ascii=False),
                 decision.reason, decision.policy_version, decision.arguments_hash,
                 decision.approval_id, int(decision.degraded), decision.ts.isoformat()),
            )
            self._conn.commit()

    def save_data_label(self, label: DataLabel) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO data_labels (source_id,field_path,labels_json,propagation_basis,ts)"
                " VALUES (?,?,?,?,?)",
                (label.source_id, label.field_path,
                 json.dumps([x.value for x in label.labels]),
                 label.propagation_basis.value,
                 utcnow().isoformat()),
            )
            self._conn.commit()

    def append_event(self, event: AuditEvent) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO events (ts,trace_id,type,session_id,call_id,parent_call_id,"
                "agent_id,source_id,decision_id,payload_json,redacted_payload_json) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (event.ts.isoformat(), event.trace_id, event.type.value, event.session_id,
                 event.call_id, event.parent_call_id, event.agent_id, event.source_id,
                 event.decision_id, json.dumps(event.payload, ensure_ascii=False),
                 json.dumps(event.redacted_payload, ensure_ascii=False)
                 if event.redacted_payload is not None
                 else json.dumps(redact_payload(event.payload), ensure_ascii=False)),
            )
            self._conn.commit()
            return cur.lastrowid

    # ---- 查询（D 阶段溯源基础，A 阶段先提供最小查询）----

    def save_approval(self, record) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO approvals VALUES (?,?,?,?,?,?,?,?)",
                record.to_row(),
            )
            self._conn.commit()

    def update_approval(self, record) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE approvals SET status = ? WHERE approval_id = ?",
                (record.status, record.approval_id),
            )
            self._conn.commit()

    def get_approval(self, approval_id: str):
        row = self._conn.execute(
            "SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)
        ).fetchone()
        if row is None:
            return None
        return _row_to_approval(row)

    def approvals_for_call(self, call_id: str) -> list:
        rows = self._conn.execute(
            "SELECT * FROM approvals WHERE call_id = ?", (call_id,)
        ).fetchall()
        return [_row_to_approval(row) for row in rows]

    def approvals_for_hash(self, arguments_hash: str) -> list:
        rows = self._conn.execute(
            "SELECT * FROM approvals WHERE arguments_hash = ? "
            "ORDER BY created_at DESC", (arguments_hash,)
        ).fetchall()
        return [_row_to_approval(row) for row in rows]

    def events_by_trace(self, trace_id: str) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM events WHERE trace_id = ? ORDER BY event_id", (trace_id,)
        ).fetchall()

    def get_decision(self, decision_id: str) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM decisions WHERE decision_id = ?", (decision_id,)
        ).fetchone()


def _row_to_approval(row: sqlite3.Row):
    from datetime import datetime

    from guard.policy.approval import ApprovalRecord

    record = ApprovalRecord(
        approval_id=row["approval_id"], call_id=row["call_id"],
        arguments_hash=row["arguments_hash"], target=row["target"],
        user_id=row["user_id"],
    )
    record.status = row["status"]
    record.created_at = datetime.fromisoformat(row["created_at"])
    record.expires_at = datetime.fromisoformat(row["expires_at"])
    return record
