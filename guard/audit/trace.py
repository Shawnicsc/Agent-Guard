"""从追加审计事件重建可解释的攻击路径 DAG 与时间轴。"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict, deque
from urllib.parse import urlsplit

from guard.audit.redact import redact_text, redact_url
from guard.audit.store import AuditStore


def _resource(tool: str, args: dict) -> tuple[str, str] | None:
    field = {
        "fs.read": "path", "fs.write": "path", "net.fetch": "url",
        "git.push": "remote", "memory.read": "key", "memory.write": "key",
        "mcp.list": "server", "mcp.call": "server",
    }.get(tool)
    if field is None or not isinstance(args.get(field), str):
        return None
    value = args[field]
    key = hashlib.sha256(f"{tool}:{value}".encode()).hexdigest()[:16]
    if tool == "net.fetch":
        # 查询串/路径可能是编码后的密钥；详情视图只展示目的主机。
        parsed = urlsplit(value)
        value = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme else "[invalid URL]"
    return f"resource:{key}", redact_text(value)


def _assert_dag(nodes: dict[str, dict], edges: list[dict]) -> None:
    incoming = {key: 0 for key in nodes}
    outgoing: dict[str, list[str]] = defaultdict(list)
    for edge in edges:
        incoming[edge["target"]] += 1
        outgoing[edge["source"]].append(edge["target"])
    ready = deque(key for key, degree in incoming.items() if degree == 0)
    visited = 0
    while ready:
        node = ready.popleft()
        visited += 1
        for target in outgoing[node]:
            incoming[target] -= 1
            if incoming[target] == 0:
                ready.append(target)
    if visited != len(nodes):
        raise ValueError("审计调用关系存在环，无法构建攻击路径 DAG")


def rebuild_dag(store: AuditStore, trace_id: str) -> dict:
    """只读重建；推断关联显式标注 inferred，不伪称模型内部因果。"""
    rows = store.events_by_trace(trace_id)
    if not rows:
        raise KeyError(f"trace 不存在: {trace_id}")

    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    seen_edges: set[tuple[str, str, str]] = set()
    timeline: list[dict] = []
    impacts: list[dict] = []
    session_id = next((row["session_id"] for row in rows if row["session_id"]), None)
    root_id = f"session:{session_id}"
    nodes[root_id] = {"id": root_id, "kind": "session", "label": session_id}

    def add_node(node_id: str, kind: str, label: str, **extra) -> None:
        nodes.setdefault(node_id, {"id": node_id, "kind": kind,
                                   "label": redact_text(str(label)), **extra})

    def add_edge(source: str, target: str, kind: str,
                 certainty: str = "observed") -> None:
        key = (source, target, kind)
        if key not in seen_edges:
            edges.append({"source": source, "target": target,
                          "kind": kind, "certainty": certainty})
            seen_edges.add(key)

    calls = store.calls_by_trace(trace_id)
    for call in calls:
        call_id = f"call:{call['call_id']}"
        agent_id = f"agent:{call['agent_id']}"
        add_node(call_id, "tool_call", call["tool"])
        add_node(agent_id, "agent", call["agent_id"])
        add_edge(agent_id, call_id, "called")
        if call["parent_call_id"]:
            parent_id = f"call:{call['parent_call_id']}"
            add_node(parent_id, "tool_call", "parent tool call")
            add_edge(parent_id, call_id, "delegated")
        else:
            add_edge(root_id, agent_id, "started")

    for row in rows:
        payload = json.loads(row["redacted_payload_json"] or "{}")
        raw_payload = json.loads(row["payload_json"] or "{}")
        event_type = row["type"]
        timeline.append({"event_id": row["event_id"], "ts": row["ts"],
                         "type": event_type, "call_id": row["call_id"],
                         "agent_id": row["agent_id"], "source_id": row["source_id"],
                         "payload": payload})
        call_id = f"call:{row['call_id']}" if row["call_id"] else None
        if row["source_id"]:
            source_id = f"source:{row['source_id']}"
            record = store.source_by_id(row["source_id"])
            source_type = record["type"] if record else "source"
            uri = record["uri"] if record else row["source_id"]
            add_node(source_id, "source", redact_url(uri), source_type=source_type,
                     content_hash=record["content_hash"] if record else None)
            if call_id and event_type in {"source_recorded", "tool_executed",
                                          "memory_read", "memory_written", "mcp_relayed"}:
                add_edge(call_id, source_id, "produced")
            if record and record["parent_source_id"]:
                parent_id = f"source:{record['parent_source_id']}"
                parent = store.source_by_id(record["parent_source_id"])
                add_node(parent_id, "source",
                         redact_url(parent["uri"]) if parent else record["parent_source_id"])
                add_edge(parent_id, source_id, "derived_from")
            if not call_id:
                add_edge(root_id, source_id, "introduced")
        if event_type == "semantic_analyzed" and call_id:
            for source in raw_payload.get("sources", []):
                source_id = f"source:{source}"
                record = store.source_by_id(source)
                add_node(source_id, "source", redact_url(record["uri"]) if record else source)
                add_edge(source_id, call_id, "possibly_influenced", "inferred")
        if event_type == "decision_made" and call_id and row["decision_id"]:
            decision_id = f"decision:{row['decision_id']}"
            add_node(decision_id, "decision", payload.get("action", ""),
                     rule_ids=payload.get("rule_ids", []),
                     reason=payload.get("reason", ""))
            add_edge(call_id, decision_id, "judged")
        if event_type == "subagent_spawned" and row["agent_id"]:
            child_id = f"agent:{row['agent_id']}"
            add_node(child_id, "agent", row["agent_id"])
            parent = call_id or root_id
            add_edge(parent, child_id, "spawned")

    for call in calls:
        args = json.loads(call["arguments_json"])
        resource = _resource(call["tool"], args)
        if resource is None:
            continue
        resource_id, label = resource
        add_node(resource_id, "resource", label)
        call_id = f"call:{call['call_id']}"
        add_edge(call_id, resource_id, "targeted")
        if any(row["call_id"] == call["call_id"] and row["type"] == "tool_executed"
               for row in rows):
            impacts.append({"tool": call["tool"], "target": label,
                            "call_id": call["call_id"]})

    _assert_dag(nodes, edges)
    return {"trace_id": trace_id, "session_id": session_id,
            "nodes": list(nodes.values()), "edges": edges,
            "timeline": timeline, "impacts": impacts}
