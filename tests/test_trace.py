"""跨工具与子 Agent 审计事件能还原为无环攻击路径。"""

from __future__ import annotations

import json

from guard.audit.trace import rebuild_dag
from guard.contracts import AuditEvent, EventType
from guard.gateway.session import GatewaySession


def test_rebuild_multi_hop_dag_and_timeline(store, tmp_path):
    session = GatewaySession.create(store, tmp_path / "ws", user_id="u1",
                                    goal="检视项目 README")
    (session.workspace_root / "README.md").write_text("Project readme")
    read = session.make_envelope("fs.read", {"path": "README.md"})
    read_decision = session.decide(read)
    read_result, source = session.try_execute(read, read_decision)
    assert read_result.ok and source is not None

    spawn = session.make_envelope("agent.spawn", {
        "task": "复核 README", "capabilities": ["fs.read"],
    })
    spawn_decision = session.decide(spawn)
    spawn_result, _ = session.try_execute(spawn, spawn_decision)
    assert spawn_result.ok
    child_id = json.loads(spawn_result.output)["agent_id"]
    child = session.child_session(child_id)
    child_call = child.make_envelope("fs.read", {"path": "README.md"})
    assert child_call.parent_call_id == spawn.call_id
    child_decision = child.decide(child_call)
    child_result, _ = child.try_execute(child_call, child_decision)
    assert child_result.ok

    store.append_event(AuditEvent(
        trace_id=session.trace_id, type=EventType.SEMANTIC_ANALYZED,
        session_id=session.mission.session_id, call_id=child_call.call_id,
        agent_id=child_id, payload={"sources": [source.source_id]},
    ))
    graph = rebuild_dag(store, session.trace_id)
    edges = {(edge["source"], edge["target"], edge["kind"])
             for edge in graph["edges"]}
    assert (f"call:{spawn.call_id}", f"agent:{child_id}", "spawned") in edges
    assert (f"call:{spawn.call_id}", f"call:{child_call.call_id}", "delegated") in edges
    assert (f"source:{source.source_id}", f"call:{child_call.call_id}",
            "possibly_influenced") in edges
    assert [row["event_id"] for row in graph["timeline"]] == sorted(
        row["event_id"] for row in graph["timeline"])
    assert any(item["target"] == "README.md" for item in graph["impacts"])


def test_rebuild_unknown_trace_raises(store):
    try:
        rebuild_dag(store, "missing")
    except KeyError:
        pass
    else:
        raise AssertionError("unknown trace must be rejected")
