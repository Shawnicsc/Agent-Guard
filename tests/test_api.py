"""API 层测试：第三方 Agent 经 HTTP 接入网关的路径。"""

from __future__ import annotations

from fastapi.testclient import TestClient

from guard.api.app import create_app


def make_client(tmp_path, monkeypatch):
    import guard.api.app as appmod

    monkeypatch.setattr(appmod.settings, "db_path", tmp_path / "api.db")
    monkeypatch.setattr(appmod.settings, "workspaces_root", tmp_path / "ws")
    app = create_app()
    return TestClient(app)


def test_health(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_create_session_and_decide(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    resp = client.post("/sessions", json={
        "user_id": "u1",
        "goal": "读取 README 并总结",
        "goal_category": "read_document",
    })
    assert resp.status_code == 200
    body = resp.json()
    session_id = body["session_id"]
    assert body["mission"]["goal"] == "读取 README 并总结"

    resp = client.post("/tool-calls/decide", json={
        "session_id": session_id,
        "tool": "fs.read",
        "arguments": {"path": "README.md"},
    })
    assert resp.status_code == 200
    assert resp.json()["action"] == "ALLOW"


def test_decide_unknown_session_404(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    resp = client.post("/tool-calls/decide", json={
        "session_id": "sess_missing",
        "tool": "fs.read",
        "arguments": {},
    })
    assert resp.status_code == 404


def test_decide_unregistered_tool(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    session_id = client.post("/sessions", json={
        "user_id": "u1", "goal": "g",
    }).json()["session_id"]
    resp = client.post("/tool-calls/decide", json={
        "session_id": session_id,
        "tool": "not.a.tool",
        "arguments": {},
    })
    # 网关构造 envelope 时即拒绝未注册工具（400）
    assert resp.status_code == 400


def _make_session(client, user_id="u1", goal="整理文档"):
    resp = client.post("/sessions", json={"user_id": user_id, "goal": goal})
    assert resp.status_code == 200
    return resp.json()["session_id"]


def test_approval_route_flow(tmp_path, monkeypatch):
    """HTTP 确认闭环：CONFIRM 产生 approval_id -> 批准 -> 重试放行。"""
    client = make_client(tmp_path, monkeypatch)
    session_id = _make_session(client)
    args = {"path": "notes.txt", "content": "hi"}

    first = client.post("/tool-calls/decide", json={
        "session_id": session_id, "tool": "fs.write", "arguments": args,
    }).json()
    assert first["action"] == "CONFIRM" and first["approval_id"]

    # 404：不存在的批准记录
    assert client.post("/approvals/appr-missing",
                       json={"user_id": "u1", "approve": True}).status_code == 404
    # 403：非发起用户
    assert client.post(f"/approvals/{first['approval_id']}",
                       json={"user_id": "attacker", "approve": True}).status_code == 403
    # 本人批准
    ok = client.post(f"/approvals/{first['approval_id']}",
                     json={"user_id": "u1", "approve": True})
    assert ok.status_code == 200 and ok.json()["status"] == "approved"

    second = client.post("/tool-calls/decide", json={
        "session_id": session_id, "tool": "fs.write", "arguments": args,
    }).json()
    assert second["action"] == "ALLOW"
    assert "approved_call" in second["rule_ids"]


def test_policies_route(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    resp = client.get("/policies")
    assert resp.status_code == 200
    body = resp.json()
    assert body["version"] == "c3"
    ids = {r["id"] for r in body["rules"]}
    assert "deny_secret_exfiltration" in ids
    assert "pypi.org" in body["trusted_domains"]
    # 高优先级在前
    priorities = [r["priority"] for r in body["rules"]]
    assert priorities == sorted(priorities, reverse=True)


def test_policies_validate_route(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    ok = client.post("/policies/validate", json={
        "content": "version: v\nrules:\n  - id: r\n    priority: 1\n"
                   "    when: {action_is: fs.read}\n    decision: BLOCK\n",
    })
    assert ok.json()["valid"] is True

    bad = client.post("/policies/validate", json={
        "content": "version: v\nrules:\n  - id: r\n    priority: 1\n"
                   "    when: {evil_eval: x}\n    decision: BLOCK\n",
    })
    body = bad.json()
    assert body["valid"] is False and "未注册的谓词" in body["error"]
    # 校验不影响当前生效版本
    assert client.get("/policies").json()["version"] == "c3"


def test_incident_routes(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    created = client.post("/sessions", json={"user_id": "u1", "goal": "读 README"}).json()
    trace_id = created["trace_id"]
    listed = client.get("/incidents")
    assert listed.status_code == 200
    assert trace_id in {item["trace_id"] for item in listed.json()}
    detail = client.get(f"/incidents/{trace_id}")
    assert detail.status_code == 200
    assert detail.json()["trace_id"] == trace_id
    assert client.get("/incidents/missing").status_code == 404


def test_run_batch_inheritance_and_conflict(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    batch = client.post('/run-batches', json={
        'user_id': 'u1', 'run_context': {
            'origin': 'evaluation', 'application': 'custom-agent',
            'dataset_id': 'new-dataset', 'dataset_name': '新的测试集',
            'dataset_version': 'v1', 'batch_name': '第一轮',
        },
    })
    assert batch.status_code == 200
    batch_id = batch.json()['batch_id']
    sessions = []
    for case_id in ('case-1', 'case-2'):
        response = client.post('/sessions', json={
            'user_id': 'u1', 'goal': '读取文档',
            'run_context': {'batch_id': batch_id, 'case_id': case_id},
        })
        assert response.status_code == 200
        sessions.append(response.json())
    assert sessions[0]['session_id'] != sessions[1]['session_id']
    assert all(session['run_context']['dataset_id'] == 'new-dataset' for session in sessions)
    conflict = client.post('/sessions', json={
        'user_id': 'u1', 'goal': '读取文档',
        'run_context': {'batch_id': batch_id, 'dataset_id': 'other-dataset'},
    })
    assert conflict.status_code == 409
    invalid = client.post('/sessions', json={
        'user_id': 'u1', 'goal': '读取文档',
        'run_context': {'origin': 'fabricated'},
    })
    assert invalid.status_code == 422


def test_console_history_updates_and_exports_without_writes(tmp_path, monkeypatch):
    from console.server import create_console

    client = make_client(tmp_path, monkeypatch)
    console = TestClient(create_console(tmp_path / 'api.db', tmp_path / 'not-needed.yaml'))
    assert console.get('/api/console/history').json()['summary']['sessions'] == 0
    created = client.post('/sessions', json={
        'user_id': 'u1', 'goal': '从真实系统进入历史报告',
        'run_context': {'origin': 'production', 'application': 'support-agent'},
    }).json()
    client.post('/tool-calls/decide', json={
        'session_id': created['session_id'], 'tool': 'fs.read',
        'arguments': {'path': 'README.md'},
    })
    data = console.get(
        '/api/console/history?group_by=month&application=support-agent').json()
    assert data['summary']['sessions'] == 1
    assert data['summary']['calls'] == 1
    assert data['items'][0]['trace_id'] == created['trace_id']
    assert console.get('/api/console/history?origin=evaluation').json()['total'] == 0
    export = console.get('/api/console/history?export_all=true').json()
    assert export['items'][0]['session_id'] == created['session_id']
    assert export['export_all'] is True
    assert console.get('/api/console/history?timezone=bad-zone').status_code == 422
    assert console.get('/api/console/history?start=bad-date').status_code == 422
    assert console.get('/api/console/history?group_by=year').status_code == 422
    assert console.get('/api/console/history?page=0').status_code == 422
    assert console.get('/api/console/history?search=does-not-exist').json()['items'] == []
    assert console.get(f"/api/incidents/{created['trace_id']}").status_code == 200
