"""真实审计历史的归属、时间边界、分页与旧库兼容验收。"""

import pytest

from guard.audit.history import query_history
from guard.audit.store import AuditStore
from guard.contracts import AuditEvent, EventType, RunContext
from guard.gateway.session import GatewaySession


def make_session(store, tmp_path, *, timestamp="2026-10-21T12:00:00+00:00", **context):
    session = GatewaySession.create(
        store,
        tmp_path / "ws",
        user_id="owner",
        goal=context.pop("goal", "整理文档"),
        run_context=RunContext(**context),
    )
    store._conn.execute(
        "UPDATE sessions SET created_at = ? WHERE session_id = ?",
        (timestamp, session.mission.session_id),
    )
    store._conn.commit()
    return session


def test_independent_sessions_batches_and_immutable_dataset_scope(store, tmp_path):
    first = make_session(
        store,
        tmp_path,
        origin="evaluation",
        dataset_id="custom",
        dataset_version="v1",
        batch_id="batch-one",
        case_id="case-a",
    )
    second = make_session(store, tmp_path, batch_id="batch-one", case_id="case-b")
    third = make_session(
        store,
        tmp_path,
        origin="evaluation",
        dataset_id="custom",
        dataset_version="v1",
        batch_id="batch-two",
    )
    assert len({first.mission.session_id, second.mission.session_id, third.mission.session_id}) == 3
    assert second.run_context["dataset_id"] == "custom"
    assert second.run_context["origin"] == "evaluation"
    assert query_history(store._conn)["summary"]["batches"] == 2
    with pytest.raises(ValueError, match="归属冲突"):
        make_session(store, tmp_path, batch_id="batch-one", dataset_id="different")
    with pytest.raises(ValueError, match="归属冲突"):
        make_session(store, tmp_path, batch_id="batch-one", dataset_version="v2")
    with pytest.raises(ValueError, match="其他用户"):
        store.register_run("another-owner", RunContext(batch_id="batch-one"))
    assert query_history(store._conn)["summary"]["sessions"] == 3


def test_local_day_month_boundaries_and_inclusive_date_range(store, tmp_path):
    make_session(store, tmp_path, timestamp="2026-09-30T15:59:59+00:00")
    make_session(store, tmp_path, timestamp="2026-09-30T16:00:00+00:00")
    make_session(store, tmp_path, timestamp="2026-10-01T16:00:00+00:00")
    local = query_history(store._conn)
    assert [period["period"] for period in local["periods"]] == [
        "2026-10-02",
        "2026-10-01",
        "2026-09-30",
    ]
    months = query_history(store._conn, group_by="month")
    assert [(period["period"], period["sessions"]) for period in months["periods"]] == [
        ("2026-10", 2),
        ("2026-09", 1),
    ]
    utc = query_history(store._conn, timezone="UTC")
    assert [(period["period"], period["sessions"]) for period in utc["periods"]] == [
        ("2026-10-01", 1),
        ("2026-09-30", 2),
    ]
    selected = query_history(store._conn, start="2026-10-01", end="2026-10-01")
    assert selected["total"] == 1
    selected = query_history(store._conn, group_by="month", period="2026-10")
    assert selected["summary"]["sessions"] == 2
    assert len(selected["periods"]) == 2


def test_zero_call_and_legacy_sessions_remain_visible_without_fabricated_attribution(
    store, tmp_path
):
    make_session(store, tmp_path, origin="production", application="support")
    store.save_session("legacy-session", "old-user")
    store._conn.execute(
        "UPDATE sessions SET meta_json = 'invalid-json' WHERE session_id = 'legacy-session'"
    )
    store._conn.commit()
    data = query_history(store._conn)
    assert data["summary"]["sessions"] == 2
    legacy = next(item for item in data["items"] if item["session_id"] == "legacy-session")
    assert legacy["run_context"] == {"origin": "unknown"}
    assert legacy["call_count"] == 0 and legacy["trace_id"] is None
    assert query_history(store._conn, origin="unknown")["total"] == 1
    assert query_history(store._conn, origin="production")["total"] == 1


def test_session_cumulative_counts_do_not_multiply_or_count_child_as_separate_task(store, tmp_path):
    session = make_session(store, tmp_path, origin="production")
    envelope = session.make_envelope("fs.read", {"path": "workspace://README.md"})
    session.decide(envelope)
    for index in range(4):
        store.append_event(
            AuditEvent(
                trace_id=session.trace_id,
                session_id=session.mission.session_id,
                type=EventType.SUBAGENT_SPAWNED,
                agent_id=f"child-{index}",
            )
        )
    data = query_history(store._conn)
    assert data["summary"]["sessions"] == 1
    assert data["summary"]["calls"] == 1
    assert data["summary"]["decisions"] == {"ALLOW": 1, "BLOCK": 0, "CONFIRM": 0}
    assert data["summary"]["events"] == len(store.events_by_trace(session.trace_id))


def test_search_filters_pagination_and_full_export_are_consistent(store, tmp_path):
    for i in range(207):
        make_session(
            store,
            tmp_path,
            origin="evaluation",
            application="my-agent",
            dataset_id="my-dataset",
            dataset_name="我的新数据集",
            batch_id="new-batch",
            batch_name="第一轮",
            case_id=f"case-{i}",
        )
    make_session(store, tmp_path, origin="demo", application="other")
    data = query_history(store._conn, dataset_id="my-dataset", page=9)
    assert data["total"] == 207 and len(data["items"]) == 7
    assert data["summary"]["sessions"] == 207 and data["summary"]["batches"] == 1
    export = query_history(store._conn, dataset_id="my-dataset", export_all=True)
    assert len(export["items"]) == 207 and export["summary"] == data["summary"]
    assert query_history(store._conn, search="我的新数据集")["total"] == 207
    assert query_history(store._conn, search="case-206")["total"] == 1
    assert query_history(store._conn, search="' OR 1=1 --")["total"] == 0
    assert query_history(store._conn, application="other", origin="demo")["total"] == 1
    assert query_history(store._conn, batch_id="missing")["summary"]["sessions"] == 0


def test_new_records_appear_on_refresh_and_shadow_is_excluded(store, tmp_path):
    assert query_history(store._conn)["total"] == 0
    primary = make_session(store, tmp_path, origin="evaluation", batch_id="batch")
    make_session(
        store,
        tmp_path,
        batch_id="batch",
        role="shadow",
        parent_session_id=primary.mission.session_id,
    )
    assert query_history(store._conn)["total"] == 1
    assert query_history(store._conn, include_shadow=True)["total"] == 2


@pytest.mark.parametrize(
    "kwargs",
    [
        {"group_by": "year"},
        {"timezone": "invalid-zone"},
        {"start": "bad-date"},
        {"start": "2026-10-22", "end": "2026-10-21"},
        {"period": "bad-period"},
        {"group_by": "month", "period": "2026-13"},
        {"page": 0},
        {"page_size": 101},
    ],
)
def test_invalid_query_rejected(store, kwargs):
    with pytest.raises(ValueError):
        query_history(store._conn, **kwargs)


def test_history_readonly_old_schema_needs_no_migration(tmp_path):
    import sqlite3

    path = tmp_path / "old.db"
    store = AuditStore(path)
    store.save_session("old-session", "old-user", {"note": "legacy"})
    store._conn.execute("DROP TABLE run_batches")
    store._conn.commit()
    store.close()
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        data = query_history(connection)
        assert data["items"][0]["run_context"]["origin"] == "unknown"
        assert "run_batches" not in {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }


def test_cve_reruns_keep_history_and_create_separate_batches(tmp_path, monkeypatch):
    import sqlite3
    import sys

    from scripts import cve_repro

    monkeypatch.setattr(cve_repro, 'PROJECT_ROOT', tmp_path)
    monkeypatch.setattr(cve_repro.settings, 'workspaces_root', tmp_path / 'initial-ws')
    monkeypatch.setattr(cve_repro, 'DB_PATH', tmp_path / 'cve.db')
    monkeypatch.setattr(cve_repro, 'JSON_PATH', tmp_path / 'cve.json')
    monkeypatch.setattr(cve_repro, 'REPORT_PATH', tmp_path / 'cve.md')
    monkeypatch.setattr(sys, 'argv', ['cve_repro.py'])
    assert cve_repro.main() == 0
    assert cve_repro.main() == 0
    with sqlite3.connect(tmp_path / 'cve.db') as connection:
        connection.row_factory = sqlite3.Row
        history = query_history(connection, origin='evaluation', dataset_id='cve-scenarios')
        assert history['total'] == 10
        assert history['summary']['batches'] == 2
        assert history['summary']['calls'] == 32
