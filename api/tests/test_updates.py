"""Platform updates: /api/health, the daily release check, fetching signed release files, alerts (DECISIONS 32)."""

import json
from datetime import timedelta

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker
from test_api import user

from nimstead import notify, updates
from nimstead.app import create_app
from nimstead.db import make_engine, now


@pytest.fixture
def gh(env, tmp_path, monkeypatch):
    """Release dir in tmp, the check switched on, running version 0.3.0, a fake GitHub, and captured alerts."""
    import nimstead.app as appmod
    monkeypatch.setattr(appmod, "RELEASE_DIR", tmp_path / "release")
    monkeypatch.setenv("NIMSTEAD_UPDATE_CHECK", "1")
    monkeypatch.setattr(updates, "current_version", lambda: "0.3.0")
    sent = []
    monkeypatch.setattr(notify, "notify", lambda s, org_id, kind, text, urgent=False: sent.append((kind, text, urgent)))
    state = {"latest": "v0.3.1", "files": {"release.json": b'{"version":"0.3.0"}', "release.json.sig": b"c2ln\n"}, "calls": []}

    def handler(req: httpx.Request):
        state["calls"].append(str(req.url))
        if req.url.path == "/repos/Nimstead/assure/releases/latest":
            return httpx.Response(200, json={"tag_name": state["latest"]}) if state["latest"] else httpx.Response(503)
        name = req.url.path.rsplit("/", 1)[1]
        if req.url.path.startswith("/Nimstead/assure/releases/download/v0.3.0/") and name in state["files"]:
            return httpx.Response(200, content=state["files"][name])
        return httpx.Response(404)
    client = httpx.Client(transport=httpx.MockTransport(handler))
    s = sessionmaker(make_engine(env))()
    yield s, client, state, sent, tmp_path / "release"
    s.close()


def test_health_reports_version_and_schema(env):
    c = TestClient(create_app(env))
    r = c.get("/api/health")
    assert r.status_code == 200 and r.json()["db"] == "ok" and r.json()["migrations"] in ("unmanaged", "head")  # SQLite create_all, or Alembic on PostgreSQL
    assert "org" not in r.text.lower()  # no tenant data


def test_health_is_503_when_migrations_are_behind(env, monkeypatch):
    import nimstead.app as appmod
    monkeypatch.setattr(appmod, "migration_state", lambda s: "behind")
    r = TestClient(create_app(env)).get("/api/health")
    assert r.status_code == 503 and r.json()["migrations"] == "behind"


def test_new_release_is_found_shown_and_alerted_once(gh):
    s, client, state, sent, d = gh
    user_c = user(s.get_bind().url.render_as_string(hide_password=False))
    out = updates.check(s, client)
    assert out["latest"] == "0.3.1" and out["release_files_fetched"] and out["alerted"] == ["update_available"]
    assert (d / "release.json").read_bytes() == b'{"version":"0.3.0"}'  # for agents; the server checks its signature before relaying
    p = user_c.get("/api/settings").json()["platform"]
    assert p["version"] == "0.3.0" and p["latest"] == "0.3.1" and p["update_available"]
    assert sent[0][0] == "update_available" and "0.3.1 is available" in sent[0][1]
    n = len(state["calls"])
    assert updates.check(s, client)["alerted"] == [] and len(state["calls"]) == n  # checked today, files present, already alerted


def test_daily_check_runs_again_after_24h_and_survives_github_being_down(gh):
    s, client, state, sent, d = gh
    updates.check(s, client)
    latest = json.loads((d / "latest.json").read_text())
    (d / "latest.json").write_text(json.dumps({**latest, "checked": (now() - timedelta(hours=25)).isoformat()}))
    state["latest"] = None  # GitHub unavailable
    out = updates.check(s, client)
    assert "error" in out and updates.status()["latest"] == "0.3.1"  # last good answer kept


def test_same_or_older_release_is_not_an_update(gh):
    s, client, state, sent, d = gh
    state["latest"] = "v0.3.0"
    updates.check(s, client)
    assert not updates.status()["update_available"] and sent == []


def test_missing_release_files_are_retried_not_invented(gh):
    s, client, state, sent, d = gh
    state["files"] = {}
    assert updates.check(s, client)["release_files_fetched"] is False and not (d / "release.json").exists()


def test_check_off_makes_no_requests(gh, monkeypatch):
    s, client, state, sent, d = gh
    monkeypatch.setenv("NIMSTEAD_UPDATE_CHECK", "0")
    assert "skipped" in updates.check(s, client) and state["calls"] == []


def test_failed_update_is_alerted_once_and_rollback_failure_is_urgent(gh):
    s, client, state, sent, d = gh
    user(s.get_bind().url.render_as_string(hide_password=False))  # an org to alert
    d.mkdir(parents=True)
    (d / "update-status.json").write_text(json.dumps({"outcome": "rolled_back", "from": "0.3.0", "to": "0.3.1",
                                                     "error": "health check failed: migrations behind"}))
    updates.check(s, client)
    failed = [x for x in sent if x[0] == "update_failed"]
    assert len(failed) == 1 and "0.3.1 failed" in failed[0][1] and not failed[0][2]
    updates.check(s, client)
    assert len([x for x in sent if x[0] == "update_failed"]) == 1
    (d / "update-status.json").write_text(json.dumps({"outcome": "rollback_failed", "to": "0.3.2", "error": "restore failed"}))
    updates.check(s, client)
    assert sent[-1][0] == "update_failed" and sent[-1][2] is True


def test_release_files_left_from_the_previous_version_are_replaced(gh):
    s, client, state, sent, d = gh
    d.mkdir(parents=True)
    (d / "release.json").write_text('{"version":"0.2.9"}')
    assert updates.check(s, client)["release_files_fetched"] and json.loads((d / "release.json").read_text())["version"] == "0.3.0"
