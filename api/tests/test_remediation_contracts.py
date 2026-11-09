"""Checks for remediation response contracts and documented policy/verification limits."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select
from test_kb_fleet import KB, W11, _host, _plan, _row, _synced
from test_remediate import add_host, plan, setup

from nimstead import remediate
from nimstead.db import Asset, Finding, RemediationJob, make_sessionmaker

ROOT = Path(__file__).resolve().parents[2]


def schemas():
    return json.loads((ROOT / "docs/reference/openapi.json").read_text())["components"]["schemas"]


def assert_fields(value, name):
    schema = schemas()[name]
    assert set(schema["required"]) <= set(value) <= set(schema["properties"])
    reference = (ROOT / "docs/reference/remediation-jobs.md").read_text()
    assert all(f"`{key}`" in reference for key in value)


def test_job_list_dispatch_report_and_policy_fields_match_export(env):
    c = setup(env)
    aid, headers = add_host(c)
    job = plan(c, aid).json()
    assert_fields(job, "RemediationJob")
    approved = c.post(f"/api/remediation/jobs/{job['id']}/approve").json()
    assert_fields(approved, "RemediationJob")
    [listed] = c.get("/api/remediation/jobs").json()
    assert_fields(listed, "RemediationJobListItem")
    assert listed["waits_for_window"] is None
    [execution] = c.get("/api/agent/jobs", headers=headers).json()
    assert_fields(execution, "AgentJobPlan")
    assert "reboot_by" not in execution
    response = c.post(f"/api/agent/jobs/{job['id']}/report", headers=headers, json={"outcome": "aborted"})
    assert response.json() == {"status": "aborted"}
    assert_fields(c.get("/api/settings").json(), "OrganisationSettings")
    assert c.get("/api/remediation/jobs", params={"status": " planned"}).json() == []


def test_windows_update_fields_and_execution_deadline_match_export(env):
    c = _synced(env)
    aid = _host(c, "windows-contract", "10.0.26200.6899")
    [summary] = c.get("/api/windows-updates").json()
    assert_fields(summary, "WindowsUpdateSummary")
    detail = _row(c)
    assert_fields(detail, "WindowsUpdateDetail")
    [missing] = detail["missing"]
    assert_fields(missing, "WindowsUpdateHost")
    jid = _plan(c, aid)
    assert c.post(f"/api/remediation/jobs/{jid}/approve").status_code == 200
    with make_sessionmaker(env)() as s:
        asset = s.get(Asset, aid)
        execution = remediate.dispatch(s, asset)
    [row] = execution
    assert_fields(row, "AgentJobPlan")
    assert row["reboot_by"].endswith("Z")
    assert c.get(f"/api/windows-updates/{KB}", params={"product": W11}).status_code == 200


def test_stepped_success_can_leave_open_findings_with_an_unrelated_reported_version(env):
    c = _synced(env)
    aid = _host(c, "stepping-contract", "10.0.26200.6899")
    jid = _plan(c, aid)
    with make_sessionmaker(env)() as s:
        job = s.get(RemediationJob, jid)
        job.packages = [{**job.packages[0], "alt": {"kb": "1234567", "to": "10.0.26200.7000"}}]
        job.result_versions = {"unrelated-product": "10.0.26200.7000"}
        job.status = "verifying"
        remediate.verify(s, s.get(Asset, aid))
        assert job.status == "succeeded"
        assert set(s.scalars(select(Finding.status).where(Finding.id.in_(job.finding_ids)))) == {"open"}


def test_non_kb_proof_does_not_require_versions_or_check_status():
    canary = RemediationJob(status="failed", result_versions={})
    job = RemediationJob(action_key="Debian:12|openssl", packages=[{"name": "openssl", "from": "1"}])
    assert remediate.proves(canary, job)


def test_window_boolean_hours_and_naive_time_contract():
    window = {"days": [0, 0], "start": "00:00", "hours": True, "tz": "UTC"}
    assert remediate.valid_window(window)
    assert remediate.window_state(window, datetime(2026, 11, 9, 0, 30)) == (True, datetime(2026, 11, 9, 1))
    with pytest.raises(TypeError):
        remediate.window_state(window, datetime(2026, 11, 9, 0, 30, tzinfo=UTC))


def test_closed_window_defers_suggest_mode_cancellation(env, monkeypatch):
    c = setup(env)
    aid, headers = add_host(c)
    job = plan(c, aid).json()
    assert c.post(f"/api/remediation/jobs/{job['id']}/approve").status_code == 200
    c.patch("/api/settings", json={"remediation_mode": "suggest", "maintenance_window": {
        "days": [0], "start": "00:00", "hours": 1, "tz": "UTC"}})
    monkeypatch.setattr(remediate, "now", lambda: datetime(2026, 11, 10, 12))
    assert c.get("/api/agent/jobs", headers=headers).json() == []
    assert c.get("/api/remediation/jobs").json()[0]["status"] == "approved"
