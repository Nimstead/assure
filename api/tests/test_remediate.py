from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select, update
from sqlalchemy.orm import sessionmaker

from nimstead.app import create_app
from nimstead.db import RemediationJob, make_engine, now

OLD = "3.0.11-1~deb12u1"
NEW = "3.9.9-1"  # beyond every fixed version in the fixture


def inv(version):
    return {"ecosystem": "Debian:12", "packages": [
        {"ecosystem": "Debian:12", "name": "libssl3", "version": version, "source": "openssl"},
        {"ecosystem": "Debian:12", "name": "openssl", "version": version, "source": "openssl"},
    ]}


def setup(env, sandbox=True, email="a@example.com"):
    c = TestClient(create_app(env))
    c.post("/api/auth/signup", json={"email": email, "password": "correct horse battery", "org_name": "Acme"})
    return c


def add_host(c, name="sbx-1", sandbox=True, version=OLD):
    token = c.post("/api/enroll-tokens", json={"sandbox": sandbox}).json()["token"]
    a = c.post("/api/agent/enroll", json={"token": token, "hostname": name, "ecosystem": "Debian:12"}).json()
    h = {"Authorization": f"Bearer {a['agent_key']}"}
    c.post("/api/agent/inventory", json=inv(version), headers=h)
    return a["asset_id"], h


def plan(c, asset_id):
    return c.post("/api/remediation/jobs", json={"asset_id": asset_id, "ecosystem": "Debian:12", "package": "openssl"})


def ledger_kinds(c):
    return [e["kind"] for e in c.get("/api/evidence/ledger").json()["entries"]]


def test_full_lifecycle_verified_by_inventory(env):
    c = setup(env)
    aid, h = add_host(c)
    r = plan(c, aid)
    assert r.status_code == 201, r.text
    job = r.json()
    assert job["status"] == "planned" and {p["name"] for p in job["packages"]} == {"libssl3", "openssl"}
    assert job["summary"].startswith("Upgrade openssl to ") and job["summary"].endswith(" on sbx-1")  # what, to which version, where
    assert plan(c, aid).status_code == 409  # no duplicate in-flight jobs

    assert c.post(f"/api/remediation/jobs/{job['id']}/approve").json()["status"] == "approved"
    jobs = c.get("/api/agent/jobs", headers=h).json()
    assert [j["id"] for j in jobs] == [job["id"]] and jobs[0]["manager"] == "apt"
    assert c.get("/api/agent/jobs", headers=h).json() == []  # dispatched once

    assert c.post(f"/api/agent/jobs/{job['id']}/report", json={"outcome": "applied"}, headers=h).json()["status"] == "verifying"
    c.post("/api/agent/inventory", json=inv(NEW), headers=h)
    j = c.get("/api/remediation/jobs").json()[0]
    assert j["status"] == "succeeded"
    assert {"remediation_planned", "remediation_approved", "remediation_dispatched", "remediation_applied",
            "remediation_succeeded"} <= set(ledger_kinds(c))


def test_cancel_only_before_a_machine_picks_the_fix_up(env):
    c = setup(env)
    aid, h = add_host(c)
    jid = plan(c, aid).json()["id"]
    r = c.post(f"/api/remediation/jobs/{jid}/cancel")
    assert r.status_code == 200 and r.json()["status"] == "cancelled" and "a@example.com" in r.json()["error"]
    assert "remediation_cancelled" in ledger_kinds(c)
    assert c.get("/api/summary").json()["attention"] == []  # a deliberate cancel isn't something that "needs a look"
    assert c.post(f"/api/remediation/jobs/{jid}/approve").status_code == 409  # cancelled stays cancelled
    jid = plan(c, aid).json()["id"]  # and no longer blocks planning again
    c.post(f"/api/remediation/jobs/{jid}/approve")
    assert c.post(f"/api/remediation/jobs/{jid}/cancel").json()["status"] == "cancelled"  # approved, not yet dispatched
    assert c.get("/api/agent/jobs", headers=h).json() == []  # nothing handed out
    jid = plan(c, aid).json()["id"]
    c.post(f"/api/remediation/jobs/{jid}/approve")
    c.get("/api/agent/jobs", headers=h)  # dispatched: the host may be running it
    r = c.post(f"/api/remediation/jobs/{jid}/cancel")
    assert r.status_code == 409 and "dispatched" in r.json()["detail"]
    assert c.post("/api/remediation/jobs/nope/cancel").status_code == 404


def test_summary_actions_carry_asset_ids_and_the_fix_in_flight(env):
    c = setup(env)
    aid, _ = add_host(c)
    action = next(a for a in c.get("/api/summary").json()["top_actions"] if a["package"] == "openssl")
    assert action["asset_ids"] == [aid] and action["job"] is None
    jid = plan(c, aid).json()["id"]
    c.post(f"/api/remediation/jobs/{jid}/approve")
    action = next(a for a in c.get("/api/summary").json()["top_actions"] if a["package"] == "openssl")
    assert action["job"] == {"id": jid, "status": "approved"}
    c.post(f"/api/remediation/jobs/{jid}/cancel")
    assert next(a for a in c.get("/api/summary").json()["top_actions"] if a["package"] == "openssl")["job"] is None


def test_summary_says_which_hosts_are_busy_and_what_failed_last(env):
    c = setup(env)
    a1, h1 = add_host(c, "sbx-1")
    a2, _ = add_host(c, "sbx-2")
    openssl = lambda: next(a for a in c.get("/api/summary").json()["top_actions"] if a["package"] == "openssl")  # noqa: E731
    assert openssl()["busy_asset_ids"] == [] and openssl()["last_attempt"] is None
    jid = plan(c, a1).json()["id"]
    act = openssl()
    assert act["busy_asset_ids"] == [a1] and sorted(act["asset_ids"]) == sorted([a1, a2])  # sbx-2 can still be planned
    c.post(f"/api/remediation/jobs/{jid}/approve")
    c.get("/api/agent/jobs", headers=h1)
    c.post(f"/api/agent/jobs/{jid}/report", json={"outcome": "aborted", "error": "would also change: libcrypto3"}, headers=h1)
    act = openssl()
    assert act["busy_asset_ids"] == [] and act["job"] is None
    assert act["last_attempt"]["id"] == jid and act["last_attempt"]["status"] == "aborted" and "libcrypto3" in act["last_attempt"]["error"]


def test_agent_claim_is_not_trusted_without_inventory_proof(env):
    c = setup(env)
    aid, h = add_host(c)
    jid = plan(c, aid).json()["id"]
    c.post(f"/api/remediation/jobs/{jid}/approve")
    c.get("/api/agent/jobs", headers=h)
    c.post(f"/api/agent/jobs/{jid}/report", json={"outcome": "applied"}, headers=h)
    c.post("/api/agent/inventory", json=inv(OLD), headers=h)  # nothing actually changed
    j = c.get("/api/remediation/jobs").json()[0]
    assert j["status"] == "not_fixed" and "still vulnerable" in j["error"]
    assert c.get("/api/summary").json()["attention"][0]["id"] == jid


def test_non_sandbox_assets_are_blocked(env, monkeypatch):
    monkeypatch.delenv("NIMSTEAD_ALLOW_PRODUCTION_REMEDIATION", raising=False)
    c = setup(env)
    aid, _ = add_host(c, "prod-1", sandbox=False)
    jid = plan(c, aid).json()["id"]  # planning (a suggestion) is fine
    r = c.post(f"/api/remediation/jobs/{jid}/approve")
    assert r.status_code == 409 and "sandbox" in r.json()["detail"]


def test_suggest_mode_blocks_approval(env):
    c = setup(env)
    aid, _ = add_host(c)
    c.patch("/api/settings", json={"remediation_mode": "suggest"})
    jid = plan(c, aid).json()["id"]
    assert c.post(f"/api/remediation/jobs/{jid}/approve").status_code == 409
    assert "policy_changed" in ledger_kinds(c)


def test_rollback_reported_loudly(env):
    c = setup(env)
    aid, h = add_host(c)
    jid = plan(c, aid).json()["id"]
    c.post(f"/api/remediation/jobs/{jid}/approve")
    c.get("/api/agent/jobs", headers=h)
    steps = [{"step": "apply", "ok": True}, {"step": "health", "ok": False, "output": "nginx.service inactive"},
             {"step": "rollback", "ok": True}]
    r = c.post(f"/api/agent/jobs/{jid}/report", json={"outcome": "rolled_back", "steps": steps, "error": "health check failed"}, headers=h)
    assert r.json()["status"] == "rolled_back"
    assert c.get("/api/summary").json()["attention"][0]["status"] == "rolled_back"
    assert "remediation_rolled_back" in ledger_kinds(c)
    # replayed or bogus reports are rejected
    assert c.post(f"/api/agent/jobs/{jid}/report", json={"outcome": "applied"}, headers=h).status_code == 409


def test_agent_cannot_touch_other_assets_jobs(env):
    c = setup(env)
    aid, _ = add_host(c, "sbx-1")
    _, h2 = add_host(c, "sbx-2")
    jid = plan(c, aid).json()["id"]
    assert c.post(f"/api/agent/jobs/{jid}/report", json={"outcome": "applied"}, headers=h2).status_code == 404


def test_silent_agent_times_out(env):
    c = setup(env)
    aid, h = add_host(c)
    jid = plan(c, aid).json()["id"]
    c.post(f"/api/remediation/jobs/{jid}/approve")
    c.get("/api/agent/jobs", headers=h)
    s = sessionmaker(make_engine(env))()
    s.execute(update(RemediationJob).values(updated=now() - timedelta(hours=3)))
    s.commit()
    c.get("/api/agent/jobs", headers=h)
    j = c.get("/api/remediation/jobs").json()[0]
    assert j["status"] == "failed" and "did not report" in j["error"]


def test_an_applied_job_that_is_never_verified_times_out_and_frees_the_fix(env):
    c = setup(env)
    aid, h = add_host(c)
    jid = plan(c, aid).json()["id"]
    c.post(f"/api/remediation/jobs/{jid}/approve")
    c.get("/api/agent/jobs", headers=h)
    assert c.post(f"/api/agent/jobs/{jid}/report", headers=h, json={"outcome": "applied"}).json()["status"] == "verifying"
    s = sessionmaker(make_engine(env))()
    s.execute(update(RemediationJob).values(updated=now() - timedelta(days=6)))
    s.commit()
    assert c.get("/api/remediation/jobs").json()[0]["status"] == "verifying"  # a few days of partial inventories are fine
    s.execute(update(RemediationJob).values(updated=now() - timedelta(days=8)))
    s.commit()
    j = c.get("/api/remediation/jobs").json()[0]
    assert j["status"] == "failed" and "7 days" in j["error"]
    assert plan(c, aid).status_code == 201  # no longer "already in progress"


def test_a_cancel_from_a_stale_copy_sees_the_job_was_dispatched_meanwhile(env):
    import pytest

    from nimstead import remediate
    c = setup(env)
    aid, h = add_host(c)
    jid = plan(c, aid).json()["id"]
    c.post(f"/api/remediation/jobs/{jid}/approve")
    admin = sessionmaker(make_engine(env))()
    job = admin.get(RemediationJob, jid)  # the admin's view: approved
    assert job.status == "approved"
    c.get("/api/agent/jobs", headers=h)  # meanwhile the agent picks it up
    with pytest.raises(remediate.RemediationError, match="dispatched"):
        remediate.cancel(admin, job, "a@example.com")


def test_a_report_from_a_stale_copy_sees_the_job_timed_out_meanwhile(env):
    from nimstead import remediate
    from nimstead.db import LedgerEntry
    c = setup(env)
    aid, h = add_host(c)
    jid = plan(c, aid).json()["id"]
    c.post(f"/api/remediation/jobs/{jid}/approve")
    c.get("/api/agent/jobs", headers=h)
    agent_view = sessionmaker(make_engine(env))()
    job = agent_view.get(RemediationJob, jid)  # the report handler's view: dispatched
    assert job.status == "dispatched"
    other = sessionmaker(make_engine(env))()
    other.execute(update(RemediationJob).values(updated=now() - timedelta(hours=3)))
    other.commit()
    remediate.sweep(other, job.org_id)  # meanwhile a page load times it out
    remediate.report(agent_view, job, "rolled_back", [], "health check failed")
    agent_view.commit()
    last = agent_view.scalars(select(LedgerEntry).where(LedgerEntry.subject == jid).order_by(LedgerEntry.seq.desc())).first()
    assert last.kind == "remediation_rolled_back" and last.data["late"] is True  # recorded as a late report, not a normal one


def test_windows_job_waiting_for_its_restart_isnt_timed_out_before_the_deadline(env):
    c = setup(env)
    aid, h = add_host(c)
    jid = plan(c, aid).json()["id"]
    c.post(f"/api/remediation/jobs/{jid}/approve")
    c.get("/api/agent/jobs", headers=h)
    s = sessionmaker(make_engine(env))()
    s.execute(update(RemediationJob).values(manager="windows", updated=now() - timedelta(hours=3)))  # default deadline: 24 h
    s.commit()
    assert c.get("/api/remediation/jobs").json()[0]["status"] == "dispatched"
    s.execute(update(RemediationJob).values(updated=now() - timedelta(hours=29)))
    s.commit()
    j = c.get("/api/remediation/jobs").json()[0]
    assert j["status"] == "failed" and "after the restart deadline" in j["error"]


def test_auto_mode_canary_first_then_broad(env):
    c = setup(env)
    c.patch("/api/settings", json={"remediation_mode": "auto", "canary_soak_hours": 1})
    canary, hc = add_host(c, "canary", version=NEW)  # healthy at first
    c.patch(f"/api/assets/{canary}", json={"ring": 0})
    broad, hb = add_host(c, "broad")  # vulnerable, ring 1: must wait for canary
    assert c.get("/api/agent/jobs", headers=hb).json() == []
    assert c.get("/api/remediation/jobs").json()[0]["status"] == "planned"

    c.post("/api/agent/inventory", json=inv(OLD), headers=hc)  # canary becomes vulnerable -> auto-approved
    [cj] = c.get("/api/agent/jobs", headers=hc).json()
    c.post(f"/api/agent/jobs/{cj['id']}/report", json={"outcome": "applied"}, headers=hc)
    c.post("/api/agent/inventory", json=inv(NEW), headers=hc)

    c.post("/api/agent/inventory", json=inv(OLD), headers=hb)
    assert c.get("/api/agent/jobs", headers=hb).json() == []  # canary not soaked yet

    s = sessionmaker(make_engine(env))()
    s.execute(update(RemediationJob).where(RemediationJob.id == cj["id"]).values(updated=now() - timedelta(hours=2)))
    s.commit()
    c.post("/api/agent/inventory", json=inv(OLD), headers=hb)
    assert len(c.get("/api/agent/jobs", headers=hb).json()) == 1


def test_auto_rollout_halts_after_any_failure(env):
    c = setup(env)
    c.patch("/api/settings", json={"remediation_mode": "auto", "canary_soak_hours": 1})
    canary, hc = add_host(c, "canary", version=NEW)
    c.patch(f"/api/assets/{canary}", json={"ring": 0})
    c.post("/api/agent/inventory", json=inv(OLD), headers=hc)
    [cj] = c.get("/api/agent/jobs", headers=hc).json()
    c.post(f"/api/agent/jobs/{cj['id']}/report", json={"outcome": "rolled_back", "error": "health"}, headers=hc)
    _, hb = add_host(c, "broad")
    assert c.get("/api/agent/jobs", headers=hb).json() == []


def _dispatched(c, aid, h):
    jid = plan(c, aid).json()["id"]
    c.post(f"/api/remediation/jobs/{jid}/approve")
    c.get("/api/agent/jobs", headers=h)
    return jid


def _age_jobs(env, hours):
    s = sessionmaker(make_engine(env))()
    s.execute(update(RemediationJob).values(updated=now() - timedelta(hours=hours)))
    s.commit()


def test_stale_jobs_swept_without_agent_and_late_report_accepted(env):
    c = setup(env)
    aid, h = add_host(c)
    jid = _dispatched(c, aid, h)
    _age_jobs(env, 3)
    s = c.get("/api/summary").json()  # no agent poll needed
    assert s["attention"][0]["id"] == jid and s["attention"][0]["status"] == "failed"
    r = c.post(f"/api/agent/jobs/{jid}/report", json={"outcome": "rollback_failed", "error": "ROLLBACK FAILED"}, headers=h)
    assert r.json()["status"] == "rollback_failed"  # the real outcome still lands, and is ledgered
    entry = next(e for e in c.get("/api/evidence/ledger").json()["entries"] if e["kind"] == "remediation_rollback_failed")
    assert entry["data"]["late"] is True


def test_kill_switch_cancels_approved_jobs(env):
    c = setup(env)
    aid, h = add_host(c)
    jid = plan(c, aid).json()["id"]
    c.post(f"/api/remediation/jobs/{jid}/approve")
    c.patch("/api/settings", json={"remediation_mode": "suggest"})
    assert c.get("/api/agent/jobs", headers=h).json() == []
    assert c.get("/api/remediation/jobs").json()[0]["status"] == "cancelled"


def test_broad_ring_pinned_to_canary_version_and_held_on_later_failure(env):
    c = setup(env)
    c.patch("/api/settings", json={"remediation_mode": "auto", "canary_soak_hours": 1})
    canary, hc = add_host(c, "canary", version=NEW)
    c.patch(f"/api/assets/{canary}", json={"ring": 0})
    c.post("/api/agent/inventory", json=inv(OLD), headers=hc)
    [cj] = c.get("/api/agent/jobs", headers=hc).json()
    proven = {"libssl3": "3.0.17-1~deb12u2", "openssl": "3.0.17-1~deb12u2"}
    c.post(f"/api/agent/jobs/{cj['id']}/report", json={"outcome": "applied", "versions": proven}, headers=hc)
    c.post("/api/agent/inventory", json=inv(NEW), headers=hc)
    _age_jobs(env, 2)  # canary soaked

    broad, hb = add_host(c, "broad")
    b2, hb2 = add_host(c, "broad-2")
    [bj] = c.get("/api/agent/jobs", headers=hb).json()
    assert {p["name"]: p["to"] for p in bj["packages"]} == proven  # exactly what the canary proved

    c.post(f"/api/agent/jobs/{bj['id']}/report", json={"outcome": "rolled_back", "error": "health"}, headers=hb)
    assert c.get("/api/agent/jobs", headers=hb2).json() == []  # approved earlier, held at dispatch
    held = next(j for j in c.get("/api/remediation/jobs").json() if j["hostname"] == "broad-2")
    assert held["status"] == "planned" and "halted" in held["error"]


def test_an_old_linux_failure_stops_halting_once_the_change_has_succeeded_since(env):
    from nimstead import remediate
    from nimstead.db import Org
    test_broad_ring_pinned_to_canary_version_and_held_on_later_failure(env)
    s = sessionmaker(make_engine(env))()
    jobs = s.scalars(select(RemediationJob)).all()
    failed = next(j for j in jobs if j.status == "rolled_back")
    held = next(j for j in jobs if j.status == "planned")
    org = s.get(Org, held.org_id)
    assert remediate.canary_ok(s, org, held)[1].endswith("halted")
    failed.updated = now() - timedelta(days=30)  # it failed a month ago; the canary has succeeded since
    s.flush()
    assert remediate.canary_ok(s, org, held)[0]
    failed.packages = [{**p, "to": "9.9.9-1"} for p in failed.packages]  # but the failure was a version nobody has proven
    s.flush()
    assert remediate.canary_ok(s, org, held)[1].endswith("halted")
    failed.status, failed.error = "failed", remediate.VERIFY_TIMEOUT_ERROR  # a host that never reported back proves nothing
    s.flush()
    assert remediate.canary_ok(s, org, held)[0]


def test_canary_report_cannot_pin_the_fleet_to_an_older_version(env):
    c = setup(env)
    c.patch("/api/settings", json={"remediation_mode": "auto", "canary_soak_hours": 1})
    canary, hc = add_host(c, "canary", version=NEW)
    c.patch(f"/api/assets/{canary}", json={"ring": 0})
    c.post("/api/agent/inventory", json=inv(OLD), headers=hc)
    [cj] = c.get("/api/agent/jobs", headers=hc).json()
    bogus = {"libssl3": "3.0.0-1", "openssl": "3.0.0-1"}  # a compromised canary claims an old, vulnerable build "worked"
    c.post(f"/api/agent/jobs/{cj['id']}/report", json={"outcome": "applied", "versions": bogus}, headers=hc)
    c.post("/api/agent/inventory", json=inv(NEW), headers=hc)
    _age_jobs(env, 2)
    _, hb = add_host(c, "broad")
    [bj] = c.get("/api/agent/jobs", headers=hb).json()
    assert all("to" not in p for p in bj["packages"])  # not pinned: the agent installs the repo's current fix


def test_unsupported_ecosystem_not_remediated(env):
    c = setup(env)
    token = c.post("/api/enroll-tokens", json={"sandbox": True}).json()["token"]
    a = c.post("/api/agent/enroll", json={"token": token, "hostname": "py", "ecosystem": "Debian:12"}).json()
    r = c.post("/api/remediation/jobs", json={"asset_id": a["asset_id"], "ecosystem": "PyPI", "package": "requests"})
    assert r.status_code == 409 and "not supported" in r.json()["detail"]


def test_plan_can_include_dependencies_named_by_the_dry_run(env):
    c = setup(env)
    token = c.post("/api/enroll-tokens", json={"sandbox": True}).json()["token"]
    a = c.post("/api/agent/enroll", json={"token": token, "hostname": "h", "ecosystem": "Debian:12"}).json()
    h = {"Authorization": f"Bearer {a['agent_key']}"}
    c.post("/api/agent/inventory", json={**inv(OLD), "packages": inv(OLD)["packages"] + [
        {"ecosystem": "Debian:12", "name": "libc6", "version": "2.36-9", "source": "glibc"},
        {"ecosystem": "Debian:12", "name": "libc-bin", "version": "2.36-9", "source": "glibc"}]}, headers=h)
    body = {"asset_id": a["asset_id"], "ecosystem": "Debian:12", "package": "openssl"}
    assert c.post("/api/remediation/jobs", json={**body, "include": ["not-installed"]}).status_code == 409
    j = c.post("/api/remediation/jobs", json={**body, "include": ["libc6"]}).json()
    assert {p["name"] for p in j["packages"]} == {"libssl3", "openssl", "libc6", "libc-bin"}  # sibling binaries come too
    assert "with libc6" in j["summary"]


def test_an_inventory_that_kept_the_old_list_does_not_judge_the_fix(env):
    """The agent couldn't read its package database, so the server kept the list from before the fix (DECISIONS 83).
    That list says nothing about the fix: the job waits for a real one instead of turning not_fixed."""
    from nimstead.engine.collection import DOC_VERSION
    c = setup(env)
    aid, h = add_host(c)
    jid = _dispatched(c, aid, h)
    c.post(f"/api/agent/jobs/{jid}/report", json={"outcome": "applied"}, headers=h)
    failed = {"v": DOC_VERSION, "sources": {"package_db": {"state": "failed", "count": 0, "error": "dpkg-query exited 2", "exit": 2}}}
    c.post("/api/agent/inventory", json={**inv(NEW), "packages": [], "collection": failed}, headers=h)
    assert c.get("/api/remediation/jobs").json()[0]["status"] == "verifying"
    c.post("/api/agent/inventory", json=inv(NEW), headers=h)
    assert c.get("/api/remediation/jobs").json()[0]["status"] == "succeeded"


def test_accepting_a_finding_mid_verification_is_not_a_fix(env):
    c = setup(env)
    aid, h = add_host(c)
    jid = _dispatched(c, aid, h)
    c.post(f"/api/agent/jobs/{jid}/report", json={"outcome": "applied"}, headers=h)
    for f in c.get("/api/findings", params={"asset_id": aid}).json():
        c.post(f"/api/findings/{f['id']}/accept", json={"reason": "vendor appliance, isolated", "days": 30})
    c.post("/api/agent/inventory", json=inv(OLD), headers=h)  # the old version is still installed
    assert c.get("/api/remediation/jobs").json()[0]["status"] == "not_fixed"
    assert "remediation_succeeded" not in ledger_kinds(c)


def test_a_timed_out_windows_job_holds_the_host_for_the_margin(env):
    """sweep() fails a silent Windows job, but its install may still be running (its late report is accepted), so the
    next Windows job for that host waits the margin out instead of being handed out alongside."""
    from nimstead.remediate import WIN_TIMEOUT_MARGIN
    c = setup(env)
    aid, h = add_host(c)
    first = _dispatched(c, aid, h)
    s = sessionmaker(make_engine(env))()
    s.execute(update(RemediationJob).values(manager="windows", updated=now() - timedelta(hours=29)))
    s.commit()
    assert c.get("/api/remediation/jobs").json()[0]["status"] == "failed"  # swept
    second = plan(c, aid).json()["id"]
    c.post(f"/api/remediation/jobs/{second}/approve")
    s.execute(update(RemediationJob).where(RemediationJob.id == second).values(manager="windows"))
    s.commit()
    assert c.get("/api/agent/jobs", headers=h).json() == []  # held by the first, which may still be installing
    s.execute(update(RemediationJob).where(RemediationJob.id == first).values(updated=now() - WIN_TIMEOUT_MARGIN - timedelta(minutes=1)))
    s.commit()
    assert [j["id"] for j in c.get("/api/agent/jobs", headers=h).json()] == [second]


def test_a_held_windows_job_is_still_cancelled_by_the_kill_switch(env):
    c = setup(env)
    aid, h = add_host(c)
    first = _dispatched(c, aid, h)
    s = sessionmaker(make_engine(env))()
    s.execute(update(RemediationJob).values(manager="windows"))
    s.commit()
    c.post(f"/api/agent/jobs/{first}/report", json={"outcome": "rolled_back", "error": "x"}, headers=h)
    held = plan(c, aid).json()["id"]
    c.post(f"/api/remediation/jobs/{held}/approve")
    s.execute(update(RemediationJob).where(RemediationJob.id.in_([first, held])).values(manager="windows"))
    s.execute(update(RemediationJob).where(RemediationJob.id == first).values(status="dispatched"))  # the host is busy
    s.commit()
    c.patch("/api/settings", json={"remediation_mode": "suggest"})
    c.get("/api/agent/jobs", headers=h)
    assert next(j for j in c.get("/api/remediation/jobs").json() if j["id"] == held)["status"] == "cancelled"


def test_a_windows_failure_halts_only_its_own_release(env):
    """One action key spans every month: a failed September cumulative halts September, not October (as kb_fleet)."""
    from nimstead import remediate
    from nimstead.db import Asset, Org
    s = sessionmaker(make_engine(env), expire_on_commit=False)()
    org = Org(name="o", canary_soak_hours=1)
    s.add(org)
    s.flush()
    s.add(Asset(org_id=org.id, hostname="canary", ring=0, agent_key_hash="c"))
    host = Asset(org_id=org.id, hostname="h", agent_key_hash="h")
    s.add(host)
    s.flush()

    def job(to, status):
        j = RemediationJob(org_id=org.id, asset_id=host.id, status=status, manager="windows", action_key="Windows|Windows 11 24H2",
                           packages=[{"name": "Windows 11 24H2", "kb": "5000000", "from": "10.0.26100.1000", "to": to}],
                           finding_ids=[], summary="s", created_by="policy")
        s.add(j)
        s.flush()
        return j
    job("10.0.26100.4000", "failed")
    assert remediate.canary_ok(s, org, job("10.0.26100.3000", "planned"))[1].startswith("This change failed")
    assert not remediate.canary_ok(s, org, job("10.0.26100.5000", "planned"))[1].startswith("This change failed")


def test_plan_the_rest_in_one_request_keeps_what_it_could_plan(env):
    c = setup(env)
    a1, _ = add_host(c, "sbx-1")
    a2, _ = add_host(c, "sbx-2", version=NEW)  # nothing to fix there
    other = setup(env, email="b@example.com")
    foreign, _ = add_host(other, "theirs")
    r = c.post("/api/remediation/jobs/batch", json={"asset_ids": [a1, a2, foreign, a1], "ecosystem": "Debian:12", "package": "openssl"})
    assert r.status_code == 201
    body = r.json()
    assert [j["asset_id"] for j in body["jobs"]] == [a1]  # planned once, though named twice
    assert {e["asset_id"]: e["error"] for e in body["errors"]} == {
        a2: "No open, fixable findings for this package on this asset", foreign: "Asset not found"}  # another org's id says nothing more
