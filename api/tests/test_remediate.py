from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import update
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
    assert "Upgrade openssl (2 packages)" in job["summary"]
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
