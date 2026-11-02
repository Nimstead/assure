"""The per-KB fleet view: who has a cumulative update, why the others don't, and who "plan the rest" may plan."""

from datetime import timedelta

from sqlalchemy import select
from test_api import user
from test_windows import W11, msrc_client

from nimstead.db import Advisory, Asset, InstalledPackage, Org, RemediationJob, make_sessionmaker, now
from nimstead.feeds import sync_msrc
from nimstead.scan import HOTPATCH

OLD, OCT = "10.0.26200.6899", "10.0.26200.9711"
KB = "5127648"


def _host(c, name, build, product=W11, facts=None, sandbox=True):
    token = c.post("/api/enroll-tokens", json={"sandbox": sandbox}).json()["token"]
    a = c.post("/api/agent/enroll", json={"token": token, "hostname": name, "ecosystem": "Windows"}).json()
    r = c.post("/api/agent/inventory", headers={"Authorization": f"Bearer {a['agent_key']}"},
               json={"ecosystem": "Windows", "packages": [{"ecosystem": "Windows", "name": product, "version": build, "source": None}], "facts": facts})
    assert r.status_code == 200, r.text
    return a["asset_id"]


def _synced(env):
    with make_sessionmaker(env)() as s:
        sync_msrc(s, 60, msrc_client())
    return user(env)


def _row(c, kb=KB, product=W11):
    r = c.get(f"/api/windows-updates/{kb}", params={"product": product})
    assert r.status_code == 200, r.text
    return r.json()


def _plan(c, asset_id):
    r = c.post("/api/remediation/jobs", json={"asset_id": asset_id, "ecosystem": "Windows", "package": W11})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _set_job(env, job_id, **fields):
    with make_sessionmaker(env)() as s:
        j = s.get(RemediationJob, job_id)
        for k, v in fields.items():
            setattr(j, k, v)
        s.commit()


def _ring0(env, *asset_ids):
    with make_sessionmaker(env)() as s:
        for i in asset_ids:
            s.get(Asset, i).ring = 0
        s.commit()


def test_counts_by_build_and_says_why_from_jobs_and_facts(env):
    c = _synced(env)
    _host(c, "patched", OCT)
    newer = _host(c, "newer", "10.0.26200.9999")
    quiet = _host(c, "quiet", OLD, facts={"wsus": "https://wsus.example", "pending_reboot": True, "wufb_quality_deferral_days": 7})
    busy = _host(c, "busy", OLD)
    prod = _host(c, "prod", OLD, sandbox=False)
    [row] = c.get("/api/windows-updates").json()
    assert (row["kb"], row["title"], row["hosts"], row["fixed"]) == (KB, f"October 2026 cumulative KB{KB}", 5, 2)
    assert row["build"] == OCT and "missing" not in row and "plan_asset_ids" not in row  # the list stays small: hosts on demand

    jid = _plan(c, busy)
    d = _row(c)
    why = {h["hostname"]: h for h in d["missing"]}
    assert set(why) == {"quiet", "busy", "prod"} and newer not in d["plan_asset_ids"]
    assert why["quiet"]["why"] == "No job yet" and why["quiet"]["job"] is None and why["quiet"]["build"] == OLD
    assert any("WSUS (https://wsus.example)" in n for n in why["quiet"]["notes"])
    assert any("restart is pending" in n for n in why["quiet"]["notes"]) and any("by 7 days" in n for n in why["quiet"]["notes"])
    assert why["busy"]["why"] == "Planned, waiting for approval" and why["busy"]["job"] == {"id": jid, "status": "planned"}
    assert any("only fixes test machines" in n for n in why["prod"]["notes"])
    assert sorted(d["plan_asset_ids"]) == sorted([quiet, prod])  # the one in flight is what plan() would refuse

    # a failure names its reason and waits for a look, as on Home; a cancel can be planned again
    _set_job(env, jid, status="rolled_back", error="health check failed")
    d = _row(c)
    assert next(h for h in d["missing"] if h["hostname"] == "busy")["why"] == "Last attempt rolled back: health check failed"
    assert busy not in d["plan_asset_ids"] and d["plan_asset_ids"] == [] and "failed on a machine" in d["plan_note"]
    _set_job(env, jid, status="aborted", error=None, steps=[{"step": "offer", "ok": False, "output": "not offered"}])
    assert next(h for h in _row(c)["missing"] if h["hostname"] == "busy")["why"] == "Last attempt aborted: not offered"
    _set_job(env, jid, status="cancelled", error="Cancelled by a@example.com")
    d = _row(c)
    assert next(h for h in d["missing"] if h["hostname"] == "busy")["why"] == "Cancelled by a@example.com"
    assert busy in d["plan_asset_ids"]
    assert c.get("/api/windows-updates/1234567", params={"product": W11}).status_code == 404


def test_a_job_for_an_older_build_is_not_a_job_for_this_update(env):
    c = _synced(env)
    host = _host(c, "pc", OLD)
    jid = _plan(c, host)
    _set_job(env, jid, status="succeeded", packages=[{"name": W11, "from": OLD, "kb": "5000000", "to": "10.0.26200.7000"}])
    d = _row(c)
    assert d["missing"][0]["why"] == "No job yet" and d["plan_asset_ids"] == [host]
    _set_job(env, jid, packages=[{"name": W11, "from": OLD, "kb": KB, "to": OCT}])
    assert "still shows an older build" in _row(c)["missing"][0]["why"]


def test_accepted_findings_leave_nothing_to_plan_and_say_so(env):
    c = _synced(env)
    host = _host(c, "pc", OLD)
    for f in c.get("/api/findings", params={"asset": host}).json():
        assert c.post(f"/api/findings/{f['id']}/accept", json={"reason": "isolated test machine", "days": 30}).status_code == 200
    d = _row(c)
    assert d["plan_asset_ids"] == [] and any("risk-accepted" in n for n in d["missing"][0]["notes"])


def test_org_scoped(env):
    c = _synced(env)
    _host(c, "mine", OLD)
    other = user(env, "b@example.com")
    assert other.get("/api/windows-updates").json() == []
    assert other.get(f"/api/windows-updates/{KB}", params={"product": W11}).status_code == 404
    theirs = _host(other, "theirs", OCT)
    [row] = other.get("/api/windows-updates").json()
    assert (row["hosts"], row["fixed"]) == (1, 1)
    assert _row(c)["hosts"] == 1 and [h["hostname"] for h in _row(c)["missing"]] == ["mine"]
    jid = _plan(c, _row(c)["missing"][0]["asset_id"])
    assert other.post(f"/api/remediation/jobs/{jid}/approve").status_code == 404
    assert theirs not in _row(c)["plan_asset_ids"]


def test_plan_the_rest_goes_through_the_canary_first(env):
    c = _synced(env)
    canary, a, b = _host(c, "canary", OLD), _host(c, "a", OLD), _host(c, "b", OLD)

    # no canary on this product: nothing to wait for, and it says a person approves each
    d = _row(c)
    assert sorted(d["plan_asset_ids"]) == sorted([canary, a, b]) and "person's approval" in d["plan_note"]

    _ring0(env, canary)
    d = _row(c)
    assert d["plan_asset_ids"] == [canary] and "Canary machines first" in d["plan_note"]

    jid = _plan(c, canary)
    d = _row(c)  # in flight, the rest wait
    assert d["plan_asset_ids"] == [] and "Waiting for a canary" in d["plan_note"]
    _set_job(env, jid, status="succeeded", updated=now())
    with make_sessionmaker(env)() as s:  # as its next report showed
        s.scalar(select(InstalledPackage).where(InstalledPackage.asset_id == canary)).version = OCT
        s.commit()
    d = _row(c)  # succeeded but not soaked
    assert d["plan_asset_ids"] == [] and "soak" in d["plan_note"]
    with make_sessionmaker(env)() as s:
        hours = s.scalar(select(Org)).canary_soak_hours
    _set_job(env, jid, updated=now() - timedelta(hours=hours + 1))
    d = _row(c)
    assert sorted(d["plan_asset_ids"]) == sorted([a, b]) and d["plan_note"] is None

    # planning changes no approval rule: a planned broad-ring job still waits for its approver
    j2 = _plan(c, a)
    assert next(x for x in c.get("/api/remediation/jobs").json() if x["id"] == j2)["status"] == "planned"

    # a canary that proved only an older update doesn't open this one
    _set_job(env, jid, packages=[{"name": W11, "from": OLD, "kb": "5000000", "to": "10.0.26200.7000"}])
    assert "No canary" in _row(c)["plan_note"]

    # a failure of this update anywhere halts it
    _set_job(env, jid, packages=[{"name": W11, "from": OLD, "kb": KB, "to": OCT}])
    _set_job(env, j2, status="not_fixed", error="still vulnerable")
    d = _row(c)
    assert d["plan_asset_ids"] == [] and "failed on a machine" in d["plan_note"]


def _advisory(s, cve, product, kb, fixed, released="2026-10-13"):
    info = {"kb": kb, "hotpatch": False, **({"released": released} if released else {})}
    s.add(Advisory(id=f"MSRC-{cve}-{product}", ecosystem="Windows", package=product, record={
        "id": f"MSRC-{cve}-{product}", "aliases": [cve], "modified": "m", "summary": "s", "database_specific": info,
        "affected": [{"package": {"ecosystem": "Windows", "name": product.removesuffix(HOTPATCH)},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}]}))


def test_a_host_on_the_hotpatch_track_has_an_update_when_its_cves_are_closed(env):
    p = "Windows Server 2025"
    with make_sessionmaker(env)() as s:
        _advisory(s, "CVE-2026-1", p, "5120001", "10.0.26100.3000")
        _advisory(s, "CVE-2026-1", p + HOTPATCH, "5120002", "10.0.26100.2500")
        s.commit()
    c = user(env)
    _host(c, "hotpatched", "10.0.26100.2500", p)
    _host(c, "behind", "10.0.26100.2400", p)
    d = _row(c, "5120001", p)
    assert (d["hosts"], d["fixed"]) == (2, 1) and [h["hostname"] for h in d["missing"]] == ["behind"]


def test_newest_updates_per_product_no_month_is_guessed_and_an_unreadable_build_is_not_counted(env):
    p = "Windows Server 2025"
    with make_sessionmaker(env)() as s:
        for n in range(5):
            _advisory(s, f"CVE-2026-{n}", p, f"512000{n}", f"10.0.26100.{1000 + n}", f"2026-{5 + n:02d}-10" if n else None)
        _advisory(s, "CVE-2026-9", p, "not-a-kb", "10.0.26100.9000")
        s.commit()
    c = user(env)
    host = _host(c, "pc", "10.0.26100.1", p)
    assert [r["kb"] for r in c.get("/api/windows-updates").json()] == ["5120004", "5120003", "5120002"]
    assert c.get("/api/windows-updates").json()[0]["title"] == "September 2026 cumulative KB5120004"
    assert c.get("/api/windows-updates/5120000", params={"product": p}).status_code == 404

    with make_sessionmaker(env)() as s:
        s.add(Advisory(id="no-month", ecosystem="Windows", package="Windows Server 2022", record={
            "id": "no-month", "aliases": ["CVE-2026-20"], "modified": "m", "summary": "s", "database_specific": {"kb": "5120010"},
            "affected": [{"package": {"ecosystem": "Windows", "name": "Windows Server 2022"},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "10.0.20348.100"}]}]}]}))
        s.commit()
    _host(c, "old-records", "10.0.20348.1", "Windows Server 2022")
    assert next(r for r in c.get("/api/windows-updates").json() if r["kb"] == "5120010")["title"] == "Cumulative KB5120010"

    with make_sessionmaker(env)() as s:  # agent input windows_cmp refuses: can't tell, so not counted either way
        s.scalar(select(InstalledPackage).where(InstalledPackage.asset_id == host)).version = "not a build"
        s.commit()
    assert not [r for r in c.get("/api/windows-updates").json() if r["product"] == p]
