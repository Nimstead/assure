"""What runs on a host (tasks/spec-runtime.md Module 2, DECISIONS 161): the agent's read stored and remembered for seven days,
findings ranked by it, a fix on disk held open while a program still runs the replaced copy, and the API that shows it."""

import csv
import io
import json
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import select
from test_api import user

from nimstead import risk, runtime
from nimstead.db import Asset, AssetRuntime, Finding, RemediationJob, make_sessionmaker, now

ECO = "Debian:12"
OSV = Path(__file__).parent / "fixtures" / "osv" / "Debian_12__openssl.json"
OLD, NEW = "3.0.11-1~deb12u2", "3.0.99-1~deb12u1"  # NEW is past every fix in the fixture's openssl advisories


def pkgs(version=OLD, extra=()):
    return [{"name": "libssl3", "version": version, "source": "openssl", "ecosystem": ECO},
            {"name": "openssl", "version": version, "source": "openssl", "ecosystem": ECO}, *extra]


def doc(n):
    return {"v": 1, "sources": {"os_release": {"state": "ok", "count": 1}, "package_db": {"state": "ok", "count": n}}}


def read(*programs, state="ok", native=("libssl3", "openssl", "nginx")):
    return {"v": 1, "state": state, "programs": list(programs), "native": list(native), "other_roots": 0}


def prog(name, loads, listen=(), replaced=(), unit=True):
    return {"name": name, "unit": unit, "users": ["www-data"], "count": 2, "listen": list(listen), "loads": list(loads), "replaced": list(replaced)}


NGINX = prog("nginx.service", ["nginx", "libssl3"], ["0.0.0.0:443/tcp", "[::]:443/tcp"])


def host(c, name="web-1"):
    token = c.post("/api/enroll-tokens").json()["token"]
    a = c.post("/api/agent/enroll", json={"token": token, "hostname": name, "ecosystem": ECO}).json()
    return a["asset_id"], {"Authorization": f"Bearer {a['agent_key']}"}


def report(c, h, packages=None, rt=None, agent="0.10.0"):
    packages = pkgs() if packages is None else packages
    body = {"os_name": "Debian 12", "ecosystem": ECO, "packages": packages, "agent_version": agent, "collection": doc(len(packages))}
    if rt is not None:
        body["runtime"] = rt
    r = c.post("/api/agent/inventory", headers=h, json=body)
    assert r.status_code == 200, r.text
    return r.json()


def findings(env, asset_id, status="open"):
    s = make_sessionmaker(env)()
    return s, s.scalars(select(Finding).where(Finding.asset_id == asset_id, Finding.status == status)).all()


# ---- the read, validated ------------------------------------------------------------------------------------------------

def test_valid_keeps_what_fits_and_drops_the_rest():
    assert runtime.valid(None) is None and runtime.valid("x") is None and runtime.valid({"v": 2, "state": "ok"}) is None
    assert runtime.valid({"v": 1, "state": "nonsense"}) is None
    rt = runtime.valid({"v": 1, "state": "partial", "problem": "p" * 999, "other_roots": True, "native": ["a", 3, "a", "b" * 999, "c d"],
                        "programs": ["junk", {"name": ""}, {"name": "n" * 500}, {"name": "evil‮"},
                                     {"name": "nginx.service", "unit": "yes", "count": True, "users": [1, "root", "x\ny"],
                                      "listen": ["0.0.0.0:80/tcp"] * 99 + ["<script>"], "loads": ["libc6", None, "nginx", "a b"],
                                      "replaced": ["libc6", "not-loaded"], "extra": {"x": 1}}]})
    assert rt["problem"] == "p" * 300 and rt["other_roots"] == 0 and rt["native"] == ["a"]  # too long or outside the set: dropped
    [p] = rt["programs"]  # names a host can't have sent honestly are dropped, not cut (security audit)
    assert p == {"name": "nginx.service", "unit": False, "users": ["root"], "count": 1, "listen": ["0.0.0.0:80/tcp"], "loads": ["libc6", "nginx"],
                 "replaced": ["libc6"]}  # a replaced copy is a loaded one; anything else isn't believed
    assert runtime.valid({"v": 1, "state": "ok", "native": ["p" * 100 + str(i) for i in range(40_000)]}) is None  # over BODY_MAX


def test_valid_caps_the_pairs_across_programs(monkeypatch):
    monkeypatch.setattr(runtime, "LOADS", 5)
    rt = runtime.valid(read(prog("a", ["p1", "p2", "p3"]), prog("b", ["p4", "p5", "p6"]), prog("c", ["p7"])))
    assert [len(p["loads"]) for p in rt["programs"]] == [3, 2, 0]


@pytest.mark.parametrize(("where", "net"), [("0.0.0.0:80/tcp", True), ("[::]:80/tcp", True), ("10.1.2.3:5432/tcp", True),
                                            ("127.0.0.1:5432/tcp", False), ("[::1]:53/udp", False), ("127.8.9.10:1/tcp", False),
                                            ("[::ffff:127.0.0.1]:80/tcp", False), ("[::ffff:10.0.0.1]:80/tcp", True), ("nonsense", True)])
def test_network_addresses(where, net):
    assert runtime.network_address(where) is net


# ---- seven days of memory -------------------------------------------------------------------------------------------------

class Timeline:
    """Reads stored for one host at days after a start 30 days ago; view(d) is the host's runtime as seen at day d."""

    def __init__(self, env, asset_id):
        self.s = make_sessionmaker(env)()
        self.a, self.t0 = self.s.get(Asset, asset_id), now() - timedelta(days=30)

    def add(self, *reads):
        for d, rt in reads:
            runtime.store(self.s, self.a, rt, self.t0 + timedelta(days=d))
            self.s.commit()
        return self

    def view(self, d):
        return runtime.View(self.s.get(AssetRuntime, self.a.id), self.t0 + timedelta(days=d))


QUIET = read(prog("cron.service", ["cron"]))


def test_a_sighting_lasts_seven_days_and_not_loaded_needs_seven_complete_days(env):
    c = user(env)
    t = Timeline(env, host(c)[0]).add((0, read(NGINX)))
    assert t.view(0).state(["libssl3"]) == ("listening", "libssl3")
    t.add(*((d, QUIET) for d in range(1, 7)))
    assert t.view(6.9).state(["libssl3", "openssl"]) == ("listening", "libssl3")  # programs come and go; the rank doesn't flap
    t.add(*((d, QUIET) for d in range(7, 10)))
    assert t.view(9).state(["libssl3"]) == ("not_loaded", "libssl3")  # seven days of complete reads, nobody loading it
    assert t.view(9).state(["cron"]) == ("loaded", "cron")  # not in this read's native list, but a sighting is a sighting
    assert t.view(9).state(["unknown-pkg"]) == (None, None)
    assert "libssl3" not in t.view(9).row.seen  # forgotten after seven days


def test_loaded_without_a_listener_is_loaded(env):
    c = user(env)
    t = Timeline(env, host(c)[0]).add((0, read(prog("worker.service", ["libssl3"], ["127.0.0.1:9000/tcp"]))))
    assert t.view(0).state(["libssl3"]) == ("loaded", "libssl3")  # loopback only
    assert "worker.service, not listening on the network" in t.view(0).reason("openssl", "libssl3", "loaded")


def test_gaps_partial_reads_and_stale_reads_conclude_nothing(env):
    c = user(env)
    t = Timeline(env, host(c)[0]).add(*((d, QUIET) for d in (0, 1, 4, 5, 8, 9, 10)))
    assert t.view(10).state(["libssl3"]) == (None, None)  # the two-day gap after day 1 started the seven days again
    t = Timeline(env, host(c, "web-2")[0]).add(*((d, read(prog("cron.service", ["cron"]), state="partial")) for d in range(10)))
    assert t.view(9).state(["libssl3"]) == (None, None)  # partial reads never prove absence
    t = Timeline(env, host(c, "web-3")[0]).add(*((d, QUIET) for d in range(9)))
    assert t.view(8).state(["libssl3"])[0] == "not_loaded" and t.view(10.5).state(["libssl3"]) == (None, None)  # last read too old


def test_a_partial_read_still_counts_what_it_saw(env):
    c = user(env)
    t = Timeline(env, host(c)[0]).add((0, read(NGINX, state="partial")))
    assert t.view(0).state(["libssl3"])[0] == "listening"


# ---- rank ----------------------------------------------------------------------------------------------------------------------

def base():
    return risk.Risk(60, "next", ["x"])


@pytest.mark.parametrize(("state", "vectors", "kw", "change"), [
    ("listening", set(), {}, +15), ("listening", {"N"}, {}, +15), ("listening", {"A"}, {}, +15), ("listening", {"N", "L"}, {}, +15),
    ("listening", {"L"}, {}, 0),  # a local flaw isn't more reachable because the program listens
    ("listening", {"N"}, {"kev": True}, 0),  # a known-exploited score isn't moved
    ("loaded", {"N"}, {}, 0),
    ("not_loaded", {"N"}, {}, -15), ("not_loaded", {"N", "A"}, {}, -15),
    ("not_loaded", set(), {}, 0),  # nothing says how it's reached
    ("not_loaded", {"N", "L"}, {}, 0),  # one of its flaws is local
    ("not_loaded", {"N"}, {"kev": True}, 0), ("not_loaded", {"N"}, {"public_exploit": True}, 0),
    ("not_loaded", {"N"}, {"exploit_db": True}, 0), ("not_loaded", {"N"}, {"msrc": {"exploited": True}}, 0),
    (None, {"N"}, {}, 0),
])
def test_rank_rules(state, vectors, kw, change):
    kw = {"kev": False, **kw}
    plain = risk.context(base(), **kw)
    r = risk.context(base(), **kw, runtime=(state, f"why {state}"), vectors=vectors)
    assert r.score == min(100, round(plain.score * 0.75) if change < 0 else plain.score + change)
    assert (f"why {state}" in r.reasons) == (state in ("listening", "loaded") or change != 0)
    if change < 0:
        assert r.priority == "planned"  # 60 x 0.75 = 45: the tier follows the score


def test_attack_vectors_from_the_advisory_and_nvd():
    sev = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
    assert risk.attack_vectors(sev, {"CVE-1": "CVSS:3.1/AV:L/AC:L"}, ["CVE-1"]) == {"N", "L"}  # both, never one over the other
    assert risk.attack_vectors(None, {"CVE-1": "CVSS:3.1/AV:L/AC:L", "CVE-2": "CVSS:4.0/AV:A/AC:L"}, ["CVE-1", "CVE-2"]) == {"L", "A"}
    assert risk.attack_vectors([{"type": "CVSS_V3", "score": "junk"}], {}, ["CVE-1"]) == {"?"} and risk.attack_vectors(None, {"CVE-1": "AV:X"}, ["CVE-1"]) == {"?"}


def vectors_of(vuln_id):
    """The fixture advisory's own attack vectors for a CVE (Debian's records carry upstream CVSS where it exists)."""
    rec = next(r for r in json.loads(OSV.read_text())["records"] if r["id"].removeprefix("DEBIAN-") == vuln_id)
    return risk.attack_vectors(rec.get("severity"))


def test_a_listening_service_raises_the_findings_on_the_library_it_loaded(env):
    c = user(env)
    plain, ph = host(c, "plain")
    seen, sh = host(c, "seen")
    report(c, ph)
    report(c, sh, rt=read(NGINX))
    s, before = findings(env, plain)
    _, after = findings(env, seen)
    by = {f.vuln_id: f for f in after}
    assert before and all(f.runtime is None for f in before)
    raised = 0
    for f in before:
        g = by[f.vuln_id]
        reachable = not vectors_of(f.vuln_id) or vectors_of(f.vuln_id) & {"N", "A"}
        assert g.runtime == "listening" and g.score == (min(100, f.score + 15) if reachable and not f.kev else f.score)
        assert any(r.startswith("libssl3 (from openssl) is loaded by nginx.service, listening on 0.0.0.0:443/tcp and [::]:443/tcp") for r in g.reasons)
        raised += g.score > f.score
    assert raised > 20  # most of them: the fixture's flaws are mostly network ones


def test_not_loaded_lowers_network_flaws_only_after_seven_days(env):
    c = user(env)
    aid, h = host(c)
    report(c, h)
    s, fs = findings(env, aid)
    scores = {f.vuln_id: f.score for f in fs}
    a, t = s.get(Asset, aid), now()
    for d in range(9, 0, -1):  # complete reads a day apart, nothing loading openssl
        runtime.store(s, a, QUIET, t - timedelta(days=d))
    s.commit()
    report(c, h, rt=QUIET)
    s, fs = findings(env, aid)
    lowered = 0
    for f in fs:
        assert f.runtime == "not_loaded"
        v = vectors_of(f.vuln_id)
        if v and v <= {"N", "A"} and not f.kev:
            assert f.score == round(scores[f.vuln_id] * 0.75) and any(r.startswith("Not loaded by any long-running program in 7 days") for r in f.reasons)
            lowered += 1
        else:  # local, physical or unknown: unchanged
            assert f.score == scores[f.vuln_id] and not any(r.startswith("Not loaded") for r in f.reasons)
    assert lowered > 20


def test_an_older_agent_is_judged_exactly_as_before(env):
    c = user(env)
    a1, h1 = host(c, "old")
    a2, h2 = host(c, "old-2")
    report(c, h1, agent="0.9.0")
    report(c, h2, agent="0.10.0", rt="not a read")
    _, f1 = findings(env, a1)
    _, f2 = findings(env, a2)
    assert [(f.vuln_id, f.score, f.reasons, f.runtime) for f in f1] == [(f.vuln_id, f.score, f.reasons, f.runtime) for f in f2]
    assert all(f.runtime is None for f in f1)


# ---- a fix counts when nothing runs the old code ------------------------------------------------------------------------------

def fixed_by_new(env, asset_id):
    """The open findings NEW fixes (some of the fixture's advisories have no fix yet: those stay matched)."""
    return {f.vuln_id for f in findings(env, asset_id)[1] if f.fixed_version}


def test_a_fix_on_disk_stays_open_until_the_program_restarts(env):
    c = user(env)
    aid, h = host(c)
    report(c, h, rt=read(NGINX))
    fixed = fixed_by_new(env, aid)
    assert len(fixed) > 20
    # apt replaced libssl3 and openssl; nginx still runs the old libssl3 (its maps say "(deleted)")
    after = report(c, h, packages=pkgs(NEW), rt=read(prog("nginx.service", ["nginx", "libssl3"], ["0.0.0.0:443/tcp"], replaced=["libssl3"])))
    assert after["resolved"] == 0
    s, still = findings(env, aid)
    held = [f for f in still if f.runtime == "restart"]
    assert {f.vuln_id for f in held} == fixed and all(f.runtime == "listening" for f in still if f.vuln_id not in fixed)
    assert all(f.reasons[-1] == "Still open: the fixed version is installed, but nginx.service still runs the copy it replaced: "
               "restart it (or the machine)" for f in held)
    assert {x["runtime"] for x in c.get("/api/findings", params={"runtime": "restart"}).json()} == {"restart"}
    [r] = c.get("/api/summary").json()["restarts"]
    assert (r["package"], r["findings"], r["hosts"], r["programs"]) == ("openssl", len(fixed), ["web-1"], ["nginx.service"])
    # restarted: the next read has no replaced copy
    assert report(c, h, packages=pkgs(NEW), rt=read(prog("nginx.service", ["nginx", "libssl3"], ["0.0.0.0:443/tcp"])))["resolved"] == len(fixed)
    assert c.get("/api/summary").json()["restarts"] == []


def test_without_a_read_a_fix_closes_as_before(env):
    c = user(env)
    aid, h = host(c)
    report(c, h)
    fixed = fixed_by_new(env, aid)
    assert report(c, h, packages=pkgs(NEW))["resolved"] == len(fixed)


def test_a_replaced_copy_holds_nothing_until_the_version_changes(env):
    c = user(env)
    aid, h = host(c)
    report(c, h, rt=read(prog("nginx.service", ["libssl3"], replaced=["libssl3"])))
    _, fs = findings(env, aid)
    assert fs and all(f.runtime == "loaded" for f in fs)  # still matched: ranked, not held


BASE = [{"name": "base-files", "version": "12.4+deb12u5", "source": "base-files", "ecosystem": ECO}]


def test_a_removed_package_still_running_is_said_so(env):
    c = user(env)
    aid, h = host(c)
    report(c, h, packages=pkgs(extra=BASE), rt=read(NGINX))
    n = len(findings(env, aid)[1])
    report(c, h, packages=BASE, rt=read(prog("nginx.service", ["libssl3"], replaced=["libssl3"])))
    _, held = findings(env, aid)
    assert len(held) == n and all(f.reasons[-1] == "Still open: the package is removed, but nginx.service still runs the copy it "
                                  "replaced: restart it (or the machine)" for f in held)
    assert report(c, h, packages=BASE, rt=QUIET)["resolved"] == n


def test_a_job_waits_for_the_restart_then_succeeds(env):
    c = user(env)
    aid, h = host(c)
    report(c, h, rt=read(NGINX))
    s, fs = findings(env, aid)
    a = s.get(Asset, aid)
    job = RemediationJob(org_id=a.org_id, asset_id=aid, manager="apt", action_key=f"{ECO}|openssl", status="verifying",
                         packages=[{"name": "libssl3", "from": OLD}, {"name": "openssl", "from": OLD}],
                         finding_ids=[f.id for f in fs if f.fixed_version], created_by="test", summary="Upgrade openssl")
    s.add(job)
    s.commit()
    jid = job.id
    report(c, h, packages=pkgs(NEW), rt=read(prog("nginx.service", ["libssl3"], replaced=["libssl3"])))
    s = make_sessionmaker(env)()
    j = s.get(RemediationJob, jid)
    assert j.status == "verifying" and j.error == "Waiting for a restart: the fix is installed, but nginx.service still runs the copy it replaced"
    report(c, h, packages=pkgs(NEW), rt=read(prog("nginx.service", ["libssl3"])))
    s = make_sessionmaker(env)()
    j = s.get(RemediationJob, jid)
    assert j.status == "succeeded" and j.error is None


def test_a_job_waiting_a_week_says_why_it_failed(env):
    from nimstead import remediate
    c = user(env)
    aid, h = host(c)
    s = make_sessionmaker(env)()
    a = s.get(Asset, aid)
    job = RemediationJob(org_id=a.org_id, asset_id=aid, manager="apt", action_key=f"{ECO}|openssl", status="verifying", packages=[],
                         finding_ids=[], created_by="test", summary="x", error=remediate.WAITING + "x", updated=now() - timedelta(days=8))
    s.add(job)
    s.commit()
    remediate.sweep(s, a.org_id)
    assert (job.status, job.error) == ("failed", remediate.RESTART_TIMEOUT_ERROR)


# ---- the API ---------------------------------------------------------------------------------------------------------------------

def test_findings_filter_csv_drawer_and_machine(env):
    c = user(env)
    aid, h = host(c)
    other, oh = host(c, "db-1")
    report(c, h, rt=read(NGINX, prog("sshd.service", ["openssh-server"], ["0.0.0.0:22/tcp"])))
    report(c, oh, rt=read(prog("cron.service", ["cron"])))
    listening = c.get("/api/findings", params={"runtime": "listening"}).json()
    assert listening and {f["hostname"] for f in listening} == {"web-1"}
    assert c.get("/api/findings", params={"runtime": "listening,loaded", "view": "list"}).json()[0]["runtime"] == "listening"
    assert c.get("/api/findings", params={"runtime": "bogus"}).status_code == 422
    assert c.get("/api/findings/count", params={"runtime": "listening"}).json()["total"] == len(listening)
    rows = list(csv.DictReader(io.StringIO(c.get("/api/findings.csv").text)))
    assert list(rows[0])[-1] == "runtime" and {r["runtime"] for r in rows if r["hostname"] == "web-1"} == {"listening"}
    d = c.get(f"/api/findings/{listening[0]['id']}").json()["running"]
    assert d["state"] == "listening" and d["binary"] == "libssl3" and d["binaries"] == ["libssl3", "openssl"]
    assert d["programs"] == [{"name": "nginx.service", "users": ["www-data"], "listen": ["0.0.0.0:443/tcp", "[::]:443/tcp"], "loads": ["libssl3"], "replaced": []}]
    assert d["read_state"] == "ok" and d["covered"] is False and d["reason"].startswith("libssl3 (from openssl) is loaded by nginx.service")
    m = c.get(f"/api/assets/{aid}/runtime").json()
    assert [p["name"] for p in m["programs"]] == ["nginx.service", "sshd.service"] and m["programs"][0]["loads"] == 2
    top = next(x for x in c.get("/api/summary").json()["top_actions"] if x["package"] == "openssl")
    assert top["runtime"] == {"listening": 1, "loaded": 1, "not_loaded": 0}
    plain, _ = host(c, "plain")
    assert c.get(f"/api/assets/{plain}/runtime").json() is None


def test_another_orgs_machine_is_not_found(env):
    c = user(env)
    aid, h = host(c)
    report(c, h, rt=read(NGINX))
    c2 = user(env, "other@example.com")
    assert c2.get(f"/api/assets/{aid}/runtime").status_code == 404


def test_the_approval_names_the_services_a_fix_will_restart(env):
    c = user(env)
    aid, h = host(c)
    report(c, h, rt=read(NGINX, prog("dbus.service", ["libssl3"]), prog("python3", ["libssl3"], unit=False), prog("cron.service", ["cron"])))
    job = c.post("/api/remediation/jobs", json={"asset_id": aid, "ecosystem": ECO, "package": "openssl"}).json()
    assert job["restarts"] == {"services": ["nginx.service"], "left": ["dbus.service", "python3"]}
    [listed] = c.get("/api/remediation/jobs").json()
    assert listed["restarts"] == job["restarts"]
    plain, ph = host(c, "plain")
    report(c, ph)
    assert c.post("/api/remediation/jobs", json={"asset_id": plain, "ecosystem": ECO, "package": "openssl"}).json()["restarts"] == {"services": [], "left": []}


def test_server_and_agent_never_restart_the_same_services():
    import importlib.util
    from pathlib import Path
    spec = importlib.util.spec_from_file_location("nimstead_agent", Path(__file__).parents[2] / "agent" / "nimstead_agent.py")
    agent = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(agent)
    assert agent.RESTART_NEVER.pattern == runtime.RESTART_NEVER.pattern


def test_a_fix_waiting_for_a_restart_is_not_planned_or_recommended_again(env):
    c = user(env)
    aid, h = host(c)
    report(c, h, rt=read(NGINX))
    report(c, h, packages=pkgs(NEW), rt=read(prog("nginx.service", ["libssl3"], ["0.0.0.0:443/tcp"], replaced=["libssl3"])))
    held = c.get("/api/findings", params={"runtime": "restart"}).json()
    assert held and all(f["plannable"] is False for f in held)  # the upgrade is done: a plan would only abort
    r = c.post("/api/remediation/jobs", json={"asset_id": aid, "ecosystem": ECO, "package": "openssl"})
    assert r.status_code == 409 and "restart nginx.service" in r.json()["detail"]
    assert all(x["package"] != "openssl" or not set(x["vulns"]) & {f["vuln_id"] for f in held} for x in c.get("/api/summary").json()["top_actions"])


def test_only_a_complete_recent_read_says_what_listens_now():
    from types import SimpleNamespace
    t = now()
    row = SimpleNamespace(state="ok", read_at=t - timedelta(hours=2), programs=[{"name": "ssh.service", "unit": True, "users": ["root"], "count": 1,
                                                                             "listen": ["0.0.0.0:22/tcp"], "loads": []}])
    assert runtime.recent_programs(row, t) == [{"name": "ssh.service", "unit": True, "users": ["root"], "listen": ["0.0.0.0:22/tcp"]}]
    assert runtime.recent_programs(SimpleNamespace(**{**vars(row), "state": "partial"}), t) is None
    assert runtime.recent_programs(SimpleNamespace(**{**vars(row), "read_at": t - timedelta(days=3)}), t) is None  # left from before an opt-out
    assert runtime.recent_programs(None, t) is None
