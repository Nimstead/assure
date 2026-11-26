"""The review round on runtime (DECISIONS 164): each test failed before its fix. A hold lasts only while a recent read sees
the old copy; "not loaded" doesn't flap; kernels get no state; a bundled advisory never lowers a local flaw; a finding that
stops matching at the same version closes; a job with one finding still vulnerable isn't waiting for a restart."""

from datetime import timedelta

import pytest
from sqlalchemy import select
from test_api import user
from test_runtime import BASE, ECO, NEW, NGINX, OLD, QUIET, Timeline, base, doc, findings, host, pkgs, prog, read, report

from nimstead import risk, runtime
from nimstead.db import Advisory, Asset, AssetRuntime, Finding, RemediationJob, make_sessionmaker, now
from nimstead.scan import rescan

HELD = read(prog("nginx.service", ["libssl3"], replaced=["libssl3"]))


def held_count(env, aid):
    return len([f for f in findings(env, aid)[1] if f.runtime == "restart"])


def hold(c, h):
    report(c, h, rt=read(NGINX))
    report(c, h, packages=pkgs(NEW), rt=HELD)


def test_a_hold_ends_when_the_agent_stops_reading_what_runs(env):
    c = user(env)
    aid, h = host(c)
    hold(c, h)
    assert held_count(env, aid)
    off = {"os_name": "Debian 12", "ecosystem": ECO, "packages": pkgs(NEW), "agent_version": "0.10.0",
           "collection": {"v": 1, "sources": {**doc(2)["sources"], "runtime": {"state": "off", "count": 0}}}}
    assert c.post("/api/agent/inventory", headers=h, json=off).status_code == 200  # the host opted out: no sighting any more
    assert held_count(env, aid) == 0


def test_a_hold_ends_when_reads_stop_arriving(env):
    c = user(env)
    aid, h = host(c)
    hold(c, h)
    s = make_sessionmaker(env)()
    s.get(AssetRuntime, aid).read_at = now() - runtime.GAP - timedelta(hours=1)  # then an older agent: no read for 37 hours
    s.commit()
    report(c, h, packages=pkgs(NEW), agent="0.9.0")
    assert held_count(env, aid) == 0


def test_a_partial_read_keeps_what_it_couldnt_see(env):
    c = user(env)
    aid, h = host(c)
    hold(c, h)
    n = held_count(env, aid)
    report(c, h, packages=pkgs(NEW), rt=read(prog("cron.service", ["cron"]), state="partial"))  # nginx not read this time
    assert held_count(env, aid) == n
    report(c, h, packages=pkgs(NEW), rt=read(prog("nginx.service", ["libssl3"]), state="partial"))  # seen again, restarted
    assert held_count(env, aid) == 0


def test_not_loaded_doesnt_flap_between_daily_reports(env):
    c = user(env)
    t = Timeline(env, host(c)[0]).add(*((d, QUIET) for d in range(0, 10)))  # one report a day
    assert all(t.view(9 + hours / 24).state(["libssl3"])[0] == "not_loaded" for hours in range(0, 36))


def test_a_partial_reads_native_list_doesnt_unsay_not_loaded(env):
    c = user(env)
    t = Timeline(env, host(c)[0]).add(*((d, QUIET) for d in range(0, 9)))
    t.add((9, read(prog("cron.service", ["cron"]), state="partial", native=())))  # cut short before the lists were read
    assert t.view(9).state(["libssl3"])[0] == "not_loaded"


def test_kernel_packages_get_no_runtime_state():
    assert runtime.is_kernel("linux", ["linux-image-6.12.48+deb13-amd64"]) and runtime.is_kernel("kernel", ["kernel-tools-libs"])
    assert runtime.is_kernel("linux-signed-amd64", ["linux-image-amd64"]) and runtime.is_kernel("linux-lts", ["linux-lts"])
    assert runtime.is_kernel("linux-hwe-6.8", ["linux-tools-6.8.0-45-generic"])
    assert not runtime.is_kernel("openssl", ["libssl3t64"]) and not runtime.is_kernel("util-linux", ["libmount1"])


def test_a_kernel_finding_is_never_lowered_by_runtime(env):
    c = user(env)
    aid, h = host(c)
    kernel = [{"name": "kernel-tools-libs", "version": OLD, "source": "openssl", "ecosystem": ECO}]  # a kernel binary of a fixture source
    s = make_sessionmaker(env)()
    a = s.get(Asset, aid)
    for d in range(9, 0, -1):
        runtime.store(s, a, read(prog("cron.service", ["cron"]), native=("kernel-tools-libs",)), now() - timedelta(days=d))
    s.commit()
    report(c, h, packages=kernel, rt=read(prog("cron.service", ["cron"]), native=("kernel-tools-libs",)))
    assert findings(env, aid)[1] and all(f.runtime is None for f in findings(env, aid)[1])


@pytest.mark.parametrize(("sev", "nvd", "cves", "want"), [
    (["AV:N"], {}, ["CVE-1"], {"N"}),                                                # one CVE, its own vector
    (["AV:N"], {"CVE-1": "AV:N", "CVE-2": "AV:L"}, ["CVE-1", "CVE-2"], {"N", "L"}),  # a bundle: NVD's for each CVE too
    (["AV:N"], {"CVE-1": "AV:N"}, ["CVE-1", "CVE-2"], {"N", "?"}),                   # a bundle with a CVE nobody scored
    ([], {}, ["CVE-1"], {"?"}),
    ([], {"CVE-1": "AV:A"}, ["CVE-1"], {"A"}),
])
def test_attack_vectors_of_a_bundle(sev, nvd, cves, want):
    severity = [{"type": "CVSS_V3", "score": f"CVSS:3.1/{v}/AC:L"} for v in sev]
    assert risk.attack_vectors(severity, {c: f"CVSS:3.1/{v}/AC:L" for c, v in nvd.items()}, cves) == want


def test_unknown_vectors_raise_on_a_listener_but_never_lower():
    assert risk.context(base(), kev=False, runtime=("listening", "why"), vectors={"?"}).score == 75
    assert risk.context(base(), kev=False, runtime=("not_loaded", "why"), vectors={"N", "?"}).score == 60


def test_a_finding_that_stops_matching_at_the_same_version_closes_despite_a_replaced_copy(env):
    c = user(env)
    aid, h = host(c)
    report(c, h, rt=read(NGINX))
    s, fs = findings(env, aid)
    gone = fs[0].vuln_id
    for adv in s.scalars(select(Advisory).where(Advisory.package == "openssl")):
        if gone == adv.id.removeprefix("DEBIAN-") or gone in (adv.record.get("aliases") or []):
            adv.record = {**adv.record, "withdrawn": "2026-11-25T00:00:00Z"}  # withdrawn; the installed version didn't change
    s.commit()
    report(c, h, rt=HELD)
    assert gone in {f.vuln_id for f in findings(env, aid, "resolved")[1]}


def test_a_job_with_a_held_finding_and_a_still_vulnerable_one_is_not_fixed(env):
    c = user(env)
    aid, h = host(c)
    report(c, h, rt=read(NGINX))
    s, fs = findings(env, aid)
    a = s.get(Asset, aid)
    fixed, unfixed = next(f for f in fs if f.fixed_version), next(f for f in fs if not f.fixed_version)  # NEW leaves the second open
    job = RemediationJob(org_id=a.org_id, asset_id=aid, manager="apt", action_key=f"{ECO}|openssl", status="verifying",
                         packages=[{"name": "libssl3", "from": OLD}], finding_ids=[fixed.id, unfixed.id], created_by="t", summary="x")
    s.add(job)
    s.commit()
    jid = job.id
    report(c, h, packages=pkgs(NEW), rt=HELD)
    assert make_sessionmaker(env)().get(RemediationJob, jid).status == "not_fixed"


def test_restart_state_clears_once_a_finding_is_held_for_another_reason(env):
    c = user(env)
    aid, h = host(c)
    hold(c, h)
    s = make_sessionmaker(env)()
    s.get(Asset, aid).collection = None  # an agent with no collection document: phase 4 holds everything, for its own reason
    row = s.get(AssetRuntime, aid)
    row.replaced, row.replaced_count = {}, 0  # and the program has restarted
    s.commit()
    rescan(s, s.get(Asset, aid), inventory_received=False)
    still = s.scalars(select(Finding).where(Finding.asset_id == aid, Finding.status == "open")).all()
    assert still and all(f.runtime != "restart" for f in still)


def test_a_removed_package_stays_held_on_the_next_report(env):
    c = user(env)
    aid, h = host(c)
    report(c, h, packages=pkgs(extra=BASE), rt=read(NGINX))
    n = len(findings(env, aid)[1])
    report(c, h, packages=BASE, rt=HELD)
    report(c, h, packages=BASE, rt=HELD)  # its rows are gone now; the source it was recorded under carries over
    assert held_count(env, aid) == n


def test_valid_checks_replaced_against_a_set():
    import time
    big = read(prog("x", [f"p{i}" for i in range(100_000)], replaced=[f"p{i}" for i in range(5_000)]))
    t = time.perf_counter()
    rt = runtime.valid(big)
    assert time.perf_counter() - t < 1.0 and len(rt["programs"][0]["replaced"]) == 5_000


def test_the_drawer_doesnt_call_stale_reads_covered(env):
    c = user(env)
    aid, h = host(c)
    report(c, h, rt=read(NGINX))
    s = make_sessionmaker(env)()
    row = s.get(AssetRuntime, aid)
    row.since, row.last_complete = now() - timedelta(days=20), now() - timedelta(days=3)
    s.commit()
    fid = findings(env, aid)[1][0].id
    assert c.get(f"/api/findings/{fid}").json()["running"]["covered"] is False


def test_sightings_expire_even_when_no_read_arrives(env):
    # mutation check: the store forgets old sightings, but a host that stops reporting never stores again; the view must expire them
    c = user(env)
    t = Timeline(env, host(c)[0]).add((0, read(NGINX, prog("worker.service", ["openssl"]))))
    assert t.view(6.9).state(["libssl3"])[0] == "listening" and t.view(6.9).state(["openssl"])[0] == "loaded"
    assert t.view(7.1).state(["libssl3"]) == (None, None) and t.view(7.1).state(["openssl"]) == (None, None)
