"""The engine on Linux (spec section 7): the distro's own fix against the distro's own package database, T-numbers from section 12."""

import copy
from collections import defaultdict

from sqlalchemy import select
from test_api import user
from test_engine import one

from nimstead import engine
from nimstead.db import Advisory, Asset, Finding, InstalledPackage, make_sessionmaker
from nimstead.engine import parity, report
from nimstead.engine.collection import Inventory, valid_document
from nimstead.engine.content import Content
from nimstead.engine.evaluate import evaluate
from nimstead.engine.model import Grade, Outcome

DEB, ALMA = "Debian:13", "AlmaLinux:9"
CYCLES = {"debian": {"13": "2030-06-30", "11": "2026-08-31"}, "almalinux": {"9": "2032-05-31"}}


def deb(cve, src, fixed=None, urgency="not yet assigned", eco=DEB, also=()):
    events = [{"introduced": "0"}, *([{"fixed": fixed}] if fixed else [])]
    return {"id": f"DEBIAN-{cve}", "upstream": [cve], "modified": "2026-10-20T00:00:00Z", "summary": f"Flaw {cve}",
            "affected": [{"package": {"ecosystem": eco, "name": src}, "ranges": [{"type": "ECOSYSTEM", "events": events}],
                          "ecosystem_specific": {"urgency": urgency}}, *also]}


def alsa(cve, src, fixed):
    return {"id": f"ALSA-{cve}", "upstream": [cve], "modified": "2026-10-20T00:00:00Z",
            "affected": [{"package": {"ecosystem": ALMA, "name": src}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}]}


def pkg(name, version, source=None):
    return {"name": name, "version": version, "source": source or name}


def ldoc(*pkgs, eco=DEB, db=None, facts=None, read="2026-11-03T10:00:00Z"):
    pkgs = [dict(p, ecosystem=eco) for p in pkgs]
    return {"hostname": "deb-1", "os_name": "Debian GNU/Linux 13 (trixie)", "ecosystem": eco, "agent_version": "0.4.0", "collected_at": read,
            "facts": {"os_id": "debian", "os_version_id": "13", "kernel_release": "6.12.48+deb13-amd64", "pending_reboot": None, **(facts or {})},
            "collection": {"v": 1, "sources": {"os_release": {"state": "ok", "count": 1}, "package_db": db or {"state": "ok", "count": len(pkgs), "exit": 0}}},
            "packages": pkgs}


def lcontent(*recs, eco=DEB, universe=(), eol=True):
    records = defaultdict(list)
    for r in recs:
        for name in {a["package"]["name"] for a in r["affected"] if a["package"]["ecosystem"] == eco}:
            records[eco, name].append(r)
    product = "debian" if eco.startswith("Debian") else "almalinux"
    return Content.make(dict(records), feeds={eco}, universe={k for _, k in records} | set(universe), eol=CYCLES[product] if eol else None)


def run(d, c, prior=()):
    return evaluate(Inventory.from_doc(d), c, prior)


SSL = (pkg("libssl3t64", "3.5.1-1+deb13u1", "openssl"), pkg("openssl", "3.5.1-1+deb13u1"))


# ---- R7.4, T11: the distro's fix, the distro's comparison

def test_t11_debian_backport_one_install_per_source_judged_once_with_its_grade():
    vs = run(ldoc(*SSL), lcontent(deb("CVE-2026-1", "openssl", "3.5.1-1+deb13u2"), deb("CVE-2026-2", "openssl", "3.5.1-1+deb13u1"),
                                  deb("CVE-2026-3", "openssl", "3.4.0-1"), universe={"curl"}))
    v = one(vs, vuln_id="CVE-2026-1")
    assert (v.outcome, v.grade, v.source, v.fixed, v.family) == (Outcome.VULNERABLE, Grade.CONFIRMED, "Debian", "3.5.1-1+deb13u2", "distro")
    assert v.instance == "openssl 3.5.1-1+deb13u1" and "dpkg database: libssl3t64, openssl" in v.observed and not v.detail
    assert one(vs, vuln_id="CVE-2026-2").outcome == Outcome.NOT_VULNERABLE  # same upstream, fixed distro revision
    assert one(vs, vuln_id="CVE-2026-3").outcome == Outcome.NOT_VULNERABLE
    assert (one(vs, check="product:curl").outcome) == Outcome.NOT_APPLICABLE  # the distro has advisories for it; it isn't installed


def test_t11_rpm_backport_and_t19_a_half_finished_upgrade_is_two_installs():
    d = ldoc(pkg("openssl-libs", "1:3.0.7-27.el9", "openssl"), pkg("openssl", "1:3.0.7-28.el9"), eco=ALMA)
    vs = run(d, lcontent(alsa("CVE-2026-1", "openssl", "1:3.0.7-28.el9"), alsa("CVE-2026-2", "openssl", "1:3.0.7-25.el9"), eco=ALMA))
    assert {(v.instance, v.outcome) for v in vs if v.vuln_id == "CVE-2026-1"} == {("openssl 1:3.0.7-27.el9", Outcome.VULNERABLE),
                                                                                  ("openssl 1:3.0.7-28.el9", Outcome.NOT_VULNERABLE)}
    assert all(v.outcome == Outcome.NOT_VULNERABLE for v in vs if v.vuln_id == "CVE-2026-2")
    assert one(vs, vuln_id="CVE-2026-1", outcome=Outcome.VULNERABLE).source == "AlmaLinux"


def test_t12_another_release_or_module_stream_never_matches():
    other = {"package": {"ecosystem": "Debian:12", "name": "openssl"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.9.0-1"}]}]}
    v = one(run(ldoc(*SSL), lcontent(deb("CVE-2026-1", "openssl", "3.5.0-1", also=[other]))), vuln_id="CVE-2026-1")
    assert (v.outcome, v.fixed) == (Outcome.NOT_VULNERABLE, "3.5.0-1")  # Debian 12's later fix says nothing about Debian 13
    node18 = pkg("nodejs", "1:18.19.0-1.module_el9.3.0+38+a1b2c3", "nodejs")
    c = lcontent(alsa("CVE-2026-5", "nodejs", "1:20.11.0-1.module_el9.3.0+40+d4e5f6"), alsa("CVE-2026-6", "nodejs", "1:18.20.0-1.module_el9.4.0+41+abc"), eco=ALMA)
    vs = run(ldoc(node18, eco=ALMA), c)
    assert (one(vs, vuln_id="CVE-2026-5").outcome, one(vs, vuln_id="CVE-2026-5").reason) == (Outcome.UNDETERMINED, "other-stream")
    assert one(vs, vuln_id="CVE-2026-6").outcome == Outcome.VULNERABLE
    plain = run(ldoc(pkg("nodejs", "1:16.20.2-8.el9"), eco=ALMA), c)  # the non-modular stream against module fixes
    assert {v.reason for v in plain if v.ecosystem == ALMA and v.vuln_id} == {"other-stream"}


def test_t10_a_version_the_package_manager_would_never_install_is_undetermined():
    v = one(run(ldoc(pkg("openssl", "not-a-version")), lcontent(deb("CVE-2026-1", "openssl", "3.5.1-1+deb13u2"))), vuln_id="CVE-2026-1")
    assert (v.outcome, v.reason) == (Outcome.UNDETERMINED, "incomparable")


# ---- R7.5, R7.6, T13: unfixed statuses and end of support

def test_t13_no_fix_planned_is_its_own_outcome_and_no_fix_yet_another():
    vs = run(ldoc(*SSL), lcontent(deb("CVE-2026-7", "openssl", urgency="unimportant"), deb("CVE-2026-8", "openssl")))
    assert (one(vs, vuln_id="CVE-2026-7").outcome, one(vs, vuln_id="CVE-2026-7").vendor_status) == (Outcome.VULNERABLE, "no-fix-planned")
    assert one(vs, vuln_id="CVE-2026-8").vendor_status == "no-fix-yet"


def test_t13_an_end_of_life_release_says_so_and_its_patch_state_is_undetermined():
    d = ldoc(*[dict(p, version="3.0.15-1~deb11u1") for p in SSL], eco="Debian:11")
    c = lcontent(deb("CVE-2026-1", "openssl", "3.0.16-1~deb11u1", eco="Debian:11"), deb("CVE-2026-2", "openssl", "3.0.14-1", eco="Debian:11"), eco="Debian:11")
    vs = run(d, c)
    eol = one(vs, vuln_id="EOL:debian-11")
    assert (eol.outcome, eol.grade, eol.source) == (Outcome.VULNERABLE, Grade.REASONABLE, "endoflife.date") and "since 2026-08-31" in eol.summary
    assert one(vs, vuln_id="CVE-2026-1").outcome == Outcome.VULNERABLE  # still positive evidence
    assert (one(vs, vuln_id="CVE-2026-2").outcome, one(vs, vuln_id="CVE-2026-2").reason) == (Outcome.UNDETERMINED, "end-of-life")
    assert one(run(ldoc(*SSL), lcontent(deb("CVE-2026-1", "openssl", "3.5.1-1+deb13u2"))), vuln_id="EOL:debian-13").outcome == Outcome.NOT_VULNERABLE
    assert one(run(ldoc(*SSL), lcontent(eol=False)), vuln_id="EOL:debian-13").reason == "eol-unknown"
    assert one(run(ldoc(*SSL, read=None), lcontent()), vuln_id="EOL:debian-13").reason == "eol-unknown"  # judged as of the read, never today
    r = report.build(Inventory.from_doc(d), c, vs)
    assert next(g for g in r["vulnerable"] if g["product"] == "debian 11")["action"] == "Upgrade to a supported release"
    assert parity.compare(vs, [("Debian:11", "openssl", "CVE-2026-1")])["ok"]  # rescan doesn't judge it: explained, not a bug


# ---- R7.7: kernels

def test_r77_a_kernel_installed_but_not_running_is_its_own_state_and_a_newer_fix_means_restart():
    running = pkg("linux-image-6.12.38+deb13-amd64", "6.12.38-1", "linux")
    newer = pkg("linux-image-6.12.48+deb13-amd64", "6.12.48-1", "linux")
    c = lcontent(deb("CVE-2026-1", "linux", "6.12.41-1"), deb("CVE-2026-2", "linux", "6.12.50-1"))
    vs = run(ldoc(running, newer, facts={"kernel_release": "6.12.38+deb13-amd64"}), c)
    live = one(vs, vuln_id="CVE-2026-1", instance="linux 6.12.38-1")
    assert (live.outcome, live.kernel, live.pending_reboot) == (Outcome.VULNERABLE, "running", True)
    assert one(vs, vuln_id="CVE-2026-1", instance="linux 6.12.48-1").kernel == "not-running"
    assert not one(vs, vuln_id="CVE-2026-2", instance="linux 6.12.38-1").pending_reboot  # no installed kernel fixes this one
    assert one(vs, vuln_id="CVE-2026-2", instance="linux 6.12.48-1").outcome == Outcome.VULNERABLE
    text = report.render(report.build(Inventory.from_doc(ldoc(running, newer, facts={"kernel_release": "6.12.38+deb13-amd64"})), c, vs))
    assert "fixed in a newer kernel that's already installed" in text and "installed but not running" in text
    rpm = ldoc(pkg("kernel-core", "0:5.14.0-427.13.1.el9_4", "kernel"), eco=ALMA, facts={"kernel_release": "5.14.0-427.13.1.el9_4.x86_64"})
    assert one(run(rpm, lcontent(alsa("CVE-2026-3", "kernel", "0:5.14.0-503.11.1.el9_5"), eco=ALMA)), vuln_id="CVE-2026-3").kernel == "running"


def test_r77_a_running_kernel_no_package_installed_is_undetermined_never_clean():
    v = one(run(ldoc(*SSL, facts={"kernel_release": "6.6.87.2-microsoft-standard-WSL2"}), lcontent()), check="product:running-kernel")
    assert (v.outcome, v.reason) == (Outcome.UNDETERMINED, "kernel-unpackaged") and "no kernel package is installed" in v.detail


# ---- verdict integrity: T2, T3, T4, R4.3, old agents

def test_t2_t3_a_package_database_not_read_in_full_judges_nothing_and_never_says_not_installed():
    c = lcontent(deb("CVE-2026-1", "openssl", "3.5.1-1+deb13u2"), universe={"curl"})
    for db, outcome, reason in [({"state": "failed", "count": 0, "exit": 2, "error": "dpkg-query exited 2: cannot open status"}, Outcome.NOT_RUN, "precondition-unknown"),
                                ({"state": "partial", "count": 2, "exit": 1, "error": "dpkg-query exited 1"}, Outcome.UNDETERMINED, "source-partial"),
                                ({"state": "ok", "count": 0, "exit": 0}, Outcome.NOT_RUN, "empty-list"),
                                ({"state": "ok", "count": 900, "exit": 0}, Outcome.UNDETERMINED, "source-partial")]:  # 900 read, 2 arrived
        vs = run(ldoc(*SSL, db=db), c, prior=[(DEB, "openssl", "CVE-2026-1")])
        assert not [v for v in vs if v.outcome in (Outcome.NOT_APPLICABLE, Outcome.NOT_VULNERABLE) and v.ecosystem == DEB], db
        assert (one(vs, check="product:curl").outcome, one(vs, check="product:curl").reason, one(vs, check="product:curl").blocker) == (outcome, reason, "package_db")
        assert one(vs, vuln_id="CVE-2026-1").reason == "not-reassessed"  # T7: the open finding stays open
        assert report.build(Inventory.from_doc(ldoc(*SSL, db=db)), c, vs)["headline"]["status"] == "not-assessed"


def test_t4_an_unknown_platform_and_a_missing_feed_are_not_run_and_say_why():
    d = ldoc(*SSL, eco="", facts={"os_unmatched": "no advisory feed maps this platform: ID=linuxmint VERSION_ID=22"})
    v = one(run(d, lcontent()), check="product:platform")
    assert (v.outcome, v.reason, v.family) == (Outcome.NOT_RUN, "unsupported-platform", "distro") and "linuxmint" in v.detail
    assert "package patch state was not assessed" in report.render(report.build(Inventory.from_doc(d), lcontent(), [v]))
    v = one(run(ldoc(*SSL), Content.make({})), check=f"product:{DEB}")
    assert (v.outcome, v.reason) == (Outcome.NOT_RUN, "feed-missing")


def test_an_old_linux_agent_is_not_run_never_clean():
    d = ldoc(*SSL)
    del d["collection"]
    vs = run(d, lcontent(deb("CVE-2026-1", "openssl", "3.5.1-1+deb13u2"), universe={"curl"}))
    assert (one(vs, check="product:curl").outcome, one(vs, check="product:curl").reason) == (Outcome.NOT_RUN, "no-collection-document")
    assert not [v for v in vs if v.outcome in (Outcome.NOT_APPLICABLE, Outcome.NOT_VULNERABLE) and v.ecosystem == DEB]


def test_the_linux_document_with_its_exit_status_is_valid_and_bounded():
    assert valid_document(ldoc(*SSL)["collection"])
    assert not valid_document({"v": 1, "sources": {"package_db": {"state": "ok", "count": 1, "exit": "0"}}})
    assert not valid_document({"v": 1, "sources": {"package_db": {"state": "ok", "count": 1, "exit": True}}})


# ---- end to end, against rescan

def seed(url):
    s = make_sessionmaker(url)()
    for rec in (deb("CVE-2026-1", "openssl", "3.5.1-1+deb13u2"), deb("CVE-2026-2", "openssl", "3.5.0-1"), deb("CVE-2026-3", "curl", "8.0-1"),
                deb("CVE-2026-7", "openssl", urgency="unimportant")):
        s.merge(Advisory(id=rec["id"], ecosystem=DEB, package=rec["affected"][0]["package"]["name"], modified=rec["modified"], record=rec))
    s.merge(Advisory(id="EOL-debian", ecosystem="EOL", package="debian", modified="2026-11-01", record={"id": "EOL-debian", "cycles": CYCLES["debian"]}))
    s.commit()
    return s


def test_linux_report_and_parity_through_the_api_and_a_failed_read_keeps_the_last_list(env):
    s = seed(env)
    c = user(env)
    token = c.post("/api/enroll-tokens").json()["token"]
    a = c.post("/api/agent/enroll", json={"token": token, "hostname": "deb-1", "ecosystem": DEB}).json()
    h = {"Authorization": f"Bearer {a['agent_key']}"}
    inv = ldoc(*SSL, pkg("bash", "5.2.37-2"))
    assert c.post("/api/agent/inventory", headers=h, json=inv).status_code == 200
    aid = a["asset_id"]
    body = c.get(f"/api/assets/{aid}/scan-report").json()
    assert body["headline"]["status"] == "vulnerable" and body["coverage"]["families"]["distro"]["determined"] >= 4
    assert {x["name"]: x["state"] for x in body["coverage"]["sources"]} == {"os_release": "ok", "package_db": "ok"}
    text = report.render(body)
    assert "Distribution packages" in text and "Windows" not in text and "doesn't plan to fix 1" in text

    def check():
        s.expire_all()
        asset = s.get(Asset, aid)
        stored = Inventory.from_asset(asset, s.scalars(select(InstalledPackage).where(InstalledPackage.asset_id == aid)).all())
        verdicts, _ = engine.scan_inventory(s, stored, engine.prior_findings(s, asset))
        found = [(f.ecosystem, f.package, f.vuln_id) for f in s.scalars(select(Finding).where(Finding.asset_id == aid, Finding.status.in_(("open", "accepted"))))]
        return parity.compare(verdicts, found), found
    p, found = check()
    assert p["ok"] and p["agree"] == 2 and len(found) == 2, p  # CVE-2026-1 and the unfixed CVE-2026-7

    broken = copy.deepcopy(inv)
    broken["packages"], broken["collection"]["sources"]["package_db"] = [], {"state": "failed", "count": 0, "exit": 2, "error": "dpkg-query exited 2"}
    assert c.post("/api/agent/inventory", headers=h, json=broken).status_code == 200
    s.expire_all()
    assert len(s.scalars(select(InstalledPackage).where(InstalledPackage.asset_id == aid)).all()) == 3  # the last list stays, so rescan closes nothing
    p, found = check()
    assert len(found) == 2 and p["ok"] and {x["engine"] for x in p["explained"]} == {"not-reassessed"}
    body = c.get(f"/api/assets/{aid}/scan-report").json()
    assert body["headline"]["status"] == "not-assessed"
    assert any(g["reason"] == "precondition-unknown" and g["blocked_by"] == "package_db" for g in body["undetermined"])
