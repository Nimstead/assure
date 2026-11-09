"""The engine on software outside the OS package manager (spec R7.9): SBOM components and the agent's opt-in language-package scans."""

import json

from sqlalchemy import select
from test_agent_remediate import agent
from test_api import user
from test_engine import doc, enrolled, one
from test_engine_linux import ldoc, pkg
from test_sbom import LOG4J, app_asset, bom, comp, maven_env, put  # noqa: F401 - maven_env: the real log4j-core OSV records

from nimstead import engine
from nimstead.db import Advisory, Asset, Finding, InstalledPackage, make_sessionmaker
from nimstead.engine import parity, report
from nimstead.engine.collection import Inventory, valid_document
from nimstead.engine.content import Content
from nimstead.engine.evaluate import evaluate
from nimstead.engine.model import Grade, Outcome


def ghsa(gid, eco, name, fixed, cve=None, introduced="0"):
    return {"id": gid, "aliases": [cve] if cve else [], "modified": "2026-10-01T00:00:00Z", "summary": f"Flaw in {name}",
            "affected": [{"package": {"ecosystem": eco, "name": name}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": introduced}, {"fixed": fixed}]}]}]}


REQUESTS = ghsa("GHSA-x84v-xcm2-53pg", "PyPI", "requests", "2.20.0", "CVE-2018-18074")


def sbom_inv(*pkgs, skipped=None):
    return Inventory(hostname="billing", kind="application", received=False, packages=[{**p, "origin": "sbom"} for p in pkgs],
                     sbom={"received": "2026-11-03T09:00:00", "components": len(pkgs) + sum((skipped or {}).values()), "mapped": len(pkgs),
                           "skipped": skipped or {"no_purl": 0, "unsupported_or_invalid_purl": 0}})


def pypi(name, version, **kw):
    return {"ecosystem": "PyPI", "name": name, "version": version, "source": None, **kw}


# ---- 1. SBOM components (R4.4: what it can't name is counted, never clean)

def test_an_sbom_component_is_judged_unverified_and_says_an_sbom_is_not_whats_running():
    c = Content.make({("PyPI", "requests"): [REQUESTS], ("PyPI", "idna"): []}, feeds={"PyPI"})
    inv = sbom_inv(pypi("requests", "2.19.1"), pypi("idna", "3.7"), skipped={"no_purl": 2, "unsupported_or_invalid_purl": 1})
    vs = evaluate(inv, c)
    v = one(vs, vuln_id="CVE-2018-18074")
    assert (v.outcome, v.grade, v.family, v.fixed, v.source) == (Outcome.VULNERABLE, Grade.UNVERIFIED, "application", "2.20.0", "GitHub Advisory Database")
    assert "what was built, not what's running" in v.detail and v.observed == "2.19.1 (SBOM component, received 2026-11-03)"
    assert not [x for x in vs if x.product == "idna"]  # no advisory: not a check, and counted below
    assert {(x.check, x.outcome, x.instance) for x in vs if x.reason == "sbom-unmapped"} == {
        ("product:sbom-no_purl", Outcome.NOT_RUN, "2 components"), ("product:sbom-unsupported_or_invalid_purl", Outcome.NOT_RUN, "1 component")}
    r = report.build(inv, c, vs)
    said = " ".join(r["coverage"]["statements"])
    assert "what was built, not what's running" in said and "3 of its 5 components weren't assessed" in said and "1 of 2 installs" in said
    assert r["coverage"]["sources"] == [{"name": "sbom", "label": "SBOM", "state": "ok", "count": 2, "error": None}]
    text = report.render(r)
    assert "Application, from its SBOM (no agent)" in text and "requests 2.19.1   how sure: unverified" in text


def test_an_sbom_at_the_fix_is_not_vulnerable_and_still_unverified():
    c = Content.make({("PyPI", "requests"): [REQUESTS]}, feeds={"PyPI"})
    v = one(evaluate(sbom_inv(pypi("requests", "2.31.0")), c), vuln_id="CVE-2018-18074")
    assert (v.outcome, v.grade) == (Outcome.NOT_VULNERABLE, Grade.UNVERIFIED)
    assert report.build(sbom_inv(pypi("requests", "2.31.0")), c, [v])["headline"]["status"] == "no-known-vulnerabilities"


def test_a_component_whose_ecosystem_has_no_feed_is_not_run_and_an_application_with_no_sbom_is_not_assessed():
    v = one(evaluate(sbom_inv({"ecosystem": "NuGet", "name": "Newtonsoft.Json", "version": "12.0.1", "source": None}), Content.make({}, feeds=set())),
            product="Newtonsoft.Json")
    assert (v.outcome, v.reason) == (Outcome.NOT_RUN, "feed-missing")
    empty = Inventory(hostname="billing", kind="application", received=False)
    vs = evaluate(empty, Content.make({}))
    assert [(x.outcome, x.reason) for x in vs] == [(Outcome.NOT_RUN, "no-sbom")]
    assert report.build(empty, Content.make({}), vs)["headline"]["status"] == "not-assessed"


def test_sbom_upload_through_the_api_has_parity_with_rescan(maven_env):  # noqa: F811
    c = user(maven_env)
    a = app_asset(c)
    assert put(c, a["id"], bom(comp(LOG4J), comp("pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"), comp("pkg:deb/debian/x@1"),
                               {"type": "file", "name": "no-purl"})).status_code == 200
    r = c.get(f"/api/assets/{a['id']}/scan-report").json()
    assert r["headline"]["status"] == "vulnerable" and r["kind"] == "application"
    g = {x["instance"]: x for x in r["vulnerable"]}["org.apache.logging.log4j:log4j-core 2.14.1"]  # T19: each version its own install
    assert g["grade"] == "unverified" and "CVE-2021-44228" in [x["id"] for x in g["vulnerabilities"]]
    assert any(x["instance"] == "org.apache.logging.log4j:log4j-core 2.17.1" for x in r["not_vulnerable"])
    assert {x["reason"] for x in r["undetermined"]} >= {"sbom-unmapped"}
    s = make_sessionmaker(maven_env)()
    asset = s.get(Asset, a["id"])
    inv = Inventory.from_asset(asset, s.scalars(select(InstalledPackage).where(InstalledPackage.asset_id == asset.id)).all(), engine.sbom_received(s, asset))
    verdicts, _ = engine.scan_inventory(s, inv, engine.prior_findings(s, asset))
    found = [(f.ecosystem, f.package, f.vuln_id) for f in s.scalars(select(Finding).where(Finding.asset_id == asset.id, Finding.status == "open"))]
    p = parity.compare(verdicts, found)
    assert found and p["ok"] and p["agree"] == len(found) and not p["outside_this_slice"], p


# ---- 2. the agent's opt-in scans: each install's own metadata, read, never run (DECISIONS 92)

def dist(sp, name, version, kind="dist-info", text=None):
    sp.mkdir(parents=True, exist_ok=True)
    text = text or f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\nName: not-this\nVersion: 0\n"
    if kind == "egg-info file":
        (sp / f"{name}-{version}.egg-info").write_text(text)
        return sp / f"{name}-{version}.egg-info"
    d = sp / f"{name}-{version}.{kind}"
    d.mkdir()
    (d / ("METADATA" if kind == "dist-info" else "PKG-INFO")).write_text(text)
    return d


def npm(nm, name, version, raw=None):
    d = nm / name
    d.mkdir(parents=True)
    (d / "package.json").write_text(raw or json.dumps({"name": name, "version": version, "description": "x"}))
    return d


NONE = ((), ())  # no well-known folders: the tests read only what they made


def scan(roots, **kw):
    return agent.scan_apps([str(r) for r in roots], known=NONE, mounts=[], **kw)


def test_t19_every_install_is_read_from_its_own_metadata_and_located(tmp_path):
    sp1 = tmp_path / "billing" / ".venv" / "lib" / "python3.13" / "site-packages"
    sp2 = tmp_path / "reports" / "venv" / "lib" / "python3.13" / "site-packages"
    old = dist(sp1, "requests", "2.19.1")
    dist(sp1, "Typing_Extensions", "4.0.0")
    dist(sp1, "PyYAML", "5.3", "egg-info file")
    dist(sp1, "six", "1.16.0", "egg-info")
    new = dist(sp2, "requests", "2.32.3")
    nm = tmp_path / "web" / "node_modules"
    lodash = npm(nm, "lodash", "4.17.15")
    npm(nm, "@types/node", "20.1.0")
    mk = npm(nm, "mkdirp", "0.5.1")
    npm(mk / "node_modules", "minimist", "0.0.8")
    (nm / ".bin").mkdir()
    pkgs, py, js, summary = scan([tmp_path])
    got = {(p["ecosystem"], p["name"], p["version"], p["source"]) for p in pkgs}
    assert ("PyPI", "requests", "2.19.1", str(old)) in got and ("PyPI", "requests", "2.32.3", str(new)) in got
    assert {(e, n, v) for e, n, v, _ in got} == {("PyPI", "requests", "2.19.1"), ("PyPI", "requests", "2.32.3"), ("PyPI", "typing-extensions", "4.0.0"),
                                                 ("PyPI", "pyyaml", "5.3"), ("PyPI", "six", "1.16.0"), ("npm", "lodash", "4.17.15"),
                                                 ("npm", "@types/node", "20.1.0"), ("npm", "mkdirp", "0.5.1"), ("npm", "minimist", "0.0.8")}
    assert ("npm", "lodash", "4.17.15", str(lodash)) in got
    assert py == {"state": "ok", "count": 5} and js == {"state": "ok", "count": 4} and summary["folders"] == 3


def test_what_cant_be_read_or_named_leaves_the_scan_partial_and_a_budget_says_where_it_stopped(tmp_path):
    sp = tmp_path / "site-packages"
    dist(sp, "requests", "2.19.1")
    dist(sp, "broken", "1.0", text="Metadata-Version: 2.1\nName: broken\n")  # no version
    dist(sp, "evil", "1.0", text="Name: ../../etc\nVersion: 1.0\n")
    npm(tmp_path / "node_modules", "bad", "1", raw='{"name": "Not A Name", "version": "1.0.0"}')
    pkgs, py, js, _ = scan([sp, tmp_path / "node_modules", tmp_path / "gone"])
    assert [p["name"] for p in pkgs] == ["requests"]
    assert py["state"] == "partial" and py["count"] == 1 and "2 installs' metadata couldn't be read" in py["error"] and "gone: not a folder" in py["error"]
    assert js["state"] == "failed" and js["count"] == 0
    _, py, js, _ = scan([sp], entries=1)
    assert py["state"] == js["state"] == "partial" and "budget" in py["error"]


def test_r79_what_the_package_manager_owns_is_left_to_it(tmp_path):
    sp = tmp_path / "usr" / "lib" / "python3" / "dist-packages"
    owned_dir = dist(sp, "requests", "2.31.0")
    mine = dist(sp, "flask", "2.0.0")
    js = npm(tmp_path / "node_modules", "semver", "7.5.1")
    info = tmp_path / "dpkg-info"
    info.mkdir()
    (info / "python3-requests.list").write_text(f"/.\n{sp}\n{owned_dir}\n{owned_dir}/METADATA\n")
    (info / "node-semver.list").write_text(f"{js}/package.json\n")
    owned, problem = agent.package_owned(dpkg_info=str(info), apk_db=str(tmp_path / "no-apk"), nt=False)
    assert problem is None and owned(str(owned_dir)) and not owned(str(mine))
    pkgs, py, _, summary = scan([sp, tmp_path / "node_modules"], owned=owned)
    assert [p["name"] for p in pkgs] == ["flask"] and summary["owned"] == 2 and py == {"state": "ok", "count": 1}
    apk = tmp_path / "installed"
    apk.write_text("P:py3-requests\nV:2.32.3-r0\nF:usr/lib/python3.12/site-packages/requests-2.32.3.dist-info\nR:METADATA\n\n")
    owned, _ = agent.package_owned(dpkg_info=str(info), apk_db=str(apk), nt=False)
    assert owned("/usr/lib/python3.12/site-packages/requests-2.32.3.dist-info") and not owned(str(mine))
    owned, _ = agent.package_owned(dpkg_info=str(tmp_path / "none"), apk_db=str(tmp_path / "none"), which=lambda c: "/usr/bin/rpm" if c == "rpm" else None, nt=False)
    assert owned("/usr/lib64/python3.9/site-packages/requests-2.25.1.dist-info") and not owned("/usr/local/lib/python3.9/site-packages/x-1.dist-info")


def test_off_reads_as_off_and_only_a_local_choice_turns_a_scan_on(tmp_path, monkeypatch):
    for k in ("PY_ROOTS_NT", "NPM_ROOTS_NT", "PY_ROOTS", "NPM_ROOTS"):
        monkeypatch.setattr(agent, k, ())
    dist(tmp_path / "site-packages", "requests", "2.19.1")
    base = {"os_name": "Debian", "ecosystem": "Debian:13", "packages": [], "facts": {}, "collection": {"v": 1, "sources": {"package_db": {"state": "ok", "count": 1}}}}
    inv = agent.with_apps(json.loads(json.dumps(base)), {})
    assert {k: v["state"] for k, v in inv["collection"]["sources"].items()} == {"package_db": "ok", "java_archives": "off", "python_packages": "off", "npm_packages": "off"}
    assert inv["packages"] == [] and valid_document(inv["collection"])
    inv = agent.with_apps(json.loads(json.dumps(base)), {"scan_apps": True, "app_roots": [str(tmp_path)]})
    assert inv["collection"]["sources"]["python_packages"] == {"state": "ok", "count": 1} and inv["packages"][0]["name"] == "requests"
    assert inv["facts"]["app_scan"]["roots"] == [str(tmp_path)] and valid_document(inv["collection"])
    monkeypatch.setattr(agent, "collect", lambda: json.loads(json.dumps(base)))
    assert agent.main(["collect", "--app-root", str(tmp_path)]) == 1  # a root means nothing without the scan
    saved = {}
    monkeypatch.setattr(agent, "post", lambda *a, **kw: {"asset_id": "a1", "agent_key": "nma_k", "scan_apps": False, "app_roots": ["/etc"]})
    monkeypatch.setattr(agent, "save_config", lambda cfg: saved.update(cfg) or "cfg")
    assert agent.main(["enroll", "--server", "https://n.example", "--token", "t", "--scan-apps", "--app-root", str(tmp_path)]) == 0
    assert saved["scan_apps"] is True and saved["app_roots"] == [str(tmp_path)]  # the server's answer can't choose them


# ---- 3. the host's verdicts and report

REQ_OLD, REQ_NEW = "/srv/billing/.venv/lib/python3.13/site-packages/requests-2.19.1.dist-info", "/srv/reports/venv/lib/python3.13/site-packages/requests-2.32.3.dist-info"
APPS = (pypi("requests", "2.19.1", source=REQ_OLD), pypi("requests", "2.32.3", source=REQ_NEW))
SCANNED = {"python_packages": {"state": "ok", "count": 2}, "npm_packages": {"state": "off", "count": 0}, "java_archives": {"state": "off", "count": 0}}


def app_doc(*pkgs, lines=None, **kw):
    d = ldoc(pkg("bash", "5.2.37-2"), **kw)  # a package list read in full: the agent rows are this read's
    d["packages"] += list(pkgs)
    d["collection"]["sources"].update(lines or SCANNED)
    return d


def test_t19_each_location_is_judged_alone_graded_reasonable_and_reported_where_it_is():
    c = Content.make({("PyPI", "requests"): [REQUESTS]}, feeds={"PyPI", "Debian:13"})
    inv = Inventory.from_doc(app_doc(*APPS))
    vs = evaluate(inv, c)
    assert {(v.instance, v.outcome, v.grade) for v in vs if v.vuln_id == "CVE-2018-18074"} == {
        (f"requests 2.19.1 at {REQ_OLD}", Outcome.VULNERABLE, Grade.REASONABLE), (f"requests 2.32.3 at {REQ_NEW}", Outcome.NOT_VULNERABLE, Grade.REASONABLE)}
    r = report.build(inv, c, vs)
    [g] = r["vulnerable"]
    assert g["instance"] == f"requests 2.19.1 at {REQ_OLD}" and g["source"] == "GitHub Advisory Database" and g["action"] == "Update to 2.20.0 or later"
    said = " ".join(r["coverage"]["statements"])
    assert "Not looked for on this host, so not assessed: npm packages, Java archives" in said
    assert {s["name"]: s["state"] for s in r["coverage"]["sources"]}["npm_packages"] == "off"
    assert r["coverage"]["families"]["application"] == {"label": "Applications outside the package manager", "attempted": 2, "determined": 2,
                                                         "outcomes": {"not-vulnerable": 1, "vulnerable": 1}}
    text = report.render(r)
    assert "Why not surer: The version is the install's own metadata" in text and "What's vulnerable" not in text
    section = text.split("Applications outside the package manager, by location\n")[1].split("\n\n")[0]
    assert section.startswith(f"  requests 2.19.1 at {REQ_OLD}   how sure: reasonable")  # vulnerable first, in the same form as any install
    assert section.endswith(f"  requests 2.32.3 at {REQ_NEW}   no known vulnerability (1 not-vulnerable)   how sure: reasonable")
    assert r["coverage"]["applications"] == {"installs": 2, "judged": 2, "vulnerable": 1, "no_advisory": 0, "left_to_package_manager": 0,
                                             "sbom_components_not_assessed": 0, "not_looked_for": ["npm packages", "Java archives"]}
    assert [a["outcomes"] for a in r["applications"]] == [{"vulnerable": 1}, {"not-vulnerable": 1}]


def test_a_partial_scan_lowers_its_readings_and_says_an_install_could_be_missing():
    c = Content.make({("PyPI", "requests"): [REQUESTS]}, feeds={"PyPI", "Debian:13"})
    part = {**SCANNED, "python_packages": {"state": "partial", "count": 2, "error": "stopped after 300000 entries / 120 s (budget)"}}
    vs = evaluate(Inventory.from_doc(app_doc(*APPS, lines=part)), c)
    assert {v.grade for v in vs if v.vuln_id and v.family == "application"} == {Grade.UNVERIFIED}
    v = one(vs, check="product:python_packages")
    assert (v.outcome, v.reason, v.blocker) == (Outcome.UNDETERMINED, "source-partial", "python_packages")


def test_t3_fewer_installs_than_the_agent_read_is_partial():
    vs = evaluate(Inventory.from_doc(app_doc(APPS[0], lines={**SCANNED, "python_packages": {"state": "ok", "count": 2}})),
                  Content.make({("PyPI", "requests"): [REQUESTS]}, feeds={"PyPI", "Debian:13"}))
    assert one(vs, check="product:python_packages").reason == "source-partial" and one(vs, vuln_id="CVE-2018-18074").grade == Grade.UNVERIFIED


def test_a_package_list_kept_from_the_last_read_judges_no_app_and_carries_its_findings():
    failed = {"state": "failed", "count": 0, "error": "dpkg-query exited 2"}
    vs = evaluate(Inventory.from_doc(app_doc(*APPS, db=failed)), Content.make({("PyPI", "requests"): [REQUESTS]}, feeds={"PyPI", "Debian:13"}),
                  [("PyPI", "requests", "CVE-2018-18074")])
    v = one(vs, vuln_id="CVE-2018-18074")
    assert (v.outcome, v.reason, v.family) == (Outcome.UNDETERMINED, "not-reassessed", "application")


def test_host_apps_through_the_api_have_parity_with_rescan_which_names_the_package_not_the_path(env):
    s = make_sessionmaker(env)()
    s.merge(Advisory(id=REQUESTS["id"], ecosystem="PyPI", package="requests", modified=REQUESTS["modified"], record=REQUESTS))
    s.commit()
    c = user(env)
    aid, _ = enrolled(c, doc(*APPS, sources=SCANNED))
    found = {(f["package"], f["vuln_id"], f["installed_version"]) for f in c.get("/api/findings", params={"asset_id": aid}).json()}
    assert ("requests", "CVE-2018-18074", "2.19.1") in found
    r = c.get(f"/api/assets/{aid}/scan-report").json()
    assert any(g["instance"] == f"requests 2.19.1 at {REQ_OLD}" for g in r["vulnerable"])
    asset = s.get(Asset, aid)
    held = s.scalars(select(InstalledPackage).where(InstalledPackage.asset_id == aid)).all()
    verdicts, _ = engine.scan_inventory(s, Inventory.from_asset(asset, held), engine.prior_findings(s, asset))
    open_ = [(f.ecosystem, f.package, f.vuln_id) for f in s.scalars(select(Finding).where(Finding.asset_id == aid, Finding.status == "open"))]
    p = parity.compare(verdicts, open_)
    assert p["ok"] and ("PyPI", "requests", "CVE-2018-18074") in open_ and not p["outside_this_slice"].get("PyPI"), p


# ---- found on the real run (sandbox/appengine.py)

def test_a_git_range_beside_the_version_range_doesnt_make_a_fixed_install_undetermined():
    """PyPA's records carry a GIT range of commits next to the ECOSYSTEM one; comparing a version with a commit hash made
    requests 2.32.3 and urllib3 2.8.0 `undetermined` on the real run. match_package reads only version ranges, and so does this."""
    rec = ghsa("PYSEC-2018-28", "PyPI", "requests", "2.20.0", "CVE-2018-18074")
    rec["affected"][0]["ranges"].append({"type": "GIT", "repo": "https://github.com/psf/requests", "events": [{"introduced": "0"}, {"fixed": "c45d7c49ea75133e52ab22a8e9e13173938e36ff"}]})
    v = one(evaluate(sbom_inv(pypi("requests", "2.32.3")), Content.make({("PyPI", "requests"): [rec]}, feeds={"PyPI"})), vuln_id="CVE-2018-18074")
    assert v.outcome == Outcome.NOT_VULNERABLE


def test_a_bind_mount_of_a_filesystem_already_walked_isnt_walked_again(monkeypatch):
    """WSLg mounts the distro's root again at /mnt/wslg/distro: every jar was found twice. The same filesystem under a second
    mount point is skipped; a different filesystem mounted is walked."""
    dev = {"/": 1, "/mnt/wslg": 2, "/mnt/wslg/distro": 1, "/data": 3}
    monkeypatch.setattr(agent.os.path, "ismount", lambda d: d in dev)
    monkeypatch.setattr(agent.os, "stat", lambda d: type("st", (), {"st_dev": dev[d]}))
    devs = set()
    assert [agent._seen_filesystem(d, devs, d == "/") for d in ("/", "/srv", "/mnt/wslg", "/mnt/wslg/distro", "/data")] == [False, False, False, True, False]


def test_phase_4_a_component_dropped_from_a_new_sbom_closes(maven_env):  # noqa: F811
    c = user(maven_env)
    a = app_asset(c)
    assert put(c, a["id"], bom(comp(LOG4J))).status_code == 200
    assert any(f["vuln_id"] == "CVE-2021-44228" for f in c.get("/api/findings", params={"asset_id": a["id"]}).json())
    assert put(c, a["id"], bom(comp("pkg:maven/com.google.guava/guava@33.0.0-jre"))).status_code == 200  # log4j-core gone
    assert not any(f["vuln_id"] == "CVE-2021-44228" for f in c.get("/api/findings", params={"asset_id": a["id"]}).json())
