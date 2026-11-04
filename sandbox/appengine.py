"""The engine on software outside the package manager, on a real Linux install, in a DISPOSABLE WSL distro (sbx.py's helpers;
docs/engine/spec-detection.md R7.9, DECISIONS 91-93).

A fresh Debian gets a known-vulnerable PyPI package in one virtualenv and its fixed version in another, a known-vulnerable npm package
in a project and one installed globally, a log4j jar, and Debian's own python3-requests (which the package manager owns, so the agent
must leave it to dpkg). The agent's real `collect --scan-apps --scan-jars` runs as root; the inventory goes to the server with real OSV
data; the report a person would read is printed, then parity with `rescan`. Then a broken install for one collect (a partial read),
a collect with the scans off (not assessed, never clean), and an SBOM upload to an application asset (unverified, its unnamed
components counted).

Run from api/:  uv run python ../sandbox/appengine.py [--keep]   Writes sandbox/last_run_appengine.json.
"""

import json
import sys
import time

import sbx as h  # noqa: E402  (reads --distro, makes the sandbox's name and temp folder)
from fastapi.testclient import TestClient
from signin import signup
from sqlalchemy import select

from nimstead import engine, feeds  # noqa: E402
from nimstead.app import create_app  # noqa: E402
from nimstead.db import Asset, Finding, InstalledPackage, make_sessionmaker  # noqa: E402
from nimstead.engine import parity, report  # noqa: E402
from nimstead.engine.collection import Inventory, valid_document  # noqa: E402

OUT = h.ROOT / "sandbox" / "last_run_appengine.json"
OLD_VENV, NEW_VENV, WEB = "/srv/billing/.venv", "/srv/reports/venv", "/srv/web"
LOG4J = "https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar"
SETUP = [  # the host's own tools install things; the agent only ever reads them
    "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-venv python3-requests nodejs npm curl >/dev/null",
    f"python3 -m venv {OLD_VENV} && {OLD_VENV}/bin/pip install -q --disable-pip-version-check requests==2.19.1",  # CVE-2018-18074, fixed in 2.20.0
    f"python3 -m venv {NEW_VENV} && {NEW_VENV}/bin/pip install -q --disable-pip-version-check requests==2.32.3",
    f"mkdir -p {WEB} && cd {WEB} && npm init -y >/dev/null && npm install -s --no-audit --no-fund lodash@4.17.15 minimist@1.2.0",
    "npm install -g -s --no-audit --no-fund semver@7.5.1",  # CVE-2022-25883, fixed in 7.5.2; Debian's npm installs globals under /usr/local
    f"mkdir -p /srv/billing/lib && curl -sSfo /srv/billing/lib/log4j-core-2.14.1.jar {LOG4J}",
]
SBOM = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
    {"type": "library", "name": "django", "purl": "pkg:pypi/django@3.2.0"},
    {"type": "library", "name": "requests", "purl": "pkg:pypi/requests@2.32.3"},
    {"type": "library", "name": "lodash", "purl": "pkg:npm/lodash@4.17.15"},
    {"type": "library", "name": "log4j-core", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
    {"type": "library", "name": "openssl", "purl": "pkg:deb/debian/openssl@3.0.11"},  # an OS package: the agent's, not an SBOM's
    {"type": "file", "name": "vendored-blob.so"}]}  # no package URL


def collect(*flags) -> dict:
    return json.loads(h.agent("collect", *flags)[1])


SCANS = ("--scan-apps", "--app-root", "/srv", "--scan-jars")


def main(keep=False) -> int:
    db = f"sqlite:///{(h.TMP / 'nimstead.db').as_posix()}"
    api = TestClient(create_app(db))
    signup(api, {"email": "apps@example.com", "password": "app-engine-sandbox", "org_name": "AppEngine"})
    try:
        h.create_sandbox()
        for step in SETUP:
            t = time.time()
            h.wsl("sh", "-c", step)
            h.note("set up", command=step[:120], seconds=round(time.time() - t))
        t = time.time()
        inv = collect(*SCANS)
        apps = [p for p in inv["packages"] if p["ecosystem"] in ("PyPI", "npm", "Maven")]
        eco = inv["ecosystem"]
        h.note("collected", seconds=round(time.time() - t), ecosystem=eco, packages=len(inv["packages"]), collection=inv["collection"],
               app_scan=inv["facts"].get("app_scan"), jar_scan={k: v for k, v in inv["facts"].get("jar_scan", {}).items() if k != "locations"},
               apps=[f"{p['ecosystem']} {p['name']} {p['version']} at {p['source']}" for p in apps])
        with make_sessionmaker(db)() as s:
            t = time.time()
            h.note("feeds", kev=feeds.sync_kev(s), osv=feeds.sync_osv(s, [eco.split(":")[0]], only={eco}), apps=feeds.sync_osv(s, ["PyPI", "npm", "Maven"], only={"PyPI", "npm", "Maven"}),  # as feeds.update does
                   eol=feeds.sync_eol(s), seconds=round(time.time() - t))
        token = api.post("/api/enroll-tokens", json={"sandbox": True}).json()["token"]
        a = api.post("/api/agent/enroll", json={"token": token, "hostname": h.NAME, "os_name": inv["os_name"], "ecosystem": eco}).json()
        auth, aid = {"Authorization": f"Bearer {a['agent_key']}"}, a["asset_id"]

        def send(doc):
            r = api.post("/api/agent/inventory", headers=auth, json=doc)
            assert r.status_code == 200, r.text
            return api.get(f"/api/assets/{aid}/scan-report").json()

        def judged(asset_id):
            with make_sessionmaker(db)() as s:
                asset = s.get(Asset, asset_id)
                held = s.scalars(select(InstalledPackage).where(InstalledPackage.asset_id == asset_id)).all()
                verdicts, again = engine.scan_inventory(s, Inventory.from_asset(asset, held, engine.sbom_received(s, asset)), engine.prior_findings(s, asset))
                found = [(x.ecosystem, x.package, x.vuln_id) for x in s.scalars(select(Finding).where(Finding.asset_id == asset_id, Finding.status.in_(("open", "accepted"))))]
            return verdicts, again, found

        rep = send(inv)
        print("\n" + "=" * 100 + "\n" + report.render(rep) + "\n" + "=" * 100 + "\n", flush=True)
        verdicts, again, found = judged(aid)
        app_v = [v for v in verdicts if v.family == "application"]
        h.note("report", headline=rep["headline"], applications=rep["applications"], coverage=rep["coverage"],
               vulnerable_apps=[{k: g[k] for k in ("instance", "grade", "count", "known_exploited", "observed", "expected", "source", "action")}
                                for g in rep["vulnerable"] if g["family"] == "application"],
               undetermined=rep["undetermined"], verdicts_sha256=rep["verdicts_sha256"], content_version=rep["content_version"])
        p = parity.compare(verdicts, found)
        apps_found = [f for f in found if f[0] in ("PyPI", "npm", "Maven")]
        apps_agree = len({(v.ecosystem, v.product, v.vuln_id) for v in app_v if v.outcome.value == "vulnerable"} & set(apps_found))
        h.note("parity with rescan", findings=len(found), app_findings=len(apps_found), app_agree=apps_agree, agree=p["agree"],
               outside_this_slice=p["outside_this_slice"], explained=len(p["explained"]), explained_by=sorted({x["engine"] for x in p["explained"]}),
               unexplained=p["unexplained"][:50])
        print(f"Parity: {len(found)} findings ({len(apps_found)} outside the package manager), {p['agree']} agree ({apps_agree} of them applications), "
              f"outside this slice {p['outside_this_slice']}, {len(p['explained'])} explained, {len(p['unexplained'])} unexplained", flush=True)

        def at(prefix, name, cve=None):
            return [v for v in app_v if v.product == name and (v.instance or "").split(" at ", 1)[-1].startswith(prefix) and (cve is None or v.vuln_id == cve)]

        # a broken install: metadata with no version, for one collect
        broken = "$(echo " + OLD_VENV + "/lib/python3*/site-packages)/broken-1.0.dist-info"
        h.wsl("sh", "-c", f"mkdir -p {broken} && printf 'Metadata-Version: 2.1\\nName: broken\\n' > {broken}/METADATA")
        try:
            part = send(collect(*SCANS))
        finally:
            h.wsl("sh", "-c", f"rm -rf {broken}")
        print("\n" + report.render(part) + "\n", flush=True)
        part_v, _, _ = judged(aid)
        h.note("with an install that can't be read", python_packages=next(x for x in part["coverage"]["sources"] if x["name"] == "python_packages"),
               headline=part["headline"], undetermined=[g for g in part["undetermined"] if g["blocked_by"] == "python_packages"],
               app_grades=sorted({str(v.grade) for v in part_v if v.family == "application" and v.grade}))

        # the scans off: nothing outside the package manager looked for
        off = send(collect())
        print("\n" + report.render(off) + "\n", flush=True)
        off_v, _, off_found = judged(aid)
        h.note("with the scans off", sources=[x for x in off["coverage"]["sources"] if x["state"] == "off"], statements=off["coverage"]["statements"],
               carried=[(v.product, v.vuln_id) for v in off_v if v.reason == "not-reassessed" and v.family == "application"][:20],
               app_findings_still_open=len([f for f in off_found if f[0] in ("PyPI", "npm", "Maven")]))

        # an SBOM, uploaded to an application asset
        app = api.post("/api/assets", json={"name": "billing-service"}).json()
        up = api.post(f"/api/assets/{app['id']}/sbom", content=json.dumps(SBOM))
        assert up.status_code == 200, up.text
        sb = api.get(f"/api/assets/{app['id']}/scan-report").json()
        print("\n" + report.render(sb) + "\n", flush=True)
        sb_v, _, sb_found = judged(app["id"])
        sp = parity.compare(sb_v, sb_found)
        h.note("SBOM", upload=up.json(), headline=sb["headline"], coverage=sb["coverage"], undetermined=sb["undetermined"],
               vulnerable=[{k: g[k] for k in ("instance", "grade", "count", "expected", "source", "raise_confidence")} for g in sb["vulnerable"]],
               parity={"findings": len(sb_found), "agree": sp["agree"], "explained": len(sp["explained"]), "unexplained": sp["unexplained"],
                       "outside_this_slice": sp["outside_this_slice"]})
        print(f"SBOM parity: {len(sb_found)} findings, {sp['agree']} agree, {len(sp['unexplained'])} unexplained", flush=True)

        sent = inv["collection"]["sources"]
        checks = {
            "collection document valid, each scan's line ok with what it read":
                valid_document(inv["collection"]) and all(sent[k]["state"] == "ok" and sent[k]["count"] > 0 for k in ("python_packages", "npm_packages", "java_archives")),
            "Debian's own python3-requests (and the rest dpkg owns) was left to dpkg, not judged twice":
                inv["facts"]["app_scan"]["owned"] > 0 and not any(p["source"].startswith("/usr/lib/python3/") for p in apps),
            "T19: requests in two virtualenvs is two installs, judged apart":
                any(v.outcome.value == "vulnerable" for v in at(OLD_VENV, "requests", "CVE-2018-18074"))
                and any(v.outcome.value == "not-vulnerable" for v in at(NEW_VENV, "requests", "CVE-2018-18074")),
            "npm in a project and globally, and the jar, each vulnerable where they are":
                any(v.outcome.value == "vulnerable" for v in at(WEB, "lodash")) and any(v.outcome.value == "vulnerable" for v in at("/usr/local/lib/node_modules", "semver"))
                and any(v.outcome.value == "vulnerable" for v in at("/srv/billing/lib", "org.apache.logging.log4j:log4j-core", "CVE-2021-44228")),
            "a file is one install, not one per mount it shows through (WSLg's /mnt/wslg/distro is the root again)":
                [p["source"] for p in apps if p["ecosystem"] == "Maven"] == ["/srv/billing/lib/log4j-core-2.14.1.jar"],
            "graded reasonable: the install's own metadata against an advisory database": {str(v.grade) for v in app_v if v.grade} == {"reasonable"},
            "every finding rescan opened is a verdict or explained": p["ok"] and bool(apps_found) and apps_agree == len(apps_found),
            "same inventory and content, same verdicts": again["verdicts_sha256"] == rep["verdicts_sha256"],
            "an install that can't be read makes the scan partial, its readings unverified, and says so":
                part["coverage"]["sources"] and any(x["name"] == "python_packages" and x["state"] == "partial" for x in part["coverage"]["sources"])
                and any(g["blocked_by"] == "python_packages" for g in part["undetermined"])
                and all(str(v.grade) == "unverified" for v in part_v if v.family == "application" and v.grade and v.ecosystem == "PyPI"),
            "scans off read as not assessed, and open findings rescan closed on silence are carried, not called fixed":
                any("Not looked for on this host" in x for x in off["coverage"]["statements"])
                and any(v.reason == "not-reassessed" and v.family == "application" for v in off_v),
            "an SBOM is judged unverified, says it isn't what's running, and counts what it can't name":
                bool(sb["vulnerable"]) and {g["grade"] for g in sb["vulnerable"]} == {"unverified"}
                and any("what was built, not what's running" in x for x in sb["coverage"]["statements"])
                and {g["reason"] for g in sb["undetermined"]} >= {"sbom-unmapped"} and sp["ok"] and sp["agree"] == len(sb_found) > 0,
        }
        ok = all(checks.values())
        h.note("RESULT: " + ("PASS" if ok else "FAIL"), checks=checks)
        return 0 if ok else 1
    except Exception as e:
        h.note("RESULT: FAIL", error=f"{type(e).__name__}: {e}"[:3000])
        return 1
    finally:
        if not keep:
            h.destroy_sandbox()
        OUT.write_text(json.dumps(h.log, indent=2, default=str))


if __name__ == "__main__":
    sys.exit(main(keep="--keep" in sys.argv))
