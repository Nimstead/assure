"""The detection engine on a real Linux install, in a DISPOSABLE WSL distro (sbx.py's helpers; docs/engine/spec-detection.md section 7).

The agent's real `collect` runs as root in a fresh distro, and the real inventory goes to the server with that release's real OSV
data and endoflife.date's cycles. The report a person would read is printed, then the parity check: every finding `scan.rescan`
opened on that same inventory must be a `vulnerable` verdict, and every difference must have its reason. Then the package database
is moved aside for one collect, a real failed read, to see the report say so where a clean result used to be, and the last good
list kept so rescan closes nothing.

Run from api/:  uv run python ../sandbox/linengine.py --distro Debian|AlmaLinux-9 [--keep]   Writes sandbox/last_run_linengine_<distro>.json.
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
from nimstead.db import Asset, Finding, InstalledPackage, LedgerEntry, make_sessionmaker  # noqa: E402
from nimstead.engine import parity, report  # noqa: E402
from nimstead.engine.collection import Inventory, manager, valid_document  # noqa: E402

OUT = h.ROOT / "sandbox" / f"last_run_linengine_{h.DISTRO.lower()}.json"
PACKAGE_DB = {"dpkg": "/var/lib/dpkg/status", "rpm": "/var/lib/rpm"}  # moved aside for one collect, then back


def collect() -> dict:
    rc, out = h.agent("collect")
    return json.loads(out)


def failed_read(mgr: str) -> dict:
    """`collect` with the package database moved aside: the real command's real failure, put back whatever happens."""
    path = PACKAGE_DB[mgr]
    h.wsl("mv", path, path + ".nimstead-aside")
    try:
        rc, out = h.agent("collect", check=False)
    finally:
        h.wsl("sh", "-c", f"rm -rf {path} && mv {path}.nimstead-aside {path}")  # rpm may have made an empty one meanwhile
    h.note("collect with the package database moved aside", rc=rc, stderr=h.wsl.last_stderr[-300:])
    return json.loads(out)


def main(keep=False) -> int:
    db = f"sqlite:///{(h.TMP / 'nimstead.db').as_posix()}"
    api = TestClient(create_app(db))
    signup(api, {"email": "lin@example.com", "password": "linux-engine-sandbox", "org_name": "LinEngine"})
    try:
        h.create_sandbox()
        inv = collect()
        eco = inv["ecosystem"]
        mgr = manager(eco)
        h.note("collected", ecosystem=eco, packages=len(inv["packages"]), collection=inv["collection"], facts=inv.get("facts"))
        with make_sessionmaker(db)() as s:
            t = time.time()
            h.note("feeds", kev=feeds.sync_kev(s), osv=feeds.sync_osv(s, [eco.split(":")[0]], only={eco}), eol=feeds.sync_eol(s), seconds=round(time.time() - t))
        token = api.post("/api/enroll-tokens", json={"sandbox": True}).json()["token"]
        a = api.post("/api/agent/enroll", json={"token": token, "hostname": h.NAME, "os_name": inv["os_name"], "ecosystem": eco}).json()
        auth = {"Authorization": f"Bearer {a['agent_key']}"}
        r = api.post("/api/agent/inventory", headers=auth, json=inv)
        assert r.status_code == 200, r.text
        aid = a["asset_id"]
        rep = api.get(f"/api/assets/{aid}/scan-report").json()
        print("\n" + "=" * 100 + "\n" + report.render(rep) + "\n" + "=" * 100 + "\n", flush=True)
        h.note("report", headline=rep["headline"], coverage=rep["coverage"], undetermined=rep["undetermined"],
               vulnerable=[{k: g[k] for k in ("instance", "grade", "count", "no_fix", "no_fix_planned", "known_exploited", "observed", "expected", "action")}
                           for g in rep["vulnerable"][:40]],
               vulnerable_installs=len(rep["vulnerable"]), not_applicable=rep["not_applicable"],
               content_version=rep["content_version"], inventory_sha256=rep["inventory_sha256"], verdicts_sha256=rep["verdicts_sha256"])

        def judged():
            with make_sessionmaker(db)() as s:
                asset = s.get(Asset, aid)
                held = s.scalars(select(InstalledPackage).where(InstalledPackage.asset_id == aid)).all()
                verdicts, again = engine.scan_inventory(s, Inventory.from_asset(asset, held), engine.prior_findings(s, asset))
                found = [(x.ecosystem, x.package, x.vuln_id) for x in s.scalars(select(Finding).where(Finding.asset_id == aid, Finding.status.in_(("open", "accepted"))))]
            return verdicts, again, found, len(held)
        verdicts, again, found, held = judged()
        split = [x for x in inv["packages"] if x.get("source_version")]  # DECISIONS 84: bsdutils 1:2.41-5 from util-linux 2.41-5
        h.note("binaries versioned unlike their source", count=len(split), examples=[
            {**{k: x[k] for k in ("name", "version", "source", "source_version")},
             "verdicts": sorted({v.outcome.value for v in verdicts if v.instance == f"{x['source']} {x['source_version']}" and f"{x['name']} {x['version']}" in (v.observed or "")})}
            for x in split[:20]])
        p = parity.compare(verdicts, found)
        h.note("parity with rescan", findings=len(found), agree=p["agree"], outside_this_slice=p["outside_this_slice"], explained=len(p["explained"]),
               explained_by=sorted({x["engine"] for x in p["explained"]}), explained_examples=p["explained"][:20], unexplained=p["unexplained"][:50])
        print(f"Parity: {len(found)} findings, {p['agree']} agree, outside this slice {p['outside_this_slice']}, "
              f"{len(p['explained'])} explained ({', '.join(sorted({x['engine'] for x in p['explained']})) or 'none'}), {len(p['unexplained'])} unexplained", flush=True)
        with make_sessionmaker(db)() as s:  # phase 3: the engine opens findings and rescan's own loop is the shadow; this is the reverse check
            rows = [e.data for e in s.scalars(select(LedgerEntry).where(LedgerEntry.kind == "engine_disagrees", LedgerEntry.subject == aid))]
        h.note("rescan's loop against the engine (engine_disagrees)", entries=len(rows), unexplained=[x for r in rows for x in r['unexplained']][:50])
        print(f"Reverse shadow: {len(rows)} engine_disagrees entries", flush=True)

        broken = failed_read(mgr)
        r = api.post("/api/agent/inventory", headers=auth, json=broken)
        assert r.status_code == 200, r.text
        less = api.get(f"/api/assets/{aid}/scan-report").json()
        print("\n" + report.render(less) + "\n", flush=True)
        _, _, found_after, held_after = judged()
        h.note("after the failed read", package_db=broken["collection"]["sources"]["package_db"], headline=less["headline"],
               undetermined=less["undetermined"][:6], findings_before=len(found), findings_after=len(found_after), packages_kept=held_after)

        sent = inv["collection"]["sources"]
        checks = {"collection document valid, platform and package database read, with the command's exit status":
                  valid_document(inv["collection"]) and sent["os_release"]["state"] == "ok" and sent["package_db"]["state"] == "ok" and sent["package_db"].get("exit") == 0,
                  "packages judged": rep["coverage"]["families"]["distro"]["determined"] > 0 and rep["not_applicable"] > 0,
                  "vulnerable verdicts graded confirmed against the distro's own advisory":
                  any(g["grade"] == "confirmed" and g["source"] == eco.split(":")[0] for g in rep["vulnerable"]),
                  "end of support judged": any(v.vuln_id and v.vuln_id.startswith("EOL:") and v.outcome.value in ("not-vulnerable", "vulnerable") for v in verdicts),
                  "the running WSL kernel isn't called clean": any(v.check == "product:running-kernel" and v.reason == "kernel-unpackaged" for v in verdicts),
                  "every finding rescan opened is a verdict or explained": p["ok"] and bool(found),
                  "a binary versioned unlike its source is judged by the source version, never its own":
                  mgr != "dpkg" or (bool(split) and not any(v.instance == f"{x['source']} {x['version']}" for x in split for v in verdicts)),
                  "same inventory and content, same verdicts": again["verdicts_sha256"] == rep["verdicts_sha256"] and again["content_version"] == rep["content_version"],
                  "a failed package database read is reported as one": broken["collection"]["sources"]["package_db"]["state"] != "ok"
                  or broken["collection"]["sources"]["package_db"]["count"] == 0,
                  "and isn't clean, names the package database, keeps the last list and closes nothing":
                  less["headline"]["status"] == "not-assessed" and any(g["blocked_by"] == "package_db" for g in less["undetermined"])
                  and held_after == held and len(found_after) == len(found)}
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
