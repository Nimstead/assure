"""Performance check at realistic scale: N hosts x ~600 packages, ~100k advisories, ~300 findings per host.

Run from api/:  uv run python ../sandbox/perf.py [--assets 1000] [--containers 10] [--apps 500] [--tickets] [--runtime] [--db postgresql+psycopg://...]
Sizes follow the real-host runs (Debian 13: 164 pkgs / 274 findings, Ubuntu 24.04: 523 / 369). Times every
user-facing endpoint the home page and findings views hit, agent inventory ingest, and the hourly re-match.
--containers N: each host also reports N running containers drawn from IMAGES shared images (tasks/plan-containers.md
C12), timing those reports and the hourly re-match before and after the images exist.
--apps N (with --containers): each image also carries N npm packages read inside it, 5 of them vulnerable
(tasks/spec-workloads.md success criterion 7).
--tickets: after the re-match, time a ticket sync's own work against an in-process GitLab fake (tasks/spec-tickets.md).
--runtime: each inventory also carries what runs (tasks/spec-runtime.md criterion 7): 60 programs loading 25 of the host's
packages each, 3 of them listening on the network, every package native, and on every tenth host one program running a
replaced copy; a second report per host 7 days later exercises the memory.
Writes sandbox/last_run_perf_<sqlite|postgresql>[_containers][_apps][_tickets][_runtime].json.
"""

import json
import os
import random
import statistics
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TMP = Path(tempfile.mkdtemp(prefix="nimstead-perf-"))
os.environ.update(NIMSTEAD_SECURE_COOKIES="0", NIMSTEAD_INVENTORY_MIN_SECONDS="0", NIMSTEAD_SIGNING_KEY_FILE=str(TMP / "k.pem"),
                  NIMSTEAD_CHECKPOINT_DIR=str(TMP / "cp"), NIMSTEAD_SECRET_KEY_FILE=str(TMP / "secret.key"))

from agentdoc import with_document  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from signin import signup  # noqa: E402  first account + its admin's TOTP sign-in
from sqlalchemy import insert  # noqa: E402

from nimstead.app import create_app  # noqa: E402
from nimstead.db import Advisory, make_sessionmaker  # noqa: E402

ASSETS = int(sys.argv[sys.argv.index("--assets") + 1]) if "--assets" in sys.argv else 1000
CONTAINERS = int(sys.argv[sys.argv.index("--containers") + 1]) if "--containers" in sys.argv else 0
TICKETS = "--tickets" in sys.argv
APPS = int(sys.argv[sys.argv.index("--apps") + 1]) if "--apps" in sys.argv else 0
RUNTIME = "--runtime" in sys.argv


def runtime_read(n, names):
    """A host's read of what runs, as agent 0.10.0 sends it: programs loading packages, a few listening, one replaced copy."""
    progs = [{"name": f"svc{k}.service", "unit": True, "users": ["root"], "count": 2,
              "listen": [f"0.0.0.0:{8000 + k}/tcp"] if k < 3 else [f"127.0.0.1:{9000 + k}/tcp"] if k < 6 else [],
              "loads": sorted({f"pkg{p}" for p in rnd.sample(names, 25)}), "replaced": []} for k in range(60)]
    if n % 10 == 0:
        progs[5]["replaced"] = progs[5]["loads"][:1]
    return {"v": 1, "state": "ok", "programs": progs, "native": sorted(f"pkg{p}" for p in names), "other_roots": 0}
APP_UNIVERSE, APP_VULN = 5000, 5  # npm packages an image's build may add, and how many of an image's are vulnerable
IMAGES, IMAGE_PKGS, IMAGE_VULN = 50, 200, 5  # a fleet's distinct images: far fewer than its containers
DB = sys.argv[sys.argv.index("--db") + 1] if "--db" in sys.argv else f"sqlite:///{(TMP / 'perf.db').as_posix()}"
ECO, UNIVERSE, PER_HOST, ADV_PER_PKG, VULN_PER_HOST = "Debian:12", 3000, 600, 33, 9
rnd = random.Random(7)  # noqa: S311 — reproducible test data, not security
result: dict = {"assets": ASSETS, "db": DB.split(":")[0]}


def timed(label, fn, n=1):
    xs = []
    for _ in range(n):
        t = time.perf_counter()
        out = fn()
        xs.append(time.perf_counter() - t)
    result[label] = {"median_s": round(statistics.median(xs), 3), "max_s": round(max(xs), 3)}
    print(f"{label:40s} median {statistics.median(xs):7.3f}s  max {max(xs):7.3f}s", flush=True)
    return out


def advisories():
    rows = []
    for p in range(UNIVERSE):
        for k in range(ADV_PER_PKG):
            cve = f"CVE-2025-{p * ADV_PER_PKG + k:06d}"
            rows.append({"id": f"DEBIAN-{cve}", "ecosystem": ECO, "package": f"pkg{p}", "record": {
                "id": f"DEBIAN-{cve}", "upstream": [cve],
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                "affected": [{"package": {"name": f"pkg{p}", "ecosystem": ECO},
                              "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": f"2.{k}-1"}]}]}]}})
    for p in range(APP_UNIVERSE if APPS else 0):
        for k in range(2):
            ghsa = f"GHSA-perf-{p:05d}-{k}"
            rows.append({"id": ghsa, "ecosystem": "npm", "package": f"npkg{p}", "record": {
                "id": ghsa, "aliases": [f"CVE-2026-{p * 2 + k:06d}"],
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                "affected": [{"package": {"name": f"npkg{p}", "ecosystem": "npm"},
                              "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": f"2.{k}.0"}]}]}]}})
    return rows


def rematch() -> float:
    """The hourly re-match of every asset (feeds.update_all's loop), in seconds."""
    from nimstead.db import Asset
    from nimstead.scan import rescan
    with make_sessionmaker(DB)() as s:
        assets = s.query(Asset).all()
        t = time.perf_counter()
        cache: dict = {}  # as feeds.update_all does
        for a in assets:
            rescan(s, a, inventory_received=False, cache=cache)
        s.commit()
        took = round(time.perf_counter() - t, 1)
        print(f"re-match all {len(assets)} assets (hourly feed update): {took}s", flush=True)
        return took


def older(img):
    """The same image as an agent before 0.9.0 sends it (no application rows or lines): with --apps, every other host, so the
    lookup that joins an OS-only reading to the image's fuller one is measured too (code review)."""
    keep = ("os_release", "package_db")
    return {**{k: v for k, v in img.items() if k != "apps"}, "collection": {**img["collection"], "sources": {k: v for k, v in img["collection"]["sources"].items() if k in keep}}}


def tickets_perf():
    """A sync's own cost at this scale (tasks/spec-tickets.md success criterion 5). GitLab is faked in-process (tests/trackers.py),
    so only Nimstead's time is measured: reading and grouping every open finding (every priority: the worst case), diffing
    them against the tickets it opened, rendering each ticket and recording the sync."""
    sys.path.insert(0, str(ROOT / "api" / "tests"))
    from trackers import FakeGitLab, client_for

    from nimstead import sso, tickets
    from nimstead.db import Org, TicketSettings
    fake = FakeGitLab()
    with make_sessionmaker(DB)() as s:
        org_id = s.query(Org.id).scalar()
        s.add(TicketSettings(org_id=org_id, kind="gitlab", site="https://gitlab.example.com", token=sso.seal("glpat-tok"),
                             default_project="platform/ops", routes=[], min_priority="low", enabled=True))
        s.commit()
        cfg = s.get(TicketSettings, org_id)
        want = timed("tickets: desired (group every open finding)", lambda: tickets.desired(s, org_id, cfg)[0], 3)
        result["tickets_groups"] = len(want)
        timed("tickets: preview", lambda: tickets.preview(s, org_id, cfg), 3)
        tickets.MAX_WRITES = 10**6  # open them all in one go, so the next syncs have nothing to change
        first = timed("tickets: first sync (opens every ticket)", lambda: tickets.sync(s, org_id, http=client_for(fake)))
        assert first["opened"] == len(want) and not first["failed"], first
        fake.calls.clear()
        again = timed("tickets: sync with nothing to change", lambda: tickets.sync(s, org_id, http=client_for(fake)), 3)
        assert not (again["opened"] or again["updated"] or again["failed"]), again
        result["tickets_no_change_tracker_calls"] = {"reads": sum(m == "GET" for m, _ in fake.calls) // 3, "writes": len(fake.writes)}
        print("tickets:", len(want), "groups;", result["tickets_no_change_tracker_calls"], flush=True)


def main():
    app = create_app(DB)
    with make_sessionmaker(DB)() as s:
        rows = advisories()
        t = time.perf_counter()
        for i in range(0, len(rows), 5000):
            s.execute(insert(Advisory), rows[i:i + 5000])
        s.commit()
        result["advisories"] = len(rows)
        print(f"loaded {len(rows)} advisories in {time.perf_counter() - t:.1f}s", flush=True)
    c = TestClient(app)
    signup(c, {"email": "perf@example.com", "password": "perf-test-password", "org_name": "Perf"})
    token = c.post("/api/enroll-tokens").json()["token"]

    ingest, headers = [], []
    for n in range(ASSETS):
        a = c.post("/api/agent/enroll", json={"token": token, "hostname": f"host{n}", "ecosystem": ECO}).json()
        headers.append({"Authorization": f"Bearer {a['agent_key']}"})
        names = rnd.sample(range(UNIVERSE), PER_HOST)
        vuln = set(names[:VULN_PER_HOST])
        pkgs = [{"ecosystem": ECO, "name": f"pkg{p}", "version": "1.0-1" if p in vuln else "9.0-1", "source": f"pkg{p}"} for p in names]
        body = with_document({"ecosystem": ECO, "packages": pkgs})
        if RUNTIME:
            body["runtime"] = runtime_read(n, names)
        t = time.perf_counter()
        r = c.post("/api/agent/inventory", json=body, headers=headers[-1])
        ingest.append(time.perf_counter() - t)
        assert r.status_code == 200, r.text
        if n % 100 == 99:
            print(f"  {n + 1} hosts, last ingest {ingest[-1]:.3f}s", flush=True)
    ingest.sort()
    result["inventory_ingest"] = {"median_s": round(statistics.median(ingest), 3), "p95_s": round(ingest[int(len(ingest) * .95)], 3),
                                  "max_s": round(ingest[-1], 3)}
    print("inventory ingest", result["inventory_ingest"], flush=True)
    if CONTAINERS:
        result["containers_per_host"], result["images"], result["apps_per_image"] = CONTAINERS, IMAGES, APPS
        result["rematch_before_containers_s"] = rematch()
        images = []
        for i in range(IMAGES):
            names = rnd.sample(range(UNIVERSE), IMAGE_PKGS)
            vuln = set(names[:IMAGE_VULN])
            images.append({"image_id": f"sha256:{i:064x}", "ref": f"registry.example/app{i}:1", "os_name": "Debian GNU/Linux 12 (bookworm)", "ecosystem": ECO,
                           "facts": {"os_id": "debian", "os_version_id": "12"},
                           "collection": {"v": 1, "sources": {"os_release": {"state": "ok", "count": 1}, "package_db": {"state": "ok", "count": IMAGE_PKGS}}},
                           "packages": [{"name": f"pkg{p}", "version": "1.0-1" if p in vuln else "9.0-1", "source": f"pkg{p}"} for p in names]})
            if APPS:  # what the image's build added: npm packages with their locations, and a line for each ecosystem read
                picked = rnd.sample(range(APP_UNIVERSE), APPS)
                bad = set(picked[:APP_VULN])
                images[-1]["apps"] = [{"ecosystem": "npm", "name": f"npkg{p}", "version": "1.0.0" if p in bad else "3.0.0",
                                       "source": f"/usr/src/app/node_modules/npkg{p}"} for p in picked]
                images[-1]["collection"]["sources"] |= {"python_packages": {"state": "ok", "count": 0}, "npm_packages": {"state": "ok", "count": APPS},
                                                        "java_archives": {"state": "ok", "count": 0}, "go_modules": {"state": "ok", "count": 0}}
        reports = []
        for n, h in enumerate(headers):
            picked = rnd.sample(range(IMAGES), CONTAINERS)
            body = {"v": 1, "complete": True, "runtimes": {}, "error": None,
                    "images": [{**(older(images[i]) if APPS and n % 2 else images[i]), "containers": [{"id": f"{n:032x}{i:032x}", "name": f"c{i}", "runtime": "docker"}]}
                               for i in picked]}
            t = time.perf_counter()
            r = c.post("/api/agent/containers", json=body, headers=h)
            reports.append(time.perf_counter() - t)
            assert r.status_code == 200, r.text
            if n % 100 == 99:
                print(f"  {n + 1} container reports, last {reports[-1]:.3f}s", flush=True)
        first = reports[0]  # the first host's report creates (and judges) its images; most later ones only record where they run
        reports.sort()
        result["containers_report"] = {"median_s": round(statistics.median(reports), 3), "p95_s": round(reports[int(len(reports) * .95)], 3),
                                       "max_s": round(reports[-1], 3), "first_s": round(first, 3)}
        print("containers report", result["containers_report"], flush=True)

    summ = timed("GET /api/summary (home page)", lambda: c.get("/api/summary").json(), 3)
    result["open_findings"] = sum(summ["open_by_priority"].values())
    print("open findings:", result["open_findings"], flush=True)
    timed("GET /api/findings (default 500)", lambda: c.get("/api/findings").json(), 3)
    timed("GET /api/findings?limit=5000", lambda: c.get("/api/findings", params={"limit": 5000}).json(), 3)
    timed("GET /api/findings?q=pkg42", lambda: c.get("/api/findings", params={"q": "pkg42"}).json(), 3)
    timed("GET /api/assets", lambda: c.get("/api/assets").json(), 3)
    timed("GET /api/progress?days=365 (ledger replay)", lambda: c.get("/api/progress", params={"days": 365}).json(), 3)
    timed("GET /api/evidence/pack", lambda: c.get("/api/evidence/pack").content, 1)

    result["rematch_all_s"] = rematch()
    if TICKETS:
        tickets_perf()
    # Windows fleet view (W22): the same number of Windows hosts, three months of updates, most hosts behind. Last, so the numbers above stay comparable.
    product = "Windows Server 2025"
    with make_sessionmaker(DB)() as s:
        for m, build in enumerate(("10.0.26100.1000", "10.0.26100.2000", "10.0.26100.3000")):
            s.execute(insert(Advisory), [{"id": f"MSRC-CVE-2026-{m}{k:04d}", "ecosystem": "Windows", "package": product, "record": {
                "id": f"MSRC-CVE-2026-{m}{k:04d}", "aliases": [f"CVE-2026-{m}{k:04d}"], "modified": "2026-10-14", "summary": "s",
                "database_specific": {"kb": f"512700{m}", "hotpatch": False, "released": f"2026-{8 + m:02d}-14"},
                "affected": [{"package": {"ecosystem": "Windows", "name": product},
                              "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": build}]}]}]}} for k in range(100)])
        s.commit()
    for n in range(ASSETS):
        a = c.post("/api/agent/enroll", json={"token": token, "hostname": f"win{n}", "ecosystem": "Windows"}).json()
        build = "10.0.26100.3000" if n % 5 == 0 else "10.0.26100.500"
        r = c.post("/api/agent/inventory", json=with_document({"ecosystem": "Windows", "packages": [{"ecosystem": "Windows", "name": product, "version": build, "source": None}]}),
                   headers={"Authorization": f"Bearer {a['agent_key']}"})
        assert r.status_code == 200, r.text
    rows = timed("GET /api/windows-updates", lambda: c.get("/api/windows-updates").json(), 3)
    assert rows[0]["hosts"] == ASSETS and rows[0]["fixed"] == (ASSETS + 4) // 5
    hosts = timed("GET /api/windows-updates/{kb} (drill down)", lambda: c.get(f"/api/windows-updates/{rows[0]['kb']}", params={"product": product}), 3)
    result["windows_updates_drilldown_kib"] = round(len(hosts.content) / 1024)
    timed("GET /api/summary (with Windows hosts)", lambda: c.get("/api/summary").json(), 3)
    (ROOT / "sandbox" / f"last_run_perf_{result['db'].split('+')[0]}{'_containers' if CONTAINERS else ''}{'_apps' if APPS else ''}{'_tickets' if TICKETS else ''}{'_runtime' if RUNTIME else ''}.json").write_text(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
