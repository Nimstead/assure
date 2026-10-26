"""Performance check at realistic scale: N hosts x ~600 packages, ~100k advisories, ~300 findings per host.

Run from api/:  uv run python ../sandbox/perf.py [--assets 1000] [--db postgresql+psycopg://...]
Sizes follow the real-host runs (Debian 13: 164 pkgs / 274 findings, Ubuntu 24.04: 523 / 369). Times every
user-facing endpoint the home page and findings views hit, agent inventory ingest, and the hourly re-match.
Writes sandbox/last_run_perf_<sqlite|postgresql>.json.
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
                  NIMSTEAD_CHECKPOINT_DIR=str(TMP / "cp"))

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import insert  # noqa: E402

from nimstead.app import create_app  # noqa: E402
from nimstead.db import Advisory, make_sessionmaker  # noqa: E402

ASSETS = int(sys.argv[sys.argv.index("--assets") + 1]) if "--assets" in sys.argv else 1000
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
    return rows


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
    c.post("/api/auth/signup", json={"email": "perf@example.com", "password": "perf-test-password", "org_name": "Perf"})
    token = c.post("/api/enroll-tokens").json()["token"]

    ingest = []
    for n in range(ASSETS):
        a = c.post("/api/agent/enroll", json={"token": token, "hostname": f"host{n}", "ecosystem": ECO}).json()
        names = rnd.sample(range(UNIVERSE), PER_HOST)
        vuln = set(names[:VULN_PER_HOST])
        pkgs = [{"ecosystem": ECO, "name": f"pkg{p}", "version": "1.0-1" if p in vuln else "9.0-1", "source": f"pkg{p}"} for p in names]
        t = time.perf_counter()
        r = c.post("/api/agent/inventory", json={"ecosystem": ECO, "packages": pkgs}, headers={"Authorization": f"Bearer {a['agent_key']}"})
        ingest.append(time.perf_counter() - t)
        assert r.status_code == 200, r.text
        if n % 100 == 99:
            print(f"  {n + 1} hosts, last ingest {ingest[-1]:.3f}s", flush=True)
    ingest.sort()
    result["inventory_ingest"] = {"median_s": round(statistics.median(ingest), 3), "p95_s": round(ingest[int(len(ingest) * .95)], 3),
                                  "max_s": round(ingest[-1], 3)}
    print("inventory ingest", result["inventory_ingest"], flush=True)

    summ = timed("GET /api/summary (home page)", lambda: c.get("/api/summary").json(), 3)
    result["open_findings"] = sum(summ["open_by_priority"].values())
    print("open findings:", result["open_findings"], flush=True)
    timed("GET /api/findings (default 500)", lambda: c.get("/api/findings").json(), 3)
    timed("GET /api/findings?limit=5000", lambda: c.get("/api/findings", params={"limit": 5000}).json(), 3)
    timed("GET /api/findings?q=pkg42", lambda: c.get("/api/findings", params={"q": "pkg42"}).json(), 3)
    timed("GET /api/assets", lambda: c.get("/api/assets").json(), 3)
    timed("GET /api/evidence/pack", lambda: c.get("/api/evidence/pack").content, 1)

    from nimstead.db import Asset
    from nimstead.scan import rescan
    with make_sessionmaker(DB)() as s:
        assets = s.query(Asset).all()
        t = time.perf_counter()
        cache: dict = {}  # as feeds.update_all does
        for a in assets:
            rescan(s, a, inventory_received=False, cache=cache)
        s.commit()
        result["rematch_all_s"] = round(time.perf_counter() - t, 1)
        print(f"re-match all {len(assets)} hosts (hourly feed update): {result['rematch_all_s']}s", flush=True)
    (ROOT / "sandbox" / f"last_run_perf_{result['db'].split('+')[0]}.json").write_text(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
