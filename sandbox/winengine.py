"""The detection engine's first slice on a real install, in a DISPOSABLE Windows VM (sandbox/winvm.py; docs/engine/design-e2.md).

The agent's real `collect` runs on the VM with an old 7-Zip beside what Windows ships, and the real inventory goes to the server
with real MSRC and NVD data. The report a person would read is printed, then the parity check: every finding `scan.rescan` opened
on that same inventory must be a `vulnerable` verdict, and every difference must have its reason. Then a read is refused on purpose,
as a standard user, to see the report say so where a clean result used to be.

Run from api/:  uv run python ../sandbox/winengine.py VM_NAME [--keep]   Writes sandbox/last_run_winengine.json.
"""

import json
import os
import secrets
import shutil
import sys

import wine2e as h  # noqa: E402  (reads VM_NAME from argv)
import winfixes as f
import winproducts as wp
from fastapi.testclient import TestClient
from signin import signup
from sqlalchemy import select

from nimstead import engine, feeds  # noqa: E402
from nimstead.db import Asset, Finding, InstalledPackage, make_sessionmaker  # noqa: E402
from nimstead.engine import parity, report  # noqa: E402
from nimstead.engine.collection import Inventory, valid_document  # noqa: E402

OUT = f.ROOT / "sandbox" / "last_run_winengine.json"
SOURCES = ("windows_build", "uninstall", "user_hives", "microsoft_products", "host_facts", "drivers")


def as_standard_user() -> dict:
    """`collect` as a user who can't load other users' hives: what it couldn't read must be said, on a real refusal."""
    pw = "Nim-eng-" + secrets.token_hex(6)
    h.guest(f"New-LocalUser nimeng -Password (ConvertTo-SecureString '{pw}' -AsPlainText -Force) | Out-Null; Add-LocalGroupMember Users nimeng")
    rc, out = h.winvm.run(h.NAME, rf'& "{f.PY}" -I "{f.AGENT}" collect', user={"user": "nimeng", "password": pw}, timeout=1800)
    h.note("collect as a standard user", rc=rc, tail=out[-200:])
    return json.JSONDecoder().raw_decode(out[out.index("{"):])[0]  # stderr follows the document in guest control's output


def main(keep=False) -> int:
    h.winvm.wait_ready(h.NAME, minutes=90)
    h.guest(r"New-Item -ItemType Directory -Force C:\nimtest | Out-Null")
    f.runtime()
    f.copy_in(f.ROOT / "agent" / "nimstead_agent.py")
    # winget lists newest first. Below 24.09 is below the fix for CVE-2025-0411 (in NVD's 2025 feed, loaded below)
    old = next(v for v in wp.versions("7zip.7zip") if [int(x) for x in v.split(".")[:2]] < [24, 9])
    h.note("old 7-Zip", version=old, output=wp.install("7zip.7zip", old)[-200:])
    inv = wp.collect()
    print(json.dumps(inv["collection"], indent=2))

    env = {"NIMSTEAD_DB": f"sqlite:///{(h.TMP / 'en.db').as_posix()}", "NIMSTEAD_SECURE_COOKIES": "0", "NIMSTEAD_OPEN_SIGNUP": "1",
           "NIMSTEAD_INVENTORY_MIN_SECONDS": "0", "NIMSTEAD_SIGNING_KEY_FILE": str(h.TMP / "sign.pem"),
           "NIMSTEAD_CHECKPOINT_DIR": str(h.TMP / "cp"), "NIMSTEAD_SECRET_KEY_FILE": str(h.TMP / "secret.key")}
    os.environ.update(env)
    from nimstead.app import create_app  # reads the cookie setting on import, so only once it's set
    db = make_sessionmaker(env["NIMSTEAD_DB"])
    with db() as s:
        h.note("feeds", msrc=feeds.sync_msrc(s, 2), nvd=feeds.sync_nvd(s, ["2025", "modified"]), kev=feeds.sync_kev(s))
    api = TestClient(create_app(env["NIMSTEAD_DB"]))
    signup(api, {"email": "win@example.com", "password": "windows-e2e-password", "org_name": "WinEngine"})
    token = api.post("/api/enroll-tokens").json()["token"]
    agent = api.post("/api/agent/enroll", json={"token": token, "hostname": h.NAME, "ecosystem": "Windows"}).json()
    auth = {"Authorization": f"Bearer {agent['agent_key']}"}
    r = api.post("/api/agent/inventory", headers=auth, json=inv)
    assert r.status_code == 200, r.text
    aid = api.get("/api/assets").json()[0]["id"]
    rep = api.get(f"/api/assets/{aid}/scan-report").json()
    print("\n" + "=" * 100 + "\n" + report.render(rep) + "\n" + "=" * 100 + "\n", flush=True)
    h.note("report", headline=rep["headline"], coverage=rep["coverage"], undetermined=rep["undetermined"],
           vulnerable=[{k: g[k] for k in ("instance", "grade", "count", "known_exploited", "observed", "expected", "action")} for g in rep["vulnerable"]],
           content_version=rep["content_version"], inventory_sha256=rep["inventory_sha256"], verdicts_sha256=rep["verdicts_sha256"])

    with db() as s:
        asset = s.get(Asset, aid)
        stored = Inventory.from_asset(asset, s.scalars(select(InstalledPackage).where(InstalledPackage.asset_id == aid)).all())
        verdicts, again = engine.scan_inventory(s, stored, engine.prior_findings(s, asset))
        found = [(x.ecosystem, x.package, x.vuln_id) for x in s.scalars(select(Finding).where(Finding.asset_id == aid, Finding.status.in_(("open", "accepted"))))]
    p = parity.compare(verdicts, found)
    shutil.copy(h.TMP / "en.db", h.TMP.parent / f"{h.TMP.name}-full.db")  # for sandbox/engine_replay.py: the same feeds and inventory judged by another build
    h.note("database kept", path=str(h.TMP.parent / f"{h.TMP.name}-full.db"))
    h.note("parity with rescan", findings=len(found), agree=p["agree"], outside_this_slice=p["outside_this_slice"], explained=p["explained"][:50], unexplained=p["unexplained"][:50])
    print(f"Parity: {len(found)} findings, {p['agree']} agree, outside this slice {p['outside_this_slice']}, {len(p['explained'])} explained, {len(p['unexplained'])} unexplained", flush=True)

    limited = as_standard_user()
    sources = limited["collection"]["sources"]
    r = api.post("/api/agent/inventory", headers=auth, json=limited)
    assert r.status_code == 200, r.text
    less = api.get(f"/api/assets/{aid}/scan-report").json()
    print("\n" + report.render(less) + "\n", flush=True)
    h.note("as a standard user", sources=sources, headline=less["headline"], undetermined=less["undetermined"])

    sent = inv["collection"]["sources"]
    checks = {"collection document valid and complete": valid_document(inv["collection"]) and set(SOURCES) <= set(sent),
              "Windows build, Uninstall entries and host facts read": all(sent[k]["state"] == "ok" for k in ("windows_build", "uninstall", "host_facts")),
              "OS judged": rep["coverage"]["families"]["os"]["determined"] > 0,
              "the old 7-Zip is vulnerable, with its grade": any("7-Zip" in (g["instance"] or "") and g["grade"] == "reasonable" for g in rep["vulnerable"]),
              "every finding rescan opened is a verdict or explained": p["ok"] and bool(found),
              "same inventory and content, same verdicts": again["verdicts_sha256"] == rep["verdicts_sha256"] and again["content_version"] == rep["content_version"],
              "a standard user's collect isn't reported clean": less["headline"]["status"] != "no-known-vulnerabilities"
              and any(sources[k]["state"] != "ok" for k in SOURCES)}
    ok = all(checks.values())
    h.note("RESULT: " + ("PASS" if ok else "FAIL"), checks=checks)
    if not keep:
        h.winvm.destroy(h.NAME)
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        rc = main(keep="--keep" in sys.argv)
    except Exception as e:
        h.note("RESULT: FAIL", error=f"{type(e).__name__}: {e}"[:3000])
        rc = 1
    OUT.write_text(json.dumps(h.log, indent=2, default=str))
    sys.exit(rc)
