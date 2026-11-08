""".NET Framework on a real install, in a DISPOSABLE Windows VM (sandbox/winvm.py; DECISIONS 63).

The agent's report opens findings on the host's own line; Windows Update's own answer must name the same KB; the planned
job installs that KB, a forced failure removes it and mscorlib goes back; the same job without the failure brings mscorlib
to the fix and the findings close.

Run from api/:  uv run python ../sandbox/winnetfx.py VM_NAME [--keep]   Writes sandbox/last_run_winnetfx.json.
"""

import json
import os
import sys
import time

import wine2e as h  # noqa: E402  (reads VM_NAME from argv)
import winfixes as f
import winoracle
from fastapi.testclient import TestClient
from signin import signup

from nimstead import feeds  # noqa: E402
from nimstead.db import make_sessionmaker  # noqa: E402

AGENT = rf'"{f.PY}" -I "{f.AGENT}"'
OUT = f.ROOT / "sandbox" / next((a[6:] for a in sys.argv if a.startswith("--out=")), "last_run_winnetfx.json")  # one file per OS


def mscorlib():
    return h.guest(r"(Get-Item (Join-Path $env:windir 'Microsoft.NET\Framework64\v4.0.30319\mscorlib.dll')).VersionInfo.FileVersion").split()[0]


def run_job(args, name):
    out = rf"C:\nimtest\{name}.json"
    h.as_system(rf"{AGENT} {args} > {out} 2>&1", wait_minutes=150, result=out)
    r = json.loads(h.guest(f"Get-Content {out} -Raw").strip().splitlines()[-1])
    h.note(name, outcome=r["outcome"], error=r.get("error"), steps=[f"{'ok ' if s['ok'] else 'FAIL'} {s['step']}: {s['output'][-160:]}" for s in r["steps"]][-8:])
    return r


def finish(r, name):
    """Through the reboots a job asks for, until it stops pending."""
    for i in range(3):
        if r["outcome"] != "pending_reboot":
            break
        h.reboot_and_wait()
        r = run_job("resume-job", f"{name}-resume{i}")
    return r


def main(keep=False) -> int:
    h.winvm.wait_ready(h.NAME, minutes=90)
    h.guest(r"New-Item -ItemType Directory -Force C:\nimtest, C:\ProgramData\Nimstead | Out-Null")
    # this run drives each job itself with the agent under test: the installed agent's tasks from an earlier run would resume
    # it first at boot, and an older installed agent discarded state it couldn't read (real Server 2019, 2026-11-08)
    h.guest("'Nimstead agent','Nimstead jobs' | ForEach-Object { Disable-ScheduledTask -TaskName $_ -ErrorAction SilentlyContinue | Out-Null }",
            check=False)
    f.runtime()
    f.copy_in(f.ROOT / "agent" / "nimstead_agent.py")
    env = {"NIMSTEAD_DB": f"sqlite:///{(h.TMP / 'nf.db').as_posix()}", "NIMSTEAD_SECURE_COOKIES": "0", "NIMSTEAD_OPEN_SIGNUP": "1",
           "NIMSTEAD_INVENTORY_MIN_SECONDS": "0", "NIMSTEAD_SIGNING_KEY_FILE": str(h.TMP / "sign.pem"),
           "NIMSTEAD_CHECKPOINT_DIR": str(h.TMP / "cp"), "NIMSTEAD_SECRET_KEY_FILE": str(h.TMP / "secret.key")}
    os.environ.update(env)
    from nimstead.app import create_app  # reads the cookie setting on import, so only once it's set
    with make_sessionmaker(env["NIMSTEAD_DB"])() as s:
        h.note("feeds", msrc=feeds.sync_msrc(s, 2))
    api = TestClient(create_app(env["NIMSTEAD_DB"]))
    signup(api, {"email": "win@example.com", "password": "windows-e2e-password", "org_name": "WinNetfx"})
    token = api.post("/api/enroll-tokens", json={"sandbox": True}).json()["token"]  # jobs are approved through the server
    agent = api.post("/api/agent/enroll", json={"token": token, "hostname": "netfx", "ecosystem": "Windows"}).json()
    auth = {"Authorization": f"Bearer {agent['agent_key']}"}

    def report():
        rc, out = h.winvm.run(h.NAME, rf"& {AGENT} collect".replace('"', "'"))
        inv = json.loads(out[out.index("{"):])
        r = api.post("/api/agent/inventory", headers=auth, json=inv)
        assert r.status_code == 200, r.text
        all_f = api.get("/api/findings", params={"limit": 5000}).json()
        return inv, all_f, [x for x in all_f if x["package"].startswith(".NET Framework")]

    checks = {}
    start = mscorlib()
    inv, all_f, nf = report()
    reported = [p for p in inv["packages"] if p["name"] == ".NET Framework"]
    h.note("reported vs the host", reported=reported, mscorlib=start, findings=len(nf), packages=sorted({x["package"] for x in nf}),
           fixed=sorted({x["fixed_version"] for x in nf}))
    checks["version matches mscorlib"] = [p["version"] for p in reported] == [start]
    checks["findings opened"] = bool(nf)
    table = winoracle.run(h.as_system, h.guest, all_f)
    h.note("oracle: Windows Update vs Nimstead", **table)
    checks["Windows Update names no .NET Framework KB we miss"] = not [u for u in table["only_windows_update"] if ".NET Framework" in u["title"]]
    # the hardening audit (DECISIONS 64) on a real host: everything read, and the findings it opens
    cfg = (inv.get("facts") or {}).get("config") or {}
    h.note("hardening audit", config=cfg, findings=sorted(x["package"] for x in all_f if x["ecosystem"] == "WinConfig"))
    checks["hardening audit read its values"] = isinstance(cfg.get("password_policy"), dict) and cfg.get("uac_lua") == 1 and cfg.get("guest_enabled") is False
    assert nf, "nothing to fix"

    package = nf[0]["package"]
    r = api.post("/api/remediation/jobs", json={"asset_id": agent["asset_id"], "ecosystem": "Microsoft", "package": package})
    assert r.status_code == 201, r.text

    def take(jid):
        """Approve the server's job and hand the agent exactly what the server sends it."""
        assert api.post(f"/api/remediation/jobs/{jid}/approve").status_code == 200, jid
        [sent] = [j for j in api.get("/api/agent/jobs", headers=auth).json() if j["id"] == jid]
        job = {**sent, "health_units": ["LanmanServer"], "settle_seconds": 60}
        h.guest("Set-Content -Path C:\\nimtest\\job.json -Encoding ascii -Value '" + json.dumps(job) + "'")
        h.note("planned", job=jid, packages=sent["packages"])
        return sent

    sent = take(r.json()["id"])
    r = finish(run_job(r"run-job --yes --fail-after-apply < C:\nimtest\job.json", "fail"), "fail")
    if r["outcome"] == "aborted" and r.get("offered"):  # a server's combined .NET cumulative (DECISIONS 118): the server plans it
        api.post(f"/api/agent/jobs/{sent['id']}/report", headers=auth, json={k: r[k] for k in ("outcome", "steps", "error", "offered") if k in r})
        follow = [j for j in api.get("/api/remediation/jobs").json() if j["status"] == "planned"]
        h.note("server planned after the abort", jobs=[{"id": j["id"], "packages": j["packages"], "summary": j["summary"]} for j in follow])
        if follow:
            sent = take(follow[0]["id"])
            r = finish(run_job(r"run-job --yes --fail-after-apply < C:\nimtest\job.json", "fail-umbrella"), "fail-umbrella")
    pkgs = sent["packages"]
    alt = (pkgs[0].get("alt") or {}).get("kb")
    checks["Windows Update names no .NET Framework KB we miss"] = not [u for u in table["only_windows_update"]
                                                                       if ".NET Framework" in u["title"] and u["kb"] != alt]
    back = mscorlib()
    h.note("after the forced failure", outcome=r["outcome"], mscorlib=back, before=start)
    checks["forced failure removed the update, mscorlib back"] = r["outcome"] == "rolled_back" and back == start

    time.sleep(120)  # let servicing settle before the same KB goes on again
    r = finish(run_job(r"run-job --yes < C:\nimtest\job.json", "apply"), "apply")
    now = mscorlib()
    _, _, left = report()
    h.note("after the update", outcome=r["outcome"], mscorlib=now, target=pkgs[0]["to"], findings_left=len(left))
    checks["update applied, mscorlib reached the fix"] = r["outcome"] == "applied" and now == pkgs[0]["to"]
    checks["findings closed by inventory"] = not left

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
