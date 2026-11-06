"""W1 and Checkpoint C: coverage (assessed vs inventory-only) measured on a real Windows VM with about 50 apps installed.

Every curated app winget can install quickly goes on at its newest version, the agent's own `collect` reads the machine, and the
real server code says how much of it is checked: GET /api/coverage and the host's line in GET /api/assets. The inventory is
kept beside the run file, so the Assets page can be shown from it by posting it as an agent report.

Run from api/:  uv run python ../sandbox/wincoverage.py VM_NAME [--keep]      writes sandbox/last_run_wincoverage.json
"""

import json
import os
import sys
import tempfile
from pathlib import Path

OUT = Path(__file__).with_name("last_run_wincoverage.json")
INV = Path(__file__).with_name("last_run_wincoverage_inventory.json")
# server installers, the IDEs that fill the disk, and those that wouldn't install in earlier runs: left out of a breadth count
SKIP = ("Elastic.", "MongoDB.", "Oracle.MySQL", "MariaDB.", "PostgreSQL.", "Atlassian.", "JetBrains.", "OctopusDeploy.", "PaperCut",
        "Plex.", "Tenable.", "GrafanaLabs.", "Oracle.VirtualBox", "TimKosse.", "VivaldiTechnologies.", "Microsoft.", "Mozilla.Thunderbird")


def measure(inv: dict) -> dict:
    tmp = Path(tempfile.mkdtemp(prefix="nimstead-sbx-coverage-"))
    env = {"NIMSTEAD_DB": f"sqlite:///{(tmp / 'n.db').as_posix()}", "NIMSTEAD_SECURE_COOKIES": "0", "NIMSTEAD_OPEN_SIGNUP": "1",
           "NIMSTEAD_INVENTORY_MIN_SECONDS": "0", "NIMSTEAD_SIGNING_KEY_FILE": str(tmp / "sign.pem"),
           "NIMSTEAD_CHECKPOINT_DIR": str(tmp / "cp"), "NIMSTEAD_SECRET_KEY_FILE": str(tmp / "secret.key")}
    os.environ.update(env)
    from fastapi.testclient import TestClient
    from signin import signup

    from nimstead.app import create_app
    api = TestClient(create_app(env["NIMSTEAD_DB"]))
    signup(api, {"email": "win@example.com", "password": "windows-e2e-password", "org_name": "Coverage"})
    token = api.post("/api/enroll-tokens").json()["token"]
    agent = api.post("/api/agent/enroll", json={"token": token, "hostname": "coverage", "ecosystem": "Windows"}).json()
    r = api.post("/api/agent/inventory", headers={"Authorization": f"Bearer {agent['agent_key']}"}, json=inv)
    assert r.status_code == 200, r.text
    cov = api.get("/api/coverage").json()
    host = api.get("/api/assets").json()[0]
    return {"coverage": {k: cov[k] for k in ("assessed", "inventory_only")}, "host_line": host.get("apps"),
            "not_assessed": [f"{x['name']} · {x['publisher']}" for x in cov["not_assessed"]]}


def main(keep=False) -> int:
    import winapps_e2e as e
    import winfixes
    apps = {w: v for d in (e.APPS, e.NEW, e.NEW5, e.NEW6, e.NEW7, e.NEW8) for w, v in d.items() if not w.startswith(SKIP)}
    e.winvm.wait_ready(e.NAME, minutes=90)
    e.guest(r"New-Item -ItemType Directory -Force C:\nimtest | Out-Null")
    winfixes.runtime()
    py, ag = winfixes.PY, r"C:\nimtest\nimstead_agent.py"
    c = e.winvm.creds(e.NAME)
    e.winvm.vbox("guestcontrol", e.NAME, "copyto", "--username", c["user"], "--password", c["password"],
                 "--target-directory", "C:\\nimtest\\", str(e.ROOT / "agent" / "nimstead_agent.py"))
    result = {"vm": e.NAME, "tried": len(apps), "installed": [], "not_installed": {}, "steps": e.log}
    for wid in apps:  # newest versions: this counts breadth, it doesn't prove matching (the batch runs did)
        rc, out = e.guest(f"winget install --id {wid} --exact --silent --accept-package-agreements --accept-source-agreements "
                          "--disable-interactivity --scope machine", timeout=900)
        if rc != 0 and "No applicable installer" in out:  # per-user only: the agent reads every profile
            rc, out = e.guest(f"winget install --id {wid} --exact --silent --accept-package-agreements --accept-source-agreements "
                              "--disable-interactivity", timeout=900)
        if rc == 0 or "already installed" in out.lower():
            result["installed"].append(wid)
        else:
            result["not_installed"][wid] = out.strip()[-150:]
            e.guest("Get-Process msiexec -ErrorAction SilentlyContinue | Where-Object { $_.StartTime -lt (Get-Date).AddMinutes(-14) } | Stop-Process -Force")  # a hung MSI holds the lock for every later one
        OUT.write_text(json.dumps(result, indent=1, default=str) + "\n", encoding="utf-8")
    inv = e.collect(py, ag)
    assert inv["packages"], "empty inventory"
    INV.write_text(json.dumps(inv, indent=1) + "\n", encoding="utf-8")
    result.update(measure(inv))
    e.note("coverage", **result["coverage"], host_line=result["host_line"], installed=len(result["installed"]))
    result["result"] = "PASS" if len(result["installed"]) >= 50 else "FAIL: fewer than 50 apps installed"
    OUT.write_text(json.dumps(result, indent=1, default=str) + "\n", encoding="utf-8")
    if not keep:
        e.winvm.destroy(e.NAME)
    return 0 if result["result"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main(keep="--keep" in sys.argv))
