"""Agentless scan on a real install, in a DISPOSABLE Windows VM (sandbox/winvm.py; DECISIONS 65).

The VM scans itself by name over real PowerShell remoting, with no agent installed and no stored credential. It must report
what the agent's own `collect` reports on the same host, and findings must open from it. It's one machine: remoting across
a domain or between two hosts isn't proven here (the host fits one VM at a time).

Run from api/:  uv run python ../sandbox/winremote.py VM_NAME [--keep]   Writes sandbox/last_run_winremote.json.
"""

import json
import os
import sys

import wine2e as h  # noqa: E402  (reads VM_NAME from argv)
import winfixes as f
import winproducts as wp
from fastapi.testclient import TestClient
from signin import signup

from nimstead import feeds  # noqa: E402
from nimstead.db import make_sessionmaker  # noqa: E402

OUT = f.ROOT / "sandbox" / "last_run_winremote.json"


def keyset(inv):
    return {(p["ecosystem"], p["name"], p["version"]) for p in inv["packages"]}


def main(keep=False) -> int:
    h.winvm.wait_ready(h.NAME, minutes=90)
    h.guest(r"New-Item -ItemType Directory -Force C:\nimtest | Out-Null")
    f.runtime()
    f.copy_in(f.ROOT / "agent" / "nimstead_agent.py")
    wp.install("7zip.7zip")
    h.note("remoting on", output=h.guest("Enable-PSRemoting -Force -SkipNetworkProfileCheck 2>&1 | Out-String", check=False)[-300:])
    name = h.guest("$env:COMPUTERNAME").strip()
    # a scheduled-task SYSTEM run has no network identity to hand on, so this runs as the VM's Administrator, like an admin at their desk
    rc, out = h.winvm.run(h.NAME, f"& '{f.PY}' -I '{f.AGENT}' scan-remote --print {name}", timeout=1800)
    h.note("scan-remote", rc=rc, tail=out[-300:])
    assert rc == 0, out[-2000:]
    remote = json.loads(out[out.index("{"):].strip().splitlines()[-1])
    local = wp.collect()
    only_local, only_remote = sorted(keyset(local) - keyset(remote)), sorted(keyset(remote) - keyset(local))
    h.note("remote vs local", packages=len(keyset(remote)), only_local=only_local[:40], only_remote=only_remote[:40])
    cfg_l, cfg_r = local["facts"].get("config") or {}, remote["facts"].get("config") or {}
    differ = {k: (cfg_l.get(k), cfg_r.get(k)) for k in set(cfg_l) | set(cfg_r) if cfg_l.get(k) != cfg_r.get(k)}
    h.note("settings that differ", differ=differ)

    env = {"NIMSTEAD_DB": f"sqlite:///{(h.TMP / 'rm.db').as_posix()}", "NIMSTEAD_SECURE_COOKIES": "0", "NIMSTEAD_OPEN_SIGNUP": "1",
           "NIMSTEAD_INVENTORY_MIN_SECONDS": "0", "NIMSTEAD_SIGNING_KEY_FILE": str(h.TMP / "sign.pem"),
           "NIMSTEAD_CHECKPOINT_DIR": str(h.TMP / "cp"), "NIMSTEAD_SECRET_KEY_FILE": str(h.TMP / "secret.key")}
    os.environ.update(env)
    from nimstead.app import create_app  # reads the cookie setting on import, so only once it's set
    with make_sessionmaker(env["NIMSTEAD_DB"])() as s:
        h.note("feeds", msrc=feeds.sync_msrc(s, 2))
    api = TestClient(create_app(env["NIMSTEAD_DB"]))
    signup(api, {"email": "win@example.com", "password": "windows-e2e-password", "org_name": "WinRemote"})
    token = api.post("/api/enroll-tokens").json()["token"]
    agent = api.post("/api/agent/enroll", json={"token": token, "hostname": name, "ecosystem": "Windows"}).json()
    r = api.post("/api/agent/inventory", headers={"Authorization": f"Bearer {agent['agent_key']}"}, json=remote)
    assert r.status_code == 200, r.text
    opened = api.get("/api/findings", params={"limit": 5000}).json()
    h.note("findings from the agentless scan", count=len(opened), ecosystems=sorted({x["ecosystem"] for x in opened}))

    checks = {"nothing the agent sees is missing": not only_local, "nothing extra": not only_remote,
              "OS, .NET Framework and an installed app are there": any(e == "Windows" for e, _, _ in keyset(remote))
              and any(n == ".NET Framework" for _, n, _ in keyset(remote)) and any(e == "WinApp" and "7-Zip" in n for e, n, _ in keyset(remote)),
              "settings were read": cfg_r.get("uac_lua") == 1, "findings opened": bool(opened)}
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
