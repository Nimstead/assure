"""Setting fixes and .NET SDK tracking on a real install, in a DISPOSABLE Windows VM (sandbox/winvm.py; DECISIONS 61, 64).

Each setting the agent can change: a forced failure must restore what was there, then the real job must leave the secure
value. An old .NET SDK must be reported as winget's installer left it, open findings on its own band, and close them when
it's updated.

Run from api/:  uv run python ../sandbox/winhardening.py VM_NAME [--keep]   Writes sandbox/last_run_winhardening.json.
"""

import importlib.util
import json
import os
import sys

import wine2e as h  # noqa: E402  (reads VM_NAME from argv)
import winfixes as f
import winproducts as wp
from fastapi.testclient import TestClient
from signin import signup

from nimstead import feeds, remediate  # noqa: E402
from nimstead.db import make_sessionmaker  # noqa: E402

spec = importlib.util.spec_from_file_location("agent_file", f.ROOT / "agent" / "nimstead_agent.py")
agent_file = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent_file)
OUT = f.ROOT / "sandbox" / next((a[6:] for a in sys.argv if a.startswith("--out=")), "last_run_winhardening.json")  # one file per OS


def value(key, name):
    return h.guest(f"(Get-ItemProperty -LiteralPath 'Registry::{key}' -Name {name} -ErrorAction SilentlyContinue).{name}", check=False).strip()


def main(keep=False) -> int:
    h.winvm.wait_ready(h.NAME, minutes=90)
    h.guest(r"New-Item -ItemType Directory -Force C:\nimtest, C:\ProgramData\Nimstead | Out-Null")
    f.runtime()
    f.copy_in(f.ROOT / "agent" / "nimstead_agent.py")
    checks = {}

    assert set(agent_file.CONFIG_FIXES) == remediate.CONFIG_FIXES
    applied_checks = []
    for check, (key, name, _typ, secure) in agent_file.CONFIG_FIXES.items():
        found = value(key, name)
        job = {"manager": "winconfig", "packages": [{"name": check}], "health_units": ["LanmanServer"]}
        safe = check.replace("-", "_")
        failed = f.job(f"{safe}_fail", job, fail=True)
        back = value(key, name)
        applied = f.job(f"{safe}_apply", job)
        now = value(key, name)
        h.note(f"setting {check}", found=found, after_failure=back, after_apply=now, secure=secure)
        applied_checks.append(check)
        checks[f"{check}: failure restored what was there"] = failed["outcome"] == "rolled_back" and back == found
        checks[f"{check}: job left the secure value"] = applied["outcome"] == "applied" and now == secure

    env = {"NIMSTEAD_DB": f"sqlite:///{(h.TMP / 'hd.db').as_posix()}", "NIMSTEAD_SECURE_COOKIES": "0", "NIMSTEAD_OPEN_SIGNUP": "1",
           "NIMSTEAD_INVENTORY_MIN_SECONDS": "0", "NIMSTEAD_SIGNING_KEY_FILE": str(h.TMP / "sign.pem"),
           "NIMSTEAD_CHECKPOINT_DIR": str(h.TMP / "cp"), "NIMSTEAD_SECRET_KEY_FILE": str(h.TMP / "secret.key")}
    os.environ.update(env)
    from nimstead.app import create_app  # reads the cookie setting on import, so only once it's set
    with make_sessionmaker(env["NIMSTEAD_DB"])() as s:
        h.note("feeds", msrc=feeds.sync_msrc(s, 2))
    api = TestClient(create_app(env["NIMSTEAD_DB"]))
    signup(api, {"email": "win@example.com", "password": "windows-e2e-password", "org_name": "WinHardening"})
    token = api.post("/api/enroll-tokens").json()["token"]
    agent = api.post("/api/agent/enroll", json={"token": token, "hostname": "hardening", "ecosystem": "Windows"}).json()
    auth = {"Authorization": f"Bearer {agent['agent_key']}"}

    # a job that "applied" must also make the finding go away: the value written isn't always the one the audit reads
    inv = wp.collect()
    assert api.post("/api/agent/inventory", headers=auth, json=inv).status_code == 200
    still = sorted({x["package"] for x in api.get("/api/findings", params={"limit": 5000}).json() if x["ecosystem"] == "WinConfig"} & set(applied_checks))
    h.note("settings the audit still reports after their job", still=still)
    checks["every applied setting closed its finding"] = not still

    def sdk_findings():
        inv = wp.collect()
        assert api.post("/api/agent/inventory", headers=auth, json=inv).status_code == 200
        return wp.found(inv, ".NET SDK"), [x for x in api.get("/api/findings", params={"limit": 5000}).json() if " SDK " in x["package"]]

    if "True" not in h.guest("[bool](Get-Command winget -ErrorAction SilentlyContinue)", check=False):
        # Server Core ships no winget (real Server 2019 and 2022 under QEMU, 2026-11-08): the SDK part can't install old SDKs here
        h.note(".NET SDK part skipped", why="no winget on this host (Server Core)")
        return finish(checks, keep)
    sdk = "Microsoft.DotNet.SDK.8"
    versions = wp.versions(sdk)
    reported, opened = [], []
    for v in versions[2:10]:  # the oldest installers leave Microsoft's CDN; a recent old one is still behind the newest fix
        wp.install(sdk, v)
        reported, opened = sdk_findings()
        if opened:
            break
    cli = h.guest(r"& 'C:\Program Files\dotnet\dotnet.exe' --list-sdks", check=False)
    h.note(".NET SDK old", reported=reported, dotnet_cli=cli, findings=len(opened), bands=sorted({x["package"] for x in opened}))
    checks[".NET SDK version matches dotnet --list-sdks"] = bool(reported) and all(v in cli for v in reported)
    checks["old .NET SDK opens findings on its band"] = bool(opened)
    wp.install(sdk, versions[0])
    now, left = sdk_findings()
    h.note(".NET SDK updated", reported=now, findings_left=len(left), newest=versions[0])
    checks[".NET SDK findings closed by the update"] = bool(opened) and not left
    return finish(checks, keep)


def finish(checks: dict, keep: bool) -> int:
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
