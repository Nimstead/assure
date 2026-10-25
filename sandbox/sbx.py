"""End-to-end test in a DISPOSABLE WSL distro: detect -> remediate -> verify -> rollback -> evidence.

Run from api/:  uv run python ../sandbox/sbx.py [--distro Debian|Ubuntu-24.04|AlmaLinux-9|alpine-3.21.0] [--keep]
- Creates a fresh distro named nimstead-sbx-<random> (downloads the Debian WSL image the first time),
  and always unregisters it at the end (unless --keep). It refuses to touch any other distro.
- The API runs in-process on a throwaway SQLite DB with real OSV/KEV/EPSS data. HTTP between agent and
  server is relayed by this script (avoids host-firewall issues); the agent's collector and remediation
  executor run for real, as root, inside the sandbox.
Writes a summary to sandbox/last_run.json.
"""

import io
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "nimstead-sbx-"
NAME = PREFIX + secrets.token_hex(4)
DISTRO = sys.argv[sys.argv.index("--distro") + 1] if "--distro" in sys.argv else "Debian"
TMP = Path(tempfile.mkdtemp(prefix="nimstead-sbx-"))
os.environ.update(NIMSTEAD_SECURE_COOKIES="0", NIMSTEAD_INVENTORY_MIN_SECONDS="0", NIMSTEAD_SIGNING_KEY_FILE=str(TMP / "signing.pem"))

from fastapi.testclient import TestClient  # noqa: E402

from nimstead import feeds  # noqa: E402
from nimstead.app import create_app  # noqa: E402
from nimstead.db import make_sessionmaker  # noqa: E402
from nimstead.verify_pack import verify  # noqa: E402

log: list[dict] = []


def note(step, **kw):
    log.append({"step": step, **kw})
    print(f"[{time.strftime('%H:%M:%S')}] {step}", json.dumps(kw)[:300] if kw else "", flush=True)


def wsl(*args, input=None, check=True, timeout=1800):
    assert NAME.startswith(PREFIX)  # never run commands in a non-sandbox distro
    p = subprocess.run(["wsl", "-d", NAME, "-u", "root", "--", *args], input=input, capture_output=True, timeout=timeout)
    out = p.stdout.decode(errors="replace")
    wsl.last_stderr = p.stderr.decode(errors="replace")
    if check and p.returncode != 0:
        raise RuntimeError(f"sandbox command failed ({p.returncode}): {' '.join(args)}\n{out}\n{p.stderr.decode(errors='replace')}")
    return p.returncode, out


def import_alpine(version):
    """Official Alpine minirootfs (an older point release, so its packages have known fixes), sha256-checked."""
    import hashlib
    import urllib.request
    branch = "v" + ".".join(version.split(".")[:2])
    url = f"https://dl-cdn.alpinelinux.org/alpine/{branch}/releases/x86_64/alpine-minirootfs-{version}-x86_64.tar.gz"
    tarball = TMP / "rootfs.tar.gz"
    urllib.request.urlretrieve(url, tarball)
    want = urllib.request.urlopen(url + ".sha256").read().decode().split()[0]
    if hashlib.sha256(tarball.read_bytes()).hexdigest() != want:
        raise RuntimeError("Alpine rootfs checksum mismatch")
    p = subprocess.run(["wsl", "--import", NAME, str(TMP / "distro"), str(tarball)], capture_output=True, timeout=600)
    if p.returncode != 0:
        raise RuntimeError("wsl --import failed: " + (p.stdout + p.stderr).decode("utf-16-le", errors="replace"))


def create_sandbox():
    note("creating sandbox distro", name=NAME, distro=DISTRO)
    if DISTRO.startswith("alpine-"):
        import_alpine(DISTRO.removeprefix("alpine-"))
    else:
        p = subprocess.run(["wsl", "--install", DISTRO, "--name", NAME, "--location", str(TMP / "distro"), "--no-launch"],
                           capture_output=True, timeout=1800)
        if p.returncode != 0:
            raise RuntimeError("wsl --install failed: " + (p.stdout + p.stderr).decode("utf-16-le", errors="replace"))
    wsl("true")
    if not DISTRO.startswith("alpine-"):  # systemd lets the rollback scenario use a real health-checked service
        wsl("sh", "-c", "grep -q '^systemd=true' /etc/wsl.conf 2>/dev/null || printf '[boot]\nsystemd=true\n' >> /etc/wsl.conf")
        subprocess.run(["wsl", "--terminate", NAME], capture_output=True)
        wsl("true")
    _, osr = wsl("cat", "/etc/os-release")
    note("sandbox ready", os=next((ln for ln in osr.splitlines() if ln.startswith("PRETTY_NAME")), "?"))
    if wsl("sh", "-c", "command -v python3", check=False)[0] != 0:
        wsl("sh", "-c", "if command -v apk; then apk add -q python3; elif command -v dnf; then dnf -q -y install python3; "
            "else apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-minimal; fi")
    wsl("sh", "-c", "mkdir -p /opt/nimstead && cat > /opt/nimstead/agent.py", input=(ROOT / "agent" / "nimstead_agent.py").read_bytes())


def destroy_sandbox():
    assert NAME.startswith(PREFIX)
    names = subprocess.run(["wsl", "-l", "-q"], capture_output=True).stdout.decode("utf-16-le", errors="replace").split()
    if NAME in names:
        subprocess.run(["wsl", "--unregister", NAME], capture_output=True)
        note("sandbox destroyed", name=NAME)
    shutil.rmtree(TMP, ignore_errors=True)


def agent(*args, input=None, check=True):
    return wsl("python3", "/opt/nimstead/agent.py", *args, input=input, check=check)


def main(keep=False):
    db = f"sqlite:///{(TMP / 'nimstead.db').as_posix()}"
    c = TestClient(create_app(db))
    c.post("/api/auth/signup", json={"email": "sbx@example.com", "password": "sandbox-only-password", "org_name": "Sandbox"})
    try:
        create_sandbox()
        inv = json.loads(agent("collect")[1])
        eco = inv["ecosystem"]
        note("collected inventory", ecosystem=eco, packages=len(inv["packages"]))

        with make_sessionmaker(db)() as s:
            t = time.time()
            note("feeds synced", kev=feeds.sync_kev(s), epss=feeds.sync_epss(s), osv=feeds.sync_osv(s, [eco.split(":")[0]], only={eco}),
                 seconds=round(time.time() - t))

        token = c.post("/api/enroll-tokens", json={"sandbox": True}).json()["token"]
        a = c.post("/api/agent/enroll", json={"token": token, "hostname": NAME, "os_name": inv["os_name"], "ecosystem": eco}).json()
        h = {"Authorization": f"Bearer {a['agent_key']}"}

        def report():
            r = c.post("/api/agent/inventory", json=json.loads(agent("collect")[1]), headers=h)
            assert r.status_code == 200, r.text
            return r.json()

        note("first inventory", **report())
        summ = c.get("/api/summary").json()
        note("findings", open_by_priority=summ["open_by_priority"], top_actions=[x["package"] for x in summ["top_actions"]])
        actions = [x for x in summ["top_actions"]]
        assert actions, "no fixable findings in this image; cannot exercise remediation"

        def attempt(pkg, health_units=None, inject=False, include=()):
            if health_units is not None:
                c.patch(f"/api/assets/{a['asset_id']}", json={"health_units": health_units})
            r = c.post("/api/remediation/jobs", json={"asset_id": a["asset_id"], "ecosystem": eco, "package": pkg, "include": list(include)})
            if r.status_code != 201:
                return {"package": pkg, "planned": False, "detail": r.json().get("detail")}
            jid = r.json()["id"]
            assert c.post(f"/api/remediation/jobs/{jid}/approve").status_code == 200
            [job] = c.get("/api/agent/jobs", headers=h).json()
            rc, out = agent("run-job", "--yes", *(["--fail-after-apply"] if inject else []), input=json.dumps(job).encode(), check=False)
            lines = [ln for ln in out.splitlines() if ln.startswith("{")]
            if not lines:
                raise RuntimeError(f"agent run-job printed no result (rc {rc}): {wsl.last_stderr[-2000:]}")
            res = json.loads(lines[-1])
            c.post(f"/api/agent/jobs/{jid}/report", json=res, headers=h)
            report()
            j = next(x for x in c.get("/api/remediation/jobs").json() if x["id"] == jid)
            return {"package": pkg, "outcome": res["outcome"], "status": j["status"], "error": j["error"],
                    "steps": [f"{'ok ' if s['ok'] else 'FAIL'} {s['step']}" for s in res["steps"]], "job": j}

        # 1) a real upgrade that the next inventory must prove fixed
        success = None
        for act in actions:
            r = attempt(act["package"])
            note("remediation attempt", **{k: v for k, v in r.items() if k != "job"})
            if r.get("status") == "aborted" and "would also change: " in (r.get("error") or ""):
                # what the UI's "Plan again including …" does: add the dependencies the dry run named
                deps = [d.strip() for d in r["error"].split("would also change: ", 1)[1].split(";")[0].split(",") if d.strip()]
                r = attempt(act["package"], include=deps)
                note("remediation attempt with dependencies", include=deps, **{k: v for k, v in r.items() if k != "job"})
            if r.get("status") == "succeeded":
                success = r
                break
        assert success, "no remediation succeeded"

        # 2) failure after the change -> automatic rollback, versions restored. With systemd: a real service that
        #    breaks on the new version. Without (Alpine/OpenRC): the agent's local --fail-after-apply test hook.
        inject = wsl("sh", "-c", "[ -d /run/systemd/system ]", check=False)[0] != 0
        rollback = None
        if True:
            remaining = [x for x in c.get("/api/summary").json()["top_actions"] if x["package"] != success["package"]]
            for act in remaining:
                pkgs = [p for p in json.loads(agent("collect")[1])["packages"] if p["source"] == act["package"]]
                if not pkgs:
                    continue
                name, ver = pkgs[0]["name"], pkgs[0]["version"]
                before = {p["name"]: p["version"] for p in pkgs}
                if not inject:
                    # a service that dies once the package version changes: stands in for "upgrade broke the app"
                    rpm_family = eco.split(":")[0] in ("AlmaLinux", "Rocky Linux")
                    query = ("rpm -q --qf '%{EPOCHNUM}:%{VERSION}-%{RELEASE}' " if rpm_family else "dpkg-query -W -f='${Version}' ") + name
                    script = "while [ \"$(" + query + ")\" = \"" + ver + "\" ]; do sleep 1; done; exit 1\n"
                    wsl("sh", "-c", "cat > /opt/nimstead/canary.sh", input=script.encode())
                    unit = ("[Unit]\nStartLimitIntervalSec=0\n[Service]\nExecStart=/bin/sh /opt/nimstead/canary.sh\n"
                            "Restart=on-failure\nRestartSec=1\n")
                    wsl("sh", "-c", "cat > /etc/systemd/system/nimstead-canary.service && systemctl daemon-reload && "
                        "systemctl start nimstead-canary.service", input=unit.encode())
                r = attempt(act["package"], health_units=None if inject else ["nimstead-canary.service"], inject=inject)
                after = {p["name"]: p["version"] for p in json.loads(agent("collect")[1])["packages"] if p["name"] in before}
                note("rollback attempt", **{k: v for k, v in r.items() if k != "job"}, restored=after == before)
                if r.get("outcome") == "rolled_back":
                    rollback = {**r, "restored": after == before}
                    break
            assert rollback and rollback["restored"], "rollback scenario did not roll back cleanly"

        # 3) evidence pack verifies offline against the pinned key
        z = zipfile.ZipFile(io.BytesIO(c.get("/api/evidence/pack", params={"days": 1}).content))
        fp = c.get("/api/evidence/public-key").json()["fingerprint_sha256"]
        problems = verify(z.read("pack.json"), z.read("pack.sig").decode(), z.read("public_key.pem"), fp)
        pack = json.loads(z.read("pack.json"))
        note("evidence pack", problems=problems, resolved=pack["metrics"]["resolved"],
             controls={f"{x['framework']} {x['control']}": x["status"] for x in pack["controls"]})
        assert not problems
        note("RESULT: PASS", rollback_tested=bool(rollback), rollback_trigger="injected" if inject else "service health check")
        return 0
    except Exception as e:
        note("RESULT: FAIL", error=str(e)[:2000])
        return 1
    finally:
        if not keep:
            destroy_sandbox()
        (ROOT / "sandbox" / f"last_run_{DISTRO.lower()}.json").write_text(json.dumps(log, indent=2, default=str))


if __name__ == "__main__":
    sys.exit(main(keep="--keep" in sys.argv))
