"""Build a realistic local demo from REAL hosts: a disposable WSL distro per host (Ubuntu 24.04 x2, Debian 13, AlmaLinux 9,
Alpine 3.21) running the real agent, REAL feeds (OSV, CISA KEV, EPSS), one application with an SBOM, and real remediation:
a fix verified by inventory, a fix that breaks a service and is rolled back, whatever the dry run says on Alpine, and a
plan waiting for approval. Every distro is destroyed at the end. Writes api/demo/nimstead-demo.db, the sign-in to
api/demo/login.txt and a run log to sandbox/last_run_demo.json.

Run from api/:  uv run python ../sandbox/demo.py
Then serve it:  NIMSTEAD_DB=sqlite:///demo/nimstead-demo.db NIMSTEAD_SECURE_COOKIES=0 NIMSTEAD_SIGNING_KEY_FILE=demo/signing.pem \
                uv run uvicorn --factory nimstead.app:create_app --port 8000
"""

import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from signin import signup  # noqa: E402  first account + its admin's TOTP sign-in

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "api" / "demo"
DB = OUT / "nimstead-demo.db"
AGENT = ROOT / "agent" / "nimstead_agent.py"
TMP = Path(tempfile.mkdtemp(prefix="nimstead-sbx-demo-"))
PREFIX = "nimstead-sbx-demo-"
# hostname, distro, criticality, internet-facing, ring, what to show
HOSTS = [
    ("web-prod-01", "Ubuntu-24.04", "high", True, 0, "fix"),
    ("web-prod-02", "Ubuntu-24.04", "high", True, 1, None),
    ("db-prod-01", "Debian", "critical", False, 1, "rollback"),
    ("build-runner-01", "AlmaLinux-9", "medium", False, 1, "pending"),
    ("edge-proxy-01", "alpine-3.21.0", "high", True, 1, "fix"),
]
log: list[dict] = []


def say(step, **kw):
    log.append({"step": step, **kw})
    print(f"[{time.strftime('%H:%M:%S')}] {step}", json.dumps(kw, default=str)[:400] if kw else "", flush=True)


def sh(name, script, data=None, check=True):
    assert name.startswith(PREFIX)  # never touch any other distro
    p = subprocess.run(["wsl", "-d", name, "-u", "root", "--", "sh", "-c", script], input=data, capture_output=True, timeout=1800)
    if check and p.returncode != 0:
        raise RuntimeError(f"{name}: {script}\n{p.stderr.decode(errors='replace')[-800:]}")
    return p.returncode, p.stdout.decode(errors="replace")


def create(distro: str) -> str:
    name = PREFIX + secrets.token_hex(3)
    if distro.startswith("alpine-"):  # official minirootfs, an older point release so its packages have known fixes
        v = distro.removeprefix("alpine-")
        url = f"https://dl-cdn.alpinelinux.org/alpine/v{'.'.join(v.split('.')[:2])}/releases/x86_64/alpine-minirootfs-{v}-x86_64.tar.gz"
        tarball = TMP / f"{name}.tar.gz"
        urllib.request.urlretrieve(url, tarball)
        if hashlib.sha256(tarball.read_bytes()).hexdigest() != urllib.request.urlopen(url + ".sha256").read().decode().split()[0]:
            raise RuntimeError("Alpine rootfs checksum mismatch")
        cmd = ["wsl", "--import", name, str(TMP / name), str(tarball)]
    else:
        cmd = ["wsl", "--install", distro, "--name", name, "--location", str(TMP / name), "--no-launch"]
    for _ in range(3):  # the Microsoft store download sometimes answers 504
        p = subprocess.run(cmd, capture_output=True, timeout=1800)
        if p.returncode == 0:
            break
        time.sleep(10)
    else:
        raise RuntimeError((p.stdout + p.stderr).decode("utf-16-le", errors="replace"))
    if not distro.startswith("alpine-"):  # systemd: health checks against real services
        sh(name, "grep -q '^systemd=true' /etc/wsl.conf 2>/dev/null || printf '[boot]\\nsystemd=true\\n' >> /etc/wsl.conf")
        subprocess.run(["wsl", "--terminate", name], capture_output=True)
    sh(name, "command -v python3 >/dev/null || if command -v apk >/dev/null; then apk add -q python3; elif command -v dnf >/dev/null; "
             "then dnf -q -y install python3; else apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-minimal; fi")
    sh(name, "mkdir -p /opt/nimstead && cat > /opt/nimstead/agent.py", AGENT.read_bytes())
    return name


def collect(name):
    return json.loads(sh(name, "python3 /opt/nimstead/agent.py collect")[1])


def main():
    OUT.mkdir(exist_ok=True)
    for f in (DB, OUT / "signing.pem", OUT / "secret.key"):
        f.unlink(missing_ok=True)
    os.environ.update(NIMSTEAD_SECURE_COOKIES="0", NIMSTEAD_INVENTORY_MIN_SECONDS="0",
                      NIMSTEAD_SIGNING_KEY_FILE=str(OUT / "signing.pem"), NIMSTEAD_SECRET_KEY_FILE=str(OUT / "secret.key"),
                      NIMSTEAD_CHECKPOINT_DIR=str(OUT / "checkpoints"))
    from fastapi.testclient import TestClient

    from nimstead import feeds
    from nimstead.app import create_app
    from nimstead.db import Advisory, make_sessionmaker
    from nimstead.match import normalize_ecosystem

    names = {}
    try:
        for host, distro, *_ in HOSTS:
            names[host] = create(distro)
            say("host ready", host=host, distro=distro, os=collect(names[host])["os_name"])

        url = f"sqlite:///{DB.as_posix()}"
        app = create_app(url)
        in_use = {normalize_ecosystem(collect(n)["ecosystem"]) for n in names.values()}
        with make_sessionmaker(url)() as s:
            t = time.time()
            say("feeds", kev=feeds.sync_kev(s), epss=feeds.sync_epss(s),
                osv=feeds.sync_osv(s, sorted({e.split(":")[0] for e in in_use}), only=in_use), seconds=round(time.time() - t))
            for fx in ("Maven__org.apache.logging.log4j_log4j-core.json", "Maven__com.fasterxml.jackson.core_jackson-databind.json"):
                d = json.loads((ROOT / "api/tests/fixtures/osv" / fx).read_text())
                for rec in d["records"]:
                    s.merge(Advisory(id=rec["id"], ecosystem="Maven", package=d["name"], record=rec))
            s.commit()

        password = "Demo-" + secrets.token_urlsafe(9)
        c = TestClient(app)
        assert signup(c, {"email": "analyst@demo.example", "password": password, "org_name": "Acme"}).status_code == 201
        token = c.post("/api/enroll-tokens", json={"sandbox": True}).json()["token"]
        agents = {}
        for host, _, crit, internet, ring, _ in HOSTS:
            inv = collect(names[host])
            a = c.post("/api/agent/enroll", json={"token": token, "hostname": host, "os_name": inv["os_name"], "ecosystem": inv["ecosystem"]}).json()
            c.patch(f"/api/assets/{a['asset_id']}", json={"criticality": crit, "internet_facing": internet, "ring": ring})
            agents[host] = (a["asset_id"], {"Authorization": f"Bearer {a['agent_key']}"}, inv["ecosystem"])
            say("enrolled and reported", host=host, **c.post("/api/agent/inventory", json=inv, headers=agents[host][1]).json())

        app_asset = c.post("/api/assets", json={"name": "billing-service", "criticality": "high", "internet_facing": True}).json()
        bom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
            {"type": "library", "name": "log4j-core", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
            {"type": "library", "name": "jackson-databind", "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.10.1"}]}
        say("billing-service SBOM", **c.post(f"/api/assets/{app_asset['id']}/sbom", content=json.dumps(bom)).json())

        def packages(host):  # fixable packages on this host, riskiest first
            found = c.get("/api/findings", params={"asset_id": agents[host][0], "fixable": True}).json()
            return list(dict.fromkeys(f["package"] for f in found))

        def run(host, pkg, include=(), approve=True, breaks_service=False):
            """What the UI does, with the agent run for real on the host. Returns the job as the server saw it."""
            aid, h, eco = agents[host]
            name = names[host]
            if breaks_service:  # a service that dies once the package version changes: stands in for "the upgrade broke the app"
                p = next(p for p in collect(name)["packages"] if p["source"] == pkg)
                q = ("rpm -q --qf '%{EPOCHNUM}:%{VERSION}-%{RELEASE}' " if eco.startswith(("AlmaLinux", "Rocky")) else "dpkg-query -W -f='${Version}' ") + p["name"]
                sh(name, "cat > /opt/nimstead/app.sh", f'while [ "$({q})" = "{p["version"]}" ]; do sleep 1; done; exit 1\n'.encode())
                sh(name, "cat > /etc/systemd/system/billing-api.service && systemctl daemon-reload && systemctl start billing-api.service",
                   b"[Unit]\nDescription=Billing API\nStartLimitIntervalSec=0\n[Service]\nExecStart=/bin/sh /opt/nimstead/app.sh\nRestart=on-failure\nRestartSec=1\n")
                c.patch(f"/api/assets/{aid}", json={"health_units": ["billing-api.service"]})
            r = c.post("/api/remediation/jobs", json={"asset_id": aid, "ecosystem": eco, "package": pkg, "include": list(include)})
            if r.status_code != 201:
                return {"planned": False, "detail": r.json().get("detail")}
            jid = r.json()["id"]
            if approve:
                assert c.post(f"/api/remediation/jobs/{jid}/approve").status_code == 200, jid
                [job] = c.get("/api/agent/jobs", headers=h).json()
                _, out = sh(name, "python3 /opt/nimstead/agent.py run-job --yes", json.dumps(job).encode(), check=False)
                res = json.loads([ln for ln in out.splitlines() if ln.startswith("{")][-1])
                c.post(f"/api/agent/jobs/{jid}/report", json=res, headers=h)
                c.post("/api/agent/inventory", json=collect(name), headers=h)  # the next inventory is what proves it
            return next(x for x in c.get("/api/remediation/jobs").json() if x["id"] == jid)

        for host, *_, show in HOSTS:
            if not show:
                continue
            for pkg in packages(host)[:6]:
                job = run(host, pkg, approve=show != "pending", breaks_service=show == "rollback")
                say(f"{show}: {host}", package=pkg, status=job.get("status"), error=job.get("error") or job.get("detail"))
                if show == "fix" and job.get("status") == "aborted" and "would also change: " in (job.get("error") or ""):
                    break  # keep the dry run's refusal on screen: the UI offers "Plan again including …"
                if job.get("status") in ("succeeded", "rolled_back", "planned"):
                    break

        say("open by priority", **c.get("/api/summary").json()["open_by_priority"])
        (OUT / "login.txt").write_text(f"email: analyst@demo.example\npassword: {password}\n")
        say("RESULT: PASS")
        return 0
    except Exception as e:
        say("RESULT: FAIL", error=str(e)[-2000:])
        return 1
    finally:
        for n in names.values():
            subprocess.run(["wsl", "--unregister", n], capture_output=True)
        shutil.rmtree(TMP, ignore_errors=True)
        (ROOT / "sandbox" / "last_run_demo.json").write_text(json.dumps(log, indent=2, default=str) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
