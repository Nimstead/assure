"""Build a realistic local demo: REAL package inventories (fresh Debian 13, Ubuntu 24.04 and AlmaLinux 9 collected by the
agent in disposable WSL distros, plus this PC's own Windows inventory, read-only), REAL feeds (OSV, CISA KEV, EPSS, NVD,
MSRC), and one application with an SBOM. Writes api/demo/nimstead-demo.db and the sign-in to api/demo/login.txt.

Run from api/:  uv run python ../sandbox/demo.py
Then serve it:  NIMSTEAD_DB=sqlite:///demo/nimstead-demo.db NIMSTEAD_SECURE_COOKIES=0 \
                uv run uvicorn --factory nimstead.app:create_app --port 8000
"""

import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "api" / "demo"
DB = OUT / "nimstead-demo.db"
AGENT = ROOT / "agent" / "nimstead_agent.py"
TMP = Path(tempfile.mkdtemp(prefix="nimstead-sbx-demo-"))
DISTROS = ["Debian", "Ubuntu-24.04", "AlmaLinux-9"]
# hostname, which inventory, criticality, internet-facing, ring
HOSTS = [
    ("web-prod-01", "Ubuntu-24.04", "high", True, 0),
    ("web-prod-02", "Ubuntu-24.04", "high", True, 1),
    ("db-prod-01", "Debian", "critical", False, 1),
    ("build-runner-01", "AlmaLinux-9", "medium", False, 1),
    ("finance-laptop-07", "windows", "medium", False, 1),
]


def say(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def collect_wsl(distro: str) -> dict:
    name = "nimstead-sbx-demo-" + secrets.token_hex(3)
    try:
        r = subprocess.run(["wsl", "--install", distro, "--name", name, "--location", str(TMP / name), "--no-launch"],
                           capture_output=True, timeout=1800)
        if r.returncode != 0:
            raise RuntimeError((r.stdout + r.stderr).decode("utf-16-le", errors="replace"))

        def sh(script, data=None):
            p = subprocess.run(["wsl", "-d", name, "-u", "root", "--", "sh", "-c", script], input=data, capture_output=True, timeout=1800)
            if p.returncode != 0:
                raise RuntimeError(p.stderr.decode(errors="replace")[-800:])
            return p.stdout.decode(errors="replace")
        sh("command -v python3 >/dev/null || (command -v dnf >/dev/null && dnf -q -y install python3) || "
           "(apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-minimal) >/dev/null")
        sh("cat > /tmp/agent.py", AGENT.read_bytes())
        inv = json.loads(sh("python3 /tmp/agent.py collect"))
        say(f"{distro}: {inv['os_name']}, {len(inv['packages'])} packages")
        return inv
    finally:
        subprocess.run(["wsl", "--unregister", name], capture_output=True)


def main():
    OUT.mkdir(exist_ok=True)
    if DB.exists():
        DB.unlink()
    inventories = {d: collect_wsl(d) for d in DISTROS}
    p = subprocess.run([sys.executable, str(AGENT), "collect"], capture_output=True, text=True, check=True)  # read-only
    inventories["windows"] = json.loads(p.stdout)
    say(f"this PC: {inventories['windows']['os_name']}, {len(inventories['windows']['packages'])} items")

    os.environ.update(NIMSTEAD_SECURE_COOKIES="0", NIMSTEAD_INVENTORY_MIN_SECONDS="0",
                      NIMSTEAD_SIGNING_KEY_FILE=str(OUT / "signing.pem"), NIMSTEAD_SECRET_KEY_FILE=str(OUT / "secret.key"),
                      NIMSTEAD_CHECKPOINT_DIR=str(OUT / "checkpoints"))
    from fastapi.testclient import TestClient

    from nimstead import feeds
    from nimstead.app import create_app
    from nimstead.db import Advisory, make_sessionmaker
    from nimstead.match import normalize_ecosystem
    url = f"sqlite:///{DB.as_posix()}"
    app = create_app(url)
    with make_sessionmaker(url)() as s:
        in_use = {normalize_ecosystem(inv["ecosystem"]) for d, inv in inventories.items() if d != "windows"}
        t = time.time()
        say(f"feeds: KEV {feeds.sync_kev(s)}, EPSS {feeds.sync_epss(s)}")
        say(f"feeds: OSV {feeds.sync_osv(s, sorted({e.split(':')[0] for e in in_use}), only=in_use)}")
        say(f"feeds: NVD {feeds.sync_nvd(s, ['2024', '2025', '2026', 'modified'])}")
        say(f"feeds: MSRC {feeds.sync_msrc(s, 3)}  ({time.time() - t:.0f}s)")
        for fx in ("Maven__org.apache.logging.log4j_log4j-core.json", "Maven__com.fasterxml.jackson.core_jackson-databind.json"):
            d = json.loads((ROOT / "api/tests/fixtures/osv" / fx).read_text())
            for rec in d["records"]:
                s.merge(Advisory(id=rec["id"], ecosystem="Maven", package=d["name"], record=rec))
        s.commit()

    password = "Demo-" + secrets.token_urlsafe(9)
    c = TestClient(app)
    assert c.post("/api/auth/signup", json={"email": "analyst@demo.example", "password": password, "org_name": "Acme Demo"}).status_code == 201
    token = c.post("/api/enroll-tokens", json={"sandbox": True}).json()["token"]
    for host, src, crit, internet, ring in HOSTS:
        inv = inventories[src]
        a = c.post("/api/agent/enroll", json={"token": token, "hostname": host, "os_name": inv["os_name"], "ecosystem": inv["ecosystem"]}).json()
        c.patch(f"/api/assets/{a['asset_id']}", json={"criticality": crit, "internet_facing": internet, "ring": ring})
        r = c.post("/api/agent/inventory", json=inv, headers={"Authorization": f"Bearer {a['agent_key']}"}).json()
        say(f"{host}: {r}")
    app_asset = c.post("/api/assets", json={"name": "billing-service", "criticality": "high", "internet_facing": True}).json()
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
        {"type": "library", "name": "log4j-core", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
        {"type": "library", "name": "jackson-databind", "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.10.1"}]}
    r = c.post(f"/api/assets/{app_asset['id']}/sbom", content=json.dumps(bom))
    say(f"billing-service SBOM: {r.json()}")
    summ = c.get("/api/summary").json()
    say(f"open by priority: {summ['open_by_priority']}")
    (OUT / "login.txt").write_text(f"email: analyst@demo.example\npassword: {password}\n")
    say(f"sign-in saved to {OUT / 'login.txt'}")


if __name__ == "__main__":
    try:
        main()
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
