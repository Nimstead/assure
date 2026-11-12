"""Network checks from one opted-in agent against REAL services (tasks/plan-network.md Checkpoint 4, DECISIONS 129), in a
DISPOSABLE WSL distro (Debian): network namespaces on one bridge, as in netneighbours.py. "web" runs the real agent; the
agentless "camera" runs a real unauthenticated Redis and an OpenSSL TLS server with an expired certificate. A neighbour
entry outside web's subnet is planted in its table (a permanent ARP entry on another prefix).

Run from api/:  uv run python ../sandbox/netinternal.py [--keep]

Must hold: the agent's own target choice is the camera and db, which has no agent here (never the planted address, never itself); its real
observations, judged by the real server, open NIM-EXPOSED-REDIS, NIM-TLS-EXPIRED and NIM-WEB-GIT (a real .git/config the agent
judged itself, sending only facts, never the file) on the camera's device asset and no
untrusted-certificate finding; Redis stopped (refused) then closes its finding; a device the host never saw, added to
the report by hand, is refused by the server. Logs to sandbox/last_run_netinternal.json.
"""

import datetime as dt
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import netneighbours as nn
from netneighbours import HOSTS, network
from signin import signup  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "nimstead-sbx-"
nn.NAME = NAME = PREFIX + "netint-" + secrets.token_hex(3)
TMP = Path(tempfile.mkdtemp(prefix="nimstead-sbx-netint-"))
PLANTED = ("10.88.0.5", "02:00:00:88:00:05")
log: list[dict] = []
DRIVER = r"""
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("a", "/root/agent.py"); a = importlib.util.module_from_spec(spec); spec.loader.exec_module(a)
view = a.network_view()
targets = a.network_check_targets(view["seen"], a.own_networks(), set(view["own"]["ips"]), 0)
print(json.dumps({"view": view, "targets": targets, "checks": a.network_checks(view["seen"])}))
"""


def note(step, **kw):
    log.append({"step": step, **kw})
    print(f"[{time.strftime('%H:%M:%S')}] {step}", json.dumps(kw, default=str)[:1500] if kw else "", flush=True)


def expired_cert() -> tuple[bytes, bytes]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "camera.lan")])
    t = dt.datetime.now(dt.UTC)
    c = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(7)
         .not_valid_before(t - dt.timedelta(days=400)).not_valid_after(t - dt.timedelta(days=30)).sign(key, hashes.SHA256()))
    return c.public_bytes(serialization.Encoding.PEM), key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                                         serialization.NoEncryption())


def agent_run(vm) -> dict:
    nn.put("/root/driver.py", DRIVER.encode())
    return json.loads(vm("ip netns exec web python3 -I /root/driver.py"))


def main(keep=False) -> int:
    vm = nn.vm
    try:
        r = subprocess.run(["wsl", "--install", "Debian", "--name", NAME, "--location", str(TMP / "d"), "--no-launch"], capture_output=True, timeout=1800)
        if r.returncode != 0:
            raise RuntimeError((r.stdout + r.stderr).decode("utf-16-le", errors="replace"))
        vm("apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iproute2 iputils-ping python3 redis-server openssl >/dev/null")
        vm("systemctl disable --now redis-server >/dev/null 2>&1 || true")
        nn.put("/root/agent.py", (ROOT / "agent" / "nimstead_agent.py").read_bytes())
        pem, key = expired_cert()
        nn.put("/root/expired.pem", pem)
        nn.put("/root/expired.key", key)
        network()
        vm("mkdir -p /root/www/.git")
        nn.put("/root/www/.git/config", b"[core]\n\trepositoryformatversion = 0\n")  # served by the camera's web server
        vm("ip netns exec camera redis-server --bind 0.0.0.0 --protected-mode no --port 6379 --save '' --daemonize yes >/dev/null")
        vm("ip netns exec camera sh -c 'nohup openssl s_server -quiet -accept 443 -cert /root/expired.pem -key /root/expired.key -www >/dev/null 2>&1 &'; sleep 2")
        vm(f"ip -n web neigh replace {PLANTED[0]} lladdr {PLANTED[1]} dev e-web nud permanent")
        vm(f"ip netns exec web ping -c 1 -W 2 {HOSTS['camera'][0]} >/dev/null", check=False)

        os.environ.update(NIMSTEAD_SECURE_COOKIES="0", NIMSTEAD_SIGNING_KEY_FILE=str(TMP / "s.pem"), NIMSTEAD_SECRET_KEY_FILE=str(TMP / "s.key"),
                          NIMSTEAD_CHECKPOINT_DIR=str(TMP / "cp"))
        from fastapi.testclient import TestClient

        from nimstead.app import create_app
        c = TestClient(create_app(f"sqlite:///{(TMP / 'n.db').as_posix()}"))
        signup(c, {"email": "netint@example.com", "password": "correct horse battery", "org_name": "NetInt"})
        token = c.post("/api/enroll-tokens").json()["token"]
        h = {"Authorization": f"Bearer {c.post('/api/agent/enroll', json={'token': token, 'hostname': 'web-1', 'ecosystem': 'Debian:13'}).json()['agent_key']}"}

        run1 = agent_run(vm)
        note("agent's own choice and observations", targets=run1["targets"], planted_in_table=any(r["ip"] == PLANTED[0] for r in run1["view"]["seen"]))
        assert any(r["ip"] == PLANTED[0] for r in run1["view"]["seen"]), "the planted entry should be in the table"
        # db has no agent in this run, so it's a fair target too; never the planted address, never web itself
        assert sorted(t[0] for t in run1["targets"]) == sorted([HOSTS["db"][0], HOSTS["camera"][0]]), run1["targets"]
        assert c.post("/api/agent/inventory", headers=h, json={"os_name": "Debian 13", "ecosystem": "Debian:13", "packages": [],
                                                               "agent_version": "0.7.0", "neighbours": run1["view"]}).status_code == 200
        forged = {**run1["checks"]["devices"][0], "ip": "10.77.0.99", "mac": "02:00:00:77:00:99"}  # never in web-1's table
        out = c.post("/api/agent/network-checks", headers=h, json={"devices": run1["checks"]["devices"] + [forged]}).json()
        f1 = sorted((f["vuln_id"], f["hostname"]) for f in c.get("/api/findings").json())
        note("server's judgement", result=out, findings=f1)
        assert out["refused"] == 1 and out["checked"] == 2, out
        assert ("NIM-EXPOSED-REDIS", HOSTS["camera"][0]) in f1 and ("NIM-TLS-EXPIRED", HOSTS["camera"][0]) in f1, f1
        assert ("NIM-WEB-GIT", HOSTS["camera"][0]) in f1, f1  # judged in the agent, from facts
        camera_obs = next(d for d in run1["checks"]["devices"] if d["ip"] == HOSTS["camera"][0])
        assert all(len(v) == 4 for v in camera_obs["http"].values()) and "repositoryformatversion" not in json.dumps(camera_obs), camera_obs["http"]
        assert not any(v in ("NIM-TLS-UNTRUSTED", "NIM-TLS-NAME") for v, _ in f1), f1

        vm("ip netns exec camera pkill redis-server || true", check=False)
        time.sleep(1)
        run2 = agent_run(vm)
        assert c.post("/api/agent/network-checks", headers=h, json={"devices": run2["checks"]["devices"]}).status_code == 200
        f2 = sorted(f["vuln_id"] for f in c.get("/api/findings").json())
        note("after Redis stopped", findings=f2)
        assert "NIM-EXPOSED-REDIS" not in f2 and "NIM-TLS-EXPIRED" in f2, f2
        dev = next(d for d in c.get("/api/network/unmanaged").json() if d["mac"] == HOSTS["camera"][1])
        note("RESULT: PASS", device=dev)
        return 0
    except Exception as e:
        note("RESULT: FAIL", error=f"{type(e).__name__}: {e}"[:2000])
        return 1
    finally:
        if not keep:
            nn.teardown()
            subprocess.run(["wsl", "--unregister", NAME], capture_output=True)
        (ROOT / "sandbox" / "last_run_netinternal.json").write_text(json.dumps(log, indent=1, default=str))


if __name__ == "__main__":
    sys.exit(main("--keep" in sys.argv))
