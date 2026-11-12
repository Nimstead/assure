"""Devices with no agent, from REAL neighbour tables (tasks/plan-network.md Checkpoint 3, DECISIONS 128), in a DISPOSABLE
WSL distro (Debian). WSL distros share one network stack, so the three machines are network namespaces on one bridge, each
with its own kernel ARP/NDP table: "web" and "db" run the real agent's `collect`, "camera" has no agent and a Hikvision
MAC prefix. The machines talk to each other (ping and one HTTP request), so their tables fill the way real traffic fills them.

Run from api/:  uv run python ../sandbox/netneighbours.py [--keep]

Each agent's real output goes to the real server (in-process, its own SQLite) as that host's inventory; the server must then
list exactly one device with no agent, the camera, seen by both hosts, named by the IEEE registry it fetched from Wireshark's
automated `manuf` (one download). The two agents, which see each other, must not be listed. Logs to
sandbox/last_run_netneighbours.json.
"""

import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from signin import signup  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "nimstead-sbx-"
NAME = PREFIX + "neigh-" + secrets.token_hex(3)
TMP = Path(tempfile.mkdtemp(prefix="nimstead-sbx-neigh-"))
CAMERA_MAC = "bc:ba:c2:11:22:33"  # a Hikvision block in the IEEE registry
HOSTS = {"web": ("10.77.0.10", "52:54:00:77:00:10"), "db": ("10.77.0.11", "52:54:00:77:00:11"), "camera": ("10.77.0.64", CAMERA_MAC)}
log: list[dict] = []


def note(step, **kw):
    log.append({"step": step, **kw})
    print(f"[{time.strftime('%H:%M:%S')}] {step}", json.dumps(kw, default=str)[:1500] if kw else "", flush=True)


def vm(script: str, check=True) -> str:
    assert NAME.startswith(PREFIX)
    p = subprocess.run(["wsl", "-d", NAME, "-u", "root", "--", "sh", "-s"], input=script.encode(), capture_output=True, timeout=1200)
    if check and p.returncode != 0:
        raise RuntimeError(f"{script[:200]}\n{p.stdout.decode(errors='replace')[-600:]}\n{p.stderr.decode(errors='replace')[-600:]}")
    return p.stdout.decode(errors="replace")


def put(path: str, data: bytes):
    subprocess.run(["wsl", "-d", NAME, "-u", "root", "--", "sh", "-c", f"cat > {path}"], input=data, check=True, timeout=120)


TEARDOWN = "ip link del br-nim 2>/dev/null; " + " ".join(f"ip link del v-{ns} 2>/dev/null; ip netns del {ns} 2>/dev/null;" for ns in HOSTS) + " true"


def teardown():
    """WSL distros share one kernel network stack: the bridge and veths outlive the distro unless removed."""
    vm(TEARDOWN, check=False)


def network():
    """A bridge and three namespaces, each with a veth, its address and its MAC; then traffic between them."""
    teardown()  # a run cut short leaves them behind
    lines = ["set -e", "ip link add br-nim type bridge", "ip link set br-nim up"]
    for ns, (ip, mac) in HOSTS.items():
        lines += [f"ip netns add {ns}", f"ip link add v-{ns} type veth peer name e-{ns}", f"ip link set v-{ns} master br-nim",
                  f"ip link set v-{ns} up", f"ip link set e-{ns} netns {ns}", f"ip -n {ns} link set e-{ns} address {mac}",
                  f"ip -n {ns} link set e-{ns} up", f"ip -n {ns} link set lo up", f"ip -n {ns} addr add {ip}/24 dev e-{ns}"]
    vm("\n".join(lines))
    vm("ip netns exec camera sh -c 'nohup python3 -m http.server 80 >/dev/null 2>&1 &'; sleep 1")
    for a in ("web", "db"):
        for b, (ip, _) in HOSTS.items():
            if a != b:
                vm(f"ip netns exec {a} ping -c 2 -W 2 {ip} >/dev/null", check=False)
    vm(f"ip netns exec web python3 -c \"import urllib.request; urllib.request.urlopen('http://{HOSTS['camera'][0]}/', timeout=5)\"", check=False)


def main(keep=False) -> int:
    try:
        r = subprocess.run(["wsl", "--install", "Debian", "--name", NAME, "--location", str(TMP / "d"), "--no-launch"],
                           capture_output=True, timeout=1800)
        if r.returncode != 0:
            raise RuntimeError((r.stdout + r.stderr).decode("utf-16-le", errors="replace"))
        vm("apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iproute2 iputils-ping python3 >/dev/null")
        put("/root/agent.py", (ROOT / "agent" / "nimstead_agent.py").read_bytes())
        network()
        tables = {ns: vm(f"ip netns exec {ns} ip -j neigh") for ns in ("web", "db")}
        note("namespaces up, traffic sent", tables={k: json.loads(v or "[]") for k, v in tables.items()})

        os.environ.update(NIMSTEAD_SECURE_COOKIES="0", NIMSTEAD_SIGNING_KEY_FILE=str(TMP / "s.pem"), NIMSTEAD_SECRET_KEY_FILE=str(TMP / "s.key"),
                          NIMSTEAD_CHECKPOINT_DIR=str(TMP / "cp"))
        from fastapi.testclient import TestClient

        from nimstead import feeds, oui
        from nimstead.app import create_app
        from nimstead.db import make_sessionmaker
        db = f"sqlite:///{(TMP / 'n.db').as_posix()}"
        c = TestClient(create_app(db))
        signup(c, {"email": "neigh@example.com", "password": "correct horse battery", "org_name": "Neigh"})
        for ns in ("web", "db"):
            inv = json.loads(vm(f"ip netns exec {ns} python3 -I /root/agent.py collect"))
            note(f"{ns}: the agent's own collect", neighbours=inv["neighbours"])
            assert any(n["mac"] == CAMERA_MAC for n in inv["neighbours"]["seen"]), f"{ns} never saw the camera"
            assert HOSTS[ns][1] in inv["neighbours"]["own"]["macs"], f"{ns} didn't report its own MAC"
            token = c.post("/api/enroll-tokens").json()["token"]
            key = c.post("/api/agent/enroll", json={"token": token, "hostname": f"{ns}-1", "ecosystem": inv["ecosystem"]}).json()["agent_key"]
            res = c.post("/api/agent/inventory", headers={"Authorization": f"Bearer {key}"}, json=inv)
            assert res.status_code == 200, res.text
        with make_sessionmaker(db)() as s:
            note("MAC vendor registry", result=oui.sync(s, lambda url, limit: feeds._get(None, url, limit)))
        got = c.get("/api/network/unmanaged").json()
        note("devices with no agent", rows=got)
        assert [d["mac"] for d in got] == [CAMERA_MAC], got
        assert got[0]["addresses"] == [HOSTS["camera"][0]] and got[0]["seen_by"] == ["db-1", "web-1"], got
        assert "Hikvision" in got[0]["vendor"], got[0]["vendor"]
        note("RESULT: PASS", camera=got[0])
        return 0
    except Exception as e:
        note("RESULT: FAIL", error=f"{type(e).__name__}: {e}"[:2000])
        return 1
    finally:
        if not keep:
            teardown()
            subprocess.run(["wsl", "--unregister", NAME], capture_output=True)
        (ROOT / "sandbox" / "last_run_netneighbours.json").write_text(json.dumps(log, indent=1, default=str))


if __name__ == "__main__":
    sys.exit(main("--keep" in sys.argv))
