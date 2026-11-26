"""Paths proof (tasks/spec-paths.md success criteria 1-6) in a DISPOSABLE lab: four machines that are systemd (or, for
Alpine, plain sshd) containers on one private Podman bridge inside a disposable WSL Fedora 44 distro.

Run from api/:  uv run python ../sandbox/paths_lab.py [--spike] [--keep] [--reuse nimstead-sbx-NAME]
- Creates nimstead-sbx-paths-<hex>, installs Podman from Fedora's repositories, builds one image per distro, starts the
  machines below on the `nimlab` bridge (10.89.7.0/24) and unregisters the distro at the end (unless --keep).
- Each container is a machine to the agent: its own addresses, accounts, sshd and /proc. The real agent runs as root in it
  and this script relays its bodies to an in-process API (as sandbox/runtime.py does).
- --spike (T0 of tasks/todo-paths.md): the lab comes up, one real `ssh` crosses it while the target sees the source's
  address, and the oracles' outputs are saved as test fixtures under api/tests/fixtures/access/. No private key is saved:
  the agent's tests build key files from these public halves.
- Only this lab's machines are ever signed in to, and only by this script (the spec's boundary): the agent never uses a key.
Writes sandbox/last_run_paths.json (or last_run_paths_spike.json): every step, PASS only if every criterion passed.
"""

import base64
import json
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "nimstead-sbx-"
REUSE = sys.argv[sys.argv.index("--reuse") + 1] if "--reuse" in sys.argv else None
NAME = REUSE or f"{PREFIX}paths-{secrets.token_hex(3)}"
SPIKE, KEEP = "--spike" in sys.argv, "--keep" in sys.argv or "--reuse" in sys.argv
TMP = Path(tempfile.mkdtemp(prefix="paths-lab-"))
FIXTURES = ROOT / "api" / "tests" / "fixtures" / "access"
NET, SUBNET = "nimlab", "10.89.7.0/24"
MACHINES = {  # name -> (image, address)
    "web-1": ("lab-debian", "10.89.7.11"),
    "build-1": ("lab-debian", "10.89.7.12"),
    "db-1": ("lab-alma", "10.89.7.13"),
    "edge-1": ("lab-alpine", "10.89.7.14"),
}
IMAGES = {
    "lab-debian": ("FROM docker.io/library/debian:13\n"
                   "RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends systemd systemd-sysv "
                   "openssh-server openssh-client sudo python3 nginx cron iproute2 procps ca-certificates >/dev/null && apt-get clean\n"
                   "RUN systemctl enable ssh nginx cron && systemctl mask getty@tty1.service console-getty.service systemd-logind.service\n"
                   "STOPSIGNAL SIGRTMIN+3\nCMD [\"/sbin/init\"]\n"),
    "lab-alma": ("FROM docker.io/library/almalinux:9\n"
                 "RUN dnf -q -y install systemd openssh-server openssh-clients sudo python3 nginx cronie iproute procps-ng >/dev/null && dnf clean all\n"
                 "RUN systemctl enable sshd nginx crond\n"
                 "STOPSIGNAL SIGRTMIN+3\nCMD [\"/usr/sbin/init\"]\n"),
    "lab-alpine": ("FROM docker.io/library/alpine:3.21\n"
                   "RUN apk add -q openssh sudo python3 iproute2 && ssh-keygen -A && passwd -d root >/dev/null && passwd -l root >/dev/null\n"
                   "CMD [\"/usr/sbin/sshd\", \"-D\", \"-e\"]\n"),
}

log: list[dict] = []
failures: list[str] = []


def note(step, **kw):
    log.append({"step": step, **kw})
    print(f"[{time.strftime('%H:%M:%S')}] {step}", json.dumps(kw, default=str)[:400] if kw else "", flush=True)


def check(criterion, ok, **kw):
    note(f"{'PASS' if ok else 'FAIL'}: {criterion}", **kw)
    if not ok:
        failures.append(criterion)


def wsl(script, timeout=1800, ok=(0,)):
    assert NAME.startswith(PREFIX)  # never run commands in a distro this script didn't make
    p = subprocess.run(["wsl", "-d", NAME, "-u", "root", "--", "sh", "-s"], input=script.replace("\r", "").encode(), capture_output=True, timeout=timeout)
    if p.returncode not in ok:
        raise RuntimeError(f"sandbox command failed ({p.returncode}): {script[:300]}\n{p.stdout.decode(errors='replace')[-2000:]}\n{p.stderr.decode(errors='replace')[-2000:]}")
    return p.stdout.decode(errors="replace")


def on(machine, script, timeout=600, ok=(0,)):
    """A shell script run as root inside one lab machine."""
    assert machine in MACHINES
    b64 = base64.b64encode(script.replace("\r", "").encode()).decode()
    return wsl(f"echo {b64} | base64 -d | podman exec -i {machine} sh -s", timeout, ok)


def put(machine, path, data: bytes, mode="600", owner="root:root"):
    b64 = base64.b64encode(data).decode()
    on(machine, f"mkdir -p $(dirname {path}) && echo {b64} | base64 -d > {path} && chmod {mode} {path} && chown {owner} {path}")


def setup():
    if not REUSE:
        r = subprocess.run(["wsl", "--install", "FedoraLinux-44", "--name", NAME, "--location", str(TMP / "d"), "--no-launch"], capture_output=True, timeout=1800)
        if r.returncode != 0:
            raise RuntimeError((r.stdout + r.stderr).decode("utf-16-le", errors="replace"))
    note("distro", name=NAME, reused=bool(REUSE))
    wsl("rpm -q podman >/dev/null 2>&1 || dnf -q -y install podman containernetworking-plugins >/dev/null", timeout=1800)
    note("podman", version=wsl("podman --version").strip(), cgroup=wsl("stat -fc %T /sys/fs/cgroup").strip())
    wsl(f"podman network exists {NET} || podman network create --subnet {SUBNET} {NET} >/dev/null")
    for image, dockerfile in IMAGES.items():
        b64 = base64.b64encode(dockerfile.encode()).decode()
        wsl(f"podman image exists {image} || (mkdir -p /root/{image} && echo {b64} | base64 -d > /root/{image}/Containerfile && "
            f"podman build -q -t {image} /root/{image} >/dev/null)", timeout=3600)
    for name, (image, addr) in MACHINES.items():
        systemd = "--systemd=always" if image != "lab-alpine" else ""
        wsl(f"podman container exists {name} || podman run -d --name {name} --hostname {name} --network {NET} --ip {addr} {systemd} {image} >/dev/null")
    for name, (image, _) in MACHINES.items():
        if image == "lab-alpine":
            continue
        state = ""
        for _ in range(60):
            state = on(name, "systemctl is-system-running 2>/dev/null; true").strip()
            if state in ("running", "degraded"):
                break
            time.sleep(2)
        failed = on(name, "systemctl --failed --no-legend --plain 2>/dev/null | cut -d' ' -f1; true").split()
        note("booted", machine=name, state=state, failed=failed)
    note("machines", **{n: on(n, "ip -4 -o addr show scope global | awk '{print $4}'").split() for n in MACHINES})


def spike():
    """T0: real ssh across the bridge, and the fixtures the agent's parsers are tested on."""
    on("web-1", "rm -f /root/.ssh/lab && ssh-keygen -q -t ed25519 -N '' -C 'root@web-1 lab' -f /root/.ssh/lab")
    pub = on("web-1", "cat /root/.ssh/lab.pub")
    put("db-1", "/root/.ssh/authorized_keys", pub.encode())
    on("db-1", "chmod 700 /root/.ssh; restorecon -R /root/.ssh 2>/dev/null; true")
    target = MACHINES["db-1"][1]
    out = on("web-1", f"ssh -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
                      f"-i /root/.ssh/lab root@{target} 'echo signed-in-as-$(id -un)' 2>&1; true")
    check("T0: ssh with a planted key crosses the bridge", "signed-in-as-root" in out, output=out.strip()[-300:])
    on("web-1", f"(ssh -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
                f"-i /root/.ssh/lab root@{target} 'sleep 30' >/dev/null 2>&1 &) ; sleep 2")
    seen = on("db-1", "ss -Htn state established 2>/dev/null; true")
    check("T0: the target sees the source's own address", MACHINES["web-1"][1] in seen, ss=seen.strip()[-400:])
    peers = on("web-1", "cat /proc/net/tcp")
    check("T0: the source's /proc/net/tcp holds the connection", "0016" in peers.upper(), lines=len(peers.splitlines()))
    record_fixtures()


def record_fixtures():
    FIXTURES.mkdir(parents=True, exist_ok=True)
    distro = {"web-1": "debian13", "db-1": "alma9", "edge-1": "alpine321"}
    for m, d in distro.items():
        (FIXTURES / f"sshd_t_{d}.txt").write_bytes(on(m, "sshd -T 2>&1").encode())
        (FIXTURES / f"passwd_{d}.txt").write_bytes(on(m, "cat /etc/passwd").encode())
        (FIXTURES / f"group_{d}.txt").write_bytes(on(m, "cat /etc/group").encode())
        (FIXTURES / f"sshd_config_{d}.txt").write_bytes(on(m, "cat /etc/ssh/sshd_config").encode())
    # a hardened sshd with a Match block, on Debian
    on("build-1", "printf 'PermitRootLogin no\\nPasswordAuthentication no\\nAllowUsers deploy backup@10.89.7.*\\nMatch Address 10.89.7.0/24\\n  PermitRootLogin prohibit-password\\n' "
                  "> /etc/ssh/sshd_config.d/50-lab.conf")
    (FIXTURES / "sshd_t_debian13_hardened.txt").write_bytes(on("build-1", "sshd -T 2>&1").encode())
    on("build-1", "rm -f /etc/ssh/sshd_config.d/50-lab.conf")
    # sudo -l: NOPASSWD ALL, a limited rule, none
    on("web-1", "id deploy >/dev/null 2>&1 || useradd -m -s /bin/bash deploy; id ops >/dev/null 2>&1 || useradd -m -s /bin/bash ops; "
                "echo 'deploy ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/deploy; echo 'ops ALL=(root) NOPASSWD: /usr/bin/systemctl restart nginx' > /etc/sudoers.d/ops; "
                "chmod 440 /etc/sudoers.d/deploy /etc/sudoers.d/ops")
    for who in ("deploy", "ops", "www-data"):
        (FIXTURES / f"sudo_l_{who}.txt").write_bytes(on("web-1", f"sudo -n -l -U {who} 2>&1; true").encode())
    # public halves and the oracle's fingerprints; the private files stay in the lab
    kinds = [("ed25519", "-t ed25519"), ("ecdsa", "-t ecdsa -b 256"), ("rsa", "-t rsa -b 2048")]
    fps = []
    for name, args in kinds:
        for pem, fmt in (("", ""), ("_pem", "-m PEM")):
            if pem and name == "ed25519":
                continue  # OpenSSH writes ed25519 only in its own format
            for enc, pw in (("", "''"), ("_enc", "labpass")):
                f = f"/root/fx/{name}{pem}{enc}"
                on("web-1", f"mkdir -p /root/fx && rm -f {f} {f}.pub && ssh-keygen -q {args} {fmt} -N {pw} -C 'fixture {name}' -f {f}")
                (FIXTURES / f"{name}{pem}{enc}.pub").write_bytes(on("web-1", f"cat {f}.pub").encode())
                if pem:  # a PEM key's armour and encryption headers only, never a line of the key itself
                    (FIXTURES / f"{name}{pem}{enc}.head").write_bytes(on("web-1", f"grep -E '^(-----BEGIN|Proc-Type:|DEK-Info:)' {f}").encode())
                fps.append(on("web-1", f"ssh-keygen -lf {f}.pub").strip() + f"  <- {name}{pem}{enc}")
    (FIXTURES / "fingerprints.txt").write_bytes(("\n".join(fps) + "\n").encode())
    note("fixtures", files=sorted(p.name for p in FIXTURES.iterdir()))


def teardown():
    if KEEP:
        note("kept", distro=NAME)
        return
    subprocess.run(["wsl", "--unregister", NAME], capture_output=True, timeout=600)
    note("unregistered", distro=NAME)


def main():
    out = ROOT / "sandbox" / ("last_run_paths_spike.json" if SPIKE else "last_run_paths.json")
    try:
        setup()
        if SPIKE:
            spike()
    except Exception as e:  # noqa: BLE001 — the record says what broke
        failures.append(f"error: {type(e).__name__}: {e}"[:2000])
        note("error", error=str(e)[:2000])
    finally:
        teardown()
    out.write_text(json.dumps({"result": "FAIL" if failures else "PASS", "failures": failures, "log": log}, indent=1, default=str) + "\n")
    print("FAIL" if failures else "PASS", failures)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
