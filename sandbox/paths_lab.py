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
    "app-1": ("lab-debian", "10.89.7.15"),
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
        # SYS_PTRACE: a real machine's root reads every process's maps; a container's root can't without it
        wsl(f"podman container exists {name} || podman run -d --name {name} --hostname {name} --network {NET} --ip {addr} --cap-add SYS_PTRACE {systemd} {image} >/dev/null")
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


# ---- the proof (T9) ---------------------------------------------------------------------------------------------------
# The chain this lab plants (every key generated here, used only by this script, never kept):
#   web-1: webapp.service, a TLS listener on 8443 running as www-data, loading libssl; www-data may sudo anything with no
#          password (the way up); root holds K_ROOT (opens root on db-1) and a passphrase key K_PASS (root on edge-1);
#          deploy holds K_DEP (opens deploy on build-1)
#   build-1: reached as deploy; deploy's own K_B opens root on edge-1; root's K_BR opens root on app-1, which deploy can't read
#   db-1:  nginx (its master runs as root) on AlmaLinux 9.8's earlier openssl from the vault: a way in that is root at once
#   app-1: the target of criterion 2's cases, one sshd change at a time
SSH_OPTS = "-o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"
MARK = "nimstead-signed-in"
COMMENT = "lab-comment-never-sent"
AWS_MARK = "AKIALABMARKERNEVERSENT"
WEBAPP = '''import http.server, ssl
s = http.server.HTTPServer(("0.0.0.0", 8443), http.server.SimpleHTTPRequestHandler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/etc/webapp/cert.pem", "/etc/webapp/key.pem")
s.socket = ctx.wrap_socket(s.socket, server_side=True)
s.serve_forever()
'''
UNIT = "[Unit]\nDescription=lab web app\n[Service]\nUser=www-data\nWorkingDirectory=/var/www\nExecStart=/usr/bin/python3 /opt/webapp/webapp.py\n[Install]\nWantedBy=multi-user.target\n"
VAULT = "".join(f"[alma-vault-98-{r.lower()}]\nname=AlmaLinux 9.8 {r} (vault)\nbaseurl=https://vault.almalinux.org/9.8/{r}/x86_64/os/\n"
                f"gpgcheck=1\ngpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-9\nenabled=0\n\n" for r in ("BaseOS", "AppStream"))


def wslpath(p: Path) -> str:
    s = str(p).replace("\\", "/")
    return "/mnt/" + s[0].lower() + s[2:]


def keygen(machine, path, owner="root", passphrase=""):
    """A fresh ed25519 key on a lab machine, owned by owner; returns its public line."""
    home = "/root" if owner == "root" else f"/home/{owner}"
    on(machine, f"mkdir -p {home}/.ssh && chmod 700 {home}/.ssh && rm -f {path} {path}.pub && ssh-keygen -q -t ed25519 -N '{passphrase}' -C '{COMMENT}' -f {path} "
                f"&& chown -R {owner}:{owner} {home}/.ssh")
    return on(machine, f"cat {path}.pub").strip()


def trust(machine, account, lines):
    """Write an account's authorized_keys on a lab machine (each line as given)."""
    home = "/root" if account == "root" else f"/home/{account}"
    put(machine, f"{home}/.ssh/authorized_keys", ("\n".join(lines) + "\n").encode(), "600", f"{account}:{account}")
    on(machine, f"chmod 700 {home}/.ssh && chown {account}:{account} {home}/.ssh; restorecon -R {home}/.ssh 2>/dev/null; true")


def ssh(src, key, account, dst, as_user="root", cmd=f"echo {MARK}"):
    """A real sign-in from src to dst with one key (the oracle): the command's output, or the error."""
    run = f"ssh {SSH_OPTS} -i {key} {account}@{MACHINES[dst][1]} '{cmd}' 2>&1; true"
    return on(src, run if as_user == "root" else f"su -s /bin/sh {as_user} -c \"{run}\"")


def plant():
    """Accounts, services, keys and weaknesses for the proof (module comment above)."""
    for m, (image, _) in MACHINES.items():
        add = "adduser -D -s /bin/sh deploy; passwd -u deploy >/dev/null 2>&1; true" if image == "lab-alpine" else "useradd -m -s /bin/bash deploy"
        on(m, f"id deploy >/dev/null 2>&1 || ({add})")
        if image == "lab-alpine":  # Alpine's adduser locks the password with "!": sshd then refuses keys too unless unlocked
            on(m, "sed -i 's/^deploy:!:/deploy:*:/' /etc/shadow")
        if image != "lab-alma":  # OpenSSH 9.8+ refuses a source after failed sign-ins; the oracles try every key on purpose
            on(m, "echo 'PerSourcePenaltyExemptList 10.89.7.0/24' > /etc/ssh/sshd_config.d/10-lab.conf && "
                  + ("kill -HUP $(cat /run/sshd.pid 2>/dev/null || pidof sshd)" if image == "lab-alpine" else "systemctl restart ssh"))
    # web-1: the way in runs as www-data, the way up is sudo, root's and deploy's keys. Its sshd is stopped before any report:
    # Debian 13's OpenSSH (as of this lab) carries a remote flaw (CVE-2026-123158) and runs as root, which would make getting
    # in there root at once (build-1 shows that case)
    on("web-1", "systemctl disable --now ssh ssh.socket >/dev/null 2>&1; systemctl disable --now nginx >/dev/null 2>&1; mkdir -p /etc/webapp /opt/webapp /var/www && "
                "openssl req -x509 -newkey rsa:2048 -nodes -keyout /etc/webapp/key.pem -out /etc/webapp/cert.pem -days 30 -subj /CN=web-1 2>/dev/null && "
                "chown www-data /etc/webapp/key.pem && echo 'www-data ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/webapp && chmod 440 /etc/sudoers.d/webapp")
    put("web-1", "/opt/webapp/webapp.py", WEBAPP.encode(), "644")
    put("web-1", "/etc/systemd/system/webapp.service", UNIT.encode(), "644")
    on("web-1", "systemctl daemon-reload && systemctl enable --now webapp >/dev/null 2>&1; sleep 2")
    keys = {"K_ROOT": keygen("web-1", "/root/.ssh/id_ed25519"), "K_PASS": keygen("web-1", "/root/.ssh/id_pass", passphrase="labpass"),  # noqa: S106 — a throwaway lab key
            "K_DEP": keygen("web-1", "/home/deploy/.ssh/id_ed25519", "deploy"), "K_CASE": keygen("web-1", "/root/.ssh/id_case"),
            "K_B": keygen("build-1", "/home/deploy/.ssh/id_ed25519", "deploy"), "K_BR": keygen("build-1", "/root/.ssh/id_ed25519")}
    put("web-1", "/root/.aws/credentials", f"[default]\naws_access_key_id={AWS_MARK}\n".encode(), "600")
    on("web-1", "ln -sf /root/.ssh/id_ed25519 /home/deploy/.ssh/id_link && (mkfifo /home/deploy/.ssh/id_fifo 2>/dev/null; true) && "
                "chown -h deploy:deploy /home/deploy/.ssh/id_link /home/deploy/.ssh/id_fifo")
    trust("db-1", "root", [keys["K_ROOT"]])
    trust("build-1", "deploy", [keys["K_DEP"]])
    trust("edge-1", "root", [keys["K_PASS"], keys["K_B"]])
    trust("app-1", "root", [keys["K_BR"]])
    note("planted", keys={k: v.split()[1][:16] + "…" for k, v in keys.items()}, webapp=on("web-1", "systemctl is-active webapp").strip(),
         web1_sshd=on("web-1", "systemctl is-active ssh; true").strip())
    return keys


class Server:
    """An in-process Nimstead with real feeds, each lab machine enrolled; the real agent's `collect` relayed to it."""

    def __init__(self):
        sys.path[:0] = [str(ROOT / "api" / "src"), str(ROOT / "sandbox")]
        import os
        os.environ.update(NIMSTEAD_SECURE_COOKIES="0", NIMSTEAD_INVENTORY_MIN_SECONDS="0", NIMSTEAD_SIGNING_KEY_FILE=str(TMP / "k.pem"),
                          NIMSTEAD_CHECKPOINT_DIR=str(TMP / "cp"), NIMSTEAD_SECRET_KEY_FILE=str(TMP / "sk"))
        from fastapi.testclient import TestClient
        from signin import signup

        from nimstead import feeds
        from nimstead.app import create_app
        from nimstead.db import make_sessionmaker
        self.db = f"sqlite:///{(TMP / 'nimstead.db').as_posix()}"
        self.c = TestClient(create_app(self.db))
        signup(self.c, {"email": "paths@example.com", "password": "sandbox-only-password", "org_name": "Paths lab"})
        self.Session = make_sessionmaker(self.db)
        with self.Session() as s:
            t = time.time()
            note("feeds", osv=feeds.sync_osv(s, ["Debian", "AlmaLinux", "Alpine"], only={"Debian:13", "AlmaLinux:9", "Alpine:v3.21"}),
                 kev=feeds.sync_kev(s), nvd={y: feeds.sync_nvd(s, [y]) for y in ("2024", "2025", "2026")}, seconds=round(time.time() - t))
        self.ids, self.h = {}, {}
        token = self.c.post("/api/enroll-tokens", json={"sandbox": True}).json()["token"]
        agent = wslpath(ROOT / "agent" / "nimstead_agent.py")
        for m in MACHINES:
            wsl(f"podman cp '{agent}' {m}:/root/nimstead_agent.py")
            a = self.c.post("/api/agent/enroll", json={"token": token, "hostname": m, "ecosystem": ""}).json()
            self.ids[m], self.h[m] = a["asset_id"], {"Authorization": f"Bearer {a['agent_key']}"}
        self.name = {v: k for k, v in self.ids.items()}

    def report(self, m) -> dict:
        inv = json.loads(on(m, "python3 /root/nimstead_agent.py collect", timeout=300))
        r = self.c.post("/api/agent/inventory", json=inv, headers=self.h[m])
        assert r.status_code == 200, r.text
        return inv

    def paths(self) -> dict:
        return self.c.get("/api/attack-paths").json()

    def edge(self, out, a, b, key=None):
        e = next((x for x in out["edges"] if (x["from"], x["to"]) == (self.ids[a], self.ids[b])), None)
        if e and key:
            ways = [w for w in e["ways"] if w.get("key") == key]
            return {**e, "ways": ways, "grade": ways[0]["grade"]} if ways else None
        return e


def fp_of(line: str) -> str:
    import hashlib
    return "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(line.split()[1])).digest()).decode().rstrip("=")


def facts_check(srv, invs):
    """Criterion 1: each machine's access read against its own oracles."""
    diffs = {}
    for m, inv in invs.items():
        acc, d = inv.get("access") or {}, []
        if acc.get("state") != "ok":
            d.append({"what": "state", "agent": acc.get("state"), "problem": acc.get("problem")})
        for a in acc.get("accounts", []):
            want = sorted(on(m, f"id -Gn {a['name']} 2>/dev/null; true").split())
            if want and a["groups"] != want:
                d.append({"what": "groups", "account": a["name"], "agent": a["groups"], "oracle": want})
        t = on(m, "sshd -T 2>&1; true")
        if "privilege separation directory" in t:  # installed, not running (web-1): sshd -T itself refuses
            if acc.get("sshd") != {"installed": True, "running": False}:
                d.append({"what": "sshd", "agent": acc.get("sshd"), "oracle": "installed, not running"})
        else:
            oracle = {ln.split(" ", 1)[0]: ln.split(" ", 1)[1].strip() for ln in t.splitlines() if " " in ln}
            for k in ("permitrootlogin", "pubkeyauthentication", "passwordauthentication", "permitemptypasswords"):
                if (acc.get("sshd") or {}).get(k) != oracle.get(k):
                    d.append({"what": "sshd", "key": k, "agent": (acc.get("sshd") or {}).get(k), "oracle": oracle.get(k)})
        files = on(m, "for f in /root/.ssh/* /home/*/.ssh/*; do case $f in *.pub|*authorized_keys*|*known_hosts*|*/config) continue;; esac; "
                      "[ -f \"$f\" ] && [ ! -L \"$f\" ] && head -c 40 \"$f\" | grep -q 'PRIVATE KEY' && "
                      "if [ -f \"$f.pub\" ]; then echo \"$f $(ssh-keygen -lf \"$f.pub\" | cut -d' ' -f2)\"; else echo \"$f $(ssh-keygen -lf \"$f\" 2>/dev/null | cut -d' ' -f2)\"; fi; done; true")
        want_held = {ln.split()[0]: ln.split()[1] for ln in files.splitlines() if len(ln.split()) == 2}
        got_held = {h["path"]: h["fp"] for h in acc.get("held", [])}
        if want_held != got_held:
            d.append({"what": "held", "agent": got_held, "oracle": want_held})
        trusted = on(m, "for u in root deploy; do h=$(getent passwd $u | cut -d: -f6); [ -f $h/.ssh/authorized_keys ] && "
                        "ssh-keygen -lf $h/.ssh/authorized_keys | while read b fp rest; do echo $u $fp; done; done; true")
        want_t = sorted(tuple(ln.split()) for ln in trusted.splitlines() if len(ln.split()) == 2)
        got_t = sorted((t["account"], t["fp"]) for t in acc.get("trusted", []))
        if want_t != got_t:
            d.append({"what": "trusted", "agent": got_t, "oracle": want_t})
        ss = on(m, "ss -Htn state established 2>/dev/null; true")
        want_p = sorted({ln.split()[-1] for ln in ss.splitlines() if ln.split() and ln.split()[-1].startswith(("10.", "172.", "192.168."))})
        got_p = sorted(inv.get("facts", {}).get("peers") or [])
        if want_p != got_p:
            d.append({"what": "peers", "agent": got_p, "oracle": want_p, "why": "connections change between the two reads"})
        if d:
            diffs[m] = d
    unexplained = {m: [x for x in d if not x.get("why")] for m, d in diffs.items()}
    check("1 facts equal the oracles (id -Gn, sshd -T, ssh-keygen -lf, ss)", not any(unexplained.values()), differences=diffs)


def privilege_check(srv, keys):
    """Criterion 3: web-1 enters as www-data and goes up through sudo; db-1's root listener skips becoming root."""
    out = srv.paths()
    web = {p["kind"]: p for p in out["hosts"][srv.ids["web-1"]]["paths"]}
    net = web.get("network")
    note("web-1 paths", paths=web)
    proof = on("web-1", "su -s /bin/sh www-data -c 'sudo -n head -c 5 /etc/shadow' 2>&1; true").strip()
    check("3a web-1: in as www-data, up through sudo, then root's keys (and sudo really makes www-data root)",
          bool(net) and net["steps"][:2] == ["Getting in", "Becoming root"] and net.get("reaches", {}).get("root") is True and proof.startswith("root:"),
          steps=net and net["steps"], sudo=proof[:5])
    rep = srv.c.get(f"/api/assets/{srv.ids['build-1']}/scan-report").json()
    full = next((p for p in rep.get("attack_paths", []) if p["kind"] == "network"), None)
    via = full and full["steps"][0]["ways"][0]["what"]
    check("3b build-1: sshd runs as root with a remote flaw in OpenSSH itself, so getting in is becoming root",
          bool(full) and "skipped" in full and full.get("reaches", {}).get("root") is True and "running as root" in (via or ""), way_in=via,
          skipped=full and full.get("skipped"))
    return out


def walk_by_ssh(srv):
    """The oracle for criterion 4: from web-1 as root (3a showed www-data becomes root there), every key readable by what is
    held, tried on every machine and account by a real ssh. A host whose own report has a foothold path reaching root is
    taken as root once reached, since ssh can't show a local flaw: each such step is returned, so the record says so."""
    footholds = {m for m in MACHINES if any(p["kind"] == "foothold" and (p.get("reaches") or {}).get("root")
                                            for p in srv.paths()["hosts"][srv.ids[m]]["paths"])}
    q, reached, upgraded = ["web-1"], {"web-1": "root"}, []
    while q:
        at = q.pop(0)
        who = reached[at]
        files = on(at, "for f in /root/.ssh/id_* /home/*/.ssh/id_*; do case $f in *.pub) continue;; esac; [ -f \"$f\" ] && [ ! -L \"$f\" ] && "
                       "echo \"$f $(stat -c %U \"$f\")\"; done; true").split("\n")
        mine = [ln.split()[0] for ln in files if ln.split() and (who == "root" or ln.split()[1] == who)]
        for dst in MACHINES:
            if dst == at:
                continue
            for account in ("root", "deploy"):
                for f in mine:
                    if MARK not in ssh(at, f, account, dst, as_user="root" if who == "root" else who):
                        continue
                    got = "root" if account == "root" or {"docker", "lxd", "disk"} & set(on(dst, f"id -Gn {account} 2>/dev/null; true").split()) else account
                    if got != "root" and dst in footholds:
                        got = "root"
                        upgraded.append(f"{dst}: arrived as {account}, its own foothold path reaches root")
                    if dst not in reached or (reached[dst] != "root" and got == "root"):
                        reached[dst] = got
                        q.append(dst)
    return reached, upgraded


def chain_check(srv, keys):
    """Criterion 4: the chain from web-1 equals an ssh walk; the top key choke point done for real shrinks reach as predicted."""
    out = srv.paths()
    chain = next((c for c in out["chains"] if c["start"] == srv.ids["web-1"]), {"reach": []})
    got = {srv.name[r["host"]]: (r["as"] if r["as"] == "root" else tuple(r["as"])) for r in chain["reach"]}
    walked, upgraded = walk_by_ssh(srv)
    want = {m: (v if v == "root" else (v,)) for m, v in walked.items() if m != "web-1"}
    check("4a the chain from web-1 equals the machines a real ssh walk reaches, and as whom", got == want, chain=got, ssh_walk=want,
          taken_from_reports=upgraded, choke=[(c["kind"], c["cuts"], c["action"][:120]) for c in out["choke_points"]])
    choke = next((c for c in out["choke_points"] if c["kind"] in ("retire-key", "untrust-key")), None)
    if not choke:
        check("4b a key choke point exists", False)
        return
    before = {srv.name[h] for h in reached_hosts(out)}
    if choke["kind"] == "retire-key":
        for m in MACHINES:  # remove it everywhere it's trusted, delete it where held
            for account in ("root", "deploy"):
                home = "/root" if account == "root" else f"/home/{account}"
                on(m, f"[ -f {home}/.ssh/authorized_keys ] && ssh-keygen -lf {home}/.ssh/authorized_keys >/dev/null 2>&1 && "
                      f"for i in $(seq 1 50); do :; done; true")
                lines = on(m, f"cat {home}/.ssh/authorized_keys 2>/dev/null; true").splitlines()
                keep = [ln for ln in lines if ln.strip() and fp_of(ln.split(" ", 1)[1] if not ln.startswith("ssh-") else ln) != choke["ref"]] \
                    if any(ln.strip() for ln in lines) else []
                if len(keep) != len([ln for ln in lines if ln.strip()]):
                    trust(m, account, keep)
            held = on(m, "for f in /root/.ssh/id_* /home/*/.ssh/id_*; do case $f in *.pub) continue;; esac; [ -f \"$f.pub\" ] && "
                         "echo \"$f $(ssh-keygen -lf \"$f.pub\" | cut -d' ' -f2)\"; done; true")
            for ln in held.splitlines():
                if len(ln.split()) == 2 and ln.split()[1] == choke["ref"]:
                    on(m, f"rm -f {ln.split()[0]} {ln.split()[0]}.pub")
    for m in MACHINES:
        srv.report(m)
    after_out = srv.paths()
    after = {srv.name[h] for h in reached_hosts(after_out)}
    gone = before - after
    walked, _ = walk_by_ssh(srv)
    check("4b the top key choke point, done for real, cuts exactly the machines it said, and ssh agrees",
          len(gone) == choke["cuts"] and {srv.name[h] for h in choke["hosts"]} == gone and not (gone & set(walked)),
          choke=choke["action"], predicted=sorted(srv.name[h] for h in choke["hosts"]), gone=sorted(gone), ssh_walk_after=sorted(walked))


def reached_hosts(out):
    return {h for h, v in out["hosts"].items() if v["entry"]} | {r["host"] for c in out["chains"] for r in c["reach"]}


CASES = [  # (name, authorized_keys line options or None, sshd lines, edge grade expected or None, what real ssh does)
    ("plain", "", "", "reasonable", "in"),
    ("from= allowing web-1", 'from="10.89.7.0/24"', "", "reasonable", "in"),
    ("from= excluding web-1", 'from="192.168.0.0/16"', "", None, "refused"),
    ("command= forced", 'command="echo forced-only"', "", "unverified", "forced"),
    ("restrict", "restrict", "", "reasonable", "in"),
    ("PermitRootLogin no", "", "PermitRootLogin no", None, "refused"),
    ("PermitRootLogin prohibit-password", "", "PermitRootLogin prohibit-password", "reasonable", "in"),
    ("AllowUsers without root", "", "AllowUsers deploy", None, "refused"),
    ("DenyUsers root", "", "DenyUsers root", None, "refused"),
    ("PubkeyAuthentication no", "", "PubkeyAuthentication no", None, "refused"),
]


def edge_cases(srv, keys):
    """Criterion 2: each case's edge and grade against a real sign-in from web-1 with the same key."""
    results, bad = [], []
    k = keys["K_CASE"]
    for name, opts, conf, grade, real in CASES:
        trust("app-1", "root", [(opts + " " + k).strip()])
        put("app-1", "/etc/ssh/sshd_config.d/50-case.conf", (conf + "\n").encode(), "644")
        on("app-1", "systemctl restart ssh; sleep 1")
        srv.report("app-1")
        e = srv.edge(srv.paths(), "web-1", "app-1", fp_of(k))
        o = ssh("web-1", "/root/.ssh/id_case", "root", "app-1")
        did = "in" if MARK in o else "forced" if "forced-only" in o else "refused"
        row = {"case": name, "edge": e and e["grade"], "want_edge": grade, "ssh": did, "want_ssh": real, "because": e and e["ways"][0]["because"]}
        results.append(row)
        if (e and e["grade"]) != grade or did != real:
            bad.append(row)
    # a key with a passphrase: unverified, refused without it, in with it
    trust("app-1", "root", [keys["K_PASS"]])
    put("app-1", "/etc/ssh/sshd_config.d/50-case.conf", b"\n", "644")
    on("app-1", "systemctl restart ssh; sleep 1")
    srv.report("app-1")
    e = srv.edge(srv.paths(), "web-1", "app-1", fp_of(keys["K_PASS"]))
    without = MARK in ssh("web-1", "/root/.ssh/id_pass", "root", "app-1")
    on("web-1", "cp /root/.ssh/id_pass /root/.ssh/opened && ssh-keygen -q -p -P labpass -N '' -f /root/.ssh/opened >/dev/null")
    with_it = MARK in ssh("web-1", "/root/.ssh/opened", "root", "app-1")
    on("web-1", "rm -f /root/.ssh/opened")
    row = {"case": "a key with a passphrase", "edge": e and e["grade"], "without": without, "with": with_it}
    results.append(row)
    if not (e and e["grade"] == "unverified" and not without and with_it):
        bad.append(row)
    # seen connected: confirmed
    trust("app-1", "root", [k])
    on("web-1", f"(ssh {SSH_OPTS} -i /root/.ssh/id_case root@{MACHINES['app-1'][1]} 'sleep 90' >/dev/null 2>&1 &); sleep 2")
    srv.report("app-1")
    srv.report("web-1")
    e = srv.edge(srv.paths(), "web-1", "app-1", fp_of(k))
    row = {"case": "seen connected", "edge": e and e["grade"]}
    results.append(row)
    if not (e and e["grade"] == "confirmed"):
        bad.append(row)
    # the key removed after a report, and sshd stopped
    trust("app-1", "root", [])
    srv.report("app-1")
    e = srv.edge(srv.paths(), "web-1", "app-1", fp_of(k))
    row = {"case": "key removed", "edge": e and e["grade"], "ssh": MARK in ssh("web-1", "/root/.ssh/id_case", "root", "app-1")}
    results.append(row)
    if e or row["ssh"]:
        bad.append(row)
    trust("app-1", "root", [k])
    on("app-1", "systemctl stop ssh ssh.socket 2>/dev/null; true")
    srv.report("app-1")
    e = srv.edge(srv.paths(), "web-1", "app-1", fp_of(k))
    row = {"case": "sshd stopped", "edge": e and e["grade"], "ssh": MARK in ssh("web-1", "/root/.ssh/id_case", "root", "app-1")}
    results.append(row)
    if e or row["ssh"]:
        bad.append(row)
    on("app-1", "systemctl start ssh; true")
    check(f"2 every key edge ({len(results)} cases) agrees with a real ssh sign-in", not bad, cases=results, wrong=bad)


def settings_check(srv):
    """Criterion 5: each of the six checks opens where planted and closes when fixed for real; stock opens none."""
    from sqlalchemy import select

    from nimstead.db import Finding

    def open_checks():
        with srv.Session() as s:
            return {(srv.name[f.asset_id], f.package) for f in s.scalars(select(Finding).where(Finding.ecosystem == "LinuxConfig", Finding.status == "open"))}
    plants = [("db-1", "ssh-root-password", "echo 'root:LabOnly-pw1' | chpasswd && printf 'PermitRootLogin yes\\nPasswordAuthentication yes\\n' > /etc/ssh/sshd_config.d/40-lab.conf && systemctl restart sshd",
               "sed -i 's/^root:[^:]*:/root:!:/' /etc/shadow && rm -f /etc/ssh/sshd_config.d/40-lab.conf && systemctl restart sshd"),
              ("edge-1", "ssh-empty-passwords", "adduser -D -s /bin/sh guest; passwd -d guest >/dev/null; printf 'PermitEmptyPasswords yes\\nPasswordAuthentication yes\\n' >> /etc/ssh/sshd_config && kill -HUP $(pidof sshd | tr ' ' '\\n' | tail -1)",
               "deluser guest; sed -i '/^PermitEmptyPasswords yes/d' /etc/ssh/sshd_config; kill -HUP $(pidof sshd | tr ' ' '\\n' | tail -1)"),
              ("edge-1", "root-equivalent-group", "addgroup -S docker 2>/dev/null; adduser -D ops 2>/dev/null; addgroup ops docker", "delgroup ops docker"),
              ("build-1", "writable-root-run", "echo '0 5 * * * root true' > /etc/cron.d/lab && chmod 666 /etc/cron.d/lab", "chmod 644 /etc/cron.d/lab"),
              ("edge-1", "shadow-readable", "chmod 644 /etc/shadow", "chmod 640 /etc/shadow")]
    already = open_checks()
    stock = {x for x in already if x[1] != "sudo-nopasswd-all"}  # web-1's sudo rule is the planted way up
    check("5a stock configurations open no settings finding (web-1's planted sudo rule aside)", not stock, open=sorted(already))
    opened, closed = {}, {}
    for m, chk, do, undo in plants:
        on(m, do)
        srv.report(m)
        opened[chk] = (m, chk) in open_checks()
        on(m, undo)
        srv.report(m)
        closed[chk] = (m, chk) not in open_checks()
    opened["sudo-nopasswd-all"] = ("web-1", "sudo-nopasswd-all") in already
    check("5b each check opens where planted and closes when fixed for real", all(opened.values()) and all(closed.values()), opened=opened, closed=closed)


def secrets_check(srv, keys):
    """Criterion 6: nothing secret in what the server stored or the evidence pack; hostile files named, not read."""
    from sqlalchemy import select

    from nimstead.db import AssetAccess, ScanRecord
    priv = on("web-1", "sed '1d;$d' /root/.ssh/id_ed25519 | tr -d '\\n'").strip()
    needles = {"private key body": priv[20:80], "key comment": COMMENT, "aws file": AWS_MARK, "forced command": "forced-only", "passphrase": "labpass"}
    with srv.Session() as s:
        stored = json.dumps([r.data for r in s.scalars(select(AssetAccess))]) + json.dumps([r.inventory for r in s.scalars(select(ScanRecord))], default=str)
    pack = srv.c.get("/api/evidence/pack").content.decode("latin-1")
    found = {k: [w for w, t in (("stored", stored), ("evidence pack", pack)) if v and v in t] for k, v in needles.items()}
    acc = (srv.report("web-1").get("access") or {})
    hostile = {"link": "a link, not read" in (acc.get("problem") or ""), "fifo": "not a regular file" in (acc.get("problem") or ""),
               "link not held": not any(h["path"].endswith("id_link") for h in acc.get("held", []))}
    check("6 nothing secret leaves the machine, and hostile files are named, never read", not any(found.values()) and all(hostile.values()),
          found=found, hostile=hostile, problem=acc.get("problem"))


def prove():
    keys = plant()
    srv = Server()
    for _ in range(2):  # a second round: each machine's report then sees the others' reports stored
        invs = {m: srv.report(m) for m in MACHINES}
    note("reports", **{m: {"access": (i.get("access") or {}).get("state"), "runtime": (i.get("runtime") or {}).get("state"),
                           "held": len((i.get("access") or {}).get("held", [])), "trusted": len((i.get("access") or {}).get("trusted", []))}
                       for m, i in invs.items()})
    facts_check(srv, invs)
    privilege_check(srv, keys)
    chain_check(srv, keys)
    edge_cases(srv, keys)
    settings_check(srv)
    secrets_check(srv, keys)


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
        else:
            prove()
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
