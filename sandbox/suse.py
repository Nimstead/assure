"""zypper + snapper remediation on a REAL openSUSE Leap 16.0 host in a DISPOSABLE VirtualBox VM.

Run from api/:  uv run python ../sandbox/suse.py [--keep]
- Boots openSUSE's official Minimal VM image (sha256-checked), configured on first boot by a Combustion script
  (SSH key only). The disk lives in the VM's own folder and is deleted with it; only nimstead-sbx-suse-* VMs are touched.
- Downgrades a package to an older build from the official repos so it is genuinely vulnerable, syncs real OSV data,
  then: a real fix that the next inventory must prove fixed, and a fix whose health check fails, which must be undone
  by `snapper undochange` -- package files, rpm database AND what the install scripts changed outside the package.
Writes a summary to sandbox/last_run_suse.json.
"""

import functools
import hashlib
import io
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sandbox"))
from winvm import vbox  # noqa: E402

from nimstead.versions import rpm_cmp  # noqa: E402

PREFIX = "nimstead-sbx-suse-"
NAME = PREFIX + secrets.token_hex(3)
IMAGE = "Leap-16.0-Minimal-VM.x86_64-VMware.vmdk"
IMAGE_URL = "https://download.opensuse.org/distribution/leap/16.0/appliances/" + IMAGE
IMAGE_SHA256 = "4cc06fe08dbd4c798a377f345b007022cd880caaf3388c9c96f789a55d456f12"
CACHE = Path(tempfile.gettempdir()) / "nimstead-sbx-cache"
TMP = Path(tempfile.mkdtemp(prefix=PREFIX))
os.environ.update(NIMSTEAD_SECURE_COOKIES="0", NIMSTEAD_INVENTORY_MIN_SECONDS="0", NIMSTEAD_SIGNING_KEY_FILE=str(TMP / "signing.pem"))
log: list[dict] = []


def note(step, **kw):
    log.append({"step": step, **kw})
    print(f"[{time.strftime('%H:%M:%S')}] {step}", json.dumps(kw, default=str)[:400] if kw else "", flush=True)


def image() -> Path:
    """The official image, downloaded once into a cache and verified against the published sha256 every run."""
    CACHE.mkdir(exist_ok=True)
    path = CACHE / IMAGE
    if not path.exists():
        note("downloading image", url=IMAGE_URL)
        urllib.request.urlretrieve(IMAGE_URL, str(path) + ".part")
        os.replace(str(path) + ".part", path)
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 22):
            h.update(chunk)
    if h.hexdigest() != IMAGE_SHA256:
        path.unlink()
        raise RuntimeError("image checksum mismatch (deleted; rerun to download again)")
    return path


def combustion_disk(pubkey: str) -> Path:
    """An ext4 filesystem labelled "combustion" holding combustion/script, built in a throwaway WSL distro."""
    script = ("#!/bin/bash\nset -e\nmkdir -p /root/.ssh\n"
              f"echo '{pubkey}' >> /root/.ssh/authorized_keys\nchmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys\n"
              "systemctl enable sshd.service\n"
              "systemctl mask jeos-firstboot.service || true\n")  # the interactive first-boot wizard would block the console
    mk = PREFIX + "mk-" + secrets.token_hex(3)
    try:
        p = subprocess.run(["wsl", "--install", "Debian", "--name", mk, "--location", str(TMP / "mk"), "--no-launch"],
                           capture_output=True, timeout=1800)
        if p.returncode != 0:
            raise RuntimeError((p.stdout + p.stderr).decode("utf-16-le", errors="replace"))
        sh = "set -e; mkdir -p /tmp/c/combustion; cat > /tmp/c/combustion/script; chmod 755 /tmp/c/combustion/script; " \
             "truncate -s 16M /tmp/c.img; mkfs.ext4 -q -L combustion -d /tmp/c /tmp/c.img; cat /tmp/c.img"
        p = subprocess.run(["wsl", "-d", mk, "-u", "root", "--", "sh", "-c", sh], input=script.encode(), capture_output=True, timeout=600)
        if p.returncode != 0 or len(p.stdout) != 16 << 20:
            raise RuntimeError(f"building combustion disk failed: {p.stderr.decode(errors='replace')[-800:]}")
        (TMP / "combustion.img").write_bytes(p.stdout)
    finally:
        subprocess.run(["wsl", "--unregister", mk], capture_output=True)
    vdi = TMP / "combustion.vdi"
    vbox("convertfromraw", str(TMP / "combustion.img"), str(vdi), "--format", "VDI")
    return vdi


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class VM:
    def __init__(self):
        self.port = free_port()
        self.key = TMP / "id_ed25519"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.key)], check=True)

    def create(self):
        assert NAME.startswith(PREFIX)
        disk = TMP / "vm" / IMAGE
        disk.parent.mkdir()
        shutil.copyfile(image(), disk)
        cdisk = combustion_disk(Path(str(self.key) + ".pub").read_text().strip())
        vbox("createvm", "--name", NAME, "--ostype", "OpenSUSE_Leap_64", "--basefolder", str(TMP / "vm"), "--register")
        # one vCPU: under Hyper-V's NEM backend (this host) multi-vCPU Linux guests stall in the initrd waiting for disks
        vbox("modifyvm", NAME, "--memory", "2048", "--cpus", "1", "--nic1", "nat", "--natpf1", f"ssh,tcp,127.0.0.1,{self.port},,22")
        # IDE, as the image's own .vmx specifies: its initrd has no SATA/SCSI driver and waits forever for the root disk
        vbox("storagectl", NAME, "--name", "IDE", "--add", "ide", "--controller", "PIIX4")
        vbox("storageattach", NAME, "--storagectl", "IDE", "--port", "0", "--device", "0", "--type", "hdd", "--medium", str(disk))
        vbox("storageattach", NAME, "--storagectl", "IDE", "--port", "0", "--device", "1", "--type", "hdd", "--medium", str(cdisk))
        vbox("startvm", NAME, "--type", "headless")
        note("VM booting", name=NAME, ssh_port=self.port)
        end = time.time() + 15 * 60
        while time.time() < end:
            try:
                if self.sh("echo up", check=False, timeout=30)[0] == 0:
                    return
            except subprocess.TimeoutExpired:
                pass
            time.sleep(10)
        raise RuntimeError("VM never answered on SSH")

    def sh(self, script: str, input: bytes | None = None, check=True, timeout=1800) -> tuple[int, str]:
        """Runs `script` as root. With `input`, the script is a command line and input goes to its stdin."""
        cmd = ["ssh", "-i", str(self.key), "-p", str(self.port), "-o", "StrictHostKeyChecking=no", "-o", f"UserKnownHostsFile={TMP / 'known_hosts'}",
               "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=10", "-o", "BatchMode=yes", "root@127.0.0.1"]
        cmd += [script] if input is not None else ["sh", "-s"]
        p = subprocess.run(cmd, input=input if input is not None else script.encode(), capture_output=True, timeout=timeout)
        out = p.stdout.decode(errors="replace")
        self.last_stderr = p.stderr.decode(errors="replace")
        if check and p.returncode != 0:
            raise RuntimeError(f"VM command failed ({p.returncode}): {script[:200]}\n{out[-1500:]}\n{self.last_stderr[-1500:]}")
        return p.returncode, out

    def agent(self, *args, input=None, check=True):
        return self.sh("python3 /opt/nimstead/agent.py " + " ".join(args), input=input or b"", check=check)

    def destroy(self):
        assert NAME.startswith(PREFIX)
        vbox("controlvm", NAME, "poweroff", check=False)
        time.sleep(3)
        vbox("unregistervm", NAME, "--delete", check=False)
        note("VM destroyed", name=NAME)


def rpm_versions(vm, names) -> dict:
    _, out = vm.sh("rpm -q --qf '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}\\n' " + " ".join(names) + " || true")
    return dict(ln.split(" ", 1) for ln in out.splitlines() if " " in ln and "not installed" not in ln)


def make_vulnerable(vm, advisories) -> list[str]:
    """Install the oldest build the official repos still carry of installed packages that OSV says were since fixed."""
    _, inst = vm.sh("rpm -qa --qf '%{NAME}\\n'")
    installed = set(inst.split())
    downgraded = []
    for pkg in sorted({p for p in advisories if p in installed}):
        _, out = vm.sh(f"zypper --non-interactive --xmlout search -s --match-exact {pkg}", check=False)
        try:
            tree = ET.fromstring(out[out.index("<stream"):])  # noqa: S314 — zypper's own output in our disposable VM
        except ValueError:
            continue
        eds = sorted({s.get("edition") for s in tree.iter("solvable") if s.get("kind", "package") == "package" and s.get("arch") != "src"})
        if len(eds) < 2:
            continue
        oldest = min(eds, key=functools.cmp_to_key(rpm_cmp))
        rc, _ = vm.sh(f"zypper --non-interactive install --oldpackage --no-recommends --force-resolution '{pkg}={oldest}'", check=False)
        if rc == 0:
            downgraded.append(f"{pkg}={oldest}")
        if len(downgraded) >= 4:
            break
    return downgraded


def main(keep=False):
    from fastapi.testclient import TestClient

    from nimstead import feeds
    from nimstead.app import create_app
    from nimstead.db import Advisory, make_sessionmaker
    from nimstead.verify_pack import verify

    db = f"sqlite:///{(TMP / 'nimstead.db').as_posix()}"
    c = TestClient(create_app(db))
    c.post("/api/auth/signup", json={"email": "sbx@example.com", "password": "sandbox-only-password", "org_name": "Sandbox"})
    vm = VM()
    try:
        vm.create()
        _, osr = vm.sh("cat /etc/os-release; findmnt -no FSTYPE /; snapper -c root list --columns number 2>&1 | tail -3")
        note("VM up", os_release=[ln for ln in osr.splitlines() if ln.startswith("PRETTY_NAME")], tail=osr.splitlines()[-4:])
        if vm.sh("snapper -c root list", check=False)[0] != 0:
            raise RuntimeError("this image has no snapper root config; the proof needs btrfs + snapper as shipped")
        vm.sh("zypper --non-interactive --gpg-auto-import-keys refresh >/dev/null && "
              "(command -v python3 || zypper --non-interactive install --no-recommends python3) >/dev/null")
        vm.sh("mkdir -p /opt/nimstead && cat > /opt/nimstead/agent.py", input=(ROOT / "agent" / "nimstead_agent.py").read_bytes())
        eco = json.loads(vm.agent("collect")[1])["ecosystem"]
        with make_sessionmaker(db)() as s:
            t = time.time()
            note("feeds synced", ecosystem=eco, kev=feeds.sync_kev(s), epss=feeds.sync_epss(s),
                 osv=feeds.sync_osv(s, [eco.split(":")[0]], only={eco}), seconds=round(time.time() - t))
            from sqlalchemy import select
            advised = set(s.scalars(select(Advisory.package).where(Advisory.ecosystem == eco)))
        note("made vulnerable with older official builds", downgraded=make_vulnerable(vm, advised))

        inv = json.loads(vm.agent("collect")[1])
        token = c.post("/api/enroll-tokens", json={"sandbox": True}).json()["token"]
        a = c.post("/api/agent/enroll", json={"token": token, "hostname": NAME, "os_name": inv["os_name"], "ecosystem": eco}).json()
        h = {"Authorization": f"Bearer {a['agent_key']}"}

        def report():
            r = c.post("/api/agent/inventory", json=json.loads(vm.agent("collect")[1]), headers=h)
            assert r.status_code == 200, r.text
            return r.json()

        note("first inventory", **report())
        actions = c.get("/api/summary").json()["top_actions"]
        note("findings", top_actions=[x["package"] for x in actions])
        assert actions, "no fixable findings; cannot exercise remediation"

        def attempt(pkg, health_units=None, include=()):
            c.patch(f"/api/assets/{a['asset_id']}", json={"health_units": health_units or []})
            r = c.post("/api/remediation/jobs", json={"asset_id": a["asset_id"], "ecosystem": eco, "package": pkg, "include": list(include)})
            if r.status_code != 201:
                return {"package": pkg, "planned": False, "detail": r.json().get("detail")}
            jid = r.json()["id"]
            assert c.post(f"/api/remediation/jobs/{jid}/approve").status_code == 200
            [job] = c.get("/api/agent/jobs", headers=h).json()
            rc, out = vm.agent("run-job", "--yes", input=json.dumps(job).encode(), check=False)
            lines = [ln for ln in out.splitlines() if ln.startswith("{")]
            if not lines:
                raise RuntimeError(f"agent run-job printed no result (rc {rc}): {vm.last_stderr[-2000:]}")
            res = json.loads(lines[-1])
            c.post(f"/api/agent/jobs/{jid}/report", json=res, headers=h)
            report()
            j = next(x for x in c.get("/api/remediation/jobs").json() if x["id"] == jid)
            return {"package": pkg, "outcome": res["outcome"], "status": j["status"], "error": j["error"], "job": job,
                    "steps": [f"{'ok ' if s['ok'] else 'FAIL'} {s['step']}" for s in res["steps"]]}

        def try_fix(act, **kw):
            r = attempt(act["package"], **kw)
            if r.get("status") == "aborted" and "would also change: " in (r.get("error") or ""):
                deps = [d.strip() for d in r["error"].split("would also change: ", 1)[1].split(";")[0].split(",") if d.strip()]
                r = attempt(act["package"], include=deps, **kw)
            note("remediation attempt", **{k: v for k, v in r.items() if k != "job"})
            return r

        # 1) a real fix, proven by the next inventory
        success = next((r for act in actions if (r := try_fix(act)).get("status") == "succeeded"), None)
        assert success, "no remediation succeeded"

        # 2) the fix breaks a service -> snapper undoes the whole change, including install-script side effects
        rollback = None
        for act in [x for x in c.get("/api/summary").json()["top_actions"] if x["package"] != success["package"]]:
            names = [p["name"] for p in json.loads(vm.agent("collect")[1])["packages"] if p["source"] == act["package"]]
            if not names:
                continue
            before = rpm_versions(vm, names)
            name = act["package"] if act["package"] in before else next(iter(before))
            ver = before[name]
            # side-effect witnesses: files install scripts rewrite outside any package's own file list
            witnesses = "/etc/ld.so.cache /etc/nimstead-canary-before"
            vm.sh("date > /etc/nimstead-canary-before")
            _, sums_before = vm.sh(f"sha256sum {witnesses}")
            vm.sh("cat > /opt/nimstead/canary.sh", input=(
                f"while [ \"$(rpm -q --qf '%{{EPOCHNUM}}:%{{VERSION}}-%{{RELEASE}}' {name})\" = \"{ver}\" ]; do sleep 1; done; exit 1\n").encode())
            vm.sh("cat > /etc/systemd/system/nimstead-canary.service && systemctl daemon-reload && systemctl start nimstead-canary.service",
                  input=b"[Unit]\nStartLimitIntervalSec=0\n[Service]\nExecStart=/bin/sh /opt/nimstead/canary.sh\n")  # no restart: once the version changes it stays failed
            r = try_fix(act, health_units=["nimstead-canary.service"])
            if r.get("outcome") != "rolled_back":
                continue
            _, sums_after = vm.sh(f"sha256sum {witnesses}")
            _, snaps = vm.sh("snapper -c root list --columns number,type,pre-number,description | tail -4")
            pre, post = None, None
            for ln in snaps.splitlines():
                cols = [x.strip() for x in ln.split("|")]
                if len(cols) >= 4 and cols[3].startswith("nimstead job") and cols[1] == "pre":
                    pre = cols[0]
                if len(cols) >= 4 and cols[1] == "post" and cols[2] == pre:
                    post = cols[0]
            _, changed = vm.sh(f"snapper -c root status {pre}..{post} | head -400", check=False) if pre and post else (0, "")
            changed_paths = [ln.split(None, 1)[1] for ln in changed.splitlines() if " " in ln]
            outside = [p for p in changed_paths if not p.startswith(("/usr/lib/sysimage/rpm", "/usr/lib64/", "/usr/lib/", "/usr/share/doc"))]
            after = rpm_versions(vm, names)
            rollback = {**{k: v for k, v in r.items() if k != "job"}, "versions_restored": after == before, "before": before, "after": after,
                        "snapper_pair": f"{pre}..{post}", "files_changed_by_upgrade": len(changed_paths),
                        "changed_outside_package_libs": outside[:20], "witness_files_restored": sums_before == sums_after}
            note("rollback attempt", **rollback)
            break
        assert rollback and rollback["versions_restored"], "snapper rollback scenario did not restore the packages"

        z = zipfile.ZipFile(io.BytesIO(c.get("/api/evidence/pack", params={"days": 1}).content))
        fp = c.get("/api/evidence/public-key").json()["fingerprint_sha256"]
        problems = verify(z.read("pack.json"), z.read("pack.sig").decode(), z.read("public_key.pem"), fp)
        note("evidence pack", problems=problems)
        assert not problems
        note("RESULT: PASS")
        return 0
    except Exception as e:
        note("RESULT: FAIL", error=f"{type(e).__name__}: {e}"[:2000])
        return 1
    finally:
        if not keep:
            vm.destroy()
            shutil.rmtree(TMP, ignore_errors=True)
        else:
            note("kept", name=NAME, ssh=f"ssh -i {vm.key} -p {vm.port} root@127.0.0.1")
        (ROOT / "sandbox" / "last_run_suse.json").write_text(json.dumps(log, indent=2, default=str))


if __name__ == "__main__":
    sys.exit(main(keep="--keep" in sys.argv))
