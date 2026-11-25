"""Real-host proof of runtime (tasks/spec-runtime.md success criteria 1-7, DECISIONS 161-163) in a DISPOSABLE WSL distro.

Run from api/:  uv run python ../sandbox/runtime.py [--distro Debian|AlmaLinux-9|alpine-3.21.0] [--keep]

A fresh distro named nimstead-sbx-rt-<random> (systemd on, except Alpine) runs nginx, OpenSSH, cron and, where packaged,
PostgreSQL on loopback. The real agent reads what runs; the distribution's own tools are the oracles:
  1. loaded packages per program = every file each process maps, owned per `dpkg -S` / `rpm -qf` / `apk info --who-owns`
  2. listening addresses per program = `ss -H -ltnup`
  3. after a real upgrade of a library a service has loaded: programs running a replaced copy = lsof's deleted package files,
     and `needrestart -b` / `needs-restarting -s` for services; the upgraded findings stay open until the restart
  4. rank: listening +15 in the reasons; "not loaded" x0.75 once seven days of complete reads are backdated (said so)
  5. a real fix job restarts the services that ran the old copy; one whose new version breaks a service rolls back and
     restarts it on the restored version; a program it won't restart (or no systemd) leaves the job waiting until a restart
  6. hostile processes (crafted names, a "(deleted)" file name with a newline, 2,000 processes, 60,000 descriptors, a secret
     in a command line and an environment) change nothing but what they should
  7. the read's time with those 2,000 extra processes
The API runs in-process on a throwaway SQLite DB with real OSV/KEV/EPSS data. The distro is unregistered at the end unless
--keep. Writes sandbox/last_run_runtime_<distro>.json.
"""

import io
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "nimstead-sbx-"
NAME = PREFIX + "rt-" + secrets.token_hex(3)
DISTRO = sys.argv[sys.argv.index("--distro") + 1] if "--distro" in sys.argv else "Debian"
ALPINE, RPM = DISTRO.startswith("alpine-"), DISTRO.startswith(("AlmaLinux", "Rocky"))
MGR = "apk" if ALPINE else "rpm" if RPM else "dpkg"
TMP = Path(tempfile.mkdtemp(prefix="nimstead-rt-"))
SECRET = "rt-secret-" + secrets.token_hex(6)
os.environ.update(NIMSTEAD_SECURE_COOKIES="0", NIMSTEAD_INVENTORY_MIN_SECONDS="0", NIMSTEAD_SIGNING_KEY_FILE=str(TMP / "signing.pem"))

from fastapi.testclient import TestClient  # noqa: E402
from signin import signup  # noqa: E402
from sqlalchemy import select  # noqa: E402

from nimstead import feeds  # noqa: E402
from nimstead.app import create_app  # noqa: E402
from nimstead.db import Asset, AssetRuntime, Finding, make_sessionmaker, now  # noqa: E402
from nimstead.scan import rescan  # noqa: E402
from nimstead.verify_pack import verify  # noqa: E402

log: list[dict] = []
checks: dict[str, str] = {}


def note(step, **kw):
    log.append({"step": step, **kw})
    print(f"[{time.strftime('%H:%M:%S')}] {step}", json.dumps(kw, default=str)[:400] if kw else "", flush=True)


def check(name, ok, **kw):
    checks[name] = "PASS" if ok else "FAIL"
    note(f"CHECK {name}: {'PASS' if ok else 'FAIL'}", **kw)


def wsl(cmd, input=None, check=True, timeout=1800):
    assert NAME.startswith(PREFIX)  # never a command in any other distro
    p = subprocess.run(["wsl", "-d", NAME, "-u", "root", "--exec", "sh", "-c", cmd], input=input, capture_output=True, timeout=timeout)
    out = p.stdout.decode(errors="replace")
    if check and p.returncode != 0:
        raise RuntimeError(f"sandbox command failed ({p.returncode}): {cmd}\n{out[-2000:]}\n{p.stderr.decode(errors='replace')[-2000:]}")
    return p.returncode, out


def create():
    note("creating sandbox distro", name=NAME, distro=DISTRO)
    if ALPINE:
        import hashlib
        import urllib.request
        v = DISTRO.removeprefix("alpine-")
        url = f"https://dl-cdn.alpinelinux.org/alpine/v{'.'.join(v.split('.')[:2])}/releases/x86_64/alpine-minirootfs-{v}-x86_64.tar.gz"
        tb = TMP / "rootfs.tar.gz"
        urllib.request.urlretrieve(url, tb)
        if hashlib.sha256(tb.read_bytes()).hexdigest() != urllib.request.urlopen(url + ".sha256").read().decode().split()[0]:
            raise RuntimeError("Alpine rootfs checksum mismatch")
        subprocess.run(["wsl", "--import", NAME, str(TMP / "distro"), str(tb)], check=True, capture_output=True, timeout=600)
    else:
        p = subprocess.run(["wsl", "--install", DISTRO, "--name", NAME, "--location", str(TMP / "distro"), "--no-launch"], capture_output=True, timeout=1800)
        if p.returncode != 0:
            raise RuntimeError("wsl --install failed: " + (p.stdout + p.stderr).decode("utf-16-le", errors="replace"))
        wsl("true")
        wsl("grep -q '^systemd=true' /etc/wsl.conf 2>/dev/null || printf '[boot]\\nsystemd=true\\n' >> /etc/wsl.conf")
        restart_distro()
    wsl("true")


def restart_distro():
    """WSL's restart of a distro: every process stops and systemd boots again (a machine restart, as far as programs go)."""
    subprocess.run(["wsl", "--terminate", NAME], capture_output=True)
    wsl("true")
    if not ALPINE:
        wsl("for i in $(seq 60); do systemctl is-system-running 2>/dev/null | grep -qE 'running|degraded' && break; sleep 1; done; true")


def destroy():
    assert NAME.startswith(PREFIX)
    names = subprocess.run(["wsl", "-l", "-q"], capture_output=True).stdout.decode("utf-16-le", errors="replace").split()
    if NAME in names:
        subprocess.run(["wsl", "--unregister", NAME], capture_output=True)
        note("sandbox destroyed", name=NAME)
    shutil.rmtree(TMP, ignore_errors=True)


def services():
    if ALPINE:
        wsl("apk add -q python3 nginx openssh iproute2 lsof >/dev/null && ssh-keygen -A >/dev/null && mkdir -p /run/nginx && "
            "(/usr/sbin/sshd; nginx; true)")
    elif RPM:
        wsl("dnf -q -y install python3 nginx openssh-server postgresql-server cronie iproute lsof dnf-utils >/dev/null && "
            "(postgresql-setup --initdb >/dev/null 2>&1; true) && systemctl enable --now nginx sshd postgresql crond >/dev/null 2>&1; true")
    else:
        wsl("apt-get update -qq && DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1 apt-get install -y -qq python3-minimal nginx openssh-server "
            "postgresql cron iproute2 lsof needrestart >/dev/null && mkdir -p /etc/needrestart/conf.d && "
            "echo \"\\$nrconf{restart} = 'l';\" > /etc/needrestart/conf.d/zz-nimstead-list-only.conf && "
            "systemctl enable --now nginx ssh postgresql cron >/dev/null 2>&1; true")
    wsl("sleep 3")
    wsl("mkdir -p /opt/nimstead && cat > /opt/nimstead/agent.py", input=(ROOT / "agent" / "nimstead_agent.py").read_bytes())
    wsl("cat > /opt/nimstead/oracle.py", input=ORACLE.encode())
    _, ss = wsl("ss -H -ltnup", check=False)
    note("services up", listening=sorted({ln.split()[4] for ln in ss.splitlines() if len(ln.split()) > 4}))


# The oracle runs inside the distro, apart from the agent: each process's mapped files from /proc/<pid>/maps, each owned per
# the distribution's own query tool; programs named by `ps -o unit=` (a system service) or the process's own name; listening
# addresses from ss; replaced copies from lsof's deleted entries owned by a package.
ORACLE = r'''
import json, os, re, subprocess, sys
mgr = sys.argv[1]
me, st = os.getpid(), os.stat("/proc/self/root")
own = (st.st_dev, st.st_ino)
name_bad = re.compile(r"[^A-Za-z0-9._@:+() -]")
units = {}
try:
    for ln in subprocess.run(["ps", "-eo", "pid=,unit="], capture_output=True, text=True).stdout.splitlines():
        f = ln.split()
        if len(f) == 2 and f[1].endswith(".service") and not f[1].startswith("user@"):
            units[f[0]] = f[1]
except OSError:
    pass
procs = {}
for p in os.listdir("/proc"):
    if not p.isdigit() or int(p) == me or int(p) == os.getppid():
        continue
    d = "/proc/" + p
    try:
        s = os.stat(d + "/root")
        if (s.st_dev, s.st_ino) != own:
            continue
        exe = os.readlink(d + "/exe")
        maps = open(d + "/maps", errors="replace").read()
        comm = open(d + "/comm", errors="replace").read().strip()
        cg = open(d + "/cgroup", errors="replace").read()
    except OSError:
        continue
    if "nimstead" in cg:
        continue
    mapped, gone = set(), set()
    for ln in maps.splitlines():
        f = ln.split(None, 5)
        if len(f) == 6 and f[4] != "0" and f[5].startswith("/"):
            (gone if f[5].endswith(" (deleted)") else mapped).add(re.sub(r";[0-9a-f]{8,}$", "", f[5].removesuffix(" (deleted)")))
    (gone if exe.endswith(" (deleted)") else mapped).add(exe.removesuffix(" (deleted)"))
    procs[p] = {"name": units.get(p) or (name_bad.sub("?", comm)[:64] or "?"), "mapped": mapped, "gone": gone}
owners = {}
def owner(path):
    if path in owners:
        return owners[path]
    if mgr == "dpkg":
        r = subprocess.run(["dpkg", "-S", path], capture_output=True, text=True)
        out = {x.strip().split(":")[0] for ln in r.stdout.splitlines() if not ln.startswith("diversion") and ": " in ln for x in ln.rsplit(": ", 1)[0].split(",")}
    elif mgr == "rpm":
        r = subprocess.run(["rpm", "-qf", "--qf", "%{NAME}\n", path], capture_output=True, text=True)
        out = {ln.strip() for ln in r.stdout.splitlines() if ln.strip() and "not owned" not in ln}
    else:
        r = subprocess.run(["apk", "info", "--who-owns", path], capture_output=True, text=True)
        out = {m.group(1) for m in re.finditer(r"is owned by (.+)-[^-]+-r\d+", r.stdout)}
    owners[path] = sorted(out)
    return owners[path]
listen = {}
for ln in subprocess.run(["ss", "-H", "-ltnup"], capture_output=True, text=True).stdout.splitlines():
    f = ln.split()
    if len(f) < 7:
        continue
    host, port = f[4].rsplit(":", 1)
    where = host.split("%")[0] + ":" + port + "/" + f[0]
    for pid in re.findall(r"pid=(\d+)", " ".join(f[6:])):
        listen.setdefault(pid, set()).add(where)
programs = {}
for pid, pr in procs.items():
    g = programs.setdefault(pr["name"], {"pids": 0, "packages": set(), "replaced": set(), "listen": set(), "unowned": set(), "alias": {}})
    g["pids"] += 1
    g["listen"] |= listen.get(pid, set())
    for path in pr["mapped"] | pr["gone"]:
        o = owner(path)
        g["packages"] |= set(o)
        if pr["gone"] and path in pr["gone"]:
            g["replaced"] |= set(o)
        if not o and path in pr["gone"]:
            m = re.match(r"(.*\.so)((?:\.\d+)+)$", path)
            parts = m.group(2).split(".")[1:] if m else []
            for short in [m.group(1) + "".join("." + x for x in parts[:i]) for i in range(len(parts) - 1, 0, -1)]:
                if owner(short):
                    g.setdefault("renamed", {})[path] = owner(short)
                    break
        if not o:
            g["unowned"].add(path)
            for alias in ([path[4:]] if path.startswith("/usr/") else []):  # merged /usr, which dpkg -S may not resolve
                if owner(alias):
                    g["alias"][path] = owner(alias)
print(json.dumps({k: {"pids": v["pids"], "packages": sorted(v["packages"]), "replaced": sorted(v["replaced"]), "listen": sorted(v["listen"]),
                      "unowned": sorted(v["unowned"])[:30], "alias": v["alias"], "renamed": v.get("renamed", {})} for k, v in programs.items()}))
'''


def agent(*args, input=None, check=True):
    return wsl("python3 /opt/nimstead/agent.py " + " ".join(args), input=input, check=check)


def collect():
    inv = json.loads(agent("collect")[1])
    return inv, inv.get("runtime") or {}


PLUMBING = re.compile(r"^(Relay\(\d+\)|SessionLeader|init|init-systemd\(.*|init-watcher|sh|bash|login|\(sd-pam\)|ps|sleep|python3|systemd|agetty)$")


def compare(oracle, rt):
    """Each program's loaded packages and listening addresses, the agent's against the oracle's; every difference with its reason."""
    ours = {p["name"]: p for p in rt["programs"]}
    diffs = []
    for name in sorted(set(oracle) | set(ours)):
        o, a = oracle.get(name), ours.get(name)
        if o is None or a is None:
            why = "the harness's own or WSL's per-command processes (a new relay and shell per wsl.exe call)" if PLUMBING.match(name) else None
            diffs.append({"program": name, "only": "agent" if o is None else "oracle", "why": why})
            continue
        only_a, only_o = set(a["loads"]) - set(o["packages"]), set(o["packages"]) - set(a["loads"])
        aliased = {p for owners in o["alias"].values() for p in owners}
        for pkg in sorted(only_a):
            why = ("a merged-/usr path dpkg -S didn't resolve, owned under its other name" if pkg in aliased
                   else "the script an interpreter runs, or a jar a JVM holds open (the agent reads these; the oracle reads mappings only)")
            diffs.append({"program": name, "package": pkg, "only": "agent", "why": why if pkg in aliased or PLUMBING.match(name) else why + " (check)"})
        for pkg in sorted(only_o):
            diffs.append({"program": name, "package": pkg, "only": "oracle",
                          "why": "processes of it started or stopped between the two reads" if o["pids"] != a["count"] else None})
        net_a, net_o = set(a["listen"]), set(o["listen"])
        if net_a != net_o:
            diffs.append({"program": name, "listen_agent": sorted(net_a), "listen_oracle": sorted(net_o),
                          "why": "processes of it started or stopped between the two reads" if o["pids"] != a["count"] else None})
    return diffs


def main(keep=False):
    db = f"sqlite:///{(TMP / 'nimstead.db').as_posix()}"
    c = TestClient(create_app(db))
    signup(c, {"email": "rt@example.com", "password": "sandbox-only-password", "org_name": "Runtime"})
    Session = make_sessionmaker(db)
    try:
        create()
        services()
        inv, rt = collect()
        eco = inv["ecosystem"]
        note("collected", ecosystem=eco, packages=len(inv["packages"]), state=rt.get("state"), problem=rt.get("problem"),
             programs={p["name"]: {"loads": len(p["loads"]), "listen": p["listen"]} for p in rt.get("programs", [])})
        with Session() as s:
            t = time.time()
            note("feeds synced", kev=feeds.sync_kev(s), epss=feeds.sync_epss(s), osv=feeds.sync_osv(s, [eco.split(":")[0]], only={eco}), seconds=round(time.time() - t))
        token = c.post("/api/enroll-tokens", json={"sandbox": True}).json()["token"]
        a = c.post("/api/agent/enroll", json={"token": token, "hostname": NAME, "os_name": inv["os_name"], "ecosystem": eco}).json()
        h = {"Authorization": f"Bearer {a['agent_key']}"}

        def report(body=None):
            r = c.post("/api/agent/inventory", json=body or collect()[0], headers=h)
            assert r.status_code == 200, r.text
            return r.json()

        # 1-2: the read against the distribution's own tools
        _, out = wsl(f"python3 /opt/nimstead/oracle.py {MGR}")
        oracle = json.loads(out)
        inv, rt = collect()
        diffs = compare(oracle, rt)
        unexplained = [d for d in diffs if not d.get("why") or d["why"].endswith("(check)")]
        note("loaded and listening vs the oracle", programs=len(rt["programs"]), oracle_programs=len(oracle), differences=diffs)
        check("1 loaded packages equal the oracle's", not [d for d in unexplained if "listen_agent" not in d], unexplained=unexplained)
        check("2 listening addresses equal ss", not [d for d in unexplained if "listen_agent" in d])
        note("first report", **report(inv))

        by_source = {}
        for p in inv["packages"]:
            by_source.setdefault(p.get("source") or p["name"], []).append(p["name"])
        source_of = {b: s for s, bs in by_source.items() for b in bs}
        loaded_by = {}
        for p in rt["programs"]:
            for b in p["loads"]:
                loaded_by.setdefault(source_of.get(b, b), set()).add(p["name"])
        listening_progs = {p["name"] for p in rt["programs"] if any(not x.startswith(("127.", "[::1]")) for x in p["listen"])}

        # 4a: listening raises
        with Session() as s:
            fs = s.scalars(select(Finding).where(Finding.asset_id == a["asset_id"], Finding.status == "open")).all()
            states = {}
            for f in fs:
                states[f.runtime] = states.get(f.runtime, 0) + 1
            raised = [f for f in fs if f.runtime == "listening" and any(" listening on " in r for r in f.reasons)]
        note("findings by runtime state", states=states, listening_with_reason=len(raised),
             sample=[(f.package, f.vuln_id, f.score, f.reasons[:3]) for f in raised[:3]])
        check("4 a network listener's library is ranked with the reason", bool(raised) or not (loaded_by.keys() & {f.package for f in fs}),
              listening=len(raised))

        # candidates: a source a running program loaded, with an upgrade waiting in the repository and findings that upgrade fixes
        if ALPINE:
            _, up = wsl("apk update -q >/dev/null; apk version -l '<' 2>/dev/null | awk 'NR>1{print $1}' | sed -E 's/-[0-9][^-]*-r[0-9]+$//'", check=False)
        elif RPM:
            _, up = wsl("dnf -q check-update 2>/dev/null | awk 'NF==3{print $1}' | sed -E 's/\\.[^.]+$//'", check=False)
        else:
            _, up = wsl("apt list --upgradable 2>/dev/null | awk -F/ 'NR>1{print $1}'", check=False)
        upgradable = {ln.strip() for ln in up.splitlines() if ln.strip()}
        fixable = {f.package for f in fs if f.fixed_version}
        cands = sorted((s for s in loaded_by if s in fixable and any(b in upgradable for b in by_source.get(s, []))),
                       key=lambda s: (not (loaded_by[s] & listening_progs), s in ("glibc", "musl"), len(loaded_by[s])))
        note("upgrade candidates", candidates=[(s, sorted(loaded_by[s])[:6]) for s in cands], upgradable=len(upgradable))
        if not cands:
            raise RuntimeError("no running program loads a package that has an upgrade with fixes waiting; nothing to restart")

        # 3: a real upgrade with the programs running
        first = cands[0]
        bins = [b for b in by_source[first] if b in upgradable]
        open_before = {f.vuln_id for f in fs if f.package == first and f.fixed_version}
        if ALPINE:
            wsl(f"apk upgrade -q {' '.join(bins)}")
        elif RPM:
            wsl(f"dnf -q -y upgrade {' '.join(bins)}")
        else:
            wsl(f"DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1 apt-get install -y -qq --only-upgrade {' '.join(bins)} >/dev/null")
        _, out = wsl(f"python3 /opt/nimstead/oracle.py {MGR}")
        oracle = json.loads(out)
        inv, rt = collect()
        ours = {p["name"]: set(p["replaced"]) for p in rt["programs"] if p["replaced"]}
        theirs = {n: set(o["replaced"]) for n, o in oracle.items() if o["replaced"]}
        held_first = {n for n, r in ours.items() if set(by_source[first]) & r}
        if not ALPINE:
            tool = "needs-restarting -s" if RPM else "needrestart -b -r l"
            _, nr = wsl(f"{tool} 2>&1", check=False)
            nr_services = set(re.findall(r"([\w@.\\-]+\.service)", nr)) if RPM else set(re.findall(r"NEEDRESTART-SVC: (\S+)", nr))
        else:
            nr_services = set()
        units_ours = {n for n in ours if n.endswith(".service")}
        note("replaced copies after the upgrade", package=first, binaries=bins, agent=sorted((k, sorted(v)) for k, v in ours.items()),
             lsof_oracle=sorted((k, sorted(v)) for k, v in theirs.items()), distribution_tool=sorted(nr_services))
        gone_diffs = []
        for n in sorted(set(ours) | set(theirs)):
            a_, o_ = ours.get(n, set()), theirs.get(n, set())
            renamed = {p for owners in (oracle.get(n) or {}).get("renamed", {}).values() for p in owners}
            for pkg in sorted(a_ - o_):
                gone_diffs.append({"program": n, "package": pkg, "only": "agent",
                                   "why": "the upgrade renamed the file; the package's own shorter name for it is in its list" if pkg in renamed
                                   else "the harness's own or WSL's per-command processes" if PLUMBING.match(n) else None})
            for pkg in sorted(o_ - a_):
                gone_diffs.append({"program": n, "package": pkg, "only": "oracle", "why": "the harness's own or WSL's per-command processes" if PLUMBING.match(n) else None})
        note("replaced copies: agent vs lsof's deleted package files", differences=gone_diffs)
        check("3 programs running a replaced copy equal the deleted package files (oracle)", not [d for d in gone_diffs if not d["why"]],
              unexplained=[d for d in gone_diffs if not d["why"]])
        if not ALPINE:
            # needrestart's names for the system manager (PID 1) and users' managers, which the agent reports as the program "systemd"
            pseudo = {"systemd-manager", "systemd-user"} if "systemd" in ours else set()
            check("3 services running a replaced copy include every one the distribution's tool names",
                  nr_services - pseudo <= units_ours | {"nimstead-agent.service"}, only_tool=sorted(nr_services - units_ours),
                  only_agent=sorted(units_ours - nr_services), named_systemd_by_the_agent=sorted(pseudo & nr_services))
        res = report(inv)
        with Session() as s:
            held = s.scalars(select(Finding).where(Finding.asset_id == a["asset_id"], Finding.package == first, Finding.status == "open",
                                                   Finding.runtime == "restart")).all()
        note("report after the upgrade", **res, held=len(held), reason=held[0].reasons[-1] if held else None)
        check("3 upgraded findings stay open while the old copy runs", bool(held) and all(r.reasons[-1].startswith("Still open: the fixed version is installed, but")
                                                                                     for r in held), held=len(held), fixable_before=len(open_before))
        restart_programs(held_first)
        res = report()
        with Session() as s:
            still = s.scalars(select(Finding).where(Finding.asset_id == a["asset_id"], Finding.package == first, Finding.status == "open",
                                                    Finding.runtime == "restart")).all()
        note("report after the restart", restarted=sorted(held_first), **res, still_held=len(still), reason=still[0].reasons[-1] if still else None)
        if still:  # held by a program that isn't a service this harness restarts (the system manager, a session): restart the machine
            restart_distro() if not ALPINE else restart_programs({"nginx", "sshd"})
            if ALPINE:
                wsl("(/usr/sbin/sshd; mkdir -p /run/nginx; nginx; true)")
            more = report()
            res = {"resolved": res["resolved"] + more["resolved"], "open": more["open"]}
            with Session() as s:
                still = s.scalars(select(Finding).where(Finding.asset_id == a["asset_id"], Finding.package == first, Finding.status == "open",
                                                        Finding.runtime == "restart")).all()
            note("report after restarting the machine", **more, still_held=len(still))
        check("3 the restart closes them on the next report", not still and res["resolved"] >= len(held))

        # 4b: "not loaded" after seven days of complete reads (the history backdated here: the harness can't wait a week)
        with Session() as s:
            row = s.get(AssetRuntime, a["asset_id"])
            row.since = now() - timedelta(days=8)
            s.commit()
            rescan(s, s.get(Asset, a["asset_id"]), inventory_received=False)
            fs = s.scalars(select(Finding).where(Finding.asset_id == a["asset_id"], Finding.status == "open")).all()
            lowered = [f for f in fs if f.runtime == "not_loaded" and any(r.startswith("Not loaded by any long-running program") for r in f.reasons)]
            kev_lowered = [f for f in fs if f.kev and any(r.startswith("Not loaded") for r in f.reasons)]
        note("not loaded, seven days backdated", lowered=len(lowered), not_loaded=sum(f.runtime == "not_loaded" for f in fs),
             sample=[(f.package, f.vuln_id, f.score, f.reasons[-1][:80]) for f in lowered[:3]])
        check("4 a network flaw in native code nothing loads is lowered, never a KEV one", bool(lowered) and not kev_lowered,
              lowered=len(lowered), kev_lowered=len(kev_lowered))

        # 5: fixes that restart what ran the old copy
        if len(cands) > 1:
            try:
                fix_job(c, h, a, eco, cands[1], by_source, report, Session)
            except Exception as e:  # recorded; the remaining criteria still run
                check("5 fix jobs ran", False, error=str(e)[:2000])
        else:
            note("only one upgrade candidate: the fix-job scenarios need a second", candidates=cands)
            checks["5 fix jobs"] = "NOT RUN"

        # 6-7: hostile processes, and the read's cost with them running
        hostile(c, h, report)

        z = zipfile.ZipFile(io.BytesIO(c.get("/api/evidence/pack", params={"days": 1}).content))
        fp = c.get("/api/evidence/public-key").json()["fingerprint_sha256"]
        problems = verify(z.read("pack.json"), z.read("pack.sig").decode(), z.read("public_key.pem"), fp)
        check("evidence pack verifies", not problems, problems=problems)
        failed = [k for k, v in checks.items() if v == "FAIL"]
        note("RESULT: " + ("PASS" if not failed else "FAIL"), checks=checks)
        return 0 if not failed else 1
    except Exception as e:
        note("RESULT: FAIL", error=str(e)[:3000], checks=checks)
        return 1
    finally:
        if not keep:
            destroy()
        (ROOT / "sandbox" / f"last_run_runtime_{DISTRO.split('-')[0].lower()}.json").write_text(json.dumps(log, indent=2, default=str))


def restart_programs(names):
    for n in sorted(names):
        if n.endswith(".service"):
            wsl(f"systemctl restart -- '{n}'")
        elif n == "nginx":
            wsl("nginx -s stop; sleep 1; nginx")
        elif n == "sshd":
            wsl("kill $(cat /var/run/sshd.pid) 2>/dev/null; sleep 1; /usr/sbin/sshd")
    wsl("sleep 2")


def fix_job(c, h, a, eco, source, by_source, report, Session):
    """5: the agent's own fix job. First a service the new version breaks (the restart fails, the fix rolls back and the
    service runs again on the restored version), then the same fix for real (the services restart, the job succeeds)."""
    def run(health_units=None):
        if health_units is not None:
            c.patch(f"/api/assets/{a['asset_id']}", json={"health_units": health_units})
        r = c.post("/api/remediation/jobs", json={"asset_id": a["asset_id"], "ecosystem": eco, "package": source})
        assert r.status_code == 201, r.text
        planned = r.json()
        assert c.post(f"/api/remediation/jobs/{planned['id']}/approve").status_code == 200
        [job] = c.get("/api/agent/jobs", headers=h).json()
        rc, out = agent("run-job --yes", input=json.dumps(job).encode(), check=False)
        res = json.loads([ln for ln in out.splitlines() if ln.startswith("{")][-1])
        c.post(f"/api/agent/jobs/{planned['id']}/report", json=res, headers=h)
        report()
        j = next(x for x in c.get("/api/remediation/jobs").json() if x["id"] == planned["id"])
        return planned, res, j

    bins = by_source[source]
    lib = None
    for b in bins:  # a shared object of the source, for the canary to load
        cmd = f"apk info -qL {b}" if ALPINE else f"rpm -ql {b}" if RPM else f"dpkg -L {b}"
        _, files = wsl(cmd + " 2>/dev/null", check=False)
        lib = next((("/" + f.lstrip("/")) for f in files.split() if re.search(r"\.so(\.\d+)*$", f)), None)
        if lib:
            binary = b
            break
    systemd = not ALPINE
    if systemd and lib:
        q = f"rpm -q --qf '%{{EPOCHNUM}}:%{{VERSION}}-%{{RELEASE}}' {binary}" if RPM else f"dpkg-query -W -f='${{Version}}' {binary}"
        _, old = wsl(q)
        # scripts, not inline commands: systemd expands $ in unit lines itself
        wsl("cat > /opt/nimstead/canary-check.sh", input=f'test "$({q})" = "{old}"\n'.encode())
        wsl("cat > /opt/nimstead/canary.py", input=f"import ctypes, time\nctypes.CDLL({lib!r})\ntime.sleep(10**9)\n".encode())
        unit = ("[Unit]\nDescription=an app the new version breaks\n[Service]\nExecStartPre=/bin/sh /opt/nimstead/canary-check.sh\n"
                "ExecStart=/usr/bin/python3 /opt/nimstead/canary.py\n")
        wsl("cat > /etc/systemd/system/rt-canary.service && systemctl daemon-reload && systemctl start rt-canary.service", input=unit.encode())
        wsl("sleep 2")
        report()
        planned, res, j = run()
        steps = [f"{'ok ' if s['ok'] else 'FAIL'} {s['step']}" for s in res["steps"]]
        _, active = wsl("systemctl is-active rt-canary.service", check=False)
        _, ver = wsl(q)
        note("fix whose new version breaks a service", source=source, restarts_named=planned.get("restarts"), outcome=res["outcome"], steps=steps,
             canary=active.strip(), version_now=ver, version_before=old)
        check("5 a service the new version breaks rolls the fix back and runs again on the restored version",
              res["outcome"] == "rolled_back" and active.strip() == "active" and ver == old
              and any("restart rt-canary.service" in s for s in steps) and "rt-canary.service" in (planned.get("restarts") or {}).get("services", []))
        wsl("systemctl stop rt-canary.service; rm -f /etc/systemd/system/rt-canary.service; systemctl daemon-reload")
        report()
    planned, res, j = run()
    steps = [f"{'ok ' if s['ok'] else 'FAIL'} {s['step']}" for s in res["steps"]]
    restarted = [s.split("restart ", 1)[1].split(":")[0] for s in steps if s.startswith("ok  restart ") and "ran the copy" in s]
    left = next((s for s in res["steps"] if s["step"] == "still running the replaced copy"), None)
    note("the fix itself", source=source, restarts_named=planned.get("restarts"), outcome=res["outcome"], status=j["status"], error=j["error"],
         restarted=restarted, left=left and left["output"], steps=steps)
    if j["status"] == "verifying":  # a program it won't restart (D-Bus, or no systemd here) still runs the old copy: a restart finishes it
        check("5 a fix a refused program holds waits for a restart", (j["error"] or "").startswith("Waiting for a restart:"), error=j["error"])
        restart_distro() if systemd else restart_programs({"nginx", "sshd"})
        if ALPINE:
            wsl("(/usr/sbin/sshd; mkdir -p /run/nginx; nginx; true)")
        report()
        j = next(x for x in c.get("/api/remediation/jobs").json() if x["id"] == j["id"])
        note("after the machine restarted", status=j["status"], error=j["error"])
    check("5 the fix restarts what ran the old copy and succeeds", res["outcome"] == "applied" and j["status"] == "succeeded"
          and (bool(restarted) or not systemd), restarted=restarted, status=j["status"])
    if not ALPINE:
        _, nr = wsl(("needs-restarting -s" if RPM else "needrestart -b -r l") + " 2>&1", check=False)
        left_over = set(re.findall(r"([\w@.\\-]+\.service)", nr)) if RPM else set(re.findall(r"NEEDRESTART-SVC: (\S+)", nr))
        check("5 the distribution's tool names none of the restarted services afterwards", not (left_over & set(restarted)), left=sorted(left_over))


def hostile(c, h, report):
    """6-7: processes that try to confuse the read, and its cost with 2,000 extra processes and 60,000 descriptors."""
    script = (
        "import ctypes, mmap, os, resource, subprocess, sys, time\n"
        "libc = ctypes.CDLL(None)\n"
        "def child(name, body):\n"
        "    if os.fork() == 0:\n"
        "        libc.prctl(15, name, 0, 0, 0)\n"
        "        body(); time.sleep(600); os._exit(0)\n"
        "path = '/srv/x (deleted)\\nfoo'\n"
        "open(path, 'wb').write(b'\\0' * 4096)\n"
        "def mapit():\n"
        "    f = open(path, 'rb'); globals()['m'] = mmap.mmap(f.fileno(), 4096, prot=mmap.PROT_READ)\n"
        "child('ev\\nil\\xe2\\x80\\xae!'.encode('latin-1')[:15], mapit)\n"
        "def fds():\n"
        "    resource.setrlimit(resource.RLIMIT_NOFILE, (70000, 70000))\n"
        "    globals()['keep'] = [os.open('/dev/null', os.O_RDONLY) for _ in range(60000)]\n"
        "child(b'many-fds', fds)\n"
        "for _ in range(2000):\n"
        "    subprocess.Popen(['sleep', '600'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)\n"
        f"subprocess.Popen(['/usr/bin/env', 'API_TOKEN={SECRET}', 'python3', '-c', 'import time; time.sleep(600)', '--password={SECRET}'], start_new_session=True)\n"
        "time.sleep(3)\n"
    )
    wsl("cat > /srv/hostile.py", input=script.encode())
    wsl("cat > /srv/timing.py", input=(
        b"import json, sys, time\nsys.path.insert(0, '/opt/nimstead')\nimport agent as a\nt = time.time()\nr = a.runtime_read()\n"
        b"print(json.dumps({'seconds': round(time.time() - t, 2), 'state': r['state'], 'problem': r.get('problem'), 'programs': len(r['programs']),"
        b" 'names': sorted(p['name'] for p in r['programs'] if p['count'] < 5)}))\n"))
    # one call: WSL ends a command's processes with it, so they're started, read and stopped while it lasts
    wsl("cd /srv && python3 /srv/hostile.py >/dev/null 2>&1; "
        "for i in $(seq 60); do [ $(ls /proc | grep -c '^[0-9]') -gt 2000 ] && break; sleep 1; done; sleep 2; "
        "ls /proc | grep -c '^[0-9]' > /srv/n; python3 /srv/timing.py > /srv/timing.json; "
        "python3 /opt/nimstead/agent.py collect > /srv/collect.json; "
        "pkill -f 'sleep 600'; pkill -f 'time.sleep'; pkill -f many-fds; true", timeout=600)
    n = wsl("cat /srv/n")[1].strip()
    t = json.loads(wsl("cat /srv/timing.json")[1])
    inv = json.loads(wsl("cat /srv/collect.json")[1])
    rt = inv.get("runtime") or {}
    body = json.dumps(inv)
    res = report(inv)
    note("hostile processes", processes=int(n), read=t, report=res)
    check("6 a secret in a command line or environment never leaves the machine", SECRET not in body)
    check("6 crafted names are sanitised and the report goes through", all(re.fullmatch(r"[A-Za-z0-9._@:+() ?-]+", p["name"]) for p in rt["programs"])
          and any(p["name"].startswith("ev?il") for p in rt["programs"]))
    check("7 the read takes under 3 s with 2,000 extra processes", t["seconds"] < 3, seconds=t["seconds"], processes=int(n))
    wsl("pkill -f 'sleep 600'; pkill -f 'time.sleep'; true", check=False)


if __name__ == "__main__":
    sys.exit(main(keep="--keep" in sys.argv))
