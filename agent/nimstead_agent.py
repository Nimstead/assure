#!/usr/bin/env python3
"""Nimstead agent: reports installed packages to the server. Single file, stdlib only, Python 3.9+.

  nimstead_agent.py enroll --server https://host --token TOKEN
  nimstead_agent.py report
  nimstead_agent.py collect          # print inventory JSON, no network
  nimstead_agent.py remediate        # run approved jobs (host must opt in at enroll)
"""

import argparse
import glob
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


class AgentError(Exception):
    pass


def config_path():
    if os.name == "nt":
        return os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "Nimstead", "agent.json")
    if os.geteuid() == 0:
        return "/etc/nimstead/agent.json"
    return os.path.expanduser("~/.config/nimstead/agent.json")


# ---- collection -------------------------------------------------------------

def parse_os_release(text):
    out = {}
    for line in text.splitlines():
        k, sep, v = line.partition("=")
        if sep and not line.startswith("#"):
            out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def ecosystem_from_os_release(text):
    """OSV ecosystem string, or '' if the distro/release is not one we can match."""
    r = parse_os_release(text)
    ver = r.get("VERSION_ID", "")
    distro = r.get("ID", "")
    if not ver:
        return ""
    # ponytail: derivatives (Mint, Pop!_OS, ...) are not mapped, exact IDs only; add ID_LIKE mapping when needed
    if distro == "debian":
        return "Debian:" + ver.split(".")[0]
    if distro == "ubuntu":
        return "Ubuntu:" + ver
    if distro == "alpine":
        return "Alpine:v" + ".".join(ver.split(".")[:2])
    if distro == "rocky":
        return "Rocky Linux:" + ver.split(".")[0]
    if distro == "almalinux":
        return "AlmaLinux:" + ver.split(".")[0]
    return ""


def parse_dpkg(text):
    pkgs = []
    for line in text.splitlines():
        f = line.split("\t")
        if len(f) < 4 or not f[3].startswith("ii"):
            continue
        pkgs.append({"name": f[0], "version": f[1], "source": f[2] or f[0]})
    return pkgs


def parse_rpm(text):
    pkgs = []
    for line in text.splitlines():
        f = line.split("\t")
        if len(f) < 3 or f[0] == "gpg-pubkey":
            continue
        src = f[2]
        if src.endswith(".src.rpm"):
            src = src[: -len(".src.rpm")].rsplit("-", 2)[0]  # strip -version-release
        else:
            src = f[0]
        # Epoch always kept ("0:1.2-3"): OSV Rocky records use "E:V-R" and the comparator treats absent == 0
        pkgs.append({"name": f[0], "version": f[1], "source": src})
    return pkgs


def parse_apk(text):
    pkgs = []
    for block in text.split("\n\n"):
        d = {}
        for line in block.splitlines():
            if len(line) > 2 and line[1] == ":":
                d.setdefault(line[0], line[2:])
        if "P" in d and "V" in d:
            pkgs.append({"name": d["P"], "version": d["V"], "source": d.get("o", d["P"])})
    return pkgs


def _run(cmd):
    try:
        return subprocess.run(cmd, check=True, capture_output=True, text=True, errors="replace").stdout
    except (OSError, subprocess.CalledProcessError) as e:
        raise AgentError(f"{cmd[0]} failed: {e}")


# MSRC names Windows Server by build; client names come from the feature-update version.
_SERVER_BY_BUILD = {14393: "Windows Server 2016", 17763: "Windows Server 2019", 20348: "Windows Server 2022", 26100: "Windows Server 2025"}
_MSRC_ARCH = {"AMD64": "x64-based", "X86": "32-bit", "ARM64": "ARM64-based"}


def msrc_product_name(build, display_version, installation_type, machine):
    """MSRC product name for this OS, or '' if we cannot name it exactly (refuse to guess).

    ponytail: OS only. Server 2012/R2 (6.x builds), Server 23H2 and Insider builds are unmapped."""
    if installation_type.startswith("Server"):
        name = _SERVER_BY_BUILD.get(build)
        return name + (" (Server Core installation)" if installation_type == "Server Core" else "") if name else ""
    arch = _MSRC_ARCH.get(machine.upper())
    if not arch or not display_version:
        return ""
    if build >= 22000:  # Windows 11 still says "Windows 10" in the ProductName registry value
        return f"Windows 11 Version {display_version} for {arch} Systems"
    if 10240 <= build < 22000:
        return ("Windows 10" if display_version == "1507" else f"Windows 10 Version {display_version}") + f" for {arch} Systems"
    return ""


def collect_windows():
    import winreg
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", 0,
                        winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
        def val(name, default=""):
            try:
                return winreg.QueryValueEx(k, name)[0]
            except OSError:
                return default
        build, ubr = int(val("CurrentBuild", 0) or 0), int(val("UBR", 0))
        dv = val("DisplayVersion") or val("ReleaseId")
        product, itype = val("ProductName"), val("InstallationType")
    machine = platform.machine()
    name = msrc_product_name(build, dv, itype, machine)
    if not name or not build:
        raise AgentError(f"unsupported Windows release: {product} {dv} build {build} {itype} {machine}")
    version = f"10.0.{build}.{ubr}"
    if build >= 22000:
        product = product.replace("Windows 10", "Windows 11")
    return {"os_name": f"{product} {dv} ({machine}) build {version}", "ecosystem": "Windows",
            "packages": [{"ecosystem": "Windows", "name": name, "version": version, "source": None}]}


def collect():
    if os.name == "nt":
        return collect_windows()
    try:
        with open("/etc/os-release") as f:
            text = f.read()
    except OSError as e:
        raise AgentError(f"cannot read /etc/os-release: {e}")
    r = parse_os_release(text)
    eco = ecosystem_from_os_release(text)
    if not eco:
        raise AgentError("unsupported distro/release: {} {}".format(r.get("ID", "?"), r.get("VERSION_ID", "?")))
    if os.path.exists("/lib/apk/db/installed"):
        with open("/lib/apk/db/installed") as f:
            pkgs = parse_apk(f.read())
    elif shutil.which("dpkg-query"):
        pkgs = parse_dpkg(_run(["dpkg-query", "-W", "-f", "${Package}\t${Version}\t${source:Package}\t${db:Status-Abbrev}\n"]))
    elif shutil.which("rpm"):
        pkgs = parse_rpm(_run(["rpm", "-qa", "--qf", "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{SOURCERPM}\n"]))
    else:
        raise AgentError("no package manager found (dpkg-query, rpm, apk db)")
    if not pkgs:
        raise AgentError("collected zero packages; refusing to report an empty inventory")
    return {"os_name": r.get("PRETTY_NAME") or r.get("NAME", ""), "ecosystem": eco,
            "packages": [dict(p, ecosystem=eco) for p in pkgs]}


# ---- remediation ------------------------------------------------------------
# The server sends a closed job description; every command below is a fixed argv
# template filled with validated names. Rollback packages are saved before any
# change, and any failure after a change triggers rollback. Nothing is silent:
# every step is reported back and lands in the evidence ledger.

SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._-]{0,200}$")
SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+~:_^-]{0,200}$")
ROLLBACK_ROOT = "/var/lib/nimstead/rollback"
APT_CACHE = "/var/cache/apt/archives"


def sh(cmd, cwd=None):
    """Default runner: (returncode, output tail). Never raises for a failing command."""
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive", LC_ALL="C")
    try:
        p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, errors="replace", timeout=1800)
        return p.returncode, (p.stdout + p.stderr)[-4000:]
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, str(e)


class StepFailed(Exception):
    pass


DPKG_INFO = "/var/lib/dpkg/info"
_CONTROL_DROP = ("Status", "Conffiles", "Config-Version")
_INFO_FILES = ("preinst", "postinst", "prerm", "postrm", "config", "templates", "triggers", "shlibs", "symbols", "conffiles", "md5sums")


def repack_deb(run, name, version, arch, outdir, info_dir=DPKG_INFO, root="/"):
    """Rebuild the installed package from its files and dpkg metadata (what dpkg-repack does).

    Used only when no pristine .deb of the installed version exists anywhere (it has usually been
    superseded in the archive). Captures the package exactly as installed, including locally edited
    conffiles, so a rollback restores the real prior state. Returns (path, note)."""
    qual = f"{name}:{arch}" if os.path.exists(os.path.join(info_dir, f"{name}:{arch}.list")) else name
    rc, control = run(["dpkg-query", "-s", qual])
    if rc != 0:
        raise StepFailed(f"cannot read dpkg metadata for {qual}")
    fields, keep = [], True
    for line in control.splitlines():
        if line and not line[0].isspace():
            keep = line.split(":", 1)[0] not in _CONTROL_DROP
        if keep and line.strip():
            fields.append(line)
    if f"Version: {version}" not in fields:
        raise StepFailed(f"installed {qual} is not version {version}")
    build = tempfile.mkdtemp(prefix=f"repack-{name}-", dir=outdir)
    debian = os.path.join(build, "DEBIAN")
    os.makedirs(debian, mode=0o755)
    with open(os.path.join(debian, "control"), "w") as f:
        f.write("\n".join(fields) + "\n")
    for kind in _INFO_FILES:
        src = os.path.join(info_dir, f"{qual}.{kind}")
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(debian, kind))
    with open(os.path.join(info_dir, f"{qual}.list")) as f:
        paths = [ln.rstrip("\n") for ln in f if ln.strip() and ln.strip() != "/."]
    missing = 0
    for path in paths:
        src = os.path.join(root, path.lstrip("/"))
        dst = os.path.join(build, path.lstrip("/"))
        if os.path.islink(src):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            os.symlink(os.readlink(src), dst)
        elif os.path.isdir(src):
            os.makedirs(dst, exist_ok=True)
            shutil.copystat(src, dst)
        elif os.path.isfile(src):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
        else:
            missing += 1  # e.g. excluded by dpkg path-exclude, or deleted by an admin: not restorable, wasn't there
            continue
        if hasattr(os, "lchown"):
            st = os.lstat(src)
            os.lchown(dst, st.st_uid, st.st_gid)
            if not os.path.islink(src):
                os.chmod(dst, st.st_mode & 0o7777)  # after chown, which clears setuid bits
    out = os.path.join(outdir, "{}_{}_{}.deb".format(name, version.replace(":", "%3a"), arch))
    rc, msg = run(["dpkg-deb", "--build", build, out])
    shutil.rmtree(build, ignore_errors=True)
    if rc != 0:
        raise StepFailed(f"dpkg-deb --build failed for {qual}: {msg[-300:]}")
    rc, got = run(["dpkg-deb", "-f", out, "Package", "Version"])
    if rc != 0 or f"Package: {name}" not in got or f"Version: {version}" not in got:
        raise StepFailed(f"rebuilt package for {qual} does not identify as {name} {version}")
    return out, f"rebuilt from installed files ({len(paths) - missing} paths, {missing} absent on disk)"


class Job:
    """One remediation job. apt only: other managers are refused until proven in a sandbox (DECISIONS 15)."""

    def __init__(self, job, run=sh, rollback_root=ROLLBACK_ROOT, apt_cache=APT_CACHE, dpkg_info=DPKG_INFO, root="/"):
        self.run, self.steps, self.artefacts = run, [], []
        self.mgr = job.get("manager")
        self.pkgs = job.get("packages") or []
        self.units = job.get("health_units") or []
        # services often fail a few seconds after a library upgrade, not instantly
        self.settle = min(max(int(job.get("settle_seconds", 15) or 0), 0), 300)
        self.dir = os.path.join(rollback_root, re.sub(r"[^A-Za-z0-9]", "", str(job.get("id", ""))) or "unknown")
        self.apt_cache, self.dpkg_info, self.root = apt_cache, dpkg_info, root

    def step(self, name, cmd=None, ok=None, output="", cwd=None):
        if cmd is not None:
            rc, output = self.run(cmd, cwd=cwd)
            ok = rc == 0
        self.steps.append({"step": name, "ok": bool(ok), "output": output[-1500:]})
        if not ok:
            raise StepFailed(f"{name} failed: {output[-300:].strip()}")
        return output

    def versions(self):
        out = {}
        for p in self.pkgs:
            rc, v = self.run(["dpkg-query", "-W", "-f=${Version}", p["name"]])
            out[p["name"]] = v.strip() if rc == 0 else None
        return out

    def health(self, when):
        for u in self.units:
            self.step(f"{u} active {when}", ["systemctl", "is-active", "--quiet", u])

    def save_rollback(self):
        """Copy a rollback package for every planned package into our own dir (caches can be cleaned mid-upgrade)."""
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        for p in self.pkgs:
            n, v = p["name"], p["from"]
            rc, arch = self.run(["dpkg-query", "-W", "-f=${Architecture}", n])
            arch = arch.strip() if rc == 0 and SAFE_NAME.match(arch.strip()) else "*"
            deb = "{}_{}_{}.deb".format(n, v.replace(":", "%3a"), arch)
            found = glob.glob(os.path.join(self.dir, deb)) or glob.glob(os.path.join(self.apt_cache, deb))
            if not found:  # pristine copy from the archive if it still carries this version
                rc, out = self.run(["apt-get", "download", f"{n}={v}"], cwd=self.dir)
                self.steps.append({"step": f"archive copy of {n}={v}" + ("" if rc == 0 else " not available (superseded); rebuilding"),
                                   "ok": True, "output": out[-500:]})
                found = glob.glob(os.path.join(self.dir, deb))
            if not found and arch != "*":  # superseded everywhere: rebuild it from the installed files
                path, why = repack_deb(self.run, n, v, arch, self.dir, self.dpkg_info, self.root)
                self.step(f"rollback package {n}={v}", ok=True, output=why)
                found = [path]
            if not found:
                self.step(f"rollback package for {n}={v} present", ok=False, output="not available; refusing an irreversible change")
            dest = os.path.join(self.dir, os.path.basename(found[0]))
            if os.path.abspath(found[0]) != os.path.abspath(dest):
                shutil.copyfile(found[0], dest)
            digest = _sha256(dest)
            self.artefacts.append((dest, digest))
            self.step("rollback package saved " + os.path.basename(dest), ok=True, output="sha256 " + digest)

    def targets(self):
        """Package specs to install: pinned to a canary-proven version when the server provides one."""
        return [f"{p['name']}={p['to']}" if p.get("to") else p["name"] for p in self.pkgs]

    def simulate(self):
        """Dry-run the transaction; refuse if it would touch anything outside the plan (rollback couldn't undo it)."""
        out = self.step("simulate upgrade", ["apt-get", "-s", "install", "--only-upgrade", "--no-remove", *self.targets()])
        touched = {ln.split()[1] for ln in out.splitlines() if ln.split()[:1] in (["Inst"], ["Remv"], ["Purg"])}
        planned = {p["name"] for p in self.pkgs}
        extra = sorted(touched - planned)
        self.step("change limited to planned packages", ok=not extra, output=("would also change: " + ", ".join(extra)) if extra else
                  "touches: " + ", ".join(sorted(touched)))

    def apply(self):
        self.step("upgrade", ["apt-get", "install", "-y", "--only-upgrade", "--no-remove",
                              "-o", "Dpkg::Options::=--force-confold", *self.targets()])
        out = self.step("package database check", ["dpkg", "--audit"])
        if out.strip():
            self.step("package database consistent", ok=False, output=out)
        self.result_versions = self.versions()

    def rollback(self):
        for path, digest in self.artefacts:
            self.step("rollback package intact " + os.path.basename(path), ok=os.path.exists(path) and _sha256(path) == digest,
                      output="sha256 mismatch or missing")
        files = [path for path, _ in self.artefacts]
        self.step("rollback install", ["dpkg", "-i", *files])
        now_v = self.versions()
        bad = [p["name"] for p in self.pkgs if now_v.get(p["name"]) != p["from"]]
        self.step("versions restored", ok=not bad, output=("mismatch: " + ", ".join(bad)) if bad else "all restored")
        if self.units and self.settle:
            time.sleep(self.settle)  # let restarted services come back before judging
        self.health("after rollback")

    def execute(self):
        """Returns (outcome, steps, error). outcome: applied | rolled_back | rollback_failed | aborted."""
        try:  # prechecks: a failure here means nothing was changed
            ok = (self.mgr == "apt" and bool(self.pkgs)
                  and all(SAFE_NAME.match(str(p.get("name", ""))) and SAFE_VERSION.match(str(p.get("from", ""))) for p in self.pkgs)
                  and all(SAFE_VERSION.match(str(p["to"])) for p in self.pkgs if p.get("to"))
                  and all(SAFE_NAME.match(str(u)) for u in self.units))
            self.step("job validated", ok=ok, output="" if ok else "unsupported manager, or invalid package name, version or unit")
            self.step("apt-get available", ["apt-get", "--version"])
            cur = self.versions()
            drift = [p["name"] for p in self.pkgs if cur.get(p["name"]) != p["from"]]
            self.step("installed versions match plan", ok=not drift, output=("drifted: " + ", ".join(drift)) if drift else "")
            self.health("before change")
            self.step("refresh package index", ["apt-get", "update"])
            self.simulate()
            self.save_rollback()
        except Exception as e:
            return "aborted", self.steps, f"No changes made: {e}"
        try:
            self.apply()
            if self.units and self.settle:
                time.sleep(self.settle)
            self.health("after change")
            return "applied", self.steps, None
        except Exception as e:
            err = str(e)
        try:
            self.rollback()
            return "rolled_back", self.steps, f"Change failed and was rolled back: {err}"
        except Exception as e:
            return "rollback_failed", self.steps, f"ROLLBACK FAILED, host needs attention. Change error: {err}; rollback error: {e}"


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


OUTCOME_DIR = "/var/lib/nimstead/outcomes"


def run_jobs(server, key, insecure_http, run=sh, outcome_dir=OUTCOME_DIR, **job_kw):
    """Execute jobs, persisting every outcome before reporting so none is lost if the report fails.
    Unsent outcomes from earlier runs are retried first. Returns the number of jobs not applied or not reported."""
    os.makedirs(outcome_dir, mode=0o700, exist_ok=True)
    problems = 0

    def send(path):
        nonlocal problems
        with open(path) as f:
            rec = json.load(f)
        try:
            post(server, "/api/agent/jobs/{}/report".format(rec["id"]), rec["report"], insecure_http, key)
            os.remove(path)
        except AgentError as e:
            if " 409:" in str(e) or " 404:" in str(e):  # server no longer accepts it; keep a local copy, stop retrying
                os.replace(path, path + ".rejected")
            print("job {}: report failed: {}".format(rec["id"], e), file=sys.stderr)
            problems += 1

    for path in sorted(glob.glob(os.path.join(outcome_dir, "*.json"))):
        send(path)
    for job in post(server, "/api/agent/jobs", None, insecure_http, key):
        j = Job(job, run=run, **job_kw)
        outcome, steps, error = j.execute()
        report = {"outcome": outcome, "steps": steps, "error": error, "versions": getattr(j, "result_versions", None)}
        path = os.path.join(outcome_dir, re.sub(r"[^A-Za-z0-9]", "", str(job.get("id"))) + ".json")
        with open(path, "w") as f:
            json.dump({"id": job.get("id"), "report": report}, f)
        print("job {}: {}{}".format(job.get("id"), outcome, f" ({error})" if error else ""))
        problems += outcome != "applied"
        send(path)
    return problems


# ---- network ----------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):  # never forward the agent key to another URL
        return None


_opener = urllib.request.build_opener(_NoRedirect)


class run_lock:
    """Single remediation run at a time (cron/timer overlap)."""

    def __enter__(self):
        import fcntl
        os.makedirs("/var/lib/nimstead", exist_ok=True)
        self.f = open("/var/lib/nimstead/agent.lock", "w")
        try:
            fcntl.flock(self.f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise AgentError("another nimstead-agent run is in progress") from None
        return self

    def __exit__(self, *exc):
        self.f.close()


def post(server, path, body, insecure_http, key=None):
    """POST JSON, or GET when body is None."""
    if not server.startswith("https://") and not (insecure_http and server.startswith("http://")):
        raise AgentError(f"refusing non-HTTPS server {server!r} (use --insecure-http for local dev)")
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = "Bearer " + key
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(server.rstrip("/") + path, data, headers, method="GET" if body is None else "POST")
    try:
        with _opener.open(req, timeout=60) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raise AgentError("server returned {}: {}".format(e.code, e.read(300).decode(errors="replace")))
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise AgentError(f"request to {server} failed: {e}")


def load_config():
    try:
        with open(config_path()) as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        raise AgentError(f"cannot read {config_path()} (run enroll first): {e}")


def save_config(cfg):
    p = config_path()
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(cfg, f)
        os.chmod(p, 0o600)  # in case the file pre-existed with looser perms
    except OSError as e:
        raise AgentError(f"cannot write {p}: {e}")
    return p


def main(argv=None):
    ap = argparse.ArgumentParser(prog="nimstead-agent")
    ap.add_argument("--insecure-http", action="store_true", help="allow plain http (local dev only)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    en = sub.add_parser("enroll")
    en.add_argument("--server", required=True)
    en.add_argument("--token", default=os.environ.get("NIMSTEAD_TOKEN"),
                    help="enrolment token (or set NIMSTEAD_TOKEN, which keeps it out of the process list)")
    en.add_argument("--allow-remediation", action="store_true",
                    help="let this host run approved package upgrades (local opt-in; the server cannot enable it)")
    sub.add_parser("report")
    sub.add_parser("collect")
    sub.add_parser("remediate", help="run approved remediation jobs, then re-report inventory")
    rj = sub.add_parser("run-job", help="run one job read as JSON from stdin, print the result JSON (no network; sandbox testing)")
    rj.add_argument("--yes", action="store_true", help="confirm: this changes installed packages on this host")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "collect":
            print(json.dumps(collect(), indent=2))
        elif a.cmd == "enroll":
            if not a.token:
                raise AgentError("an enrolment token is required (--token or NIMSTEAD_TOKEN)")
            inv = collect()
            body = {"token": a.token, "hostname": socket.gethostname(), "os_name": inv["os_name"], "ecosystem": inv["ecosystem"]}
            res = post(a.server, "/api/agent/enroll", body, a.insecure_http)
            if "agent_key" not in res:
                raise AgentError("enroll response missing agent_key")
            print("enrolled as asset {}; config saved to {}".format(res.get("asset_id"), save_config({"server": a.server, "allow_remediation": a.allow_remediation, **res})))
        elif a.cmd == "run-job":
            if not a.yes:
                raise AgentError("run-job changes installed packages; pass --yes to confirm")
            j = Job(json.load(sys.stdin))
            outcome, steps, error = j.execute()
            print(json.dumps({"outcome": outcome, "steps": steps, "error": error, "versions": getattr(j, "result_versions", None)}))
            return 0 if outcome == "applied" else 2
        elif a.cmd == "remediate":
            cfg = load_config()
            if not cfg.get("allow_remediation"):
                raise AgentError("remediation is not enabled on this host (re-enroll with --allow-remediation)")
            with run_lock():
                problems = run_jobs(cfg["server"], cfg["agent_key"], a.insecure_http)
                post(cfg["server"], "/api/agent/inventory", collect(), a.insecure_http, cfg["agent_key"])  # server verifies the fix
            if problems:
                return 2
        else:
            cfg = load_config()
            inv = collect()
            post(cfg["server"], "/api/agent/inventory", inv, a.insecure_http, cfg["agent_key"])
            print(f"reported {len(inv['packages'])} packages")
    except AgentError as e:
        print(f"nimstead-agent: error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
