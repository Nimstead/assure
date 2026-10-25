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


def collect():
    if os.name == "nt":
        # ponytail: Windows reports host only, no packages yet; add registry/winget inventory when Windows matching exists
        return {"os_name": platform.platform(), "ecosystem": "", "packages": []}
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
APK_CACHE = "/etc/apk/cache"


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


class Job:
    def __init__(self, job, run=sh, rollback_root=ROLLBACK_ROOT, apt_cache=APT_CACHE, apk_cache=APK_CACHE,
                 apk_db="/lib/apk/db/installed"):
        self.run, self.steps, self.artefacts = run, [], []
        self.mgr = job.get("manager")
        self.pkgs = job.get("packages") or []
        self.units = job.get("health_units") or []
        self.dir = os.path.join(rollback_root, re.sub(r"[^A-Za-z0-9]", "", str(job.get("id", ""))) or "unknown")
        self.apt_cache, self.apk_cache, self.apk_db = apt_cache, apk_cache, apk_db

    def step(self, name, cmd=None, ok=None, output="", cwd=None):
        if cmd is not None:
            rc, output = self.run(cmd, cwd=cwd)
            ok = rc == 0
        self.steps.append({"step": name, "ok": bool(ok), "output": output[-1500:]})
        if not ok:
            raise StepFailed(f"{name} failed: {output[-300:].strip()}")
        return output

    def versions(self):
        installed = {}
        if self.mgr == "apk":
            try:
                with open(self.apk_db) as f:
                    installed = {p["name"]: p["version"] for p in parse_apk(f.read())}
            except OSError:
                pass
        out = {}
        for p in self.pkgs:
            n = p["name"]
            if self.mgr == "apt":
                rc, v = self.run(["dpkg-query", "-W", "-f=${Version}", n])
            elif self.mgr == "dnf":
                rc, v = self.run(["rpm", "-q", "--qf", "%{EPOCHNUM}:%{VERSION}-%{RELEASE}", n])
            else:
                rc, v = (0, installed[n]) if n in installed else (1, "")
            out[n] = v.strip() if rc == 0 else None
        return out

    def health(self, when):
        for u in self.units:
            self.step(f"{u} active {when}", ["systemctl", "is-active", "--quiet", u])

    def save_rollback(self):
        os.makedirs(self.dir, exist_ok=True)
        for p in self.pkgs:
            n, v = p["name"], p["from"]
            if self.mgr == "apt":
                deb = "{}_{}_*.deb".format(n, v.replace(":", "%3a"))
                cached = glob.glob(os.path.join(self.apt_cache, deb))
                if not cached:
                    self.step(f"fetch rollback package {n}={v}", ["apt-get", "download", f"{n}={v}"], cwd=self.dir)
                files = cached + glob.glob(os.path.join(self.dir, deb))
            elif self.mgr == "apk":
                cached = glob.glob(os.path.join(self.apk_cache, f"{n}-{v}.*.apk"))
                if not cached:
                    self.step(f"fetch rollback package {n}={v}", ["apk", "fetch", "-o", self.dir, f"{n}={v}"])
                files = cached + glob.glob(os.path.join(self.dir, f"{n}-{v}.apk"))
            else:
                nv = v.split(":", 1)[1] if ":" in v else v
                self.step(f"fetch rollback package {n}-{nv}", ["dnf", "download", "--destdir", self.dir, f"{n}-{nv}"])
                files = glob.glob(os.path.join(self.dir, f"{n}-{nv}.*.rpm"))
            if not files:
                self.step(f"rollback package for {n}={v} present", ok=False, output="not available; refusing an irreversible change")
            with open(files[0], "rb") as fh:
                digest = hashlib.sha256(fh.read()).hexdigest()
            self.artefacts.append(files[0])
            self.step("rollback package saved " + os.path.basename(files[0]), ok=True, output="sha256 " + digest)

    def apply(self):
        names = [p["name"] for p in self.pkgs]
        if self.mgr == "apt":
            self.step("upgrade", ["apt-get", "install", "-y", "--only-upgrade", "-o", "Dpkg::Options::=--force-confold", *names])
            out = self.step("package database check", ["dpkg", "--audit"])
            if out.strip():
                self.step("package database consistent", ok=False, output=out)
        elif self.mgr == "apk":
            self.step("upgrade", ["apk", "add", "--upgrade", *names])
        else:
            self.step("upgrade", ["dnf", "upgrade", "-y", *names])

    def rollback(self):
        if self.mgr == "apt":
            self.step("rollback install", ["dpkg", "-i", *self.artefacts])
        elif self.mgr == "apk":
            self.step("rollback install", ["apk", "add", *self.artefacts])
        else:
            self.step("rollback install", ["rpm", "-Uvh", "--oldpackage", "--replacepkgs", *self.artefacts])
        now_v = self.versions()
        bad = [p["name"] for p in self.pkgs if now_v.get(p["name"]) != p["from"]]
        self.step("versions restored", ok=not bad, output=("mismatch: " + ", ".join(bad)) if bad else "all restored")
        self.health("after rollback")

    def execute(self):
        """Returns (outcome, steps, error). outcome: applied | rolled_back | rollback_failed | aborted."""
        try:  # prechecks: a failure here means nothing was changed
            ok = (self.mgr in ("apt", "apk", "dnf") and bool(self.pkgs)
                  and all(SAFE_NAME.match(str(p.get("name", ""))) and SAFE_VERSION.match(str(p.get("from", ""))) for p in self.pkgs)
                  and all(SAFE_NAME.match(str(u)) for u in self.units))
            self.step("job validated", ok=ok, output="" if ok else "invalid manager, package name, version or unit")
            tool = {"apt": "apt-get", "apk": "apk", "dnf": "dnf"}[self.mgr]
            self.step(f"{tool} available", [tool, "--version"])
            cur = self.versions()
            drift = [p["name"] for p in self.pkgs if cur.get(p["name"]) != p["from"]]
            self.step("installed versions match plan", ok=not drift, output=("drifted: " + ", ".join(drift)) if drift else "")
            self.health("before change")
            self.step("refresh package index", {"apt": ["apt-get", "update"], "apk": ["apk", "update"], "dnf": ["dnf", "makecache"]}[self.mgr])
            self.save_rollback()
        except Exception as e:
            return "aborted", self.steps, f"No changes made: {e}"
        try:
            self.apply()
            self.health("after change")
            return "applied", self.steps, None
        except Exception as e:
            err = str(e)
        try:
            self.rollback()
            return "rolled_back", self.steps, f"Change failed and was rolled back: {err}"
        except Exception as e:
            return "rollback_failed", self.steps, f"ROLLBACK FAILED, host needs attention. Change error: {err}; rollback error: {e}"


# ---- network ----------------------------------------------------------------

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
        with urllib.request.urlopen(req, timeout=60) as r:
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
    en.add_argument("--token", required=True)
    en.add_argument("--allow-remediation", action="store_true",
                    help="let this host run approved package upgrades (local opt-in; the server cannot enable it)")
    sub.add_parser("report")
    sub.add_parser("collect")
    sub.add_parser("remediate", help="run approved remediation jobs, then re-report inventory")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "collect":
            print(json.dumps(collect(), indent=2))
        elif a.cmd == "enroll":
            inv = collect()
            body = {"token": a.token, "hostname": socket.gethostname(), "os_name": inv["os_name"], "ecosystem": inv["ecosystem"]}
            res = post(a.server, "/api/agent/enroll", body, a.insecure_http)
            if "agent_key" not in res:
                raise AgentError("enroll response missing agent_key")
            print("enrolled as asset {}; config saved to {}".format(res.get("asset_id"), save_config({"server": a.server, "allow_remediation": a.allow_remediation, **res})))
        elif a.cmd == "remediate":
            cfg = load_config()
            if not cfg.get("allow_remediation"):
                raise AgentError("remediation is not enabled on this host (re-enroll with --allow-remediation)")
            failed = 0
            for job in post(cfg["server"], "/api/agent/jobs", None, a.insecure_http, cfg["agent_key"]):
                outcome, steps, error = Job(job).execute()
                post(cfg["server"], "/api/agent/jobs/{}/report".format(job["id"]),
                     {"outcome": outcome, "steps": steps, "error": error}, a.insecure_http, cfg["agent_key"])
                print("job {}: {}{}".format(job["id"], outcome, f" ({error})" if error else ""))
                failed += outcome != "applied"
            inv = collect()  # server confirms the fix from fresh inventory
            post(cfg["server"], "/api/agent/inventory", inv, a.insecure_http, cfg["agent_key"])
            if failed:
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
