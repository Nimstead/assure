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
import tarfile
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
    if distro == "opensuse-leap":
        return "openSUSE:Leap " + ver
    if distro == "opensuse-tumbleweed":
        return "openSUSE:Tumbleweed"
    if distro == "sles" and "." in ver:
        major, minor = ver.split(".", 1)
        return f"SUSE:Linux Enterprise Server {major} SP{minor}"
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


UNINSTALL = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"


USER_SID = re.compile(r"^S-1-5-21-[0-9-]+$")


def windows_apps(reg):
    """Installed apps from the registry Uninstall keys: HKLM 64-bit and 32-bit views, then every loaded user hive
    (per-user installs such as VS Code (User); the agent runs as SYSTEM, whose own HKCU has none), then HKCU.
    Profiles of users who aren't logged on aren't loaded and so aren't seen.
    `reg` is the winreg module (or a fake). Skips SystemComponent=1 and entries without a name or version.
    The publisher travels in `source`; the server decides which apps it can match (curated map only)."""
    seen, out = set(), []
    places = [(reg.HKEY_LOCAL_MACHINE, UNINSTALL, reg.KEY_WOW64_64KEY), (reg.HKEY_LOCAL_MACHINE, UNINSTALL, reg.KEY_WOW64_32KEY)]
    i = 0
    while True:
        try:
            sid = reg.EnumKey(reg.HKEY_USERS, i)
        except OSError:
            break
        i += 1
        if USER_SID.match(sid):
            places.append((reg.HKEY_USERS, sid + "\\" + UNINSTALL, 0))
    places.append((reg.HKEY_CURRENT_USER, UNINSTALL, 0))
    for hive, path, view in places:
        try:
            root = reg.OpenKey(hive, path, 0, reg.KEY_READ | view)
        except OSError:
            continue
        with root:
            i = 0
            while True:
                try:
                    sub = reg.EnumKey(root, i)
                except OSError:
                    break
                i += 1
                try:
                    with reg.OpenKey(root, sub) as k:
                        def val(n, k=k):
                            try:
                                return reg.QueryValueEx(k, n)[0]
                            except OSError:
                                return None
                        name, ver, pub, sysc = val("DisplayName"), val("DisplayVersion"), val("Publisher"), val("SystemComponent")
                except OSError:
                    continue
                if sysc == 1 or not isinstance(name, str) or not isinstance(ver, str) or not name.strip() or not ver.strip():
                    continue
                pub = pub.strip()[:255] if isinstance(pub, str) and pub.strip() else None
                item = (name.strip()[:255], ver.strip()[:255], pub)
                if item not in seen:
                    seen.add(item)
                    out.append({"ecosystem": "WinApp", "name": item[0], "version": item[1], "source": pub})
    return sorted(out, key=lambda p: (p["name"], p["version"]))


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
            "packages": [{"ecosystem": "Windows", "name": name, "version": version, "source": None}, *windows_apps(winreg)]}


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
    """Default runner: (returncode, full output). Never raises for a failing command. Steps keep only the tail;
    parsers (zypper's XML dry run runs to tens of KB with package descriptions) need all of it."""
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive", LC_ALL="C")
    try:
        p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, errors="replace", timeout=1800)
        return p.returncode, p.stdout + p.stderr
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


def apk_owned(db_text, names):
    """Paths owned by the named packages, from apk's installed database (F: dir, R: file within it)."""
    out = []
    for block in db_text.split("\n\n"):
        lines = block.splitlines()
        if not any(ln[2:] in names for ln in lines if ln.startswith("P:")):
            continue
        cur = ""
        for ln in lines:
            if ln.startswith("F:"):
                cur = ln[2:]
                out.append("/" + cur)
            elif ln.startswith("R:"):
                out.append("/" + (cur + "/" if cur else "") + ln[2:])
    return out


def dnf_touched(out):
    """Package names in a dnf4 transaction table (sections between the header and 'Transaction Summary')."""
    names, section = set(), False
    for ln in out.splitlines():
        s = ln.strip()
        if s.startswith("Transaction Summary"):
            break
        if s.endswith(":") and s.rstrip(":").split()[0] in ("Installing", "Upgrading", "Removing", "Downgrading", "Reinstalling", "Obsoleting"):
            section = True
            continue
        if section and ln.startswith(" ") and s:
            names.add(s.split()[0])
    return names


def zypper_touched(xml):
    """Package names in a `zypper --xmlout ... --dry-run` install summary."""
    import xml.etree.ElementTree as ET
    names = set()
    # local root-run zypper output, not network input; the agent is stdlib-only so defusedxml isn't available
    tree = ET.fromstring(xml[xml.index("<stream"):] if "<stream" in xml else xml)  # noqa: S314
    for section in ("to-install", "to-upgrade", "to-downgrade", "to-remove", "to-reinstall", "to-upgrade-change-arch"):
        for el in tree.iter(section):
            names |= {s.get("name") for s in el.iter("solvable") if s.get("type", "package") == "package"}
    return names


TOOLS = {"apt": "apt-get", "apk": "apk", "dnf": "dnf", "zypper": "zypper"}


class Job:
    """One remediation job: plan check, dry run, rollback artefact, change, health check, rollback on failure.

    apt: rollback = the old .deb (archive copy, or rebuilt from the installed files).
    apk / dnf: neither keeps old builds, so rollback = snapshot of every file the planned packages own plus
    the package database. Sound because the dry run proves the transaction touches only those packages.
    Maintainer-script side effects (e.g. a restarted service) are not snapshotted; health checks cover them."""

    def __init__(self, job, run=sh, rollback_root=ROLLBACK_ROOT, apt_cache=APT_CACHE, dpkg_info=DPKG_INFO, root="/",
                 fail_after_apply=False):
        self.run, self.steps, self.artefacts = run, [], []
        self.mgr = job.get("manager")
        self.pkgs = job.get("packages") or []
        self.units = job.get("health_units") or []
        # services often fail a few seconds after a library upgrade, not instantly
        self.settle = min(max(int(job.get("settle_seconds", 15) or 0), 0), 300)
        self.dir = os.path.join(rollback_root, re.sub(r"[^A-Za-z0-9]", "", str(job.get("id", ""))) or "unknown")
        self.apt_cache, self.dpkg_info, self.root = apt_cache, dpkg_info, root
        self.fail_after_apply = fail_after_apply  # sandbox fault injection (run-job only; never from the server)

    def path(self, p):
        return os.path.join(self.root, p.lstrip("/"))

    def step(self, name, cmd=None, ok=None, output="", cwd=None):
        if cmd is not None:
            rc, output = self.run(cmd, cwd=cwd)
            ok = rc == 0
        self.steps.append({"step": name, "ok": bool(ok), "output": output[-1500:]})
        if not ok:
            raise StepFailed(f"{name} failed: {output[-300:].strip()}")
        return output

    # --- state --------------------------------------------------------------

    def versions(self):
        out = {}
        if self.mgr == "apk":
            try:
                with open(self.path("/lib/apk/db/installed")) as f:
                    installed = {p["name"]: p["version"] for p in parse_apk(f.read())}
            except OSError:
                installed = {}
            return {p["name"]: installed.get(p["name"]) for p in self.pkgs}
        for p in self.pkgs:
            if self.mgr == "apt":
                rc, v = self.run(["dpkg-query", "-W", "-f=${Version}", p["name"]])
            else:
                rc, v = self.run(["rpm", "-q", "--qf", "%{EPOCHNUM}:%{VERSION}-%{RELEASE}\\n", p["name"]])
                if rc == 0 and len(v.split()) != 1:  # several installed (install-only packages like kernels): refuse
                    rc = 1
            out[p["name"]] = v.strip() if rc == 0 else None
        return out

    def owned_paths(self):
        names = {p["name"] for p in self.pkgs}
        if self.mgr == "apk":
            with open(self.path("/lib/apk/db/installed")) as f:
                return set(apk_owned(f.read(), names))
        paths = set()
        for n in sorted(names):
            rc, out = self.run(["rpm", "-ql", n])
            if rc != 0:
                raise StepFailed(f"cannot list files of {n}")
            paths |= {ln.strip() for ln in out.splitlines() if ln.startswith("/")}
        return paths

    def health(self, when):
        for u in self.units:
            self.step(f"{u} active {when}", ["systemctl", "is-active", "--quiet", u])

    def snapper_ok(self):
        rc, out = self.run(["snapper", "-c", "root", "list", "--columns", "number"])
        return rc == 0

    def _snap_post(self):
        if getattr(self, "snap_pre", None) and not getattr(self, "snap_post", None):
            rc, out = self.run(["snapper", "-c", "root", "create", "--type", "post", "--pre-number", self.snap_pre, "--print-number"])
            self.step("snapper post-change snapshot", ok=rc == 0 and out.strip().isdigit(), output=out)
            self.snap_post = out.strip()

    def targets(self):
        """Package specs to install: pinned to a canary-proven version when the server provides one."""
        if self.mgr == "dnf":
            return [f"{p['name']}-{p['to']}" if p.get("to") else p["name"] for p in self.pkgs]
        return [f"{p['name']}={p['to']}" if p.get("to") else p["name"] for p in self.pkgs]

    # --- dry run ------------------------------------------------------------

    def simulate(self):
        """Dry-run the transaction; refuse if it would touch anything outside the plan (rollback couldn't undo it)."""
        if self.mgr == "apt":
            out = self.step("simulate upgrade", ["apt-get", "-s", "install", "--only-upgrade", "--no-remove", *self.targets()])
            touched = {ln.split()[1] for ln in out.splitlines() if ln.split()[:1] in (["Inst"], ["Remv"], ["Purg"])}
        elif self.mgr == "apk":
            out = self.step("simulate upgrade", ["apk", "add", "-s", "--upgrade", *self.targets()])
            touched = set(re.findall(r"\b(?:Upgrading|Installing|Purging|Downgrading|Replacing|Reinstalling) (\S+)", out))
        elif self.mgr == "zypper":
            out = self.step("simulate upgrade", ["zypper", "--non-interactive", "--xmlout", "install", "--dry-run", *self.targets()])
            touched = zypper_touched(out)
        else:
            rc, out = self.run(["dnf", "upgrade", "--assumeno", *self.targets()])  # exits 1 after printing the plan
            self.steps.append({"step": "simulate upgrade", "ok": "Transaction Summary" in out or "Nothing to do" in out,
                               "output": out[-1500:]})
            if "Transaction Summary" not in out:
                raise StepFailed("simulate upgrade failed: " + out[-300:].strip())
            touched = dnf_touched(out)
        planned = {p["name"] for p in self.pkgs}
        extra = sorted(touched - planned)
        self.step("change limited to planned packages", ok=not extra,
                  output=("would also change: " + ", ".join(extra)) if extra else "touches: " + ", ".join(sorted(touched)))

    # --- rollback artefacts -------------------------------------------------

    def save_rollback(self):
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        if self.mgr == "apt":
            return self._save_debs()
        if self.mgr == "zypper" and self.snapper_ok():
            # btrfs + snapper: a pre/post snapshot pair captures EVERYTHING the change does to the root filesystem,
            # including what the packages' install scripts touch outside their own files
            rc, out = self.run(["snapper", "-c", "root", "create", "--type", "pre", "--print-number",
                                "--cleanup-algorithm", "number", "--description", f"nimstead job {os.path.basename(self.dir)}"])
            self.step("snapper pre-change snapshot", ok=rc == 0 and out.strip().isdigit(), output=out)
            self.snap_pre = out.strip()
            return
        self.old_paths = self.owned_paths()
        tar_path = os.path.join(self.dir, "files.tar")
        with tarfile.open(tar_path, "w") as tar:
            for p in sorted(self.old_paths):
                if os.path.lexists(self.path(p)):
                    tar.add(self.path(p), arcname=p.lstrip("/"), recursive=False)
        self.artefacts.append((tar_path, _sha256(tar_path)))
        dbs = ["/lib/apk/db", "/etc/apk/world"] if self.mgr == "apk" else ["/var/lib/rpm"]
        self.db_backups = []
        for i, d in enumerate(dbs):
            real = os.path.realpath(self.path(d))  # newer rpm systems: /var/lib/rpm -> /usr/lib/sysimage/rpm
            dest = os.path.join(self.dir, f"db{i}")
            (shutil.copytree if os.path.isdir(real) else shutil.copy2)(real, dest)
            self.db_backups.append((d, dest, _tree_sha256(dest), real))
        self.step("rollback snapshot saved", ok=True,
                  output=f"{len(self.old_paths)} owned paths, package database; sha256 {self.artefacts[0][1]}")

    def _save_debs(self):
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

    # --- change -------------------------------------------------------------

    def apply(self):
        if self.mgr == "apt":
            self.step("upgrade", ["apt-get", "install", "-y", "--only-upgrade", "--no-remove",
                                  "-o", "Dpkg::Options::=--force-confold", *self.targets()])
            out = self.step("package database check", ["dpkg", "--audit"])
            if out.strip():
                self.step("package database consistent", ok=False, output=out)
        elif self.mgr == "apk":
            try:
                self.step("upgrade", ["apk", "add", "--upgrade", *self.targets()])
            finally:  # `apk add` would also record these packages (and pins) in the world file: keep it as it was
                world_bak = next(b for d, b, *_ in self.db_backups if d == "/etc/apk/world")
                shutil.copy2(world_bak, self.path("/etc/apk/world"))
        elif self.mgr == "zypper":
            try:
                self.step("upgrade", ["zypper", "--non-interactive", "install", "--no-recommends", *self.targets()])
            finally:
                self._snap_post()
        else:
            self.step("upgrade", ["dnf", "upgrade", "-y", *self.targets()])
        self.result_versions = self.versions()
        if self.fail_after_apply:
            self.step("injected failure (sandbox test)", ok=False, output="--fail-after-apply")

    def rollback(self):
        for path, digest in self.artefacts:
            self.step("rollback artefact intact " + os.path.basename(path), ok=os.path.exists(path) and _sha256(path) == digest,
                      output="sha256 mismatch or missing")
        if self.mgr == "apt":
            self.step("rollback install", ["dpkg", "-i", *[p for p, _ in self.artefacts]])
        elif getattr(self, "snap_pre", None):
            self._snap_post()
            self.step("snapper undo of all changes", ["snapper", "-c", "root", "undochange", f"{self.snap_pre}..{self.snap_post}"])
        else:
            for d, bak, digest, _real in self.db_backups:
                self.step(f"database backup intact {d}", ok=_tree_sha256(bak) == digest, output="sha256 mismatch")
            added = sorted(self.owned_paths() - self.old_paths, reverse=True)  # files the new version brought in
            for p in added:
                real = self.path(p)
                if os.path.islink(real) or os.path.isfile(real):
                    os.remove(real)
                elif os.path.isdir(real):
                    try:
                        os.rmdir(real)  # only if empty; shared dirs stay
                    except OSError:
                        pass
            with tarfile.open(self.artefacts[0][0]) as tar:
                kw = {"filter": "fully_trusted"} if hasattr(tarfile, "fully_trusted_filter") else {}  # our own, sha-verified
                tar.extractall(self.root, **kw)  # noqa: S202 — exact restore needs owners/setuid; archive verified above
            for _d, bak, _, real in self.db_backups:
                if os.path.isdir(bak):
                    shutil.rmtree(real)
                    shutil.copytree(bak, real)
                else:
                    shutil.copy2(bak, real)
            self.step("rollback restore", ok=True, output=f"removed {len(added)} new paths, restored files and package database")
        now_v = self.versions()
        bad = [p["name"] for p in self.pkgs if now_v.get(p["name"]) != p["from"]]
        self.step("versions restored", ok=not bad, output=("mismatch: " + ", ".join(bad)) if bad else "all restored")
        for u in self.units:  # a service the bad version crashed stays down until restarted on the restored files
            if self.run(["systemctl", "is-active", "--quiet", u])[0] != 0:
                rc, out = self.run(["systemctl", "restart", u])
                self.steps.append({"step": f"restart {u} on the restored version", "ok": rc == 0, "output": out[-500:]})
        if self.units and self.settle:
            time.sleep(self.settle)  # let restarted services come back before judging
        self.health("after rollback")

    def execute(self):
        """Returns (outcome, steps, error). outcome: applied | rolled_back | rollback_failed | aborted."""
        try:  # prechecks: a failure here means nothing was changed
            ok = (self.mgr in TOOLS and bool(self.pkgs)
                  and all(SAFE_NAME.match(str(p.get("name", ""))) and SAFE_VERSION.match(str(p.get("from", ""))) for p in self.pkgs)
                  and all(SAFE_VERSION.match(str(p["to"])) for p in self.pkgs if p.get("to"))
                  and all(SAFE_NAME.match(str(u)) for u in self.units))
            self.step("job validated", ok=ok, output="" if ok else "unsupported manager, or invalid package name, version or unit")
            tool = TOOLS[self.mgr]
            self.step(f"{tool} available", [tool, "--version"])
            cur = self.versions()
            drift = [p["name"] for p in self.pkgs if cur.get(p["name"]) != p["from"]]
            self.step("installed versions match plan", ok=not drift, output=("drifted: " + ", ".join(drift)) if drift else "")
            self.health("before change")
            self.step("refresh package index", {"apt": ["apt-get", "update"], "apk": ["apk", "update"],
                                                "dnf": ["dnf", "makecache"],
                                                "zypper": ["zypper", "--non-interactive", "refresh"]}[self.mgr])
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


def _tree_sha256(path):
    """sha256 over a file, or over every file (name + content) under a directory."""
    if os.path.isfile(path):
        return _sha256(path)
    h = hashlib.sha256()
    for base, dirs, files in os.walk(path):
        dirs.sort()
        for fn in sorted(files):
            fp = os.path.join(base, fn)
            h.update(os.path.relpath(fp, path).encode() + b"\0" + _sha256(fp).encode())
    return h.hexdigest()


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


OUTCOME_DIR = (os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "Nimstead", "outcomes") if os.name == "nt"
               else "/var/lib/nimstead/outcomes")


def run_jobs(server, key, insecure_http, run=sh, outcome_dir=None, win_state=None, **job_kw):
    """Execute jobs, persisting every outcome before reporting so none is lost if the report fails.
    Unsent outcomes from earlier runs are retried first.
    Returns (number of jobs not applied or not reported, whether a reboot is needed to continue a Windows job)."""
    outcome_dir = outcome_dir or OUTCOME_DIR
    win_state = win_state or WIN_STATE
    os.makedirs(outcome_dir, mode=0o700, exist_ok=True)
    problems = 0

    def send(path):
        nonlocal problems
        try:
            with open(path) as f:
                rec = json.load(f)
            if not SAFE_NAME.match(str(rec.get("id"))):
                raise ValueError("bad job id")
        except (OSError, ValueError, AttributeError) as e:
            os.replace(path, path + ".invalid")
            print(f"outcome file {path} is unreadable or invalid ({e}); set aside", file=sys.stderr)
            problems += 1
            return
        try:
            post(server, "/api/agent/jobs/{}/report".format(rec["id"]), rec["report"], insecure_http, key)
            os.remove(path)
        except AgentError as e:
            if " 409:" in str(e) or " 404:" in str(e):  # server no longer accepts it; keep a local copy, stop retrying
                os.replace(path, path + ".rejected")
            print("job {}: report failed: {}".format(rec["id"], e), file=sys.stderr)
            problems += 1

    def record(job_id, report):
        nonlocal problems
        path = os.path.join(outcome_dir, re.sub(r"[^A-Za-z0-9]", "", str(job_id)) + ".json")
        with open(path, "w") as f:
            json.dump({"id": job_id, "report": report}, f)
        print("job {}: {}{}".format(job_id, report["outcome"], f" ({report['error']})" if report.get("error") else ""))
        problems += report["outcome"] != "applied"
        send(path)

    for path in sorted(glob.glob(os.path.join(outcome_dir, "*.json"))):
        send(path)
    if os.name == "nt" and os.path.exists(win_state):  # a Windows job is mid-flight across a reboot: finish it first
        try:
            w = WinJob(run=run, state_path=win_state)
        except (AgentError, OSError, ValueError) as e:
            os.replace(win_state, win_state + ".invalid")
            print(f"pending Windows job not resumed: {e}; set aside, host needs attention", file=sys.stderr)
            problems += 1
        else:
            res = w.advance()
            if res["outcome"] == "pending_reboot":
                return problems, True
            record(w.s["job"]["id"], res)
    for job in post(server, "/api/agent/jobs", None, insecure_http, key):
        try:
            runner = WinJob(job, run=run, state_path=win_state) if job.get("manager") == "windows" else Job(job, run=run, **job_kw)
        except Exception as e:  # malformed job from the server: report it, keep going
            record(job.get("id"), {"outcome": "aborted", "steps": [], "error": f"No changes made: malformed job: {e}"[:500],
                                   "versions": None})
            continue
        if isinstance(runner, WinJob):
            res = runner.advance()
            if res["outcome"] == "pending_reboot":
                return problems, True  # the server keeps it dispatched; the next run after the reboot reports it
            record(job.get("id"), res)
            continue
        j = runner
        outcome, steps, error = j.execute()
        record(job.get("id"), {"outcome": outcome, "steps": steps, "error": error, "versions": getattr(j, "result_versions", None)})
    return problems, False


# ---- Windows remediation -------------------------------------------------------
# One cumulative update by KB through the Windows Update Agent, run as SYSTEM. It needs a reboot, so the job is a
# small state machine persisted to disk: apply -> reboot -> verify/health -> done, or -> remove the new package with
# DISM -> reboot -> verify the original build is back. Rollback = DISM removal of the newly added RollupFix package;
# if Windows marks that package permanent the change can't be undone, which is reported loudly, never as success.

WIN_STATE = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "Nimstead", "pending-job.json")
SAFE_KB = re.compile(r"^[0-9]{6,8}$")
# DISM/CBS "busy" results: servicing still running (RPC disconnected, CBS busy/pending, file in use)
DISM_TRANSIENT = ("0x80010108", "0x800f0816", "0x800f082f", "0x80070020", "0x800f0805", "0x80004005")
DISM_RETRIES = 15
SAFE_PRODUCT = re.compile(r"^Windows [A-Za-z0-9 .()-]{1,120}$")
ROLLUP = re.compile(r"Package Identity : (Package_for_RollupFix~[^\s]+)\s+State : ([A-Za-z ]+)")
ROLLUP_NAME = re.compile(r"^Package_for_RollupFix~[A-Za-z0-9._~-]{1,200}$")
TRUSTED_OWNERS = {"S-1-5-18", "S-1-5-32-544"}  # SYSTEM, Administrators

PS_FIND = r"""
$s = New-Object -ComObject Microsoft.Update.Session
$r = $s.CreateUpdateSearcher().Search("IsInstalled=0 and Type='Software'")
ConvertTo-Json -Compress -InputObject @($r.Updates | Where-Object { $_.KBArticleIDs -contains '%KB%' } | ForEach-Object {
  [pscustomobject]@{ title = $_.Title; uninstallable = $_.IsUninstallable; reboot = $_.InstallationBehavior.RebootBehavior } })
"""
PS_DOWNLOAD = r"""
$s = New-Object -ComObject Microsoft.Update.Session
$r = $s.CreateUpdateSearcher().Search("IsInstalled=0 and Type='Software'")
$c = New-Object -ComObject Microsoft.Update.UpdateColl
$r.Updates | Where-Object { $_.KBArticleIDs -contains '%KB%' } | ForEach-Object { [void]$c.Add($_) }
if ($c.Count -ne 1) { throw "expected exactly one update for KB%KB%, found $($c.Count)" }
$d = $s.CreateUpdateDownloader(); $d.Updates = $c; [int]$d.Download().ResultCode
"""
# Whether the downloaded package is permanent, read from its own top-level manifest (update.mum) BEFORE installing.
# WUA's IsUninstallable can't be used: on Server 2025 it says False for cumulative updates that DISM removes fine.
# Newer cumulative updates arrive as a .wim (mounted read-only), older ones as a .cab. Anything else: can't tell -> fail.
PS_PERMANENCE = r"""
$f = Get-ChildItem C:\Windows\SoftwareDistribution\Download -Recurse -Depth 1 -File -Include '*KB%KB%*.wim','*KB%KB%*.cab' |
  Where-Object { $_.FullName -notmatch '\\Metadata\\' } | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $f) { throw "downloaded package for KB%KB% not found" }
$tmp = Join-Path $env:ProgramData ('Nimstead\mum-' + [guid]::NewGuid()); New-Item -ItemType Directory $tmp | Out-Null
try {
  if ($f.Extension -eq '.wim') {
    dism /mount-wim "/wimfile:$($f.FullName)" /index:1 "/mountdir:$tmp" /readonly /english | Out-Null
    if ($LASTEXITCODE) { throw "mounting $($f.Name) failed: $LASTEXITCODE" }
  } else { expand.exe "-F:*.mum" $f.FullName $tmp | Out-Null }
  $x = [xml](Get-Content -LiteralPath (Join-Path $tmp 'update.mum') -Raw -ErrorAction Stop)
  $parts = @(Get-ChildItem -LiteralPath $tmp -File -Filter *.mum | Select-String -Pattern 'permanence="permanent"' -List | ForEach-Object { $_.Filename })
  [pscustomobject]@{ file = $f.Name; permanent = (@($x.assembly.permanence, $x.assembly.package.permanence) -contains 'permanent');
                     permanent_parts = $parts } | ConvertTo-Json -Compress
} finally {
  if ($f.Extension -eq '.wim') { dism /unmount-wim "/mountdir:$tmp" /discard | Out-Null }
  Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
"""
PS_INSTALL = r"""
$s = New-Object -ComObject Microsoft.Update.Session
$r = $s.CreateUpdateSearcher().Search("IsInstalled=0 and Type='Software'")
$c = New-Object -ComObject Microsoft.Update.UpdateColl
$r.Updates | Where-Object { $_.KBArticleIDs -contains '%KB%' } | ForEach-Object { if (-not $_.EulaAccepted) { $_.AcceptEula() }; [void]$c.Add($_) }
if ($c.Count -ne 1) { throw "expected exactly one update for KB%KB%, found $($c.Count)" }
$d = $s.CreateUpdateDownloader(); $d.Updates = $c; $dr = $d.Download()
$i = $s.CreateUpdateInstaller(); $i.Updates = $c; $ir = $i.Install()
[pscustomobject]@{ download = [int]$dr.ResultCode; install = [int]$ir.ResultCode; reboot = $ir.RebootRequired } | ConvertTo-Json -Compress
"""
PS_REBOOT_PENDING = r"""
(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
"""


def ps(run, script):
    return run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script])


def windows_build():
    import winreg
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", 0,
                        winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
        return "10.0.{}.{}".format(int(winreg.QueryValueEx(k, "CurrentBuild")[0]), int(winreg.QueryValueEx(k, "UBR")[0]))


class WinJob:
    """Phases: start -> (reboot) -> verify -> done | rollback -> (reboot) -> rolled_back. State lives in WIN_STATE."""

    def __init__(self, job=None, run=sh, state_path=WIN_STATE, build=windows_build, settle=None, fail_after_apply=False,
                 retry_wait=60):
        self.run, self.state_path, self.build, self.retry_wait = run, state_path, build, retry_wait
        if job is not None:
            p = (job.get("packages") or [{}])[0]
            self.s = {"job": job, "phase": "start", "steps": [], "kb": str(p.get("kb", "")), "from": p.get("from"),
                      "to": p.get("to"), "product": p.get("name"), "units": job.get("health_units") or [],
                      "settle": min(max(int(job.get("settle_seconds", 60) or 0), 0), 900) if settle is None else int(settle),
                      "inject": bool(fail_after_apply)}  # sandbox fault injection (run-job only; never from the server)
        else:
            with open(state_path) as f:
                self.s = json.load(f)
            if not self.valid():  # never trust the file: it decides what runs as SYSTEM after the reboot
                raise AgentError(f"{state_path} failed validation; not resumed")

    def valid(self):
        s = self.s
        try:
            return bool(
                s.get("phase") in ("start", "verify", "rolled_back_pending") and isinstance(s.get("steps"), list)
                and SAFE_KB.match(str(s.get("kb", ""))) and SAFE_PRODUCT.match(str(s.get("product")))
                and SAFE_VERSION.match(str(s.get("from") or "")) and (s.get("to") is None or SAFE_VERSION.match(str(s["to"])))
                and isinstance(s.get("units"), list) and all(SAFE_NAME.match(str(u)) for u in s["units"])
                and isinstance(s.get("settle"), int) and 0 <= s["settle"] <= 900
                and all(ROLLUP_NAME.match(str(x)) for x in [*s.get("new_packages", []), *s.get("baseline", {})]))
        except (TypeError, AttributeError):
            return False

    # -- plumbing
    def save(self):
        os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
        with open(self.state_path, "w") as f:
            json.dump(self.s, f)  # inherits the locked-down folder ACL (secure_windows_dir)

    def clear(self):
        if os.path.exists(self.state_path):
            os.remove(self.state_path)

    def step(self, name, ok, output=""):
        self.s["steps"].append({"step": name, "ok": bool(ok), "output": str(output)[-1500:]})
        if not ok:
            raise StepFailed(f"{name} failed: {str(output)[-300:].strip()}")

    def result(self, outcome, error=None):
        self.clear()
        return {"outcome": outcome, "steps": self.s["steps"], "error": error,
                "versions": {self.s["product"]: self.build()} if outcome == "applied" else None}

    def pending(self):
        self.save()
        return {"outcome": "pending_reboot", "steps": self.s["steps"], "error": None, "versions": None}

    def rollups(self):
        rc, out = self.run(["dism", "/online", "/get-packages", "/format:list", "/english"])
        if rc != 0:
            raise StepFailed("dism /get-packages failed: " + out[-300:])
        return dict(ROLLUP.findall(out.replace("\r", "")))

    def health(self, when):
        for u in self.s["units"]:
            rc, out = ps(self.run, f"(Get-Service -Name '{u}' -ErrorAction Stop).Status")
            self.step(f"{u} running {when}", rc == 0 and out.strip() == "Running", out)

    # -- phases
    def advance(self):
        """Run until finished or until a reboot is needed. Returns a report dict (outcome may be pending_reboot)."""
        phase = self.s["phase"]
        try:
            if phase == "start":
                return self._start()
            if phase == "verify":
                return self._verify()
            if phase == "rolled_back_pending":
                return self._after_rollback()
            raise StepFailed(f"unknown phase {phase}")
        except Exception as e:
            now = self.s["phase"]  # where we were when it failed decides what is safe
            if now == "start":
                return self.result("aborted", f"No changes made: {e}")
            if now == "verify":
                return self._rollback(str(e))
            return self.result("rollback_failed", f"ROLLBACK FAILED, host needs attention: {e}")

    def _start(self):
        s = self.s
        ok = self.valid()
        self.step("job validated", ok, "" if ok else "invalid KB, product, version or service name")
        cur = self.build()
        self.step("installed build matches plan", cur == s["from"], f"installed {cur}, planned {s['from']}")
        rc, out = ps(self.run, PS_REBOOT_PENDING)
        self.step("no reboot already pending", rc == 0 and out.strip().lower() == "false", out)
        self.health("before change")
        rc, out = ps(self.run, PS_FIND.replace("%KB%", s["kb"]))
        offered = json.loads(out) if rc == 0 and out.strip().startswith("[") else []
        self.step(f"Windows Update offers exactly KB{s['kb']}", len(offered) == 1, out)
        s["baseline"] = self.rollups()
        self.step("rollback baseline recorded", any(v.strip() == "Installed" for v in s["baseline"].values()),
                  "installed cumulative packages: " + ", ".join(k for k, v in s["baseline"].items() if v.strip() == "Installed"))
        rc, out = ps(self.run, PS_DOWNLOAD.replace("%KB%", s["kb"]))
        self.step(f"KB{s['kb']} downloaded", rc == 0 and out.strip().splitlines()[-1:] in (["2"], ["3"]), out)
        rc, out = ps(self.run, PS_PERMANENCE.replace("%KB%", s["kb"]))
        perm = json.loads(out) if rc == 0 and out.strip().startswith("{") else {}
        # permanent sub-packages (Features on Demand) stay behind on removal; rollback is judged by the build returning
        self.step("update is removable (manifest checked before install)", perm.get("permanent") is False,
                  out if perm.get("permanent") is not False else
                  f"{perm['file']}: update.mum not permanent; permanent parts: {', '.join(perm.get('permanent_parts') or []) or 'none'}")
        rc, out = ps(self.run, PS_INSTALL.replace("%KB%", s["kb"]))
        res = json.loads(out) if rc == 0 and out.strip().startswith("{") else {}
        s["phase"] = "verify"  # from here on, failures roll back
        self.step(f"KB{s['kb']} downloaded and installed", res.get("install") in (2, 3), out)
        new = sorted(set(self.rollups()) - set(s["baseline"]))
        s["new_packages"] = new
        self.step("new cumulative package identified", len(new) >= 1, ", ".join(new) or "none")
        if res.get("reboot"):
            self.s["steps"].append({"step": "reboot required to finish", "ok": True, "output": ""})
            return self.pending()
        return self._verify()

    def _verify(self):
        s = self.s
        cur = self.build()
        reached = (windows_version_key(cur) >= windows_version_key(s["to"])) if s.get("to") else cur != s["from"]
        self.step("build updated", reached, f"now {cur}, target {s.get('to')}")
        if s["units"] and s["settle"]:
            time.sleep(s["settle"])
        self.health("after change")
        if s.get("inject"):
            self.step("injected failure (sandbox test)", False, "--fail-after-apply")
        return self.result("applied")

    def _rollback(self, err):
        s = self.s
        s["error"] = err
        try:
            for pkg in s.get("new_packages", []):
                # Right after the reboot Windows is still finalising the update and DISM fails with transient
                # errors (seen for real: 0x80010108 at +30 s, success 13 min later). Retry those; fail on anything else.
                for attempt in range(1, DISM_RETRIES + 1):
                    rc, out = self.run(["dism", "/online", "/remove-package", f"/packagename:{pkg}", "/quiet", "/norestart"])
                    if rc in (0, 3010) or not any(code in out for code in DISM_TRANSIENT) or attempt == DISM_RETRIES:
                        break
                    self.s["steps"].append({"step": f"servicing busy, retry {attempt} removing {pkg}", "ok": True, "output": out[-300:]})
                    time.sleep(self.retry_wait)
                self.step(f"remove {pkg}", rc in (0, 3010), out)  # 3010 = success, reboot required
            s["phase"] = "rolled_back_pending"
            self.s["steps"].append({"step": "reboot required to finish rollback", "ok": True, "output": ""})
            return self.pending()
        except Exception as e:
            return self.result("rollback_failed", f"ROLLBACK FAILED, host needs attention. Change error: {err}; rollback error: {e}")

    def _after_rollback(self):
        s = self.s
        cur = self.build()
        if cur != s["from"]:
            return self.result("rollback_failed", f"ROLLBACK FAILED: build is {cur}, expected {s['from']}. Change error: {s.get('error')}")
        self.s["steps"].append({"step": "original build restored", "ok": True, "output": cur})
        try:
            self.health("after rollback")
        except StepFailed as e:
            return self.result("rollback_failed", f"ROLLBACK FAILED: {e}")
        return self.result("rolled_back", f"Change failed and was rolled back: {s.get('error')}")


def windows_version_key(v):
    return tuple(int(x) for x in str(v).split("."))


# ---- network ----------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):  # never forward the agent key to another URL
        return None


_opener = urllib.request.build_opener(_NoRedirect)


class run_lock:
    """Single remediation run at a time (cron/timer overlap)."""

    def __enter__(self):
        d = os.path.dirname(WIN_STATE) if os.name == "nt" else "/var/lib/nimstead"
        os.makedirs(d, exist_ok=True)
        self.f = open(os.path.join(d, "agent.lock"), "w")
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.f.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
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
    if os.name == "nt":  # chmod is a no-op on Windows and ProgramData is readable by all users
        try:
            secure_windows_dir(d=os.path.dirname(p))
        except AgentError:
            os.remove(p)
            raise
    return p


PS_OWNERS = r"""
Get-ChildItem -LiteralPath '%DIR%' -Recurse -Force | ForEach-Object {
  $_.FullName + '|' + (Get-Acl -LiteralPath $_.FullName).GetOwner([Security.Principal.SecurityIdentifier]).Value }
"""


def secure_windows_dir(run=sh, d=None):
    """ProgramData lets every user create files, and a file planted in our folder would be read by the SYSTEM task
    (a pending job decides what runs after a reboot). So: anything in it not owned by SYSTEM or Administrators is
    removed and reported, then Administrators own everything and only SYSTEM and Administrators have access.
    Returns the paths removed."""
    d = d or os.path.dirname(WIN_STATE)
    os.makedirs(d, exist_ok=True)
    rc, out = ps(run, PS_OWNERS.replace("%DIR%", d.replace("'", "''")))
    if rc != 0:
        raise AgentError(f"cannot read owners in {d}: {out.strip()[-300:]}")
    removed = []
    for line in out.splitlines():
        path, _, sid = line.strip().rpartition("|")
        if path and sid not in TRUSTED_OWNERS and os.path.exists(path):
            shutil.rmtree(path, ignore_errors=True) if os.path.isdir(path) else os.remove(path)
            removed.append(path)
    cmds = [["icacls", d, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "/Q"],
            ["icacls", d, "/setowner", "*S-1-5-32-544", "/T", "/C", "/Q"]]
    if os.listdir(d):  # children: drop any explicit ACEs, inherit only the folder's
        cmds.append(["icacls", os.path.join(d, "*"), "/reset", "/T", "/C", "/Q"])
    for cmd in cmds:
        rc, out = run(cmd)
        if rc != 0:
            raise AgentError(f"could not lock down {d}: {out.strip()[-300:]}")
    for path in removed:
        print(f"removed {path}: not created by SYSTEM or Administrators", file=sys.stderr)
    return removed


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
    sub.add_parser("resume-job", help="Windows: continue the pending job after its reboot (no network)")
    rj.add_argument("--fail-after-apply", action="store_true", help="sandbox testing: force a failure after the change to exercise rollback")
    a = ap.parse_args(argv)
    try:
        if os.name == "nt" and a.cmd in ("report", "remediate", "resume-job"):  # before reading anything from the folder
            secure_windows_dir()
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
            job = json.load(sys.stdin)
            if job.get("manager") == "windows":
                res = WinJob(job, fail_after_apply=a.fail_after_apply).advance()
                print(json.dumps(res))
                return 0 if res["outcome"] in ("applied", "pending_reboot") else 2
            j = Job(job, fail_after_apply=a.fail_after_apply)
            outcome, steps, error = j.execute()
            print(json.dumps({"outcome": outcome, "steps": steps, "error": error, "versions": getattr(j, "result_versions", None)}))
            return 0 if outcome == "applied" else 2
        elif a.cmd == "resume-job":  # Windows: continue a job after the reboot it asked for
            if not os.path.exists(WIN_STATE):
                raise AgentError("no pending job")
            res = WinJob().advance()
            print(json.dumps(res))
            return 0 if res["outcome"] in ("applied", "pending_reboot", "rolled_back") else 2
        elif a.cmd == "remediate":
            cfg = load_config()
            if not cfg.get("allow_remediation"):
                raise AgentError("remediation is not enabled on this host (re-enroll with --allow-remediation)")
            with run_lock():
                problems, reboot = run_jobs(cfg["server"], cfg["agent_key"], a.insecure_http)
                if reboot:  # Windows update needs a restart; the startup run resumes the job and reports it
                    print("restarting to finish the update")
                    rc, out = sh(["shutdown", "/r", "/t", "60", "/c", "Nimstead: finishing a security update"])
                    if rc != 0:
                        raise AgentError(f"could not schedule the restart the update needs: {out.strip()}")
                    return 0
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
