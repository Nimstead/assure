#!/usr/bin/env python3
"""Nimstead agent: reports installed packages to the server. Single file, stdlib only, Python 3.9+.

  nimstead_agent.py enroll --server https://host --token TOKEN
  nimstead_agent.py report
  nimstead_agent.py collect          # print inventory JSON, no network
  nimstead_agent.py remediate        # run approved jobs (host must opt in at enroll)
  nimstead_agent.py doctor           # check this host's setup and say how to fix it; changes nothing
"""

import argparse
import base64
import email.utils
import glob
import hashlib
import io
import json
import os
import platform
import re
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

AGENT_VERSION = "0.4.0"  # the server reads this line to flag outdated agents; bump on every agent change
# Ed25519 public keys (hex) allowed to sign releases (DECISIONS 31): primary (GitHub Actions) and offline backup.
# The server only relays signed releases, so it can withhold an update but never forge one. Empty = never self-update.
RELEASE_KEYS = ["a91fa6539c6c2593009fc71b1c1fba341b5685ba7bc97c127c068b1d732b21d2", "2438f2ccebab5bf26edf9e21a8aa8f09abd1861f52fbe0d6641b28b90f8b0e5a"]  # noqa: E501
MAX_AGENT_BYTES = 5 * 1024 * 1024


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


def _query(cmd, timeout=600):
    """(exit status, stdout, stderr) of a read-only query; None when it couldn't run. Its status is reported, not just its output (R7.2)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout, env=dict(os.environ, LC_ALL="C"))
        return p.returncode, p.stdout, p.stderr
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, "", str(e)


OS_RELEASE = ("/etc/os-release", "/usr/lib/os-release")  # os-release(5): the first that exists, and only it
APK_DB = "/lib/apk/db/installed"
DPKG_QUERY = ["dpkg-query", "-W", "-f", "${Package}\t${Version}\t${source:Package}\t${db:Status-Abbrev}\n"]
RPM_QUERY = ["rpm", "-qa", "--qf", "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{SOURCERPM}\n"]
NOTIFY_REBOOT = "/usr/share/update-notifier/notify-reboot-required"  # Debian/Ubuntu: what writes the flag below, when installed
REBOOT_FLAG = "/run/reboot-required"


def package_db(query=_query, apk_db=APK_DB, which=shutil.which):
    """(packages, collection line): the package database read directly in a fixed format. A cut-short or failed read says so;
    an empty one is sent as read, and the server calls it a failure (DECISIONS 80)."""
    if os.path.exists(apk_db):
        try:
            with open(apk_db) as f:
                text = f.read()
        except OSError as e:
            return [], _source(0, f"{apk_db}: {e}")
        pkgs = parse_apk(text)
        bad = sum(1 for b in text.split("\n\n") if b.strip() and not ("\nP:" in "\n" + b and "\nV:" in "\n" + b))
        return pkgs, {**_source(len(pkgs), f"{bad} entries couldn't be read" if bad else None), "exit": 0}
    if which("dpkg-query"):
        cmd, parse, tabs = DPKG_QUERY, parse_dpkg, 3
    elif which("rpm"):
        cmd, parse, tabs = RPM_QUERY, parse_rpm, 2
    else:
        return [], _source(0, "no package database found (dpkg-query, rpm or the apk database)")
    rc, out, err = query(cmd)
    pkgs = parse(out)
    bad = sum(1 for ln in out.splitlines() if ln and ln.count("\t") != tabs)
    last = (err.strip().splitlines() or [""])[-1]
    problem = f"{bad} lines couldn't be read" if bad else None
    if rc != 0:
        problem = (f"{cmd[0]} couldn't run" if rc is None else f"{cmd[0]} exited {rc}") + (f": {last}" if last else "")
    return pkgs, {**_source(len(pkgs), problem), **({"exit": rc} if rc is not None else {})}


def reboot_pending(query=_query, which=shutil.which, exists=os.path.exists):
    """True or False only where the distro says so; None when it doesn't (no flag mechanism installed)."""
    if exists(NOTIFY_REBOOT):
        return exists(REBOOT_FLAG)
    if which("needs-restarting"):  # dnf-utils / yum-utils: exit 1 means a reboot is needed
        rc = query(["needs-restarting", "-r"], timeout=120)[0]
        return {0: False, 1: True}.get(rc)
    return None


def collect_linux(query=_query, files=OS_RELEASE, apk_db=APK_DB, which=shutil.which, kernel=None):
    """What the host is, its packages and how far the read got (R7.1, R7.2, R4.3). An unknown platform is reported, never silence."""
    text, problem = "", "no os-release file"
    for path in files:
        if os.path.exists(path):
            try:
                with open(path) as f:
                    text, problem = f.read(), None
            except OSError as e:
                problem = f"{path}: {e}"
            break
    r = parse_os_release(text)
    eco = ecosystem_from_os_release(text)
    pkgs, db = package_db(query, apk_db, which)
    facts = {"os_id": r.get("ID", ""), "os_version_id": r.get("VERSION_ID", ""), "kernel_release": kernel or os.uname().release,
             "pending_reboot": reboot_pending(query, which)}
    if not eco:
        facts["os_unmatched"] = f"no advisory feed maps this platform: ID={r.get('ID', '?')} VERSION_ID={r.get('VERSION_ID', '?')}"[:300]
    return {"os_name": r.get("PRETTY_NAME") or r.get("NAME", ""), "ecosystem": eco, "agent_version": AGENT_VERSION, "facts": facts,
            "collection": {"v": 1, "sources": {"os_release": _source(1 if text else 0, problem), "package_db": db}},
            "packages": [dict(p, ecosystem=eco) for p in pkgs]}


# MSRC names Windows Server by build; client names come from the feature-update version.
_SERVER_BY_BUILD = {9200: "Windows Server 2012", 9600: "Windows Server 2012 R2", 14393: "Windows Server 2016",
                    17763: "Windows Server 2019", 20348: "Windows Server 2022", 26100: "Windows Server 2025",
                    25398: "Windows Server 2022, 23H2 Edition"}  # 23H2: the Annual Channel, Server Core only
_MSRC_ARCH = {"AMD64": "x64-based", "X86": "32-bit", "ARM64": "ARM64-based"}


def msrc_product_name(build, display_version, installation_type, machine):
    """MSRC product name for this OS, or '' if we cannot name it exactly (refuse to guess).

    Insider and other unlisted builds are unmapped: the host still reports apps and says why (collect_windows)."""
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


USER_SID = re.compile(r"^S-1-5-21-[0-9-]+\Z")


def _read_problem(where, e):
    """A failed read in words we write ourselves: the state comes from the error's type, never its translated text (DECISIONS 68, 80)."""
    denied = isinstance(e, PermissionError) or getattr(e, "winerror", None) == 5
    return f"{where}: access denied" if denied else f"{where}: {type(e).__name__} {getattr(e, 'winerror', '') or ''}".strip()


def _list_ended(e):
    """winreg ends every enumeration with an OSError; only ERROR_NO_MORE_ITEMS means the list was read to its end."""
    return getattr(e, "winerror", None) in (None, 259)


def windows_apps(reg, users=None, problems=None):
    """Installed apps from the registry Uninstall keys: HKLM 64-bit and 32-bit views, then every loaded user hive
    (per-user installs such as VS Code (User); the agent runs as SYSTEM, whose own HKCU has none), then HKCU.
    Profiles of users who aren't signed in are read by offline_user_apps. `users`: only these HKU keys.
    `reg` is the winreg module (or a fake). Skips SystemComponent=1 and entries without a name or version.
    The publisher travels in `source`; the server decides which apps it can match (curated map only).
    `problems` gets a line for each read that failed, as against a key that simply isn't there (R4.3)."""
    seen, out = set(), []
    problems = problems if problems is not None else []
    if users is not None:
        places = [(reg.HKEY_USERS, u + "\\" + UNINSTALL, 0) for u in users]
    else:
        places = [(reg.HKEY_LOCAL_MACHINE, UNINSTALL, reg.KEY_WOW64_64KEY), (reg.HKEY_LOCAL_MACHINE, UNINSTALL, reg.KEY_WOW64_32KEY)]
        places += [(reg.HKEY_USERS, sid + "\\" + UNINSTALL, 0) for sid in _subkeys(reg, reg.HKEY_USERS, "", problems) if USER_SID.match(sid)]
        places.append((reg.HKEY_CURRENT_USER, UNINSTALL, 0))
    for hive, path, view in places:
        try:
            root = reg.OpenKey(hive, path, 0, reg.KEY_READ | view)
        except FileNotFoundError:
            continue
        except OSError as e:
            problems.append(_read_problem(path, e))
            continue
        with root:
            i = 0
            while True:
                try:
                    sub = reg.EnumKey(root, i)
                except OSError as e:
                    if not _list_ended(e):
                        problems.append(_read_problem(path, e))
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
                except FileNotFoundError:  # uninstalled while we read
                    continue
                except OSError as e:
                    problems.append(_read_problem(path + "\\" + sub, e))
                    continue
                if sysc == 1 or not isinstance(name, str) or not isinstance(ver, str) or not name.strip() or not ver.strip():
                    continue
                pub = pub.strip()[:255] if isinstance(pub, str) and pub.strip() else None
                item = (name.strip()[:255], ver.strip()[:255], pub)
                if item not in seen:
                    seen.add(item)
                    out.append({"ecosystem": "WinApp", "name": item[0], "version": item[1], "source": pub})
    return sorted(out, key=lambda p: (p["name"], p["version"]))


PROFILES = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"


def offline_user_apps(reg, run=None, loaded=None, problems=None):
    """Per-user apps of profiles whose hive isn't loaded (users not signed in): each NTUSER.DAT is loaded under a
    temporary HKU key, its Uninstall key read with windows_apps, and unloaded at once, also on error, so a user signing
    in a moment later still gets their own profile. Needs SYSTEM or an elevated admin; otherwise nothing is read,
    and `problems` says which profiles."""
    run = run or sh
    problems = problems if problems is not None else []
    loaded = set(loaded if loaded is not None else _subkeys(reg, reg.HKEY_USERS, "", problems))
    out = []
    for sid in _subkeys(reg, reg.HKEY_LOCAL_MACHINE, PROFILES, problems):
        if not USER_SID.match(sid) or sid in loaded:
            continue
        try:
            with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, PROFILES + "\\" + sid) as k:
                home = os.path.expandvars(str(reg.QueryValueEx(k, "ProfileImagePath")[0]))
        except OSError as e:
            problems.append(_read_problem("profile " + sid, e))
            continue
        hive = os.path.join(home, "NTUSER.DAT")
        if not os.path.isfile(hive):  # a profile that was never used has no hive and no apps
            continue
        if is_link(home):
            problems.append(f"profile {sid}: its folder is a link, not read")
            continue
        tmp = "NimsteadOffline_" + sid.replace("-", "_")
        rc, _ = run(["reg", "load", "HKU\\" + tmp, hive])
        if rc != 0:  # in use (signed in after all) or no privilege: skip it
            problems.append(f"profile {sid}: its hive couldn't be loaded")
            continue
        try:
            out += windows_apps(reg, users=[tmp], problems=problems)
        finally:
            run(["reg", "unload", "HKU\\" + tmp])
    return out


def _subkeys(reg, root, path, problems=None):
    problems = problems if problems is not None else []
    try:
        k = reg.OpenKey(root, path) if path else root
    except FileNotFoundError:
        return []
    except OSError as e:
        problems.append(_read_problem(path or "HKEY_USERS", e))
        return []
    names, i = [], 0
    while True:
        try:
            names.append(reg.EnumKey(k, i))
        except OSError as e:
            if not _list_ended(e):
                problems.append(_read_problem(path or "HKEY_USERS", e))
            return names
        i += 1


def collect_windows(winreg=None, run=None, machine=None, dotnet_dirs=None):
    """This host, or with the arguments another one over PowerShell remoting (collect_remote)."""
    remote = winreg is not None
    if not remote:
        import winreg
    build, ubr, dv, product, itype, edition, read_error = 0, None, "", "", "", "", None
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", 0,
                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            def val(name, default=""):
                try:
                    return winreg.QueryValueEx(k, name)[0]
                except OSError:
                    return default
            build, ubr = int(val("CurrentBuild", 0) or 0), val("UBR", None)
            dv = val("DisplayVersion") or val("ReleaseId")
            product, itype = val("ProductName"), val("InstallationType")
            edition = val("EditionID")
    except OSError as e:  # still report the apps, and say the build wasn't read
        read_error = _read_problem(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", e)
    build_read = _source(0, read_error or "CurrentBuild not found", failed=True) if read_error or not build else None
    if build >= 10240 and ubr is None:
        build_read = _source(1, "UBR not found: the build's revision is unknown")
    ubr = int(ubr or 0)
    machine = machine or platform.machine()
    name = msrc_product_name(build, dv, itype, machine)
    version = f"10.0.{build}.{ubr}"
    if build >= 22000:
        product = product.replace("Windows 10", "Windows 11")
    facts = {"edition_id": edition, "installation_type": itype, "esu": esu_active(name, run)}
    os_pkg = []
    if not name or not build:  # still report apps; the server shows why the OS isn't matched
        facts["os_unmatched"] = f"no exact MSRC product for {product} {dv} build {build} {itype} {machine}"
    elif build < 10240:  # 2012/R2 keep no update build revision: matched by end of support only, never by CVE
        facts["os_product"], facts["os_unmatched"] = name, f"{name} has no update build revision to compare with MSRC fixes"
    else:
        os_pkg = [{"ecosystem": "Windows", "name": name, "version": version, "source": None}]
    ms, ms_problem = windows_microsoft(winreg, run, dotnet_dirs)
    if ms_problem:
        facts["microsoft_check"] = ms_problem
    host, host_problem = windows_host_facts(run)
    facts.update(host)
    if host_problem:
        facts["host_check"] = host_problem
    drivers, driver_scan = windows_drivers(run)
    facts["driver_scan"] = driver_scan
    app_problems, hive_problems = [], []
    apps = windows_apps(winreg, problems=app_problems)
    offline = [] if remote else offline_user_apps(winreg, problems=hive_problems)
    unread = [k for k in ("pending_reboot", "baseline") if host.get(k) is None]
    # no judgement here: it only says what was read and how far it got (R4.3, spec section 14). The server decides what follows
    sources = {"windows_build": build_read or _source(len(os_pkg)),
               "uninstall": _source(len(apps), "; ".join(app_problems)),
               "user_hives": ({"state": "partial", "count": 0, "error": "profiles of users who aren't signed in aren't read over remoting"}
                              if remote else _source(len(offline), "; ".join(hive_problems))),
               "microsoft_products": _source(len(ms), ms_problem),
               "host_facts": _source(0, host_problem, failed=True) if host_problem else _source(len(host), f"not read: {', '.join(unread)}" if unread else None),
               "drivers": _source(len(drivers), None if driver_scan.get("complete") else driver_scan.get("problem") or "not every driver file was read")}
    return {"os_name": f"{product} {dv} ({machine}) build {version}", "ecosystem": "Windows", "agent_version": AGENT_VERSION,
            "facts": facts, "collection": {"v": 1, "sources": sources}, "packages": [*os_pkg, *apps, *offline, *ms, *drivers]}


def _source(count, problem=None, failed=False):
    """One line of the collection document: a list that was read and came back empty must not look like a read that failed (DECISIONS 80)."""
    d = {"state": "failed" if failed or (problem and not count) else "partial" if problem else "ok", "count": count}
    if problem:
        d["error"] = problem[:300]
        if "access denied" in problem:  # our own wording (_read_problem), never Windows'
            d["code"] = "access-denied"
    return d


# ---- agentless: an admin scans hosts from their own machine, as themselves. PowerShell remoting carries their identity,
# so no credential is typed, stored or sent to the server (DECISIONS 65). What comes back is treated like any agent's report.
PS_REMOTE_DUMP = r"""
$ErrorActionPreference = 'SilentlyContinue'
$keys = [ordered]@{}
$denied = New-Object Collections.ArrayList
# a read that failed, as against a key that isn't there: by error category, whose name isn't translated
function Note($p, $errs) { foreach ($e in $errs) { if ($e.CategoryInfo.Category -ne 'ObjectNotFound' -and $denied.Count -lt 50) { [void]$denied.Add($p.ToLower()); break } } }
function Dump($p) {
  $ev = $null; $k = Get-Item -LiteralPath "Registry::$p" -ErrorVariable ev
  Note $p $ev
  if (-not $k) { return @() }
  $v = @{}
  foreach ($n in $k.GetValueNames()) { $d = $k.GetValue($n); if ($d -is [string] -or $d -is [int] -or $d -is [long]) { $v[$n] = $d } }
  $subs = @($k.GetSubKeyNames())
  $keys[$p.ToLower()] = @{ values = $v; subkeys = $subs }
  return $subs
}
$un = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
$roots = @("HKEY_LOCAL_MACHINE\$un", "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
foreach ($sid in (Get-ChildItem 'Registry::HKEY_USERS').PSChildName) { if ($sid -match '^S-1-5-21-[0-9-]+$') { $roots += "HKEY_USERS\$sid\$un" } }
foreach ($r in $roots) { foreach ($s in Dump $r) { Dump "$r\$s" | Out-Null } }
$lm = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft'
foreach ($p in "$lm\Windows NT\CurrentVersion", "$lm\Office\ClickToRun\Configuration", "$lm\NET Framework Setup\NDP\v4\Full", "$lm\Microsoft SQL Server\Instance Names\SQL") { Dump $p | Out-Null }
$sql = $keys["$lm\Microsoft SQL Server\Instance Names\SQL".ToLower()]
if ($sql) { foreach ($id in $sql.values.Values) { Dump "$lm\Microsoft SQL Server\$id\Setup" | Out-Null } }
$dirs = @{}
foreach ($r in "$env:ProgramFiles\dotnet", "$env:ProgramFiles\dotnet\x64", "${env:ProgramFiles(x86)}\dotnet") {
  foreach ($s in 'shared\Microsoft.NETCore.App', 'shared\Microsoft.AspNetCore.App', 'sdk') {
    $ev = $null; $dirs[("$r\$s").ToLower()] = @(Get-ChildItem -LiteralPath "$r\$s" -Directory -ErrorVariable ev | ForEach-Object Name); Note "$r\$s" $ev
  }
}
ConvertTo-Json -Compress -Depth 6 -InputObject @{ host = $env:COMPUTERNAME; machine = $env:PROCESSOR_ARCHITECTURE; keys = $keys; dirs = $dirs; denied = @($denied) }
"""
SAFE_HOSTNAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,252})\Z")


class RemoteReg:
    """The part of winreg the collectors use, over a dump of another host's registry."""
    HKEY_LOCAL_MACHINE, HKEY_USERS, HKEY_CURRENT_USER = "hkey_local_machine", "hkey_users", "hkey_current_user"
    KEY_READ, KEY_WOW64_64KEY, KEY_WOW64_32KEY = 0, 0x100, 0x200

    class Key:
        def __init__(self, path, d):
            self.path, self.values, self.subkeys = path, d.get("values") or {}, d.get("subkeys") or []

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def __init__(self, keys, denied=()):
        self.keys, self.denied = keys, set(denied)

    def OpenKey(self, root, path, reserved=0, access=0):
        base = root.path if isinstance(root, self.Key) else root
        path = path.lower()
        if access & self.KEY_WOW64_32KEY and path.startswith("software\\"):
            path = "software\\wow6432node\\" + path[len("software\\"):]
        full = f"{base}\\{path}".rstrip("\\")
        if full in self.denied:
            raise PermissionError(full)
        if full not in self.keys:
            raise FileNotFoundError(full)
        return self.Key(full, self.keys[full])

    def EnumKey(self, k, i):
        subs = k.subkeys if isinstance(k, self.Key) else sorted({x[len(k) + 1:].split("\\")[0].upper() for x in self.keys if x.startswith(k + "\\")})  # a hive
        if i >= len(subs):
            raise OSError("no more")
        return subs[i]

    def EnumValue(self, k, i):
        items = list(k.values.items())
        if i >= len(items):
            raise OSError("no more")
        return (*items[i], 1)

    def QueryValueEx(self, k, name):
        if name not in k.values:
            raise OSError(name)
        return k.values[name], 1


def collect_remote(host, run=None):
    """(hostname, inventory) of another Windows host, read with the same collectors as an agent."""
    if not SAFE_HOSTNAME.match(host):
        raise AgentError(f"not a host name: {host!r}")
    run = run or sh

    def remote(cmd, **kw):  # a file, because a script as an argument hits the command line limit
        fd, path = tempfile.mkstemp(suffix=".ps1")
        try:
            with os.fdopen(fd, "w", encoding="utf-8-sig") as f:
                f.write(cmd[-1])
            return run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
                        f"Invoke-Command -ComputerName {host} -FilePath '{path}' -ErrorAction Stop"], **kw)
        finally:
            os.unlink(path)
    rc, out = ps(remote, PS_REMOTE_DUMP, timeout=600)
    try:
        d = json.loads(out.strip().splitlines()[-1]) if rc == 0 else None
    except (ValueError, IndexError):
        d = None
    if not isinstance(d, dict) or not isinstance(d.get("keys"), dict) or not isinstance(d.get("dirs"), dict):
        raise AgentError(f"{host}: couldn't read it over PowerShell remoting: {out.strip()[-300:]}")
    dirs = {str(k).lower(): v for k, v in d["dirs"].items()}
    denied = {str(x).lower() for x in d.get("denied") or [] if isinstance(x, str)}

    def dotnet_dirs(path):
        if path.lower() in denied:
            raise PermissionError(path)
        got = dirs.get(path.lower()) or []
        return [str(x) for x in got] if isinstance(got, list) else [str(got)]
    machine = {"AMD64": "AMD64", "ARM64": "ARM64"}.get(str(d.get("machine")), "AMD64")
    return str(d.get("host") or host)[:255], collect_windows(RemoteReg(d["keys"], denied), remote, machine, dotnet_dirs)


def scan_remote(server, hosts, token, insecure_http=False, keys_path=None, run=None, post_fn=None):
    """Enrol each host once as an asset with no agent, then report its inventory. One host failing doesn't stop the rest.
    Keys go in the admin's own profile: each can only report that one host's inventory."""
    keys_path = keys_path or os.path.join(os.path.expanduser("~"), ".nimstead-remote-scan.json")
    send = post_fn or post
    try:
        with open(keys_path) as f:
            keys = json.load(f)
    except (OSError, ValueError):
        keys = {}
    failed = {}
    for host in hosts:
        try:
            name, inv = collect_remote(host, run)
            if server not in keys.get(name.lower(), {}):
                if not token:
                    raise AgentError("not enrolled yet: an enrolment token is required (NIMSTEAD_TOKEN)")
                res = send(server, "/api/agent/enroll", {"token": token, "hostname": name, "os_name": inv["os_name"], "ecosystem": inv["ecosystem"]}, insecure_http)
                keys.setdefault(name.lower(), {})[server] = res["agent_key"]
                fd = os.open(keys_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w") as f:
                    json.dump(keys, f)
            send(server, "/api/agent/inventory", inv, insecure_http, key=keys[name.lower()][server])
            print(f"{name}: reported {len(inv['packages'])} packages")
        except (AgentError, OSError, KeyError, subprocess.SubprocessError) as e:
            failed[host] = str(e)
            print(f"{host}: {e}", file=sys.stderr)
    return failed


# Microsoft products MSRC publishes exact builds for (server: msproducts.py). Facts only, from fixed places; the server
# decides what they are compared with. Store packages: exactly these families (kept equal to msproducts.STORE_PACKAGES).
STORE_PACKAGES = ("Microsoft.Paint", "Microsoft.SecHealthUI", "Microsoft.HEVCVideoExtension", "Microsoft.MPEG2VideoExtension",
                  "Microsoft.RawImageExtension", "Microsoft.GamingServices")
PS_MICROSOFT = r"""
$o = [ordered]@{}
$ex = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup' -ErrorAction SilentlyContinue).MsiInstallPath
if ($ex -and (Test-Path -LiteralPath (Join-Path $ex 'Bin\ExSetup.exe'))) { $o.exchange = (Get-Item -LiteralPath (Join-Path $ex 'Bin\ExSetup.exe')).VersionInfo.FileVersionRaw.ToString() }
$sp = Join-Path $env:CommonProgramFiles 'microsoft shared\Web Server Extensions\16\ISAPI\Microsoft.SharePoint.dll'
if (Test-Path -LiteralPath $sp) { $o.sharepoint = (Get-Item -LiteralPath $sp).VersionInfo.FileVersionRaw.ToString() }
$fx = Join-Path $env:windir $(if ([Environment]::Is64BitOperatingSystem) { 'Microsoft.NET\Framework64\v4.0.30319\mscorlib.dll' } else { 'Microsoft.NET\Framework\v4.0.30319\mscorlib.dll' })
if (Test-Path -LiteralPath $fx) { $o.netfx = (Get-Item -LiteralPath $fx).VersionInfo.FileVersion }
$short = @()  # what couldn't be read in full, as against a product that isn't there
$apps = try { Get-AppxPackage -AllUsers -ErrorAction Stop } catch { $short += 'Store apps of other users'; Get-AppxPackage -ErrorAction SilentlyContinue }  # -AllUsers needs elevation; SYSTEM has it
$o.store = @($apps | Where-Object { @(%STORE%) -contains $_.Name } | ForEach-Object { @{ name = $_.Name; version = $_.Version.ToString() } })
$mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($mp) { $o.defender = @{ platform = $mp.AMProductVersion; engine = $mp.AMEngineVersion; mode = "$($mp.AMRunningMode)" } }
elseif (Get-Service -Name WinDefend -ErrorAction SilentlyContinue) { $short += 'Defender status' }
$o.short = @($short)
ConvertTo-Json -Compress -Depth 4 -InputObject $o
""".replace("%STORE%", ", ".join(f"'{n}'" for n in STORE_PACKAGES))


def _reg_values(reg, path, view, problems=None):
    """Value names and data under HKLM\\path in one registry view; [] if missing. A failed read goes in `problems`."""
    problems = problems if problems is not None else []
    try:
        k = reg.OpenKey(reg.HKEY_LOCAL_MACHINE, path, 0, reg.KEY_READ | view)
    except FileNotFoundError:
        return []
    except OSError as e:
        problems.append(_read_problem(path, e))
        return []
    out, i = [], 0
    with k:
        while True:
            try:
                name, data, _ = reg.EnumValue(k, i)
            except OSError as e:
                if not _list_ended(e):
                    problems.append(_read_problem(path, e))
                return out
            out.append((name, data))
            i += 1


def _dirs(path):
    return [e.name for e in os.scandir(path) if e.is_dir(follow_symlinks=False)]


def windows_microsoft(reg, run=None, dotnet_dirs=None):
    """(packages, problem): .NET and ASP.NET Core runtimes, SQL Server instances, Exchange, SharePoint, Store apps and
    Defender, as ecosystem "Microsoft" facts. A PowerShell failure costs only those facts, never the inventory."""
    out, seen, problems = [], set(), []

    def folders(path):
        try:
            return (dotnet_dirs or _dirs)(path)
        except FileNotFoundError:
            return []
        except OSError as e:
            problems.append(_read_problem(path, e))
            return []

    def add(name, version, source=None):
        item = (name, str(version).strip()[:100], source)
        if item[1] and item not in seen:
            seen.add(item)
            out.append({"ecosystem": "Microsoft", "name": name, "version": item[1], "source": source})
    # .NET from the runtime folders themselves (the registry keeps versions long uninstalled). Only the newest patch
    # of each major.minor: by default .NET runs every app on the latest patch installed, so older ones don't run.
    pf, pf86 = os.environ.get("ProgramFiles", r"C:\Program Files"), os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    for root, arch in ((os.path.join(pf, "dotnet"), "native"), (os.path.join(pf, "dotnet", "x64"), "x64"), (os.path.join(pf86, "dotnet"), "x86")):
        for fx, name in (("Microsoft.NETCore.App", ".NET runtime"), ("Microsoft.AspNetCore.App", "ASP.NET Core")):
            newest = {}
            for v in folders(os.path.join(root, "shared", fx)):
                if re.fullmatch(r"\d+\.\d+\.\d+", v):
                    mm = tuple(v.split(".")[:2])
                    if mm not in newest or version_tuple(v) > version_tuple(newest[mm]):
                        newest[mm] = v
            for v in newest.values():
                add(name, v, arch)
        newest = {}  # SDKs: newest of each feature band (8.0.1xx, 8.0.4xx), which Microsoft patches separately
        for v in folders(os.path.join(root, "sdk")):
            if re.fullmatch(r"\d+\.\d+\.\d{3,}", v):
                band = (*v.split(".")[:2], v.split(".")[2][:-2])
                if band not in newest or version_tuple(v) > version_tuple(newest[band]):
                    newest[band] = v
        for v in newest.values():
            add(".NET SDK", v, arch)
    c2r = dict(_reg_values(reg, r"SOFTWARE\Microsoft\Office\ClickToRun\Configuration", reg.KEY_WOW64_64KEY, problems))
    if c2r.get("VersionToReport"):  # Microsoft 365 Apps / Office LTSC; a policy-set UpdateChannel wins over the CDN it came from
        add("Microsoft 365 Apps", c2r["VersionToReport"], str(c2r.get("UpdateChannel") or c2r.get("CDNBaseUrl") or "")[:200] or None)
    for inst, iid in _reg_values(reg, r"SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL", reg.KEY_WOW64_64KEY, problems):
        for n, v in _reg_values(reg, rf"SOFTWARE\Microsoft\Microsoft SQL Server\{iid}\Setup", reg.KEY_WOW64_64KEY, problems):
            if n == "PatchLevel":
                add("SQL Server", v, str(inst)[:100])
    rc, text = ps(run or sh, PS_MICROSOFT)
    try:
        d = json.loads(text.strip().splitlines()[-1]) if rc == 0 else None
    except (ValueError, IndexError):
        d = None
    if not isinstance(d, dict):
        return out, "; ".join([*problems, f"Microsoft product check failed: {text.strip()[-200:]}"])
    if d.get("exchange"):
        add("Exchange Server", d["exchange"])
    if d.get("sharepoint"):
        add("SharePoint Server", d["sharepoint"])
    release = dict(_reg_values(reg, r"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full", reg.KEY_WOW64_64KEY)).get("Release")
    if d.get("netfx") and release:  # "4.8.9363.0 built by: NET481REL1": mscorlib carries the build MSRC names as the fix
        add(".NET Framework", str(d["netfx"]).split()[0], str(release))
    for s in d.get("store") or []:
        if isinstance(s, dict) and s.get("name") in STORE_PACKAGES:
            add(s["name"], s.get("version", ""))
    df = d.get("defender") if isinstance(d.get("defender"), dict) else {}
    for part in ("platform", "engine"):
        if df.get(part):
            add(f"Defender {part}", df[part], df.get("mode") or None)
    short = [str(x)[:60] for x in d.get("short") or []][:5] if isinstance(d.get("short"), list) else []
    return out, "; ".join([*problems, *(f"not read: {x}" for x in short)]) or None


# Host state the server evaluates (winconfig.py, plan T10-T12, T36, T37, T42): a closed list read from fixed places.
# The server never names a registry path or setting; it only reads what this script reports. Unreadable = null.
PS_HOST = r"""
$ErrorActionPreference = 'SilentlyContinue'
function Reg($path, $name) { $v = (Get-ItemProperty -LiteralPath "Registry::$path" -Name $name -ErrorAction SilentlyContinue).$name; if ($null -eq $v) { $null } else { $v } }
function UserWritable($p) {
  if (-not $p -or -not (Test-Path -LiteralPath $p)) { return $false }
  $acl = Get-Acl -LiteralPath $p
  foreach ($r in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
    if ($r.AccessControlType -ne 'Allow') { continue }
    if ($r.IdentityReference.Value -notin 'S-1-5-32-545', 'S-1-5-11', 'S-1-1-0', 'S-1-5-4') { continue }  # Users, Authenticated Users, Everyone, INTERACTIVE: by SID, names are localised
    if ($r.FileSystemRights -band 0x40116) { return $true }  # write data/add file, append, write attributes/EA, write DAC, owner
  }
  return $false
}
function FwAllows($rules, $port, $path) {  # an inbound allow rule covers this port for this program
  foreach ($r in $rules) {
    if ($r.prog -ne 'Any' -and [Environment]::ExpandEnvironmentVariables($r.prog) -ine $path) { continue }
    foreach ($lp in $r.ports) { if ("$lp" -eq 'Any' -or "$lp" -eq "$port" -or ("$lp" -match '^(\d+)-(\d+)$' -and [int]$Matches[1] -le $port -and $port -le [int]$Matches[2])) { return $true } }
  }
  return $false
}
$c = [ordered]@{}
$sb = $null; try { $sb = Confirm-SecureBootUEFI } catch { }
$c.secure_boot = $sb
$svc = 'HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing'
$c.uefica2023_status = Reg $svc 'UEFICA2023Status'; $c.uefica2023_error = Reg $svc 'UEFICA2023Error'
$ev = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-TPM-WMI'; Id = 1801, 1808 } -MaxEvents 1
$c.secure_boot_last_event = if ($ev) { $ev.Id } else { $null }
$c.dbx_pca2011_revoked = $null
if ($sb) { try { $c.dbx_pca2011_revoked = [Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI -Name dbx).Bytes) -match 'Microsoft Windows Production PCA 2011' } catch { } }
$c.cert_padding_check = @((Reg 'HKLM\SOFTWARE\Microsoft\Cryptography\Wintrust\Config' 'EnableCertPaddingCheck'), (Reg 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Cryptography\Wintrust\Config' 'EnableCertPaddingCheck'))
$mm = 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
$c.spectre_override = Reg $mm 'FeatureSettingsOverride'; $c.spectre_mask = Reg $mm 'FeatureSettingsOverrideMask'
$smb = Get-SmbServerConfiguration
$c.smb1_server = if ($smb) { $smb.EnableSMB1Protocol } else { $null }
$c.smb_signing_required = if ($smb) { $smb.RequireSecuritySignature } else { $null }
$c.llmnr = Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
$c.netbios_adapters = @(Get-ChildItem 'Registry::HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' | ForEach-Object { (Get-ItemProperty $_.PSPath).NetbiosOptions } | Where-Object { $_ -ne 2 }).Count
$lsa = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
$c.lm_compat = Reg $lsa 'LmCompatibilityLevel'; $c.run_as_ppl = Reg $lsa 'RunAsPPL'
$c.wdigest = Reg 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
$c.rdp_enabled = (Reg 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections') -eq 0
$c.rdp_nla = Reg 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
foreach ($t in 'TLS 1.0', 'TLS 1.1') { $c["$($t.Replace(' ','').ToLower())_server"] = Reg "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$t\Server" 'Enabled' }
$ntds = 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
$c.ldap_signing = Reg $ntds 'LDAPServerIntegrity'; $c.ldap_channel_binding = Reg $ntds 'LdapEnforceChannelBinding'
$c.always_install_elevated = Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
$pol = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$c.uac_lua = Reg $pol 'EnableLUA'; $c.uac_admin_prompt = Reg $pol 'ConsentPromptBehaviorAdmin'; $c.remote_uac_off = Reg $pol 'LocalAccountTokenFilterPolicy'
$c.restrict_anonymous_sam = Reg $lsa 'RestrictAnonymousSAM'; $c.restrict_anonymous = Reg $lsa 'RestrictAnonymous'
$c.everyone_includes_anonymous = Reg $lsa 'EveryoneIncludesAnonymous'; $c.no_lm_hash = Reg $lsa 'NoLMHash'
$c.autorun = Reg 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'
$c.smb_client_signing = Reg 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature'
$c.insecure_guest_auth = Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' 'AllowInsecureGuestAuth'
$wr = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
$c.winrm_basic = Reg $wr 'AllowBasic'; $c.winrm_unencrypted = Reg $wr 'AllowUnencryptedTraffic'
$c.rdp_encryption = Reg 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'MinEncryptionLevel'
$c.safe_dll_search = Reg 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager' 'SafeDllSearchMode'
$c.auto_update_off = Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate'
$wl = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$c.autologon_stored = ("$(Reg $wl 'AutoAdminLogon')" -eq '1') -and ("$(Reg $wl 'DefaultPassword')" -ne '')  # only whether one is stored, never the value
$c.script_block_logging = Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
$c.ssl3_server = Reg 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' 'Enabled'
$c.remote_registry_running = (Get-Service RemoteRegistry).Status -eq 'Running'
$snmp = 'Registry::HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities'
$c.snmp_default_community = if (Test-Path -LiteralPath $snmp) { $null -ne (Get-ItemProperty -LiteralPath $snmp).public -or $null -ne (Get-ItemProperty -LiteralPath $snmp).private } else { $false }
$c.guest_enabled = @(Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' -and $_.Enabled }).Count -gt 0
$c.password_policy = $null
$sp = Join-Path $env:ProgramData ('Nimstead\sec-' + [guid]::NewGuid() + '.inf')  # the agent's own locked folder; holds settings only, no secrets
secedit /export /areas SECURITYPOLICY /cfg $sp /quiet 2>$null | Out-Null
if (Test-Path -LiteralPath $sp) {
  $pp = [ordered]@{}; foreach ($l in Get-Content -LiteralPath $sp) { if ($l -match '^(MinimumPasswordLength|PasswordComplexity|LockoutBadCount|ClearTextPassword)\s*=\s*(\d+)') { $pp[$Matches[1]] = [int]$Matches[2] } }
  Remove-Item -LiteralPath $sp -Force; if ($pp.Count) { $c.password_policy = $pp }
}
$c.spooler_running = (Get-Service Spooler).Status -eq 'Running'
$unq = @(); $wsvc = @()
foreach ($s in Get-CimInstance Win32_Service) {
  $p = "$($s.PathName)".Trim()
  if (-not $p -or $p.StartsWith('"')) { $exe = ($p -split '"')[1] } else {
    $exe = if ($p -match '^(.+?\.exe)') { $Matches[1] } else { $p }
    if ($exe -match ' ' -and $exe -notmatch '^[A-Za-z]:\\Windows\\') {
      $parts = $exe -split ' '; $cand = ''
      for ($i = 0; $i -lt $parts.Count - 1; $i++) { $cand = ($cand + ' ' + $parts[$i]).Trim(); if (UserWritable (Split-Path $cand -Parent)) { $unq += $s.Name; break } }
    }
  }
  if ($exe -and $exe -notmatch '^[A-Za-z]:\\Windows\\' -and ((UserWritable $exe) -or (UserWritable (Split-Path $exe -Parent)))) { $wsvc += $s.Name }
}
$c.unquoted_service_paths = @($unq | Select-Object -Unique -First 20); $c.writable_service_binaries = @($wsvc | Select-Object -Unique -First 20)
$ps2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
$c.powershell2 = if ($ps2) { "$($ps2.State)" -eq 'Enabled' } else { $null }
$mp = Get-MpComputerStatus
$c.defender = if ($mp) { @{ mode = "$($mp.AMRunningMode)"; realtime = $mp.RealTimeProtectionEnabled; signature_age = $mp.AntivirusSignatureAge } } else { $null }
$c.firewall_off = @(Get-NetFirewallProfile | Where-Object { -not $_.Enabled } | ForEach-Object { "$($_.Name)" })
$bl = Get-BitLockerVolume -MountPoint $env:SystemDrive
$c.bitlocker_os = if ($bl) { "$($bl.ProtectionStatus)" } else { $null }
$certs = @()
foreach ($x in @(Get-ChildItem Cert:\LocalMachine\My, Cert:\LocalMachine\WebHosting | Select-Object -First 30)) {
  $bits = $null; try { $bits = $x.PublicKey.Key.KeySize } catch { }  # .NET Framework can't read every key type: null = can't tell
  $sub = "$($x.Subject)"
  $certs += [ordered]@{ subject = $sub.Substring(0, [Math]::Min(120, $sub.Length)); self_signed = $x.Subject -eq $x.Issuer; private_key = $x.HasPrivateKey
    not_after = $x.NotAfter.ToUniversalTime().ToString('o'); signature_oid = $x.SignatureAlgorithm.Value; key_oid = $x.PublicKey.Oid.Value; key_bits = $bits }
}
$fwr = $null
try {
  $on = @{}; Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop | ForEach-Object { $on[$_.InstanceID] = 1 }
  $apps = @{}; Get-NetFirewallApplicationFilter -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object { $apps[$_.InstanceID] = "$($_.Program)" }
  $fwr = @(Get-NetFirewallPortFilter -PolicyStore ActiveStore -ErrorAction Stop | Where-Object { $on[$_.InstanceID] -and "$($_.Protocol)" -in 'TCP', '6', 'Any' } | ForEach-Object { @{ ports = @($_.LocalPort); prog = $apps[$_.InstanceID] } })
} catch { }
$lis = [ordered]@{}
foreach ($t in Get-NetTCPConnection -State Listen) {
  $k = "$($t.LocalPort)/$($t.OwningProcess)"
  if ($t.LocalAddress -match '^(127\.|::1$)' -or $lis.Contains($k) -or $lis.Count -ge 60) { continue }
  $pr = Get-Process -Id $t.OwningProcess
  $fw = if (@($c.firewall_off).Count) { 'off' } elseif ($null -eq $fwr) { $null } elseif (FwAllows $fwr ([int]$t.LocalPort) "$($pr.Path)") { 'allowed' } else { 'blocked' }
  $lis[$k] = [ordered]@{ port = [int]$t.LocalPort; process = "$($pr.ProcessName)"; firewall = $fw }
}
$cs = Get-CimInstance Win32_ComputerSystem
$wu = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$roles = if (Get-Command Get-WindowsFeature) { @(Get-WindowsFeature | Where-Object Installed | ForEach-Object Name) } else {
  @(Get-WindowsOptionalFeature -Online | Where-Object State -eq 'Enabled' | ForEach-Object FeatureName) }
$last = $null; try { $last = (New-Object -ComObject Microsoft.Update.AutoUpdate).Results.LastInstallationSuccessDate.ToString('o') } catch { }
$pending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
ConvertTo-Json -Compress -Depth 4 -InputObject ([ordered]@{ config = $c; roles = @($roles | Select-Object -First 400);
  machine_certs = @($certs); listening = @($lis.Values);
  domain_role = [int]$cs.DomainRole; domain = "$($cs.Domain)"; cluster = Reg 'HKLM\Cluster' 'ClusterName';
  wsus = if ((Reg "$wu\AU" 'UseWUServer') -eq 1) { Reg $wu 'WUServer' } else { $null };
  wufb_quality_deferral_days = Reg $wu 'DeferQualityUpdatesPeriodInDays'; pending_reboot = $pending; last_update_success = $last })
"""
HOST_FACTS = ("config", "roles", "domain_role", "domain", "cluster", "wsus", "wufb_quality_deferral_days", "pending_reboot",
              "last_update_success", "machine_certs", "listening")


# Benchmark settings the server judges (winbaseline.py, DECISIONS 75): a closed list in the signed agent, generated once from
# the STIGs by scripts/xccdf_rules.py and reviewed. The server can't add to it or choose from it (DECISIONS 7, 27); a rule whose
# value isn't here simply reads "not assessed". Each entry is "HKLM path|value name".
BASELINE_REG = (
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon|CachedLogonsCount",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI|EnumerateAdministrators",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer|NoAutorun",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer|NoDriveTypeAutoRun",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer|NoWebServices",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer|PreXPSP2ShellProtocolBehavior",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit|ProcessCreationIncludeCmdLine_Enabled",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters|DevicePKInitEnabled",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters|SupportedEncryptionTypes",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|ConsentPromptBehaviorAdmin",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|ConsentPromptBehaviorUser",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|DisableAutomaticRestartSignOn",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|EnableInstallerDetection",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|EnableLUA",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|EnableSecureUIAPaths",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|EnableUIADesktopToggle",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|EnableVirtualization",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|FilterAdministratorToken",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|InactivityTimeoutSecs",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|LocalAccountTokenFilterPolicy",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|MSAOptional",
    r"SOFTWARE\Policies\Microsoft\Cryptography|ForceKeyProtection",
    r"SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds|AllowBasicAuthInClear",
    r"SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds|DisableEnclosureDownload",
    r"SOFTWARE\Policies\Microsoft\MicrosoftAccount|DisableUserAuth",
    r"SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51|ACSettingIndex",
    r"SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51|DCSettingIndex",
    r"SOFTWARE\Policies\Microsoft\Windows NT\Printers|DisableHTTPPrinting",
    r"SOFTWARE\Policies\Microsoft\Windows NT\Printers|DisableWebPnPDownload",
    r"SOFTWARE\Policies\Microsoft\Windows NT\Rpc|RestrictRemoteClients",
    r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services|DisablePasswordSaving",
    r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services|fAllowToGetHelp",
    r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services|fDisableCdm",
    r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services|fEncryptRPCTraffic",
    r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services|fPromptForPassword",
    r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services|MinEncryptionLevel",
    r"SOFTWARE\Policies\Microsoft\Windows\AppCompat|DisableInventory",
    r"SOFTWARE\Policies\Microsoft\Windows\AppPrivacy|LetAppsActivateWithVoice",
    r"SOFTWARE\Policies\Microsoft\Windows\AppPrivacy|LetAppsActivateWithVoiceAboveLock",
    r"SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation|AllowProtectedCreds",
    r"SOFTWARE\Policies\Microsoft\Windows\DataCollection|AllowTelemetry",
    r"SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization|DODownloadMode",
    r"SOFTWARE\Policies\Microsoft\Windows\Explorer|NoAutoplayfornonVolume",
    r"SOFTWARE\Policies\Microsoft\Windows\Explorer|NoDataExecutionPrevention",
    r"SOFTWARE\Policies\Microsoft\Windows\Explorer|NoHeapTerminationOnCorruption",
    r"SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}|NoGPOListChanges",
    r"SOFTWARE\Policies\Microsoft\Windows\Installer|AlwaysInstallElevated",
    r"SOFTWARE\Policies\Microsoft\Windows\Installer|EnableUserControl",
    r"SOFTWARE\Policies\Microsoft\Windows\Installer|SafeForScripting",
    r"Software\Policies\Microsoft\Windows\Kernel DMA Protection|DeviceEnumerationPolicy",
    r"SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation|AllowInsecureGuestAuth",
    r"SOFTWARE\Policies\Microsoft\Windows\Network Connections|NC_ShowSharedAccessUI",
    r"SOFTWARE\Policies\Microsoft\Windows\Personalization|NoLockScreenSlideshow",
    r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging|EnableScriptBlockLogging",
    r"SOFTWARE\Policies\Microsoft\Windows\System|DontDisplayNetworkSelectionUI",
    r"SOFTWARE\Policies\Microsoft\Windows\System|EnumerateLocalUsers",
    r"SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy|fBlockNonDomain",
    r"SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy|fMinimizeConnections",
    r"SOFTWARE\Policies\Microsoft\Windows\Windows Search|AllowIndexingEncryptedStoresOrItems",
    r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Client|AllowBasic",
    r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Client|AllowDigest",
    r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Client|AllowUnencryptedTraffic",
    r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service|AllowBasic",
    r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service|AllowUnencryptedTraffic",
    r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service|DisableRunAs",
    r"SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy|Enabled",
    r"SYSTEM\CurrentControlSet\Control\LSA\MSV1_0|allownullsessionfallback",
    r"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0|NTLMMinClientSec",
    r"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0|NTLMMinServerSec",
    r"SYSTEM\CurrentControlSet\Control\LSA\pku2u|AllowOnlineID",
    r"SYSTEM\CurrentControlSet\Control\Lsa|EveryoneIncludesAnonymous",
    r"SYSTEM\CurrentControlSet\Control\Lsa|LimitBlankPasswordUse",
    r"SYSTEM\CurrentControlSet\Control\Lsa|LmCompatibilityLevel",
    r"SYSTEM\CurrentControlSet\Control\Lsa|NoLMHash",
    r"SYSTEM\CurrentControlSet\Control\Lsa|RestrictAnonymous",
    r"SYSTEM\CurrentControlSet\Control\Lsa|RestrictAnonymousSAM",
    r"SYSTEM\CurrentControlSet\Control\Lsa|RestrictRemoteSAM",
    r"SYSTEM\CurrentControlSet\Control\Lsa|SCENoApplyLegacyAuditPolicy",
    r"SYSTEM\CurrentControlSet\Control\LSA|UseMachineId",
    r"SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest|UseLogonCredential",
    r"SYSTEM\CurrentControlSet\Control\Session Manager\kernel|DisableExceptionChainValidation",
    r"SYSTEM\CurrentControlSet\Control\Session Manager|ProtectionMode",
    r"SYSTEM\CurrentControlSet\Services\LanManServer\Parameters|EnableSecuritySignature",
    r"SYSTEM\CurrentControlSet\Services\LanManServer\Parameters|RequireSecuritySignature",
    r"SYSTEM\CurrentControlSet\Services\LanManServer\Parameters|RestrictNullSessAccess",
    r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters|EnablePlainTextPassword",
    r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters|EnableSecuritySignature",
    r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters|RequireSecuritySignature",
    r"SYSTEM\CurrentControlSet\Services\LDAP|LDAPClientIntegrity",
    r"SYSTEM\CurrentControlSet\Services\Netbt\Parameters|NoNameReleaseOnDemand",
    r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters|DisablePasswordChange",
    r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters|MaximumPasswordAge",
    r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters|RefusePasswordChange",
    r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters|RequireSignOrSeal",
    r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters|RequireStrongKey",
    r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters|SealSecureChannel",
    r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters|SignSecureChannel",
    r"SYSTEM\CurrentControlSet\Services\NTDS\Parameters|LDAPServerEnforceIntegrity",
    r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters|DisableIPSourceRouting",
    r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters|DisableIPSourceRouting",
    r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters|EnableICMPRedirect",
)
BASELINE_AUDIT = (  # audit subcategories, by GUID: Windows translates their names
    "{0CCE9210-69AE-11D9-BED3-505054503030}",
    "{0CCE9211-69AE-11D9-BED3-505054503030}",
    "{0CCE9212-69AE-11D9-BED3-505054503030}",
    "{0CCE9213-69AE-11D9-BED3-505054503030}",
    "{0CCE9214-69AE-11D9-BED3-505054503030}",
    "{0CCE9215-69AE-11D9-BED3-505054503030}",
    "{0CCE9216-69AE-11D9-BED3-505054503030}",
    "{0CCE9217-69AE-11D9-BED3-505054503030}",
    "{0CCE921B-69AE-11D9-BED3-505054503030}",
    "{0CCE921C-69AE-11D9-BED3-505054503030}",
    "{0CCE9224-69AE-11D9-BED3-505054503030}",
    "{0CCE9227-69AE-11D9-BED3-505054503030}",
    "{0CCE9228-69AE-11D9-BED3-505054503030}",
    "{0CCE922B-69AE-11D9-BED3-505054503030}",
    "{0CCE922F-69AE-11D9-BED3-505054503030}",
    "{0CCE9230-69AE-11D9-BED3-505054503030}",
    "{0CCE9231-69AE-11D9-BED3-505054503030}",
    "{0CCE9232-69AE-11D9-BED3-505054503030}",
    "{0CCE9234-69AE-11D9-BED3-505054503030}",
    "{0CCE9235-69AE-11D9-BED3-505054503030}",
    "{0CCE9236-69AE-11D9-BED3-505054503030}",
    "{0CCE9237-69AE-11D9-BED3-505054503030}",
    "{0CCE923A-69AE-11D9-BED3-505054503030}",
    "{0CCE923B-69AE-11D9-BED3-505054503030}",
    "{0CCE923C-69AE-11D9-BED3-505054503030}",
    "{0CCE923F-69AE-11D9-BED3-505054503030}",
    "{0CCE9244-69AE-11D9-BED3-505054503030}",
    "{0CCE9248-69AE-11D9-BED3-505054503030}",
    "{0CCE9249-69AE-11D9-BED3-505054503030}",
)
BASELINE_RIGHTS = (  # user rights, by constant: Windows translates their names too
    "SeAuditPrivilege", "SeBackupPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege",
    "SeCreatePermanentPrivilege", "SeCreateTokenPrivilege", "SeDebugPrivilege", "SeDenyBatchLogonRight",
    "SeDenyInteractiveLogonRight", "SeDenyNetworkLogonRight", "SeDenyRemoteInteractiveLogonRight", "SeDenyServiceLogonRight",
    "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege", "SeInteractiveLogonRight",
    "SeLoadDriverPrivilege", "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege",
    "SeNetworkLogonRight", "SeProfileSingleProcessPrivilege", "SeRemoteInteractiveLogonRight", "SeRemoteShutdownPrivilege",
    "SeRestorePrivilege", "SeSystemEnvironmentPrivilege", "SeSystemtimePrivilege", "SeTakeOwnershipPrivilege",
    "SeTcbPrivilege", "SeTrustedCredManAccessPrivilege",
)
# A value that isn't there is null; one that can't be read, or has a type no rule expects, is left out: "not assessed", not a fail.
PS_BASELINE = r"""
$ErrorActionPreference = 'SilentlyContinue'
$reg = [ordered]@{}
$lm = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'Registry64')
foreach ($e in '__REG__' -split ';') {
  $p, $n = $e -split '\|', 2
  try {
    $k = $lm.OpenSubKey($p)
    if ($null -eq $k -or $k.GetValueNames() -notcontains $n) { $reg[$e] = $null; continue }
    $v = $k.GetValue($n, $null, 'DoNotExpandEnvironmentNames')
    if ($v -is [int]) { $v = [BitConverter]::ToUInt32([BitConverter]::GetBytes($v), 0) }  # a DWORD reads back signed
    if ($v -is [uint32] -or $v -is [string]) { $reg[$e] = $v }
  } catch { }
}
# No translated word is read (DECISIONS 68, 76). auditpol's table: its numeric last column, found from the GUID, whatever the other
# columns say. secedit's file: rights by constant and holders by SID. A name secedit couldn't turn into a SID is resolved here;
# one that won't resolve is "?", which reads "not assessed". Both files go in the agent's own locked folder and hold settings only.
$dir = Join-Path $env:ProgramData 'Nimstead'
$audit = [ordered]@{}
$f = Join-Path $dir ('audit-' + [guid]::NewGuid() + '.csv')
auditpol /backup /file:$f 2>$null | Out-Null
if (Test-Path -LiteralPath $f) {
  foreach ($l in Get-Content -LiteralPath $f) { if ($l -match '(\{[0-9A-Fa-f-]{36}\}),.*,([0-3])\s*$') { $audit[$Matches[1].ToUpper()] = [int]$Matches[2] } }
  Remove-Item -LiteralPath $f -Force
}
$rights = [ordered]@{}
$f = Join-Path $dir ('rights-' + [guid]::NewGuid() + '.inf')
secedit /export /areas USER_RIGHTS /cfg $f /quiet 2>$null | Out-Null
if (Test-Path -LiteralPath $f) {
  $held = @{}; $found = $false; $in = $false
  foreach ($l in Get-Content -LiteralPath $f) {
    if ($l -match '^\[') { $in = $l -match '^\[Privilege Rights\]'; if ($in) { $found = $true }; continue }
    if ($in -and $l -match '^(Se\w+)\s*=\s*(.*)$') {
      $right = $Matches[1]; $sids = @()
      foreach ($h in ($Matches[2] -split ',')) {
        $h = $h.Trim(); if (-not $h) { continue }
        if ($h.StartsWith('*')) { $sids += $h.Substring(1) } else {
          try { $sids += (New-Object Security.Principal.NTAccount($h)).Translate([Security.Principal.SecurityIdentifier]).Value } catch { $sids += '?' }
        }
      }
      $held[$right] = $sids
    }
  }
  Remove-Item -LiteralPath $f -Force
  if ($found) { foreach ($r in '__RIGHTS__' -split ';') { if ($held.ContainsKey($r)) { $rights[$r] = [object[]]$held[$r] } else { $rights[$r] = [object[]]@() } } }
}
ConvertTo-Json -Compress -Depth 4 -InputObject ([ordered]@{ reg = $reg; audit = $audit; rights = $rights })
""".replace("__REG__", ";".join(BASELINE_REG)).replace("__RIGHTS__", ";".join(BASELINE_RIGHTS))
BASELINE_HOLDER = re.compile(r"^(S-1-[0-9-]{1,180}|\?)\Z")
BASELINE_MAX_BYTES = 20_000  # the server drops a whole report's facts over 64 KB (app.py, facts_ok); these must never cost the rest


def baseline_id(entry):
    """Short and stable, so the report stays small and old agents keep matching newer rule tables."""
    return hashlib.sha256(entry.lower().encode()).hexdigest()[:8]


def last_json(out):
    """The last line that is a JSON object: a tool's error text after it (seen for real: auditpol's, on Windows 11) isn't the answer."""
    for line in reversed(out.strip().splitlines()):
        if line.startswith("{"):
            return json.loads(line)
    raise ValueError("no JSON object in the output")


def windows_baseline_facts(run=None):
    """{"reg": {id: value or null}, "audit": {guid: 0-3}, "rights": {constant: [SID]}} for the closed lists above, or None.
    Only what's on those lists is kept. Whatever isn't in the answer reads "not assessed" on the server."""
    rc, out = ps(run or sh, PS_BASELINE)
    try:
        d = last_json(out) if rc == 0 else None
    except ValueError:
        d = None
    if not isinstance(d, dict) or not isinstance(d.get("reg"), dict):
        return None
    reg = {}
    for e in BASELINE_REG:
        v = d["reg"].get(e, reg)  # reg itself is just "not in the answer"
        if v is None or (isinstance(v, int) and not isinstance(v, bool)):
            reg[baseline_id(e)] = v
        elif isinstance(v, str):
            reg[baseline_id(e)] = v[:100]
    audit = d.get("audit") if isinstance(d.get("audit"), dict) else {}
    rights = d.get("rights") if isinstance(d.get("rights"), dict) else {}
    facts = {"reg": reg, "audit": {g: audit[g] for g in BASELINE_AUDIT if audit.get(g) in (0, 1, 2, 3)},
             "rights": {r: rights[r] for r in BASELINE_RIGHTS if isinstance(rights.get(r), list) and len(rights[r]) <= 30
                        and all(isinstance(s, str) and BASELINE_HOLDER.match(s) for s in rights[r])}}
    if len(json.dumps(facts)) > BASELINE_MAX_BYTES:  # only a host with very long rights lists gets here
        facts["rights"] = {}
    return facts if len(json.dumps(facts)) <= BASELINE_MAX_BYTES else None


def windows_host_facts(run=None):
    """Facts from PS_HOST, or ({}, problem). Only the keys in HOST_FACTS are kept."""
    rc, out = ps(run or sh, PS_HOST)
    try:
        d = last_json(out) if rc == 0 else None
    except ValueError:
        d = None
    if not isinstance(d, dict):
        return {}, f"host check failed: {out.strip()[-200:]}"
    facts = {k: d.get(k) for k in HOST_FACTS}
    if (baseline := windows_baseline_facts(run)) is not None:  # its own script: a failure here costs only these rules
        facts["baseline"] = baseline
    return facts, None


# Driver files' SHA-256 (DECISIONS 71): loaded drivers first, then *.sys directly in System32\drivers, which is also how a
# planted driver that isn't loaded yet is seen. Read only, fixed places, no driver is opened as anything but a file.
# Hash values and CIM's Started flag don't change with Windows' language (DECISIONS 68). The file and time caps keep it bounded.
PS_DRIVERS = r"""
$ErrorActionPreference = 'SilentlyContinue'
$native = Join-Path $env:SystemRoot 'Sysnative'  # a 32-bit process asking for System32 gets SysWOW64
$sys = if (Test-Path -LiteralPath $native) { $native } else { Join-Path $env:SystemRoot 'System32' }
$found = [ordered]@{}; $bad = 0; $big = 0; $stopped = $false
$loaded = @(Get-CimInstance Win32_SystemDriver -Filter 'Started = TRUE')
if (-not $loaded.Count) { $bad++ }
foreach ($d in $loaded) {
  $p = "$($d.PathName)".Trim().Trim('"') -replace '^\\\?\?\\', ''
  if ($p -imatch '^\\SystemRoot\\(.*)$') { $p = $Matches[1] }
  if ($p -notmatch '^[A-Za-z]:\\') { $p = Join-Path $env:SystemRoot $p }
  $found[($p -ireplace '\\system32\\', ('\' + (Split-Path $sys -Leaf) + '\')).ToLowerInvariant()] = $true
}
foreach ($f in Get-ChildItem -LiteralPath (Join-Path $sys 'drivers') -Filter '*.sys' -File -Force) {
  $k = $f.FullName.ToLowerInvariant(); if (-not $found.Contains($k)) { $found[$k] = $false }
}
$rows = New-Object Collections.ArrayList
$clock = [Diagnostics.Stopwatch]::StartNew()
foreach ($k in $found.Keys) {
  if ($rows.Count -ge 3000 -or $clock.Elapsed.TotalSeconds -gt 180) { $stopped = $true; break }
  $i = Get-Item -LiteralPath $k -Force
  if (-not $i) { $bad++; continue }
  if ($i.Length -gt 134217728) { $big++; continue }  # 128 MiB
  $h = Get-FileHash -LiteralPath $k -Algorithm SHA256
  if ($h) { [void]$rows.Add(@($i.Name, $h.Hash.ToLowerInvariant(), [bool]$found[$k])) } else { $bad++ }
}
ConvertTo-Json -Compress -Depth 3 -InputObject ([ordered]@{ drivers = @($rows); unreadable = $bad; too_large = $big; stopped = $stopped })
"""
SAFE_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def windows_drivers(run=None):
    """([driver rows as packages], summary). `complete` false: not everything was read, so a driver missing from the rows
    proves nothing and the server keeps its findings open. A file over the size cap can't break that: a listed hash means
    a listed size, so one seen before would still be under it."""
    rc, out = ps(run or sh, PS_DRIVERS)
    try:
        d = json.loads(out.strip().splitlines()[-1]) if rc == 0 else None
    except (ValueError, IndexError):
        d = None
    if not isinstance(d, dict) or not isinstance(d.get("drivers"), list) or not d["drivers"]:
        return [], {"complete": False, "problem": f"driver check failed: {out.strip()[-200:]}"}
    pkgs = [{"ecosystem": "WinDriver", "name": r[0].lower(), "version": r[1], "source": "loaded" if r[2] is True else "on disk"}
            for r in d["drivers"] if isinstance(r, list) and len(r) == 3 and isinstance(r[0], str) and 0 < len(r[0]) <= 255
            and isinstance(r[1], str) and SAFE_SHA256.match(r[1])]
    return pkgs, {"hashed": len(pkgs), "too_large": d.get("too_large"), "unreadable": d.get("unreadable"), "stopped": d.get("stopped"),
                  "complete": d.get("unreadable") == 0 and d.get("stopped") is False}


ESU_PRODUCTS = re.compile(r"^Windows (10 Version 22H2|Server 2012)")
PS_ESU = ("@(Get-CimInstance SoftwareLicensingProduct -Filter \"LicenseStatus=1 and PartialProductKey is not null\" | "
          "Where-Object { $_.Name -match 'ESU' }).Count")


def esu_active(product, run=None):
    """True/False whether an Extended Security Updates licence is active, None where ESU doesn't apply or can't be read."""
    if not product or not ESU_PRODUCTS.match(product):
        return None
    rc, out = ps(run or sh, PS_ESU)
    return int(out.strip()) > 0 if rc == 0 and out.strip().isdigit() else None


def collect():
    return collect_windows() if os.name == "nt" else collect_linux()


# ---- remediation ------------------------------------------------------------
# The server sends a closed job description; every command below is a fixed argv
# template filled with validated names. Rollback packages are saved before any
# change, and any failure after a change triggers rollback. Nothing is silent:
# every step is reported back and lands in the evidence ledger.

SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._-]{0,200}\Z")  # \Z: $ also matches before a final newline
SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+~:_^-]{0,200}\Z")
ROLLBACK_ROOT = "/var/lib/nimstead/rollback"
MIN_FREE_BYTES = 1 << 30  # refuse a change rather than fill the disk with its rollback copy
APT_CACHE = "/var/cache/apt/archives"


def sh(cmd, cwd=None, timeout=1800):
    """Default runner: (returncode, full output). Never raises for a failing command. Steps keep only the tail;
    parsers (zypper's XML dry run runs to tens of KB with package descriptions) need all of it."""
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive", LC_ALL="C")
    try:
        p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, errors="replace", timeout=timeout)
        return p.returncode, p.stdout + p.stderr
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, str(e)


INSTALL_TIMEOUT = 7200  # a Windows cumulative update install, in seconds


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


DNF_SECTIONS = ("Installing", "Upgrading", "Removing", "Downgrading", "Reinstalling", "Obsoleting")
ZYPPER_SECTIONS = ("to-install", "to-upgrade", "to-downgrade", "to-remove", "to-reinstall", "to-upgrade-change-arch")


def dnf_touched(out, sections=DNF_SECTIONS):
    """Package names in a dnf4 transaction table (sections between the header and 'Transaction Summary')."""
    names, section = set(), False
    for ln in out.splitlines():
        s = ln.strip()
        if s.startswith("Transaction Summary"):
            break
        if s.endswith(":") and s.rstrip(":").split()[0] in DNF_SECTIONS:
            section = s.rstrip(":").split()[0] in sections
            continue
        if section and ln.startswith(" ") and s:
            names.add(s.split()[0])
    return names


def zypper_touched(xml, sections=ZYPPER_SECTIONS):
    """Package names in a `zypper --xmlout ... --dry-run` install summary."""
    import xml.etree.ElementTree as ET
    names = set()
    # local root-run zypper output, not network input; the agent is stdlib-only so defusedxml isn't available
    tree = ET.fromstring(xml[xml.index("<stream"):] if "<stream" in xml else xml)  # noqa: S314
    for section in sections:
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
        self.restarts = {}  # unit -> systemd's NRestarts when the change (or rollback) began
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
            rc, state = self.run(["systemctl", "is-active", u])  # prints the state, so a failure says why
            # one sample can catch a crash-looping service in its moment of "active": restarts since the mark count too
            more = self.restart_count(u) - self.restarts[u] if u in self.restarts else 0
            why = f"service is {state.strip() or ('active' if rc == 0 else 'not active')}" + (f", restarted {more} times since the change" if more > 0 else "")
            self.step(f"{u} active {when}", ok=rc == 0 and more <= 0, output=why)

    def restart_count(self, u):
        out = self.run(["systemctl", "show", "-p", "NRestarts", "--value", u])[1].strip()
        return int(out) if out.isdigit() else 0

    def mark_restarts(self):
        self.restarts = {u: self.restart_count(u) for u in self.units}

    def newer(self, to, cur):
        """The package manager's own ordering (rpm-based managers refuse downgrades themselves; the dry run checks too)."""
        if self.mgr == "apt":
            return self.run(["dpkg", "--compare-versions", to, "gt", cur])[0] == 0
        if self.mgr == "apk":
            rc, out = self.run(["apk", "version", "-t", to, cur])
            return rc == 0 and out.strip() == ">"
        return True

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
        down = set()  # apt: --only-upgrade, and pins are compared with dpkg before this (newer_than_installed)
        if self.mgr == "apt":
            out = self.step("simulate upgrade", ["apt-get", "-s", "install", "--only-upgrade", "--no-remove", *self.targets()])
            touched = {ln.split()[1] for ln in out.splitlines() if ln.split()[:1] in (["Inst"], ["Remv"], ["Purg"])}
        elif self.mgr == "apk":
            out = self.step("simulate upgrade", ["apk", "add", "-s", "--upgrade", *self.targets()])
            touched = set(re.findall(r"\b(?:Upgrading|Installing|Purging|Downgrading|Replacing|Reinstalling) (\S+)", out))
            down = set(re.findall(r"\bDowngrading (\S+)", out))
        elif self.mgr == "zypper":
            out = self.step("simulate upgrade", ["zypper", "--non-interactive", "--xmlout", "install", "--dry-run", *self.targets()])
            touched, down = zypper_touched(out), zypper_touched(out, ("to-downgrade",))
        else:
            rc, out = self.run(["dnf", "upgrade", "--assumeno", *self.targets()])  # exits 1 after printing the plan
            self.steps.append({"step": "simulate upgrade", "ok": "Transaction Summary" in out or "Nothing to do" in out,
                               "output": out[-1500:]})
            if "Transaction Summary" not in out:
                raise StepFailed("simulate upgrade failed: " + out[-300:].strip())
            touched, down = dnf_touched(out), dnf_touched(out, ("Downgrading",))
        # a fix only ever moves forward: an older build (with its known flaws) is never installed on a server's say-so
        self.step("no package downgraded", ok=not down, output=("would downgrade: " + ", ".join(sorted(down))) if down else "")
        planned = {p["name"] for p in self.pkgs}
        extra = sorted(touched - planned)
        self.step("change limited to planned packages", ok=not extra,
                  output=("would also change: " + ", ".join(extra)) if extra else "touches: " + ", ".join(sorted(touched)))

    # --- rollback artefacts -------------------------------------------------

    def save_rollback(self):
        os.makedirs(os.path.dirname(self.dir), mode=0o700, exist_ok=True)
        os.mkdir(self.dir, mode=0o700)  # new, never reused: the precheck refused a job whose folder exists
        self.made_dir = True
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
        self.mark_restarts()
        if self.units and self.settle:
            time.sleep(self.settle)  # let restarted services come back before judging
        self.health("after rollback")

    def discard_rollback(self, outcome):
        """After the outcome is saved: the copy has done its job. A failed rollback keeps it for whoever repairs the host.
        Only a folder this run made: a job id reused by a server can't delete a copy an earlier job kept."""
        if outcome != "rollback_failed" and getattr(self, "made_dir", False):
            shutil.rmtree(self.dir, ignore_errors=True)

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
            older = [f"{p['name']} {p['to']}" for p in self.pkgs if p.get("to") and not self.newer(p["to"], p["from"])]
            self.step("fix is newer than installed", ok=not older, output=("not newer: " + ", ".join(older)) if older else "")
            self.step("no rollback copy kept from an earlier job with this id", ok=not os.path.lexists(self.dir),
                      output=f"{self.dir} exists (a failed rollback keeps it for repair); remove it once the host is fixed")
            free = free_bytes(self.dir)
            self.step("free space for the rollback copy", ok=free >= MIN_FREE_BYTES,
                      output=f"{free // 2**20} MiB free; at least {MIN_FREE_BYTES // 2**20} MiB needed")
            self.health("before change")
            self.step("refresh package index", {"apt": ["apt-get", "update"], "apk": ["apk", "update"],
                                                "dnf": ["dnf", "makecache"],
                                                "zypper": ["zypper", "--non-interactive", "refresh"]}[self.mgr])
            self.simulate()
            self.save_rollback()
        except Exception as e:
            return "aborted", self.steps, f"No changes made: {e}"
        try:
            self.mark_restarts()
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


# ---- Windows apps and settings (plan T17, T21, T38) ---------------------------------------------------------------
# Closed maps held here, never sent by the server: a job names only a key from them and versions (strict regexes), so a
# compromised server can only move a curated app to a newer published build, or apply one of these exact settings.
WINGET_IDS = {  # curated product key (server: winapps.py / msproducts.py) -> winget package id
    "google:chrome": "Google.Chrome", "mozilla:firefox": "Mozilla.Firefox", "mozilla:firefox_esr": "Mozilla.Firefox.ESR",
    "7-zip:7-zip": "7zip.7zip", "notepad-plus-plus:notepad++": "Notepad++.Notepad++", "videolan:vlc_media_player": "VideoLAN.VLC",
    "zoom:workplace_desktop": "Zoom.Zoom", "adobe:acrobat_reader": "Adobe.Acrobat.Reader.64-bit", "git-scm:git": "Git.Git",
    "putty:putty": "PuTTY.PuTTY", "rarlab:winrar": "RARLab.WinRAR", "wireshark:wireshark": "WiresharkFoundation.Wireshark",
    "winscp:winscp": "WinSCP.WinSCP", "filezilla-project:filezilla_client": "TimKosse.FileZilla.Client",
    "keepass:keepass": "DominikReichl.KeePass", "vivaldi:vivaldi": "VivaldiTechnologies.Vivaldi", "opera:opera_browser": "Opera.Opera",
    "mozilla:thunderbird": "Mozilla.Thunderbird", "libreoffice:libreoffice": "TheDocumentFoundation.LibreOffice",
    "foxit:pdf_reader": "Foxit.FoxitReader", "teamviewer:teamviewer": "TeamViewer.TeamViewer", "anydesk:anydesk": "AnyDesk.AnyDesk",
    "oracle:vm_virtualbox": "Oracle.VirtualBox", "docker:desktop": "Docker.DockerDesktop",
    "Microsoft Edge": "Microsoft.Edge", "Visual Studio Code": "Microsoft.VisualStudioCode",
    # batch 4, winget's upgrade replaced the old version on a real VM. Not PostgreSQL, MariaDB or IntelliJ: side by side or one id per major
    "irfanview:irfanview": "IrfanSkiljan.IrfanView", "gimp:gimp": "GIMP.GIMP.3", "golang:go": "GoLang.Go", "grafana:grafana": "GrafanaLabs.Grafana.OSS",
    "calibre-ebook:calibre": "calibre.calibre", "tigervnc:tigervnc": "TigerVNC.TigerVNC", "sumatrapdfreader:sumatrapdf": "SumatraPDF.SumatraPDF",
    "nextcloud:desktop": "Nextcloud.NextcloudDesktop", "nomachine:nomachine": "NoMachine.NoMachine", "gpg4win:gpg4win": "GnuPG.Gpg4win",
    "qbittorrent:qbittorrent": "qBittorrent.qBittorrent", "imagemagick:imagemagick": "ImageMagick.ImageMagick",
    "pdf-xchange:pdf-xchange_editor": "TrackerSoftware.PDF-XChangeEditor", "devolutions:remote_desktop_manager": "Devolutions.RemoteDesktopManager",
    "uvnc:ultravnc": "uvncbvba.UltraVNC", "anysphere:cursor": "Anysphere.Cursor"}
# check id (server: winconfig.py) -> (registry key, value name, type, secure value); rollback restores what was there
CONFIG_FIXES = {
    "wdigest": (r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential", "REG_DWORD", "0"),
    "ntlmv1": (r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel", "REG_DWORD", "5"),
    "llmnr": (r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast", "REG_DWORD", "0"),
    "smb-signing": (r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "RequireSecuritySignature", "REG_DWORD", "1"),
    "smb1": (r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1", "REG_DWORD", "0"),
    "cert-padding-check": (r"HKLM\SOFTWARE\Microsoft\Cryptography\Wintrust\Config", "EnableCertPaddingCheck", "REG_SZ", "1"),
    "anonymous-sam": (r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "RestrictAnonymousSAM", "REG_DWORD", "1"),
    "lm-hash": (r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "NoLMHash", "REG_DWORD", "1"),
    "autorun": (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun", "REG_DWORD", "255"),
    "insecure-guest-auth": (r"HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation", "AllowInsecureGuestAuth", "REG_DWORD", "0"),
    "winrm-basic": (r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service", "AllowBasic", "REG_DWORD", "0"),
    "winrm-unencrypted": (r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service", "AllowUnencryptedTraffic", "REG_DWORD", "0"),
    "script-block-logging": (r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging", "REG_DWORD", "1"),
}
# Microsoft's fix is both registry views, and the finding reads both
CONFIG_ALSO = {"cert-padding-check": (r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Cryptography\Wintrust\Config", "EnableCertPaddingCheck", "REG_SZ", "1")}
WIN_APP_MANAGERS = ("winget", "office", "winconfig")
SAFE_BUILD = re.compile(r"^\d{1,6}(\.\d{1,8}){1,4}\Z")
C2R = r"C:\Program Files\Common Files\microsoft shared\ClickToRun\OfficeC2RClient.exe"
OFFICE_APPS = ("WINWORD", "EXCEL", "POWERPNT", "OUTLOOK", "MSACCESS", "ONENOTE", "MSPUB", "VISIO", "WINPROJ")
# Only admins can write under WindowsApps: its root is TrustedInstaller's; package folders belong to an admin-equivalent
# owner (seen for real on Windows 11 26H2: BUILTIN\Administrators). Owners compared by SID: group names are localised.
PS_WINDOWSAPP_FILE = r"""$sid = { (Get-Acl -LiteralPath $args[0]).GetOwner([Security.Principal.SecurityIdentifier]).Value }
$ti = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'; $root = "$env:ProgramFiles\WindowsApps"
if ((Test-Path -LiteralPath $root) -and (& $sid $root) -eq $ti) {
 (Get-ChildItem -LiteralPath $root -Directory -Filter '%PKG%_*_x64__8wekyb3d8bbwe' -ErrorAction SilentlyContinue |
  Where-Object { (& $sid $_.FullName) -in @($ti, 'S-1-5-18', 'S-1-5-32-544') -and (Test-Path -LiteralPath (Join-Path $_.FullName '%FILE%')) } |
  Sort-Object Name -Descending | Select-Object -First 1 | ForEach-Object { Join-Path $_.FullName '%FILE%' }) }"""
PS_WINGET = PS_WINDOWSAPP_FILE.replace("%PKG%", "Microsoft.DesktopAppInstaller").replace("%FILE%", "winget.exe")
# As SYSTEM nothing puts winget's C++ runtime on the DLL path, so it exits with C0000135 before doing anything (real Windows 11 26H2);
# the folder is run from, under the same ownership check
PS_VCLIBS = PS_WINDOWSAPP_FILE.replace("%PKG%", "Microsoft.VCLibs.140.00.UWPDesktop").replace("%FILE%", "msvcp140.dll")


class WinAppJob:
    """manager winget | office | winconfig. Same contract as Job.execute: (outcome, steps, error).
    winget is forward-only (most installers can't go back): the server only hands it out after a person approved that.
    office rolls back to the build it found; winconfig restores the value it found."""

    def __init__(self, job, run=sh, fail_after_apply=False):
        self.run, self.steps, self.mgr = run, [], job.get("manager")
        self.pkgs, self.units = job.get("packages") or [], job.get("health_units") or []
        self.inject, self.result_versions = fail_after_apply, None

    def step(self, name, cmd=None, ok=None, output="", cwd=None):
        if cmd is not None:
            rc, output = self.run(cmd, cwd=cwd)
            ok = rc == 0 if ok is None else ok
        self.steps.append({"step": name, "ok": bool(ok), "output": str(output)[-1500:]})
        if not ok:
            raise StepFailed(f"{name} failed: {str(output)[-300:].strip()}")
        return output

    def health(self, when):
        for u in self.units:
            rc, out = ps(self.run, f"(Get-Service -Name '{u}' -ErrorAction Stop).Status")
            self.step(f"{u} running {when}", ok=rc == 0 and out.strip() == "Running", output=out)

    def valid(self):
        p = self.pkgs[0] if len(self.pkgs) == 1 and isinstance(self.pkgs[0], dict) else {}
        keys = {"winget": WINGET_IDS, "office": {"Microsoft 365 Apps": 1}, "winconfig": CONFIG_FIXES}.get(self.mgr, {})
        return (p.get("name") in keys and all(SAFE_NAME.match(str(u)) for u in self.units)
                and (self.mgr == "winconfig" or (SAFE_BUILD.match(str(p.get("from", ""))) and SAFE_BUILD.match(str(p.get("to", ""))))))

    def execute(self):
        try:
            self.step("job validated", ok=self.valid(), output="" if self.valid() else "unknown product or setting, or invalid version")
            p = self.pkgs[0]
            if self.mgr != "winconfig":
                self.step("fix is newer than installed", ok=windows_version_key(p["to"]) > windows_version_key(p["from"]),
                          output=f"{p['from']} -> {p['to']}")
            self.health("before change")
            undo = getattr(self, f"_{self.mgr}")(p)
        except Exception as e:
            return "aborted", self.steps, f"No changes made: {e}"
        try:
            self.health("after change")
            if self.inject:
                self.step("injected failure (sandbox test)", ok=False, output="--fail-after-apply")
            return "applied", self.steps, None
        except Exception as e:
            err = str(e)
        if undo is None:
            return "rollback_failed", self.steps, f"Change failed and can't be undone (forward-only, approved as such): {err}"
        try:
            undo()
            return "rolled_back", self.steps, f"Change failed and was rolled back: {err}"
        except Exception as e:
            return "rollback_failed", self.steps, f"ROLLBACK FAILED, host needs attention. Change error: {err}; rollback error: {e}"

    def _winget(self, p):
        wid = WINGET_IDS[p["name"]]
        rc, exe = ps(self.run, PS_WINGET)
        exe = exe.strip().splitlines()[-1] if rc == 0 and exe.strip() else ""
        self.step("winget found (App Installer under WindowsApps, admin-owned)", ok=bool(exe), output=exe or "winget unavailable")
        rc, vc = ps(self.run, PS_VCLIBS)
        cwd = os.path.dirname(vc.strip().splitlines()[-1]) if rc == 0 and vc.strip() else None
        common = ["--id", wid, "--exact", "--source", "winget", "--version", p["to"], "--accept-source-agreements", "--disable-interactivity"]
        out = self.step(f"winget lists {wid} {p['to']} with an installer hash", [exe, "show", *common], cwd=cwd)
        self.step("installer SHA-256 published", ok=bool(re.search(r"(?im):\s*[0-9a-f]{64}\s*$", out)), output=out)  # by the value: winget's labels are localised
        self.step(f"{wid} upgraded to {p['to']}", [exe, "install", *common, "--silent", "--force", "--accept-package-agreements",
                                                    "--scope", "machine"], cwd=cwd)
        self.result_versions = {p["name"]: p["to"]}
        return None  # forward-only

    def _office(self, p):
        rc, out = ps(self.run, "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Office\\ClickToRun\\Configuration').VersionToReport")
        self.step("installed build matches plan", ok=rc == 0 and out.strip() == p["from"], output=out)
        rc, out = ps(self.run, "@(Get-Process -Name " + ",".join(OFFICE_APPS) + " -ErrorAction SilentlyContinue).Count")
        self.step("no Office app open (never force-closed)", ok=rc == 0 and out.strip() == "0", output=f"{out.strip()} Office app(s) open")

        def go(build):
            cmd = [C2R, "/update", "user", f"updatetoversion={build}", "displaylevel=false", "forceappshutdown=false"]
            self.step(f"Office updated to {build}", cmd)
            for i in range(60):  # the client returns at once; the update finishes in the background
                if i and i % 4 == 0:  # it can drop a request with exit 0 (real VM: nothing for 10 min, a repeat worked in under 3)
                    self.run(cmd)
                rc, cur = ps(self.run, "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Office\\ClickToRun\\Configuration').VersionToReport")
                if cur.strip() == build:
                    return
                time.sleep(30)
            self.step(f"Office reports {build}", ok=False, output=f"still {cur.strip()}")
        go(p["to"])
        self.result_versions = {p["name"]: p["to"]}
        return lambda: go(p["from"])

    def _winconfig(self, p):
        undos = [self._set_value(*CONFIG_FIXES[p["name"]])]
        if p["name"] in CONFIG_ALSO:
            undos.append(self._set_value(*CONFIG_ALSO[p["name"]]))
        self.result_versions = {p["name"]: "fixed"}

        def undo():
            for u in reversed(undos):
                u()
        return undo

    def _set_value(self, key, name, typ, value):
        rc, out = self.run(["reg", "query", key, "/v", name])
        m = re.search(rf"{re.escape(name)}\s+(REG_\w+)\s+(\S*)", out) if rc == 0 else None
        before = (m[1], m[2]) if m else None  # None: absent, restored by deleting it again
        self.step(f"recorded {name} before the change", ok=True, output=f"{before or 'not set'}")
        self.step(f"{name} set to {value}", ["reg", "add", key, "/v", name, "/t", typ, "/d", value, "/f"])

        def undo():
            if before:
                self.step(f"{name} restored to {before[1]}", ["reg", "add", key, "/v", name, "/t", before[0], "/d", before[1], "/f"])
            else:
                self.step(f"{name} removed again", ["reg", "delete", key, "/v", name, "/f"])
        return undo

    def discard_rollback(self, outcome):
        pass


def free_bytes(path):
    """Free space on the filesystem that holds path (or would, once created)."""
    while not os.path.isdir(path) and os.path.dirname(path) != path:
        path = os.path.dirname(path)
    return shutil.disk_usage(path).free


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


# ---- local log (DECISIONS 69) ------------------------------------------------------
LOG_PATH = (os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "Nimstead", "agent.log") if os.name == "nt"
            else "/var/lib/nimstead/agent.log")
LOG_MAX_BYTES = 1 << 20  # the log and one rotated copy, agent.log.1
LOGGED_COMMANDS = ("report", "remediate", "resume-job")  # each locks the folder first; `collect` must never write here
LOG_SECRET = re.compile(r"\bnm[a-z]_[A-Za-z0-9_-]+")  # the server's agent keys and tokens, whatever text echoes one
_log_on = False  # set once this run's command has locked the folder; a planted link there must never be written through
_agent_key = None


def log_event(text):
    """Add one line to the local log. Never raises and never prints: a logging failure must not stop a run."""
    if not _log_on:
        return
    try:
        text = str(text)
        for secret in (_agent_key, os.environ.get("NIMSTEAD_TOKEN")):
            if secret:
                text = text.replace(secret, "[secret]")
        line = " ".join(LOG_SECRET.sub("[secret]", text).split())[:2000]  # server text: one line, bounded
        os.makedirs(os.path.dirname(LOG_PATH), mode=0o700, exist_ok=True)
        if os.path.exists(LOG_PATH) and os.path.getsize(LOG_PATH) >= LOG_MAX_BYTES:
            os.replace(LOG_PATH, LOG_PATH + ".1")
        fd = os.open(LOG_PATH, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "a", encoding="utf-8", errors="replace") as f:
            f.write(time.strftime("%Y-%m-%dT%H:%M:%SZ ", time.gmtime()) + line + "\n")
    except (OSError, ValueError, TypeError):
        pass


OUTCOME_DIR = (os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "Nimstead", "outcomes") if os.name == "nt"
               else "/var/lib/nimstead/outcomes")


def run_jobs(server, key, insecure_http, run=sh, outcome_dir=None, win_state=None, ran=None, **job_kw):
    """Execute jobs, persisting every outcome before reporting so none is lost if the report fails.
    Unsent outcomes from earlier runs are retried first. The id of every job that ran is appended to `ran`.
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
            log_event("job {}: report failed: {}".format(rec["id"], e))
            problems += 1

    def record(job_id, report):
        nonlocal problems
        path = os.path.join(outcome_dir, re.sub(r"[^A-Za-z0-9]", "", str(job_id)) + ".json")
        with open(path, "w") as f:
            json.dump({"id": job_id, "report": report}, f)
        print("job {}: {}{}".format(job_id, report["outcome"], f" ({report['error']})" if report.get("error") else ""))
        log_event("job {}: {}{}".format(job_id, report["outcome"], f" ({report['error']})" if report.get("error") else ""))
        if ran is not None:
            ran.append(job_id)
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
            log_event(f"pending Windows job not resumed: {e}")
            problems += 1
        else:
            rc, pending = ps(run, PS_REBOOT_PENDING)
            if w.s["phase"] in ("verify", "rolled_back_pending") and rc == 0 and pending.strip().lower() == "true":
                return problems, True  # its restart hasn't happened yet (a user put it off): judge nothing until it has
            res = w.advance()
            if res["outcome"] == "pending_reboot":
                return problems, True
            record(w.s["job"]["id"], res)
    for job in post(server, "/api/agent/jobs", None, insecure_http, key):
        try:
            mgr = job.get("manager")
            runner = (WinJob(job, run=run, state_path=win_state) if mgr == "windows" else WinAppJob(job, run=run)
                      if mgr in WIN_APP_MANAGERS else Job(job, run=run, **job_kw))
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
        j.discard_rollback(outcome)
    return problems, False


# ---- Windows remediation -------------------------------------------------------
# One cumulative update by KB through the Windows Update Agent, run as SYSTEM. It needs a reboot, so the job is a
# small state machine persisted to disk: apply -> reboot -> verify/health -> done, or -> remove the new package with
# DISM -> reboot -> verify the original build is back. Rollback = DISM removal of the newly added RollupFix package;
# if Windows marks that package permanent the change can't be undone, which is reported loudly, never as success.

WIN_STATE = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "Nimstead", "pending-job.json")
SAFE_KB = re.compile(r"^[0-9]{6,8}\Z")
# DISM/CBS "busy" results: servicing still running (RPC disconnected, CBS busy/pending, file in use)
DISM_TRANSIENT = ("0x80010108", "0x800f0816", "0x800f082f", "0x80070020", "0x800f0805", "0x80004005")
DISM_RETRIES = 15
SAFE_PRODUCT = re.compile(r"^(?:\.NET Framework 4[0-9.]* on )?Windows [A-Za-z0-9 .()-]{1,120}\Z")
ROLLUP = re.compile(r"Package Identity : (Package_for_(?:RollupFix|DotNetRollup_\d+)~[^\s]+)\s+State : ([A-Za-z ]+)")
ROLLUP_NAME = re.compile(r"^Package_for_(?:RollupFix|DotNetRollup_\d+)~[A-Za-z0-9._~-]{1,200}\Z")
TRUSTED_OWNERS = {"S-1-5-18", "S-1-5-32-544"}  # SYSTEM, Administrators

PS_FIND = r"""
$s = New-Object -ComObject Microsoft.Update.Session
$q = $s.CreateUpdateSearcher(); %WU_SOURCE%
$r = $q.Search("IsInstalled=0 and Type='Software'")
ConvertTo-Json -Compress -InputObject @($r.Updates | Where-Object { $_.KBArticleIDs -contains '%KB%' } | ForEach-Object {
  [pscustomobject]@{ title = $_.Title; uninstallable = $_.IsUninstallable; reboot = $_.InstallationBehavior.RebootBehavior } })
"""
PS_DOWNLOAD = r"""
$s = New-Object -ComObject Microsoft.Update.Session
$q = $s.CreateUpdateSearcher(); %WU_SOURCE%
$r = $q.Search("IsInstalled=0 and Type='Software'")
$c = New-Object -ComObject Microsoft.Update.UpdateColl
$r.Updates | Where-Object { $_.KBArticleIDs -contains '%KB%' } | ForEach-Object { [void]$c.Add($_) }
if ($c.Count -ne 1) { throw "expected exactly one update for KB%KB%, found $($c.Count)" }
$d = $s.CreateUpdateDownloader(); $d.Updates = $c; [int]$d.Download().ResultCode
"""
# Whether the downloaded packages are permanent, read from their own top-level manifests (update.mum) BEFORE installing.
# WUA's IsUninstallable can't be used: on Server 2025 it says False for cumulative updates that DISM removes fine.
# Windows 11 downloads "express" updates: Windows Update's own install plan (ActionList.xml) lists every package it will
# install (the cumulative update plus companions: servicing stack, Safe OS, enablement), and the cumulative update's
# manifests are already expanded under its ExpressPackagePath at download time. Without an ActionList (Server 2025) the
# update is one .wim (mounted read-only) or .cab. Anything else, or a manifest that can't be read: fail, never guess.
PS_PERMANENCE = r"""
$dl = 'C:\Windows\SoftwareDistribution\Download'
function Read-Manifest($path, $reason, $partition) {
  $tmp = $null; $mounted = $false
  try {
    if (Test-Path -LiteralPath $path -PathType Container) { $dir = $path } else {
      $tmp = Join-Path $env:ProgramData ('Nimstead\mum-' + [guid]::NewGuid()); New-Item -ItemType Directory $tmp | Out-Null; $dir = $tmp
      if ($path -like '*.wim') {
        dism /mount-wim "/wimfile:$path" /index:1 "/mountdir:$tmp" /readonly /english | Out-Null
        if ($LASTEXITCODE) { throw "mounting $path failed: $LASTEXITCODE" }
        $mounted = $true
      } elseif ($path -like '*.cab') { expand.exe "-F:*.mum" $path $tmp | Out-Null } else { throw "unknown package format: $path" }
    }
    $x = [xml](Get-Content -LiteralPath (Join-Path $dir 'update.mum') -Raw -ErrorAction Stop)
    [pscustomobject]@{ file = (Split-Path $path -Leaf); reason = $reason; partition = $partition;
      permanent = (@($x.assembly.permanence, $x.assembly.package.permanence) -contains 'permanent');
      permanent_parts = @(Get-ChildItem -LiteralPath $dir -File -Filter *.mum | Select-String -Pattern 'permanence="permanent"' -List | ForEach-Object { $_.Filename }) }
  } finally {
    if ($mounted) { dism /unmount-wim "/mountdir:$tmp" /discard | Out-Null }
    if ($tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
  }
}
$al = Get-ChildItem $dl -Directory | ForEach-Object { Get-Item -LiteralPath (Join-Path $_.FullName 'ActionList.xml') -ErrorAction SilentlyContinue } |
  Where-Object { (Get-Content -LiteralPath $_.FullName -Raw) -match 'FeatureId="CumulativeUpdate_KB%KB%"' } |
  Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($al) {
  $root = $al.DirectoryName
  $plan = ([xml](Get-Content -LiteralPath $al.FullName -Raw)).ActionList
  $acts = @($plan.Actions.InstallPackage)
  if (-not $acts) { throw "no packages in $($al.FullName)" }
  function Inside($rel) {
    $p = [IO.Path]::GetFullPath((Join-Path $root $rel))
    if (-not $p.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { throw "package path outside the download folder: $rel" }
    $p
  }
  $out = @(foreach ($a in $acts) {
    Read-Manifest (Inside $(if ($a.PayloadType -eq 'Express') { $a.ExpressPackagePath } else { $a.FilePath })) $a.Reason $a.Partition
  })
  if (-not @($out | Where-Object reason -eq 'CumulativeUpdate')) {  # Windows 10: the plan's actions are the servicing stack; the update is only a download
    $out += @($plan.Downloads.Package | Where-Object FeatureId -eq 'CumulativeUpdate_KB%KB%' | ForEach-Object { Read-Manifest (Inside $_.Payload.SourceName) $_.Reason 'MainOS' })
  }
} else {
  $f = Get-ChildItem $dl -Recurse -Depth 1 -File -Include '*KB%KB%*.wim','*KB%KB%*.cab' |
    Where-Object { $_.FullName -notmatch '\\Metadata\\' } | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if (-not $f) { throw "downloaded package for KB%KB% not found" }
  $out = Read-Manifest $f.FullName 'CumulativeUpdate' 'MainOS'
}
ConvertTo-Json -Compress -Depth 4 -InputObject @($out)
"""
# Companions Windows ships as permanent with every Windows 11 cumulative update. Neither changes the OS build that
# rollback restores, so like permanent Feature-on-Demand parts they stay after a rollback and are reported, not refused.
PERMANENT_COMPANIONS = {("ServicingStackUpdate", "MainOS"), ("SafeOSDU", "WinRE")}


def removable(pkgs):
    """(ok, detail) for the packages Windows Update will install. Rollback removes only the new cumulative package, so
    that must not be permanent; every companion must be readable and either removable or a known permanent companion."""
    main = [p for p in pkgs if p.get("reason") == "CumulativeUpdate"]
    if len(main) != 1:
        return False, f"expected one cumulative update package, found {len(main)}: {json.dumps(pkgs)[:600]}"
    rest = [p for p in pkgs if p is not main[0]]
    bad = [p for p in [main[0], *rest] if p.get("permanent") is not False
           and not (p is not main[0] and p.get("permanent") is True and (p.get("reason"), p.get("partition")) in PERMANENT_COMPANIONS)]
    if bad:
        return False, "permanent or unreadable: " + ", ".join(f"{p.get('file')} ({p.get('reason')}, {p.get('partition')})" for p in bad)
    stays = ", ".join(f"{p.get('file')} ({p.get('reason')}, {p.get('partition')}{', permanent' if p['permanent'] else ''})" for p in rest)
    return True, (f"{main[0].get('file')}: update.mum not permanent; permanent parts: {', '.join(main[0].get('permanent_parts') or []) or 'none'}"
                  + (f"; also installed, stays after rollback: {stays}" if stays else ""))
PS_INSTALL = r"""
$s = New-Object -ComObject Microsoft.Update.Session
$q = $s.CreateUpdateSearcher(); %WU_SOURCE%
$r = $q.Search("IsInstalled=0 and Type='Software'")
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


# Service Control Manager crash/stop events (7031, 7034, 7024) for one service since a moment, as "id time" lines
PS_CRASHES = r"""
$dn = (Get-Service -Name '%SVC%' -ErrorAction Stop).DisplayName
$t = [DateTimeOffset]::FromUnixTimeSeconds(%SINCE%).LocalDateTime
@(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = 7031, 7034, 7024; StartTime = $t } -ErrorAction SilentlyContinue |
  Where-Object { $_.Properties[0].Value -eq $dn } | ForEach-Object { "event $($_.Id) at $($_.TimeCreated.ToString('s'))" }) -join "; "
"""
# Battery below half and not on mains power: an update must not start (plan T41); no battery = fine
PS_ON_BATTERY = r"""
$b = @(Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue)
if ($b.Count -and ($b | Where-Object { $_.BatteryStatus -ne 2 -and $_.EstimatedChargeRemaining -lt 50 })) { "battery $($b[0].EstimatedChargeRemaining)%" }
"""
# Whole GB free on the system drive. A Windows 11 VM with 40 GB filled up after one install + rollback (WinSxS 19.6 GB)
# and the next download failed with a bare code 4; refuse before downloading instead
PS_FREE_GB = "[math]::Floor((Get-PSDrive $env:SystemDrive.TrimEnd(':')).Free / 1GB)"
WIN_MIN_FREE_GB = 10
# Why Windows Update offered nothing for a KB (plan T14): its source, deferrals, ESU
PS_WHY_NOT_OFFERED = r"""
$wu = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$p = Get-ItemProperty $wu -ErrorAction SilentlyContinue; $au = Get-ItemProperty "$wu\AU" -ErrorAction SilentlyContinue
$why = @()
if ($au.UseWUServer -eq 1) { $why += "this machine gets updates from WSUS ($($p.WUServer)); WSUS hasn't approved KB%KB% for it" }
if ($p.DeferQualityUpdates -eq 1 -or $p.DeferQualityUpdatesPeriodInDays) { $why += "quality updates are deferred $($p.DeferQualityUpdatesPeriodInDays) days by policy" }
if ($p.PauseQualityUpdatesStartTime) { $why += "quality updates are paused by policy since $($p.PauseQualityUpdatesStartTime)" }
$esu = @(Get-CimInstance SoftwareLicensingProduct -Filter "LicenseStatus=1 and PartialProductKey is not null" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'ESU' }).Count
if ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -lt 22000 -and -not $esu) { $why += "no Extended Security Updates licence is active" }
$why -join "; "
"""
# Failover cluster node: drain its roles before the update, bring it back after (plan T42)
PS_CLUSTER_NODE = r"""if (Get-ItemProperty 'HKLM:\Cluster' -ErrorAction SilentlyContinue) { $env:COMPUTERNAME }"""
PS_CLUSTER_DRAIN = r"""Suspend-ClusterNode -Name $env:COMPUTERNAME -Drain -Wait -ErrorAction Stop | Out-Null; (Get-ClusterNode -Name $env:COMPUTERNAME).State"""
PS_CLUSTER_RESUME = r"""Resume-ClusterNode -Name $env:COMPUTERNAME -Failback Immediate -ErrorAction Stop | Out-Null; (Get-ClusterNode -Name $env:COMPUTERNAME).State"""
# Someone signed in at the console or over RDP: their restart can be put off until the job's deadline (plan T41)
PS_SIGNED_IN = r"""@(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction SilentlyContinue).Count"""


WU_SOURCE = None  # "microsoft": search Microsoft Update directly, not WSUS (enroll --windows-update-source; local only)


def wu(script):
    """A Windows Update script searching this host's configured source, or Microsoft Update when the host opted in."""
    return script.replace("%WU_SOURCE%", "$q.ServerSelection = 2" if WU_SOURCE == "microsoft" else "")


def ps(run, script, **kw):
    return run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], **kw)


def boot_time():
    """When this machine last booted (epoch seconds), from the tick counter; 0 where unknown."""
    if os.name != "nt":
        return 0
    import ctypes
    ctypes.windll.kernel32.GetTickCount64.restype = ctypes.c_ulonglong
    return time.time() - ctypes.windll.kernel32.GetTickCount64() / 1000


def windows_build():
    import winreg
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", 0,
                        winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
        return "10.0.{}.{}".format(int(winreg.QueryValueEx(k, "CurrentBuild")[0]), int(winreg.QueryValueEx(k, "UBR")[0]))


def netfx_build(run=sh):
    """The file version MSRC's .NET Framework fixes are stated in; a .NET update doesn't change the Windows build."""
    rc, out = ps(run, r"(Get-Item (Join-Path $env:windir 'Microsoft.NET\Framework64\v4.0.30319\mscorlib.dll')).VersionInfo.FileVersion")
    if rc != 0 or not re.match(r"\d+\.\d+\.\d+\.\d+", out.strip()):
        raise AgentError(f"couldn't read the .NET Framework version: {out.strip()[-200:]}")
    return out.split()[0]


class WinJob:
    """Phases: start -> (reboot) -> verify -> done | rollback -> (reboot) -> rolled_back. State lives in WIN_STATE."""

    def __init__(self, job=None, run=sh, state_path=WIN_STATE, build=windows_build, settle=None, fail_after_apply=False,
                 retry_wait=60, booted=None):
        self.run, self.state_path, self.build, self.retry_wait = run, state_path, build, retry_wait
        self.booted = booted or boot_time
        if job is not None:
            p = (job.get("packages") or [{}])[0]
            alt = p.get("alt") if isinstance(p.get("alt"), dict) else None  # the same fix as a hotpatch (DECISIONS 52)
            reboot_by = job.get("reboot_by") if re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", str(job.get("reboot_by", ""))) else None
            self.s = {"job": job, "phase": "start", "steps": [], "kb": str(p.get("kb", "")), "from": p.get("from"),
                      "to": p.get("to"), "product": p.get("name"), "units": job.get("health_units") or [],
                      "alt": {"kb": str(alt.get("kb", "")), "to": alt.get("to")} if alt else None, "reboot_by": reboot_by,
                      "settle": min(max(int(job.get("settle_seconds", 60) or 0), 0), 900) if settle is None else int(settle),
                      "inject": bool(fail_after_apply)}  # sandbox fault injection (run-job only; never from the server)
        else:
            with open(state_path) as f:
                self.s = json.load(f)
            if not self.valid():  # never trust the file: it decides what runs as SYSTEM after the reboot
                raise AgentError(f"{state_path} failed validation; not resumed")
        if str(self.s.get("product")).startswith(".NET Framework"):
            self.build = lambda: netfx_build(self.run)

    def valid(self):
        s = self.s
        try:
            return bool(
                s.get("phase") in ("start", "verify", "rolled_back_pending") and isinstance(s.get("steps"), list)
                and SAFE_KB.match(str(s.get("kb", ""))) and SAFE_PRODUCT.match(str(s.get("product")))
                and SAFE_VERSION.match(str(s.get("from") or "")) and (s.get("to") is None or SAFE_VERSION.match(str(s["to"])))
                and (s.get("alt") is None or (isinstance(s["alt"], dict) and SAFE_KB.match(str(s["alt"].get("kb", "")))
                                              and SAFE_VERSION.match(str(s["alt"].get("to") or ""))))
                and (s.get("reboot_by") is None or re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", str(s["reboot_by"])))
                and (s.get("changed_at") is None or (isinstance(s["changed_at"], int) and not isinstance(s["changed_at"], bool)))
                and isinstance(s.get("cluster", False), bool) and isinstance(s.get("notified_at", 0), (int, float))
                and isinstance(s.get("late_removal", False), bool) and isinstance(s.get("installing", False), bool)
                and isinstance(s.get("boot", 0), int) and not isinstance(s.get("boot", 0), bool)
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

    def _resume_cluster(self):
        """Bring a drained cluster node back (after success, rollback or a failed start); recorded, never raises."""
        if self.s.get("cluster") and not self.s.get("resumed"):
            rc, out = ps(self.run, PS_CLUSTER_RESUME)
            self.s["resumed"] = rc == 0
            self.s["steps"].append({"step": "cluster node resumed", "ok": rc == 0, "output": str(out)[-1500:]})

    def result(self, outcome, error=None):
        self._resume_cluster()
        self.clear()
        return {"outcome": outcome, "steps": self.s["steps"], "error": error,
                "versions": {self.s["product"]: self.build()} if outcome == "applied" else None}

    def pending(self):
        self.s["boot"] = int(self.booted())  # the restart it waits for is a new boot, not just time passing
        self.save()
        return {"outcome": "pending_reboot", "steps": self.s["steps"], "error": None, "versions": None}

    def restarted(self):
        """Whether the machine has booted since the job started waiting. Seen for real (Windows 11 VM): after a DISM
        removal with /norestart no reboot-pending flag is set, and a job poll that judged the rollback before the restart
        found the new build still running and reported ROLLBACK FAILED."""
        return self.s.get("boot") is None or abs(self.booted() - self.s["boot"]) > 120

    def rollups(self):
        rc, out = self.run(["dism", "/online", "/get-packages", "/format:list", "/english"])
        if rc != 0:
            raise StepFailed("dism /get-packages failed: " + out[-300:])
        netfx = str(self.s.get("product")).startswith(".NET Framework")  # each job removes only its own kind of package
        return {k: v for k, v in ROLLUP.findall(out.replace("\r", "")) if ("DotNetRollup" in k) == netfx}

    def health(self, when):
        """Running now, and no crash or unexpected stop logged for it since the change (DECISIONS 29 for Windows,
        plan T13): a service that dies and is restarted by its recovery actions can read "Running" when sampled."""
        since = self.s.get("changed_at")
        for u in self.s["units"]:
            rc, out = ps(self.run, f"(Get-Service -Name '{u}' -ErrorAction Stop).Status")
            ok = rc == 0 and out.strip() == "Running"
            if ok and since:
                rc2, crashes = ps(self.run, PS_CRASHES.replace("%SVC%", u).replace("%SINCE%", str(int(since))))
                ok = rc2 == 0 and not crashes.strip()
                out = out.strip() + (f"; since the change: {crashes.strip()[-300:]}" if crashes.strip() else "")
            self.step(f"{u} running {when}", ok, out)

    # -- phases
    def advance(self):
        """Run until finished or until a reboot is needed. Returns a report dict (outcome may be pending_reboot)."""
        phase = self.s["phase"]
        if phase in ("verify", "rolled_back_pending") and not self.restarted():
            return {"outcome": "pending_reboot", "steps": self.s["steps"], "error": None, "versions": None}  # judge nothing yet
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

    def _interrupted(self):
        """The machine stopped during the install (seen for real, Windows 10). Anything new goes the way of a failed update;
        nothing new means nothing changed, and a drained cluster node comes back either way (DECISIONS 78)."""
        s = self.s
        try:
            new = sorted(set(self.rollups()) - set(s["baseline"]))
        except StepFailed:  # servicing still busy: look again at the next poll, never guess
            return {"outcome": "pending_reboot", "steps": s["steps"], "error": None, "versions": None}
        s["steps"].append({"step": "stopped during the install, checked what it left", "ok": True, "output": ", ".join(new) or "nothing new"})
        if new:
            s["phase"], s["new_packages"] = "verify", new
            return self._verify()
        return self.result("aborted", "No changes made: the machine stopped during the install and nothing new is installed. Plan the fix again.")

    def _start(self):
        s = self.s
        if s.get("installing"):
            return self._interrupted()
        ok = self.valid()
        self.step("job validated", ok, "" if ok else "invalid KB, product, version or service name")
        s["steps"] = s["steps"][-1:]  # a resume after a power cut starts its checks again
        self.save()  # nothing has changed yet: a machine that stops here starts the job over at its next run
        cur = self.build()
        self.step("installed build matches plan", cur == s["from"], f"installed {cur}, planned {s['from']}")
        rc, out = ps(self.run, PS_REBOOT_PENDING)
        self.step("no reboot already pending", rc == 0 and out.strip().lower() == "false", out)
        self.health("before change")
        rc, out = ps(self.run, PS_ON_BATTERY)
        self.step("on mains power or battery above half", rc == 0 and not out.strip(), out.strip() or "ok")
        rc, out = ps(self.run, PS_FREE_GB)
        self.step(f"at least {WIN_MIN_FREE_GB} GB free on the system drive", rc == 0 and out.strip().isdigit()
                  and int(out) >= WIN_MIN_FREE_GB, f"{out.strip()} GB free")
        found = {}  # KB -> (target build, how many updates Windows Update offers for it)
        for kb, to in [(s["kb"], s["to"]), *([(s["alt"]["kb"], s["alt"]["to"])] if s.get("alt") else [])]:
            rc, out = ps(self.run, wu(PS_FIND).replace("%KB%", kb))
            found[kb] = (to, len(json.loads(out)) if rc == 0 and out.strip().startswith("[") else 0, out)
        offered = [kb for kb, (_, n, _) in found.items() if n == 1]
        if not offered:  # say why, from this machine's own update settings (plan T14)
            rc, why = ps(self.run, PS_WHY_NOT_OFFERED.replace("%KB%", s["kb"]))
            for kb in found:
                found[kb] = (found[kb][0], found[kb][1], (found[kb][2].strip() + "; " if found[kb][2].strip() else "")
                             + (why.strip() or "Windows Update didn't offer it (not needed, superseded, or not released for this build)"))
        if len(found) == 1:
            self.step(f"Windows Update offers exactly KB{s['kb']}", offered, found[s["kb"]][2])
        else:  # cumulative or hotpatch: whichever this host is offered, never both
            self.step(f"Windows Update offers exactly one of KB{' / KB'.join(found)}", len(offered) == 1,
                      "; ".join(f"KB{kb}: {n} offered" for kb, (_, n, _) in found.items()) + ("" if offered else f"; {found[s['kb']][2]}"))
            s["kb"], s["to"] = offered[0], found[offered[0]][0]
        s["baseline"] = self.rollups()
        self.step("rollback baseline recorded", any(v.strip() == "Installed" for v in s["baseline"].values()),
                  "installed cumulative packages: " + ", ".join(k for k, v in s["baseline"].items() if v.strip() == "Installed"))
        rc, out = ps(self.run, wu(PS_DOWNLOAD).replace("%KB%", s["kb"]))
        self.step(f"KB{s['kb']} downloaded", rc == 0 and out.strip().splitlines()[-1:] in (["2"], ["3"]), out)
        rc, out = ps(self.run, PS_PERMANENCE.replace("%KB%", s["kb"]))
        # permanent sub-packages (Features on Demand) stay behind on removal; rollback is judged by the build returning
        ok, detail = removable(json.loads(out)) if rc == 0 and out.strip().startswith("[") else (False, out)
        self.step("update is removable (manifest checked before install)", ok, detail)
        rc, node = ps(self.run, PS_CLUSTER_NODE)
        if rc == 0 and node.strip():  # a failover cluster node: move its roles off first; a failed drain changes nothing
            rc, out = ps(self.run, PS_CLUSTER_DRAIN)
            s["cluster"] = True
            if rc != 0 or out.strip().splitlines()[-1:] != ["Paused"]:
                self._resume_cluster()
            self.step("cluster node drained", rc == 0 and out.strip().splitlines()[-1:] == ["Paused"], out)
        s["changed_at"] = int(time.time())  # health checks look for crashes after this
        s["installing"] = True
        self.save()  # a power cut from here on must leave something to resume from
        # seen for real (Windows 11, user signed in): a reinstall of the cumulative update ran past 30 minutes
        rc, out = ps(self.run, wu(PS_INSTALL).replace("%KB%", s["kb"]), timeout=INSTALL_TIMEOUT)
        res = json.loads(out) if rc == 0 and out.strip().startswith("{") else {}
        s["phase"], s["installing"] = "verify", False  # from here on, failures roll back
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
            if not s.get("new_packages") and "baseline" in s:  # the install step failed before it listed them
                s["new_packages"] = sorted(set(self.rollups()) - set(s["baseline"]))
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
        # Windows Update keeps installing after the agent stops waiting for it (seen for real: the install call timed
        # out, the update landed during the rollback restart); remove what arrived late, once
        late = sorted(set(self.rollups()) - set(s.get("baseline", {})) - set(s.get("new_packages", []))) if cur != s["from"] else []
        if late and not s.get("late_removal"):
            s["late_removal"], s["new_packages"] = True, late
            self.s["steps"].append({"step": "update finished installing after the agent stopped waiting", "ok": True, "output": ", ".join(late)})
            return self._rollback(s.get("error") or "")
        if cur != s["from"]:
            return self.result("rollback_failed", f"ROLLBACK FAILED: build is {cur}, expected {s['from']}. Change error: {s.get('error')}")
        self.s["steps"].append({"step": "original build restored", "ok": True, "output": cur})
        try:
            self.health("after rollback")
        except StepFailed as e:
            return self.result("rollback_failed", f"ROLLBACK FAILED: {e}")
        return self.result("rolled_back", f"Change failed and was rolled back: {s.get('error')}")


def restart_for_update(run=None, state_path=None, client=None, now=None):
    """The restart a Windows job needs (plan T41). Servers restart now: the job was only handed out inside the
    maintenance window. A workstation with someone signed in is told and may put it off until the job's deadline
    (reboot_by), reminded at most hourly; then it restarts with a 15-minute warning. Returns ("now"|"later", message)."""
    run, state_path = run or sh, state_path or WIN_STATE
    w = WinJob(run=run, state_path=state_path)
    if client is None:
        rc, it = ps(run, "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').InstallationType")
        client = rc == 0 and it.strip() == "Client"
    rc, users = ps(run, PS_SIGNED_IN)
    signed_in = rc == 0 and users.strip().isdigit() and int(users.strip()) > 0
    t = now or time.time()
    import calendar
    deadline = calendar.timegm(time.strptime(w.s["reboot_by"], "%Y-%m-%dT%H:%M:%SZ")) if w.s.get("reboot_by") else t
    if client and signed_in and t < deadline:
        if t - w.s.get("notified_at", 0) >= 3600:
            run(["msg", "*", "/TIME:3600", "A security update needs a restart. Please restart when convenient; it will restart "
                 f"automatically after {time.strftime('%Y-%m-%d %H:%M', time.localtime(deadline))}. Windows may restart it sooner, outside active hours."])
            w.s["notified_at"] = t
            w.save()
        return "later", f"restart put off until {w.s['reboot_by']}: someone is signed in"
    warn = 900 if signed_in else 60
    rc, out = run(["shutdown", "/r", "/t", str(warn), "/c", "Nimstead: restarting to finish a security update"])
    if rc != 0:
        raise AgentError(f"could not schedule the restart the update needs: {out.strip()}")
    return "now", f"restarting in {warn} s to finish the update"


# Enabled computer objects in this machine's own domain, read with the machine's identity (plan T43): no credentials,
# no network probing, names and OS strings only.
PS_AD_COMPUTERS = r"""
$s = [adsisearcher]'(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
$s.PageSize = 1000; $s.SizeLimit = 20000
[void]$s.PropertiesToLoad.AddRange(@('name', 'operatingsystem', 'operatingsystemversion', 'lastlogontimestamp'))
ConvertTo-Json -Compress -InputObject ([ordered]@{ domain = "$((Get-CimInstance Win32_ComputerSystem).Domain)"; computers = @($s.FindAll() | ForEach-Object {
  $p = $_.Properties
  [ordered]@{ name = "$($p['name'])"; os = "$($p['operatingsystem'])"; os_version = "$($p['operatingsystemversion'])";
    last_logon = if ($p['lastlogontimestamp'].Count) { [DateTime]::FromFileTimeUtc([int64]"$($p['lastlogontimestamp'])").ToString('s') + 'Z' } else { $null } } }) })
"""


def ad_computers(run=None):
    rc, out = ps(run or sh, PS_AD_COMPUTERS)
    try:
        d = json.loads(out.strip().splitlines()[-1]) if rc == 0 else None
    except (ValueError, IndexError):
        d = None
    if not (isinstance(d, dict) and isinstance(d.get("computers"), list) and d.get("domain")):
        raise AgentError(f"Active Directory read failed: {out.strip()[-200:]}")
    return d


def windows_version_key(v):
    return tuple(int(x) for x in str(v).split("."))


# ---- network ----------------------------------------------------------------

# --- Ed25519 verification (RFC 8032 5.1.7), stdlib only, for release signatures. Verify only: no signing code here.
_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _ed_add(a, b):  # extended homogeneous coordinates (RFC 8032 5.1.4)
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    pa, pb = (y1 - x1) * (y2 - x2) % _P, (y1 + x1) * (y2 + x2) % _P
    pc, pd = 2 * t1 * t2 * _D % _P, 2 * z1 * z2 % _P
    e, f, g, h = pb - pa, pd - pc, pd + pc, pb + pa
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _ed_mul(s, pt):
    q = (0, 1, 1, 0)
    while s:
        if s & 1:
            q = _ed_add(q, pt)
        pt, s = _ed_add(pt, pt), s >> 1
    return q


def _ed_decode(b):
    """Point decompression (RFC 8032 5.1.3); None for anything that isn't a valid encoding."""
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        if sign:
            return None
        return (0, y, 1, 0)
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P:
        return None
    if x & 1 != sign:
        x = _P - x
    return (x, y, 1, x * y % _P)


_ED_BASE = _ed_decode((4 * pow(5, _P - 2, _P) % _P).to_bytes(32, "little"))


def ed25519_verify(pub, msg, sig):
    """True only for a valid signature by pub over msg; never raises on malformed input."""
    if not (isinstance(pub, bytes) and isinstance(sig, bytes)) or len(pub) != 32 or len(sig) != 64:
        return False
    a, r = _ed_decode(pub), _ed_decode(sig[:32])
    s = int.from_bytes(sig[32:], "little")
    if a is None or r is None or s >= _L:  # s < L rules out malleable signatures
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little") % _L
    x1, y1, z1, _ = _ed_mul(s, _ED_BASE)
    x2, y2, z2, _ = _ed_add(r, _ed_mul(h, a))
    return (x1 * z2 - x2 * z1) % _P == 0 and (y1 * z2 - y2 * z1) % _P == 0


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):  # never forward the agent key to another URL
        return None


_opener = urllib.request.build_opener(_NoRedirect)
_proxy = None
SAFE_PROXY = re.compile(r"^https?://[A-Za-z0-9.\-\[\]:]{1,255}\Z")


def winhttp_proxy(run=None):
    """The machine-wide WinHTTP proxy (what Windows Update uses as SYSTEM), or None. `netsh` prints either one
    host:port or per-scheme entries; only an https= entry or a single host:port is used."""
    rc, out = (run or sh)(["netsh", "winhttp", "show", "proxy"])
    m = re.search(r"(?m)^[ \t]*[^:\r\n]+:[ \t]*(\S+)", out) if rc == 0 else None  # first "label: value" line: labels are localised
    if not m:
        return None
    v = m.group(1)
    if "=" in v:
        v = next((p.split("=", 1)[1] for p in v.split(";") if p.startswith("https=")), "")
    return f"http://{v}" if v and "://" not in v else v or None


def use_proxy(url, run=None):
    """Send every server call through `url` (the enrol --proxy), else the WinHTTP proxy on Windows. TLS stays end to
    end (CONNECT); plain-http servers are refused through a proxy, so the agent key never crosses it in clear."""
    global _opener, _proxy
    url = url or (winhttp_proxy(run) if os.name == "nt" else None)
    if not url:
        return None
    if not SAFE_PROXY.match(url):
        raise AgentError(f"proxy must be http://host:port or https://host:port, not {url!r}")
    _proxy = url
    _opener = urllib.request.build_opener(_NoRedirect, urllib.request.ProxyHandler({"https": url, "http": url}))
    return url


class run_lock:
    """Single remediation run at a time (cron/timer overlap)."""
    dir = None  # default: the agent's state folder

    def __enter__(self):
        d = self.dir or (os.path.dirname(WIN_STATE) if os.name == "nt" else "/var/lib/nimstead")
        try:
            os.makedirs(d, exist_ok=True)
            self.f = open(os.path.join(d, "agent.lock"), "w")
        except OSError as e:  # e.g. `report` run as a non-root user: callers decide whether that matters
            raise AgentError(f"cannot take the run lock in {d}: {e}") from None
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


def post(server, path, body, insecure_http, key=None, raw=False, limit=MAX_AGENT_BYTES):
    """POST JSON, or GET when body is None; raw=True returns the response bytes (capped) instead of parsed JSON."""
    if not server.startswith("https://") and not (insecure_http and server.startswith("http://")):
        raise AgentError(f"refusing non-HTTPS server {server!r} (use --insecure-http for local dev)")
    if _proxy and not server.startswith("https://"):
        raise AgentError("refusing to send the agent key to a plain-http server through a proxy")
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = "Bearer " + key
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(server.rstrip("/") + path, data, headers, method="GET" if body is None else "POST")
    try:
        with _opener.open(req, timeout=60) as r:
            data = r.read(limit + 1)  # JSON too: a server can't exhaust a root process's memory
            if len(data) > limit:
                raise AgentError(f"response from {path} is larger than {limit} bytes")
            return data if raw else json.loads(data or b"{}")
    except urllib.error.HTTPError as e:
        raise AgentError("server returned {}: {}".format(e.code, e.read(300).decode(errors="replace")))
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise AgentError(f"request to {server} failed: {e}")


def version_tuple(v):
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", v) if isinstance(v, str) else None
    return tuple(int(x) for x in m.groups()) if m else None


RUNTIME_ARCHES = {"AMD64": "amd64", "ARM64": "arm64", "X86": "win32"}.values()


def verify_release(manifest, sig_b64, keys=None):
    """The fields of a release manifest signed by a pinned key over these exact bytes; AgentError otherwise."""
    keys = RELEASE_KEYS if keys is None else keys
    if not keys:
        raise AgentError("no release keys are pinned in this agent")
    try:
        sig = base64.b64decode(sig_b64, validate=True)
    except (ValueError, TypeError):
        raise AgentError("release signature is not base64") from None
    if not any(ed25519_verify(bytes.fromhex(k), manifest, sig) for k in keys):
        raise AgentError("release signature doesn't match any pinned release key")
    rel = json.loads(manifest)
    if not (isinstance(rel, dict) and version_tuple(rel.get("version")) and version_tuple(rel.get("agent_version"))
            and re.fullmatch(r"[0-9a-f]{64}", str(rel.get("agent_sha256"))) and re.fullmatch(r"[0-9a-f]{40}", str(rel.get("commit")))):
        raise AgentError("signed release manifest is malformed")
    rt = rel.get("runtimes")  # the Windows agent's bundled Python (absent before 0.6.0)
    if rt is not None and not (isinstance(rt, dict) and rt and all(
            a in RUNTIME_ARCHES and isinstance(r, dict) and version_tuple(r.get("version"))
            and re.fullmatch(r"[0-9a-f]{64}", str(r.get("sha256"))) for a, r in rt.items())):
        raise AgentError("signed release manifest has a malformed runtimes entry")
    return rel


FAILED_RETRY_SECONDS = 24 * 3600
CHANNELS = ("preview", "beta", "stable")  # least to most proven, as the server's updates.CHANNELS


def release_channel(rel):
    return rel.get("channel") if rel.get("channel") in CHANNELS else "preview"  # manifests from before channels (0.3.0)


def channel_ok(rel, cfg):
    """A host takes its channel and anything more proven. Enrolled before channels existed: everything, as then."""
    mine = cfg.get("channel") if cfg.get("channel") in CHANNELS else "preview"
    return CHANNELS.index(release_channel(rel)) >= CHANNELS.index(mine)


def _failed_releases(memo):
    try:
        with open(memo) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _remember_failed(memo, sha):
    try:
        with open(memo, "w") as f:
            json.dump({**_failed_releases(memo), sha: time.time()}, f)
    except OSError:
        pass


def self_update(cfg, insecure_http, path=None, keys=None, smoke=None, memo=None):
    """Replace this agent file with a newer signed release relayed by the server.

    Returns (new_version, None) after an update, (None, None) when there's nothing to do, or (None, reason) when an update
    was refused or failed; the working agent is then left exactly as it was and the run carries on with it."""
    if not cfg.get("auto_update", True):
        return None, None
    if os.name == "nt" and os.path.exists(WIN_STATE):  # never swap the agent while a Windows job waits for its reboot
        return None, None
    path = path or os.path.abspath(__file__)
    tmp = path + ".new"
    memo = memo or os.path.join(os.path.dirname(config_path()), "failed-updates.json")
    try:
        m = post(cfg["server"], "/api/agent/manifest", None, insecure_http, cfg["agent_key"])
        if not isinstance(m, dict):
            raise AgentError("manifest response is not a JSON object")
        if m.get("paused") or not m.get("release") or not m.get("sig"):
            return None, None
        rel = verify_release(str(m["release"]).encode(), m["sig"], keys)
        # never from a release older than this agent: a replayed old manifest can't move a host to an older runtime
        runtime_problem = runtime_update(cfg, rel, insecure_http)             if channel_ok(rel, cfg) and version_tuple(rel["agent_version"]) >= version_tuple(AGENT_VERSION) else None
        if version_tuple(rel["agent_version"]) <= version_tuple(AGENT_VERSION):  # anti-rollback: only strictly newer
            return None, runtime_problem
        if not channel_ok(rel, cfg):  # the channel is signed: a server can't hand a stable host a preview build
            return None, f"skipping agent {rel['agent_version']}: signed for {release_channel(rel)}, this host takes {cfg.get('channel', 'preview')}"
        failed = _failed_releases(memo)
        if time.time() - failed.get(rel["agent_sha256"], 0) < FAILED_RETRY_SECONDS:  # don't redo a failing self-test every poll
            return None, f"skipping agent {rel['agent_version']}: it failed its self-test on this host in the last 24 hours"
        body = post(cfg["server"], "/agent/nimstead_agent.py", None, insecure_http, raw=True)
        if hashlib.sha256(body).hexdigest() != rel["agent_sha256"]:
            raise AgentError("downloaded agent doesn't match the signed release")
        with open(tmp, "wb") as f:
            f.write(body)
        os.chmod(tmp, stat.S_IMODE(os.stat(path).st_mode))  # same mode as the agent it replaces
        smoke = smoke or _smoke_test
        problem = smoke(tmp)
        if problem:
            _remember_failed(memo, rel["agent_sha256"])
            raise AgentError(f"new agent {rel['agent_version']} failed its self-test, kept {AGENT_VERSION}: {problem}")
        shutil.copy2(path, path + ".prev")  # kept for manual recovery
        os.replace(tmp, path)
        return rel["agent_version"], None
    except Exception as e:  # nothing about an update may stop the run that follows it
        try:
            os.remove(tmp)
        except OSError:
            pass
        return None, f"self-update failed: {e}"[:500]


# ---- the Windows agent's bundled Python (plan decision 9) ---------------------------------------------------------
RUNTIME_ROOT = os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Nimstead", "runtime")
RUNTIME_ARCH = {"AMD64": "amd64", "ARM64": "arm64", "X86": "win32"}
MAX_RUNTIME_BYTES = 40 * 1024 * 1024
PS_PSF_SIGNED = ("@(Get-ChildItem -LiteralPath %DIR% -Recurse -File | Where-Object { @('.exe', '.dll', '.pyd') -contains "
                 "$_.Extension.ToLower() } | Where-Object { "
                 "$s = Get-AuthenticodeSignature -LiteralPath $_.FullName; $s.Status -ne 'Valid' -or -not "
                 "($s.SignerCertificate.Subject -match '^CN=Python Software Foundation,' -or ($_.Name -match "
                 "'^vcruntime140(_1)?\\.dll$' -and $s.SignerCertificate.Subject -match ', O=Microsoft Corporation,')) }).Count")


def _runtime_dirs(root):
    try:
        return [os.path.join(root, n) for n in os.listdir(root) if re.fullmatch(r"[0-9a-f]{12}", n)]
    except OSError:
        return []


def runtime_update(cfg, rel, insecure_http, run=None, root=None, executable=None, smoke=None, machine=None):
    """Windows: move to the signed release's runtime when it isn't the one running (also off a system Python), the way
    the agent replaces itself: hash from the signed manifest, Python Software Foundation signature on every program file,
    the agent's own `collect` on it, then the scheduled tasks re-registered on it. Never while a Windows job waits for its
    reboot; never to an older Python. Returns a problem (the host keeps what it had) or None."""
    arch = RUNTIME_ARCH.get((machine or platform.machine()).upper())
    want = (rel.get("runtimes") or {}).get(arch)
    if (os.name != "nt" and machine is None) or not want or os.path.exists(WIN_STATE):
        return None
    run, root, exe = run or sh, root or RUNTIME_ROOT, executable or sys.executable
    target = os.path.join(root, want["sha256"][:12])
    keep = {os.path.normcase(os.path.dirname(exe)), os.path.normcase(target)}
    for d in _runtime_dirs(root):  # what an earlier switch left behind; never the one running
        if os.path.normcase(d) not in keep:
            shutil.rmtree(d, ignore_errors=True)
    if os.path.normcase(os.path.dirname(exe)) == os.path.normcase(target):
        return None
    bundled = os.path.normcase(os.path.dirname(os.path.dirname(exe))) == os.path.normcase(root)
    if bundled and version_tuple(want["version"]) < version_tuple(platform.python_version()):
        return f"skipping runtime {want['version']}: older than the Python {platform.python_version()} this agent runs on"
    tmp = target + ".new"
    try:
        body = post(cfg["server"], f"/agent/runtime/{arch}.zip", None, insecure_http, raw=True, limit=MAX_RUNTIME_BYTES)
        if hashlib.sha256(body).hexdigest() != want["sha256"]:
            raise AgentError("downloaded runtime doesn't match the signed release")
        shutil.rmtree(tmp, ignore_errors=True)
        with zipfile.ZipFile(io.BytesIO(body)) as z:
            if any(n.startswith(("/", "\\")) or ":" in n or ".." in n.replace("\\", "/").split("/") for n in z.namelist()):
                raise AgentError("runtime archive has unsafe paths")
            z.extractall(tmp)  # noqa: S202 - every member name checked just above, and the bytes match the signed hash
        rc, out = ps(run, PS_PSF_SIGNED.replace("%DIR%", _ps_quote(tmp)))
        if rc != 0 or out.strip() != "0" or not os.path.exists(os.path.join(tmp, "python.exe")):
            raise AgentError(f"runtime isn't signed by the Python Software Foundation: {out.strip()[-200:]}")
        shutil.rmtree(target, ignore_errors=True)
        os.replace(tmp, target)
        new_exe = os.path.join(target, "python.exe")
        problem = (smoke or _smoke_test)(os.path.abspath(__file__), new_exe)
        if problem:
            raise AgentError(f"agent failed on runtime {want['version']}: {problem}")
        new_cfg = {**cfg, "python": new_exe}
        schedule(new_cfg, run=run)  # the tasks now start the new runtime; the old folder goes on the next run
        cfg.update(python=new_exe)
        return None
    except Exception as e:  # the host keeps its runtime and tasks exactly as they were
        shutil.rmtree(tmp, ignore_errors=True)
        if cfg.get("python") != os.path.join(target, "python.exe"):
            shutil.rmtree(target, ignore_errors=True)
        return f"runtime update failed: {e}"[:500]


def _smoke_test(path, python=None):
    """The new agent must run on this host and collect a real inventory (no network). Returns a problem or None."""
    try:
        p = subprocess.run([python or sys.executable, "-I", path, "collect"], capture_output=True, text=True, errors="replace", timeout=600)
    except (OSError, subprocess.TimeoutExpired) as e:
        return str(e)
    if p.returncode != 0:
        return (p.stderr or p.stdout).strip()[-300:] or f"exit {p.returncode}"
    try:
        inv = json.loads(p.stdout)
    except ValueError:
        return "collect printed no JSON"
    if not (isinstance(inv, dict) and isinstance(inv.get("packages"), list)
            and (inv["packages"] or (inv.get("facts") or {}).get("os_unmatched"))):
        return "collect returned no packages"
    return None


def load_config():
    try:
        with open(config_path()) as f:
            cfg = json.load(f)
    except (OSError, ValueError) as e:
        raise AgentError(f"cannot read {config_path()} (run enroll first): {e}")
    use_proxy(cfg.get("proxy"))  # every command that talks to the server loads the config first
    global WU_SOURCE, _agent_key
    WU_SOURCE = cfg.get("windows_update_source")  # set at enrol on this host; the server never sends it
    _agent_key = cfg.get("agent_key")  # so the log can leave it out
    return cfg


def save_config(cfg):
    p = config_path()
    if os.name == "nt":  # chmod is a no-op on Windows and ProgramData is open to all users: lock it before the key lands
        secure_windows_dir(d=os.path.dirname(p))
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(cfg, f)
        os.chmod(p, 0o600)  # in case the file pre-existed with looser perms
    except OSError as e:
        raise AgentError(f"cannot write {p}: {e}")
    return p


# Lists the folder without ever following a junction or symlink (Windows PowerShell 5.1's -Recurse would): path|owner|link
PS_OWNERS = r"""
function Walk($p) { Get-ChildItem -LiteralPath $p -Force | ForEach-Object {
  $link = [int][bool]($_.Attributes -band [IO.FileAttributes]::ReparsePoint)
  $owner = if ($link) { '' } else { (Get-Acl -LiteralPath $_.FullName).GetOwner([Security.Principal.SecurityIdentifier]).Value }
  $_.FullName + '|' + $owner + '|' + $link
  if ($_.PSIsContainer -and -not $link) { Walk $_.FullName } } }
Walk '%DIR%'
"""


def is_link(path):
    """Symlink or junction (any reparse point): something to remove, never to follow."""
    try:
        st = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & 0x400)  # FILE_ATTRIBUTE_REPARSE_POINT


def remove_link(path):
    (os.rmdir if os.path.isdir(path) else os.remove)(path)  # removes the link itself, not what it points at


def secure_windows_dir(run=sh, d=None):
    """ProgramData lets every user create files and folders, including this folder before the agent is installed, and a
    file planted in it would be read by the SYSTEM task (a pending job decides what runs after a reboot). So, in order:
    take the folder (Administrators own it, every explicit ACE dropped, then only SYSTEM and Administrators have access),
    list what's inside, give all of it to Administrators, then remove links and anything a non-admin created.
    Nothing outside the folder is ever touched. Returns the paths removed."""
    d = d or os.path.dirname(WIN_STATE)
    if is_link(d):  # our folder itself planted as a junction would aim the lockdown, and our files, somewhere else
        remove_link(d)
    os.makedirs(d, exist_ok=True)
    take = [["icacls", d, "/setowner", "*S-1-5-32-544", "/Q"],  # an owner can always rewrite the ACL, so owner first
            ["icacls", d, "/reset", "/Q"],  # drops explicit ACEs that /grant:r would keep (it replaces only the SIDs it names)
            ["icacls", d, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "/Q"]]
    for cmd in take:
        rc, out = run(cmd)
        if rc != 0:
            raise AgentError(f"could not lock down {d}: {out.strip()[-300:]}")
    rc, out = ps(run, PS_OWNERS.replace("%DIR%", d.replace("'", "''")))
    if rc != 0:
        raise AgentError(f"cannot read owners in {d}: {out.strip()[-300:]}")
    entries = [line.strip().rsplit("|", 2) for line in out.splitlines() if line.count("|") >= 2]
    # after this no user can change anything inside, so what was listed is what gets removed
    give = [["icacls", d, "/setowner", "*S-1-5-32-544", "/T", "/C", "/Q"]]
    if os.listdir(d):  # children: drop any explicit ACEs, inherit only the folder's
        give.append(["icacls", os.path.join(d, "*"), "/reset", "/T", "/C", "/Q"])
    for cmd in give:
        rc, out = run(cmd)
        if rc != 0:
            raise AgentError(f"could not lock down {d}: {out.strip()[-300:]}")
    root, removed = os.path.realpath(d), []
    for path, sid, link in sorted(entries, key=lambda e: e[2] != "1"):  # links first, so no removal can go through one
        if not os.path.lexists(path):
            continue
        if link == "1" or is_link(path):
            remove_link(path)
        elif sid in TRUSTED_OWNERS or os.path.commonpath([root, os.path.realpath(path)]) != root:
            continue
        else:
            shutil.rmtree(path, ignore_errors=True) if os.path.isdir(path) else os.remove(path)
        removed.append(path)
    for path in removed:
        print(f"removed {path}: not created by SYSTEM or Administrators", file=sys.stderr)
    return removed


# ---- schedule -----------------------------------------------------------------
# The agent owns its schedule, so an updated agent can change it without a reinstall. Bump SCHEDULE_VERSION whenever
# the units or tasks below change; an updated agent re-applies them once.
SCHEDULE_VERSION = 2  # 2: random delay and below-normal priority on Windows (plan T44)
SYSTEMD_DIR = "/etc/systemd/system"
_SERVICE = "[Unit]\nDescription={desc}\nAfter=network-online.target\n[Service]\nType=oneshot\nExecStart={cmd}\n"
_TIMER = "[Unit]\nDescription={desc}\n[Timer]\n{when}\n[Install]\nWantedBy=timers.target\n"
JOB_UNITS = ("nimstead-agent-jobs.service", "nimstead-agent-jobs.timer")


def _agent_cmd(cfg):
    return [cfg.get("python") or sys.executable, "-I", os.path.abspath(__file__), *(["--insecure-http"] if cfg["server"].startswith("http://") else [])]


def _join(args):
    return " ".join(f'"{a}"' if " " in a else a for a in args)


def schedule_units(cfg):
    """systemd units: inventory every 6 hours (remediate on opted-in hosts, which re-reports too), and on opted-in
    hosts a 15-minute poll that only fetches approved jobs, so a fix starts within minutes of approval."""
    cmd = _join(_agent_cmd(cfg))
    verb = "remediate" if cfg.get("allow_remediation") else "report"
    units = {"nimstead-agent.service": _SERVICE.format(desc="Nimstead agent", cmd=f"{cmd} {verb}"),
             "nimstead-agent.timer": _TIMER.format(desc="Run Nimstead agent periodically",
                                                   when="OnBootSec=5min\nOnUnitActiveSec=6h\nRandomizedDelaySec=15min")}
    if cfg.get("allow_remediation"):
        units["nimstead-agent-jobs.service"] = _SERVICE.format(desc="Nimstead agent: approved fixes", cmd=f"{cmd} remediate --if-jobs")
        units["nimstead-agent-jobs.timer"] = _TIMER.format(desc="Check for approved Nimstead fixes",
                                                           when="OnBootSec=2min\nOnUnitActiveSec=15min\nRandomizedDelaySec=2min")
    return units


def _ps_quote(v):
    return "'" + v.replace("'", "''") + "'"


def schedule_windows_script(cfg):
    """SYSTEM scheduled tasks: every 6 hours and at startup (so an update that needed a restart is finished and reported
    right after it), plus the 15-minute job poll on opted-in hosts."""
    py, *args = _agent_cmd(cfg)
    base = _join(args)
    verb = "remediate" if cfg.get("allow_remediation") else "report"
    # a random delay spreads a fleet's reports over half an hour (polls over 2 minutes), and below-normal priority keeps
    # the agent out of the way of the host's own work (plan T44); the startup run stays immediate to finish a fix
    lines = ["$ErrorActionPreference = 'Stop'",
             f"$py = {_ps_quote(py)}",
             "$set = New-ScheduledTaskSettingsSet -Priority 7 -StartWhenAvailable -MultipleInstances IgnoreNew",
             "$main = @((New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Hours 6) "
             "-RandomDelay (New-TimeSpan -Minutes 30)), (New-ScheduledTaskTrigger -AtStartup))",
             f"Register-ScheduledTask -TaskName 'Nimstead agent' -Action (New-ScheduledTaskAction -Execute $py -Argument {_ps_quote(base + ' ' + verb)}) "
             "-Trigger $main -Settings $set -User 'SYSTEM' -RunLevel Highest -Force | Out-Null"]
    if cfg.get("allow_remediation"):
        lines += ["$poll = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) -RepetitionInterval (New-TimeSpan -Minutes 15) "
                  "-RandomDelay (New-TimeSpan -Minutes 2)",
                  "Register-ScheduledTask -TaskName 'Nimstead jobs' -Action (New-ScheduledTaskAction -Execute $py -Argument "
                  f"{_ps_quote(base + ' remediate --if-jobs')}) -Trigger $poll -Settings $set -User 'SYSTEM' -RunLevel Highest -Force | Out-Null"]
    else:
        # only if it's there: a silenced "not found" still sets $?, and powershell -Command exits 1 on the last statement's $?
        lines.append("Get-ScheduledTask | Where-Object TaskName -eq 'Nimstead jobs' | Unregister-ScheduledTask -Confirm:$false")
    return "\n".join(lines)


def _in_program_files(exe):
    trusted = [os.environ.get(v) for v in ("ProgramFiles", "ProgramFiles(x86)") if os.environ.get(v)]
    return any(os.path.normcase(exe).startswith(os.path.normcase(t.rstrip("\\") + "\\")) for t in trusted)


def schedule(cfg, run=sh, unit_dir=SYSTEMD_DIR, systemd=None):
    """Install (or update) this host's schedule and return what was done. Records SCHEDULE_VERSION in the config."""
    remediation = bool(cfg.get("allow_remediation"))
    poll = ", approved fixes checked every 15 minutes" if remediation else ""
    if os.name == "nt":
        exe = _agent_cmd(cfg)[0]
        if not _in_program_files(exe):
            raise AgentError(f"{exe} is not a Python under Program Files; the SYSTEM task must not run an interpreter "
                             "other users can modify (rerun the install command: it brings its own)")
        rc, out = ps(run, schedule_windows_script(cfg))
        if rc != 0:
            raise AgentError(f"could not register the scheduled tasks (PowerShell exit {rc}): {out.strip()[-300:]}")
        msg = "scheduled: every 6 hours and at startup" + poll
    else:
        if systemd is None:
            systemd = bool(shutil.which("systemctl")) and os.path.isdir("/run/systemd/system")
        cmd = _join(_agent_cmd(cfg))
        if not systemd:
            return (f"no systemd: schedule '{cmd} {'remediate' if remediation else 'report'}' every 6 hours with cron"
                    + (f", and '{cmd} remediate --if-jobs' every 15 minutes" if remediation else ""))
        units = schedule_units(cfg)
        if not remediation:  # host not (or no longer) opted in: no job poll
            run(["systemctl", "disable", "--now", "nimstead-agent-jobs.timer"])
            for name in JOB_UNITS:
                try:
                    os.remove(os.path.join(unit_dir, name))
                except FileNotFoundError:
                    pass
        for name, text in units.items():
            with open(os.path.join(unit_dir, name), "w") as f:
                f.write(text)
        for c in (["systemctl", "daemon-reload"], *(["systemctl", "enable", "--now", n] for n in units if n.endswith(".timer"))):
            rc, out = run(c)
            if rc != 0:
                raise AgentError(f"{' '.join(c)} failed: {out.strip()[-300:]}")
        msg = "scheduled: inventory every 6 hours" + poll
    save_config({**cfg, "schedule_version": SCHEDULE_VERSION})
    return msg


def uninstall(run=sh, unit_dir=SYSTEMD_DIR, state_dirs=None, agent_path=None):
    """Remove the schedule, config, key, saved outcomes and rollback copies, and the agent itself. Returns what was removed."""
    if os.name == "nt" and os.path.exists(WIN_STATE):
        raise AgentError("a Windows update is waiting for its restart; uninstall after it has finished and reported")
    if os.name == "nt":
        ps(run, "foreach ($t in 'Nimstead agent', 'Nimstead jobs') { Unregister-ScheduledTask -TaskName $t -Confirm:$false -ErrorAction SilentlyContinue }")
        state_dirs = state_dirs or [os.path.dirname(config_path())]
    else:
        run(["systemctl", "disable", "--now", "nimstead-agent.timer", "nimstead-agent-jobs.timer"])
        units = [os.path.join(unit_dir, f"nimstead-agent{j}.{k}") for j in ("", "-jobs") for k in ("service", "timer")]
        state_dirs = state_dirs or [os.path.dirname(config_path()), "/var/lib/nimstead"]
        if any(os.path.exists(u) for u in units):
            for u in units:
                if os.path.exists(u):
                    os.remove(u)
            run(["systemctl", "daemon-reload"])
    agent_path = agent_path or os.path.abspath(__file__)
    removed = []
    try:
        for d in state_dirs:
            if os.path.isdir(d) and not is_link(d):
                shutil.rmtree(d)  # removes links inside without following them
                removed.append(d)
        for f in (agent_path, agent_path + ".prev", agent_path + ".new"):
            if os.path.exists(f):
                os.remove(f)
                removed.append(f)
        if os.name == "nt":  # bundled runtimes; the running one is removed by a detached cmd once this process exits
            root = os.path.join(os.path.dirname(agent_path), "runtime")
            mine = os.path.normcase(os.path.dirname(sys.executable))
            for d in _runtime_dirs(root):
                if os.path.normcase(d) != mine:
                    shutil.rmtree(d)
                    removed.append(d)
            if any(os.path.normcase(d) == mine for d in _runtime_dirs(root)):
                later = f'ping -n 6 127.0.0.1 >nul & rmdir /s /q "{mine}" & rmdir "{root}" & rmdir "{os.path.dirname(agent_path)}"'
                # one string, not a list: list2cmdline would escape the inner quotes as \" which cmd doesn't read (VM proof)
                subprocess.Popen(f'cmd /c "{later}"', creationflags=getattr(subprocess, "DETACHED_PROCESS", 0), close_fds=True)
                removed.append(mine + " (once this process exits)")
            else:
                try:
                    os.rmdir(root)
                except OSError:
                    pass
        try:
            os.rmdir(os.path.dirname(agent_path))  # only if nothing else is in it
        except OSError:
            pass
    except OSError as e:
        raise AgentError(f"uninstall stopped: {e} (removed so far: {', '.join(removed) or 'nothing'})")
    return removed


_update_error = None  # this run's self-update failure, reported with the inventory so admins see it


def inventory(cfg):
    # auto_update None = can't (no pinned keys), so the server asks for a reinstall rather than blaming an opt-out
    inv = {**collect(), "auto_update": bool(cfg.get("auto_update", True)) if RELEASE_KEYS else None, "update_error": _update_error}
    if cfg.get("scan_jars"):  # local opt-in only (enroll --scan-jars); the server can't turn it on
        jars, summary = scan_jars(local_roots())
        inv["packages"] = [*inv["packages"], *jars]
        inv["facts"] = {**(inv.get("facts") or {}), "jar_scan": summary}
    return inv


# ---- Java libraries on disk (plan T35): jar/war/ear files and one level of nested jars -> Maven packages ----------
JAR_SKIP = re.compile(r"(?i)^(?:[a-z]:\\(?:windows|\$recycle\.bin|system volume information)|/(?:proc|sys|dev|run|snap))(?:[\\/]|$)")
NET_FS = {"nfs", "nfs4", "cifs", "smb3", "smbfs", "fuse.sshfs", "9p", "afs"}
POM = re.compile(r"(?:^|/)META-INF/maven/([^/]+)/([^/]+)/pom\.properties$")
MAX_NESTED = 50 * 1024 * 1024


def local_roots():
    """Fixed local drives on Windows, / elsewhere (network mounts are skipped while walking)."""
    if os.name != "nt":
        return ["/"]
    import ctypes
    return [f"{d}:\\" for d in "CDEFGHIJKLMNOPQRSTUVWXYZ" if ctypes.windll.kernel32.GetDriveTypeW(f"{d}:\\") == 3]  # DRIVE_FIXED


def _poms(z, where, out):
    for n in z.namelist():
        if (m := POM.search(n)) and z.getinfo(n).file_size <= 64 * 1024:  # no zip bomb in a properties file
            try:
                props = dict(ln.split("=", 1) for ln in z.read(n).decode("utf-8", "replace").splitlines() if "=" in ln and not ln.startswith("#"))
            except (OSError, zipfile.BadZipFile, KeyError):
                continue
            g, a, v = props.get("groupId", m[1]).strip(), props.get("artifactId", m[2]).strip(), props.get("version", "").strip()
            # bounded so one planted jar can't make the server refuse the whole inventory (names <= 255)
            if v and len(v) <= 100 and SAFE_VERSION.match(v) and re.fullmatch(r"[A-Za-z0-9._-]{1,120}", g) and re.fullmatch(r"[A-Za-z0-9._-]{1,120}", a):
                out.setdefault((f"{g}:{a}", v), where)


def scan_jars(roots, max_seconds=300, max_files=500_000, mounts=None):
    """([Maven packages], summary). Stops at the time or file budget and says so; never follows links or enters
    network mounts. Each finding's file is in the summary's `locations`."""
    if mounts is None:
        try:
            with open("/proc/mounts") as f:
                mounts = [ln.split()[1] for ln in f if len(ln.split()) > 2 and ln.split()[2] in NET_FS]
        except OSError:
            mounts = []
    start, files, found, partial = time.time(), 0, {}, None
    for root in roots:
        for d, dirs, names in os.walk(root, followlinks=False):
            if JAR_SKIP.match(d) or d in mounts:
                dirs[:] = []
                continue
            dirs[:] = [x for x in dirs if not is_link(os.path.join(d, x))]
            for n in names:
                files += 1
                if files > max_files or time.time() - start > max_seconds:
                    partial = f"stopped after {files - 1} files / {int(time.time() - start)} s (budget)"
                    break
                if not n.lower().endswith((".jar", ".war", ".ear")):
                    continue
                p = os.path.join(d, n)
                try:
                    with zipfile.ZipFile(p) as z:
                        _poms(z, p, found)
                        for inner in z.infolist():
                            if inner.filename.lower().endswith(".jar") and inner.file_size <= MAX_NESTED:
                                with zipfile.ZipFile(io.BytesIO(z.read(inner))) as zz:
                                    _poms(zz, f"{p}!/{inner.filename}", found)
                except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError):
                    continue
            if partial:
                break
        if partial:
            break
    pkgs = [{"ecosystem": "Maven", "name": k[0], "version": k[1], "source": None} for k in sorted(found)]
    return pkgs, {"files": min(files, max_files), "complete": partial is None, **({"partial": partial} if partial else {}),
                  "locations": [[k[0], k[1], w[-300:]] for k, w in list(sorted(found.items()))[:100]]}


# ---- doctor: reads this host and changes nothing (DECISIONS 69) ---------------------
MAX_CLOCK_SKEW = 300  # seconds
PS_DOCTOR_TASKS = "Get-ScheduledTask | Where-Object TaskName -like 'Nimstead *' | ForEach-Object { $_.TaskName + '|' + $_.State }"
PS_DOCTOR_WU = "$s = Get-Service -Name wuauserv -ErrorAction Stop; $s.Status.ToString() + '|' + $s.StartType"
# SIDs only: names like Administratoren are translated (DECISIONS 68). Owner, whether inheritance is off, then who is allowed
PS_DOCTOR_ACL = r"""
$a = Get-Acl -LiteralPath %DIR% -ErrorAction Stop
$a.GetOwner([Security.Principal.SecurityIdentifier]).Value
$a.AreAccessRulesProtected
$a.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object AccessControlType -eq 'Allow' | ForEach-Object { $_.IdentityReference.Value }
"""


class _DoctorFail(Exception):
    def __init__(self, problem, fix):
        super().__init__(problem)
        self.fix = fix


def _read_config():
    with open(config_path()) as f:
        return json.load(f)


def _server_reply(url):
    """(HTTP status, Date header) from a GET that carries no key. Any answer proves the server is there."""
    try:
        with _opener.open(urllib.request.Request(url), timeout=15) as r:
            return r.status, r.headers.get("Date")
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Date")


def doctor(insecure_http=False, run=sh, read=_read_config, fetch=_server_reply, connect=socket.create_connection, now=time.time,
           disk=free_bytes, exists=os.path.exists, windows=None, state_dir=None, systemd=None, version=None):
    """Print ok or FAIL (with one line on how to fix it) for each check; returns the exit code. Only reads: no lockdown,
    no agent key sent, no log written."""
    windows = os.name == "nt" if windows is None else windows
    state = state_dir or (os.path.dirname(WIN_STATE) if windows else "/var/lib/nimstead")
    as_admin = "Administrator" if windows else "root"
    cfg, date = None, None

    def need_config():
        if cfg is None:
            raise _DoctorFail("not checked: no readable config", "Fix the config check first.")

    def config():
        nonlocal cfg
        try:
            cfg = read()
        except (OSError, ValueError) as e:
            raise _DoctorFail(f"cannot read {config_path()}: {e}",
                              f"Run this as {as_admin}; if it still fails, rerun the install command from Add a machine.") from None
        return config_path()

    def proxy():
        need_config()
        try:
            url = use_proxy(cfg.get("proxy"), run)
        except AgentError as e:
            raise _DoctorFail(str(e), "Rerun enroll with --proxy http://host:port.") from None
        if not url:
            return "none: connects directly"
        u = urllib.parse.urlsplit(url)
        try:
            connect((u.hostname, u.port or (443 if u.scheme == "https" else 80)), 10).close()
        except (OSError, ValueError) as e:
            raise _DoctorFail(f"cannot connect to {url}: {e}", "Check the proxy is running and this machine's firewall allows it.") from None
        return url

    def server():
        nonlocal date
        need_config()
        s = str(cfg.get("server"))
        if not s.startswith("https://") and not (insecure_http and s.startswith("http://")):
            raise _DoctorFail(f"{s} is not HTTPS", "Put the server behind HTTPS (docs/install.md), or add --insecure-http for local dev only.")
        if _proxy and not s.startswith("https://"):
            raise _DoctorFail("a plain-http server is refused through a proxy", "Put the server behind HTTPS (docs/install.md).")
        try:
            status, date = fetch(s.rstrip("/") + "/api/health")
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise _DoctorFail(f"cannot reach {s}: {e}", "Check DNS, the firewall, the proxy and the server's certificate from this machine.") from None
        if status != 200:
            raise _DoctorFail(f"{s} answered HTTP {status}", "Check the server address and that the server is healthy; agents don't follow redirects.")
        return s

    def clock():
        parsed = email.utils.parsedate_tz(date) if date else None
        if not parsed:
            raise _DoctorFail("not checked: no usable Date header from the server", "Fix the server check first; a reverse proxy must not remove Date.")
        skew = now() - email.utils.mktime_tz(parsed)
        if abs(skew) > MAX_CLOCK_SKEW:
            sync = "w32tm /resync" if windows else "timedatectl set-ntp true"
            raise _DoctorFail(f"this machine is {int(abs(skew))} seconds {'ahead of' if skew > 0 else 'behind'} the server", f"Set the time: {sync}.")
        return f"within {int(abs(skew))} seconds of the server"

    def tasks():
        jobs = bool(cfg and cfg.get("allow_remediation"))
        if windows:
            rc, out = ps(run, PS_DOCTOR_TASKS)
            if rc != 0:
                raise _DoctorFail(f"cannot list scheduled tasks: {out.strip()[-200:]}", f"Run this as {as_admin}.")
            found = dict(line.strip().rsplit("|", 1) for line in out.splitlines() if "|" in line)
            names = ["Nimstead agent", *(["Nimstead jobs"] if jobs else [])]
            bad = [n for n in names if found.get(n, "Disabled") == "Disabled"]  # State's names aren't translated
        else:
            on_systemd = (bool(shutil.which("systemctl")) and os.path.isdir("/run/systemd/system")) if systemd is None else systemd
            if not on_systemd:
                return "no systemd here: a cron schedule isn't checked"
            names = ["nimstead-agent.timer", *(["nimstead-agent-jobs.timer"] if jobs else [])]
            bad = [n for n in names if run(["systemctl", "is-enabled", n])[0] != 0]
        if bad:
            raise _DoctorFail(f"missing or disabled: {', '.join(bad)}", f"Run `nimstead_agent.py schedule` as {as_admin}.")
        return ", ".join(names)

    def folder_acl():
        fix = "Run `nimstead_agent.py report` as Administrator: every run locks the folder again."
        if is_link(state):
            raise _DoctorFail(f"{state} is a link", fix)
        rc, out = ps(run, PS_DOCTOR_ACL.replace("%DIR%", _ps_quote(state)))
        lines = [line.strip() for line in out.splitlines() if line.strip()]
        if rc != 0 or len(lines) < 2:
            raise _DoctorFail(f"cannot read {state}: {out.strip()[-200:]}", f"Run this as Administrator; if {state} is missing, rerun the install command.")
        owner, protected, *allowed = lines
        others = sorted(set(allowed) - TRUSTED_OWNERS)
        if owner not in TRUSTED_OWNERS or protected != "True" or others:
            raise _DoctorFail(f"{state} is open: owner {owner}, inheritance off: {protected}, also allowed: {', '.join(others) or 'nobody'}", fix)
        return f"{state}: only SYSTEM and Administrators"

    def windows_update():
        rc, out = ps(run, PS_DOCTOR_WU)
        parts = out.strip().rsplit("|", 1)
        if rc != 0 or len(parts) != 2:
            raise _DoctorFail(f"cannot read the service: {out.strip()[-200:]}", "Run this as Administrator; Windows fixes need the service wuauserv.")
        if parts[1] == "Disabled":  # stopped is normal: it starts on demand and stops itself when idle
            raise _DoctorFail("the service wuauserv is disabled", "Run: Set-Service wuauserv -StartupType Manual (and check no policy disables it).")
        return f"{parts[0]}, start type {parts[1]}"

    def free_disk():
        free = disk(state)
        if free < MIN_FREE_BYTES:
            raise _DoctorFail(f"{free // 2**20} MiB free for {state}; fixes need {MIN_FREE_BYTES // 2**20} MiB", "Free up space on that disk.")
        return f"{free // 2**20} MiB free"

    def runtime():
        exe = (cfg or {}).get("python") or sys.executable
        have = version or sys.version_info[:2]
        reinstall = "Rerun the install command: on Windows it brings its own Python."
        if tuple(have) < (3, 9):
            raise _DoctorFail(f"Python {have[0]}.{have[1]} is older than 3.9", reinstall)
        if not exists(exe):
            raise _DoctorFail(f"{exe} doesn't exist", reinstall)
        if windows and not _in_program_files(exe):
            raise _DoctorFail(f"{exe} isn't under Program Files, so other users may be able to change what SYSTEM runs", reinstall)
        return f"agent {AGENT_VERSION} on Python {have[0]}.{have[1]}: {exe}"

    checks = [("config", config), ("proxy", proxy), ("server", server), ("clock", clock), ("schedule", tasks),
              *([("state folder", folder_acl), ("Windows Update", windows_update)] if windows else []),
              ("disk", free_disk), ("runtime", runtime)]
    failed = 0
    for name, check in checks:
        try:
            print(f"ok    {name}: {check()}")
        except _DoctorFail as e:
            failed += 1
            print(f"FAIL  {name}: {e}. Fix: {e.fix}")
        except Exception as e:  # a check that can't run is a failure, and the others still run
            failed += 1
            print(f"FAIL  {name}: could not check: {e!r}. Fix: Run this as {as_admin}; if it persists, report it with this line.")
    print(f"{failed} of {len(checks)} checks failed" if failed else f"all {len(checks)} checks passed")
    print(f"log: {LOG_PATH}")
    return 1 if failed else 0


def _update_then_rerun(a, argv):
    """Self-update before a report/remediate run. After an update, run the same command with the new agent and return
    its exit code; otherwise None and this agent carries on."""
    global _update_error
    cfg = load_config()
    try:
        with run_lock():
            new, _update_error = self_update(cfg, a.insecure_http)
    except AgentError:  # another run (e.g. the 15-minute job poll) holds the lock: update next time
        return None
    if _update_error:
        print(f"nimstead-agent: warning: {_update_error}", file=sys.stderr)
        log_event(f"warning: {_update_error}")
    if not new:
        return None
    print(f"updated nimstead-agent {AGENT_VERSION} -> {new}", flush=True)  # before the new agent's own output
    log_event(f"updated {AGENT_VERSION} -> {new}")
    args = list(sys.argv[1:] if argv is None else argv)
    new_agent = [sys.executable, *(["-I"] if sys.flags.isolated else []), os.path.abspath(__file__), "--no-self-update"]
    if "schedule_version" in cfg:  # installed with a schedule: the new agent re-applies it if its units changed
        subprocess.call([*new_agent, "schedule", "--if-changed"])
    return subprocess.call([*new_agent, *args])


def main(argv=None):
    global _log_on
    try:
        rc = _main(argv)
        log_event(f"run end: exit {rc}")
        return rc
    except Exception as e:  # leave a trace of what stopped the run, then fail as before
        log_event(f"run crashed: {e!r}")
        raise
    finally:
        _log_on = False


def _main(argv):
    global _log_on
    ap = argparse.ArgumentParser(prog="nimstead-agent")
    ap.add_argument("--insecure-http", action="store_true", help="allow plain http (local dev only)")
    ap.add_argument("--no-self-update", action="store_true", help="skip the signed self-update check for this run")
    sub = ap.add_subparsers(dest="cmd", required=True)
    en = sub.add_parser("enroll")
    en.add_argument("--server", required=True)
    en.add_argument("--token", default=os.environ.get("NIMSTEAD_TOKEN"),
                    help="enrolment token (or set NIMSTEAD_TOKEN, which keeps it out of the process list)")
    en.add_argument("--allow-remediation", action="store_true",
                    help="let this host run approved package upgrades (local opt-in; the server cannot enable it)")
    en.add_argument("--windows-update-source", choices=("default", "microsoft"), default="default",
                    help="Windows: where fixes are searched for; 'microsoft' bypasses WSUS for Nimstead's jobs (local choice)")
    en.add_argument("--ad-discovery", action="store_true",
                    help="Windows, domain member: also report the domain's enabled computers, to list those with no agent")
    en.add_argument("--scan-jars", action="store_true",
                    help="also look for Java libraries (jar/war/ear) on local disks at each report, within a 5-minute budget")
    en.add_argument("--no-auto-update", action="store_true",
                    help="never replace this agent with newer signed releases (default: update automatically)")
    en.add_argument("--proxy", help="send all traffic to the server through this proxy (http://host:port); "
                    "default: the machine's WinHTTP proxy on Windows, if set")
    en.add_argument("--channel", choices=CHANNELS, default="stable",
                    help="least proven signed releases this agent takes (the installer passes its server's channel)")
    sub.add_parser("report")
    sub.add_parser("collect")
    sub.add_parser("doctor", help="check this host's setup and print how to fix each failure; changes nothing")
    sr = sub.add_parser("scan-remote", help="Windows: scan other hosts with no agent, over PowerShell remoting, as you (no stored credentials)")
    sr.add_argument("--server", help="report here; NIMSTEAD_TOKEN enrols hosts the first time")
    sr.add_argument("--print", action="store_true", dest="print_only", help="print each host's inventory instead of reporting it")
    sr.add_argument("hosts", nargs="+")
    rm = sub.add_parser("remediate", help="run approved remediation jobs, then re-report inventory")
    rm.add_argument("--if-jobs", action="store_true", help="re-report inventory only if a job ran (the 15-minute poll)")
    un = sub.add_parser("uninstall", help="remove the agent, its schedule, key and saved state from this host")
    un.add_argument("--yes", action="store_true", help="confirm")
    sc = sub.add_parser("schedule", help="install or update this host's systemd timers / scheduled tasks")
    sc.add_argument("--if-changed", action="store_true", help="only if this agent's schedule differs from the installed one")
    rj = sub.add_parser("run-job", help="run one job read as JSON from stdin, print the result JSON (no network; sandbox testing)")
    rj.add_argument("--yes", action="store_true", help="confirm: this changes installed packages on this host")
    sub.add_parser("resume-job", help="Windows: continue the pending job after its reboot (no network)")
    vr = sub.add_parser("verify-release", help="check a release manifest's signature against the pinned keys; print it if valid")
    vr.add_argument("manifest")
    vr.add_argument("sig")
    rj.add_argument("--fail-after-apply", action="store_true", help="sandbox testing: force a failure after the change to exercise rollback")
    a = ap.parse_args(argv)
    try:
        if os.name == "nt" and a.cmd in ("report", "remediate", "resume-job", "schedule", "uninstall"):  # before reading anything from the folder
            secure_windows_dir()
        if a.cmd in LOGGED_COMMANDS:
            _log_on = True
            log_event(f"run start: {a.cmd}, agent {AGENT_VERSION}")
        if a.cmd == "collect":
            print(json.dumps(collect(), indent=2))
        elif a.cmd == "doctor":
            return doctor(a.insecure_http)
        elif a.cmd == "scan-remote":
            if a.print_only:
                for h in a.hosts:
                    print(json.dumps(collect_remote(h)[1]))
                return 0
            if not a.server:
                raise AgentError("--server is required, or --print")
            return 2 if scan_remote(a.server, a.hosts, os.environ.get("NIMSTEAD_TOKEN"), a.insecure_http) else 0
        elif a.cmd == "enroll":
            if not a.token:
                raise AgentError("an enrolment token is required (--token or NIMSTEAD_TOKEN)")
            use_proxy(a.proxy)
            inv = collect()
            body = {"token": a.token, "hostname": socket.gethostname(), "os_name": inv["os_name"], "ecosystem": inv["ecosystem"]}
            res = post(a.server, "/api/agent/enroll", body, a.insecure_http)
            if "agent_key" not in res:
                raise AgentError("enroll response missing agent_key")
            # only the fields we expect from the server, and local choices last: the server can't opt a host in
            cfg = {"asset_id": res.get("asset_id"), "agent_key": res["agent_key"], "server": a.server,
                   "allow_remediation": a.allow_remediation, "auto_update": not a.no_auto_update, "channel": a.channel,
                   "scan_jars": a.scan_jars, "ad_discovery": a.ad_discovery,
                   **({"windows_update_source": "microsoft"} if a.windows_update_source == "microsoft" else {}),
                   **({"proxy": a.proxy} if a.proxy else {})}
            print("enrolled as asset {}; config saved to {}".format(res.get("asset_id"), save_config(cfg)))
        elif a.cmd == "uninstall":
            if not a.yes:
                raise AgentError("uninstall removes the agent and its key from this host; pass --yes to confirm")
            for r in uninstall():
                print(f"removed {r}")
            print("Nimstead agent uninstalled. Delete this host on the Assets page to remove its findings and history.")
        elif a.cmd == "schedule":
            cfg = load_config()
            if not (a.if_changed and cfg.get("schedule_version") == SCHEDULE_VERSION):
                print(schedule(cfg))
        elif a.cmd == "verify-release":
            with open(a.manifest, "rb") as f, open(a.sig) as g:
                print(json.dumps(verify_release(f.read(), g.read().strip())))
        elif a.cmd == "run-job":
            if not a.yes:
                raise AgentError("run-job changes installed packages; pass --yes to confirm")
            job = json.load(sys.stdin)
            if job.get("manager") == "windows":
                res = WinJob(job, fail_after_apply=a.fail_after_apply).advance()
                print(json.dumps(res))
                return 0 if res["outcome"] in ("applied", "pending_reboot") else 2
            j = (WinAppJob if job.get("manager") in WIN_APP_MANAGERS else Job)(job, fail_after_apply=a.fail_after_apply)
            outcome, steps, error = j.execute()
            print(json.dumps({"outcome": outcome, "steps": steps, "error": error, "versions": getattr(j, "result_versions", None)}))
            j.discard_rollback(outcome)
            return 0 if outcome == "applied" else 2
        elif a.cmd == "resume-job":  # Windows: continue a job after the reboot it asked for
            if not os.path.exists(WIN_STATE):
                raise AgentError("no pending job")
            with run_lock():  # the startup run may be advancing the same job
                res = WinJob().advance()
            print(json.dumps(res))
            return 0 if res["outcome"] in ("applied", "pending_reboot", "rolled_back") else 2
        elif a.cmd in ("report", "remediate") and not a.no_self_update and (new := _update_then_rerun(a, argv)) is not None:
            return new
        elif a.cmd == "remediate":
            cfg = load_config()
            if not cfg.get("allow_remediation"):
                raise AgentError("remediation is not enabled on this host (re-enroll with --allow-remediation)")
            with run_lock():
                ran = []
                problems, reboot = run_jobs(cfg["server"], cfg["agent_key"], a.insecure_http, ran=ran)
                if reboot:  # Windows update needs a restart; the startup run resumes the job and reports it
                    when, msg = restart_for_update()
                    print(msg)
                    log_event(msg)
                    return 0
                if ran or not a.if_jobs:  # server verifies the fix
                    post(cfg["server"], "/api/agent/inventory", inventory(cfg), a.insecure_http, cfg["agent_key"])
            if problems:
                return 2
        else:
            cfg = load_config()
            inv = inventory(cfg)
            post(cfg["server"], "/api/agent/inventory", inv, a.insecure_http, cfg["agent_key"])
            print(f"reported {len(inv['packages'])} packages")
            log_event(f"reported {len(inv['packages'])} packages")
            if cfg.get("ad_discovery") and os.name == "nt":  # local opt-in only: which domain computers have no agent
                d = ad_computers()
                post(cfg["server"], "/api/agent/directory", d, a.insecure_http, cfg["agent_key"])
                print(f"reported {len(d['computers'])} computers from {d['domain']}")
    except AgentError as e:
        print(f"nimstead-agent: error: {e}", file=sys.stderr)
        log_event(f"error: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
