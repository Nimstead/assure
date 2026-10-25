#!/usr/bin/env python3
"""Nimstead agent: reports installed packages to the server. Single file, stdlib only, Python 3.9+.

  nimstead_agent.py enroll --server https://host --token TOKEN
  nimstead_agent.py report
  nimstead_agent.py collect          # print inventory JSON, no network
"""

import argparse
import json
import os
import platform
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


# ---- network ----------------------------------------------------------------

def post(server, path, body, insecure_http, key=None):
    if not server.startswith("https://") and not (insecure_http and server.startswith("http://")):
        raise AgentError(f"refusing non-HTTPS server {server!r} (use --insecure-http for local dev)")
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = "Bearer " + key
    req = urllib.request.Request(server.rstrip("/") + path, json.dumps(body).encode(), headers, method="POST")
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
    sub.add_parser("report")
    sub.add_parser("collect")
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
            print("enrolled as asset {}; config saved to {}".format(res.get("asset_id"), save_config({"server": a.server, **res})))
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
