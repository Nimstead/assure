"""Linux settings that open a stage of an attack path, judged from the agent's access read (tasks/spec-paths.md Module 2,
DECISIONS 166): the counterpart of winconfig, ecosystem "LinuxConfig". Each check says what was read, who it helps and the fix
in words (no automated fix in V1). A setting whose facts weren't read opens nothing, and scan.unproven keeps open findings
open while the read isn't complete.
"""

import ipaddress
import re

from nimstead.risk import Risk

ECOSYSTEM = "LinuxConfig"
ROOT_EQUIVALENT = ("docker", "lxd", "incus-admin", "disk")
STAGE = {"ssh-root-password": "entry", "ssh-empty-passwords": "entry", "root-equivalent-group": "escalate",
         "sudo-nopasswd-all": "escalate", "writable-root-run": "escalate", "shadow-readable": "credentials"}
_SHOWN = 5
_UNSAFE = re.compile(r"[^A-Za-z0-9._/@+-]")


def _path(p: str) -> str:
    """A path a host sent, as finding reasons and AI prompts may carry it: the agent's own name characters only (security audit:
    a path is free text a compromised host or a user who can plant a file writes)."""
    return _UNSAFE.sub("?", p)[:120]


def _beyond_loopback(addr: str) -> bool:
    """Whether a listen address ("0.0.0.0:22", "[::]:22", "10.0.0.5:22/tcp") is reachable from another machine."""
    host = addr.split("/")[0].rsplit(":", 1)[0].strip("[]")
    try:
        return not ipaddress.ip_address(host.split("%")[0]).is_loopback
    except ValueError:
        return False


_SSH_UNIT = re.compile(r"sshd?(@[^/]*)?\.service")


def ssh_listening(programs: list | None, sshd: dict | None) -> tuple[bool, str] | None:
    """(listening beyond loopback, how it's known) for this host's sshd: from a complete, recent runtime read when it saw sshd,
    else from sshd's own configuration (said so: whether it runs isn't read); None when neither says. programs None: no such
    read. sshd is its systemd service, or without one a program called sshd running as root; anything root runs that listens
    on sshd's port counts too, as systemd does for a socket-activated sshd. Every one is read before deciding (code review:
    the first program called ssh decided, and a signed-in session or a user's ssh client sorted before the service), and a
    user's own program is never sshd, whatever it calls itself."""
    ports = {str(p) for p in (sshd or {}).get("port") or ["22"]}
    seen, mine = None, []
    for p in programs or []:
        name, root = str(p.get("name", "")), "root" in (p.get("users") or [])
        ours = bool(_SSH_UNIT.fullmatch(name)) if p.get("unit") is True else name == "sshd" and root
        seen = seen or (name if ours else None)
        mine += [(name, a) for a in p.get("listen") or [] if ours or root and a.endswith("/tcp") and a.split("/")[0].rsplit(":", 1)[-1] in ports]
    if mine:
        net = [(n, a) for n, a in mine if _beyond_loopback(a)]
        return (True, f"{net[0][0]} listens on {net[0][1].split('/')[0]}") if net else (False, f"{mine[0][0]} listens only on loopback")
    if seen:
        return False, f"{seen} runs but listens on nothing"
    if programs is not None and sshd and sshd.get("installed"):  # a complete runtime read that didn't see sshd: it isn't running
        return False, "sshd isn't running"
    if sshd and sshd.get("installed"):
        net = [a for a in sshd.get("listenaddress") or [] if _beyond_loopback(a)]
        return (bool(net), f"sshd's configuration listens on {net[0]}; whether it runs isn't read" if net else "sshd's configuration listens only on loopback")
    return None


def _lists(sshd: dict) -> list[list[str]]:
    """sshd's AuthenticationMethods as lists of methods, each list one way to sign in; [] when any single method will do."""
    return [m.split(",") for m in sshd.get("authenticationmethods") or [] if m != "any"]


def password_alone(sshd: dict) -> bool:
    """Whether a password by itself signs in: password or keyboard-interactive on, and no AuthenticationMethods list asking
    for more (code review: a key plus a password, or a password plus a one-time code, isn't a guessable password)."""
    on = sshd.get("passwordauthentication") == "yes" or sshd.get("kbdinteractiveauthentication") == "yes"
    lists = _lists(sshd)
    return on and (not lists or any(len(ms) == 1 and ms[0].split(":")[0] in ("password", "keyboard-interactive") for ms in lists))


def key_alone(sshd: dict) -> bool | None:
    """Whether a key by itself signs in: True, False when it takes another method too, None when keys never sign in."""
    lists = _lists(sshd)
    if lists and not any("publickey" in ms for ms in lists):
        return None
    return not lists or any(ms == ["publickey"] for ms in lists)


def _names(xs: list[str]) -> str:
    return ", ".join(xs[:_SHOWN]) + (f" and {len(xs) - _SHOWN} more" if len(xs) > _SHOWN else "")


def evaluate(data: dict | None, listening: tuple[bool, str] | None = None) -> list[dict]:
    """Settings findings (package, version, vuln_id, summary, risk, helps) from an access read's data and whether sshd listens
    beyond loopback. No I/O. Nothing is concluded from a field the read didn't fill (None)."""
    if not isinstance(data, dict):
        return []
    out = []

    def add(check, value, summary, priority, score, fix, helps):
        out.append({"package": check, "version": str(value)[:100], "vuln_id": f"CFG:{check}", "summary": f"{summary}. {fix}"[:1000],
                    "risk": Risk(score, priority, [summary, fix]), "helps": helps})

    sshd = data.get("sshd") or {}
    accounts = [a for a in data.get("accounts") or [] if isinstance(a, dict)]
    if sshd.get("installed") and listening and listening[0]:
        root = next((a for a in accounts if a.get("uid") == 0), None)
        passwords = password_alone(sshd)
        if sshd.get("permitrootlogin") == "yes" and passwords and root and root.get("password") == "usable":
            add("ssh-root-password", "PermitRootLogin yes", f"root can sign in over SSH with a password ({listening[1]}), so a guessed or "
                "reused password is root", "next", 65, "Set PermitRootLogin prohibit-password (keys only) and sign in as a named account", ["anyone on the network"])
        empty = [a["name"] for a in accounts if a.get("password") == "empty" and a.get("login")]
        if sshd.get("permitemptypasswords") == "yes" and passwords and empty:
            add("ssh-empty-passwords", _names(empty), f"sshd accepts empty passwords and {_names(empty)} {'has' if len(empty) == 1 else 'have'} none "
                f"({listening[1]}): anyone who can reach it signs in", "fix-now", 85,
                "Set PermitEmptyPasswords no and give every account a password or lock it", ["anyone on the network"])
    equal = [(a["name"], g) for a in accounts if a.get("uid") != 0 for g in a.get("groups") or [] if g in ROOT_EQUIVALENT]
    if equal:
        who = [f"{n} ({g})" for n, g in equal]
        add("root-equivalent-group", _names(who), f"{_names(who)}: membership of {', '.join(sorted({g for _, g in equal}))} lets an account run "
            "anything as root (a container with the disk mounted, or the raw disk itself)", "planned", 45,
            "Remove these accounts from the group; give the few people who need it sudo with a password instead", sorted({n for n, _ in equal}))
    nopass = [a["name"] for a in accounts if a.get("uid") != 0 and a.get("sudo_all") is True]
    if nopass:
        add("sudo-nopasswd-all", _names(nopass), f"{_names(nopass)} can run every command as root with no password (sudo NOPASSWD: ALL), "
            "so whoever runs as them is root", "planned", 45, "Require a password, or limit the rule to the commands they need", nopass)
    def who(by: list[str]) -> list[str]:
        """The accounts a "user:X" or "group:X" names: a group's members as the read lists them (code review: a group name
        never matched an account, so a group-writable file helped no one)."""
        if "everyone" in by:
            return [ANYONE]
        out = set()
        for b in by:
            kind, _, name = b.partition(":")
            out |= {name} if kind == "user" else {a["name"] for a in accounts if name in (a.get("groups") or [])}
        return sorted(out)

    writable = [w for w in data.get("writable") or [] if isinstance(w, dict)]
    if writable:
        anyone = any(w.get("by") == "everyone" for w in writable)
        shown = [f"{_path(w['path'])} ({'anyone' if w['by'] == 'everyone' else w['by'].split(':', 1)[1]} can replace "
                 f"{'it' if w.get('at') in (None, w['path']) else _path(w['at'])})" for w in writable]
        add("writable-root-run", f"{len(writable)} file{'s' * (len(writable) > 1)}", f"Files root runs can be replaced by someone else: {_names(shown)}",
            "next" if anyone else "planned", 60 if anyone else 50, "Make each file and the folders above it writable by root only",
            who([w["by"] for w in writable]))
    shadow = data.get("shadow_readable_by")
    if isinstance(shadow, list) and shadow:
        add("shadow-readable", _names(shadow), f"/etc/shadow (every account's password hash) can be read by {_names(shadow)}", "next", 60,
            "Make /etc/shadow readable by root (and group shadow) only: chmod 640, chown root:shadow", who(shadow))
    return out


ANYONE = "anyone with an account"
