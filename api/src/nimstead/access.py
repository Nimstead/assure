"""Who can get in and what they hold, per Linux host (tasks/spec-paths.md Module 1, DECISIONS 165): the agent's latest
`access` read, validated and stored for the settings checks (linconfig), the host's attack paths and the fleet's key edges.

What a host sends is checked as hostile: unknown keys dropped, names and paths in bounded character sets (no control or
bidirectional-override characters, which reach the UI and reasons), fingerprints exactly as ssh-keygen prints them, lists
capped. A read that failed keeps the last stored data and says so; a partial read replaces it (what it saw counts); a host
that turned the read off loses its row, so no stale key ever links it to anything.
"""

import json
import re
from datetime import datetime

from sqlalchemy.orm import Session

from nimstead.db import Asset, AssetAccess, now

ACCOUNTS, GROUPS, WRITABLE, HELD, TRUSTED, CREDENTIALS, FROM = 64, 64, 50, 256, 5_000, 100, 16
BODY_MAX = 2 * 1024 * 1024
_NAME = re.compile(r"[A-Za-z0-9._@+?-]{1,64}")  # the agent's own sanitised set
_PATH = re.compile(r"[^\x00-\x1f\x7f‎‏‪-‮⁦-⁩]{1,255}")
_FP = re.compile(r"SHA256:[A-Za-z0-9+/]{43}")
_PATTERN = re.compile(r"[A-Za-z0-9._@*?!%/:\[\]-]{1,100}")  # sshd user and address patterns, from= entries
_BY = re.compile(r"everyone|(?:group|user):[A-Za-z0-9._@+?-]{1,64}")
KEY_TYPES = frozenset(("ssh-ed25519", "ssh-rsa", "ssh-dss", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
                       "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com", "ecdsa", "other"))
ROOT_LOGIN = frozenset(("yes", "no", "prohibit-password", "without-password", "forced-commands-only"))
CREDENTIAL_KINDS = frozenset(("aws", "kubernetes", "docker", "postgresql", "netrc", "git", "keytab"))
_YES_NO = ("pubkeyauthentication", "passwordauthentication", "kbdinteractiveauthentication", "permitemptypasswords", "strictmodes")
_LISTS = ("authorizedkeysfile", "allowusers", "denyusers", "allowgroups", "denygroups", "listenaddress")


def _int(v, lo: int, hi: int) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi else None


def _bool(v) -> bool | None:
    return v if isinstance(v, bool) else None


def _strs(v, n: int, pattern: re.Pattern) -> list[str]:
    return [x for x in v[:n] if isinstance(x, str) and pattern.fullmatch(x)] if isinstance(v, list) else []


def _rows(raw: dict, key: str, cap: int) -> list[dict]:
    """Up to cap dictionaries from raw[key] when it's a list; anything else is no rows."""
    v = raw.get(key)
    return [x for x in v[:cap] if isinstance(x, dict)] if isinstance(v, list) else []


def _sshd(v) -> dict | None:
    if not isinstance(v, dict):
        return None
    if v.get("installed") is False:
        return {"installed": False}
    if v.get("installed") is True and v.get("running") is False:  # installed but not running: no settings to read, nothing to sign in to
        return {"installed": True, "running": False}
    if v.get("installed") is not True or v.get("permitrootlogin") not in ROOT_LOGIN:
        return None
    out = {"installed": True, "permitrootlogin": v["permitrootlogin"], "authorizedkeyscommand": v.get("authorizedkeyscommand") is True,
           "match": v.get("match") is True}
    for k in _YES_NO:
        out[k] = v.get(k) if v.get(k) in ("yes", "no") else None
    for k in _LISTS:
        out[k] = _strs(v.get(k), 64, _PATTERN)
    out["port"] = [p for p in _strs(v.get("port"), 16, re.compile(r"\d{1,5}"))]
    return out


def valid(raw) -> dict | None:
    """The agent's access object reduced to what fits, or None when it isn't one. Never raises on any JSON value."""
    if not isinstance(raw, dict) or raw.get("v") != 1 or raw.get("state") not in ("ok", "partial", "failed"):
        return None
    accounts, names = [], set()
    for a in _rows(raw, "accounts", ACCOUNTS):
        if not (isinstance(a.get("name"), str) and _NAME.fullmatch(a["name"]) and a["name"] not in names):
            continue
        uid = _int(a.get("uid"), 0, 2**32 - 1)
        if uid is None:
            continue
        names.add(a["name"])
        accounts.append({"name": a["name"], "uid": uid, "groups": sorted(set(_strs(a.get("groups"), GROUPS, _NAME))), "login": a.get("login") is True,
                         "password": a.get("password") if a.get("password") in ("usable", "locked", "empty") else None,
                         "sudo_all": _bool(a.get("sudo_all"))})
    owner = lambda x: isinstance(x, str) and x in names  # noqa: E731 — a key or file must belong to an account the read lists
    writable = [{"path": w["path"], "kind": w["kind"], "by": w["by"], "at": w.get("at") if isinstance(w.get("at"), str) and _PATH.fullmatch(w["at"]) else w["path"]}
                for w in _rows(raw, "writable", WRITABLE) if isinstance(w.get("path"), str) and _PATH.fullmatch(w["path"])
                and w.get("kind") in ("unit", "service", "cron") and isinstance(w.get("by"), str) and _BY.fullmatch(w["by"])]
    held = [{"account": h["account"], "path": h["path"], "type": h["type"], "fp": h["fp"], "passphrase": h.get("passphrase") is True}
            for h in _rows(raw, "held", HELD) if owner(h.get("account")) and isinstance(h.get("path"), str) and _PATH.fullmatch(h["path"])
            and h.get("type") in KEY_TYPES and isinstance(h.get("fp"), str) and _FP.fullmatch(h["fp"])]
    trusted = [{"account": t["account"], "fp": t["fp"], "type": t["type"], "from": [x[:64] for x in _strs(t.get("from"), FROM, _PATTERN)],
                "forced": t.get("forced") is True, "restrict": t.get("restrict") is True}
               for t in _rows(raw, "trusted", TRUSTED) if owner(t.get("account")) and t.get("type") in KEY_TYPES and isinstance(t.get("fp"), str) and _FP.fullmatch(t["fp"])]
    creds = [{"kind": c["kind"], "account": c["account"], "path": c["path"]}
             for c in _rows(raw, "credentials", CREDENTIALS) if c.get("kind") in CREDENTIAL_KINDS and owner(c.get("account"))
             and isinstance(c.get("path"), str) and _PATH.fullmatch(c["path"])]
    shadow = raw.get("shadow_readable_by")
    out = {"v": 1, "state": raw["state"], "problem": raw["problem"][:300] if isinstance(raw.get("problem"), str) and raw["problem"] else None,
           "sshd": _sshd(raw.get("sshd")), "accounts": accounts, "writable": writable,
           "shadow_readable_by": _strs(shadow, 3, _BY) if isinstance(shadow, list) else None, "held": held, "trusted": trusted,
           "credentials": creds, "agent_sockets": _int(raw.get("agent_sockets"), 0, 1000) or 0,
           "unidentified_keys": _int(raw.get("unidentified_keys"), 0, 100_000) or 0}
    return out if len(json.dumps(out)) <= BODY_MAX else None


def store(s: Session, asset: Asset, raw, t: datetime | None = None) -> AssetAccess | None:
    """Record one access read for host asset; returns the row, or None when raw isn't a read (the stored row, if any, is left
    as it was). A failed read keeps the last data and records the failure; the caller commits."""
    acc = valid(raw)
    if acc is None:
        return None
    t = t or now()
    row = s.get(AssetAccess, asset.id)
    if row is None:
        row = AssetAccess(asset_id=asset.id, org_id=asset.org_id, data={}, data_at=None)
        s.add(row)
    row.read_at, row.state, row.problem = t, acc["state"], acc["problem"]
    if acc["state"] != "failed":
        row.data, row.data_at = {k: v for k, v in acc.items() if k not in ("v", "state", "problem")}, t
    return row


def forget(s: Session, asset: Asset) -> None:
    """The host turned the read off: nothing it said before may link it to anything any more."""
    row = s.get(AssetAccess, asset.id)
    if row is not None:
        s.delete(row)
