"""Attack-path correlation on one host (docs/engine/design-paths.md): how this host's own weaknesses chain into a compromise.

Four stages: getting in, becoming SYSTEM or an administrator, taking credentials, reaching the next host. Every step is a
vulnerable verdict or a setting `winconfig` already judged; nothing here re-decides either. A vulnerability's stage comes
from its CVSS vector first (vendor-neutral), then from MSRC's impact in the title. "From the network" needs evidence the
host is reachable: a setting that opens it, a firewall-allowed listener for the vulnerable product, or a remote flaw CISA
lists as exploited. A remote-looking CVE in a library is never treated as exposure on its own.

A path is as sure as its weakest step, and the report names the stage with the fewest ways through: fixing those breaks it.
"""

import re

from nimstead import winconfig
from nimstead.engine.collection import Inventory
from nimstead.engine.content import Content
from nimstead.engine.model import Grade, Outcome, Verdict
from nimstead.match import canonical_id

STAGES = {"entry": "Getting in", "escalate": "Becoming SYSTEM or an administrator", "credentials": "Taking credentials",
          "lateral": "Reaching other hosts"}
# winconfig checks -> the stage they open. Settings that only weaken one stage's defence still count: each is a way through
SETTINGS = {"smb1": "entry", "rdp-nla": "entry", "guest-account": "entry",
            "always-install-elevated": "escalate", "unquoted-service-paths": "escalate", "writable-service-binaries": "escalate",
            "uac": "escalate", "spooler-on-dc": "escalate",
            "wdigest": "credentials", "autologon-password": "credentials", "reversible-passwords": "credentials",
            "lsa-protection": "credentials", "ntlmv1": "credentials",
            "smb-signing": "lateral", "llmnr": "lateral", "netbios": "lateral", "remote-uac": "lateral",
            "ldap-signing": "lateral", "ldap-channel-binding": "lateral"}
_ORDER = ("unverified", "reasonable", "confirmed")
_SHOWN = 5


def _vector(rec: dict) -> dict[str, str]:
    for s in rec.get("severity") or []:
        if str(s.get("type", "")).startswith("CVSS_V") and isinstance(s.get("score"), str):
            return dict(p.split(":", 1) for p in s["score"].split("/")[1:] if ":" in p)
    return {}


def _vectors(content: Content) -> dict[tuple[str, str, str], dict]:
    return {(e, k, canonical_id(r)): _vector(r) for (e, k), recs in content.records.items() for r in recs}


def _stage(v: Verdict, vec: dict) -> tuple[str, str] | None:
    """(stage, why) for a vulnerable verdict, or None when nothing says how it would be used."""
    high = vec.get("C") == "H" or vec.get("I") == "H"
    if vec.get("AV") == "L" and vec.get("PR") in ("L", "N") and high or (not vec and re.search(r"Elevation of Privilege", v.summary or "")):
        return "escalate", "a local user can gain higher privileges" + (" (CVSS AV:L)" if vec else " (MSRC: Elevation of Privilege)")
    if vec.get("AV") == "N" and vec.get("PR") == "N" and high or (not vec and re.search(r"Remote Code Execution", v.summary or "")):
        return "remote", "runs code over the network" + (" with no sign-in" if vec else "") + (" once a user opens something" if vec.get("UI") == "R" else "")
    return None


def _grade(*grades: str | None) -> str:
    return min((g or "unverified" for g in grades), key=_ORDER.index)


def build(inv: Inventory, content: Content, verdicts: list[Verdict]) -> list[dict]:
    """Return correlated attack paths from Inventory inv, Content content and verdicts.

    Linux and application inventories return []. Windows uses vulnerable verdicts
    plus host settings. Return at most one network path, then one foothold path.
    Each stage shows at most five ways, with its full count. Does not scan or
    modify inputs. Malformed internal models can raise KeyError, TypeError or ValueError."""
    if inv.kind == "application":
        return []
    if inv.is_linux:
        return build_linux(inv, content, verdicts)
    facts_grade = Grade.CONFIRMED.value if inv.source("host_facts").state == "ok" else Grade.UNVERIFIED.value
    ways: dict[str, list[dict]] = {s: [] for s in STAGES}
    for f in winconfig.evaluate(inv.facts, next((p["version"] for p in inv.packages if p.get("ecosystem") == "Windows"), "")):
        if (stage := SETTINGS.get(f["package"])):
            ways[stage].append({"what": f["summary"].split(". ")[0], "ref": f["vuln_id"], "grade": facts_grade, "kev": False})
    listening = winconfig.reachable_listeners(inv.facts)
    vec = _vectors(content)
    found: dict[tuple, list[tuple[Verdict, str, str | None]]] = {}  # (stage, product, install) -> its flaws: one way, one thing to update
    for v in verdicts:
        if v.outcome != Outcome.VULNERABLE or not v.vuln_id:
            continue
        s = _stage(v, vec.get((v.ecosystem, v.product, v.vuln_id), {}))
        if not s:
            continue
        stage, why = s
        exposed = next((reason for keys, reason in listening if any(str(v.product).startswith(k) for k in keys)), None)
        if stage == "remote" and not exposed and not v.kev:
            continue
        found.setdefault(("escalate" if stage == "escalate" else "entry", v.product, v.instance), []).append((v, why, exposed))
    for (stage, product, instance), vs in found.items():
        vs.sort(key=lambda x: (not x[0].kev, not x[2], x[0].vuln_id))  # known exploited first, then a seen listener
        v, why, exposed = vs[0]
        more = f" (and {len(vs) - 1} more like it in the same install)" if len(vs) > 1 else ""
        what, grade = f"{v.vuln_id} in {instance or product}: {why}{more}", v.grade.value if v.grade else None
        if exposed:
            what += f". {exposed}"
        elif stage == "entry":  # exploited in the wild: worth a path without seeing the port, and said so
            what, grade = what + "; CISA lists it as exploited, the port wasn't seen", _grade(grade, "reasonable")
        ways[stage].append({"what": what, "ref": v.vuln_id, "grade": grade, "kev": v.kev, "flaws": len(vs)})
    for w in ways.values():
        w.sort(key=lambda x: (not x["kev"], -_ORDER.index(x["grade"] or "unverified"), x["ref"]))
    out = []
    after_entry = [s for s in ("escalate", "credentials") if ways[s]]
    if ways["entry"] and after_entry:
        out.append(_path("network", ["entry", *after_entry], ways))
    if ways["escalate"] and ways["credentials"]:
        out.append(_path("foothold", ["escalate", "credentials"], ways))
    return out


LINUX_LABELS = {**STAGES, "escalate": "Becoming root"}
ANYONE = "anyone with an account"


def _listeners(inv: Inventory, product: str) -> list[dict]:
    """The programs listening beyond loopback that loaded any binary of this source package in the last seven days."""
    binaries = {p["name"] for p in inv.packages if (p.get("source") or p["name"]) == product} or {product}
    heard = inv.context.get("listening") or {}
    return [x for b in sorted(binaries) for x in heard.get(b, [])]


def _who(listeners: list[dict]) -> set[str]:
    return {u for x in listeners for u in x.get("users") or []}


def ssh_state(inv: Inventory) -> dict | None:
    """{"listening", "how"} for this Linux host's sshd, from the runtime read when it saw sshd, else its configuration; None
    when neither was read. Stored in the report, so the fleet view knows whether a key trusted here can be used."""
    from nimstead import linconfig
    acc = inv.context.get("access") or {}
    heard = inv.context.get("listening")
    programs = None if heard is None else [{"name": x["program"], "listen": x["listen"]} for xs in heard.values() for x in xs]
    got = linconfig.ssh_listening(programs, acc.get("sshd")) if acc else None
    return {"listening": got[0], "how": got[1]} if got else None


def build_linux(inv: Inventory, content: Content, verdicts: list[Verdict]) -> list[dict]:
    """Attack paths on one Linux host (tasks/spec-paths.md Module 3, DECISIONS 167), privilege-aware: a way in names the user
    the listening program runs as; a program running as root skips becoming root; a setting helps only the users it names;
    credentials are every key on the machine once root, only the way-in user's own before. Each path says what it reaches
    ("root", or the users), which the fleet view uses to decide whose keys an attacker holds. Returns [] when nothing chains."""
    from nimstead import linconfig
    acc = inv.context.get("access") or {}
    facts_grade = Grade.CONFIRMED.value if acc.get("state") == "ok" else Grade.UNVERIFIED.value
    st = ssh_state(inv)
    ssh = (st["listening"], st["how"]) if st else None
    entry, escalate = [], []
    for f in linconfig.evaluate(acc, ssh) if acc else []:
        stage = linconfig.STAGE[f["package"]]
        way = {"what": f["summary"].split(". ")[0], "ref": f["vuln_id"], "grade": facts_grade, "kev": False, "helps": f["helps"]}
        if stage == "entry":  # signing in as root, or as the accounts with no password
            entry.append({**way, "users": {"root"} if f["package"] == "ssh-root-password" else
                          {a["name"] for a in acc.get("accounts", []) if a.get("password") == "empty" and a.get("login")}})
        elif stage == "escalate":
            escalate.append(way)
    vec = _vectors(content)
    found: dict[tuple, list] = {}
    for v in verdicts:
        if v.outcome != Outcome.VULNERABLE or not v.vuln_id:
            continue
        s = _stage(v, vec.get((v.ecosystem, v.product, v.vuln_id), {}))
        if s:
            found.setdefault((s[0], v.product, v.instance), []).append((v, s[1]))
    for (stage, product, instance), vs in found.items():
        vs.sort(key=lambda x: (not x[0].kev, x[0].vuln_id))
        v, why = vs[0]
        more = f" (and {len(vs) - 1} more like it in the same package)" if len(vs) > 1 else ""
        what, grade = f"{v.vuln_id} in {instance or product}: {why}{more}", v.grade.value if v.grade else None
        if stage == "escalate":
            escalate.append({"what": what, "ref": v.vuln_id, "grade": grade, "kev": v.kev, "flaws": len(vs), "helps": [ANYONE]})
            continue
        ls = _listeners(inv, product)
        if ls:
            x = ls[0]
            users = _who(ls)
            what += (f". Loaded by {x['program']}, listening on {', '.join(a.split('/')[0] for a in x['listen'][:2])}"
                     + (f", running as {', '.join(sorted(users))}" if users else "") + "; the host firewall isn't read")
            entry.append({"what": what, "ref": v.vuln_id, "grade": _grade(grade, "reasonable"), "kev": v.kev, "flaws": len(vs), "users": users})
        elif v.kev:  # exploited in the wild: worth a path without seeing a listener, and said so
            entry.append({"what": what + "; CISA lists it as exploited, no listener was seen", "ref": v.vuln_id, "grade": _grade(grade, "reasonable"),
                          "kev": True, "flaws": len(vs), "users": set()})
    held = [h for h in acc.get("held", []) if isinstance(h, dict)]

    def creds(users: set[str] | None) -> list[dict]:
        """Credentials an attacker holds as root (users None) or as these users."""
        out = []
        for h in held:
            if users is None or h["account"] in users:
                out.append({"what": f"{h['account']}'s SSH key {h['path']}" + (" (needs its passphrase)" if h["passphrase"] else " (no passphrase)"),
                            "ref": h["fp"], "grade": "unverified" if h["passphrase"] else facts_grade, "kev": False})
        for c in acc.get("credentials", []):
            if users is None or c["account"] in users:
                out.append({"what": "the machine's Kerberos keytab (its domain account)" if c["kind"] == "keytab" else
                            f"{c['account']}'s {c['kind']} credentials file {c['path']}: opens something beyond this fleet, not followed",
                            "ref": c["path"], "grade": facts_grade, "kev": False})
        return out

    def usable(way: dict, users: set[str]) -> bool:
        return ANYONE in way["helps"] or bool(users & set(way["helps"]))

    def order(ws):
        return sorted(ws, key=lambda x: (not x["kev"], -_ORDER.index(x["grade"] or "unverified"), x["ref"]))

    out = []
    as_root = [w for w in entry if "root" in w["users"]]
    if as_root:
        ways = {"entry": order(as_root), "credentials": order(creds(None))}
        out.append(_path("network", ["entry", *(["credentials"] if ways["credentials"] else [])], ways, LINUX_LABELS,
                         reaches={"root": True, "users": []}, skipped="the way in runs as root, so getting in is becoming root",
                         keys=len(held)))
    elif entry:
        users = set().union(*(w["users"] for w in entry))
        up = order([w for w in escalate if usable(w, users)])
        mine = order(creds(users))
        if up:
            ways = {"entry": order(entry), "escalate": up, "credentials": order(creds(None))}
            out.append(_path("network", ["entry", "escalate", *(["credentials"] if ways["credentials"] else [])], ways, LINUX_LABELS,
                             reaches={"root": True, "users": []}, keys=len(held)))
        elif mine:
            ways = {"entry": order(entry), "credentials": mine}
            out.append(_path("network", ["entry", "credentials"], ways, LINUX_LABELS, reaches={"root": False, "users": sorted(users)},
                             keys=len([h for h in held if h["account"] in users])))
    anyone = order([w for w in escalate if ANYONE in w["helps"]])
    root_creds = order(creds(None))
    if anyone and root_creds:
        out.append(_path("foothold", ["escalate", "credentials"], {"escalate": anyone, "credentials": root_creds}, LINUX_LABELS,
                         reaches={"root": True, "users": []}, keys=len(held)))
    for p in out:  # sets and helper keys stay out of the stored report
        for st in p["steps"]:
            st["ways"] = [{k: v for k, v in w.items() if k not in ("users", "helps")} for w in st["ways"]]
    return out


def _path(kind: str, stages: list[str], ways: dict, labels: dict = STAGES, reaches: dict | None = None, skipped: str | None = None,
          keys: int = 0) -> dict:
    if labels is LINUX_LABELS:
        lateral = {"label": labels["lateral"], "ways": [{"what": f"{keys} SSH key{'s' * (keys != 1)} this path takes: the fleet view shows which "
                                                                  "machines trust them", "ref": "SSH keys", "grade": None, "kev": False}],
                   "count": keys} if keys else None
        ways = {**ways, "lateral": lateral["ways"] if lateral else []}
    steps = [{"stage": s, "label": labels[s], "ways": ways[s][:_SHOWN], "count": len(ways[s])} for s in stages]
    narrow = min(steps, key=lambda x: x["count"])  # first of the narrowest: the earliest place to break it
    out = {"kind": kind, "start": "from the network" if kind == "network" else "from any program already running on it as a user",
           "grade": _grade(*(st["ways"][0]["grade"] for st in steps)), "steps": steps,
           "then": {"label": STAGES["lateral"], "ways": ways["lateral"][:_SHOWN], "count": len(ways["lateral"])} if ways["lateral"] else None,
           "break_at": {"stage": narrow["stage"], "label": narrow["label"], "fixes": narrow["count"],
                        "refs": [w["ref"] for w in ways[narrow["stage"]]][:_SHOWN]}}
    if labels is LINUX_LABELS:  # Windows reports keep their shape byte for byte
        out["reaches"] = reaches or {"root": False, "users": []}
        if lateral:
            out["then"]["count"] = keys
        if skipped:
            out["skipped"] = {"stage": "escalate", "label": labels["escalate"], "why": skipped}
    return out


def render(paths: list[dict]) -> list[str]:
    """Return display lines for attack-path dictionaries from build(), or [] when paths is empty.

    Does not escape terminal controls or write output. The enclosing report renderer
    handles escaping. Malformed dictionaries can raise KeyError or TypeError."""
    if not paths:
        return []
    out = ["", "How these combine (attack paths)"]
    for p in paths:
        out.append(f"  {p['start'].capitalize()}, how sure: {p['grade']}")
        for st in p["steps"]:
            out.append(f"    {st['label']}: {st['count']} way{'s' * (st['count'] > 1)}")
            out += [f"      - {w['what']}" for w in st["ways"]]
            if st["stage"] == "entry" and (sk := p.get("skipped")):
                out.append(f"    {sk['label']}: not needed, {sk['why']}")
        if t := p["then"]:
            out.append(f"    Then {t['label'].lower()}: " + "; ".join(w["what"] for w in t["ways"]))
        b = p["break_at"]
        out.append(f"    Break it: fix the {b['fixes']} way{'s' * (b['fixes'] > 1)} of {b['label'].lower()} ({', '.join(b['refs'])}"
                   + (" and others" if b["fixes"] > len(b["refs"]) else "") + ")")
    return out
