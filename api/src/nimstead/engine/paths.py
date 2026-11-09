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
    """The host's attack paths, strongest first: at most one from the network and one from a foothold already on it."""
    if inv.is_linux or inv.kind == "application":
        return []  # shortcut: Windows settings are what make most chains here; Linux needs its own settings facts first
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


def _path(kind: str, stages: list[str], ways: dict) -> dict:
    steps = [{"stage": s, "label": STAGES[s], "ways": ways[s][:_SHOWN], "count": len(ways[s])} for s in stages]
    narrow = min(steps, key=lambda x: x["count"])  # first of the narrowest: the earliest place to break it
    return {"kind": kind, "start": "from the network" if kind == "network" else "from any program already running on it as a user",
            "grade": _grade(*(st["ways"][0]["grade"] for st in steps)), "steps": steps,
            "then": {"label": STAGES["lateral"], "ways": ways["lateral"][:_SHOWN], "count": len(ways["lateral"])} if ways["lateral"] else None,
            "break_at": {"stage": narrow["stage"], "label": narrow["label"], "fixes": narrow["count"],
                         "refs": [w["ref"] for w in ways[narrow["stage"]]][:_SHOWN]}}


def render(paths: list[dict]) -> list[str]:
    """Return display lines for attack-path dictionaries from build(), or [] when paths is empty."""
    if not paths:
        return []
    out = ["", "How these combine (attack paths)"]
    for p in paths:
        out.append(f"  {p['start'].capitalize()}, how sure: {p['grade']}")
        for st in p["steps"]:
            out.append(f"    {st['label']}: {st['count']} way{'s' * (st['count'] > 1)}")
            out += [f"      - {w['what']}" for w in st["ways"]]
        if t := p["then"]:
            out.append(f"    Then {t['label'].lower()}: " + "; ".join(w["what"] for w in t["ways"]))
        b = p["break_at"]
        out.append(f"    Break it: fix the {b['fixes']} way{'s' * (b['fixes'] > 1)} of {b['label'].lower()} ({', '.join(b['refs'])}"
                   + (" and others" if b["fixes"] > len(b["refs"]) else "") + ")")
    return out
