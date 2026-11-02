"""Benchmark references (DECISIONS 75): how a Windows host's settings compare with the automated part of a published baseline.

Rule tables are data (baselines/*.json, from scripts/xccdf_rules.py): IDs, severity and the setting each rule reads, never the
benchmark's own text. Values come from the agent's closed list, and the server only judges them here; nothing a rule says ever
reaches the agent. Results are worked out from the host's stored facts when asked for, so they aren't findings and need no table.

A rule reads "not assessed" whenever we can't tell: no value from the agent, or applicability we can't establish. This is a
reference, not a conformance result: the manual rules are never assessed and a pass only means the setting read as expected.
"""

import hashlib
import json
import re
from functools import lru_cache
from pathlib import Path

DIR = Path(__file__).parent / "baselines"
PASS, FAIL, NOT_ASSESSED, NOT_APPLICABLE = "pass", "fail", "not assessed", "not applicable"
EXCEPTION_NOTE = "A documented need for this right can be an accepted exception, which we can't see"
SID_NAMES = {"S-1-5-32-544": "Administrators", "S-1-5-32-545": "Users", "S-1-5-32-546": "Guests", "S-1-5-32-555": "Remote Desktop Users",
             "S-1-5-11": "Authenticated Users", "S-1-5-9": "Enterprise Domain Controllers", "S-1-5-6": "Service", "S-1-5-19": "Local Service",
             "S-1-5-20": "Network Service", "S-1-5-113": "Local account", "S-1-5-114": "Local account and member of Administrators",
             "*-512": "Domain Admins", "*-519": "Enterprise Admins"}


@lru_cache(maxsize=1)
def baselines() -> tuple[dict, ...]:
    return tuple(json.loads(p.read_text(encoding="utf-8")) for p in sorted(DIR.glob("*.json")))


def for_host(os_name: str | None) -> dict | None:
    """The baseline for this OS. A second baseline is one more data file; an OS with none gets None, never a near match."""
    return next((b for b in baselines() if re.match(b["os_re"], os_name or "")), None)


def reg_id(key: str, name: str) -> str:
    """Same as the agent's baseline_id: what a registry value is called in its report."""
    return hashlib.sha256(f"{key}|{name}".lower().encode()).hexdigest()[:8]


def applies(rule: dict, facts: dict) -> bool | None:
    """Whether the rule is for this host; None when the facts can't say, which is never judged."""
    if rule.get("no_core"):
        kind = facts.get("installation_type")
        if kind == "Server Core":
            return False
        if kind != "Server":
            return None
    scope = rule.get("scope", "all")
    if scope == "all":
        return True
    role = facts.get("domain_role")  # Win32_ComputerSystem: 0/2 standalone, 1/3 member, 4/5 domain controller
    if not isinstance(role, int) or isinstance(role, bool) or not 0 <= role <= 5:
        return None
    return {"dc": role >= 4, "member": role in (1, 3), "not_dc": role < 4, "domain": role not in (0, 2)}[scope]


def _expected(want: dict) -> str:
    if "eq" in want:
        text = str(want["eq"])
    elif "in" in want:
        text = " or ".join(map(str, want["in"]))
    elif "ge" in want:
        text = f"at least {want['ge']}"
    else:
        text = f"{want.get('min', 0)} to {want['le']}" if want.get("min") else f"at most {want['le']}"
    return text + (", or not set" if want.get("absent_ok") else "")


def _meets(want: dict, value) -> bool:
    if want.get("sz"):  # a number kept as text (CachedLogonsCount), or an exact string
        if not isinstance(value, str):
            return False
        if "eq" in want:
            return value == want["eq"]
        value = int(value) if value.strip().isdigit() else None
    if not isinstance(value, int) or isinstance(value, bool):
        return False  # the wrong type isn't what the setting needs, and Windows won't read it as one
    if "eq" in want:
        return value == want["eq"]
    if "in" in want:
        return value in want["in"]
    if "ge" in want:
        return value >= want["ge"]
    return want.get("min", 0) <= value <= want["le"]


def _holders(sids) -> str:
    return ", ".join(SID_NAMES.get(x, x) for x in sids) or "nobody"


def _holds(pattern: str, held: list) -> bool:
    if pattern.startswith("*"):  # any domain's Domain Admins, Enterprise Admins
        return any(h.startswith("S-1-5-21-") and h.endswith(pattern[1:]) for h in held)
    return pattern in held


def _judge(rule: dict, values: dict, facts: dict) -> tuple[str, str, str, str]:
    """(status, setting, expected, what was read)."""
    if "audit" in rule:
        return _judge_audit(rule, values)
    if "right" in rule:
        return _judge_right(rule, values, facts)
    key, name = rule["reg"]
    setting, want = f"HKLM\\{key}\\{name}", rule["want"]
    expected, rid = _expected(want), reg_id(key, name)
    reg = values.get("reg") if isinstance(values.get("reg"), dict) else {}
    if rid not in reg:
        return NOT_ASSESSED, setting, expected, "not read"
    value = reg[rid]
    if value is None:
        return PASS if want.get("absent_ok") else FAIL, setting, expected, "not set"
    return PASS if _meets(want, value) else FAIL, setting, expected, str(value)[:100]


def _judge_audit(rule: dict, values: dict) -> tuple[str, str, str, str]:
    setting, expected = f"Audit policy: {rule['label']}", "audits " + ("success" if rule["bit"] == 1 else "failure")
    audit = values.get("audit") if isinstance(values.get("audit"), dict) else {}
    value = audit.get(rule["audit"])
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 3:
        return NOT_ASSESSED, setting, expected, "not read"
    found = ("no auditing", "success", "failure", "success and failure")[value]
    return PASS if value & rule["bit"] else FAIL, setting, expected, found


def _judge_right(rule: dict, values: dict, facts: dict) -> tuple[str, str, str, str]:
    setting = f"User right: {rule['right']}"
    domain = rule.get("require_domain", [])
    if "only" in rule:
        expected = "held only by " + _holders(rule["only"]) if rule["only"] else "held by nobody"
    else:
        expected = "includes " + _holders(" or ".join(SID_NAMES.get(x, x) for x in alt) for alt in [*rule["require"], *domain])
    rights = values.get("rights") if isinstance(values.get("rights"), dict) else {}
    held = rights.get(rule["right"])
    if not isinstance(held, list) or not all(isinstance(h, str) and h.startswith("S-1-") for h in held):  # "?": a name that wouldn't resolve
        return NOT_ASSESSED, setting, expected, "not read"
    found = _holders(held)[:100]
    if "only" in rule:
        return PASS if all(any(_holds(p, [h]) for p in rule["only"]) for h in held) else FAIL, setting, expected, found
    role = facts.get("domain_role")
    if domain and (not isinstance(role, int) or isinstance(role, bool)):
        return NOT_ASSESSED, setting, expected, found  # some holders are only needed on a domain
    needed = [*rule["require"], *(domain if role not in (0, 2) else [])]
    return PASS if all(any(_holds(p, held) for p in alt) for alt in needed) else FAIL, setting, expected, found


def evaluate(os_name: str | None, facts: dict | None) -> dict | None:
    """{baseline fields, pass, fail, not_assessed, not_applicable, manual, rules}, or None when this OS has no baseline."""
    b = for_host(os_name)
    if not b:
        return None
    facts = facts if isinstance(facts, dict) else {}
    values = facts.get("baseline") if isinstance(facts.get("baseline"), dict) else {}
    rows = []
    for r in b["rules"]:
        status, setting, expected, found = _judge(r, values, facts)
        fit = applies(r, facts)
        if fit is False:
            status = NOT_APPLICABLE
        elif fit is None:
            status = NOT_ASSESSED
        rows.append({"id": r["id"], "v": r["v"], "severity": r["sev"], "status": status, "setting": setting, "expected": expected, "found": found,
                     "note": EXCEPTION_NOTE if r.get("exception") and status == FAIL else ""})
    count = lambda s: sum(x["status"] == s for x in rows)  # noqa: E731
    return {"baseline_id": b["id"], "name": b["name"], "version": b["version"], "date": b["date"], "automated": len(rows),
            "manual": len(b["not_automated"]), "pass": count(PASS), "fail": count(FAIL), "not_assessed": count(NOT_ASSESSED),
            "not_applicable": count(NOT_APPLICABLE), "rules": rows}
