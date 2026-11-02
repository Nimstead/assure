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


def _judge(rule: dict, values: dict) -> tuple[str, str, str, str]:
    """(status, setting, expected, what was read)."""
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


def evaluate(os_name: str | None, facts: dict | None) -> dict | None:
    """{baseline fields, pass, fail, not_assessed, not_applicable, manual, rules}, or None when this OS has no baseline."""
    b = for_host(os_name)
    if not b:
        return None
    facts = facts if isinstance(facts, dict) else {}
    values = facts.get("baseline") if isinstance(facts.get("baseline"), dict) else {}
    rows = []
    for r in b["rules"]:
        status, setting, expected, found = _judge(r, values)
        fit = applies(r, facts)
        if fit is False:
            status = NOT_APPLICABLE
        elif fit is None:
            status = NOT_ASSESSED
        rows.append({"id": r["id"], "v": r["v"], "severity": r["sev"], "status": status, "setting": setting, "expected": expected, "found": found})
    count = lambda s: sum(x["status"] == s for x in rows)  # noqa: E731
    return {"baseline_id": b["id"], "name": b["name"], "version": b["version"], "date": b["date"], "automated": len(rows),
            "manual": len(b["not_automated"]), "pass": count(PASS), "fail": count(FAIL), "not_assessed": count(NOT_ASSESSED),
            "not_applicable": count(NOT_APPLICABLE), "rules": rows}
