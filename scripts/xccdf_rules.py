#!/usr/bin/env python3
"""Turn a DISA STIG XCCDF file into a rule table (api/src/nimstead/baselines/*.json; DECISIONS 75).

The XCCDF is untrusted input, and its text isn't ours to ship: only IDs, severity and the setting facts (registry path, value
name, expected value) reach the table, and the words shown to people are written by winbaseline.py from those facts. A rule is
automated only when its whole check text is understood: any sentence not on the lists below makes it "not automated", which
reads "not assessed". Being wrong costs a false pass or fail, so a rule stays out on any doubt. Review the report it prints.

    python -I scripts/xccdf_rules.py FILE-xccdf.xml --id windows-server-2025 --name "DISA STIG for Windows Server 2025" \\
        --os-re "^Windows Server 2025\\b" --source-sha256 HASH --out api/src/nimstead/baselines/windows-server-2025.json
    python -I scripts/xccdf_rules.py --agent-list api/src/nimstead/baselines/*.json     # what the agent's closed lists must hold
"""

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET  # noqa: S405  (entities refused below, before parsing)

NS = "{http://checklists.nist.gov/xccdf/1.1}"
MAX_XML = 20 * 1024 * 1024

# Sentences that change nothing about how the value is judged. They're matched whole, so a new condition falls out as manual.
INFO = [re.compile(p, re.I) for p in (
    r"Verify the registry value below[.:]?",
    r"If the following registry values? (does|do) not exist or (is|are) not configured as specified, this is a finding[.:]?",
    r"If the following registry values? (is|are) not configured as specified, this is a finding[.:]?",
    r"If the registry value does not exist or is not configured as specified, this is a finding\.?",
    r"\.?\s*If it does not exist or is not configured as specified, this is a finding\.?",
    r"If the registry value is not \"\w+\", this is a finding\.?",
    r"Verify SEHOP is turned on\.",
    r"The default behaviou?r (is|for) .*",
    r"If the registry value name below does not exist, this is not a finding\.",
    r"If it exists and is configured with a value of \"[^\"]+\", this is (not )?a finding\.",
    r"Possible values for this setting are:?",
    r"A value of 0x[0-9a-f]+ \(\d+\), internet, is a finding\.",
    r"This setting may prevent a system from being joined to a domain if not configured consistently between systems\.",
    r"Clients with this setting enabled will not be able to communicate via digitally encrypted or signed protocols with servers that do not support these algorithms\.",
    r"Both the browser and web server must be configured to use TLS; otherwise, the browser will not be able to connect to a secure site\.",
    r"(\(remove\))?This is the default configuration for this setting \(30 days\)\.",
    r"This LDAPServerEnforceIntegrity registry key explicitly overrides the legacy LDAPServerIntegrity key used in Windows Server 2022 and older\.",
    r"If the value for NoDriveTypeAutorun is entered manually, it must be entered as \"ff\" when Hexadecimal is selected or \"255\" if Decimal is selected\.",
    r"If this enforcement key is present and enabled, LDAP signing is strictly required regardless of the older policy setting\.",
)]
# Applicability we can tell from facts the agent already reports. Longest first, so "member servers and ..." isn't cut short.
SCOPES = [
    (r"This applies to domain controllers\. It is not applicable for other systems\.?", "dc"),
    (r"This applies to member servers\. For domain controllers and stand-alone or nondomain-joined systems, this is not applicable\.?", "member"),
    (r"This applies to member servers and stand-alone or nondomain-joined systems[,;] it is not applicable for domain controllers\.?", "not_dc"),
    (r"This is not applicable for Domain Controllers\.?", "not_dc"),
    (r"This requirement is applicable to domain-joined systems, for standalone systems this is NA\.?", "domain"),
    (r"If the system is not a member of a domain, this is NA\.?", "domain"),
    (r"For stand-alone or nondomain-joined systems, this is not applicable\.?", "domain"),
]
SERVER_CORE = r"UAC requirements are not applicable for Server Core installations \(this is the default installation option for Windows Server 2025 versus Server with Desktop Experience\)\.?"


def field(line: str, label: str) -> str | None:
    m = re.fullmatch(rf"\s*{label}\s*:?\s*(.*?)\s*", line, re.I)
    return m.group(1) if m else None


def parse_number(s: str) -> int | None:
    """0x00000001 (1), or a bare 1. A hex and decimal that disagree are a typo we can't resolve, so None."""
    m = re.fullmatch(r"0x([0-9a-f]+)(?: \((\d+)\))?", s.strip(), re.I)
    if m:
        return int(m.group(1), 16) if not m.group(2) or int(m.group(1), 16) == int(m.group(2)) else None
    return int(s) if s.strip().isdigit() else None


def parse_want(spec: str, extra: list[str]) -> dict | None:
    """The expected value: {"eq": n} | {"in": [..]} | {"ge": n} | {"le": n, "min": n}, plus "absent_ok". None = not understood."""
    spec = spec.strip()
    want: dict = {}
    if re.search(r"\(or if the Value Name does not exist\)", spec, re.I):
        want["absent_ok"] = True
        spec = re.sub(r"\s*\(or if the Value Name does not exist\)", "", spec, flags=re.I).strip()
    if (m := re.fullmatch(r"(.+?)\s*\(?or greater\)?", spec, re.I)) and (n := parse_number(m.group(1))) is not None:
        return {**want, "ge": n}
    if (m := re.fullmatch(r"(.+?)\s*\(or less, (?:but not|excluding) \"?0\"?[^)]*\)", spec, re.I)) and (n := parse_number(m.group(1))) is not None:
        return {**want, "le": n, "min": 1}
    if (m := re.fullmatch(r"(.+?)\s*\(or less\)", spec, re.I)) and (n := parse_number(m.group(1))) is not None:
        return {**want, "le": n}
    values = []
    for part in [*re.split(r",\s*(?:or\s+)?|\s+or\s+", spec), *extra]:
        # a value may carry a label after it: "0x00000002 (2) (Prompt ...)", "0x00000000 (0) - No peering"
        m = re.fullmatch(r"(0x[0-9a-f]+(?: \(\d+\))?|\d+)(?:\s*(?:\([^)]*\)|- .*))?", part.strip(), re.I)
        n = parse_number(m.group(1)) if m else None
        if n is None:
            return None
        values.append(n)
    return {**want, "eq": values[0]} if len(values) == 1 else {**want, "in": values}


def registry_rule(text: str) -> tuple[dict | None, str]:
    """(rule fields, "") or (None, why it stays manual)."""
    hive = path = name = typ = spec = None
    prose, extra = [], []
    for line in text.splitlines():
        if (v := field(line, "Registry Hive")) is not None:
            if hive:
                return None, "more than one registry value"
            hive = v
        elif (v := field(line, "Registry Path")) is not None:
            if path:
                return None, "more than one registry value"
            path = v
        elif (v := field(line, "Value Name")) is not None:
            if name:
                return None, "more than one registry value"
            name = v
        elif (v := field(line, "(?:Value )?Type")) is not None:
            typ = v
        elif (v := field(line, "Value")) is not None and spec is None:
            spec = v
        elif spec is not None and re.match(r"\s*0x[0-9a-f]+ \(\d+\)", line, re.I):
            extra.append(line)  # further accepted values, one per line
        else:
            prose.append(line)
    if not (hive and path and name and typ and spec):
        return None, "registry value not in the usual form"
    if hive.upper() != "HKEY_LOCAL_MACHINE":
        return None, "per-user registry value"  # the agent runs as SYSTEM: there's no one user's hive to read
    if not re.fullmatch(r"\\?[\w .{}\\-]+", path) or re.search(r"[*\[]", name):
        return None, "registry path with alternatives or placeholders"
    if typ not in ("REG_DWORD", "REG_SZ"):
        return None, f"{typ} value"
    rest = " ".join(prose)
    scope = "all"
    for pat, sc in SCOPES:
        if re.search(pat, rest, re.I):
            scope, rest = sc, re.sub(pat, " ", rest, flags=re.I)
    no_core = bool(re.search(SERVER_CORE, rest, re.I))
    rest = re.sub(SERVER_CORE, " ", rest, flags=re.I)
    if not_understood := unknown_sentences(rest):
        return None, "condition in the text: " + not_understood[0][:90]
    if typ == "REG_SZ":
        if re.fullmatch(r"O:BAG:BAD:\(A;;RC;;;BA\)", spec):
            want = {"eq": spec}
        elif (m := re.fullmatch(r"(\d+) \(or less\)", spec)):
            want = {"le": int(m.group(1))}
        else:
            return None, "text value"
        want["sz"] = True
    elif (want := parse_want(spec, extra)) is None:
        return None, "expected value not understood: " + spec[:60]
    rule = {"scope": scope, "reg": [path.strip("\\ "), name], "want": want}
    return ({**rule, "no_core": True} if no_core else rule), ""


def unknown_sentences(text: str) -> list[str]:
    parts = [p.strip() for p in re.split(r"(?<=[.:])\s+", re.sub(r"(Note|Warning):\s*|\s+", " ", text)) if p.strip(" .")]
    return [p for p in parts if not any(i.fullmatch(p) for i in INFO)]


def apply_id_scope(rule: dict, stig_id: str) -> dict | None:
    """The overview says -DC- rules are for domain controllers and -MS- for the rest; text that disagrees is left to a person."""
    part = stig_id.split("-")[1] if stig_id.count("-") >= 2 else ""
    if part == "DC" and rule["scope"] in ("all", "dc"):
        return {**rule, "scope": "dc"}
    if part == "MS" and rule["scope"] in ("all", "not_dc", "member"):
        return {**rule, "scope": "not_dc" if rule["scope"] == "all" else rule["scope"]}
    return None if part in ("DC", "MS") else rule


def classify(text: str, stig_id: str) -> tuple[dict | None, str]:
    if re.search(r"Registry Hive", text):
        rule, why = registry_rule(text)
    else:
        return None, "not a registry value"
    if rule and not (rule := apply_id_scope(rule, stig_id)):
        return None, "applicability in the text and the ID disagree"
    return rule, why


def load_benchmark(path: str) -> ET.Element:
    with open(path, "rb") as f:
        raw = f.read(MAX_XML + 1)
    if len(raw) > MAX_XML:
        raise SystemExit("file too large for a STIG")
    if b"<!DOCTYPE" in raw or b"<!ENTITY" in raw:  # XCCDF has no use for them: no entity expansion, no external fetches
        raise SystemExit("refusing XML with a DOCTYPE or entity declaration")
    return ET.fromstring(raw)  # noqa: S314


def build(root: ET.Element, ident: str, name: str, os_re: str, source: str, source_sha256: str) -> tuple[dict, list[tuple[str, str]]]:
    info = next((p.text or "" for p in root.findall(NS + "plain-text") if p.get("id") == "release-info"), "")
    release = re.search(r"Release: (\d+) Benchmark Date: (.+)", info)
    version = f"V{root.findtext(NS + 'version')}R{release.group(1) if release else '?'}"
    automated, manual, why = [], [], []
    for g in root.findall(NS + "Group"):
        r = g.find(NS + "Rule")
        check = r.find(NS + "check")
        ids = {"id": r.findtext(NS + "version"), "v": g.get("id"), "sev": r.get("severity")}
        rule, reason = classify(check.findtext(NS + "check-content") or "", ids["id"])
        if rule:
            automated.append({**ids, **rule})
        else:
            manual.append(ids)
            why.append((ids["id"], reason))
    return {"id": ident, "name": name, "version": version, "date": release.group(2).strip() if release else "", "os_re": os_re,
            "source": source, "source_sha256": source_sha256, "total": len(automated) + len(manual),
            "rules": automated, "not_automated": manual}, why


def agent_list(paths: list[str]) -> dict:
    """The union every baseline reads: the agent ships this, reviewed, and the server can't change it (DECISIONS 7, 27)."""
    reg = {}  # Windows doesn't care about case in a path, and the STIGs spell the same key several ways
    for p in paths:
        with open(p, encoding="utf-8") as f:
            for r in json.load(f)["rules"]:
                if "reg" in r:
                    reg.setdefault("|".join(r["reg"]).lower(), "|".join(r["reg"]))
    return {"reg": [reg[k] for k in sorted(reg)]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("xccdf", nargs="?")
    ap.add_argument("--id")
    ap.add_argument("--name")
    ap.add_argument("--os-re")
    ap.add_argument("--source", default="DISA, https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/")
    ap.add_argument("--source-sha256", default="")
    ap.add_argument("--out")
    ap.add_argument("--agent-list", nargs="+")
    a = ap.parse_args()
    if a.agent_list:
        print(json.dumps(agent_list(a.agent_list), indent=1))
        return 0
    table, why = build(load_benchmark(a.xccdf), a.id, a.name, a.os_re, a.source, a.source_sha256)
    lines = ",\n".join(" " + json.dumps(r, separators=(",", ":")) for r in table["rules"])  # one rule a line, so a diff reviews well
    head = {k: v for k, v in table.items() if k not in ("rules", "not_automated")}
    text = json.dumps(head, indent=1)[:-2] + ',\n"rules":[\n' + lines + '\n],\n"not_automated":' + json.dumps(table["not_automated"], separators=(",", ":")) + "\n}\n"
    json.loads(text)
    with open(a.out, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print(f"{table['id']} {table['version']}: {len(table['rules'])} automated of {table['total']}", file=sys.stderr)
    for rid, reason in why:
        print(f"  {rid}: {reason}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
