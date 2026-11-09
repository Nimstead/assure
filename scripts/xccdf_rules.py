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
    r"Verify the \"block all consumer Microsoft account user authentication\" is enabled\.",
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
    (r"This applies to domain controllers, it is not applicable for other systems\.?", "dc"),
    (r"This applies to domain controllers\. A separate version applies to other systems\.?", "dc"),
    (r"This applies to member servers and stand-alone or nondomain-joined systems\. A separate version applies to domain controllers\.?", "not_dc"),
    (r"This applies to member servers and stand-alone or nondomain-joined systems\. It is not applicable for domain controllers\.?", "not_dc"),
    (r"This applies to member servers\. For domain controllers and stand-alone or nondomain-joined systems, this is not applicable\.?", "member"),
    (r"This applies to member servers and stand-alone or nondomain-joined systems[,;] it is not applicable for domain controllers\.?", "not_dc"),
    (r"This is not applicable for Domain Controllers\.?", "not_dc"),
    (r"This requirement is applicable to domain-joined systems, for standalone systems this is NA\.?", "domain"),
    (r"If the system is not a member of a domain, this is NA\.?", "domain"),
    (r"For stand-alone or nondomain-joined systems, this is not applicable\.?", "domain"),
]
SERVER_CORE = r"UAC requirements are not applicable for Server Core installations \(this is the default installation option for Windows Server 2025 versus Server with Desktop Experience\)\.?"

GUID = "{{0CCE{}-69AE-11D9-BED3-505054503030}}"
# Audit subcategories (Microsoft's MS-GPAC list). Windows translates the names, so everything after this table uses the GUID.
AUDIT = {name: GUID.format(code) for name, code in {
    "Credential Validation": "923F", "Computer Account Management": "9236", "Other Account Management Events": "923A",
    "Security Group Management": "9237", "User Account Management": "9235", "Plug and Play Events": "9248", "PNP Activity": "9248",
    "Process Creation": "922B", "Directory Service Access": "923B", "Directory Service Changes": "923C", "Account Lockout": "9217",
    "Group Membership": "9249", "Logoff": "9216", "Logon": "9215", "Other Logon/Logoff Events": "921C", "Special Logon": "921B",
    "Detailed File Share": "9244", "File Share": "9224", "Other Object Access Events": "9227", "Removable Storage": "9245",
    "Audit Policy Change": "922F", "Audit Audit Policy Change": "922F", "Authentication Policy Change": "9230",
    "Authorization Policy Change": "9231", "MPSSVC Rule-Level Policy Change": "9232", "Other Policy Change Events": "9234",
    "Sensitive Privilege Use": "9228", "IPsec Driver": "9213", "IPSec Driver": "9213", "Other System Events": "9214",
    "Security State Change": "9210", "Security System Extension": "9211", "System Integrity": "9212",
}.items()}
AUDIT_INFO = [re.compile(p, re.I) for p in (
    r"Security Option \"Audit: Force audit policy subcategory settings .*",
    r"Use the \"?AuditPol\"? tool to review the current Audit Policy configuration[.:]?",
    r"-?Open (PowerShell|a Command Prompt)( or a command prompt)? with elevated privileges \(\"?Run as administrator\"?\)\.",
    r"-?Enter \"AuditPol /get /category:\*\"\.?",
    r"-?Compare the \"?AuditPol\"? settings with the following[.:]?",
    r"If the system does not audit the (following|above), this is a finding[.:]?",
)]
# The names the STIGs use for rights and groups, only to reach the constant and the SID. "*-512" is any domain's Domain Admins.
RIGHT_NAMES = {
    "Access Credential Manager as a trusted caller": "SeTrustedCredManAccessPrivilege", "Access this computer from the network": "SeNetworkLogonRight",
    "Act as part of the operating system": "SeTcbPrivilege", "Add workstations to domain": "SeMachineAccountPrivilege", "Allow log on locally": "SeInteractiveLogonRight",
    "Allow log on through Remote Desktop Services": "SeRemoteInteractiveLogonRight", "Back up files and directories": "SeBackupPrivilege",
    "Change the system time": "SeSystemtimePrivilege", "Create a pagefile": "SeCreatePagefilePrivilege", "Create a token object": "SeCreateTokenPrivilege",
    "Create global objects": "SeCreateGlobalPrivilege", "Create permanent shared objects": "SeCreatePermanentPrivilege", "Create symbolic links": "SeCreateSymbolicLinkPrivilege",
    "Debug programs": "SeDebugPrivilege", "Deny access to this computer from the network": "SeDenyNetworkLogonRight", "Deny log on as a batch job": "SeDenyBatchLogonRight",
    "Deny log on as a service": "SeDenyServiceLogonRight", "Deny log on locally": "SeDenyInteractiveLogonRight", "Deny log on through Remote Desktop Services": "SeDenyRemoteInteractiveLogonRight",
    "Enable computer and user accounts to be trusted for delegation": "SeEnableDelegationPrivilege", "Force shutdown from a remote system": "SeRemoteShutdownPrivilege",
    "Generate security audits": "SeAuditPrivilege", "Impersonate a client after authentication": "SeImpersonatePrivilege", "Increase scheduling priority": "SeIncreaseBasePriorityPrivilege",
    "Load and unload device drivers": "SeLoadDriverPrivilege", "Lock pages in memory": "SeLockMemoryPrivilege", "Manage auditing and security log": "SeSecurityPrivilege",
    "Modify firmware environment values": "SeSystemEnvironmentPrivilege", "Perform volume maintenance tasks": "SeManageVolumePrivilege", "Profile single process": "SeProfileSingleProcessPrivilege",
    "Restore files and directories": "SeRestorePrivilege", "Take ownership of files or other objects": "SeTakeOwnershipPrivilege",
}
GROUPS = {
    "Administrators": "S-1-5-32-544", "Users": "S-1-5-32-545", "Guests": "S-1-5-32-546", "Remote Desktop Users": "S-1-5-32-555", "Authenticated Users": "S-1-5-11",
    "Enterprise Domain Controllers": "S-1-5-9", "Service": "S-1-5-6", "Local Service": "S-1-5-19", "Network Service": "S-1-5-20", "Local account": "S-1-5-113",
    "Local account and member of Administrators group": "S-1-5-114", "Enterprise Admins Group": "*-519", "Enterprise Admin Group": "*-519",
    "Enterprise Admins": "*-519", "Domain Admins Group": "*-512", "Domain Admins": "*-512",
}
GROUPS = {k.lower().removesuffix(" group"): v for k, v in GROUPS.items()} | {"domain admin": "*-512"}
RIGHT_NAMES = {k.lower(): v for k, v in RIGHT_NAMES.items()}
RIGHT_INFO = [re.compile(p, re.I) for p in (
    r"(Review|Verify) the effective (User Rights )?setting in Local Group Policy Editor\.",
    r"Run \"?gpedit\.msc\"?\.",
    r"Navigate to Local Computer Policy >> .* >> User Rights Assignment\.",
    r"For server core installations, run the following command:",
    r"Secedit /Export /Areas User_Rights /cfg c:\\path\\filename\.txt",
    r"Review the text file\.",
    r"\"Local account\" refers to the Windows built-in security group\.",
    r"These are built-in security groups\. \"Local account\" is more restrictive but may cause issues on servers such as systems that provide failover clustering\.",
)]
# A documented need for the right is accepted: we can't see that, so a fail carries a note saying so.
RIGHT_EXCEPTION = [re.compile(p, re.I) for p in (
    r"If (an application|a domain application account such as for a management tool) requires this user right, this (is|would) not (be )?a finding\.",
    r"Vendor documentation must support the requirement for having the user right\.",
    r"The requirement must be documented with the (information system security officer \(ISSO\)|ISSO)\.",
    r"The application account, managed at the domain level, must meet requirements for application account passwords, such as length and frequency of changes as defined in the Windows Server STIGs\.",
    r"The application account must meet requirements for application account passwords, such as length \(\S+\) and required frequency of changes \(\S+\)\.",
    r"Passwords for (application )?accounts with this user right must be protected as highly privileged accounts\.",
)]


def field(line: str, label: str) -> str | None:
    """Return the value following label in line, or None if the full line does not match.

    Both inputs are strings; label is inserted as a regular-expression fragment."""
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
    """Parse registry check text into (rule fields, empty reason), or (None, refusal reason).

    text is the complete XCCDF check-content string. Unknown conditions, unsupported hives,
    multiple values, and ambiguous paths remain manual rather than producing a partial rule.
    This function does not read the registry or change host settings.
    """
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

def audit_rule(text: str) -> tuple[dict | None, str]:
    """Return (audit-rule dictionary, empty reason) for recognised audit-policy check text.

    Return (None, reason string) if the setting or a condition is not understood."""
    hits = re.findall(r"^\s*(.+?) >> (.+?) - (Success|Failure)\s*$", text, re.M)
    if len(hits) != 1 or (guid := AUDIT.get(hits[0][1])) is None:
        return None, "audit requirement not understood"
    rest = re.sub(r"^.* >> .* - (Success|Failure)\s*$", " ", text, flags=re.M)
    scope = "all"
    for pat, sc in SCOPES:
        if re.search(pat, rest, re.I):
            scope, rest = sc, re.sub(pat, " ", rest, flags=re.I)
    parts = [p.strip() for p in re.split(r"(?<=\.)\s+|\n+", rest) if p.strip(" .")]
    # the option other rules check: it makes these settings count, and has its own rule
    if unknown := [p for p in parts if not any(i.fullmatch(p) for i in AUDIT_INFO)
                   and not p.startswith(("must be set to \"Enabled\"", "(Windows 7 or later)"))]:
        return None, "condition in the text: " + unknown[0][:90]
    return {"scope": scope, "audit": guid, "label": hits[0][1].removeprefix("Audit "), "bit": 1 if hits[0][2] == "Success" else 2}, ""


def entry_sids(line: str) -> list[str] | None:
    """Return accepted SID alternatives parsed from one user-rights holder line.

    line can contain a literal SID, a known group name, or alternatives separated by "or".
    Domain group identifiers use wildcard suffixes. Return None if any holder is unknown.
    """
    out = []
    for part in re.split(r"\s+or\s+", re.sub(r"\s*\(see Note below\)", "", line).strip(" -.\t")):
        part = part.strip(' "')
        if (m := re.fullmatch(r"(S-1-[\w -]+?)(?: \(.*\))?", part)):
            sid = m.group(1).strip()
            sid = {"S-1-5-root domain-519": "*-519", "S-1-5-domain-512": "*-512"}.get(sid, sid)
            if not re.fullmatch(r"S-1-[\d-]+|\*-\d+", sid):
                return None
            out.append(sid)
        elif part.lower().removesuffix(" group") in GROUPS:
            out.append(GROUPS[part.lower().removesuffix(" group")])
        else:
            return None
    return out


def rights_rule(text: str) -> tuple[dict | None, str]:
    """Return (user-rights rule, empty reason) from complete XCCDF check text.

    text must describe one understood right with consistent holder lists and applicability.
    Return (None, refusal reason) for unknown conditions or conflicting console/SID forms.
    The parser does not inspect or modify the local security policy.
    """
    right, scope, exception = None, "all", False
    sections: list[dict] = []
    current = target = None
    for pat, sc in SCOPES:
        if re.search(pat, text, re.I):
            scope, text = sc, re.sub(pat, " ", text, flags=re.I)
    for raw in re.sub(r"(?<=\.) +(?=[A-Z\"])", "\n", text).splitlines():
        line = re.sub(r"^(Note|Warning):\s*", "", raw.strip())
        if not line:
            continue
        m = re.fullmatch(r"If any (?:SIDs|groups or accounts|accounts or groups)(?: \(to include administrators\),?)?( other than the following)? (?:are|is) (?:granted|defined for) the \"(.+?)\"(?: user)? right(?:, this is a finding|, this is a finding)[.:]?", line, re.I)
        n = re.fullmatch(r"If the following (?:SIDs?|SID\(s\)|groups or accounts|accounts or groups) (?:are|is) not defined for the \"(.+?)\"(?: user)? right, this is a finding[.:]?", line, re.I)
        if m or n:
            name = (m.group(2) if m else n.group(1))
            se = name if name.startswith("Se") else RIGHT_NAMES.get(name.lower())
            if not se or (right and right != se):
                return None, f"right not understood: {name[:60]}"
            right = se
            current = {"kind": ("only" if m.group(1) else "none") if m else "require", "all": [], "domain": []}
            sections.append(current)
            target = current["all"]
        elif re.fullmatch(r"Domain Systems Only:", line, re.I) and current:
            target = current["domain"]
        elif re.fullmatch(r"All Systems:", line, re.I) and current:
            target = current["all"]
        elif any(i.fullmatch(line) for i in RIGHT_EXCEPTION):
            exception = True
            current = target = None
        elif any(i.fullmatch(line) for i in RIGHT_INFO):
            current = target = None
        elif target is not None and (sids := entry_sids(line)) is not None:
            target.append(sids)
        else:
            return None, "condition in the text: " + line[:90]
    if not sections:
        return None, "rights requirement not understood"
    kinds = {x["kind"] for x in sections}
    # as sets of sorted alternatives, so the console's and the file's lists compare whatever their order
    shape = {(x["kind"], tuple(sorted(map(tuple, x["all"]))), tuple(sorted(map(tuple, x["domain"])))) for x in sections}
    if len(shape) != 1 or len(kinds) != 1:
        return None, "the rule's two wordings disagree"
    first = sections[0]
    rule = {"scope": scope, "right": right}
    if first["kind"] == "require":
        rule["require"] = first["all"]
        if first["domain"]:
            rule["require_domain"] = first["domain"]
    else:
        if first["domain"] or any(len(a) > 1 for a in first["all"]):
            return None, "allowed list has alternatives"
        rule["only"] = [] if first["kind"] == "none" else [a[0] for a in first["all"]]
    return ({**rule, "exception": True} if exception else rule), ""


def unknown_sentences(text: str) -> list[str]:
    """Return sentence fragments in check text that do not match the accepted informational patterns."""
    parts = [p.strip() for p in re.split(r"(?<=[.:])\s+", re.sub(r"\b(Note|Warning):\s*|\s+", " ", text)) if p.strip(" .")]
    return [p for p in parts if not any(i.fullmatch(p) for i in INFO)]


def apply_id_scope(rule: dict, stig_id: str) -> dict | None:
    """Reconcile rule applicability with the domain role encoded in stig_id.

    rule is a parsed dictionary containing scope. Return a scoped copy for DC/MS identifiers,
    the original rule for other identifiers, or None for contradictory applicability.
    A missing scope on a DC/MS rule raises KeyError. The input dictionary is not mutated.
    """
    part = stig_id.split("-")[1] if stig_id.count("-") >= 2 else ""
    if part == "DC" and rule["scope"] in ("all", "dc"):
        return {**rule, "scope": "dc"}
    if part == "MS" and rule["scope"] in ("all", "not_dc", "member"):
        return {**rule, "scope": "not_dc" if rule["scope"] == "all" else rule["scope"]}
    return None if part in ("DC", "MS") else rule


def classify(text: str, stig_id: str) -> tuple[dict | None, str]:
    """Return (rule dictionary or None, reason string) for text and stig_id.

    text is complete XCCDF check content. stig_id is the benchmark rule identifier.

    Select registry, audit, or user-rights parsing and refuse conflicting applicability."""
    if re.search(r"Registry Hive", text):
        rule, why = registry_rule(text)
    elif re.search(r"AuditPol", text):
        rule, why = audit_rule(text)
    elif re.search(r"User Rights Assignment", text):
        rule, why = rights_rule(text)
    else:
        return None, "not a setting the agent can read"
    if rule and not (rule := apply_id_scope(rule, stig_id)):
        return None, "applicability in the text and the ID disagree"
    return rule, why


def load_benchmark(path: str) -> ET.Element:
    """Parse an XCCDF file at path into an XML Element.

    Raise SystemExit for excessive size or DOCTYPE/entity declarations. File I/O and XML
    parse errors propagate; no external resources are fetched."""
    with open(path, "rb") as f:
        raw = f.read(MAX_XML + 1)
    if len(raw) > MAX_XML:
        raise SystemExit("file too large for a STIG")
    if b"<!DOCTYPE" in raw or b"<!ENTITY" in raw:  # XCCDF has no use for them: no entity expansion, no external fetches
        raise SystemExit("refusing XML with a DOCTYPE or entity declaration")
    return ET.fromstring(raw)  # noqa: S314


def build(root: ET.Element, ident: str, name: str, os_re: str, source: str, source_sha256: str) -> tuple[dict, list[tuple[str, str]]]:
    """Return (baseline dictionary, list of manual-rule reasons) from an XCCDF root Element.

    ident and name label the baseline; os_re selects host OS names. source and source_sha256
    record provenance. Unsupported checks remain manual. Malformed benchmark structures can
    raise attribute or key errors; the caller reviews the output before shipping it."""
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
    """Return sorted registry, audit, and user-rights collection lists for baseline paths.

    paths names local JSON baseline files. Registry keys are deduplicated case-insensitively.
    File errors, invalid JSON, and missing required rule fields propagate to the caller.
    The result needs review before it becomes the agent's closed collection list.
    """
    reg, audit, rights = {}, set(), set()  # Windows doesn't care about case in a path, and the STIGs spell the same key several ways
    for p in paths:
        with open(p, encoding="utf-8") as f:
            for r in json.load(f)["rules"]:
                if "reg" in r:
                    reg.setdefault("|".join(r["reg"]).lower(), "|".join(r["reg"]))
                audit |= {r["audit"]} if "audit" in r else set()
                rights |= {r["right"]} if "right" in r else set()
    return {"reg": [reg[k] for k in sorted(reg)], "audit": sorted(audit), "rights": sorted(rights)}


def main() -> int:
    """Parse command-line arguments and write a baseline JSON file or print an agent collection list.

    Return 0 on success. Parsing, benchmark, JSON, and file errors propagate or exit nonzero."""
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
