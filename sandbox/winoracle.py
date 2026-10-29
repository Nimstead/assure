"""Accuracy oracle for Windows (plan decision 1): Windows Update's own list of missing security updates vs our open
findings, by KB. Used by wine2e.py right after the agent's first report; `compare` is pure and unit-tested.

Windows Update runs as SYSTEM (it refuses network logons) with the Microsoft Update service added, so .NET, SQL Server
and Office MSI updates are listed too, not only Windows itself.
"""

import json
import re

MICROSOFT_UPDATE = "7971f918-a847-4430-9279-4a52d1efe18d"
SECURITY_UPDATES = "0fa1201d-4330-4fa8-8ae9-b877473b6441"  # WUA category "Security Updates"

PS_MISSING = r"""
$sm = New-Object -ComObject Microsoft.Update.ServiceManager
try { [void]$sm.AddService2('%MU%', 7, '') } catch { }
$s = New-Object -ComObject Microsoft.Update.Session
$q = $s.CreateUpdateSearcher(); $q.ServerSelection = 3; $q.ServiceID = '%MU%'
$r = $q.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
ConvertTo-Json -Compress -Depth 3 -InputObject @($r.Updates | Where-Object {
    ($_.Categories | ForEach-Object { $_.CategoryID }) -contains '%SEC%' -or $_.MsrcSeverity } | ForEach-Object {
  [pscustomobject]@{ kb = @($_.KBArticleIDs); title = $_.Title; severity = $_.MsrcSeverity; cves = @($_.CveIDs) } })
""".replace("%MU%", MICROSOFT_UPDATE).replace("%SEC%", SECURITY_UPDATES)

KB = re.compile(r"\(KB(\d{6,8})\)")


def compare(wua: list[dict], findings: list[dict]) -> dict:
    """KBs both agree on, KBs only Windows Update lists, KBs only we list, each with the CVEs involved."""
    theirs = {str(k): u for u in wua for k in u.get("kb") or []}
    ours: dict[str, set[str]] = {}
    for f in findings:
        if m := KB.search(f.get("summary") or ""):
            ours.setdefault(m.group(1), set()).add(f["vuln_id"])
    both = sorted(set(theirs) & set(ours))
    # (product, highest fixed build) per KB: a cumulative update both sides agree on supersedes any older month's KB
    # for the same product whose fixes it reaches (each finding names the month its fix first shipped)
    top: dict[str, tuple[str, tuple[int, ...]]] = {}
    for f in findings:
        if (m := KB.search(f.get("summary") or "")) and re.fullmatch(r"[\d.]+", f.get("fixed_version") or ""):
            b = tuple(int(x) for x in f["fixed_version"].split("."))
            top[m.group(1)] = max(top.get(m.group(1), (f["package"], b)), (f["package"], b), key=lambda t: t[1])

    def why_ours(k):
        p, b = top.get(k, (None, ()))
        sup = [a for a in both if a in top and top[a][0] == p and top[a][1] >= b]
        return f"superseded by KB{sup[0]} (cumulative, includes these fixes)" if sup else "not explained"

    def why_theirs(u):
        return ".NET Framework isn't detected (DECISIONS 51)" if ".NET Framework" in u["title"] else "not explained"
    return {
        "agree": [{"kb": k, "title": theirs[k]["title"], "cves": sorted(ours[k])} for k in both],
        "only_windows_update": [{"kb": k, "title": theirs[k]["title"], "cves": sorted(theirs[k].get("cves") or []),
                                 "why": why_theirs(theirs[k])} for k in sorted(set(theirs) - set(ours))],
        "only_nimstead": [{"kb": k, "cves": sorted(ours[k]), "why": why_ours(k)} for k in sorted(set(ours) - set(theirs))],
    }


def run(as_system, guest, findings: list[dict]) -> dict:
    """as_system/guest: wine2e's helpers. Returns the comparison table."""
    guest("New-Item -ItemType Directory -Force C:\\nimtest | Out-Null; Set-Content -Path C:\\nimtest\\oracle.ps1 -Encoding utf8 -Value @'\r\n"
          + PS_MISSING + "\r\n'@")
    as_system(r"powershell -NoProfile -ExecutionPolicy Bypass -File C:\nimtest\oracle.ps1 > C:\nimtest\oracle.json 2>&1",
              name="NimsteadOracle", wait_minutes=60)
    out = guest(r"Get-Content C:\nimtest\oracle.json -Raw").strip()
    return compare(json.loads(out.splitlines()[-1]) if out.startswith("[") else [], findings)
