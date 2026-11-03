"""Parity with `scan.rescan` on the same inventory (design-e2.md): every finding it opened is a `vulnerable` verdict, and
every difference is listed with its reason. Anything left in `unexplained` is a bug in one of the two."""

from collections import defaultdict

from nimstead import lifecycle, sbom
from nimstead.engine.collection import linux
from nimstead.engine.content import ECOSYSTEMS as WINDOWS
from nimstead.engine.model import REASONS, Outcome, Verdict


def in_slice(ecosystem: str) -> bool:
    return ecosystem in WINDOWS or linux(ecosystem) or ecosystem in sbom.ECOSYSTEMS


def compare(verdicts: list[Verdict], findings: list[tuple[str, str, str]]) -> dict:
    """`findings`: (ecosystem, package, vuln_id) that rescan has open on this inventory."""
    by_key: dict[tuple, list[Verdict]] = defaultdict(list)
    for v in verdicts:
        if v.vuln_id:
            by_key[v.ecosystem, v.product, v.vuln_id].append(v)
    vulnerable = {k for k, vs in by_key.items() if any(v.outcome == Outcome.VULNERABLE for v in vs)}
    wanted = set(findings)
    outside, explained, unexplained = defaultdict(int), [], []
    for k in sorted(wanted):
        if not in_slice(k[0]):
            outside[k[0]] += 1
        elif k not in vulnerable:
            why = next((v.reason for v in by_key.get(k, []) if v.reason), None)
            row = {"ecosystem": k[0], "package": k[1], "vuln_id": k[2]}
            if why:
                explained.append({**row, "engine": why, "why": f"rescan opened it; the engine won't say vulnerable because {REASONS[why][0]}"})
            else:
                unexplained.append({**row, "problem": "rescan opened it and the engine has no verdict for it"})
    for k in sorted(vulnerable - wanted):
        row = {"ecosystem": k[0], "package": k[1], "vuln_id": k[2]}
        if k[0] == lifecycle.ECOSYSTEM and k[2].startswith("EOL:"):  # DECISIONS 85: only the engine judges a Linux release's end of support
            explained.append({**row, "engine": "end-of-life", "why": "the engine reports this release's end of support; rescan doesn't for Linux"})
        else:
            unexplained.append({**row, "problem": "the engine says vulnerable and rescan has no finding"})
    return {"agree": len(vulnerable & wanted), "outside_this_slice": dict(sorted(outside.items())), "explained": explained, "unexplained": unexplained, "ok": not unexplained}
