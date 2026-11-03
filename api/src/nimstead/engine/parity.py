"""Parity with `scan.rescan` on the same inventory (design-e2.md): every finding it opened is a `vulnerable` verdict, and
every difference is listed with its reason. Anything left in `unexplained` is a bug in one of the two."""

from collections import defaultdict

from nimstead.engine.content import ECOSYSTEMS as IN_SLICE
from nimstead.engine.model import REASONS, Outcome, Verdict


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
        if k[0] not in IN_SLICE:
            outside[k[0]] += 1
        elif k not in vulnerable:
            why = next((v.reason for v in by_key.get(k, []) if v.reason), None)
            row = {"ecosystem": k[0], "package": k[1], "vuln_id": k[2]}
            if why:
                explained.append({**row, "engine": why, "why": f"rescan opened it; the engine won't say vulnerable because {REASONS[why][0]}"})
            else:
                unexplained.append({**row, "problem": "rescan opened it and the engine has no verdict for it"})
    for k in sorted(vulnerable - wanted):
        unexplained.append({"ecosystem": k[0], "package": k[1], "vuln_id": k[2], "problem": "the engine says vulnerable and rescan has no finding"})
    return {"agree": len(vulnerable & wanted), "outside_this_slice": dict(sorted(outside.items())), "explained": explained, "unexplained": unexplained, "ok": not unexplained}
