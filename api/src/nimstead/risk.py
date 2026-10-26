"""Real-world risk scoring with a plain-English reason for every score.

Order of evidence: known exploitation (CISA KEV) is a hard override, then
probability of exploitation (FIRST EPSS), then impact (CVSS), adjusted by
what the asset is (criticality, internet exposure) and whether a fix exists.
"""

from dataclasses import dataclass, field

from cvss import CVSS3, CVSS4

CRITICALITY = {"low": 0.6, "medium": 0.8, "high": 1.0, "critical": 1.15}
# ponytail: hand-tuned weights; calibrate against real remediation outcomes once we have them


@dataclass
class Risk:
    score: int  # 0-100
    priority: str  # fix-now | next | planned | low
    reasons: list[str] = field(default_factory=list)

    @property
    def headline(self) -> str:
        return "; ".join(self.reasons)


def cvss_base(severity: list[dict] | None) -> float | None:
    """Highest base score from OSV `severity` vectors."""
    best = None
    for s in severity or []:
        try:
            if s.get("type") == "CVSS_V3":
                v = CVSS3(s["score"]).scores()[0]
            elif s.get("type") == "CVSS_V4":
                v = CVSS4(s["score"]).base_score
            else:
                continue
        except Exception:  # noqa: S112 — malformed vector in feed: ignore that vector only
            continue
        best = v if best is None else max(best, v)
    return float(best) if best is not None else None


def score(
    *,
    kev: bool,
    epss: float | None,
    cvss: float | None,
    criticality: str = "medium",
    internet_facing: bool = False,
    fix_available: bool = True,
    likelihood: float | None = None,
    likelihood_reason: str | None = None,
) -> Risk:
    """`likelihood`/`likelihood_reason`: for findings with no CVE (external exposure checks), a stated estimate
    instead of EPSS, so the reason shown says where it came from."""
    reasons: list[str] = []
    if kev:
        reasons.append("Exploited in the wild (CISA KEV)")
        likelihood = 1.0
    elif epss is not None:
        likelihood = epss**0.5  # spreads the long tail of small probabilities
        if epss >= 0.1:
            reasons.append(f"{epss:.0%} chance of exploitation in 30 days (EPSS)")
    elif likelihood is not None:
        if likelihood_reason:
            reasons.append(likelihood_reason)
    else:
        likelihood = 0.1

    impact = (cvss if cvss is not None else 5.0) / 10
    if cvss is not None and cvss >= 9:
        reasons.append(f"Critical severity (CVSS {cvss:.1f})")

    raw = 0.55 * likelihood + 0.45 * impact
    raw *= CRITICALITY.get(criticality, 0.8)
    raw *= 1.0 if internet_facing else 0.75
    if internet_facing:
        reasons.append("Internet-facing asset")
    if criticality in ("high", "critical"):
        reasons.append(f"{criticality.capitalize()}-criticality asset")
    if fix_available:
        reasons.append("Fix available")
    else:
        raw *= 0.7
        reasons.append("No fix yet — mitigate or accept")

    s = max(0, min(100, round(raw * 100)))
    if kev:
        s = max(s, 90)
    priority = "fix-now" if kev or s >= 75 else "next" if s >= 50 else "planned" if s >= 25 else "low"
    if not reasons:
        reasons.append("Low likelihood of exploitation")
    return Risk(s, priority, reasons)
