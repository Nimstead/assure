"""Real-world risk scoring with a plain-English reason for every score.

Order of evidence: known exploitation (CISA KEV) is a hard override, then
probability of exploitation (FIRST EPSS), then impact (CVSS), adjusted by
what the asset is (criticality, internet exposure) and whether a fix exists.
"""

from dataclasses import dataclass, field
from functools import lru_cache

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


@lru_cache(maxsize=65536)  # a rescan pass scores the same few thousand vectors once per finding
def _vector_score(kind: str, vector: str):
    try:
        if kind == "CVSS_V3":
            return CVSS3(vector).scores()[0]
        if kind == "CVSS_V4":
            return CVSS4(vector).base_score
    except Exception:  # noqa: S110 — malformed vector in feed: ignore that vector only
        pass
    return None


def cvss_base(severity: list[dict] | None) -> float | None:
    """Highest base score from OSV `severity` vectors."""
    scores = [v for s in severity or [] if isinstance(s.get("score"), str)
              and (v := _vector_score(s.get("type"), s["score"])) is not None]
    return float(max(scores)) if scores else None


# CVRF component tags (DECISIONS 51) -> the Windows Server roles or client optional features that expose them. A tag
# not listed here changes nothing; the finding stays open either way (plan decision 6: the build is still vulnerable).
ROLE_TAGS = {
    "Role: DNS Server": ("DNS",), "Windows DHCP Server": ("DHCP",),
    "Windows Routing and Remote Access Service (RRAS)": ("RemoteAccess", "Routing", "DirectAccess-VPN"),
    "Windows Hyper-V": ("Hyper-V", "Microsoft-Hyper-V", "Microsoft-Hyper-V-All"),
    "Windows Message Queuing Queue Manager": ("MSMQ", "MSMQ-Server", "MSMQ-Container"),
    "Remote Desktop Gateway Service": ("RDS-Gateway",), "Network Policy Server (NPS)": ("NPAS",),
    "Active Directory Federation Services (AD FS)": ("ADFS-Federation",), "Active Directory Domain Services": ("AD-Domain-Services",),
    "WebDAV": ("Web-DAV-Publishing", "IIS-WebDAV"), "Windows Subsystem for Linux": ("Microsoft-Windows-Subsystem-Linux",),
}
PRIORITY = [(75, "fix-now"), (50, "next"), (25, "planned"), (0, "low")]


def _tier(s: int) -> str:
    return next(p for t, p in PRIORITY if s >= t)


def context(r: Risk, *, kev: bool, ransomware: bool = False, public_exploit: bool = False, msrc: dict | None = None,
            roles: list | None = None) -> Risk:
    """Threat and exposure context on top of score() (plan T11, T39). KEV still overrides everything: a known-exploited
    CVE is never lowered. Microsoft saying "exploited" counts like KEV before CISA lists it."""
    msrc = msrc or {}
    s, reasons = r.score, list(r.reasons)
    if ransomware:
        reasons.insert(1, "Used in ransomware campaigns (CISA KEV)")
    if msrc.get("exploited") and not kev:
        s = max(s, 90)
        reasons.insert(0, "Exploited in the wild (Microsoft)")
    elif not kev and msrc.get("exploitability") in ("Exploitation More Likely", "Exploitation Detected"):
        s = min(100, s + 10)
        reasons.append(f"Microsoft rates it: {msrc['exploitability']}")
    if public_exploit and not kev:
        s = min(100, s + 10)
        reasons.append("Public exploit (Metasploit module)")
    if msrc.get("disclosed"):
        reasons.append("Publicly disclosed before the fix")
    feats = ROLE_TAGS.get(msrc.get("tag", ""))
    if feats and isinstance(roles, list) and roles and not kev and not msrc.get("exploited") and not set(feats) & set(roles):
        s = round(s * 0.6)
        reasons.append(f"{msrc['tag'].removeprefix('Role: ')} isn't installed here: lower priority until it is")
    if s == r.score and reasons == r.reasons:
        return r
    return Risk(s, "fix-now" if kev or msrc.get("exploited") else _tier(s), reasons)


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
