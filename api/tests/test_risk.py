from nimstead import risk
from nimstead.feeds import msrc_context
from nimstead.risk import cvss_base, score


def test_kev_beats_high_cvss_low_epss():
    kev = score(kev=True, epss=0.02, cvss=6.5)
    loud = score(kev=False, epss=0.001, cvss=9.8)
    assert kev.priority == "fix-now" and kev.score >= 90
    assert kev.score > loud.score
    assert loud.priority != "fix-now"  # a scary CVSS alone is not an emergency


def test_epss_drives_order_at_equal_cvss():
    assert score(kev=False, epss=0.6, cvss=7.5).score > score(kev=False, epss=0.01, cvss=7.5).score


def test_context_matters():
    base = dict(kev=False, epss=0.3, cvss=8.0)
    exposed = score(**base, criticality="critical", internet_facing=True)
    internal = score(**base, criticality="low", internet_facing=False)
    assert exposed.score > internal.score
    assert "Internet-facing asset" in exposed.reasons


def test_no_fix_downranks_but_explains():
    r = score(kev=False, epss=0.05, cvss=7.0, fix_available=False)
    assert r.score < score(kev=False, epss=0.05, cvss=7.0).score
    assert any("No fix" in x for x in r.reasons)


def test_bounds():
    assert 0 <= score(kev=False, epss=0.0, cvss=0.0).score <= 100
    assert score(kev=True, epss=1.0, cvss=10, criticality="critical", internet_facing=True).score == 100


def test_cvss_base_from_osv_severity():
    sev = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
    assert cvss_base(sev) == 9.8
    assert cvss_base([{"type": "CVSS_V3", "score": "garbage"}]) is None
    assert cvss_base(None) is None


# ---- threat and exposure context (plan T11, T39)



def base(**kw):
    return risk.score(kev=False, epss=0.02, cvss=8.1, **kw)


def test_microsoft_exploited_counts_like_kev():
    r = risk.context(base(), kev=False, msrc={"exploited": True})
    assert r.priority == "fix-now" and r.score >= 90 and r.reasons[0] == "Exploited in the wild (Microsoft)"


def test_ransomware_public_exploit_and_exploitability_are_reasons():
    r = risk.context(base(), kev=False, public_exploit=True, msrc={"exploitability": "Exploitation More Likely", "disclosed": True})
    assert r.score == base().score + 20
    assert {"Public exploit (Metasploit module)", "Microsoft rates it: Exploitation More Likely", "Publicly disclosed before the fix"} <= set(r.reasons)
    k = risk.context(risk.score(kev=True, epss=None, cvss=9.8), kev=True, ransomware=True)
    assert "Used in ransomware campaigns (CISA KEV)" in k.reasons and k.priority == "fix-now"


def test_role_not_installed_lowers_but_never_below_kev():
    msrc = {"tag": "Windows Message Queuing Queue Manager"}
    hi = risk.score(kev=False, epss=0.6, cvss=9.8)
    low = risk.context(hi, kev=False, msrc=msrc, roles=["Web-Server", "DNS"])
    assert low.score < hi.score and "Windows Message Queuing Queue Manager isn't installed here" in low.reasons[-1]
    assert risk.context(hi, kev=False, msrc=msrc, roles=["MSMQ"]).score == hi.score  # installed: unchanged
    assert risk.context(hi, kev=False, msrc=msrc, roles=None) is hi  # roles unknown: unchanged
    kev = risk.score(kev=True, epss=None, cvss=9.8)
    assert risk.context(kev, kev=True, msrc=msrc, roles=["Web-Server"]).priority == "fix-now"
    assert risk.context(hi, kev=False, msrc={"tag": "Windows Kernel"}, roles=["Web-Server"]) is hi  # unmapped tag


def test_msrc_context_reads_the_real_cvrf_shape():
    v = {"Notes": [{"Type": 7, "Value": "Role: DNS Server"}],
         "Threats": [{"Type": 1, "Description": {"Value": "Publicly Disclosed:No;Exploited:Yes;Latest Software Release:Exploitation Detected"}}]}
    assert msrc_context(v) == {"tag": "Role: DNS Server", "exploited": True, "disclosed": False, "exploitability": "Exploitation Detected"}
    assert msrc_context({}) == {}


def test_no_fix_can_lower_kev_score_but_preserves_floor():
    inputs = dict(kev=True, epss=1.0, cvss=10, criticality="critical", internet_facing=True)
    assert score(**inputs, fix_available=True).score == 100
    result = score(**inputs, fix_available=False)
    assert result.score == 90 and result.priority == "fix-now"
