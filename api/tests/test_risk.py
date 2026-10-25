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
