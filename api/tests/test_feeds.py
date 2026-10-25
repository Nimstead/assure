import gzip
import io
import json
import zipfile

import httpx
import pytest
from sqlalchemy import func, select

from nimstead.db import Advisory, Epss, Kev, make_sessionmaker
from nimstead.feeds import sync_epss, sync_kev, sync_osv


def rec(id, modified, pkg="openssl", eco="Ubuntu:22.04:LTS"):
    return {"id": id, "modified": modified, "details": "x" * 900, "upstream": ["CVE-1"],
            "affected": [{"package": {"ecosystem": eco, "name": pkg}, "ranges": []},
                         {"package": {"ecosystem": eco, "name": "other"}, "ranges": []}]}


def zip_of(*recs):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for r in recs:
            z.writestr(r["id"] + ".json", json.dumps(r))
    return b.getvalue()


def client(body=None, status=200):
    return httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(status, content=body)), follow_redirects=True)


def count(s, model):
    return s.scalar(select(func.count()).select_from(model))


def test_osv_upsert_and_incremental_skip():
    s = make_sessionmaker("sqlite://")()
    assert sync_osv(s, ["Ubuntu"], client(zip_of(rec("USN-1", "2024-01-01")))) == {"inserted": 2, "updated": 0, "skipped": 0}
    a = s.get(Advisory, ("USN-1", "Ubuntu:22.04", "openssl"))  # LTS suffix normalized
    assert len(a.record["details"]) == 500 and [x["package"]["name"] for x in a.record["affected"]] == ["openssl"]
    assert sync_osv(s, ["Ubuntu"], client(zip_of(rec("USN-1", "2024-01-01")))) == {"inserted": 0, "updated": 0, "skipped": 2}
    assert sync_osv(s, ["Ubuntu"], client(zip_of(rec("USN-1", "2024-02-01"), rec("USN-2", "2024-02-01")))) == {"inserted": 2, "updated": 2, "skipped": 0}
    assert s.get(Advisory, ("USN-1", "Ubuntu:22.04", "openssl")).modified == "2024-02-01"
    assert count(s, Advisory) == 4


def test_osv_http_error_raises():
    with pytest.raises(httpx.HTTPStatusError):
        sync_osv(make_sessionmaker("sqlite://")(), ["Debian"], client(status=404))


def test_kev_parse():
    body = json.dumps({"vulnerabilities": [
        {"cveID": "CVE-2024-1", "dateAdded": "2024-01-01", "dueDate": "2024-01-22", "knownRansomwareCampaignUse": "Known"},
        {"cveID": "CVE-2024-2", "dateAdded": "2024-01-02", "dueDate": "2024-01-23", "knownRansomwareCampaignUse": "Unknown"}]}).encode()
    s = make_sessionmaker("sqlite://")()
    assert sync_kev(s, client(body)) == 2
    assert s.get(Kev, "CVE-2024-1").ransomware is True and s.get(Kev, "CVE-2024-2").ransomware is False
    assert s.get(Kev, "CVE-2024-1").due_date == "2024-01-22"


CSV = "#model_version:v2025.03.14,score_date:2026-01-01T00:00:00Z\ncve,epss,percentile\nCVE-2024-1,0.5,0.9\nCVE-2024-2,0.01,0.1\n"


def test_epss_parse_and_failure_keeps_old_data():
    s = make_sessionmaker("sqlite://")()
    assert sync_epss(s, client(gzip.compress(CSV.encode()))) == 2
    assert s.get(Epss, "CVE-2024-1").score == 0.5
    for bad in (b"not gzip", gzip.compress(b"#m\ncve,epss,percentile\n"), gzip.compress(b"#m\ncve,epss,percentile\nCVE-3,abc,0.1\n")):
        with pytest.raises((OSError, ValueError)):
            sync_epss(s, client(bad))
    with pytest.raises(httpx.HTTPStatusError):
        sync_epss(s, client(status=500))
    assert count(s, Epss) == 2


def test_nvd_prefers_v31_primary_and_upserts():
    from nimstead.db import Cvss
    from nimstead.feeds import sync_nvd

    def m(score, typ):
        return {"type": typ, "cvssData": {"baseScore": score, "vectorString": f"v{score}"}}

    feed = {"vulnerabilities": [
        {"cve": {"id": "CVE-1", "metrics": {"cvssMetricV31": [m(5.0, "Secondary"), m(7.5, "Primary")], "cvssMetricV40": [m(9.0, "Primary")]}}},
        {"cve": {"id": "CVE-2", "metrics": {"cvssMetricV40": [m(6.1, "Secondary")]}}},
        {"cve": {"id": "CVE-3", "metrics": {}}},
    ]}
    s = make_sessionmaker("sqlite://")()
    assert sync_nvd(s, ["2024"], client(gzip.compress(json.dumps(feed).encode()))) == 2
    assert s.get(Cvss, "CVE-1").score == 7.5 and s.get(Cvss, "CVE-2").score == 6.1
    feed["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"] = [m(9.8, "Primary")]
    sync_nvd(s, ["modified"], client(gzip.compress(json.dumps(feed).encode())))
    assert s.get(Cvss, "CVE-1").score == 9.8 and count(s, Cvss) == 2


def test_osv_only_keeps_releases_in_use():
    s = make_sessionmaker("sqlite://")()
    z = zip_of(rec("USN-1", "2024-01-01", eco="Ubuntu:22.04:LTS"), rec("USN-2", "2024-01-01", eco="Ubuntu:24.04:LTS"))
    sync_osv(s, ["Ubuntu"], client(z), only={"Ubuntu:24.04"})
    assert {a.ecosystem for a in s.scalars(select(Advisory))} == {"Ubuntu:24.04"}
