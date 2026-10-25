import json
from pathlib import Path

import pytest

from nimstead.match import Package, canonical_id, match_package

FIXTURES = sorted((Path(__file__).parent / "fixtures" / "osv").glob("*.json"))


def _cases():
    for f in FIXTURES:
        d = json.loads(f.read_text())
        for version, want in d["oracle"].items():
            yield pytest.param(d, version, want, id=f"{d['ecosystem']}/{d['name']}@{version}")


@pytest.mark.parametrize("d,version,want", list(_cases()))
def test_agrees_with_osv_oracle(d, version, want):
    matches = match_package(Package(d["name"], version), d["ecosystem"], d["records"])
    got = sorted(a for m in matches for a in m.advisory_ids)
    assert got == want


def test_backport_not_flagged():
    rec = {"id": "DSA-1", "aliases": ["CVE-2024-1"], "affected": [{
        "package": {"ecosystem": "Debian:12", "name": "openssl"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.11-1~deb12u2"}]}]}]}
    # upstream 3.0.11 is "older" than many upstream fixes, but Debian backported: no finding
    assert match_package(Package("libssl3", "3.0.11-1~deb12u2", "openssl"), "Debian:12", [rec]) == []
    m = match_package(Package("libssl3", "3.0.11-1~deb12u1", "openssl"), "Debian:12", [rec])
    assert [(x.vuln_id, x.fixed) for x in m] == [("CVE-2024-1", "3.0.11-1~deb12u2")]


def test_duplicates_collapse_and_withdrawn_ignored():
    aff = [{"package": {"ecosystem": "PyPI", "name": "requests"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.32.0"}]}]}]
    recs = [
        {"id": "GHSA-x", "aliases": ["CVE-2024-35195"], "affected": aff},
        {"id": "PYSEC-y", "aliases": ["CVE-2024-35195"], "affected": aff},
        {"id": "GHSA-z", "withdrawn": "2024-01-01T00:00:00Z", "affected": aff},
    ]
    m = match_package(Package("requests", "2.31.0"), "PyPI", recs)
    assert len(m) == 1 and sorted(m[0].advisory_ids) == ["GHSA-x", "PYSEC-y"]


def test_wrong_ecosystem_release_ignored():
    rec = {"id": "A", "affected": [{"package": {"ecosystem": "Debian:11", "name": "openssl"},
                                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]}
    assert match_package(Package("openssl", "1.0"), "Debian:12", [rec]) == []


def test_last_affected_and_unsupported():
    rec = {"id": "B", "affected": [{"package": {"ecosystem": "npm", "name": "x"},
                                    "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"last_affected": "1.2.0"}]}]}]}
    assert len(match_package(Package("x", "1.2.0"), "npm", [rec])) == 1
    assert match_package(Package("x", "1.2.1"), "npm", [rec]) == []
    assert match_package(Package("x", "0.9.0"), "npm", [rec]) == []
    assert match_package(Package("x", "1.0"), "Maven", [rec]) == []


def test_canonical_id_prefers_cve():
    assert canonical_id({"id": "UBUNTU-CVE-2023-1", "upstream": ["CVE-2023-1"]}) == "CVE-2023-1"
    assert canonical_id({"id": "GHSA-abc"}) == "GHSA-abc"
