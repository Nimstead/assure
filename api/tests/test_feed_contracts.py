"""Behavioral checks for documented feed boundaries and application mapping limits."""

import copy
import gzip
import importlib.util
import io
import json
import zipfile
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select

from nimstead import feeds, winapps
from nimstead.db import Advisory, Cvss, Org, make_sessionmaker
from nimstead.winapps_evidence import EVIDENCE

ROOT = Path(__file__).resolve().parents[2]
V5_PATH = Path(__file__).parent / "fixtures/cvelist/CVE-2025-6554.json"


def test_osv_later_parse_failure_keeps_prior_batch_and_unrelated_commit():
    factory = make_sessionmaker("sqlite://")
    record = {"id": "DOC-1", "modified": "1", "affected": [
        {"package": {"ecosystem": "PyPI", "name": "example"}, "ranges": []}]}
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("first.json", json.dumps(record))
        z.writestr("broken.json", "{")
    with factory() as session, httpx.Client(transport=httpx.MockTransport(
            lambda r: httpx.Response(200, content=archive.getvalue()))) as client:
        session.add(Org(id="doc-org", name="Pending before sync"))
        with pytest.raises(json.JSONDecodeError):
            feeds.sync_osv(session, ["PyPI"], client, batch=1)
        session.rollback()
    with factory() as session:
        assert session.get(Advisory, ("DOC-1", "PyPI", "example")) is not None
        assert session.get(Org, "doc-org") is not None


def test_nvd_unscored_cve_keeps_existing_score():
    with make_sessionmaker("sqlite://")() as session:
        session.add(Cvss(cve="CVE-2026-1234", score=8.0, vector="old"))
        session.commit()
        body = gzip.compress(json.dumps({"vulnerabilities": [{"cve": {
            "id": "CVE-2026-1234", "metrics": {}}}]}).encode())
        with httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=body))) as client:
            assert feeds.sync_nvd(session, ["modified"], client) == 0
        assert session.get(Cvss, "CVE-2026-1234").score == 8.0


def test_rejection_retains_fallback_but_translated_nvd_removes_all_fallback_products():
    v5 = json.loads(V5_PATH.read_text())
    cve = v5["cveMetadata"]["cveId"]
    with make_sessionmaker("sqlite://")() as session:
        assert feeds.cvelist_records(session, [v5]) == 1
        assert feeds.sync_winapps(session, [{"id": cve, "vulnStatus": "Rejected"}]) == 0
        original = session.scalar(select(Advisory))
        assert original.id == cve + "-v5"
        session.add(Advisory(id=original.id, ecosystem="WinApp", package="another:product",
                             modified=original.modified, record=copy.deepcopy(original.record)))
        session.commit()
        nvd = {"id": cve, "configurations": [{"nodes": [{"cpeMatch": [{
            "vulnerable": True, "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
            "versionEndExcluding": "138.0.7204.96"}]}]}]}
        assert feeds.sync_winapps(session, [nvd]) == 1
        assert [(a.id, a.package) for a in session.scalars(select(Advisory))] == [(cve, "google:chrome")]


def test_v5_platform_filter_is_substring_search_and_result_fields_match_reference():
    v5 = json.loads(V5_PATH.read_text())
    affected = v5["containers"]["cna"]["affected"][0]
    affected["platforms"] = ["small appliance"]  # contains the filter's unanchored "all"
    [(key, record)] = winapps.advisories_v5(v5)
    assert key == "google:chrome"
    reference = (ROOT / "docs/reference/windows-apps.md").read_text()
    assert set(record) == {"id", "aliases", "modified", "summary", "severity", "affected"}
    assert all(f"`{field}`" in reference for field in record)
    assert winapps.names_product("Google Chrome", None)
    assert winapps.identify("Google Chrome", None, "unreadable") is None


def test_historical_evidence_mapping_matches_current_run_files():
    spec = importlib.util.spec_from_file_location("doc_winapps_evidence", ROOT / "sandbox/winapps_evidence.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    derived = {key: (label, tuple(files)) for key, (label, files) in module.derive().items()}
    assert derived == EVIDENCE
