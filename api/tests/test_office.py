"""Microsoft 365 Apps / Office LTSC by channel (plan T9): MSRC's Office CVEs paired with Microsoft's OfficeReleases
feed (real copy, 2026-10-29), per channel and version line."""

import copy
import json
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select
from test_api import user
from test_msrc_products import client as msrc_client

from nimstead import office
from nimstead.db import Advisory, make_sessionmaker
from nimstead.feeds import sync_msrc, sync_office

FIX = Path(__file__).parent / "fixtures" / "msrc"
FEED = json.loads((FIX / "OfficeReleases-2026-10-29.json").read_text())
MEC = "http://officecdn.microsoft.com/pr/55336b82-a18d-4dd6-b5f6-9e5095c314a6"


def feed_client(feed=None, status=200):
    return httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(status, json=feed if feed is not None else FEED)))


@pytest.fixture
def session():
    s = make_sessionmaker("sqlite://")()
    sync_msrc(s, 60, msrc_client())
    return s


def test_office_cves_are_kept_and_paired_with_each_channel_line(session):
    [cve] = office.stored_cves(session)
    assert cve["cve"] == "CVE-2026-100209" and cve["released"].isoformat() == "2026-10-13" and "MonthlyEnterprise" in cve["channels"]
    assert sync_office(session, feed_client())["rows"] > 0
    rows = {a.package: a.record["affected"][0]["ranges"][0]["events"][-1]["fixed"]
            for a in session.scalars(select(Advisory).where(Advisory.package.like("Microsoft 365 Apps %")))}
    # the first build of each line made available on or after the October security release
    assert rows["Microsoft 365 Apps MonthlyEnterprise 20430"] == "16.0.20430.20180"
    assert rows["Microsoft 365 Apps SemiAnnual 20430"] == "16.0.20430.20178"
    assert not [k for k in rows if "PerpetualVL" in k]  # an M365 Apps CVE says nothing about Office LTSC


@pytest.mark.parametrize("breakage", [
    lambda f: f.clear(),
    lambda f: f[0].pop("channelId"),
    lambda f: f[3]["officeVersions"][0].update(legacyVersion="sixteen"),
    # the MonthlyEnterprise channel suddenly served from Current's GUID: the pinned channel map no longer holds
    lambda f: f[3]["officeVersions"][0].update(cdnBaseUrl="http://officecdn.microsoft.com/pr/492350f6-3a01-4f97-b9c0-c7c6ddf67d60"),
])
def test_a_changed_feed_fails_loudly_and_keeps_stored_rows(session, breakage):
    sync_office(session, feed_client())
    before = session.scalars(select(Advisory.id).where(Advisory.package.like("Microsoft 365 Apps %"))).all()
    bad = copy.deepcopy(FEED)
    breakage(bad)
    assert "error" in sync_office(session, feed_client(bad))
    assert session.scalars(select(Advisory.id).where(Advisory.package.like("Microsoft 365 Apps %"))).all() == before
    assert "error" in sync_office(session, feed_client(status=503))


@pytest.mark.parametrize("build,channel,want", [
    ("16.0.20430.20100", MEC, "Microsoft 365 Apps MonthlyEnterprise 20430"),
    ("16.0.20430.20100", "55336b82-a18d-4dd6-b5f6-9e5095c314a6", "Microsoft 365 Apps MonthlyEnterprise 20430"),
    ("16.0.20430.20100", "http://officecdn.microsoft.com/pr/unknown", None),
    ("15.0.4569.1506", MEC, None),
])
def test_host_key(build, channel, want):
    assert office.host_key(build, channel) == want


def test_click_to_run_host_end_to_end(env):
    with make_sessionmaker(env)() as s:
        sync_msrc(s, 60, msrc_client())
        sync_office(s, feed_client())
    c = user(env)
    token = c.post("/api/enroll-tokens").json()["token"]
    a = c.post("/api/agent/enroll", json={"token": token, "hostname": "pc", "ecosystem": "Windows"}).json()
    h = {"Authorization": f"Bearer {a['agent_key']}"}

    def inv(build):
        return c.post("/api/agent/inventory", headers=h, json={"ecosystem": "Windows", "packages": [
            {"ecosystem": "Microsoft", "name": "Microsoft 365 Apps", "version": build, "source": MEC}]}).json()
    inv("16.0.20430.20120")
    [f] = c.get("/api/findings").json()
    assert f["vuln_id"] == "CVE-2026-100209" and f["package"] == "Microsoft 365 Apps MonthlyEnterprise 20430"
    assert f["fixed_version"] == "16.0.20430.20180"
    assert inv("16.0.20430.20180")["open"] == 0
    assert inv("16.0.20999.20000")["open"] == 0  # a line the feed doesn't list: not judged, never guessed


def test_a_superseded_line_takes_its_fix_from_a_newer_line_of_its_channel(session):
    """SemiAnnual 20131's last build is 2026-09-08: a host on it gets October's fix only by moving to 20228 or later."""
    sync_office(session, feed_client())
    rows = {a.package: a.record["affected"][0]["ranges"][0]["events"] for a in session.scalars(select(Advisory).where(Advisory.package.like("Microsoft 365 Apps %")))}
    assert rows["Microsoft 365 Apps SemiAnnual 20131"] == [{"introduced": "16.0.20131.0"}, {"fixed": "16.0.20228.20274"}]
    assert "Microsoft 365 Apps MonthlyEnterprise 20131" not in rows  # a line the channel doesn't list has no CVE rows


def test_a_line_older_than_its_channel_still_lists_is_end_of_support(env):
    with make_sessionmaker(env)() as s:
        sync_msrc(s, 60, msrc_client())
        sync_office(s, feed_client())
    c = user(env)
    token = c.post("/api/enroll-tokens").json()["token"]
    a = c.post("/api/agent/enroll", json={"token": token, "hostname": "pc", "ecosystem": "Windows"}).json()
    h = {"Authorization": f"Bearer {a['agent_key']}"}

    def inv(build):
        c.post("/api/agent/inventory", headers=h, json={"ecosystem": "Windows", "packages": [
            {"ecosystem": "Microsoft", "name": "Microsoft 365 Apps", "version": build, "source": MEC}]})
        return [f["vuln_id"] for f in c.get("/api/findings").json() if f["status"] == "open"]
    assert inv("16.0.17928.20114") == ["EOL:m365-MonthlyEnterprise-17928"]  # two years behind on a channel listing 20228 onwards
    assert inv("16.0.20228.20276") == []
