"""The engine on software outside the OS package manager (spec R7.9): SBOM components and the agent's opt-in language-package scans."""

from sqlalchemy import select
from test_api import user
from test_engine import one
from test_sbom import LOG4J, app_asset, bom, comp, maven_env, put  # noqa: F401 - maven_env: the real log4j-core OSV records

from nimstead import engine
from nimstead.db import Asset, Finding, InstalledPackage, make_sessionmaker
from nimstead.engine import parity, report
from nimstead.engine.collection import Inventory
from nimstead.engine.content import Content
from nimstead.engine.evaluate import evaluate
from nimstead.engine.model import Grade, Outcome


def ghsa(gid, eco, name, fixed, cve=None, introduced="0"):
    return {"id": gid, "aliases": [cve] if cve else [], "modified": "2026-10-01T00:00:00Z", "summary": f"Flaw in {name}",
            "affected": [{"package": {"ecosystem": eco, "name": name}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": introduced}, {"fixed": fixed}]}]}]}


REQUESTS = ghsa("GHSA-x84v-xcm2-53pg", "PyPI", "requests", "2.20.0", "CVE-2018-18074")


def sbom_inv(*pkgs, skipped=None):
    return Inventory(hostname="billing", kind="application", received=False, packages=[{**p, "origin": "sbom"} for p in pkgs],
                     sbom={"received": "2026-11-03T09:00:00", "components": len(pkgs) + sum((skipped or {}).values()), "mapped": len(pkgs),
                           "skipped": skipped or {"no_purl": 0, "unsupported_or_invalid_purl": 0}})


def pypi(name, version, **kw):
    return {"ecosystem": "PyPI", "name": name, "version": version, "source": None, **kw}


# ---- 1. SBOM components (R4.4: what it can't name is counted, never clean)

def test_an_sbom_component_is_judged_unverified_and_says_an_sbom_is_not_whats_running():
    c = Content.make({("PyPI", "requests"): [REQUESTS], ("PyPI", "idna"): []}, feeds={"PyPI"})
    inv = sbom_inv(pypi("requests", "2.19.1"), pypi("idna", "3.7"), skipped={"no_purl": 2, "unsupported_or_invalid_purl": 1})
    vs = evaluate(inv, c)
    v = one(vs, vuln_id="CVE-2018-18074")
    assert (v.outcome, v.grade, v.family, v.fixed, v.source) == (Outcome.VULNERABLE, Grade.UNVERIFIED, "application", "2.20.0", "GitHub Advisory Database")
    assert "what was built, not what's running" in v.detail and v.observed == "2.19.1 (SBOM component, received 2026-11-03)"
    assert not [x for x in vs if x.product == "idna"]  # no advisory: not a check, and counted below
    assert {(x.check, x.outcome, x.instance) for x in vs if x.reason == "sbom-unmapped"} == {
        ("product:sbom-no_purl", Outcome.NOT_RUN, "2 components"), ("product:sbom-unsupported_or_invalid_purl", Outcome.NOT_RUN, "1 components")}
    r = report.build(inv, c, vs)
    said = " ".join(r["coverage"]["statements"])
    assert "what was built, not what's running" in said and "3 of its 5 components weren't assessed" in said and "1 of 2 installs" in said
    assert r["coverage"]["sources"] == [{"name": "sbom", "label": "SBOM", "state": "ok", "count": 2, "error": None}]
    text = report.render(r)
    assert "Application, from its SBOM (no agent)" in text and "requests 2.19.1   how sure: unverified" in text


def test_an_sbom_at_the_fix_is_not_vulnerable_and_still_unverified():
    c = Content.make({("PyPI", "requests"): [REQUESTS]}, feeds={"PyPI"})
    v = one(evaluate(sbom_inv(pypi("requests", "2.31.0")), c), vuln_id="CVE-2018-18074")
    assert (v.outcome, v.grade) == (Outcome.NOT_VULNERABLE, Grade.UNVERIFIED)
    assert report.build(sbom_inv(pypi("requests", "2.31.0")), c, [v])["headline"]["status"] == "no-known-vulnerabilities"


def test_a_component_whose_ecosystem_has_no_feed_is_not_run_and_an_application_with_no_sbom_is_not_assessed():
    v = one(evaluate(sbom_inv({"ecosystem": "NuGet", "name": "Newtonsoft.Json", "version": "12.0.1", "source": None}), Content.make({}, feeds=set())),
            product="Newtonsoft.Json")
    assert (v.outcome, v.reason) == (Outcome.NOT_RUN, "feed-missing")
    empty = Inventory(hostname="billing", kind="application", received=False)
    vs = evaluate(empty, Content.make({}))
    assert [(x.outcome, x.reason) for x in vs] == [(Outcome.NOT_RUN, "no-sbom")]
    assert report.build(empty, Content.make({}), vs)["headline"]["status"] == "not-assessed"


def test_sbom_upload_through_the_api_has_parity_with_rescan(maven_env):  # noqa: F811
    c = user(maven_env)
    a = app_asset(c)
    assert put(c, a["id"], bom(comp(LOG4J), comp("pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"), comp("pkg:deb/debian/x@1"),
                               {"type": "file", "name": "no-purl"})).status_code == 200
    r = c.get(f"/api/assets/{a['id']}/scan-report").json()
    assert r["headline"]["status"] == "vulnerable" and r["kind"] == "application"
    g = {x["instance"]: x for x in r["vulnerable"]}["org.apache.logging.log4j:log4j-core 2.14.1"]  # T19: each version its own install
    assert g["grade"] == "unverified" and "CVE-2021-44228" in [x["id"] for x in g["vulnerabilities"]]
    assert any(x["instance"] == "org.apache.logging.log4j:log4j-core 2.17.1" for x in r["not_vulnerable"])
    assert {x["reason"] for x in r["undetermined"]} >= {"sbom-unmapped"}
    s = make_sessionmaker(maven_env)()
    asset = s.get(Asset, a["id"])
    inv = Inventory.from_asset(asset, s.scalars(select(InstalledPackage).where(InstalledPackage.asset_id == asset.id)).all(), engine.sbom_received(s, asset))
    verdicts, _ = engine.scan_inventory(s, inv, engine.prior_findings(s, asset))
    found = [(f.ecosystem, f.package, f.vuln_id) for f in s.scalars(select(Finding).where(Finding.asset_id == asset.id, Finding.status == "open"))]
    p = parity.compare(verdicts, found)
    assert found and p["ok"] and p["agree"] == len(found) and not p["outside_this_slice"], p
