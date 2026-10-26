import hashlib
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker
from test_api import INV, enrol, user

from nimstead import feeds, sbom
from nimstead.app import create_app
from nimstead.db import Advisory, Asset, InstalledPackage, LedgerEntry, Org, make_engine
from nimstead.match import normalize_ecosystem

FIX = Path(__file__).parent / "fixtures" / "osv"
LOG4J = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"


def bom(*components, spec="1.5"):
    return {"bomFormat": "CycloneDX", "specVersion": spec, "components": list(components)}


def comp(purl, **kw):
    return {"type": "library", "name": "x", "purl": purl, **kw}


@pytest.fixture
def maven_env(env):
    s = sessionmaker(make_engine(env))()
    d = json.loads((FIX / "Maven__org.apache.logging.log4j_log4j-core.json").read_text())
    for r in d["records"]:
        s.merge(Advisory(id=r["id"], ecosystem="Maven", package=d["name"], record=r))
    s.commit()
    return env


def app_asset(c, **kw):
    r = c.post("/api/assets", json={"name": "billing-service", **kw})
    assert r.status_code == 201, r.text
    return r.json()


def put(c, asset_id, doc, **kw):
    return c.post(f"/api/assets/{asset_id}/sbom", content=json.dumps(doc) if isinstance(doc, dict) else doc, **kw)


PURLS = [
    ("pkg:pypi/Django@4.2.1", ("PyPI", "django", "4.2.1")),
    ("pkg:pypi/typing_extensions@4.9.0", ("PyPI", "typing-extensions", "4.9.0")),
    ("pkg:npm/lodash@4.17.21", ("npm", "lodash", "4.17.21")),
    ("pkg:npm/%40angular/core@16.0.0", ("npm", "@angular/core", "16.0.0")),
    (LOG4J + "?type=jar", ("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1")),
    ("pkg:nuget/Newtonsoft.Json@13.0.1", ("NuGet", "Newtonsoft.Json", "13.0.1")),
    ("pkg:gem/rack@2.2.8", ("RubyGems", "rack", "2.2.8")),
    ("pkg:golang/github.com/gin-gonic/gin@v1.9.0", ("Go", "github.com/gin-gonic/gin", "1.9.0")),
    ("pkg:cargo/serde@1.0.190#sub", ("crates.io", "serde", "1.0.190")),
    ("pkg:deb/debian/openssl@3.0.11", None),  # OS packages come from the agent
    ("pkg:maven/onlyname@1.0", None),
    ("pkg:npm/lodash", None),  # no version: never guess
    ("not-a-purl", None),
]


@pytest.mark.parametrize("purl,want", PURLS)
def test_purl_mapping(purl, want):
    assert sbom.parse_purl(purl) == want


def test_nested_components_and_counts():
    doc = bom(
        comp("pkg:npm/a@1.0.0", components=[comp("pkg:npm/b@2.0.0", components=[comp("pkg:gem/rack@2.2.8")])]),
        comp("pkg:npm/a@1.0.0"),  # duplicate collapses
        comp("pkg:deb/debian/curl@7"), {"type": "file", "name": "no-purl"},
    )
    pkgs, counts = sbom.parse(doc)
    assert pkgs == [("RubyGems", "rack", "2.2.8"), ("npm", "a", "1.0.0"), ("npm", "b", "2.0.0")]
    assert counts == {"components": 6, "mapped": 4, "unique_packages": 3, "skipped": {"no_purl": 1, "unsupported_or_invalid_purl": 1}}


def test_log4shell_found_then_resolved_and_ledger(maven_env):
    c = user(maven_env)
    a = app_asset(c, criticality="high", internet_facing=True)
    assert a["kind"] == "application" and a["upload_token"].startswith("nmu_")
    doc = json.dumps(bom(comp(LOG4J), comp("pkg:pypi/requests@2.31.0"), comp("pkg:deb/debian/x@1"))).encode()
    r = put(c, a["id"], doc)
    assert r.status_code == 200, r.text
    assert r.json()["components"] == 3 and r.json()["mapped"] == 2 and r.json()["open"] >= 1
    ids = {f["vuln_id"]: f for f in c.get("/api/findings", params={"asset_id": a["id"]}).json()}
    assert "CVE-2021-44228" in ids and ids["CVE-2021-44228"]["package"] == "org.apache.logging.log4j:log4j-core"
    assert ids["CVE-2021-44228"]["fixed_version"] == "2.15.0"

    s = sessionmaker(make_engine(maven_env))()
    e = s.scalars(select(LedgerEntry).where(LedgerEntry.kind == "sbom_received")).one()
    assert e.data["sha256"] == hashlib.sha256(doc).hexdigest() and e.data["mapped"] == 2 and e.data["components"] == 3

    # a fixed version in the next upload resolves it
    assert put(c, a["id"], bom(comp("pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"))).status_code == 200
    assert not [f for f in c.get("/api/findings", params={"asset_id": a["id"]}).json() if f["vuln_id"] == "CVE-2021-44228"]
    assert any(f["vuln_id"] == "CVE-2021-44228" for f in c.get("/api/findings", params={"status": "resolved"}).json())


def test_replace_semantics_sbom_and_agent_inventory_are_independent(env):
    c = user(env)
    agent = enrol(c)
    h = {"Authorization": f"Bearer {agent['agent_key']}"}
    s = sessionmaker(make_engine(env))()

    def rows(origin):
        return sorted((p.ecosystem, p.name) for p in s.scalars(select(InstalledPackage).where(InstalledPackage.origin == origin)))
    s.close()

    assert c.post("/api/agent/inventory", json=INV, headers=h).status_code == 200
    os_pkgs = rows("agent")
    assert len(os_pkgs) == 3
    put(c, agent["asset_id"], bom(comp("pkg:npm/a@1.0.0"), comp("pkg:npm/b@1.0.0")))  # host asset with a cookie
    assert rows("sbom") == [("npm", "a"), ("npm", "b")] and rows("agent") == os_pkgs
    put(c, agent["asset_id"], bom(comp("pkg:npm/c@1.0.0")))  # replaces only SBOM rows
    assert rows("sbom") == [("npm", "c")] and rows("agent") == os_pkgs
    assert c.post("/api/agent/inventory", json=INV, headers=h).status_code == 200  # agent report keeps SBOM rows
    assert rows("sbom") == [("npm", "c")] and rows("agent") == os_pkgs
    put(c, agent["asset_id"], bom(), headers=h)  # the host's own agent key may upload too, and an empty SBOM clears
    assert rows("sbom") == [] and rows("agent") == os_pkgs


def test_auth_and_tenant_isolation(maven_env):
    a_client, b_client = user(maven_env, "a@example.com"), user(maven_env, "b@example.com")
    a = app_asset(a_client)
    doc = bom(comp(LOG4J))
    assert put(b_client, a["id"], doc).status_code == 404  # other org's asset
    assert put(TestClient(create_app(maven_env)), a["id"], doc).status_code == 401  # no credentials
    b_asset = app_asset(b_client)
    tok = {"Authorization": f"Bearer {a['upload_token']}"}
    anon = TestClient(create_app(maven_env))
    assert put(anon, b_asset["id"], doc, headers=tok).status_code == 401  # A's token on B's asset
    assert put(anon, a["id"], doc, headers={"Authorization": "Bearer nmu_wrong"}).status_code == 401
    assert put(anon, a["id"], doc, headers=tok).status_code == 200  # CI upload with the token
    assert b_client.get("/api/findings").json() == []
    # an upload token is not an agent key
    assert anon.post("/api/agent/inventory", json=INV, headers=tok).status_code == 401
    assert anon.get("/api/agent/jobs", headers=tok).status_code == 401
    assert [x["kind"] for x in a_client.get("/api/assets").json()] == ["application"]


@pytest.mark.parametrize("body,code", [
    (b"{not json", 422),
    (b"\xff\xfe", 422),
    (b"[]", 422),
    (json.dumps({"bomFormat": "SPDX"}).encode(), 422),
    (json.dumps(bom(spec="1.3")).encode(), 422),
    (json.dumps({**bom(), "components": "nope"}).encode(), 422),
    (json.dumps(bom(["x"])).encode(), 422),
    pytest.param(b"[" * 100_000, 422, id="deep-json"),  # parser recursion limit
])
def test_invalid_documents_rejected(env, body, code):
    c = user(env)
    a = app_asset(c)
    assert put(c, a["id"], body).status_code == code


def test_deeply_nested_components_rejected(env):
    c = user(env)
    a = app_asset(c)
    node: dict = comp("pkg:npm/x@1.0.0")
    for _ in range(200):
        node = comp("pkg:npm/x@1.0.0", components=[node])
    assert put(c, a["id"], bom(node)).status_code == 422


def test_oversized_body_413(env):
    c = user(env)
    a = app_asset(c)
    big = b" " * (10 * 1024 * 1024 + 1)
    assert put(c, a["id"], big).status_code == 413
    assert put(c, a["id"], (x for x in (big[:6_000_000], big[6_000_000:]))).status_code == 413  # chunked: no content-length


def test_osv_sync_follows_sbom_ecosystems(env, monkeypatch):
    s = sessionmaker(make_engine(env))()
    org = Org(name="o")
    s.add(org)
    s.flush()
    a = Asset(org_id=org.id, hostname="app", kind="application", agent_key_hash="h")
    s.add(a)
    s.flush()
    s.add_all([InstalledPackage(asset_id=a.id, origin="sbom", ecosystem="PyPI", name="x", version="1"),
               InstalledPackage(asset_id=a.id, origin="sbom", ecosystem="Maven", name="g:a", version="1"),
               InstalledPackage(asset_id=a.id, origin="agent", ecosystem="Ubuntu:22.04:LTS", name="curl", version="1")])
    s.commit()
    seen = {}
    monkeypatch.setattr(feeds, "sync_kev", lambda *a, **k: 0)
    monkeypatch.setattr(feeds, "sync_epss", lambda *a, **k: 0)
    monkeypatch.setattr(feeds, "sync_nvd", lambda *a, **k: {})
    monkeypatch.setattr(feeds, "sync_osv", lambda sess, ecos, client=None, only=None: seen.update(ecos=ecos, only=only) or {})
    feeds.update_all(s)
    assert seen["ecos"] == ["Maven", "PyPI", "Ubuntu"]
    assert seen["only"] == {"PyPI", "Maven", "Ubuntu:22.04"}  # no release suffix for language ecosystems


def test_osv_sync_only_filter_keeps_language_ecosystem(monkeypatch):
    from test_feeds import client, count, rec, zip_of
    s = sessionmaker(make_engine("sqlite://"))()
    r = rec("GHSA-1", "2024-01-01", eco="PyPI", pkg="requests")
    assert feeds.sync_osv(s, ["PyPI"], client(zip_of(r)), only={"PyPI"}) == {"inserted": 2, "updated": 0, "skipped": 0}
    assert count(s, Advisory) == 2 and s.get(Advisory, ("GHSA-1", normalize_ecosystem("PyPI"), "requests"))


# --- SPDX JSON 2.2/2.3 ---------------------------------------------------------

def spdx(*pkgs, version="SPDX-2.3"):
    return {"spdxVersion": version, "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": "app", "packages": list(pkgs)}


def spkg(name, purl=None, version=None, ref_type="purl"):
    p = {"SPDXID": f"SPDXRef-{name}", "name": name, "downloadLocation": "NOASSERTION"}
    if version:
        p["versionInfo"] = version
    if purl:
        p["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": ref_type, "referenceLocator": purl}]
    return p


def test_spdx_parse_counts_and_skips():
    doc = spdx(
        spkg("app"),  # the root package has no purl
        spkg("log4j-core", LOG4J, "2.14.1"),
        spkg("lodash", "pkg:npm/lodash", "4.17.21"),  # purl without a version takes versionInfo
        spkg("laravel", "pkg:composer/laravel/framework@10.48.29"),
        spkg("deb", "pkg:deb/debian/curl@7", "7"),
        spkg("cpe", "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*", ref_type="cpe23Type"),  # other ref types are not purls
        spkg("log4j-core-again", LOG4J, "2.14.1"),
        version="SPDX-2.2",
    )
    pkgs, counts = sbom.parse(doc)
    assert pkgs == [("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1"), ("Packagist", "laravel/framework", "10.48.29"),
                    ("npm", "lodash", "4.17.21")]
    assert counts == {"components": 7, "mapped": 4, "unique_packages": 3, "skipped": {"no_purl": 2, "unsupported_or_invalid_purl": 1}}


def test_spdx_log4shell_end_to_end(maven_env):
    c = user(maven_env)
    a = app_asset(c)
    r = put(c, a["id"], spdx(spkg("app"), spkg("log4j-core", LOG4J, "2.14.1")))
    assert r.status_code == 200, r.text
    assert (r.json()["components"], r.json()["mapped"], r.json()["skipped"]["no_purl"]) == (2, 1, 1)
    assert "CVE-2021-44228" in {f["vuln_id"] for f in c.get("/api/findings", params={"asset_id": a["id"]}).json()}


def test_spdx_cap(monkeypatch):
    monkeypatch.setattr(sbom, "MAX_COMPONENTS", 2)
    with pytest.raises(sbom.SbomError):
        sbom.parse(spdx(spkg("a"), spkg("b"), spkg("c")))


@pytest.mark.parametrize("purl,want", [
    ("pkg:composer/laravel/framework@10.0.0", ("Packagist", "laravel/framework", "10.0.0")),
    ("pkg:hex/plug@1.14.0", ("Hex", "plug", "1.14.0")), ("pkg:hex/org/plug@1.14.0", None), ("pkg:pub/http@1.2.0", ("Pub", "http", "1.2.0")),
])
def test_php_hex_pub_purls(purl, want):
    assert sbom.parse_purl(purl) == want


@pytest.mark.parametrize("body,msg", [
    (b"SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0\n", "tag-value"),
    (b'<?xml version="1.0"?><Document/>', "XML"),
    (b"<bom xmlns='http://cyclonedx.org/schema/bom/1.5'/>", "XML"),
    (b"{nope", "not valid JSON"),
    (json.dumps(spdx(version="SPDX-2.1")).encode(), "SPDX-2.2"),
    (json.dumps({**spdx(), "packages": "x"}).encode(), "packages"),
    (json.dumps(spdx("x")).encode(), "not an object"),
])
def test_unsupported_formats_422_with_message(env, body, msg):
    c = user(env)
    r = put(c, app_asset(c)["id"], body)
    assert r.status_code == 422 and msg in r.json()["detail"]
