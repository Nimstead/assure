"""Container image SBOMs (tasks/plan-containers.md C9-C10, DECISIONS 142): OS package URLs map to the distribution release and
source package the agent itself would read, and an application with a distribution is judged as that release's packages.

The fixtures are real Syft 1.57.2 and Trivy 0.76.2 output (CycloneDX and SPDX) for debian:11, alpine:3.18 and almalinux:9,
trimmed to the fields the parser reads, taken the same day as each image's own dpkg-query, apk and rpm answers."""

import importlib.util
import json
from pathlib import Path

import pytest
from sqlalchemy import select
from test_api import user

from nimstead import sbom
from nimstead.db import Advisory, Finding, make_sessionmaker

FIX = Path(__file__).parent / "fixtures" / "containers"
spec = importlib.util.spec_from_file_location("nimstead_agent", Path(__file__).parents[2] / "agent" / "nimstead_agent.py")
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


def agent_rows(eco, pkgs):
    """The agent's own reading of the same image, as sbom.parse's rows."""
    return sorted((eco, p["name"], p["version"], p["source"], p.get("source_version")) for p in pkgs)


def os_rows(name):
    rows, counts = sbom.parse(json.loads((FIX / "sbom" / name).read_text(encoding="utf-8")))
    return sorted(r for r in rows if r[3] is not None and r[0] == counts["distro"]), counts


DEBIAN = agent_rows("Debian:11", agent.parse_dpkg((FIX / "debian11-dpkg-query.txt").read_text(encoding="utf-8")))
ALPINE = agent_rows("Alpine:v3.18", agent.parse_apk((FIX / "alpine318-apk-installed").read_text(encoding="utf-8")))
ALMA = agent_rows("AlmaLinux:9", agent.parse_rpm((FIX / "almalinux9-rpm-qa-full.txt").read_text(encoding="utf-8")))


@pytest.mark.parametrize("name,want,n", [
    ("syft-debian_11.cdx.json", DEBIAN, 96), ("syft-debian_11.spdx.json", DEBIAN, 96), ("trivy-debian_11.cdx.json", DEBIAN, 96),
    ("trivy-debian_11.spdx.json", DEBIAN, 96), ("syft-alpine_3.18.cdx.json", ALPINE, 15), ("syft-alpine_3.18.spdx.json", ALPINE, 15),
    ("trivy-alpine_3.18.cdx.json", ALPINE, 15), ("syft-almalinux_9.cdx.json", ALMA, 158), ("syft-almalinux_9.spdx.json", ALMA, 158),
    ("trivy-almalinux_9.cdx.json", ALMA, 158)])
def test_every_tool_and_format_gives_the_rows_the_agent_reads_from_the_same_image(name, want, n):
    got, counts = os_rows(name)
    assert len(want) == n and got == want  # name, version (epoch as the agent writes it), source and source version, row for row
    assert counts["distro"] == want[0][0] and not counts["skipped"].get("other_distro")


def test_the_awkward_rows_specifically():
    deb = {r[1]: r for r in os_rows("trivy-debian_11.cdx.json")[0]}
    assert deb["bsdutils"] == ("Debian:11", "bsdutils", "1:2.36.1-8+deb11u2", "util-linux", "2.36.1-8+deb11u2")  # epoch from the qualifier
    assert deb["libssl1.1"][3:] == ("openssl", None)  # source name only: the same version
    alma = {r[1]: r for r in os_rows("syft-almalinux_9.cdx.json")[0]}
    assert alma["openssl-libs"] == ("AlmaLinux:9", "openssl-libs", "1:3.5.9-1.el9_9", "openssl", None)
    assert alma["bash"][2] == "0:5.1.8-9.el9"  # rpm always carries its epoch, as `rpm -qa %{EPOCHNUM}` does


@pytest.mark.parametrize("ptype,ns,distro,want", [
    ("deb", "debian", "debian-12.8", "Debian:12"), ("deb", "ubuntu", "ubuntu-24.04", "Ubuntu:24.04"), ("apk", "alpine", "3.18.12", "Alpine:v3.18"),
    ("apk", "alpine", "alpine-3.21.0", "Alpine:v3.21"), ("rpm", "alma", "alma-9.9", "AlmaLinux:9"), ("rpm", "almalinux", "almalinux-9.9", "AlmaLinux:9"),
    ("rpm", "rocky", "rocky-9.3", "Rocky Linux:9"), ("rpm", "opensuse", "opensuse.leap-15.6", "openSUSE:Leap 15.6"),
    ("rpm", "opensuse", "opensuse-leap-15.6", "openSUSE:Leap 15.6"), ("rpm", "suse", "sles-15.5", "SUSE:Linux Enterprise Server 15 SP5"),
    ("deb", "debian", "alpine-3.18", None), ("rpm", "redhat", "rhel-9.3", None), ("deb", "ubuntu", "ubuntu-24", None), ("apk", "alpine", "edge", None),
    ("deb", "debian", "", None)])
def test_distribution_releases_map_as_the_agent_maps_os_release(ptype, ns, distro, want):
    assert sbom.distro_ecosystem(ptype, ns, distro) == want


def comp(purl, **props):
    return {"type": "library", "purl": purl, **({"properties": [{"name": k, "value": v} for k, v in props.items()]} if props else {})}


def bom(*components):
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": list(components)}


def test_one_sbom_is_one_image_and_what_doesnt_map_is_counted():
    rows, counts = sbom.parse(bom(
        comp("pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12.4&upstream=openssl"),
        comp("pkg:deb/debian/openssl@3.0.11-1~deb12u2?distro=debian-12.4"),
        comp("pkg:apk/alpine/musl@1.2.4-r2?distro=alpine-3.18.4"),  # a second release in one SBOM
        comp("pkg:deb/debian/curl@7.88.1-10"),  # no release named
        comp("pkg:rpm/redhat/bash@5.1.8-6.el9?distro=rhel-9.3"),  # a release no feed here covers
        comp("pkg:deb/debian/$(x)@1?distro=debian-12"), comp("pkg:pypi/requests@2.31.0")))
    assert counts["distro"] == "Debian:12" and [r[1] for r in rows] == ["libssl3", "openssl", "requests"]
    assert counts["skipped"] == {"no_purl": 0, "unsupported_or_invalid_purl": 1, "other_distro": 1, "no_distro": 1, "unsupported_distro": 1}
    assert counts["components"] == 7 and counts["mapped"] == 3
    _, counts = sbom.parse(bom(comp("pkg:deb/debian/openssl@3.0.11-1~deb12u2?distro=debian-12.4"), comp("pkg:npm/a@1.0.0")), os_packages=False)
    assert counts["skipped"]["os_package_on_host"] == 1 and counts["distro"] is None


IMAGE_SBOM = bom(comp("pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12.4&upstream=openssl"),
                 comp("pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64&distro=debian-12.4"),
                 comp("pkg:deb/debian/base-files@12.4+deb12u5?arch=amd64&distro=debian-12.4"),
                 comp("pkg:pypi/requests@2.31.0"))


def app(c):
    a = c.post("/api/assets", json={"name": "billing-image", "criticality": "high"}).json()
    return a["id"], {"Authorization": f"Bearer {a['upload_token']}"}


def upload(c, aid, h, doc):
    r = c.post(f"/api/assets/{aid}/sbom", headers=h, content=json.dumps(doc).encode())
    assert r.status_code == 200, r.text
    return r.json()


def test_an_image_sbom_is_judged_as_its_release_at_sbom_grade_and_closes_on_a_new_one(env):
    s = make_sessionmaker(env)()
    s.add(Advisory(id="debian", ecosystem="EOL", package="debian", record={"cycles": {"12": "2028-06-30", "11": "2026-08-31"}}))
    s.commit()
    c = user(env)
    aid, h = app(c)
    out = upload(c, aid, h, IMAGE_SBOM)
    assert out["distro"] == "Debian:12" and out["unique_packages"] == 4
    found = {f["vuln_id"]: f for f in c.get("/api/findings", params={"asset_id": aid}).json()}
    openssl = [f for f in found.values() if f["package"] == "openssl"]
    assert openssl and all(f["ecosystem"] == "Debian:12" and f["asset_kind"] == "application" and not f["plannable"] for f in openssl)
    assert any(f["package"] == "requests" for f in found.values())  # its language components are still judged
    report = c.get(f"/api/assets/{aid}/scan-report").json()
    ssl = next(g for g in report["vulnerable"] if g["product"] == "openssl")
    assert ssl["grade"] == "unverified" and "An SBOM states what was built" in ssl["raise_confidence"] and ssl["observed"].startswith("3.0.11-1~deb12u2 (SBOM components")
    assert report["coverage"]["families"]["distro"]["attempted"] > 0
    assert c.post("/api/remediation/jobs", json={"asset_id": aid, "ecosystem": "Debian:12", "package": "openssl"}).status_code == 409
    # the image is rebuilt without the vulnerable openssl: its findings close on that evidence (removed, the SBOM read whole)
    upload(c, aid, h, bom(comp("pkg:deb/debian/base-files@12.4+deb12u5?arch=amd64&distro=debian-12.4")))
    s = make_sessionmaker(env)()
    assert not s.scalars(select(Finding).where(Finding.asset_id == aid, Finding.package == "openssl", Finding.status == "open")).all()


def test_an_end_of_life_base_image_opens_its_finding(env):
    s = make_sessionmaker(env)()
    s.add(Advisory(id="debian", ecosystem="EOL", package="debian", record={"cycles": {"11": "2026-08-31"}}))
    s.commit()
    c = user(env)
    aid, h = app(c)
    upload(c, aid, h, json.loads((FIX / "sbom" / "syft-debian_11.cdx.json").read_text(encoding="utf-8")))
    vulns = {f["vuln_id"] for f in c.get("/api/findings", params={"asset_id": aid}).json()}
    assert "EOL:debian-11" in vulns
    eol = next(g for g in c.get(f"/api/assets/{aid}/scan-report").json()["vulnerable"] if g["product"] == "debian 11")
    assert eol["grade"] == "unverified" and "An SBOM states what was built" in eol["raise_confidence"]  # the base OS is the SBOM's word too


def test_a_hosts_sbom_never_adds_os_packages_or_says_they_went_unjudged(env):
    c = user(env)
    token = c.post("/api/enroll-tokens").json()["token"]
    a = c.post("/api/agent/enroll", json={"token": token, "hostname": "vm-1", "ecosystem": "Debian:12"}).json()
    h = {"Authorization": f"Bearer {a['agent_key']}"}
    out = upload(c, a["asset_id"], h, IMAGE_SBOM)
    assert out["skipped"]["os_package_on_host"] == 3 and out["distro"] is None
    report = c.get(f"/api/assets/{a['asset_id']}/scan-report").json()
    assert not any("os_package_on_host" in json.dumps(g) or "which this host's agent reads" in json.dumps(g) for g in report["undetermined"])
