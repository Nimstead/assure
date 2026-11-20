"""Container images the org's hosts run (tasks/plan-containers.md C4-C6, DECISIONS 139-141): one content-addressed asset per
image, judged by the engine like a host, running where the hosts' complete lists say, closed only on that evidence."""

from datetime import datetime, timedelta

import pytest
from sqlalchemy import select
from test_api import user

from nimstead import containers
from nimstead.db import Advisory, Asset, Container, Finding, LedgerEntry, make_sessionmaker, now
from nimstead.scan import rescan

IMG = "sha256:" + "ab" * 32
OTHER = "sha256:" + "cd" * 32
OPENSSL = [{"name": "libssl3", "version": "3.0.11-1~deb12u2", "source": "openssl"},
           {"name": "openssl", "version": "3.0.11-1~deb12u2", "source": "openssl"},
           {"name": "base-files", "version": "12.4+deb12u5", "source": "base-files"}]


def cid(n: int) -> str:
    return f"{n:064x}"


def doc(n):
    return {"v": 1, "sources": {"os_release": {"state": "ok", "count": 1}, "package_db": {"state": "ok", "count": n}}}


def entry(image_id=IMG, packages=OPENSSL, ctrs=((1, "web"),), ref="nginx:1.25", runtime="docker", eco="Debian:12"):
    return {"image_id": image_id, "ref": ref, "os_name": "Debian GNU/Linux 12 (bookworm)", "ecosystem": eco,
            "facts": {"os_id": "debian", "os_version_id": "12"}, "collection": doc(len(packages)), "packages": list(packages),
            "containers": [{"id": cid(n), "name": name, "runtime": runtime} for n, name in ctrs]}


def host(c, name, eco="Debian:12"):
    token = c.post("/api/enroll-tokens").json()["token"]
    a = c.post("/api/agent/enroll", json={"token": token, "hostname": name, "ecosystem": eco}).json()
    h = {"Authorization": f"Bearer {a['agent_key']}"}
    r = c.post("/api/agent/inventory", headers=h, json={"os_name": "Debian 12", "ecosystem": eco, "packages": [], "agent_version": "0.8.0"})
    assert r.status_code == 200, r.text
    return a["asset_id"], h


def send(c, h, images, complete=True, status=200, listed=None):
    """As the agent sends it: a complete report lists every runtime's running containers; an incomplete one (a runtime that
    didn't answer) lists none, unless the test names what was listed."""
    if listed is None:
        listed = {rt: [x["id"] for i in images if isinstance(i, dict) for x in i.get("containers", []) if isinstance(x, dict) and x.get("runtime") == rt]
                  for rt in ("docker", "podman")} if complete else {}
    r = c.post("/api/agent/containers", headers=h, json={"v": 1, "complete": complete, "images": images, "runtimes": {}, "listed": listed, "error": None})
    assert r.status_code == status, r.text
    return r.json()


def images(env):
    s = make_sessionmaker(env)()
    return s, s.scalars(select(Asset).where(Asset.kind == "image").order_by(Asset.first_seen, Asset.id)).all()


def open_on(s, asset_id):
    return sorted(f.vuln_id for f in s.scalars(select(Finding).where(Finding.asset_id == asset_id, Finding.status == "open")))


def test_two_hosts_running_one_image_share_one_asset_and_its_findings(env):
    c = user(env)
    a_id, a = host(c, "web-1")
    b_id, b = host(c, "web-2")
    assert send(c, a, [entry(ctrs=((1, "web"), (2, "web-replica")))]) == {"images": 1, "containers": 2, "new": 1, "stopped": 0, "refused": 0, "complete": True}
    assert send(c, b, [entry(ctrs=((3, "web"),), ref="registry.example/nginx:1.25")])["new"] == 0
    s, imgs = images(env)
    assert len(imgs) == 1
    img = imgs[0]
    assert (img.hostname, img.ecosystem, img.facts["image_id"]) == ("nginx:1.25", "Debian:12", IMG)  # the most common reference
    assert sorted((r.asset_id, r.name) for r in s.scalars(select(Container))) == sorted([(a_id, "web"), (a_id, "web-replica"), (b_id, "web")])
    found = open_on(s, img.id)
    assert found and all(f.startswith("CVE-") for f in found)
    assert open_on(s, a_id) == [] and open_on(s, b_id) == []  # the host's own packages are its inventory's, not its containers'
    # the same image id with other contents (a container changed at runtime, or a host's different answer) is its own asset
    send(c, b, [entry(ctrs=((3, "web"),)), entry(packages=OPENSSL[2:], ctrs=((4, "patched"),))])
    s, imgs = images(env)
    assert len(imgs) == 2 and open_on(s, imgs[1].id) == []


def test_an_image_is_judged_as_a_host_with_the_same_packages_is(env):
    c = user(env)
    h_id, h = host(c, "vm-1")
    c.post("/api/agent/inventory", headers=h, json={"os_name": "Debian 12", "ecosystem": "Debian:12", "agent_version": "0.8.0",
                                                    "packages": [dict(p, ecosystem="Debian:12") for p in OPENSSL]})
    send(c, h, [entry()])
    s, (img,) = images(env)
    assert open_on(s, img.id) == open_on(s, h_id) != []
    report = c.get(f"/api/assets/{img.id}/scan-report").json()
    assert report["kind"] == "image" and report["host"] == "nginx:1.25"


def test_findings_close_only_when_every_host_reported_without_the_image(env):
    c = user(env)
    _, a = host(c, "web-1")
    _, b = host(c, "web-2")
    send(c, a, [entry(ctrs=((1, "web"),))])
    send(c, b, [entry(ctrs=((2, "web"),))])
    s, (img,) = images(env)
    vulns = open_on(s, img.id)
    send(c, a, [], complete=False)  # a partial list (a runtime failed) proves nothing stopped
    send(c, a, [])  # web-1 says it runs nothing now; web-2 still runs it
    s, (img,) = images(env)
    assert open_on(s, img.id) == vulns
    send(c, b, [])  # and now nothing does
    s, (img,) = images(env)
    assert open_on(s, img.id) == []
    done = s.scalars(select(Finding).where(Finding.asset_id == img.id)).all()
    assert {f.status for f in done} == {"resolved"} and all(containers.NOT_RUNNING in f.reasons for f in done)
    ledger = s.scalars(select(LedgerEntry).where(LedgerEntry.kind == "finding_resolved")).all()
    assert len(ledger) == len(vulns) and all(e.data["why"] == "not running on any host" for e in ledger)
    stopped = [e for e in s.scalars(select(LedgerEntry).where(LedgerEntry.kind == "containers_reported")) if e.data["stopped"]]
    assert [e.data["host"] for e in stopped] == ["web-2"]
    # it runs again: the same asset, its findings reopened as a regression, as on a host
    send(c, a, [entry(ctrs=((5, "web"),))])
    s, (img2,) = images(env)
    assert img2.id == img.id and open_on(s, img.id) == vulns
    assert len(s.scalars(select(LedgerEntry).where(LedgerEntry.kind == "finding_reopened")).all()) == len(vulns)


def test_a_silent_host_keeps_its_images_running(env):
    c = user(env)
    _, a = host(c, "web-1")
    send(c, a, [entry()])
    s, (img,) = images(env)
    rescan(s, img, inventory_received=False)  # the hourly re-match, with web-1 silent since
    assert open_on(s, img.id) != []


def test_one_host_cannot_change_or_close_what_another_reported(env):
    c = user(env)
    web, a = host(c, "web-1")
    _, b = host(c, "evil-1")
    send(c, a, [entry(ctrs=((1, "web"),))])
    s, (img,) = images(env)
    vulns = open_on(s, img.id)
    # evil-1 claims web-1's container id and the same image with the vulnerable package gone, then says it runs nothing
    send(c, b, [entry(packages=OPENSSL[2:], ctrs=((1, "web"),))])
    send(c, b, [])
    s, imgs = images(env)
    assert open_on(s, img.id) == vulns and len(imgs) == 2
    assert s.scalars(select(Container.asset_id).where(Container.image_asset_id == img.id)).all() == [web]


def test_entries_that_dont_fit_are_refused_and_make_the_report_incomplete(env):
    c = user(env)
    _, a = host(c, "web-1")
    send(c, a, [entry(ctrs=((1, "web"),)), entry(OTHER, OPENSSL[2:], ctrs=((2, "db"),), ref="postgres:16")])
    bad = [entry(ctrs=((1, "web"),)), dict(entry(), image_id="latest"), dict(entry(), containers=[{"id": "x", "runtime": "docker"}])]
    out = send(c, a, bad, listed={"docker": [cid(1), cid(2)]})  # two entries refused: postgres's container is still listed, so it stays
    assert out["refused"] == 2 and out["complete"] is False
    s, imgs = images(env)
    assert len(s.scalars(select(Container)).all()) == 2
    # a package row the server can't hold: the image is stored, its package list partial, and nothing in it is judged
    send(c, a, [entry(OTHER, [*OPENSSL, {"name": "x" * 300, "version": "1"}], ctrs=((3, "odd"),))], complete=False)
    s, imgs = images(env)
    odd = next(i for i in imgs if s.scalar(select(Container.name).where(Container.image_asset_id == i.id)) == "odd")
    assert odd.collection["sources"]["package_db"]["state"] == "partial" and open_on(s, odd.id) == []
    assert "1 package rows didn't fit" in odd.collection["sources"]["package_db"]["error"]


def test_caps_and_rate_limit(env, monkeypatch):
    c = user(env)
    _, a = host(c, "web-1")
    monkeypatch.setattr(containers, "MAX_IMAGES_PER_ORG", 1)
    out = send(c, a, [entry(ctrs=((1, "web"),)), entry(OTHER, ctrs=((2, "db"),))])
    assert out["new"] == 1 and out["refused"] == 1 and out["complete"] is False
    for _ in range(3):
        send(c, a, [entry(ctrs=((1, "web"),))])
    send(c, a, [entry(ctrs=((1, "web"),))], status=429)  # the fifth in an hour: the agent sends one per report
    r = c.post("/api/agent/containers", headers=a, json={"v": 1, "complete": True, "images": [entry()] * 200})
    assert r.status_code == 422  # more entries than one report can hold


def test_an_image_ranks_by_the_most_critical_host_it_runs_on(env):
    c = user(env)
    a_id, a = host(c, "web-1")
    b_id, b = host(c, "pay-1")
    c.patch(f"/api/assets/{b_id}", json={"internet_facing": True, "criticality": "critical"})
    send(c, a, [entry(ctrs=((1, "web"),))])
    s, (img,) = images(env)
    assert (img.criticality, img.internet_facing) == ("medium", False)
    low = {f.vuln_id: f.score for f in s.scalars(select(Finding).where(Finding.asset_id == img.id))}
    send(c, b, [entry(ctrs=((2, "pay"),))])
    s, (img,) = images(env)
    assert (img.criticality, img.internet_facing) == ("critical", True)
    high = {f.vuln_id: f.score for f in s.scalars(select(Finding).where(Finding.asset_id == img.id))}
    assert all(high[v] > low[v] for v in low)  # re-scored the moment it ran somewhere that matters more


def test_deleting_a_host_deletes_the_images_only_it_ran(env):
    c = user(env)
    a_id, a = host(c, "web-1")
    _, b = host(c, "web-2")
    send(c, a, [entry(ctrs=((1, "web"),)), entry(OTHER, OPENSSL[2:], ctrs=((2, "only-here"),))])
    send(c, b, [entry(ctrs=((3, "web"),))])
    assert c.delete(f"/api/assets/{a_id}").status_code == 204
    s, imgs = images(env)
    assert [i.facts["image_id"] for i in imgs] == [IMG]  # still run by web-2
    assert len(s.scalars(select(Container)).all()) == 1


def test_deleting_a_host_re_ranks_the_images_it_shared(env):
    c = user(env)
    _, a = host(c, "web-1")
    b_id, b = host(c, "pay-1")
    c.patch(f"/api/assets/{b_id}", json={"internet_facing": True, "criticality": "critical"})
    send(c, a, [entry(ctrs=((1, "web"),))])
    send(c, b, [entry(ctrs=((2, "pay"),))])
    s, (img,) = images(env)
    assert (img.criticality, img.internet_facing) == ("critical", True)
    high = {f.vuln_id: f.score for f in s.scalars(select(Finding).where(Finding.asset_id == img.id))}
    assert c.delete(f"/api/assets/{b_id}").status_code == 204
    s, (img,) = images(env)
    assert (img.criticality, img.internet_facing) == ("medium", False)  # web-1 alone runs it now, before it next reports
    low = {f.vuln_id: f.score for f in s.scalars(select(Finding).where(Finding.asset_id == img.id))}
    assert low.keys() == high.keys() and all(low[v] < high[v] for v in low)


def test_images_nothing_runs_for_30_days_are_pruned(env):
    c = user(env)
    _, a = host(c, "web-1")
    send(c, a, [entry(ctrs=((1, "web"),)), entry(OTHER, OPENSSL[2:], ctrs=((2, "db"),))])
    send(c, a, [entry(ctrs=((1, "web"),))])  # db stopped
    s, imgs = images(env)
    for i in imgs:
        i.last_seen = now() - timedelta(days=31)
    s.commit()
    assert containers.prune(s) == 1  # the running one stays, whatever its last_seen
    s.commit()
    s, imgs = images(env)
    assert [i.facts["image_id"] for i in imgs] == [IMG]


def test_another_org_cannot_see_or_reach_an_image(env):
    c = user(env)
    _, a = host(c, "web-1")
    send(c, a, [entry()])
    _, (img,) = images(env)
    other = user(env, "b@example.com")
    assert other.get(f"/api/assets/{img.id}/scan-report").status_code == 404
    assert c.get("/api/findings").json() and other.get("/api/findings").json() == []


@pytest.mark.parametrize("bad", [{"complete": True, "images": "x"}, {"images": [1, 2]}, {}])
def test_malformed_bodies_change_nothing(env, bad):
    c = user(env)
    _, a = host(c, "web-1")
    send(c, a, [entry()])
    r = c.post("/api/agent/containers", headers=a, json=bad)
    assert r.status_code in (200, 422)
    s, imgs = images(env)
    assert len(s.scalars(select(Container)).all()) == 1


def test_an_image_is_never_planned_on_and_fix_first_says_rebuild(env):
    c = user(env)
    h_id, h = host(c, "vm-1")
    c.post("/api/agent/inventory", headers=h, json={"os_name": "Debian 12", "ecosystem": "Debian:12", "agent_version": "0.8.0",
                                                    "packages": [dict(p, ecosystem="Debian:12") for p in OPENSSL]})
    send(c, h, [entry(ctrs=((1, "web"),))])
    s, (img,) = images(env)
    r = c.post("/api/remediation/jobs", json={"asset_id": img.id, "ecosystem": "Debian:12", "package": "openssl"})
    assert r.status_code == 409 and "rebuilding it" in r.json()["detail"]
    r = c.post("/api/remediation/jobs/batch", json={"asset_ids": [h_id, img.id], "ecosystem": "Debian:12", "package": "openssl"})
    assert [j["asset_id"] for j in r.json()["jobs"]] == [h_id] and [e["asset_id"] for e in r.json()["errors"]] == [img.id]
    summary = c.get("/api/summary").json()
    openssl = next(a for a in summary["top_actions"] if a["package"] == "openssl")
    assert openssl["asset_ids"] == [h_id] and openssl["hosts"] == ["vm-1"]  # the image's finding never joins the host's action
    (rebuild,) = summary["images_to_rebuild"]
    assert (rebuild["asset_id"], rebuild["name"], rebuild["hosts"]) == (img.id, "nginx:1.25", ["vm-1"])
    assert rebuild["fixes"][0]["package"] == "openssl" and rebuild["fixes"][0]["fixed_version"] and rebuild["findings"] == len(open_on(s, img.id))
    rows = c.get("/api/findings", params={"asset_id": img.id}).json()
    assert rows and all(f["asset_kind"] == "image" and f["plannable"] is False for f in rows)
    assert all(f["asset_kind"] == "image" for f in c.get("/api/findings", params={"asset_id": img.id, "view": "list"}).json())
    one = c.get(f"/api/findings/{rows[0]['id']}").json()
    assert "rebuilding it" in one["rebuild"] and one["runs_on"] == ["vm-1"]
    assert c.get("/api/findings", params={"asset_id": h_id}).json()[0]["plannable"] is True


def test_assets_say_where_each_image_runs_and_what_each_host_runs(env):
    c = user(env)
    a_id, a = host(c, "web-1")
    send(c, a, [entry(ctrs=((1, "web"), (2, "worker"))), entry(OTHER, [], ctrs=((3, "tools"),), ref="busybox:1.36", eco="")])
    assets = {x["hostname"]: x for x in c.get("/api/assets").json()}
    img, bb = assets["nginx:1.25"], assets["busybox:1.36"]
    assert img["kind"] == "image" and img["image_id"] == IMG and img["hosts_total"] == 1 and img["containers_total"] == 2
    assert [(r["hostname"], r["name"]) for r in img["running_on"]] == [("web-1", "web"), ("web-1", "worker")]
    assert img["packages_read"] is True and img["not_read_why"] is None
    assert bb["packages_read"] is False and bb["not_read_why"]  # never shown as clean
    assert sorted(x["name"] for x in assets["web-1"]["containers"]) == ["tools", "web", "worker"]
    on_host = next(x for x in assets["web-1"]["containers"] if x["name"] == "web")  # every field of a row, both ways round
    assert img["running_on"][0] == {"name": "web", "runtime": "docker", "ref": "nginx:1.25", "since": on_host["since"], "host_id": a_id, "hostname": "web-1"}
    assert on_host == {"name": "web", "runtime": "docker", "ref": "nginx:1.25", "since": on_host["since"], "image_id": img["id"]}
    assert datetime.fromisoformat(on_host["since"]) <= now()
    r = c.patch(f"/api/assets/{img['id']}", json={"criticality": "critical"})
    assert r.status_code == 409 and "follow the hosts" in r.json()["detail"]
    c.patch(f"/api/assets/{a_id}", json={"criticality": "critical"})  # changed on the host: its images follow
    assert {x["hostname"]: x for x in c.get("/api/assets").json()}["nginx:1.25"]["criticality"] == "critical"


@pytest.mark.skipif(not __import__("conftest").PG, reason="SQLite serialises writers; the race is Postgres-only")
def test_two_hosts_reporting_one_new_image_at_once_make_one_asset(env, monkeypatch):
    import threading
    import time
    c = user(env)
    hosts = [host(c, f"web-{n}") for n in (1, 2)]
    create = containers._create
    monkeypatch.setattr(containers, "_create", lambda *a: (time.sleep(0.5), create(*a))[1])  # both past the lookup before either inserts
    gate, codes = threading.Barrier(2), []

    def post(h, n):
        gate.wait()
        codes.append(c.post("/api/agent/containers", headers=h, json={"v": 1, "complete": True, "images": [entry(ctrs=((n, f"web{n}"),))]}).status_code)
    threads = [threading.Thread(target=post, args=(h, n)) for n, (_, h) in enumerate(hosts, 1)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    s, imgs = images(env)
    assert codes == [200, 200] and len(imgs) == 1
    assert sorted(s.scalars(select(Container.asset_id).where(Container.image_asset_id == imgs[0].id))) == sorted(h_id for h_id, _ in hosts)


# ---- security and code review (DECISIONS 143) ------------------------------------------------------------------------

def test_a_stopped_container_closes_by_its_own_runtimes_listing_whatever_else_failed(env):
    c = user(env)
    _, a = host(c, "web-1")
    send(c, a, [entry(ctrs=((1, "web"),)), entry(OTHER, OPENSSL[2:], ctrs=((2, "tools"),), runtime="podman")])
    s, imgs = images(env)
    web = next(i for i in imgs if i.facts["image_id"] == IMG)
    # web stopped; podman broke (not listed); and the agent read nothing at all this time (its budget, say)
    out = send(c, a, [], complete=False, listed={"docker": []})
    s, _ = images(env)
    assert out["stopped"] == 1 and open_on(s, web.id) == []  # docker's whole listing proves web stopped
    assert [r.name for r in s.scalars(select(Container))] == ["tools"]  # podman's container isn't taken as stopped
    # a container listed as running but not read keeps its row
    send(c, a, [entry(ctrs=((3, "web"),))])
    out = send(c, a, [], complete=False, listed={"docker": [cid(3)]})
    s, _ = images(env)
    assert out["stopped"] == 0 and open_on(s, web.id) != []


def test_one_host_cant_take_the_orgs_share_of_images(env, monkeypatch):
    c = user(env)
    _, a = host(c, "evil-1")
    _, b = host(c, "web-1")
    monkeypatch.setattr(containers, "MAX_NEW_IMAGES_PER_HOST_DAY", 2)
    many = [entry("sha256:" + f"{n:064x}", OPENSSL[2:], ctrs=((n, f"c{n}"),)) for n in range(1, 5)]
    out = send(c, a, many)
    assert out["new"] == 2 and out["refused"] == 2  # two new images a day from one host
    assert send(c, b, [entry(ctrs=((9, "web"),))])["new"] == 1  # the next host is unaffected
    monkeypatch.setattr(containers, "MAX_NEW_IMAGES_PER_HOST_DAY", 99)
    monkeypatch.setattr(containers, "MAX_IMAGES_PER_HOST", 3)
    assert send(c, a, many, complete=False)["refused"] == 1  # it runs two already: room for one more image
    monkeypatch.setattr(containers, "MAX_CONTAINERS_PER_HOST", 4)
    out = send(c, a, [entry("sha256:" + f"{n:064x}", OPENSSL[2:], ctrs=tuple((n * 10 + k, "x") for k in range(5))) for n in range(1, 2)], complete=False)
    assert out["refused"] == 1  # five more containers than the host may hold


def test_a_host_gets_one_vote_on_a_shared_images_name(env):
    c = user(env)
    _, a = host(c, "web-1")
    _, b = host(c, "evil-1")
    send(c, a, [entry(ctrs=((1, "web"),))])
    send(c, b, [entry(ctrs=tuple((n, f"x{n}") for n in range(2, 12)), ref="PAYROLL-DB do-not-patch")])
    s, (img,) = images(env)
    assert img.hostname == "nginx:1.25"  # ten containers are still one vote, and a tie keeps the name
    assert img.agent_key_hash.startswith("img:")  # never a hex SHA-256: no key hashes to it


def test_an_image_seen_running_after_its_releases_end_is_judged_as_of_then(env):
    s = make_sessionmaker(env)()
    s.add(Advisory(id="debian", ecosystem="EOL", package="debian", record={"cycles": {"12": "2026-06-01"}}))
    s.commit()
    c = user(env)
    _, a = host(c, "web-1")
    send(c, a, [entry()])
    s, (img,) = images(env)
    assert "EOL:debian-12" in open_on(s, img.id)
    img.last_inventory_at = img.first_seen = datetime(2026, 1, 1)  # first stored before the end date, still running now
    s.commit()
    rescan(s, img, inventory_received=False)
    assert "EOL:debian-12" in open_on(s, img.id)


def test_an_image_on_a_platform_no_feed_maps_is_not_assessed(env):
    c = user(env)
    _, a = host(c, "web-1")
    wolfi = entry(OTHER, [{"name": "glibc", "version": "2.40-r1", "source": "glibc"}], ref="cgr.dev/chainguard/wolfi-base", eco="")
    wolfi["facts"] = {"os_id": "wolfi", "os_version_id": "20230201", "os_unmatched": "no advisory feed maps this platform: ID=wolfi VERSION_ID=20230201"}
    send(c, a, [wolfi])
    row = next(x for x in c.get("/api/assets").json() if x["kind"] == "image")
    assert row["packages_read"] is False and row["not_read_why"].startswith("no advisory feed maps this platform")


def test_images_dont_count_against_the_asset_quota_and_take_no_sbom(env, monkeypatch):
    import nimstead.app as appmod
    c = user(env)
    _, a = host(c, "web-1")
    send(c, a, [entry()])
    monkeypatch.setattr(appmod, "MAX_ASSETS_PER_ORG", 2)
    assert c.post("/api/assets", json={"name": "billing", "criticality": "high"}).status_code == 201  # host + application; the image is apart
    _, (img,) = images(env)
    r = c.post(f"/api/assets/{img.id}/sbom", content=b'{"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}')
    assert r.status_code == 409
