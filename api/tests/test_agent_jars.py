"""Opt-in Java library scan (plan T35): jar files on disk -> Maven packages for the existing OSV matcher."""

import io
import zipfile

from test_agent_remediate import agent
from test_sbom import maven_env  # noqa: F401 - fixture: the real log4j-core OSV records

POM = "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties"


def jar(entries: dict) -> bytes:
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for n, data in entries.items():
            z.writestr(n, data)
    return b.getvalue()


def test_finds_log4j_inside_a_fat_jar_and_names_the_file(tmp_path):
    inner = jar({POM: "#generated\ngroupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.14.1\n"})
    app = tmp_path / "srv" / "billing.jar"
    app.parent.mkdir()
    app.write_bytes(jar({"BOOT-INF/lib/log4j-core-2.14.1.jar": inner, "META-INF/MANIFEST.MF": "x"}))
    (tmp_path / "srv" / "broken.jar").write_bytes(b"not a zip")
    pkgs, summary = agent.scan_jars([str(tmp_path)], mounts=[])
    [pkg] = pkgs  # one row per file it's in, named in its source (T19)
    assert {k: pkg[k] for k in ("ecosystem", "name", "version")} == {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core", "version": "2.14.1"}
    assert pkg["source"].endswith("billing.jar!/BOOT-INF/lib/log4j-core-2.14.1.jar")
    [[name, ver, where]] = summary["locations"]
    assert summary["complete"] and (name, ver) == ("org.apache.logging.log4j:log4j-core", "2.14.1")
    assert where.endswith("billing.jar!/BOOT-INF/lib/log4j-core-2.14.1.jar")


def test_budget_reports_a_partial_scan(tmp_path):
    for i in range(5):
        (tmp_path / f"f{i}.txt").write_text("x")
    _, summary = agent.scan_jars([str(tmp_path)], max_files=2, mounts=[])
    assert not summary["complete"] and "budget" in summary["partial"]


def test_unsafe_coordinates_are_ignored(tmp_path):
    (tmp_path / "a.jar").write_bytes(jar({POM: "groupId=org.evil;rm -rf\nartifactId=x\nversion=1.0\n"}))
    assert agent.scan_jars([str(tmp_path)], mounts=[])[0] == []


def test_only_when_the_host_opted_in(monkeypatch):
    monkeypatch.setattr(agent, "collect", lambda: {"packages": [], "facts": {}})
    monkeypatch.setattr(agent, "neighbours", lambda: [])
    monkeypatch.setattr(agent, "own_addresses", lambda: {"ips": [], "macs": []})
    monkeypatch.setattr(agent, "scan_jars", lambda roots, owned: ([{"ecosystem": "Maven", "name": "g:a", "version": "1", "source": None}], {"complete": True}))
    assert agent.inventory({})["packages"] == []
    inv = agent.inventory({"scan_jars": True})
    assert inv["packages"][0]["name"] == "g:a" and inv["facts"]["jar_scan"] == {"complete": True}


def test_jar_finding_names_the_file(maven_env):  # noqa: F811
    from test_api import user
    c = user(maven_env)
    token = c.post("/api/enroll-tokens").json()["token"]
    a = c.post("/api/agent/enroll", json={"token": token, "hostname": "app-1", "ecosystem": "Windows"}).json()
    h = {"Authorization": f"Bearer {a['agent_key']}"}
    where = r"D:\apps\billing.jar!/BOOT-INF/lib/log4j-core-2.14.1.jar"
    r = c.post("/api/agent/inventory", headers=h, json={"ecosystem": "Windows", "packages": [
        {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core", "version": "2.14.1", "source": None}],
        "facts": {"jar_scan": {"complete": True, "files": 9, "locations": [["org.apache.logging.log4j:log4j-core", "2.14.1", where]]}}})
    assert r.status_code == 200, r.text
    f = {x["vuln_id"]: x for x in c.get("/api/findings").json()}
    assert where in f["CVE-2021-44228"]["summary"]


def test_a_planted_jar_cant_break_the_report(tmp_path):
    """Security review: an over-long groupId made the server refuse the whole inventory; a huge properties entry
    could exhaust memory. Both are skipped."""
    (tmp_path / "long.jar").write_bytes(jar({f"META-INF/maven/{'A' * 200}/b/pom.properties": "version=1"}))
    (tmp_path / "bomb.jar").write_bytes(jar({POM: "version=2.14.1\n" + "x" * 70_000}))
    assert agent.scan_jars([str(tmp_path)], mounts=[])[0] == []


def test_facts_that_dont_fit_are_dropped_not_the_report(env):
    from test_api import user
    c = user(env)
    token = c.post("/api/enroll-tokens").json()["token"]
    a = c.post("/api/agent/enroll", json={"token": token, "hostname": "h", "ecosystem": "Windows"}).json()
    h = {"Authorization": f"Bearer {a['agent_key']}"}
    r = c.post("/api/agent/inventory", headers=h, json={"ecosystem": "Windows", "packages": [], "facts": {"x" * 200: 1}})
    assert r.status_code == 200 and c.get("/api/assets").json()[0]["facts"] == {}


def test_too_many_jar_packages_are_capped_and_the_scan_says_partial(tmp_path):
    for i in range(3):
        (tmp_path / f"a{i}.jar").write_bytes(jar({POM: f"groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.{i}.0\n"}))
    pkgs, summary = agent.scan_jars([str(tmp_path)], mounts=[], max_packages=2)
    assert len(pkgs) == 2 and not summary["complete"] and "2 jar packages" in summary["partial"]
