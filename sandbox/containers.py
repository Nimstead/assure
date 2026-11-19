"""Containers proof (tasks/plan-containers.md C11, tasks/spec-containers.md success criteria 1-8) in a DISPOSABLE WSL Debian
distro with real Docker and Podman, real images and the real agent.

Run from api/:  uv run python ../sandbox/containers.py [--keep] [--reuse nimstead-sbx-NAME]
- Creates nimstead-sbx-ctr-<hex>, installs docker.io and podman, pulls real images, runs real containers, and unregisters
  the distro at the end (unless --keep). --reuse runs against an existing nimstead-sbx-* distro (development only).
- The API runs in-process on a throwaway SQLite DB with real OSV, KEV, EPSS and endoflife.date data. The real agent's
  `collect` runs as root in the distro; this script relays what it sends exactly as `report` does (sbx.py does the same),
  so the host firewall never matters.
- Two oracles: each container's own package manager (dpkg-query, apk, rpm, run inside it) for what is installed, and the
  OSV API, asked about every source package of every image, for what is vulnerable.
Writes sandbox/last_run_containers.json: every step, and PASS only if every criterion passed.
"""

import importlib.util
import io
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "nimstead-sbx-"
REUSE = sys.argv[sys.argv.index("--reuse") + 1] if "--reuse" in sys.argv else None
NAME = REUSE or PREFIX + "ctr-" + secrets.token_hex(3)
TMP = Path(tempfile.mkdtemp(prefix="nimstead-sbx-ctr-"))
OUT = Path(__file__).with_name("last_run_containers.json")
os.environ.update(NIMSTEAD_SECURE_COOKIES="0", NIMSTEAD_INVENTORY_MIN_SECONDS="0", NIMSTEAD_SIGNING_KEY_FILE=str(TMP / "signing.pem"))

import httpx  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from signin import signup  # noqa: E402
from sqlalchemy import select  # noqa: E402

from nimstead import containers as ctrmod  # noqa: E402
from nimstead import feeds  # noqa: E402
from nimstead.app import create_app  # noqa: E402
from nimstead.db import Advisory, Asset, Container, Finding, InstalledPackage, LedgerEntry, make_sessionmaker  # noqa: E402
from nimstead.match import canonical_id, normalize_ecosystem  # noqa: E402
from nimstead.verify_pack import verify  # noqa: E402

spec = importlib.util.spec_from_file_location("nimstead_agent", ROOT / "agent" / "nimstead_agent.py")
agentmod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agentmod)

log: list[dict] = []
failures: list[str] = []


def note(step, **kw):
    log.append({"step": step, **kw})
    print(f"[{time.strftime('%H:%M:%S')}] {step}", json.dumps(kw, default=str)[:400] if kw else "", flush=True)


def check(criterion, ok, **kw):
    """One success criterion's verdict, on the record either way."""
    note(f"{'PASS' if ok else 'FAIL'}: {criterion}", **kw)
    if not ok:
        failures.append(criterion)


def wsl(script, timeout=1800, ok=(0,)):
    assert NAME.startswith(PREFIX)  # never run commands in a distro this script didn't make
    p = subprocess.run(["wsl", "-d", NAME, "-u", "root", "--", "sh", "-s"], input=script.replace("\r", "").encode(), capture_output=True, timeout=timeout)
    if p.returncode not in ok:
        raise RuntimeError(f"sandbox command failed ({p.returncode}): {script[:300]}\n{p.stdout.decode(errors='replace')[-2000:]}\n{p.stderr.decode(errors='replace')[-2000:]}")
    return p.stdout.decode(errors="replace")


IMAGES = ["debian:11", "debian:12", "alpine:3.18", "almalinux:9", "ubuntu:24.04", "gcr.io/distroless/base-debian12:debug", "busybox:1.36"]
ECOSYSTEMS = {"Debian:11", "Debian:12", "Alpine:v3.18", "AlmaLinux:9", "Ubuntu:24.04"}
MARKER = "/etc/nimstead-host-marker"  # on the host only: if a reader ever escaped a container, HOSTLEAK would be a package
HOSTILE = {  # name -> Dockerfile body after FROM busybox:1.36, and what the read must say
    # both links resolve inside the container, where the marker doesn't exist: there is no package database at all
    "hostile-abs": (f"RUN mkdir -p /var/lib/dpkg && ln -s {MARKER} /var/lib/dpkg/status", "no package database found"),
    "hostile-rel": (f"RUN mkdir -p /var/lib/dpkg && ln -s ../../../../../../../..{MARKER} /var/lib/dpkg/status", "no package database found"),
    "hostile-fifo": ("RUN mkdir -p /var/lib/dpkg && mkfifo /var/lib/dpkg/status", "not a regular file"),
    "hostile-big": ("RUN mkdir -p /var/lib/dpkg && dd if=/dev/zero of=/var/lib/dpkg/status bs=1M count=200 2>/dev/null", "larger than 64 MB"),
}
RUNNING = {"legacy": "debian:11", "web1": "alpine:3.18", "web2": "alpine:3.18", "alma": "almalinux:9", "ubu": "ubuntu:24.04", "bb": "busybox:1.36"}


def setup():
    if not REUSE:
        r = subprocess.run(["wsl", "--install", "Debian", "--name", NAME, "--location", str(TMP / "d"), "--no-launch"], capture_output=True, timeout=1800)
        if r.returncode != 0:
            raise RuntimeError((r.stdout + r.stderr).decode("utf-16-le", errors="replace"))
    note("distro", name=NAME, reused=bool(REUSE))
    setup.keepalive = subprocess.Popen(["wsl", "-d", NAME, "-u", "root", "--", "sleep", "infinity"])  # WSL stops idle distros
    wsl("command -v podman >/dev/null || (apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io podman python3 >/dev/null)")
    wsl("docker info >/dev/null 2>&1 || (nohup dockerd >/var/log/dockerd.log 2>&1 &); for i in $(seq 60); do docker info >/dev/null 2>&1 && exit 0; sleep 1; done; exit 1")
    note("runtimes", versions=wsl("docker --version; podman --version").split("\n")[:2], os=wsl(". /etc/os-release; echo $PRETTY_NAME").strip())
    wsl(f"printf 'Package: HOSTLEAK\\nStatus: install ok installed\\nVersion: 1\\n' > {MARKER}")
    wsl("mkdir -p /opt/nimstead && cat > /opt/nimstead/agent.py <<'NIMSTEAD_AGENT'\n" + (ROOT / "agent" / "nimstead_agent.py").read_text(encoding="utf-8") + "\nNIMSTEAD_AGENT\n")
    for img in IMAGES:
        wsl(f"docker pull -q {img} >/dev/null", timeout=1800)
    wsl("podman pull -q docker.io/library/alpine:3.18 >/dev/null 2>&1", timeout=1800)
    for name, (body, _) in HOSTILE.items():
        wsl(f"printf 'FROM busybox:1.36\\n{body}\\n' | docker build -q -t {name} - >/dev/null", timeout=900)
    wsl("for c in $(docker ps -aq); do docker rm -f $c >/dev/null; done; for c in $(podman ps -aq); do podman rm -f $c >/dev/null; done")
    for name, img in {**RUNNING, **{h: h for h in HOSTILE}}.items():
        wsl(f"docker run -d --name {name} {img} sleep infinity >/dev/null")
    wsl("docker run -d --name dl --entrypoint /busybox/sleep gcr.io/distroless/base-debian12:debug infinity >/dev/null")
    wsl("podman run -d --name pod1 docker.io/library/alpine:3.18 sleep infinity >/dev/null")
    note("containers running", docker=wsl("docker ps --format '{{.Names}}'").split(), podman=wsl("podman ps --format '{{.Names}}'").split())


def collect():
    """The agent's own report path: collect, put the containers line in the inventory's document, split the two bodies."""
    t = time.time()
    inv = json.loads(wsl("cd /opt/nimstead && python3 agent.py collect", timeout=600))
    ctr = inv.pop("containers")
    inv.pop("neighbours", None)
    inv["collection"]["sources"]["containers"] = ctr.pop("line")
    return inv, ctr, round(time.time() - t, 1)


def truth(name, ecosystem):
    """What the container's own package manager says is installed, as the agent's row tuples."""
    if ecosystem.startswith(("Debian", "Ubuntu")):
        fmt = "${Package}\\t${Version}\\t${source:Package}\\t${source:Version}\\t${db:Status-Abbrev}\\n"
        pkgs = agentmod.parse_dpkg(wsl(f"docker exec {name} dpkg-query -W -f '{fmt}'"))
    elif ecosystem.startswith("Alpine"):
        pkgs = agentmod.parse_apk(wsl(f"docker exec {name} cat /lib/apk/db/installed"))
        listed = sorted(wsl(f"docker exec {name} apk info -v 2>/dev/null").split())
        assert listed == sorted(f"{p['name']}-{p['version']}" for p in pkgs), "apk info disagrees with its own database"
    else:
        pkgs = agentmod.parse_rpm(wsl(f"docker exec {name} rpm -qa --qf '%{{NAME}}\\t%{{EPOCHNUM}}:%{{VERSION}}-%{{RELEASE}}\\t%{{SOURCERPM}}\\n'"))
    return sorted((p["name"], p["version"], p["source"], p.get("source_version")) for p in pkgs)


def osv_answer(s, http, image: Asset) -> set[str]:
    """The OSV API's affected vulnerabilities for every source package in the image, as canonical ids (the engine's own key)."""
    eco = normalize_ecosystem(image.ecosystem)
    rec = s.scalar(select(Advisory.record).where(Advisory.ecosystem == eco).limit(1))
    osv_eco = next(a["package"]["ecosystem"] for a in rec["affected"] if normalize_ecosystem(a["package"]["ecosystem"]) == eco)
    seen, out = set(), set()
    for p in s.scalars(select(InstalledPackage).where(InstalledPackage.asset_id == image.id)):
        key = (p.source or p.name, p.source_version or p.version)
        if key in seen:
            continue
        seen.add(key)
        token = None
        while True:
            r = http.post("https://api.osv.dev/v1/query", json={"package": {"name": key[0], "ecosystem": osv_eco}, "version": key[1], **({"page_token": token} if token else {})})
            r.raise_for_status()
            body = r.json()
            out |= {canonical_id(v) for v in body.get("vulns", []) if not v.get("withdrawn")}
            if not (token := body.get("next_page_token")):
                break
    return out


def open_ids(s, image_id, eco=None):
    q = select(Finding.vuln_id).where(Finding.asset_id == image_id, Finding.status == "open")
    return set(s.scalars(q.where(Finding.ecosystem == eco) if eco else q))


def main(keep=False):
    db = f"sqlite:///{(TMP / 'nimstead.db').as_posix()}"
    c = TestClient(create_app(db))
    signup(c, {"email": "sbx@example.com", "password": "sandbox-only-password", "org_name": "Sandbox"})
    Session = make_sessionmaker(db)
    try:
        setup()
        with Session() as s:
            t = time.time()
            got = {"kev": feeds.sync_kev(s), "epss": feeds.sync_epss(s), "eol": feeds.sync_eol(s)}
            for family in sorted({e.split(":")[0] for e in ECOSYSTEMS}):
                got[family] = feeds.sync_osv(s, [family], only=ECOSYSTEMS)
            note("feeds synced", seconds=round(time.time() - t), **{k: (v if isinstance(v, (int, str)) else str(v)[:120]) for k, v in got.items()})
        token = c.post("/api/enroll-tokens", json={"sandbox": True}).json()["token"]
        inv, ctr, secs = collect()
        a = c.post("/api/agent/enroll", json={"token": token, "hostname": "ctr-host", "os_name": inv["os_name"], "ecosystem": inv["ecosystem"]}).json()
        h = {"Authorization": f"Bearer {a['agent_key']}"}

        def report(inv, ctr):
            r = c.post("/api/agent/inventory", json=inv, headers=h)
            assert r.status_code == 200, r.text
            r = c.post("/api/agent/containers", json=ctr, headers=h)
            assert r.status_code == 200, r.text
            return r.json()

        note("first report", collect_seconds=secs, sent_complete=ctr["complete"], error=ctr["error"], runtimes=ctr["runtimes"], server=report(inv, ctr))
        s = Session()
        by_ctr = {r.name: s.get(Asset, r.image_asset_id) for r in s.scalars(select(Container))}  # container name -> the image it runs
        rows = lambda a: sorted((p.name, p.version, p.source or p.name, p.source_version) for p in s.scalars(select(InstalledPackage).where(InstalledPackage.asset_id == a.id)))  # noqa: E731

        # 1. every image, its base OS, and its packages row for row as its own package manager lists them
        per = {}
        for name in ("legacy", "web1", "alma", "ubu"):
            img = by_ctr[name]
            want, have = truth(name, img.ecosystem), rows(img)
            per[name] = {"image": img.hostname, "ecosystem": img.ecosystem, "packages": len(have), "own_manager": len(want), "equal": want == have}
        dl = by_ctr["dl"]
        dl_truth = int(wsl("docker exec dl /busybox/sh -c 'ls /var/lib/dpkg/status.d | grep -v md5sums | wc -l'").strip())
        per["dl"] = {"image": dl.hostname, "ecosystem": dl.ecosystem, "packages": len(rows(dl)), "own_manager": dl_truth, "equal": len(rows(dl)) == dl_truth}
        bb = by_ctr["bb"]
        bb_db = (bb.collection or {}).get("sources", {}).get("package_db", {})
        check("1. each image's packages equal its own package manager's; busybox is not assessed", all(v["equal"] for v in per.values()) and
              bb_db.get("state") == "failed" and "no package database" in (bb_db.get("error") or ""), images=per, busybox=bb_db)

        # 4. replicas of one image, across Docker and Podman, are one image listing all of them
        alpine = by_ctr["web1"]
        runs = sorted((r.name, r.runtime) for r in s.scalars(select(Container).where(Container.image_asset_id == alpine.id)))
        check("4. two Docker replicas and a Podman container of one image are one image asset", runs == [("pod1", "podman"), ("web1", "docker"), ("web2", "docker")]
              and by_ctr["pod1"].id == alpine.id, runs=runs)

        # 6. hostile containers: nothing outside them read, no hang, every one not assessed with the reason
        leaked = s.scalar(select(InstalledPackage.id).where(InstalledPackage.name == "HOSTLEAK"))
        hostile = {n: (by_ctr[n].collection or {}).get("sources", {}).get("package_db") or {} for n in HOSTILE}
        ok6 = leaked is None and secs < agentmod.CONTAINER_SECONDS and all(
            d.get("state") == "failed" and want in (d.get("error") or "") for (_, want), d in zip(HOSTILE.values(), hostile.values(), strict=True))
        check("6. hostile containers (absolute and climbing links to a host-only file, a FIFO, a 200 MB file) read nothing outside, never hang, are not assessed",
              ok6, host_file_read=leaked is not None, collect_seconds=secs, package_db=hostile)

        # 3. end of support from the image's own os-release
        eol = {n: sorted(v for v in open_ids(s, by_ctr[n].id) if v.startswith("EOL:")) for n in ("legacy", "web1", "alma")}
        check("3. Debian 11 and Alpine 3.18 open their end-of-support findings; AlmaLinux 9 doesn't", bool(eol["legacy"]) and bool(eol["web1"]) and not eol["alma"], eol=eol)

        # 2. findings agree with the OSV API on every source package of every image
        agree = {}
        with httpx.Client(timeout=60) as http:
            for name in ("legacy", "web1", "alma", "ubu", "dl"):
                img = by_ctr[name]
                ours, theirs = open_ids(s, img.id, img.ecosystem), osv_answer(s, http, img)
                agree[img.hostname] = {"ours": len(ours), "osv": len(theirs), "only_ours": sorted(ours - theirs)[:20], "only_osv": sorted(theirs - ours)[:20]}
        check("2. every image's findings agree with the OSV API's answers for its source packages", all(not v["only_ours"] and not v["only_osv"] for v in agree.values()), agreement=agree)

        # 8. an image is never planned on
        r = c.post("/api/remediation/jobs", json={"asset_id": by_ctr["legacy"].id, "ecosystem": "Debian:11", "package": next(iter(rows(by_ctr["legacy"])))[2]})
        check("8. remediation on an image is refused", r.status_code == 409 and "rebuild" in r.text.lower(), status=r.status_code, detail=r.json().get("detail"))

        # 7. image SBOMs from real Syft and Trivy match the agent's own reading of the same images: every finding, end of support
        # included. Debian 11 and Alpine 3.18 are past it, so their distributions publish no more advisories (OSV agrees, above):
        # Ubuntu 24.04 and distroless Debian 12 carry the CVEs
        sbom_cmp = {}
        for img, cname in (("debian:11", "legacy"), ("alpine:3.18", "web1"), ("ubuntu:24.04", "ubu"), ("gcr.io/distroless/base-debian12:debug", "dl")):
            ours = open_ids(s, by_ctr[cname].id)
            for tool, cmd in (("syft", f"docker run --rm -v /var/run/docker.sock:/var/run/docker.sock anchore/syft:latest docker:{img} -o cyclonedx-json -q"),
                              ("trivy", f"docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v trivycache:/root/.cache aquasec/trivy:latest image -q --format cyclonedx {img}")):
                doc = wsl(cmd, timeout=1800)
                app = c.post("/api/assets", json={"name": f"{tool}-{img}", "criticality": "medium"}).json()
                up = c.post(f"/api/assets/{app['id']}/sbom", content=doc.encode(), headers={"Authorization": f"Bearer {app['upload_token']}"})
                theirs = open_ids(Session(), app["id"])
                sbom_cmp[f"{tool} {img}"] = {"status": up.status_code, "distro": up.json().get("distro"), "ours": len(ours), "sbom": len(theirs),
                                             "only_agent": sorted(ours - theirs)[:10], "only_sbom": sorted(theirs - ours)[:10]}
        grades = {g["grade"] for app in c.get("/api/assets").json() if app["kind"] == "application"
                  for g in c.get(f"/api/assets/{app['id']}/scan-report").json()["vulnerable"] if g["family"] == "distro"}
        check("7. real Syft and Trivy image SBOMs give the agent's findings for the same images (end of support and CVEs), graded unverified",
              all(v["status"] == 200 and not v["only_agent"] and not v["only_sbom"] for v in sbom_cmp.values())
              and sum(v["ours"] for v in sbom_cmp.values()) > 4 * 2 and grades == {"unverified"}, sboms=sbom_cmp, grades=sorted(grades))

        # 5a. a partial list closes nothing: podman fails, and web1 stops
        before = {n: open_ids(s, by_ctr[n].id) for n in ("legacy", "web1")}
        wsl("mv /usr/bin/podman /usr/bin/podman.real && printf '#!/bin/sh\\necho \"Error: database is locked\" >&2\\nexit 125\\n' > /usr/bin/podman && chmod +x /usr/bin/podman")
        wsl("docker rm -f web1 >/dev/null")
        inv, ctr, _ = collect()
        out = report(inv, ctr)
        wsl("mv -f /usr/bin/podman.real /usr/bin/podman")
        s = Session()
        still = sorted(r.name for r in s.scalars(select(Container).where(Container.image_asset_id == alpine.id)))
        check("5a. a partial container list (a runtime failing) closes nothing", ctr["complete"] is False and out["complete"] is False and "web1" in still
              and open_ids(s, alpine.id) == before["web1"], complete=ctr["complete"], error=ctr["error"], alpine_runs=still)

        # 5b. rebuild and redeploy: the old image's findings close on the evidence, the new image's are there
        wsl("docker rm -f legacy >/dev/null && docker run -d --name legacy debian:12 sleep infinity >/dev/null")
        inv, ctr, _ = collect()
        out = report(inv, ctr)
        s = Session()
        old = s.get(Asset, by_ctr["legacy"].id)
        resolved = s.scalars(select(Finding).where(Finding.asset_id == old.id)).all()
        new = next(i for i in s.scalars(select(Asset).where(Asset.kind == "image")) if i.ecosystem == "Debian:12" and i.hostname == "debian:12")
        new_open = open_ids(s, new.id)
        ledger = s.scalars(select(LedgerEntry).where(LedgerEntry.kind == "finding_resolved")).all()
        check("5b. after redeploying on debian:12, debian:11's findings are resolved as not running, and debian:12's are open",
              ctr["complete"] and resolved and all(f.status == "resolved" and ctrmod.NOT_RUNNING in f.reasons for f in resolved)
              and sum(e.data.get("why") == "not running on any host" for e in ledger) >= len(before["legacy"]) and not any(v.startswith("EOL:") for v in new_open)
              and open_ids(s, alpine.id) == before["web1"],  # web1 is gone, but web2 and pod1 still run alpine:3.18
              stopped=out["stopped"], debian11_resolved=len(resolved), debian11_were_open=len(before["legacy"]), debian12_open=len(new_open))

        # the evidence pack over all of it verifies offline, as an auditor would check it
        z = zipfile.ZipFile(io.BytesIO(c.get("/api/evidence/pack", params={"days": 1}).content))
        fp = c.get("/api/evidence/public-key").json()["fingerprint_sha256"]
        problems = verify(z.read("pack.json"), z.read("pack.sig").decode(), z.read("public_key.pem"), fp)
        pack = json.loads(z.read("pack.json"))
        check("evidence pack verifies, its findings including the images'", not problems and any(f["host"] == "debian:11" for f in pack.get("findings", [])),
              problems=problems, resolved=pack["metrics"]["resolved"],
              containers_reported=len(Session().scalars(select(LedgerEntry).where(LedgerEntry.kind == "containers_reported")).all()))
    except Exception as e:
        failures.append(f"crashed: {type(e).__name__}: {e}"[:500])
        note("crashed", error=f"{type(e).__name__}: {e}"[:2000])
        raise
    finally:
        log.append({"result": "PASS" if not failures else "FAIL", "failures": failures})
        OUT.write_text(json.dumps(log, indent=2, default=str), encoding="utf-8")
        if not keep and not REUSE:
            if getattr(setup, "keepalive", None):
                setup.keepalive.kill()
            names = subprocess.run(["wsl", "-l", "-q"], capture_output=True).stdout.decode("utf-16-le", errors="replace").split()
            if NAME in names:
                subprocess.run(["wsl", "--unregister", NAME], capture_output=True)
                note("distro destroyed", name=NAME)
        shutil.rmtree(TMP, ignore_errors=True)
    print("RESULT:", "PASS" if not failures else f"FAIL {failures}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main(keep="--keep" in sys.argv))
