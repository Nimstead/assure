"""Workloads proof (tasks/spec-workloads.md success criteria 1-5 and 7) in a DISPOSABLE WSL Fedora 44 distro: real Docker,
Podman, containerd and CRI-O, real images and the real agent.

Run from api/:  uv run python ../sandbox/workloads.py [--keep] [--reuse nimstead-sbx-NAME]
- Creates nimstead-sbx-wl-<hex> (Fedora 44, for its containerd, CRI-O and crictl packages; Debian ships no crictl), installs
  moby-engine, podman, containerd, cri-o and cri-tools from Fedora's own repositories, builds and pulls the images below, and
  unregisters the distro at the end (unless --keep). --reuse runs against an existing nimstead-sbx-* distro (development).
- Kubernetes: containers are created through the CRI exactly as the kubelet creates them (its io.kubernetes.* labels, the image
  by its id) on containerd and on CRI-O; a k3s download was refused by the session's safety policy, and the kubelet only
  calls the same CRI.
- WSL2 distros share one network namespace: run it while no other distro runs Docker or CRI-O (their bridge and CRI-O's
  metrics port 9537 would collide).
- The API runs in-process on a throwaway SQLite DB with real OSV, KEV and EPSS data; the real agent's `collect` runs as root
  in the distro and this script relays its bodies as `report` does (as sandbox/containers.py).
- Oracles: Syft (anchore/syft, run as a container) for what is installed, read through Nimstead's own SBOM parser so names
  and versions are compared in one form; the OSV API for what is vulnerable.
Writes sandbox/last_run_workloads.json: every step, and PASS only if every criterion passed.
"""

import base64
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
NAME = REUSE or PREFIX + "wl-" + secrets.token_hex(3)
TMP = Path(tempfile.mkdtemp(prefix="nimstead-sbx-wl-"))
OUT = Path(__file__).with_name("last_run_workloads.json")
os.environ.update(NIMSTEAD_SECURE_COOKIES="0", NIMSTEAD_INVENTORY_MIN_SECONDS="0", NIMSTEAD_SIGNING_KEY_FILE=str(TMP / "signing.pem"))

import httpx  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from signin import signup  # noqa: E402
from sqlalchemy import select  # noqa: E402

from nimstead import feeds, sbom  # noqa: E402
from nimstead.app import create_app  # noqa: E402
from nimstead.db import Asset, Container, Finding, InstalledPackage, LedgerEntry, make_sessionmaker  # noqa: E402
from nimstead.match import canonical_id, normalize_ecosystem  # noqa: E402
from nimstead.verify_pack import verify  # noqa: E402

spec = importlib.util.spec_from_file_location("nimstead_agent", ROOT / "agent" / "nimstead_agent.py")
agentmod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agentmod)

log: list[dict] = []
failures: list[str] = []
APP_ECOS = ("PyPI", "npm", "Maven", "Go")


def note(step, **kw):
    log.append({"step": step, **kw})
    print(f"[{time.strftime('%H:%M:%S')}] {step}", json.dumps(kw, default=str)[:400] if kw else "", flush=True)


def check(criterion, ok, **kw):
    note(f"{'PASS' if ok else 'FAIL'}: {criterion}", **kw)
    if not ok:
        failures.append(criterion)


def wsl(script, timeout=1800, ok=(0,)):
    assert NAME.startswith(PREFIX)  # never run commands in a distro this script didn't make
    p = subprocess.run(["wsl", "-d", NAME, "-u", "root", "--", "sh", "-s"], input=script.replace("\r", "").encode(), capture_output=True, timeout=timeout)
    if p.returncode not in ok:
        raise RuntimeError(f"sandbox command failed ({p.returncode}): {script[:300]}\n{p.stdout.decode(errors='replace')[-2000:]}\n{p.stderr.decode(errors='replace')[-2000:]}")
    return p.stdout.decode(errors="replace")


def put(path, data: bytes):
    """A file into the distro, through base64 so any bytes survive the pipe."""
    wsl(f"mkdir -p $(dirname {path}) && base64 -d > {path} <<'B64'\n{base64.b64encode(data).decode()}\nB64\n")


# ---- what runs ----------------------------------------------------------------------------------------------------
BUILT = {  # built for the proof: name -> Dockerfile
    "py-app": "FROM python:3.12-slim\nRUN pip install --no-cache-dir -q requests==2.19.1 urllib3==1.23 Django==3.2 Jinja2==2.10.1 Werkzeug==0.15.0\n",
    "node-app": "FROM node:20-slim\nWORKDIR /usr/src/app\nRUN npm init -y >/dev/null && npm install -s --no-audit --no-fund lodash@4.17.20 minimist@1.2.0 express@4.17.1\n",
    "java-app": ("FROM eclipse-temurin:17-jre\n"
                 "ADD https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar /opt/app/lib/\n"
                 "ADD https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-databind/2.9.10/jackson-databind-2.9.10.jar /opt/app/lib/\n"),
    # criterion 3: what the package manager installed is its own; only pip's additions are PyPI's
    "deb-owned": "FROM debian:12\nRUN apt-get update -qq && apt-get install -y -qq python3-requests python3-pip >/dev/null && pip install -q --break-system-packages Flask==1.0\n",
    "apk-owned": "FROM alpine:3.20\nRUN apk add -q py3-requests py3-pip && pip install -q --break-system-packages Jinja2==2.10.1\n",
}
PULLED = {  # real images: a war with nested jars, and Go services
    "jenkins": "jenkins/jenkins:2.319.1-lts-jdk11",
    "coredns": "registry.k8s.io/coredns/coredns:v1.10.1",
    "node-exporter": "quay.io/prometheus/node-exporter:v1.5.0",
}
CRITERION_1 = ("py-app", "node-app", "java-app", "jenkins", "coredns", "node-exporter")
MARKER = "/etc/nimstead-marker"  # on the host only: if the walk ever left a container, "hostleak" would be a package
HOSTILE = {  # name -> Dockerfile body after FROM busybox:1.36 (files from CTX are in the build context)
    "h-links": (f"RUN mkdir -p /app/node_modules /usr/local/lib/python3.12 && ln -s {MARKER}/node_modules/hostleak /app/node_modules/hostleak"
                f" && ln -s ../../../../../../..{MARKER}/site-packages /usr/local/lib/python3.12/site-packages && ln -s {MARKER} /app/lib"),
    "h-loop": "RUN mkdir -p /app/a && ln -s /app /app/a/up && ln -s . /app/self",
    "h-fifo": ("RUN mkdir -p /app/node_modules/f /usr/local/lib/python3.12/site-packages/f-1.dist-info"
               " && mkfifo /app/node_modules/f/package.json /usr/local/lib/python3.12/site-packages/f-1.dist-info/METADATA /app/evil.jar"),
    "h-sparse": "RUN mkdir /app && dd if=/dev/zero of=/app/app.jar bs=1 count=0 seek=200M 2>/dev/null",
    "h-bomb": "COPY bomb.jar /app/bomb.jar",
    "h-deep": "RUN mkdir -p /app/$(seq -s/ 1 64) && echo x > /app/$(seq -s/ 1 64)/end",
    "h-wide": "RUN mkdir /many && cd /many && seq 1 210000 | xargs touch",
}


def bomb_jar() -> bytes:
    """A jar whose nested jar holds 600 MB of zeros (declared past the 50 MB nested cap, so never inflated), beside one of
    40 MB (under it: inflated, bounded, and read)."""
    def zeros_jar(mb):
        b = io.BytesIO()
        with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z, z.open("META-INF/maven/bomb/zeros/pom.properties", "w", force_zip64=True) as f:
            chunk = b"\0" * (1 << 20)
            for _ in range(mb):
                f.write(chunk)
        return b.getvalue()
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        z.writestr("META-INF/maven/bomb/outer/pom.properties", "groupId=bomb\nartifactId=outer\nversion=1.0\n")
        z.writestr("BOOT-INF/lib/huge.jar", zeros_jar(600))
        z.writestr("BOOT-INF/lib/big.jar", zeros_jar(40))
    return out.getvalue()


def setup():
    if not REUSE:
        r = subprocess.run(["wsl", "--install", "FedoraLinux-44", "--name", NAME, "--location", str(TMP / "d"), "--no-launch"], capture_output=True, timeout=1800)
        if r.returncode != 0:
            raise RuntimeError((r.stdout + r.stderr).decode("utf-16-le", errors="replace"))
    note("distro", name=NAME, reused=bool(REUSE))
    setup.keepalive = subprocess.Popen(["wsl", "-d", NAME, "-u", "root", "--", "sleep", "infinity"])  # WSL stops idle distros
    wsl("rpm -q cri-tools crun >/dev/null 2>&1 || dnf -q -y install moby-engine podman containerd cri-o crun cri-tools containernetworking-plugins python3 >/dev/null",
        timeout=3600)
    wsl("systemctl start containerd crio docker && sleep 2 && systemctl is-active containerd crio docker >/dev/null "
        "|| { journalctl -u crio -u docker --no-pager -n 20 | cut -c1-300; exit 1; }")
    note("runtimes", versions=wsl("docker --version; podman --version; containerd --version; crio --version | head -1; crictl --version").strip().split("\n"),
         os=wsl(". /etc/os-release; echo $PRETTY_NAME").strip())
    hostleak = io.BytesIO()
    with zipfile.ZipFile(hostleak, "w") as z:
        z.writestr("META-INF/maven/hostleak/hostleak/pom.properties", "groupId=hostleak\nartifactId=hostleak\nversion=1.0\n")
    wsl(f"mkdir -p {MARKER}/node_modules/hostleak {MARKER}/site-packages/hostleak-1.0.dist-info && "
        f"echo '{{\"name\": \"hostleak\", \"version\": \"1.0.0\"}}' > {MARKER}/node_modules/hostleak/package.json && "
        f"printf 'Name: hostleak\\nVersion: 1.0\\n' > {MARKER}/site-packages/hostleak-1.0.dist-info/METADATA")
    put(f"{MARKER}/hostleak.jar", hostleak.getvalue())
    wsl("mkdir -p /opt/nimstead && cat > /opt/nimstead/agent.py <<'NIMSTEAD_AGENT'\n" + (ROOT / "agent" / "nimstead_agent.py").read_text(encoding="utf-8") + "\nNIMSTEAD_AGENT\n")
    put("/tmp/ctx/bomb.jar", bomb_jar())  # noqa: S108 — a path inside the disposable distro
    t = time.time()
    for name, dockerfile in BUILT.items():
        wsl(f"cd /tmp/ctx && docker build -q -t {name} -f - . >/dev/null <<'DOCKERFILE'\n{dockerfile}DOCKERFILE\n", timeout=3600)
    for name, body in HOSTILE.items():
        wsl(f"cd /tmp/ctx && docker build -q -t {name} -f - . >/dev/null <<'DOCKERFILE'\nFROM busybox:1.36\n{body}\nDOCKERFILE\n", timeout=3600)
    for ref in PULLED.values():
        wsl(f"docker pull -q {ref} >/dev/null", timeout=3600)
    note("images built and pulled", seconds=round(time.time() - t))
    wsl("for c in $(docker ps -aq); do docker rm -f $c >/dev/null; done; for c in $(podman ps -aq); do podman rm -f $c >/dev/null; done; "
        "for ep in unix:///run/containerd/containerd.sock unix:///var/run/crio/crio.sock; do crictl -r $ep rmp -fa >/dev/null 2>&1; done; true")
    for name in [*BUILT, *HOSTILE]:
        wsl(f"docker run -d --name {name} --entrypoint sleep {name} infinity >/dev/null" if not name.startswith("h-") else
            f"docker run -d --name {name} {name} sleep infinity >/dev/null")
    wsl(f"docker run -d --name jenkins --entrypoint sleep {PULLED['jenkins']} infinity >/dev/null")
    for name in ("coredns", "node-exporter"):  # no shell inside: their own binaries run, on their defaults, in their own network namespace
        wsl(f"docker run -d --name {name} {PULLED[name]} >/dev/null")
    note("docker containers running", names=wsl("docker ps --format '{{.Names}}'").split())


def cri(runtime):
    """Point the node's crictl at containerd or CRI-O, as a node's /etc/crictl.yaml does."""
    sock = {"containerd": "unix:///run/containerd/containerd.sock", "cri-o": "unix:///var/run/crio/crio.sock", "dead": "unix:///run/nimstead-nothing.sock"}[runtime]
    wsl(f"printf 'runtime-endpoint: {sock}\\nimage-endpoint: {sock}\\ntimeout: 10\\n' > /etc/crictl.yaml")


def pod(runtime, ns, name, image_ref):
    """A pod and its container created through the CRI as the kubelet does: its labels, and the image by its id."""
    cri(runtime)
    uid = secrets.token_hex(8)
    script = f"""
set -e
ID=$(crictl inspecti -o json {image_ref} | python3 -c "import json,sys;print(json.load(sys.stdin)['status']['id'])")
mkdir -p /tmp/cri
cat > /tmp/cri/pod-{uid}.json <<J
{{"metadata": {{"name": "{name}", "namespace": "{ns}", "uid": "{uid}", "attempt": 0}},
 "labels": {{"io.kubernetes.pod.name": "{name}", "io.kubernetes.pod.namespace": "{ns}", "io.kubernetes.pod.uid": "{uid}"}},
 "log_directory": "/tmp/cri/logs-{uid}", "linux": {{"security_context": {{"namespace_options": {{"network": 2}}}}}}}}
J
cat > /tmp/cri/ctr-{uid}.json <<J
{{"metadata": {{"name": "app", "attempt": 0}}, "image": {{"image": "$ID", "user_specified_image": "{image_ref}"}},
 "command": ["sleep", "infinity"], "log_path": "app.log",
 "labels": {{"io.kubernetes.container.name": "app", "io.kubernetes.pod.name": "{name}", "io.kubernetes.pod.namespace": "{ns}", "io.kubernetes.pod.uid": "{uid}"}},
 "linux": {{}}}}
J
POD=$(crictl runp /tmp/cri/pod-{uid}.json)
C=$(crictl create $POD /tmp/cri/ctr-{uid}.json /tmp/cri/pod-{uid}.json)
crictl start $C >/dev/null
echo $POD
"""
    return wsl(script).strip().split()[-1]


def collect():
    """The agent's own report path: collect, put the containers line in the inventory's document, split the two bodies."""
    t = time.time()
    inv = json.loads(wsl("cd /opt/nimstead && python3 agent.py collect", timeout=900))
    ctr = inv.pop("containers")
    inv.pop("neighbours", None)
    inv["collection"]["sources"]["containers"] = ctr.pop("line")
    return inv, ctr, round(time.time() - t, 1)


def walk_times():
    """How long one image's application walk takes, per running Docker container (criterion 7)."""
    script = r"""
import importlib.util, json, subprocess, time
spec = importlib.util.spec_from_file_location("a", "/opt/nimstead/agent.py"); a = importlib.util.module_from_spec(spec); spec.loader.exec_module(a)
out = {}
for line in subprocess.run(["docker", "ps", "--format", "{{.Names}} {{.ID}}"], capture_output=True, text=True).stdout.split("\n"):
    if not line.strip():
        continue
    name, cid = line.split()
    full = subprocess.run(["docker", "inspect", "-f", "{{.Id}} {{.State.Pid}}", cid], capture_output=True, text=True).stdout.split()
    root = a.ContainerRoot.of_pid(int(full[1]), container_id=full[0])
    t = time.monotonic()
    rows, lines = a.container_apps(root)
    root.close()
    out[name] = {"seconds": round(time.monotonic() - t, 2), "rows": len(rows), "states": {k: v["state"] for k, v in lines.items()}}
print(json.dumps(out))
"""
    return json.loads(wsl(f"python3 - <<'PY'\n{script}\nPY\n", timeout=900))


def syft(ref):
    """Syft's reading of an image, as Nimstead's own SBOM parser reads it: {(ecosystem, name, version): Syft artifact}."""
    doc = json.loads(wsl(f"docker run --rm -v /var/run/docker.sock:/var/run/docker.sock anchore/syft:latest docker:{ref} -o syft-json -q", timeout=1800))
    out = {}
    for art in doc.get("artifacts", []):
        p = sbom.parse_purl(art.get("purl") or "")
        if p and p[0] in APP_ECOS:
            eco, name, ver = p
            if name == "stdlib":  # Syft writes the toolchain as Go names it (go1.20); the agent in semver form (1.20.0), as OSV compares it
                ver = ver.removeprefix("go")
                ver += ".0" if ver.count(".") == 1 else ""
            out.setdefault((eco, name, ver), art)
    return out, doc.get("descriptor", {}).get("version")


def owned_paths(container):
    """Every path the container's own package manager installed (dpkg's lists, or apk's database), for explaining Syft."""
    text = wsl(f"docker exec {container} sh -c 'cat /var/lib/dpkg/info/*.list 2>/dev/null; cat /lib/apk/db/installed 2>/dev/null' 2>/dev/null || true")
    out, d = set(), ""
    for ln in text.splitlines():
        if ln.startswith("F:"):
            d = "/" + ln[2:]
        elif ln.startswith("R:"):
            out.add(f"{d}/{ln[2:]}")
        elif ln.startswith("/"):
            out.add(ln)
    return out | {"/usr" + p for p in out if p.startswith(("/bin/", "/sbin/", "/lib/"))}


def explain(eco, art, owned):
    """Why Syft names something the agent doesn't, from Syft's own record of how it found it; None if unexplained."""
    md, found = art.get("metadata") or {}, art.get("foundBy") or ""
    where = [loc.get("path") or "" for loc in art.get("locations") or []]
    if eco == "Maven" and not md.get("pomProperties"):
        return "no pom.properties: Syft guessed the coordinates from the manifest or the file name (the agent never guesses)"
    if "lock" in found:
        return "an entry of a lock file, not an installed package's own package.json"
    if eco == "Go" and (art.get("version") in ("(devel)", "") or md.get("mainModule") == art.get("name")):
        return "the binary's own main module: Go records it as (devel), and Syft makes a version up from its VCS stamp"
    if where and all(p in owned for p in where):
        return "installed by the image's own package manager, so judged by its distribution's advisories (DECISIONS 156; Trivy does the same)"
    if eco == "npm" and where and not any("/node_modules/" in p for p in where):
        return ("a package.json outside node_modules: the image's own project, or a tool unpacked from a tarball (yarn in node images); "
                "it can be named like a public package it isn't, so it isn't matched")
    return None


def main(keep=False):
    db = f"sqlite:///{(TMP / 'nimstead.db').as_posix()}"
    c = TestClient(create_app(db))
    signup(c, {"email": "sbx@example.com", "password": "sandbox-only-password", "org_name": "Sandbox"})
    Session = make_sessionmaker(db)
    try:
        setup()
        # Kubernetes: the same image run under Podman and in pods on containerd and CRI-O (criterion 4)
        wsl("docker save py-app -o /tmp/py-app.tar && podman load -q -i /tmp/py-app.tar >/dev/null && ctr -n k8s.io images import /tmp/py-app.tar >/dev/null")
        pref = wsl("podman images --format '{{.Repository}}:{{.Tag}}' | grep py-app | head -1").strip()  # the name podman gave it
        wsl(f"podman run -d --name papi --entrypoint sleep {pref} infinity >/dev/null")
        ctrd_pod = pod("containerd", "payments", "api-7d9f4-x2k", "docker.io/library/py-app:latest")
        crio_pod = pod("cri-o", "billing", "worker-5c6d-q8r", pref)
        cri("containerd")
        inv, ctr, secs = collect()
        ecos = {normalize_ecosystem(i["ecosystem"]) for i in ctr["images"] if i.get("ecosystem")} | {normalize_ecosystem(inv["ecosystem"])} | set(APP_ECOS)
        with Session() as s:
            t = time.time()
            got = {"kev": feeds.sync_kev(s), "epss": feeds.sync_epss(s), "eol": feeds.sync_eol(s)}
            for family in sorted({e.split(":")[0] for e in ecos}):
                try:  # the host's own Fedora has no OSV feed: said, not fatal
                    got[family] = feeds.sync_osv(s, [family], only=ecos)
                except Exception as e:  # noqa: BLE001
                    s.rollback()
                    got[family] = f"skipped: {type(e).__name__}: {e}"[:120]
            note("feeds synced", seconds=round(time.time() - t), ecosystems=sorted(ecos), **{k: str(v)[:120] for k, v in got.items()})
        token = c.post("/api/enroll-tokens", json={"sandbox": True}).json()["token"]
        a = c.post("/api/agent/enroll", json={"token": token, "hostname": "k8s-node-1", "os_name": inv["os_name"], "ecosystem": inv["ecosystem"]}).json()
        h = {"Authorization": f"Bearer {a['agent_key']}"}

        def report(inv, ctr):
            r = c.post("/api/agent/inventory", json=inv, headers=h)
            assert r.status_code == 200, r.text
            r = c.post("/api/agent/containers", json=ctr, headers=h)
            assert r.status_code == 200, r.text
            return r.json()

        note("first report", collect_seconds=secs, sent_complete=ctr["complete"], error=ctr["error"], runtimes=ctr["runtimes"], server=report(inv, ctr))
        s = Session()
        by = {r.name: s.get(Asset, r.image_asset_id) for r in s.scalars(select(Container))}  # container name -> its image asset

        def apps(img):
            return {(p.ecosystem, p.name, p.version) for p in s.scalars(select(InstalledPackage).where(InstalledPackage.asset_id == img.id))
                    if p.ecosystem in APP_ECOS}

        # 1. application packages equal Syft's, every difference explained by how Syft found it
        per, version = {}, None
        for name in CRITERION_1:
            ref = PULLED.get(name, name)
            theirs, version = syft(ref)
            ours = apps(by[name])
            owned = owned_paths(name) if name not in ("coredns", "node-exporter") else set()  # no shell in those: no package manager either
            only_syft = {k: explain(k[0], theirs[k], owned) for k in sorted(set(theirs) - ours)}
            # a jar Syft named from its manifest or file name (no pom.properties in its record) that the agent named from the
            # pom.properties inside it: the same artifact and version, two names (jaxb-core: com.sun.xml.bind or org.glassfish.jaxb)
            guessed = {(k[1].rsplit(":", 1)[-1], k[2]) for k, why in only_syft.items() if k[0] == "Maven" and why and why.startswith("no pom.properties")}
            only_ours = {k: ("the same jar Syft named from its manifest or file name; the agent's name is the pom.properties inside it"
                             if k[0] == "Maven" and (k[1].rsplit(":", 1)[-1], k[2]) in guessed else None) for k in sorted(ours - set(theirs))}
            per[name] = {"image": ref, "agent": len(ours), "syft": len(theirs), "same": len(ours & set(theirs)),
                         "only_agent_explained": [[*k, why] for k, why in only_ours.items() if why][:300],
                         "only_agent": [list(k) for k, why in only_ours.items() if not why][:300],
                         "only_syft_explained": [[*k, why] for k, why in only_syft.items() if why][:300],
                         "only_syft_unexplained": [list(k) for k, why in only_syft.items() if not why][:300],
                         "by_ecosystem": {e: sum(k[0] == e for k in ours) for e in APP_ECOS}}
        check("1. each image's application packages equal Syft's, every difference explained", all(
            not v["only_agent"] and not v["only_syft_unexplained"] and v["same"] > 0 for v in per.values()), syft_version=version, images=per)

        # 2. findings on those packages equal the OSV API's answer for every (ecosystem, name, version)
        agree, records = {}, {}
        with httpx.Client(timeout=120) as http:
            for name in CRITERION_1:
                img = by[name]
                rows = sorted(apps(img))
                theirs = set()
                for i in range(0, len(rows), 500):
                    q = [{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in rows[i:i + 500]]
                    res = http.post("https://api.osv.dev/v1/querybatch", json={"queries": q}).raise_for_status().json()["results"]
                    for (e, n, _), r in zip(rows[i:i + 500], res, strict=True):
                        for vid in {x["id"] for x in r.get("vulns", [])}:
                            rec = records.get(vid) or records.setdefault(vid, http.get(f"https://api.osv.dev/v1/vulns/{vid}").raise_for_status().json())
                            if not rec.get("withdrawn"):
                                theirs.add((e, n, canonical_id(rec)))
                ours = {(f.ecosystem, f.package, f.vuln_id) for f in s.scalars(select(Finding).where(
                    Finding.asset_id == img.id, Finding.status == "open", Finding.ecosystem.in_(APP_ECOS)))}
                agree[name] = {"ours": len(ours), "osv": len(theirs), "only_ours": sorted(map(list, ours - theirs))[:20], "only_osv": sorted(map(list, theirs - ours))[:20]}
        check("2. every application package's findings equal the OSV API's", all(not v["only_ours"] and not v["only_osv"] for v in agree.values())
              and sum(v["ours"] for v in agree.values()) > 20, agreement=agree)

        # 3. no base-image noise: what apt and apk installed is theirs; pip's additions are PyPI's
        owned = {n: sorted(k[1] for k in apps(by[n]) if k[0] == "PyPI") for n in ("deb-owned", "apk-owned")}
        check("3. Debian's python3-requests and Alpine's py3-requests are left to their package managers; pip's packages are read",
              "requests" not in owned["deb-owned"] and "flask" in owned["deb-owned"] and "requests" not in owned["apk-owned"] and "jinja2" in owned["apk-owned"],
              pypi_rows=owned)

        # 4. Kubernetes: kubelet-made containers read through crictl, one image with Podman's, a deleted pod gone, a failing crictl closing nothing
        img = by["papi"]
        runs = sorted((r.runtime, r.name) for r in s.scalars(select(Container).where(Container.image_asset_id == img.id)))
        cri("cri-o")
        inv2, ctr2, _ = collect()
        out2 = report(inv2, ctr2)
        s = Session()
        runs2 = sorted((r.runtime, r.name) for r in s.scalars(select(Container).where(Container.image_asset_id == img.id)))
        wsl(f"crictl -r unix:///run/containerd/containerd.sock stopp {ctrd_pod} >/dev/null && crictl -r unix:///run/containerd/containerd.sock rmp {ctrd_pod} >/dev/null")
        cri("containerd")
        inv3, ctr3, _ = collect()
        out3 = report(inv3, ctr3)
        s = Session()
        runs3 = sorted((r.runtime, r.name) for r in s.scalars(select(Container).where(Container.image_asset_id == img.id)))
        cri("dead")
        inv4, ctr4, _ = collect()
        report(inv4, ctr4)
        s = Session()
        runs4 = sorted((r.runtime, r.name) for r in s.scalars(select(Container).where(Container.image_asset_id == img.id)))
        check("4. containerd and CRI-O containers are read through crictl as namespace/pod/container, share Podman's image, "
              "a deleted pod leaves, a failing crictl closes nothing",
              ("containerd", "payments/api-7d9f4-x2k/app") in runs and ("podman", "papi") in runs
              and ("cri-o", "billing/worker-5c6d-q8r/app") in runs2 and ("containerd", "payments/api-7d9f4-x2k/app") in runs2
              and ("containerd", "payments/api-7d9f4-x2k/app") not in runs3 and ("cri-o", "billing/worker-5c6d-q8r/app") in runs3 and ("podman", "papi") in runs3
              and runs4 == runs3 and ctr4["runtimes"].get("crictl", {}).get("state") == "failed" and not ctr4["complete"],
              with_containerd=runs, with_crio=runs2, crio_report=out2, after_pod_deleted=runs3, deleted_report=out3, crictl_failing=runs4,
              failing=ctr4["runtimes"].get("crictl"), docker_id=wsl("docker inspect -f '{{.Image}}' py-app").strip(), podman_id=img.facts.get("image_id"))

        # 5. hostile images: nothing from the host, no hang, each limit said
        leaked = s.scalar(select(InstalledPackage.id).where(InstalledPackage.name.in_(("hostleak", "hostleak:hostleak"))))
        lines = {n: {k: v for k, v in ((by[n].collection or {}).get("sources") or {}).items() if k in ("python_packages", "npm_packages", "java_archives", "go_modules")}
                 for n in HOSTILE}
        said = {n: " ".join(v.get("error") or "" for v in ls.values()) for n, ls in lines.items()}
        ok5 = (leaked is None and secs < agentmod.CONTAINER_SECONDS and "deeper than" in said["h-deep"] and "budget" in said["h-wide"]
               and "couldn't be read" in said["h-sparse"] and "couldn't be read" in said["h-fifo"]
               and ("Maven", "bomb:outer", "1.0") in apps(by["h-bomb"]))
        check("5. hostile images (links out and climbing, a loop, FIFOs, a 200 MB sparse jar, a nested zip bomb, 64 levels, 210,000 files) read "
              "nothing outside, never hang, and say each limit", ok5, host_file_read=leaked is not None, collect_seconds=secs, lines=lines)

        # 7. the walk's cost per image, inside the pass's budget
        times = walk_times()
        check("7. each image's walk stays inside its budget and the whole pass inside 120 seconds", secs < agentmod.CONTAINER_SECONDS
              and all(v["seconds"] <= agentmod.CONTAINER_WALK_SECONDS + 5 for v in times.values()), collect_seconds=secs, per_image=times)

        # the evidence pack over all of it verifies offline
        z = zipfile.ZipFile(io.BytesIO(c.get("/api/evidence/pack", params={"days": 1}).content))
        fp = c.get("/api/evidence/public-key").json()["fingerprint_sha256"]
        problems = verify(z.read("pack.json"), z.read("pack.sig").decode(), z.read("public_key.pem"), fp)
        check("evidence pack verifies", not problems, problems=problems,
              containers_reported=len(Session().scalars(select(LedgerEntry).where(LedgerEntry.kind == "containers_reported")).all()))
        _ = crio_pod
    except Exception as e:
        failures.append(f"crashed: {type(e).__name__}: {e}"[:500])
        note("crashed", error=f"{type(e).__name__}: {e}"[:2000])
        raise
    finally:
        log.append({"result": "PASS" if not failures else "FAIL", "failures": failures})
        OUT.write_text(json.dumps(log, indent=2, default=str), encoding="utf-8")
        if getattr(setup, "keepalive", None):
            setup.keepalive.kill()
        if not keep and not REUSE:
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
