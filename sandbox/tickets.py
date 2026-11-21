"""Tickets proof (tasks/plan-tickets.md T9, tasks/spec-tickets.md success criteria 2-4) against a REAL GitLab CE in a
DISPOSABLE WSL Debian distro, behind TLS from its own test CA, with the real agent's inventory and the real API.

Run from api/:  uv run python ../sandbox/tickets.py [--keep] [--reuse nimstead-sbx-NAME]
- Creates nimstead-sbx-tkt-<hex>, installs Docker, runs gitlab/gitlab-ce with https://gitlab.sbx.test:8943 (a test CA made
  in the distro), and unregisters the distro at the end (unless --keep).
- The API runs in-process on a throwaway SQLite DB with real OSV (Debian 13), KEV and EPSS data; the real agent's `collect`
  runs as root in the distro and this script relays what it sends, as sbx.py does. gitlab.sbx.test resolves to 127.0.0.1
  in this process only (WSL forwards the port), so the tracker is a private address: the run proves the guard refuses it
  until NIMSTEAD_ALLOW_PRIVATE_HOSTS names it.
- Machines: pay-1 (the distro itself) and pay-2 (its inventory, relayed under a second name) owned by Payments, routed to
  payments/app; plat-1 owned by Platform, which has no route, so its tickets go to the default project platform/ops.
Writes sandbox/last_run_tickets.json: every step, and PASS only if every check passed.
"""

import importlib.util
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "nimstead-sbx-"
REUSE = sys.argv[sys.argv.index("--reuse") + 1] if "--reuse" in sys.argv else None
NAME = REUSE or PREFIX + "tkt-" + secrets.token_hex(3)
TMP = Path(tempfile.mkdtemp(prefix="nimstead-sbx-tkt-"))
OUT = Path(__file__).with_name("last_run_tickets.json")
HOST, PORT = "gitlab.sbx.test", 8943
SITE = f"https://{HOST}:{PORT}"
GL_SECRET = "glpat-" + secrets.token_hex(12)  # set on a fresh root account's access token in this throwaway GitLab only
HOSTILE = "evil``` @root [x](https://evil.example) <img src=https://evil.example/p.png>\n/close\n#1 ~bug"
os.environ.update(NIMSTEAD_SECURE_COOKIES="0", NIMSTEAD_INVENTORY_MIN_SECONDS="0", NIMSTEAD_SIGNING_KEY_FILE=str(TMP / "signing.pem"),
                  NIMSTEAD_PUBLIC_URL="https://nimstead.sbx.test")
os.environ.pop("NIMSTEAD_ALLOW_PRIVATE_TARGETS", None)
os.environ.pop("NIMSTEAD_ALLOW_PRIVATE_HOSTS", None)

import certifi  # noqa: E402
import httpx  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from signin import signup  # noqa: E402
from sqlalchemy import func, select  # noqa: E402

from nimstead import evidence, feeds, tickets  # noqa: E402
from nimstead.app import create_app  # noqa: E402
from nimstead.db import Asset, Finding, LedgerEntry, Org, Ticket, TicketSettings, make_sessionmaker, new_id  # noqa: E402
from nimstead.versions import comparator_for  # noqa: E402

spec = importlib.util.spec_from_file_location("nimstead_agent", ROOT / "agent" / "nimstead_agent.py")
agentmod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agentmod)

_gai = socket.getaddrinfo
socket.getaddrinfo = lambda host, *a, **kw: _gai("127.0.0.1" if host == HOST else host, *a, **kw)  # this process only

log: list[dict] = []
failures: list[str] = []


def note(step, **kw):
    log.append({"step": step, **kw})
    print(f"[{time.strftime('%H:%M:%S')}] {step}", json.dumps(kw, default=str)[:500] if kw else "", flush=True)


def check(criterion, ok, **kw):
    """One check's verdict, on the record either way."""
    note(f"{'PASS' if ok else 'FAIL'}: {criterion}", **kw)
    if not ok:
        failures.append(criterion)


def wsl(script, timeout=1800, ok=(0,)):
    assert NAME.startswith(PREFIX)  # never run commands in a distro this script didn't make
    p = subprocess.run(["wsl", "-d", NAME, "-u", "root", "--", "sh", "-s"], input=script.replace("\r", "").encode(), capture_output=True, timeout=timeout)
    if p.returncode not in ok:  # the run file is committed: the throwaway GitLab's token never goes in it
        raise RuntimeError(f"sandbox command failed ({p.returncode}): {script[:300]}\n{p.stdout.decode(errors='replace')[-2000:]}\n"
                           f"{p.stderr.decode(errors='replace')[-2000:]}".replace(GL_SECRET, "[token]"))
    return p.stdout.decode(errors="replace")


def setup():
    if not REUSE:
        r = subprocess.run(["wsl", "--install", "Debian", "--name", NAME, "--location", str(TMP / "d"), "--no-launch"], capture_output=True, timeout=1800)
        if r.returncode != 0:
            raise RuntimeError((r.stdout + r.stderr).decode("utf-16-le", errors="replace"))
    note("distro", name=NAME, reused=bool(REUSE))
    setup.keepalive = subprocess.Popen(["wsl", "-d", NAME, "-u", "root", "--", "sleep", "infinity"])  # WSL stops idle distros
    wsl("command -v docker >/dev/null || (apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io python3 openssl curl >/dev/null)")
    wsl("docker info >/dev/null 2>&1 || (nohup dockerd >/var/log/dockerd.log 2>&1 &); for i in $(seq 60); do docker info >/dev/null 2>&1 && exit 0; sleep 1; done; exit 1")
    wsl(f"""set -e
        mkdir -p /opt/tkt/ssl && cd /opt/tkt
        [ -f ca.pem ] || openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=Nimstead tickets test CA" -keyout ca.key -out ca.pem \
          -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -addext "subjectKeyIdentifier=hash" 2>/dev/null
        openssl req -newkey rsa:2048 -nodes -subj "/CN={HOST}" -keyout ssl/{HOST}.key -out gl.csr 2>/dev/null
        printf 'subjectAltName=DNS:{HOST}\\nbasicConstraints=CA:FALSE\\nkeyUsage=critical,digitalSignature,keyEncipherment\\nextendedKeyUsage=serverAuth\\nauthorityKeyIdentifier=keyid\\n' > san.ext
        openssl x509 -req -in gl.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile san.ext -out ssl/{HOST}.crt 2>/dev/null
    """)
    (TMP / "bundle.pem").write_text(Path(certifi.where()).read_text() + "\n" + wsl("cat /opt/tkt/ca.pem"))
    os.environ["SSL_CERT_FILE"] = str(TMP / "bundle.pem")  # the public CAs (feeds) plus the test CA (GitLab)
    config = ("; ".join([f"external_url '{SITE}'", "letsencrypt['enable'] = false", "prometheus_monitoring['enable'] = false",
                         "puma['worker_processes'] = 0", "sidekiq['concurrency'] = 5", "gitlab_rails['usage_ping_enabled'] = false"]))
    wsl(f"""docker inspect gitlab >/dev/null 2>&1 || docker run -d --name gitlab --hostname {HOST} -p {PORT}:{PORT} --shm-size 256m \
        -e GITLAB_OMNIBUS_CONFIG="{config}" -v /opt/tkt/ssl:/etc/gitlab/ssl gitlab/gitlab-ce:latest >/dev/null""", timeout=3600)
    t = time.time()
    while time.time() - t < 1500:  # a first boot reconfigures everything: several minutes
        code = wsl(f"curl -s -o /dev/null -w '%{{http_code}}' --cacert /opt/tkt/ca.pem --resolve {HOST}:{PORT}:127.0.0.1 {SITE}/users/sign_in || true", ok=(0, 7, 28, 35, 52, 56))
        if code.strip() == "200":
            break
        time.sleep(10)
    else:
        raise RuntimeError("GitLab did not come up:\n" + wsl("docker logs --tail 60 gitlab 2>&1", ok=(0, 1)))
    note("GitLab up", seconds=round(time.time() - t))
    rails = ("u = User.find_by_username('root'); t = u.personal_access_tokens.create!(scopes: ['api'], name: 'nimstead', "
             f"expires_at: 7.days.from_now); t.set_token('{GL_SECRET}'); t.save!")
    wsl(f'docker exec gitlab gitlab-rails runner "{rails}"', timeout=900)
    wsl("mkdir -p /opt/nimstead && cat > /opt/nimstead/agent.py <<'NIMSTEAD_AGENT'\n" + (ROOT / "agent" / "nimstead_agent.py").read_text(encoding="utf-8") + "\nNIMSTEAD_AGENT\n")


def gl():
    return httpx.Client(base_url=SITE, headers={"PRIVATE-TOKEN": GL_SECRET}, verify=str(TMP / "bundle.pem"), timeout=30)


def issues(g, project, **params):
    out, page = [], "1"
    while page:
        r = g.get(f"/api/v4/projects/{project.replace('/', '%2F')}/issues", params={"per_page": "100", "page": page, **params})
        r.raise_for_status()
        out += r.json()
        page = r.headers.get("x-next-page")
    return out


def notes(g, project, iid):
    """The comments Nimstead wrote on an issue, oldest first (GitLab's own system notes, such as "changed the description",
    left out)."""
    r = g.get(f"/api/v4/projects/{project.replace('/', '%2F')}/issues/{iid}/notes", params={"sort": "asc", "per_page": "100"})
    return [n["body"] for n in r.json() if not n.get("system")]


def rendered(g, project, text):
    """How GitLab itself renders text in the project (its Markdown API: GitLab Flavored Markdown, references and mentions)."""
    return g.post("/api/v4/markdown", json={"text": text, "gfm": True, "project": project}).json().get("html", "")


def collect():
    inv = json.loads(wsl("cd /opt/nimstead && python3 agent.py collect", timeout=600))
    inv.pop("containers", None)
    inv.pop("neighbours", None)
    inv.get("collection", {}).get("sources", {}).pop("containers", None)
    return inv


def main(keep=False):
    db = f"sqlite:///{(TMP / 'nimstead.db').as_posix()}"
    c = TestClient(create_app(db))
    signup(c, {"email": "sbx@example.com", "password": "sandbox-only-password", "org_name": "Sandbox"})
    Session = make_sessionmaker(db)
    try:
        setup()
        g = gl()
        version = g.get("/api/v4/version").json()
        groups = {}
        for path in ("payments", "platform"):
            r = g.post("/api/v4/groups", json={"name": path.capitalize(), "path": path, "visibility": "private"})
            groups[path] = r.json()["id"] if r.status_code == 201 else g.get(f"/api/v4/groups/{path}").json()["id"]
        for path, project in (("payments", "app"), ("platform", "ops")):
            g.post("/api/v4/projects", json={"name": project, "path": project, "namespace_id": groups[path]})
        note("GitLab ready", version=version.get("version"), projects=["payments/app", "platform/ops"])

        inv = collect()
        with Session() as s:
            t = time.time()
            got = {"kev": feeds.sync_kev(s), "epss": feeds.sync_epss(s), "osv": feeds.sync_osv(s, ["Debian"], only={inv["ecosystem"]})}
            note("feeds synced", seconds=round(time.time() - t), ecosystem=inv["ecosystem"], **{k: str(v)[:120] for k, v in got.items()})
        keys = {}
        for host, owner in (("pay-1", "Payments"), ("pay-2", "Payments"), ("plat-1", "Platform")):
            enrol = c.post("/api/enroll-tokens", json={"owner": owner, "sandbox": True}).json()
            a = c.post("/api/agent/enroll", json={"token": enrol["token"], "hostname": host, "os_name": inv["os_name"], "ecosystem": inv["ecosystem"]}).json()
            keys[host] = {"Authorization": f"Bearer {a['agent_key']}"}
            r = c.post("/api/agent/inventory", json=inv, headers=keys[host])
            assert r.status_code == 200, r.text
        s = Session()
        org_id = s.scalar(select(Org.id))
        by_prio = dict(s.execute(select(Finding.priority, func.count()).where(Finding.status == "open").group_by(Finding.priority)).all())
        note("machines reported", packages=len(inv["packages"]), ecosystem=inv["ecosystem"], open_by_priority=by_prio)

        cfg = {"kind": "gitlab", "site": SITE, "user": "", "token": GL_SECRET, "default_project": "platform/ops",
               "routes": [{"owner": "Payments", "project": "payments/app"}], "min_priority": "low", "enabled": False}
        assert c.put("/api/settings/tickets", json=cfg).status_code == 200
        r = c.post("/api/settings/tickets/test").json()
        check("a tracker at a private address is refused until the operator names it", not r["ok"] and "private" in r["message"], message=r["message"])
        os.environ["NIMSTEAD_ALLOW_PRIVATE_HOSTS"] = HOST
        r = c.post("/api/settings/tickets/test").json()
        check("Test connection signs in and finds both projects", r["ok"] and "payments/app" in r["message"] and "platform/ops" in r["message"], message=r["message"])

        p = c.get("/api/settings/tickets/preview").json()
        before = issues(g, "payments/app", state="all") + issues(g, "platform/ops", state="all")
        check("Preview lists tickets and writes nothing", p["tickets"] > 0 and not before, would_open=len(p["open"]), findings=p["findings"])

        assert c.put("/api/settings/tickets", json={**cfg, "token": None, "enabled": True}).status_code == 200
        assert c.post("/api/settings/tickets/sync").status_code == 202  # the endpoint's own path once; the rest call the sync directly
        syncs = [s.get(TicketSettings, org_id, populate_existing=True).last_sync]
        while syncs[-1].get("waiting"):
            syncs.append(tickets.sync(s, org_id))
        want, _ = tickets.desired(s, org_id, s.get(TicketSettings, org_id, populate_existing=True))
        opened = {p: issues(g, p, labels="nimstead", state="opened") for p in ("payments/app", "platform/ops")}
        labels = {(proj, lab) for proj, xs in opened.items() for i in xs for lab in i["labels"] if lab.startswith("nimstead-") and len(lab) == 21}
        expect = {(gp["project"], f"nimstead-{fp}") for fp, gp in want.items()}
        check("every open finding at the threshold is in exactly one open issue, and no open issue lacks one",
              labels == expect and sum(map(len, opened.values())) == len(want),
              groups=len(want), open_issues={k: len(v) for k, v in opened.items()}, syncs=syncs)
        check("the first sync stopped at 100 changes and the next finished", len(want) <= tickets.MAX_WRITES or (len(syncs) > 1 and syncs[0]["waiting"] > 0),
              first=syncs[0])

        # a fix verified by the machine's own inventory: upgrade a package in the distro for real, report, sync
        wsl("apt-get update -qq >/dev/null", timeout=900)
        upgradable = {}
        for line in wsl("apt list --upgradable 2>/dev/null").splitlines()[1:]:
            if m := re.match(r"([^/]+)/\S+ (\S+)", line):
                upgradable[m[1]] = m[2]
        pay = {fp: gp for fp, gp in want.items() if gp["owner"] == "Payments" and gp["action"]["kind"] == "package"}
        srcs = {p["name"]: (p.get("source") or p["name"]) for p in inv["packages"]}
        cmp = comparator_for(inv["ecosystem"])
        pay1_id = s.scalar(select(Asset.id).where(Asset.hostname == "pay-1"))

        def reaches(gp):  # the upgrade clears every finding of the package on the machine: each has a fix the repository offers
            pkg = gp["action"]["package"]
            fixes = s.scalars(select(Finding.fixed_version).where(Finding.asset_id == pay1_id, Finding.package == pkg, Finding.status == "open")).all()
            installed = [b for b, src in srcs.items() if src == pkg]
            return (bool(fixes) and all(fixes) and bool(installed) and all(b in upgradable for b in installed)
                    and all(cmp(upgradable[b], f) >= 0 for b in installed for f in fixes))  # dpkg order, epochs included
        target = next((gp for gp in sorted(pay.values(), key=lambda x: -x["findings"]) if reaches(gp)), None)
        check("a Payments ticket's package can really be upgraded in the distro", target is not None, upgradable=len(upgradable))
        if target:
            fp = target["fingerprint"]
            row = s.scalar(select(Ticket).where(Ticket.fingerprint == fp))
            binaries = sorted(b for b, src in srcs.items() if src == target["action"]["package"])
            wsl(f"DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --only-upgrade {' '.join(binaries)} >/dev/null", timeout=900)
            fixed_inv = collect()
            c.post("/api/agent/inventory", json=fixed_inv, headers=keys["pay-1"])
            tickets.sync(s, org_id)
            issue = g.get(f"/api/v4/projects/payments%2Fapp/issues/{row.key}").json()
            said = notes(g, "payments/app", row.key)
            still = s.scalars(select(Finding.id).where(Finding.asset_id == pay1_id, Finding.package == target["action"]["package"], Finding.status == "open")).all()
            check("a machine fixed by its own inventory leaves the ticket with the version it now has, and the ticket stays open for the other",
                  issue["state"] == "opened" and not still and any("pay-1  fixed" in n and "in the machine's inventory" in n for n in said),
                  package=target["action"]["package"], binaries=binaries, note=said[-1][:300] if said else None, still_open_on_pay1=len(still))
            c.post("/api/agent/inventory", json=fixed_inv, headers=keys["pay-2"])
            tickets.sync(s, org_id)
            issue = g.get(f"/api/v4/projects/payments%2Fapp/issues/{row.key}").json()
            said = notes(g, "payments/app", row.key)
            check("when no finding is left the ticket closes, saying why each machine left",
                  issue["state"] == "closed" and any("closing it" in n and "pay-2  fixed" in n for n in said), note=said[-1][:300] if said else None)
            c.post("/api/agent/inventory", json=inv, headers=keys["pay-2"])  # pay-2 is back on the old version: a regression
            tickets.sync(s, org_id)
            issue = g.get(f"/api/v4/projects/payments%2Fapp/issues/{row.key}").json()
            said = notes(g, "payments/app", row.key)
            check("a regression reopens the same issue, naming the machine", issue["state"] == "opened" and "open again" in said[-1] and "pay-2" in said[-1],
                  note=said[-1][:300])

        other = next(t for t in s.scalars(select(Ticket).where(Ticket.state == "open", Ticket.project == "platform/ops")))
        g.put(f"/api/v4/projects/platform%2Fops/issues/{other.key}", json={"state_event": "close"})  # as a person would
        tickets.sync(s, org_id)
        issue = g.get(f"/api/v4/projects/platform%2Fops/issues/{other.key}").json()
        said = notes(g, "platform/ops", other.key)
        check("an issue closed by hand while findings are open is reopened with the evidence",
              issue["state"] == "opened" and "closed in the tracker" in said[-1], issue=other.key)

        gone = next(t for t in s.scalars(select(Ticket).where(Ticket.state == "open", Ticket.project == "platform/ops", Ticket.id != other.id)))
        old_key = gone.key
        g.delete(f"/api/v4/projects/platform%2Fops/issues/{old_key}")
        tickets.sync(s, org_id)
        s.refresh(gone)
        found = issues(g, "platform/ops", labels=f"nimstead-{gone.fingerprint}", state="all")
        check("an issue deleted in the tracker is opened afresh, once", len(found) == 1 and str(found[0]["iid"]) == gone.key != old_key,
              old=old_key, new=gone.key)

        lost = next(t for t in s.scalars(select(Ticket).where(Ticket.state == "open", Ticket.project == "payments/app")))
        lost_key, lost.key = lost.key, None  # as if the server stopped between GitLab's create and saving the key
        s.commit()
        tickets.sync(s, org_id)
        s.refresh(lost)
        found = issues(g, "payments/app", labels=f"nimstead-{lost.fingerprint}", state="all")
        check("a create that reached GitLab before a crash is found by its label, not repeated", len(found) == 1 and lost.key == lost_key)

        pay1 = s.scalar(select(Asset).where(Asset.hostname == "pay-1"))
        s.add(Finding(id=new_id(), org_id=org_id, asset_id=pay1.id, ecosystem=inv["ecosystem"], package=HOSTILE, installed_version="1<b>",
                      vuln_id="CVE-2099-0001", advisory_ids=["CVE-2099-0001"], fixed_version=None, priority="fix-now", score=90, reasons=[]))
        s.commit()  # what a hostile agent's report could leave in a finding's package name
        tickets.sync(s, org_id)
        hostile = next(t for t in s.scalars(select(Ticket).where(Ticket.org_id == org_id)) if t.action.get("package") == HOSTILE)
        r = g.get(f"/api/v4/projects/payments%2Fapp/issues/{hostile.key}").json()
        html = rendered(g, "payments/app", r["description"]) + rendered(g, "payments/app", r["title"])
        control = rendered(g, "payments/app", HOSTILE)  # the same text outside a block: proves the renderer would act on it
        check("a hostile package name renders inert in GitLab: no link, image, mention or quick action",
              r["state"] == "opened" and not r.get("assignees") and "<img" not in html and "gfm-project_member" not in html
              and 'href="https://evil' not in html and "bug" not in r["labels"] and "evil" in html
              and ("<img" in control or 'href="https://evil' in control),
              state=r["state"], labels=r["labels"], control_sample=control[:300], html_sample=html[html.find("evil") - 200:][:500])

        problems = evidence.verify_chain(s, org_id)
        counted = {k: len(s.scalars(select(LedgerEntry.id).where(LedgerEntry.kind == k)).all())
                   for k in ("tickets_configured", "ticket_opened", "ticket_closed", "ticket_reopened")}
        check("every ticket step is in the ledger and the chain verifies", not problems and all(counted.values()), counted=counted, problems=problems[:3])
    except Exception as e:
        failures.append(f"run stopped: {type(e).__name__}: {e}"[:600])
        note("run stopped", error=f"{type(e).__name__}: {e}"[:2000])
    finally:
        OUT.write_text(json.dumps({"result": "PASS" if not failures else "FAIL", "failures": failures, "distro": NAME,
                                   "when": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "steps": log}, indent=1, default=str))
        if hasattr(setup, "keepalive"):
            setup.keepalive.kill()
        if not keep and not REUSE:
            subprocess.run(["wsl", "--unregister", NAME], capture_output=True, timeout=600)
            note("distro removed", name=NAME)
    print("RESULT:", "PASS" if not failures else f"FAIL {failures}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main(keep="--keep" in sys.argv))
