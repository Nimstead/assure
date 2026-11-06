"""Noise review with every curated app batch installed (todo: Checkpoint G), in a DISPOSABLE Windows VM (sandbox/winvm.py).

Every app the batches name goes on one VM at an old version, then each is updated. At both points each WinApp finding is
judged by a second, separate reading of NVD's raw CPE data: its CVE must list the product, the version must be in range, and
nothing may tie it to another platform. CVEs that reading says apply but that opened no finding are listed too. Anything
that disagrees is written out for review by hand: this reports disagreements, it doesn't decide who is right.

Run from api/:  uv run python ../sandbox/winnoise.py VM_NAME [--keep] [--resume]   --resume keeps the apps a stopped run left. Writes sandbox/last_run_winnoise.json.
"""

import gzip
import json
import os
import re
import sys
import tempfile
from pathlib import Path

import winapps_e2e as e  # noqa: E402  (reads VM_NAME from argv)
from fastapi.testclient import TestClient
from signin import signup

from nimstead import feeds, winapps  # noqa: E402
from nimstead.db import make_sessionmaker  # noqa: E402

# --part=2/3: this VM installs every third app from the second on, so every curated app fits on some VM's disk (one VM ran out at 50)
PART = next((a[7:] for a in sys.argv if a.startswith("--part=")), None)
OUT = Path(__file__).with_name(f"last_run_winnoise_part{PART.replace('/', 'of')}.json" if PART else "last_run_winnoise.json")
SKIP = {"OctopusDeploy.Server", "PaperCutSoftware.NG"}  # winget couldn't install either in batch 7 (30-minute timeouts)
TMP = Path(tempfile.mkdtemp(prefix="nimstead-sbx-noise-"))
KEYS = {c for p in winapps.PRODUCTS for c in (p.cpes or (p.key,))}
TO_KEY = {c: p.key for p in winapps.PRODUCTS for c in (p.cpes or (p.key,))}


def nums(v):
    return [int(x) for x in re.findall(r"\d+", v)]


def cmp(a, b):
    a, b = nums(a), nums(b)
    n = max(len(a), len(b))
    a, b = a + [0] * (n - len(a)), b + [0] * (n - len(b))
    return (a > b) - (a < b)


def applies(m, version):
    """This reading's own answer: does this cpeMatch cover this version?"""
    cpe = m["criteria"].split(":")[5]
    if not any(k in m for k in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding")):
        return cpe == "*" or (cpe != "-" and cmp(cpe, version) == 0)
    return not (("versionStartIncluding" in m and cmp(version, m["versionStartIncluding"]) < 0)
                or ("versionStartExcluding" in m and cmp(version, m["versionStartExcluding"]) <= 0)
                or ("versionEndIncluding" in m and cmp(version, m["versionEndIncluding"]) > 0)
                or ("versionEndExcluding" in m and cmp(version, m["versionEndExcluding"]) >= 0))


assert applies({"criteria": "cpe:2.3:a:x:y:*", "versionEndExcluding": "2.0"}, "1.9.9") and not applies({"criteria": "cpe:2.3:a:x:y:*", "versionEndExcluding": "2.0"}, "2.0")
assert applies({"criteria": "cpe:2.3:a:x:y:1.2"}, "1.2.0") and not applies({"criteria": "cpe:2.3:a:x:y:-"}, "1.2")


def raw_entries(cve):
    """[(product key, cpeMatch, what it's tied to)] for curated products in one raw NVD CVE."""
    out = []
    for cfg in cve.get("configurations") or []:
        tied = [m["criteria"] for n in cfg.get("nodes", []) for m in n["cpeMatch"] if not m.get("vulnerable")]
        other = bool(tied) and not any(":microsoft:windows" in c for c in tied)
        for n in cfg.get("nodes", []):
            for m in n["cpeMatch"]:
                p = m["criteria"].split(":")
                if m.get("vulnerable") and p[2] == "a" and f"{p[3]}:{p[4]}" in KEYS:
                    sw = p[10] not in ("*", "-", "windows")
                    out.append((TO_KEY[f"{p[3]}:{p[4]}"], m, (tied[:2] if other else []) + ([f"target_sw={p[10]}"] if sw else [])))
    return out


def review(inv, opened, raw):
    """Disagreements between the findings and the raw reading, for this inventory."""
    have = {}
    for p in inv["packages"]:
        if p["ecosystem"] == "WinApp" and (hit := winapps.identify(p["name"], p["source"], p["version"])):
            have.setdefault(hit[0], set()).add(hit[1])
    mine = {(x["package"], x["vuln_id"].removesuffix("-v5")) for x in opened if x["ecosystem"] == winapps.ECOSYSTEM}
    unexplained, tied = [], []
    for key, cve in sorted(mine):
        entries = [en for en in raw.get(cve, []) if en[0] == key]
        if key not in have:
            unexplained.append([key, cve, "product isn't installed"])
        elif not entries:
            unexplained.append([key, cve, "NVD's raw data doesn't list it (CVE List v5 or newer than the feed)"])
        elif not any(applies(en[1], v) for en in entries for v in have[key]):
            unexplained.append([key, cve, f"{sorted(have[key])} out of range", [en[1] for en in entries][:3]])
        elif all(en[2] for en in entries if any(applies(en[1], v) for v in have[key])):
            tied.append([key, cve, entries[0][2]])
    missed = sorted({(key, cve) for cve, es in raw.items() for key, m, t in es
                     if key in have and not t and any(applies(m, v) for v in have[key]) and (key, cve) not in mine})
    return {"products": {k: sorted(v) for k, v in have.items()}, "winapp_findings": len(mine), "unexplained": unexplained,
            "tied_to_something_else": tied, "raw_says_applies_no_finding": [list(x) for x in missed]}


def main(keep=False) -> int:
    result = {"steps": e.log}

    def save():
        OUT.write_text(json.dumps(result, indent=1, default=str) + "\n", encoding="utf-8")

    env = {"NIMSTEAD_DB": f"sqlite:///{(TMP / 'n.db').as_posix()}", "NIMSTEAD_SECURE_COOKIES": "0", "NIMSTEAD_OPEN_SIGNUP": "1",
           "NIMSTEAD_INVENTORY_MIN_SECONDS": "0", "NIMSTEAD_SIGNING_KEY_FILE": str(TMP / "sign.pem"),
           "NIMSTEAD_CHECKPOINT_DIR": str(TMP / "cp"), "NIMSTEAD_SECRET_KEY_FILE": str(TMP / "secret.key")}
    os.environ.update(env)
    from nimstead.app import create_app  # reads the cookie setting on import, so only once it's set
    api = TestClient(create_app(env["NIMSTEAD_DB"]))
    raw = {}
    with make_sessionmaker(env["NIMSTEAD_DB"])() as s:
        for feed in [*map(str, range(2010, 2027)), "modified"]:  # before any install: a dead feed fails in minutes, not hours
            vulns = [v["cve"] for v in json.loads(gzip.decompress(feeds._get(None, feeds.NVD_URL.format(feed))))["vulnerabilities"]]
            feeds.sync_winapps(s, vulns)
            raw.update({c["id"]: en for c in vulns if c.get("vulnStatus") != "Rejected" and (en := raw_entries(c))})
            e.note("feed", feed=feed, curated_cves=len(raw))
    assert raw
    signup(api, {"email": "win@example.com", "password": "windows-e2e-password", "org_name": "WinNoise"})
    token = api.post("/api/enroll-tokens").json()["token"]
    agent = api.post("/api/agent/enroll", json={"token": token, "hostname": "noise", "ecosystem": "Windows"}).json()
    auth = {"Authorization": f"Bearer {agent['agent_key']}"}

    def judge(inv):
        r = api.post("/api/agent/inventory", headers=auth, json=inv)
        assert r.status_code == 200, r.text
        return review(inv, api.get("/api/findings", params={"limit": 5000}).json(), raw)

    e.winvm.wait_ready(e.NAME, minutes=90)
    import winfixes
    e.guest(r"New-Item -ItemType Directory -Force C:\nimtest | Out-Null")
    winfixes.runtime()
    py, ag = winfixes.PY, r"C:\nimtest\nimstead_agent.py"
    c = e.winvm.creds(e.NAME)
    e.winvm.vbox("guestcontrol", e.NAME, "copyto", "--username", c["user"], "--password", c["password"],
                 "--target-directory", "C:\\nimtest\\", str(e.ROOT / "agent" / "nimstead_agent.py"))
    assert e.collect(py, ag)["packages"], "the agent can't read inventory here"

    apps = {w: v for w, v in {**e.APPS, **e.NEW, **e.NEW5, **e.NEW6, **e.NEW7}.items() if w not in SKIP}
    mongo = [w for w in apps if "mongo" in w.lower()]  # it hung guest control on a real VM: last, so it can't cost the others
    order = [w for w in apps if w not in mongo] + mongo
    if PART:
        k, n = map(int, PART.split("/"))
        order = order[k - 1::n]
    install = ("winget install --id {} --exact --version {} --silent --accept-package-agreements "
               "--accept-source-agreements --disable-interactivity --scope machine")
    done = json.loads(OUT.read_text(encoding="utf-8"))["installed"] if "--resume" in sys.argv else {}  # apps already on this VM
    installed = result["installed"] = done

    def judged(label):
        inv = e.collect(py, ag)
        assert inv["packages"], "empty inventory: the guest is gone, and judging it would pass with nothing checked"
        result[label] = judge(inv)
        e.note(label, **{k: (v if k == "winapp_findings" else len(v)) for k, v in result[label].items()})
        save()

    def drop_ides():  # they fill the 80 GB guest disk (real VM, 2026-11-01): what's left needs the room
        for wid in order:
            if wid.startswith("JetBrains."):
                e.guest(f"winget uninstall --id {wid} --exact --silent --disable-interactivity", timeout=600)
                installed.get(wid, {})["removed_for_room"] = True

    if done:
        judged("old_part1")
        drop_ides()
    todo = [w for w in order if not (done.get(w) or {}).get("ok")]
    for i, wid in enumerate(todo):
        old = apps[wid][0]
        rc, out = e.guest(install.format(wid, old), timeout=1200)
        if rc != 0 and "No version found" in out and (alt := e.older_version(wid)):
            old = alt
            rc, out = e.guest(install.format(wid, old), timeout=1200)
        if rc != 0 and "No applicable installer" in out:
            rc, out = e.guest(install.format(wid, old).replace(" --scope machine", ""), timeout=1200)
        installed[wid] = {"version": old, "ok": rc == 0, **({} if rc == 0 else {"why": out.strip()[-160:]})}
        e.note("install", i=i, app=wid, version=old, ok=rc == 0)
        if rc != 0:  # one app failing is fine; the guest being gone isn't, and every later step would fail instantly
            assert e.guest("$env:COMPUTERNAME")[0] == 0, "guest control is gone"
        if i == 0 and not done:  # the whole review once, on one app: a bug here shows now, not after hours of installs
            judged("early")
            assert result["early"]["winapp_findings"] or not result["early"]["products"], "an old app opened no findings"
        save()
    judged("old")
    drop_ides()
    for wid in order:
        if installed[wid]["ok"] and not wid.startswith("JetBrains."):
            e.guest(f"winget upgrade --id {wid} --exact --silent --accept-package-agreements --disable-interactivity", timeout=1200)
    judged("updated")
    bad = [x for k in ("old_part1", "old", "updated") for x in result.get(k, {}).get("unexplained", [])]
    result["result"] = f"REVIEW {len(bad)}" if bad else "NOTHING UNEXPLAINED"
    save()
    if not keep:
        e.winvm.destroy(e.NAME)
    return 0


if __name__ == "__main__":
    sys.exit(main(keep="--keep" in sys.argv))
