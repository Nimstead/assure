"""Platform updates (DECISIONS 32): which release is running, whether a newer one exists, and the signed release files
agents need.

Run by the hourly feed update. Once a day it looks at the recent GitHub releases and picks the newest one this server's
channel takes (NIMSTEAD_UPDATE_CHANNEL: preview, beta or stable, default stable; a server takes its channel and anything
more stable, DECISIONS 33), judged by the channel in the release's signed manifest, never by GitHub's labels. Each org
hears once per new version. Every run it also fetches release.json + its signature for the running version if they're missing, so agents
can update themselves (the server only relays them; agents check the signature against the keys they pin). Applying an
update is deploy/update.sh's job on the Docker host, never the server's: the server can't rebuild itself.
NIMSTEAD_UPDATE_CHECK=0 turns all of this off (offline installs: copy the two files from the release page into
NIMSTEAD_RELEASE_DIR instead).
"""

import json
import logging
import os
import re
from datetime import datetime, timedelta
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from nimstead import notify
from nimstead.db import Org, now

log = logging.getLogger(__name__)
REPO = "Nimstead/assure"
CHECK_EVERY = timedelta(hours=24)
MAX_FILE = 64 * 1024
MAX_LIST = 2 * 1024 * 1024  # the releases API page, with release notes
CHANNELS = ("preview", "beta", "stable")  # least to most proven (scripts/sign_release.py)
CANDIDATES = 5  # newest releases above ours whose manifests are checked per daily run


def channel() -> str:
    c = os.environ.get("NIMSTEAD_UPDATE_CHANNEL", "stable").strip().lower()
    return c if c in CHANNELS else "stable"


def release_channel(rel: dict) -> str:
    """A manifest signed before channels existed (0.3.0) counts as preview."""
    return rel.get("channel") if rel.get("channel") in CHANNELS else "preview"


def takes(server_channel: str, rel_channel: str) -> bool:
    return CHANNELS.index(rel_channel) >= CHANNELS.index(server_channel)


def release_dir() -> Path:
    from nimstead.app import RELEASE_DIR  # one setting, defined beside the endpoint that serves it
    return RELEASE_DIR


def current_version() -> str:
    try:
        return version("nimstead")
    except PackageNotFoundError:
        return ""


def vtuple(v: str) -> tuple | None:
    m = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", v or "")
    return tuple(int(x) for x in m.groups()) if m else None


def _read(name: str) -> dict:
    try:
        return json.loads((release_dir() / name).read_text())
    except (OSError, ValueError):
        return {}


def _write(name: str, data: dict | bytes) -> None:
    d = release_dir()
    d.mkdir(parents=True, exist_ok=True)
    tmp = d / (name + ".tmp")
    tmp.write_bytes(data if isinstance(data, bytes) else json.dumps(data).encode())
    tmp.replace(d / name)


def status() -> dict:
    """What Settings shows: running version, newest release, and the last deploy/update.sh result."""
    latest, running = _read("latest.json"), current_version()
    if latest.get("for_channel") != channel():  # the channel changed since the last check: that answer no longer applies
        latest = {}
    newer = vtuple(latest.get("version") or "") and vtuple(running) and vtuple(latest["version"]) > vtuple(running)
    mine = _read("release.json")
    return {"version": running, "channel": channel(), "running_channel": release_channel(mine) if mine.get("version") == running else None,
            "latest": latest.get("version"), "latest_url": latest.get("url"), "latest_channel": latest.get("channel"),
            "update_available": bool(newer), "checked": latest.get("checked"), "last_update": _read("update-status.json") or None}


def _get(client: httpx.Client, url: str, limit: int = MAX_FILE) -> httpx.Response:
    r = client.get(url, follow_redirects=True, timeout=30)  # release downloads redirect to GitHub's object storage
    r.raise_for_status()
    if len(r.content) > limit:
        raise ValueError(f"{url}: larger than {limit} bytes")
    return r


def newest_for_channel(client: httpx.Client, running: str, ch: str) -> dict:
    """The newest release above `running` whose signed manifest is for `ch` or a more stable channel; {} if none.
    Releases whose manifest is missing, unsigned or for another version are skipped (a release still waiting for its
    signing approval has no manifest yet)."""
    from nimstead.app import verify_manifest  # the keys pinned in the agent this server serves
    page = _get(client, f"https://api.github.com/repos/{REPO}/releases?per_page=30", MAX_LIST).json()
    tags = sorted({str(r.get("tag_name")) for r in page if isinstance(r, dict) and not r.get("draft")
                   and re.fullmatch(r"v\d+\.\d+\.\d+", str(r.get("tag_name")))}, key=vtuple, reverse=True)
    for tag in [t for t in tags if vtuple(running) and vtuple(t) > vtuple(running)][:CANDIDATES]:
        base = f"https://github.com/{REPO}/releases/download/{tag}/"
        try:
            manifest, sig = _get(client, base + "release.json").content, _get(client, base + "release.json.sig").text
        except (httpx.HTTPError, ValueError):
            continue
        rel = verify_manifest(manifest, sig)
        if rel and rel.get("version") == tag[1:] and takes(ch, release_channel(rel)):
            return {"version": tag[1:], "url": f"https://github.com/{REPO}/releases/tag/{tag}", "channel": release_channel(rel)}
    return {}


def fetch_release_files(client: httpx.Client) -> bool:
    """release.json + .sig for the running version, if missing or left over from the previous version. True when fetched now."""
    running = current_version()
    if not running or _read("release.json").get("version") == running:
        return False
    base = f"https://github.com/{REPO}/releases/download/v{running}/"
    try:
        manifest, sig = _get(client, base + "release.json").content, _get(client, base + "release.json.sig").content
    except (httpx.HTTPError, ValueError) as e:
        log.info("no signed release files for v%s yet: %s", running, e)
        return False
    _write("release.json.sig", sig)
    _write("release.json", manifest)  # the server checks the signature before relaying (app.signed_release)
    return True


def check(s: Session, client: httpx.Client | None = None) -> dict:
    if os.environ.get("NIMSTEAD_UPDATE_CHECK", "1") == "0":
        return {"skipped": "NIMSTEAD_UPDATE_CHECK=0"}
    own = client is None
    client = client or httpx.Client(headers={"User-Agent": "nimstead-assure"})
    out: dict = {}
    try:
        out["release_files_fetched"] = fetch_release_files(client)
        latest = _read("latest.json")
        checked = latest.get("checked")
        if checked and latest.get("for_channel") == channel() and now() - datetime.fromisoformat(checked) < CHECK_EVERY:
            out["latest"] = latest.get("version")
        else:
            try:
                found = newest_for_channel(client, current_version(), channel())
                keep = {"alerted": latest["alerted"]} if latest.get("alerted") else {}
                latest = {**keep, **found, "for_channel": channel(), "checked": now().isoformat()}
                _write("latest.json", latest)
                out["latest"] = latest.get("version")
            except (httpx.HTTPError, ValueError) as e:
                log.info("release check failed: %s", e)  # offline is normal; try again next run
                out["error"] = str(e)[:200]
        out["alerted"] = _alert(s)
    finally:
        if own:
            client.close()
    return out


def _alert(s: Session) -> list[str]:
    """Each org hears once about a new release and once about each failed update attempt."""
    st, latest, sent = status(), _read("latest.json"), []
    if st["update_available"] and latest.get("alerted") != st["latest"]:
        text = (f"Nimstead Assure {st['latest']} ({st['latest_channel']}) is available (running {st['version']}, following the "
                f"{st['channel']} channel): {st['latest_url']}. "
                "deploy/update.sh installs it, with a database backup and automatic rollback.")
        for org_id in s.scalars(select(Org.id)):
            notify.notify(s, org_id, "update_available", text)
        _write("latest.json", {**latest, "alerted": st["latest"]})
        sent.append("update_available")
    last = st["last_update"]
    if last and last.get("outcome") != "updated" and not last.get("alerted"):
        text = f"Nimstead Assure update to {last.get('to')} failed: {last.get('error')}. {last.get('outcome_detail', '')}".strip()
        for org_id in s.scalars(select(Org.id)):
            notify.notify(s, org_id, "update_failed", text, urgent=last.get("outcome") == "rollback_failed")
        _write("update-status.json", {**last, "alerted": True})
        sent.append("update_failed")
    return sent
