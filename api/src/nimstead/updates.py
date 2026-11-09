"""Platform updates (DECISIONS 32): which release is running, whether a newer one exists, and the signed release files
agents need.

Run by the hourly feed update. Once a day it looks at the recent GitHub releases and picks the newest one this server's
channel takes (NIMSTEAD_UPDATE_CHANNEL: preview, beta or stable, default stable; a server takes its channel and anything
more stable, DECISIONS 33), judged by the channel in the release's signed manifest, never by GitHub's labels. Each org
hears once per new version. Enabled runs also attempt release/runtime cache refresh for agent distribution. A matching
manifest cache can skip a fetch without checking its signature file. Agents verify relayed files against pinned keys. Applying an
update is deploy/update.sh's job on the Docker host, never the server's: the server can't rebuild itself.
It also fetches the Windows agent's bundled Python zips the signed manifest names (`python-embed-<arch>.zip`, kept only
on a SHA-256 match). NIMSTEAD_UPDATE_CHECK=0 turns all of this off (offline installs: copy release.json, its .sig and
the python-embed-*.zip files from the release page into NIMSTEAD_RELEASE_DIR instead).
"""

import hashlib
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
MAX_RUNTIME = 40 * 1024 * 1024  # one embeddable Python zip is ~14 MB
MAX_LIST = 2 * 1024 * 1024  # the releases API page, with release notes
CHANNELS = ("preview", "beta", "stable")  # least to most proven (scripts/sign_release.py)


def channel() -> str:
    """Return the configured release channel; missing or unrecognised values fall back to stable."""
    c = os.environ.get("NIMSTEAD_UPDATE_CHANNEL", "stable").strip().lower()
    return c if c in CHANNELS else "stable"


def release_channel(rel: dict) -> str:
    """Return a recognized channel from manifest dictionary rel, otherwise preview.

    Missing, unknown or incompatible channel values use the fallback. Does not verify signatures."""
    return rel.get("channel") if rel.get("channel") in CHANNELS else "preview"


def takes(server_channel: str, rel_channel: str) -> bool:
    """Return whether rel_channel is at least as stable as server_channel.

    Both strings must be preview, beta, or stable; an unknown value raises ValueError."""
    return CHANNELS.index(rel_channel) >= CHANNELS.index(server_channel)


def release_dir() -> Path:
    """Return the Path configured by the application for release files and update status."""
    from nimstead.app import RELEASE_DIR  # one setting, defined beside the endpoint that serves it
    return RELEASE_DIR


def current_version() -> str:
    """Return the installed nimstead distribution version, or an empty string when package metadata is absent."""
    try:
        return version("nimstead")
    except PackageNotFoundError:
        return ""


def vtuple(v: str) -> tuple | None:
    """Parse an optional v prefix and three decimal version components into an integer tuple, or return None."""
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
    """Return running/channel/latest fields and the last updater result from local cache.

    Fields are version, channel, running_channel, latest, latest_url, latest_channel,
    update_available, checked and last_update. Latest data is ignored when its
    for_channel differs. Update availability compares three-component version tuples.
    This function does not verify the cached signature, request releases or apply updates.
    Missing/unreadable/invalid JSON files act as empty data. Valid JSON with the wrong
    shape can raise AttributeError or TypeError. Package/backend errors can propagate."""
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
    signing approval has no manifest yet).

    client is caller-owned. running is a three-component version string. Invalid
    running versions return {} after the listing request. ch must name a supported
    channel. Inspect one page of 30 nondraft numeric tags, highest first. A result
    has version, url and channel. Per-release HTTP/size failures are skipped.
    Listing HTTP, JSON/shape and unsupported-channel errors can propagate. The server
    signature check does not validate every agent-manifest field. No files are written."""
    from nimstead.app import verify_manifest  # the keys pinned in the agent this server serves
    page = _get(client, f"https://api.github.com/repos/{REPO}/releases?per_page=30", MAX_LIST).json()
    tags = sorted({str(r.get("tag_name")) for r in page if isinstance(r, dict) and not r.get("draft")
                   and re.fullmatch(r"v\d+\.\d+\.\d+", str(r.get("tag_name")))}, key=vtuple, reverse=True)
    for tag in [t for t in tags if vtuple(running) and vtuple(t) > vtuple(running)]:  # all of them: five previews in a row can hide a stable one
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
    """Fetch the running release's manifest/signature through caller-owned HTTP client.

    Return True when files were stored, False otherwise. A matching cached version
    with an eligible channel skips fetching without checking its signature file.
    HTTP/size failures log and return False. Identical manifest bytes also return False,
    even if the fetched signature differs. Store signature first, then manifest,
    using separate atomic file replacements. This step does not verify either file.
    Filesystem, malformed cache and other unhandled client errors propagate."""
    running = current_version()
    cached = _read("release.json")
    if not running or (cached.get("version") == running and takes(channel(), release_channel(cached))):
        return False
    base = f"https://github.com/{REPO}/releases/download/v{running}/"
    try:
        manifest, sig = _get(client, base + "release.json").content, _get(client, base + "release.json.sig").content
    except (httpx.HTTPError, ValueError) as e:
        log.info("no signed release files for v%s yet: %s", running, e)
        return False
    d = release_dir()
    if (d / "release.json").exists() and (d / "release.json").read_bytes() == manifest:
        return False  # not promoted since the last look
    _write("release.json.sig", sig)
    _write("release.json", manifest)  # the server checks the signature before relaying (app.signed_release)
    return True


def runtime_file(arch: str) -> Path:
    """Return the release-directory Path for the Windows runtime archive named by arch.

    arch is expected to be a trusted architecture name; this function does not validate it or read the file."""
    return release_dir() / f"python-embed-{arch}.zip"


def fetch_runtimes(client: httpx.Client) -> list[str]:
    """Return architecture names fetched now from the cached manifest through HTTP client.

    client remains caller-owned. Verify the cached manifest signature, then use its
    version and runtime entries, without checking the server's running version.
    Keep each zip only on a SHA-256 match. Matching local files are skipped.
    Missing/unreadable manifest files return []. Download HTTP/size/hash failures
    skip that architecture. Missing manifest fields, filesystem and other backend
    errors can propagate. Does not validate or unpack archive contents."""
    from nimstead.app import verify_manifest
    try:
        manifest, sig = (release_dir() / "release.json").read_bytes(), (release_dir() / "release.json.sig").read_text().strip()
    except OSError:
        return []
    rel = verify_manifest(manifest, sig) or {}
    got = []
    for arch, r in (rel.get("runtimes") or {}).items():
        f = runtime_file(arch)
        if f.exists() and hashlib.sha256(f.read_bytes()).hexdigest() == r["sha256"]:
            continue
        try:
            body = _get(client, f"https://github.com/{REPO}/releases/download/v{rel['version']}/{f.name}", MAX_RUNTIME).content
        except (httpx.HTTPError, ValueError) as e:
            log.info("runtime %s for v%s not fetched: %s", arch, rel.get("version"), e)
            continue
        if hashlib.sha256(body).hexdigest() != r["sha256"]:
            log.warning("runtime %s for v%s doesn't match its signed SHA-256; not stored", arch, rel.get("version"))
            continue
        _write(f.name, body)
        got.append(arch)
    return got


def check(s: Session, client: httpx.Client | None = None) -> dict:
    """Refresh release files and daily release discovery, and queue update notifications.

    s is the database Session; client optionally supplies an httpx.Client and remains caller-owned.
    Return a result dictionary, or a skipped reason when update checks are disabled. Discovery HTTP
    errors are returned as error text. Storage and other unhandled backend errors propagate.
    Normal fields are release_files_fetched, runtimes_fetched, latest and alerted.
    A failed discovery can replace latest with error. Files change and notifications
    can be queued through s. This function does not explicitly commit s. Malformed
    cached timestamps can fail before the discovery-error handler."""
    if os.environ.get("NIMSTEAD_UPDATE_CHECK", "1") == "0":
        return {"skipped": "NIMSTEAD_UPDATE_CHECK=0"}
    own = client is None
    client = client or httpx.Client(headers={"User-Agent": "nimstead-assure"})
    out: dict = {}
    try:
        out["release_files_fetched"] = fetch_release_files(client)
        out["runtimes_fetched"] = fetch_runtimes(client)
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
