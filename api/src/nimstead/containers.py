"""Container images the org's hosts run (tasks/plan-containers.md, DECISIONS 138-141).

A host's agent reads its running containers and sends one entry per distinct image content. Each becomes an `image` asset
of the org, found by the server's own hash of everything stored for it (image id, base OS, the image's collection
document and package rows): hosts running one image share one asset and its findings, and no host's report can change
or close an asset another host's report made, only add one. The `container` table says which host runs which image.
Only a host's complete list removes its rows, so silence never closes anything; an image no row points at has its
findings resolved by `scan.rescan` (DECISIONS 140). Images are never remediated (DECISIONS 141).
"""

import hashlib
import json
import os
import re
from collections import Counter
from datetime import timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from nimstead import evidence
from nimstead.db import Asset, Container, Finding, InstalledPackage, RemediationJob, ScanRecord, now
from nimstead.engine.collection import valid_document

MAX_IMAGES_PER_REPORT = 128  # the agent reads at most 128 containers a report
MAX_CONTAINERS_PER_REPORT = 256
MAX_PACKAGES_PER_IMAGE = 10_000  # as the agent's own cap; real images rarely pass 3,000
MAX_IMAGES_PER_ORG = int(os.environ.get("NIMSTEAD_MAX_IMAGES_PER_ORG", "2000"))  # outside the asset quota, so its own cap
# one compromised host can't take the org's share (security review): its rows, the images it runs, and the images it
# introduces a day. 48 a day for the 30 days an unrun image is kept stays under the org's 2,000, whatever it does
MAX_CONTAINERS_PER_HOST, MAX_IMAGES_PER_HOST, MAX_NEW_IMAGES_PER_HOST_DAY = 512, 256, 48
KEEP = timedelta(days=30)  # an image no host has run for this long is deleted; its findings were resolved when it stopped
RUNTIMES = ("docker", "podman")
CRITICALITY = ("low", "medium", "high", "critical")
NOT_RUNNING = "Closed: no host runs this image any more (each host that ran it has since reported its containers without it)"
_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")
_FACTS = ("os_id", "os_version_id", "os_unmatched")


def _text(v, n: int) -> str:
    return v[:n] if isinstance(v, str) else ""


def _row(p) -> dict | None:
    """One package row as InstalledPackage holds it, or None if it doesn't fit."""
    if not isinstance(p, dict):
        return None
    name, ver, src, sv = p.get("name"), p.get("version"), p.get("source"), p.get("source_version")
    if not (isinstance(name, str) and isinstance(ver, str) and 0 < len(name) <= 255 and 0 < len(ver) <= 255):
        return None
    if not all(v is None or (isinstance(v, str) and len(v) <= 255) for v in (src, sv)):
        return None
    return {"name": name, "version": ver, "source": src or None, "source_version": sv or None}


def image(raw) -> dict | None:
    """One image entry as the server keeps it, or None if it can't be one (no image id, no valid container).

    Package rows that don't fit are dropped and the package list marked partial, so the engine judges none of it rather
    than calling the missing rows absent (R4.2). Facts are the three the agent sends; a collection document that isn't
    valid is dropped, which the engine reports as "no collection document" (DECISIONS 125)."""
    if not isinstance(raw, dict) or not isinstance(raw.get("image_id"), str) or not _IMAGE_ID.match(raw["image_id"]):
        return None
    ctrs = {}
    for c in raw.get("containers") if isinstance(raw.get("containers"), list) else []:
        if isinstance(c, dict) and isinstance(c.get("id"), str) and _CONTAINER_ID.match(c["id"]) and c.get("runtime") in RUNTIMES:
            ctrs[c["id"]] = {"id": c["id"], "name": _text(c.get("name"), 255), "runtime": c["runtime"]}
    if not ctrs:
        return None
    sent = raw.get("packages") if isinstance(raw.get("packages"), list) else []
    rows = [r for r in map(_row, sent[:MAX_PACKAGES_PER_IMAGE]) if r]
    collection = raw.get("collection") if valid_document(raw.get("collection")) else None
    if (dropped := len(sent) - len(rows)) and collection:
        db = collection["sources"].get("package_db") or {"count": len(sent)}
        collection = {**collection, "sources": {**collection["sources"], "package_db": {
            **db, "state": "partial", "error": f"{dropped} package rows didn't fit what the server stores"}}}
    facts = raw.get("facts") if isinstance(raw.get("facts"), dict) else {}
    return {"image_id": raw["image_id"], "ref": _text(raw.get("ref"), 255), "os_name": _text(raw.get("os_name"), 255),
            "ecosystem": _text(raw.get("ecosystem"), 100), "facts": {k: facts[k][:300] for k in _FACTS if isinstance(facts.get(k), str)},
            "collection": collection, "containers": list(ctrs.values()),
            "packages": sorted(rows, key=lambda r: (r["name"], r["version"], r["source"] or "", r["source_version"] or ""))}


def key(org_id: str, img: dict) -> str:
    """The image asset's lookup key, kept in its unique agent_key_hash: a hash of everything stored for the image, so a host
    whose answer differs in anything gets an asset of its own instead of changing a shared one. "img:" can never be a hex
    SHA-256, so the reporting host, which knows the hash's input, can't present it as any asset's key (security review)."""
    body = {k: img[k] for k in ("image_id", "os_name", "ecosystem", "facts", "collection", "packages")}
    return "img:" + hashlib.sha256(("image\0" + org_id + "\0" + json.dumps(body, sort_keys=True)).encode()).hexdigest()[:60]


def _create(s: Session, host: Asset, img: dict, h: str) -> tuple[Asset | None, bool]:
    """(asset, created): a new image asset with its packages, or the one another host's report stored a moment ago."""
    t = now()
    a = Asset(org_id=host.org_id, hostname=img["ref"] or img["image_id"][:19], kind="image", os_name=img["os_name"], ecosystem=img["ecosystem"],
              facts={"image_id": img["image_id"], **img["facts"], "first_host": host.id}, collection=img["collection"], agent_key_hash=h, internet_facing=False,
              agent_version=host.agent_version, first_seen=t, last_seen=t, last_inventory_at=t)  # its contents never change: read once
    try:
        with s.begin_nested():
            s.add(a)
            s.flush()
            s.add_all(InstalledPackage(asset_id=a.id, origin="agent", ecosystem=img["ecosystem"], **r) for r in img["packages"])
            s.flush()
    except IntegrityError:  # two hosts reporting one new image at once (PostgreSQL): theirs stands, ours joins it
        return s.scalar(select(Asset).where(Asset.agent_key_hash == h)), False
    return a, True


def _running(s: Session, image_ids: set[str]) -> dict[str, int]:
    """Container rows pointing at each image, across every host."""
    if not image_ids:
        return {}
    return dict(s.execute(select(Container.image_asset_id, func.count()).where(Container.image_asset_id.in_(image_ids))
                          .group_by(Container.image_asset_id)).all())


def refresh(s: Session, images: list[Asset]) -> set[str]:
    """Each image's name and risk context from the hosts that run it: the reference the most hosts started it from (one vote
    per host, however many containers it claims; a tie keeps the current name), the most critical host's criticality,
    internet-facing if any host is. Returns the ids whose score inputs changed."""
    changed = set()
    for a in images:
        rows = s.execute(select(Container.asset_id, Container.ref, Container.last_seen, Asset.criticality, Asset.internet_facing)
                         .join(Asset, Asset.id == Container.asset_id).where(Container.image_asset_id == a.id)).all()
        if not rows:
            continue
        per_host: dict[str, Counter] = {}
        for r in rows:
            if r.ref:
                per_host.setdefault(r.asset_id, Counter())[r.ref] += 1
        votes = Counter(c.most_common(1)[0][0] for c in per_host.values())
        if votes:
            top = max(votes.values())
            tied = sorted(ref for ref, n in votes.items() if n == top)
            a.hostname = a.hostname if a.hostname in tied else tied[0]
        crit = max((r.criticality for r in rows), key=lambda c: CRITICALITY.index(c) if c in CRITICALITY else 1)
        facing = any(r.internet_facing for r in rows)
        if (a.criticality, a.internet_facing) != (crit, facing):
            a.criticality, a.internet_facing = crit, facing
            changed.add(a.id)
    return changed


MAX_LISTED = 4096  # container ids one runtime's listing may carry; a longer one proves nothing


def listed(body: dict) -> dict[str, set[str]]:
    """Each runtime whose running containers the agent listed in full (its `ps` answered): runtime -> their ids. Only a
    container missing from its own runtime's full listing has stopped, so only these can take rows away (DECISIONS 140).
    The listing is cheap and outside the agent's read budget, so a host with more containers than one report reads, or a
    second runtime that failed, still closes what it proves stopped. A listing that doesn't fit proves nothing."""
    out = {}
    raw = body.get("listed")
    for rt, ids in (raw.items() if isinstance(raw, dict) else ()):
        if rt in RUNTIMES and isinstance(ids, list) and len(ids) <= MAX_LISTED and all(isinstance(i, str) and _CONTAINER_ID.match(i) for i in ids):
            out[rt] = set(ids)
    return out


def _new_today(s: Session, host: Asset) -> int:
    """Images this host was first to report in the last 24 hours (the cap on what one host can introduce)."""
    return s.scalar(select(func.count()).select_from(Asset).where(
        Asset.org_id == host.org_id, Asset.kind == "image", Asset.first_seen >= now() - timedelta(days=1),
        Asset.facts["first_host"].as_string() == host.id)) or 0


def store(s: Session, host: Asset, body: dict) -> tuple[dict, list[Asset], list[Asset]]:
    """Record what host's agent sent to POST /api/agent/containers; return (counts, new images, other images to rescan:
    stopped, back, or re-scored). No commit.

    Every image entry is checked (image()); one that can't be stored, or past a cap (per report, per host, per org, new
    images a day), is refused. A row goes only when its runtime listed its running containers in full without it
    (`listed`); a refused entry's containers are still listed, so their rows stay. Ledger entries come last, after every
    insert: an append locks the org row, and holding it while inserting could deadlock two hosts' reports (as rescan)."""
    s.execute(select(Asset.id).where(Asset.id == host.id).with_for_update())  # one host's reports one at a time
    t = now()
    sent = body.get("images") if isinstance(body.get("images"), list) else []
    refused = max(0, len(sent) - MAX_IMAGES_PER_REPORT)
    sent = sent[:MAX_IMAGES_PER_REPORT]
    full = listed(body)
    have = {c.container_id: c for c in s.scalars(select(Container).where(Container.asset_id == host.id))}
    kept = {cid for cid, row in have.items() if row.runtime not in full or cid in full[row.runtime]}  # still running, or not proven stopped
    held = {have[cid].image_asset_id for cid in kept}  # the images this host runs, for its cap
    running: dict[str, tuple[Asset, dict, str]] = {}  # container id -> (image asset, container, reference)
    created: list[Asset] = []
    count = today = None
    for raw in sent:
        img = image(raw)
        new_rows = {c["id"] for c in img["containers"]} - kept - running.keys() if img else set()
        if img is None or len(running) + len(img["containers"]) > MAX_CONTAINERS_PER_REPORT or len(kept | running.keys()) + len(new_rows) > MAX_CONTAINERS_PER_HOST:
            refused += 1
            continue
        h = key(host.org_id, img)
        a = s.scalar(select(Asset).where(Asset.agent_key_hash == h))
        if (a is None or a.id not in held) and len(held) >= MAX_IMAGES_PER_HOST:
            refused += 1
            continue
        if a is None:
            if count is None:
                count = s.scalar(select(func.count()).select_from(Asset).where(Asset.org_id == host.org_id, Asset.kind == "image"))
                today = _new_today(s, host)
            if count >= MAX_IMAGES_PER_ORG or today >= MAX_NEW_IMAGES_PER_HOST_DAY:
                refused += 1
                continue
            a, new = _create(s, host, img, h)
            if a is None:
                refused += 1
                continue
            if new:
                created.append(a)
                count, today = count + 1, today + 1
        a.last_seen = t
        held.add(a.id)
        for c in img["containers"]:
            running[c["id"]] = (a, c, img["ref"])
    touched = {c.image_asset_id for c in have.values()} | {a.id for a, _, _ in running.values()}
    before = _running(s, touched)
    changed = False
    for cid, (a, c, ref) in running.items():
        row = have.get(cid)
        if row is None:
            s.add(Container(asset_id=host.id, container_id=cid, image_asset_id=a.id, org_id=host.org_id, name=c["name"], runtime=c["runtime"],
                            ref=ref, first_seen=t, last_seen=t))
            changed = True
        else:
            changed |= row.image_asset_id != a.id
            row.image_asset_id, row.name, row.runtime, row.ref, row.last_seen = a.id, c["name"], c["runtime"], ref, t
    gone = [row for cid, row in have.items() if cid not in kept and cid not in running]
    for row in gone:
        s.delete(row)
    s.flush()
    after = _running(s, touched)
    images = {a.id: a for a in s.scalars(select(Asset).where(Asset.id.in_(touched)))} if touched else {}
    rescored = refresh(s, list(images.values()))
    stopped = sorted(i for i in touched if before.get(i) and not after.get(i))
    back = sorted(i for i in touched if not before.get(i) and after.get(i) and i not in {a.id for a in created})
    complete = body.get("complete") is True and not refused and set(full) >= {r.runtime for r in have.values()} | {c["runtime"] for _, c, _ in running.values()}
    for a in created:
        evidence.append(s, host.org_id, "asset_created", a.id, {"by": host.hostname, "name": a.hostname, "kind": "image"})
    if changed or gone or refused:
        evidence.append(s, host.org_id, "containers_reported", host.id, {
            "host": host.hostname, "complete": complete, "containers": len(running), "images": sorted({a.id for a, _, _ in running.values()}),
            "new": [a.id for a in created], "stopped": stopped, "refused": refused, "listed": sorted(full)})
    s.flush()
    others = [images[i] for i in sorted(set(stopped) | set(back) | (rescored - {a.id for a in created})) if i in images]
    return ({"images": len({a.id for a, _, _ in running.values()}), "containers": len(running), "new": len(created), "stopped": len(stopped),
             "refused": refused, "complete": complete}, created, others)


def resolve_not_running(s: Session, image: Asset) -> int:
    """An image no host runs: every host that ran it has sent a complete container list without it, since only that removes
    a row (DECISIONS 140). Its open and accepted findings are resolved, with the reason and a ledger entry each. No commit."""
    t = now()
    done = list(s.scalars(select(Finding).where(Finding.asset_id == image.id, Finding.status.in_(("open", "accepted")))))
    for f in done:
        f.status, f.resolved_at = "resolved", t
        f.reasons = [r for r in f.reasons or [] if not r.startswith(("Still open: ", "Closed: "))] + [NOT_RUNNING]
    s.flush()
    for f in done:
        evidence.append(s, image.org_id, "finding_resolved", f.id, {
            "host": image.hostname, "vuln_id": f.vuln_id, "package": f.package, "installed_version": f.installed_version,
            "fixed_version": f.fixed_version, "priority": f.priority, "why": "not running on any host"})
    return len(done)


def is_running(s: Session, image: Asset) -> bool:
    """Whether any host's container rows point at this image."""
    return s.scalar(select(Container.container_id).where(Container.image_asset_id == image.id).limit(1)) is not None


def delete_image(s: Session, image: Asset) -> None:
    """Remove an image asset and everything stored for it (the ledger stays). No commit."""
    for model in (Finding, InstalledPackage, RemediationJob, ScanRecord):
        s.execute(delete(model).where(model.asset_id == image.id))
    s.execute(delete(Container).where(Container.image_asset_id == image.id))
    s.delete(image)


def only_on(s: Session, host: Asset) -> list[Asset]:
    """Images that no host but this one runs: they go with it when it's deleted, as its device views do."""
    mine = set(s.scalars(select(Container.image_asset_id).where(Container.asset_id == host.id)))
    shared = set(s.scalars(select(Container.image_asset_id).where(Container.image_asset_id.in_(mine), Container.asset_id != host.id))) if mine else set()
    return list(s.scalars(select(Asset).where(Asset.id.in_(mine - shared)))) if mine - shared else []


def prune(s: Session) -> int:
    """The hourly clean-up for every org: images no host has run for KEEP are deleted (their findings were resolved when
    they stopped running; the ledger keeps everything). No commit."""
    gone = [a for a in s.scalars(select(Asset).where(Asset.kind == "image", Asset.last_seen < now() - KEEP)) if not is_running(s, a)]
    for a in gone:
        delete_image(s, a)
    return len(gone)
