"""Tickets (DECISIONS 150-153): open findings reach the owning team's tracker as one ticket per fix; a ticket closes only
when none of its findings is open, and reopens when one is again or when it was closed in the tracker while open.

desired() is a pure read of the tickets that should be open. sync() makes the tracker match and records what it wrote on
Ticket rows and in the ledger; preview() is the same plan with no tracker call. Jira (Cloud and Data Center, REST API v2)
and GitLab (API v4) share one small client interface over netguard's guarded client: HTTPS only, the connection pinned
to the checked address, no redirects, replies capped. Links are built from the site URL, never taken from a reply.
"""

import functools
import hashlib
import json
import logging
import os
import re
from base64 import b64encode
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from urllib.parse import quote, urlencode

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from nimstead import evidence, sso
from nimstead.db import Asset, Container, Finding, InstalledPackage, Ticket, TicketSettings, now
from nimstead.netguard import guarded_client, read_capped
from nimstead.versions import comparator_for

log = logging.getLogger(__name__)

PRIORITIES = ("fix-now", "next", "planned", "low")
LABEL = {"fix-now": "Fix now", "next": "Next", "planned": "Routine", "low": "Low"}  # as the UI names them (DECISIONS 49)
MAX_WRITES = 100  # ticket changes per org per sync, most urgent first; the rest wait for the next run (DECISIONS 152)
MAX_CHECKS = 200  # open tickets whose tracker state is read per sync, least recently checked first
STALE_CLAIM = timedelta(minutes=15)  # a sync that claimed the org longer ago than this died; the next one may run
LIST_CAP = 100  # machines listed in a ticket (vulnerabilities: half); the rest are counted
NOUN = {"host": "machine", "application": "application", "external": "internet target", "device": "device"}
JIRA_KEY = re.compile(r"[A-Z][A-Z0-9_]*-[1-9][0-9]{0,9}")
http_client: httpx.Client | None = None  # injectable for tests; None = netguard's guarded client


# --- which tickets should be open --------------------------------------------------------------------------------------

def route(cfg: TicketSettings, owner: str | None) -> str | None:
    """The project an owner's findings go to: its route (names compared with casefold, as owners are), else the default
    project, else None (not sent)."""
    if owner:
        hit = next((r["project"] for r in cfg.routes if r["owner"].casefold() == owner.casefold()), None)
        if hit:
            return hit
    return cfg.default_project or None


def fingerprint(project: str, owner: str | None, action: dict) -> str:
    """The stable id of a (project, owner, fix): 12 hex of SHA-256, also the tracker label nimstead-<fingerprint>."""
    key = json.dumps([project, (owner or "").casefold(), action], sort_keys=True)
    return hashlib.sha256(key.encode()).hexdigest()[:12]


def action_of(kind: str, asset_id: str, ecosystem: str, package: str) -> dict:
    """The fix a finding belongs to: a container image is rebuilt as a whole (DECISIONS 141); anything else is fixed
    package by package (or setting by setting), as Fix first groups it."""
    return {"kind": "image", "asset_id": asset_id} if kind == "image" else {"kind": "package", "ecosystem": ecosystem, "package": package}


def wanted_priorities(cfg: TicketSettings) -> tuple:
    """The priorities at or above the org's threshold."""
    return PRIORITIES[:PRIORITIES.index(cfg.min_priority) + 1] if cfg.min_priority in PRIORITIES else PRIORITIES[:1]


def desired(s: Session, org_id: str, cfg: TicketSettings) -> tuple[dict, Counter]:
    """The tickets that should be open now, by fingerprint, most urgent first (KEV, then worst score), and the findings
    that aren't sent because their owner has no route and there's no default project ({owner or "": count}).

    Every open finding at or above the threshold is in exactly one group. A pure read: nothing is written."""
    rows = s.execute(select(Finding.asset_id, Finding.ecosystem, Finding.package, Finding.installed_version, Finding.vuln_id,
                            Finding.fixed_version, Finding.priority, Finding.score, Finding.kev, Finding.first_seen,
                            Asset.hostname, Asset.owner, Asset.kind)
                     .join(Asset, Asset.id == Finding.asset_id)
                     .where(Finding.org_id == org_id, Finding.status == "open", Finding.priority.in_(wanted_priorities(cfg)))).all()
    sla_at = evidence.sla_history(s, org_id)
    groups: dict[str, dict] = {}
    skipped: Counter = Counter()
    for r in rows:
        project = route(cfg, r.owner)
        if not project:
            skipped[r.owner or ""] += 1
            continue
        action = action_of(r.kind, r.asset_id, r.ecosystem, r.package)
        fp = fingerprint(project, r.owner, action)
        g = groups.get(fp)
        if g is None:
            g = groups[fp] = {"fingerprint": fp, "project": project, "owner": r.owner, "action": action, "ecosystem": r.ecosystem,
                              "image": r.hostname if r.kind == "image" else None, "kinds": set(), "machines": {}, "vulns": set(),
                              "fixes": defaultdict(set), "findings": 0, "priority": "low", "kev": False, "score": 0, "due": None}
        g["findings"] += 1
        g["kinds"].add(r.kind)
        g["machines"][r.asset_id] = [r.hostname, r.installed_version] if r.kind != "image" else [r.hostname, ""]
        g["vulns"].add(r.vuln_id)
        if r.fixed_version:
            g["fixes"][r.package].add(r.fixed_version)
        if PRIORITIES.index(r.priority) < PRIORITIES.index(g["priority"]):
            g["priority"] = r.priority
        g["kev"] = g["kev"] or r.kev
        g["score"] = max(g["score"], r.score or 0)
        due = r.first_seen + timedelta(days=sla_at(r.first_seen).get(r.priority, 180))
        g["due"] = min(g["due"], due) if g["due"] else due
    for g in groups.values():  # the highest fixed version clears them all, as on Home
        cmp = comparator_for(g["ecosystem"])
        g["fixes"] = {p: max(v, key=functools.cmp_to_key(cmp)) if cmp else sorted(v)[-1] for p, v in g["fixes"].items()}
        if g["image"]:
            g["hosts"] = sorted(set(s.scalars(select(Asset.hostname).join(Container, Container.asset_id == Asset.id)
                                              .where(Container.image_asset_id == g["action"]["asset_id"]))))
    return dict(sorted(groups.items(), key=lambda kv: (kv[1]["kev"], kv[1]["score"]), reverse=True)), skipped


# --- what a ticket says ------------------------------------------------------------------------------------------------

_CTRL = re.compile(r"[\x00-\x1f\x7f​-‏‪-‮⁦-⁩﻿]")  # controls, zero-width, bidi


def clean(v, cap: int = 200) -> str:
    """Text from an agent, a feed or an admin with control, zero-width and bidi characters dropped, at most cap long."""
    return _CTRL.sub("", str(v if v is not None else ""))[:cap]


def _n(count: int, word: str) -> str:
    return f"{count:,} {word}{'' if count == 1 else 's'}"


def _noun(g: dict) -> str:
    return NOUN.get(next(iter(g["kinds"])), "asset") if len(g["kinds"]) == 1 else "asset"


class Style:
    """How a tracker shows a ticket. Every value from an agent, a feed or an admin goes in a block or a code span the
    tracker doesn't interpret, so a hostile package name can't add links, mentions, markup or quick actions."""

    def code(self, v: str) -> str:
        """A value inside a title (Jira titles are plain text)."""
        return clean(v, 120)

    def heading(self, text: str) -> str:
        """A section heading."""
        return f"h3. {text}"

    def block(self, lines: list[str]) -> str:
        """Lines in {noformat}, which turns off all markup, links included, until the next {noformat}."""
        return "{noformat}\n" + "\n".join(re.sub(r"(?i)\{noformat", "{no-format", clean(x, 300)) for x in lines) + "\n{noformat}"

    def link(self, label: str, url: str) -> str:
        """A link with a label."""
        return f"[{label}|{url}]"


class MarkdownStyle(Style):
    """GitLab Markdown: code spans and fenced blocks."""

    def code(self, v: str) -> str:
        """A value inside a title."""
        return "`" + clean(v, 120).replace("`", "'") + "`"

    def heading(self, text: str) -> str:
        """A section heading."""
        return f"### {text}"

    def block(self, lines: list[str]) -> str:
        """Lines in a fence longer than any backtick run inside, indented, so no line can close it or be a quick action."""
        text = "\n".join("  " + clean(x, 300) for x in lines)
        fence = "`" * max(3, max((len(m) for m in re.findall(r"`+", text)), default=0) + 1)
        return f"{fence}\n{text}\n{fence}"

    def link(self, label: str, url: str) -> str:
        """A link with a label."""
        return f"[{label}]({url})"


def title(g: dict, st: Style) -> str:
    """One line in the team's words: what to do, on how many machines, for whom. At most 250 characters."""
    n, noun, pkg = len(g["machines"]), _noun(g), g["action"].get("package", "")
    where = f"on {_n(n, noun)}"
    if g["image"]:
        t = f"Rebuild image {st.code(g['image'])} ({_n(g['findings'], 'finding')})"
    elif g["ecosystem"] == "WinConfig":
        t = f"Change {st.code(pkg)} {where}"
    elif g["ecosystem"] == "Lifecycle":
        t = f"Upgrade or replace {st.code(pkg)} (end of support) {where}"
    elif g["fixes"].get(pkg):
        t = f"Upgrade {st.code(pkg)} to {st.code(g['fixes'][pkg])} {where}"
    else:
        t = f"Fix {st.code(pkg)} {where}"
    if g["owner"]:
        t += f" ({clean(g['owner'], 100)})"
    return " ".join(t.split())[:250]


def findings_link(g: dict, cfg: TicketSettings) -> str | None:
    """The ticket's findings on the Findings page (None without NIMSTEAD_PUBLIC_URL). Every value is percent-encoded,
    so nothing in it can end the tracker's link syntax."""
    base = (os.environ.get("NIMSTEAD_PUBLIC_URL") or "").rstrip("/")
    if not base:
        return None
    q = {"asset": g["action"]["asset_id"]} if g["image"] else {"q": g["action"]["package"], "eco": g["ecosystem"]}
    q["priority"] = ",".join(wanted_priorities(cfg))
    q |= {"owner": g["owner"]} if g["owner"] else {"noowner": "1"}
    return f"{base}/findings?{urlencode(q, quote_via=quote, safe='')}"


def body(g: dict, cfg: TicketSettings, st: Style) -> str:
    """The description: priority and due date, what to do, the machines with their installed version, the
    vulnerabilities, a link back, and how the ticket is closed."""
    n, noun, pkg, at = len(g["machines"]), _noun(g), g["action"].get("package", ""), now()
    due = g["due"]
    lead = (f"{_n(g['findings'], 'open finding')} ({len(g['vulns']):,} vulnerabilit{'y' if len(g['vulns']) == 1 else 'ies'}) "
            f"on {_n(n, noun)}. Priority: {LABEL.get(g['priority'], g['priority'])}"
            + (", known exploited (CISA KEV)" if g["kev"] else "")
            + (f". Due {due:%d %b %Y}" + (" (overdue)" if due < at else "") if due else "") + ".")
    if g["image"] and g["fixes"]:
        todo = [f"Rebuild image {g['image']} so it has at least:"] + [f"{p} {v}" for p, v in sorted(g["fixes"].items())]
    elif g["image"]:
        todo = [f"Rebuild image {g['image']} from a newer base image: no fixed version is published yet for its packages."]
    elif g["ecosystem"] == "WinConfig":
        todo = [f"Change the setting {pkg} to its secure value (Nimstead can apply it from Remediation)."]
    elif g["ecosystem"] == "Lifecycle":
        todo = [f"{pkg} is past its end of support: upgrade to a supported release or replace it."]
    elif g["fixes"].get(pkg):
        todo = [f"Upgrade {pkg} ({g['ecosystem']}) to {g['fixes'][pkg]} or later."]
    else:
        todo = [f"{pkg} ({g['ecosystem']}): no fixed version is published yet. See the findings for mitigations."]
    details = [f"Owner: {g['owner']}" if g["owner"] else "Owner: none"]
    machines = sorted(g["machines"].values())
    listed = [f"{h}  {v}".rstrip() for h, v in machines[:LIST_CAP]] + ([f"and {len(machines) - LIST_CAP:,} more"] if len(machines) > LIST_CAP else [])
    vulns = sorted(g["vulns"])
    vlist = vulns[:LIST_CAP // 2] + ([f"and {len(vulns) - LIST_CAP // 2:,} more"] if len(vulns) > LIST_CAP // 2 else [])
    parts = [lead, st.heading("What to do"), st.block(todo + details)]
    if g["image"]:
        hosts = g.get("hosts", [])
        parts += [st.heading(f"Machines running it ({len(hosts):,})"), st.block(hosts[:LIST_CAP] or ["none reported"])]
    else:
        parts += [st.heading(f"{noun.capitalize()}s ({n:,})"), st.block(listed)]
    parts += [st.heading(f"Vulnerabilities ({len(vulns):,})"), st.block(vlist)]
    if link := findings_link(g, cfg):
        parts.append(st.link("Open these findings in Nimstead", link))
    parts.append("Nimstead closes this ticket when the machines' own inventory shows the fix, and reopens it if any is exposed "
                 "again or it's closed while findings are open. To stop tracking a finding, accept the risk in Nimstead: "
                 "that's recorded and has an end date.")
    return "\n\n".join(parts)


def payload(g: dict, cfg: TicketSettings, st: Style) -> dict:
    """What is written to the tracker for a group."""
    return {"title": title(g, st), "body": body(g, cfg, st), "due": g["due"].date().isoformat() if g["due"] else None,
            "labels": ["nimstead", f"nimstead-{g['priority']}", f"nimstead-{g['fingerprint']}"]}


def digest(p: dict) -> str:
    """What a ticket last said, so an unchanged ticket isn't rewritten."""
    return hashlib.sha256(json.dumps([p["title"], p["body"], p["due"]]).encode()).hexdigest()


# --- trackers ----------------------------------------------------------------------------------------------------------

class TrackerError(Exception):
    """A tracker refused or failed a request. str() is safe to show: the tracker's own message, trimmed, or the
    transport's error; never the token."""


class Missing(TrackerError):
    """The issue or project doesn't exist, or the token can't see it."""


def _message(raw: bytes) -> str:
    try:
        d = json.loads(raw)
    except ValueError:
        return clean(raw.decode("utf-8", "replace"), 200)
    if not isinstance(d, dict):
        return clean(json.dumps(d), 200)
    parts = [str(m) for m in d.get("errorMessages") or [] if isinstance(d.get("errorMessages"), list)]  # Jira
    if isinstance(d.get("errors"), dict):
        parts += [f"{k}: {v}" for k, v in d["errors"].items()]
    parts += [v if isinstance(v, str) else json.dumps(v) for k in ("message", "error") if (v := d.get(k))]  # GitLab
    return clean("; ".join(parts) or json.dumps(d), 200)


class Client:
    """One tracker site. Calls go through the guarded client; a reply is read up to netguard's 1 MB cap."""

    kind = ""
    style: Style = Style()

    def __init__(self, site: str, user: str, token: str, http: httpx.Client | None = None):
        self.site, self.user, self.token = site.rstrip("/"), user, token
        self.http = http or http_client or guarded_client(timeout=10.0)
        self._own = http is None and http_client is None

    def shutdown(self) -> None:
        """Release the HTTP client if this object made it."""
        if self._own:
            self.http.close()

    def headers(self) -> dict:
        """The request headers that sign in."""
        raise NotImplementedError

    def call(self, method: str, path: str, **kw):
        """Send one request; return the parsed JSON reply (None when empty). Raise Missing on 404, TrackerError otherwise."""
        try:
            with self.http.stream(method, self.site + path, headers=self.headers(), **kw) as r:
                raw = read_capped(r)
        except (httpx.HTTPError, ValueError) as e:  # ValueError: a refused address or an oversized reply
            raise TrackerError(clean(f"{type(e).__name__}: {e}", 300)) from None
        if r.status_code == 404:
            raise Missing(f"not found: {_message(raw)}")
        if 300 <= r.status_code < 400:
            raise TrackerError(f"HTTP {r.status_code}: the site redirected; use its https address with no path")
        if r.status_code >= 400:
            raise TrackerError(f"HTTP {r.status_code}: {_message(raw)}")
        try:
            return json.loads(raw) if raw.strip() else None
        except ValueError:
            raise TrackerError("the tracker's reply isn't JSON") from None


def _dict(v) -> dict:
    if not isinstance(v, dict):
        raise TrackerError("unexpected reply from the tracker")
    return v


class Jira(Client):
    """Jira Cloud (account email + API token, Basic) or Data Center (personal access token, Bearer), REST API v2."""

    kind = "jira"

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._types: dict[str, str] = {}

    def headers(self) -> dict:
        """The request headers that sign in."""
        auth = "Basic " + b64encode(f"{self.user}:{self.token}".encode()).decode() if self.user else f"Bearer {self.token}"
        return {"Authorization": auth, "Accept": "application/json"}

    def link(self, project: str, key: str) -> str:
        """The issue's address, built from the site URL (never from a reply)."""
        return f"{self.site}/browse/{key}"

    def whoami(self) -> str:
        """The name the tracker knows the signed-in account by."""
        d = _dict(self.call("GET", "/rest/api/2/myself"))
        return clean(d.get("displayName") or d.get("name") or d.get("emailAddress") or "?", 100)

    def project(self, project: str) -> str:
        """Look up a project; return its name. Raise Missing when it doesn't exist or can't be seen."""
        d = _dict(self.call("GET", f"/rest/api/2/project/{quote(project, safe='')}"))
        # Task, then Bug, then any standard type: the issue type every ticket here is created as
        types = [t for t in d.get("issueTypes") or [] if isinstance(t, dict) and not t.get("subtask")]
        pick = next((t for name in ("Task", "Bug") for t in types if t.get("name") == name), types[0] if types else None)
        if not pick:
            raise TrackerError(f"project {project} has no issue type a ticket can be created as")
        self._types[project] = str(pick.get("id"))
        return clean(d.get("name") or project, 100)

    def _fields(self, project: str, p: dict) -> dict:
        return {"summary": p["title"], "description": p["body"], "labels": p["labels"]} | ({"duedate": p["due"]} if p["due"] else {})

    def _send_fields(self, method: str, path: str, fields: dict):
        try:
            return self.call(method, path, json={"fields": fields})
        except Missing:
            raise
        except TrackerError as e:  # the project's screen may not have a due date: send the rest
            if "duedate" not in fields or "duedate" not in str(e):
                raise
            return self.call(method, path, json={"fields": {k: v for k, v in fields.items() if k != "duedate"}})

    def create(self, project: str, p: dict) -> str:
        """Open an issue; return its key."""
        if project not in self._types:
            self.project(project)
        fields = self._fields(project, p) | {"project": {"key": project}, "issuetype": {"id": self._types[project]}}
        key = _dict(self._send_fields("POST", "/rest/api/2/issue", fields)).get("key")
        if not isinstance(key, str) or not JIRA_KEY.fullmatch(key):
            raise TrackerError("the tracker answered without a valid issue key")
        return key

    def update(self, project: str, key: str, p: dict) -> None:
        """Rewrite an issue's title, description and due date."""
        f = self._fields(project, p)
        f.pop("labels")  # labels a team added stay
        self._send_fields("PUT", f"/rest/api/2/issue/{key}", f)

    def comment(self, project: str, key: str, text: str) -> None:
        """Add a comment."""
        self.call("POST", f"/rest/api/2/issue/{key}/comment", json={"body": text})

    def is_done(self, project: str, key: str) -> bool:
        """Whether the issue is closed (Jira: in the Done status category)."""
        d = _dict(self.call("GET", f"/rest/api/2/issue/{key}", params={"fields": "status"}))
        return ((((d.get("fields") or {}).get("status") or {}).get("statusCategory") or {}).get("key")) == "done"

    def _move(self, key: str, done: bool) -> None:
        """Move the issue to the first status in the Done category (done) or in To Do, else In Progress (not done):
        workflows name their statuses as they like, but every status has one of Jira's three categories."""
        ts = [t for t in _dict(self.call("GET", f"/rest/api/2/issue/{key}/transitions")).get("transitions") or [] if isinstance(t, dict)]
        cat = lambda t: (((t.get("to") or {}).get("statusCategory") or {}).get("key"))  # noqa: E731
        want = ("done",) if done else ("new", "indeterminate")
        pick = next((t for c in want for t in ts if cat(t) == c), None)
        if not pick:
            raise TrackerError(f"no transition to {'Done' if done else 'To Do or In Progress'} from this issue's status")
        self.call("POST", f"/rest/api/2/issue/{key}/transitions", json={"transition": {"id": str(pick.get("id"))}})

    def close(self, project: str, key: str) -> None:
        """Close the issue (a no-op when it already is)."""
        if not self.is_done(project, key):
            self._move(key, True)

    def reopen(self, project: str, key: str) -> None:
        """Reopen the issue (a no-op when it's open)."""
        if self.is_done(project, key):
            self._move(key, False)

    def find(self, project: str, label: str) -> str | None:
        """The issue carrying label in project, if any. Cloud serves /search/jql (its /search is gone); Data Center serves
        /search."""
        params = {"jql": f'project = "{project}" AND labels = "{label}"', "fields": "key", "maxResults": "1"}
        for path in ("/rest/api/2/search/jql", "/rest/api/3/search/jql", "/rest/api/2/search"):
            try:
                d = _dict(self.call("GET", path, params=params))
            except Missing:
                continue
            except TrackerError as e:
                if str(e).startswith("HTTP 410"):
                    continue
                raise
            keys = [i.get("key") for i in d.get("issues") or [] if isinstance(i, dict)]
            return next((k for k in keys if isinstance(k, str) and JIRA_KEY.fullmatch(k)), None)
        raise TrackerError("this Jira has no issue search Nimstead knows")


class GitLab(Client):
    """gitlab.com or self-managed GitLab, API v4, with a personal, group or project access token (api scope)."""

    kind = "gitlab"
    style = MarkdownStyle()

    def headers(self) -> dict:
        """The request headers that sign in."""
        return {"PRIVATE-TOKEN": self.token, "Accept": "application/json"}

    def link(self, project: str, key: str) -> str:
        """The issue's address, built from the site URL (never from a reply)."""
        return f"{self.site}/{project}/-/issues/{key}"

    def _p(self, project: str) -> str:
        return f"/api/v4/projects/{quote(project, safe='')}"

    def whoami(self) -> str:
        """The name the tracker knows the signed-in account by."""
        return clean(_dict(self.call("GET", "/api/v4/user")).get("username") or "?", 100)

    def project(self, project: str) -> str:
        """Look up a project; return its name. Raise Missing when it doesn't exist or can't be seen."""
        return clean(_dict(self.call("GET", self._p(project))).get("path_with_namespace") or project, 255)

    def _data(self, p: dict) -> dict:
        return {"title": p["title"], "description": p["body"]} | ({"due_date": p["due"]} if p["due"] else {})

    def create(self, project: str, p: dict) -> str:
        """Open an issue; return its key."""
        iid = _dict(self.call("POST", f"{self._p(project)}/issues", json=self._data(p) | {"labels": ",".join(p["labels"])})).get("iid")
        if not isinstance(iid, int) or isinstance(iid, bool) or iid < 1:
            raise TrackerError("the tracker answered without a valid issue number")
        return str(iid)

    def update(self, project: str, key: str, p: dict) -> None:
        """Rewrite an issue's title, description and due date."""
        self.call("PUT", f"{self._p(project)}/issues/{int(key)}", json=self._data(p))

    def comment(self, project: str, key: str, text: str) -> None:
        """Add a comment."""
        self.call("POST", f"{self._p(project)}/issues/{int(key)}/notes", json={"body": text})

    def is_done(self, project: str, key: str) -> bool:
        """Whether the issue is closed (Jira: in the Done status category)."""
        return _dict(self.call("GET", f"{self._p(project)}/issues/{int(key)}")).get("state") == "closed"

    def close(self, project: str, key: str) -> None:
        """Close the issue (a no-op when it already is)."""
        self.call("PUT", f"{self._p(project)}/issues/{int(key)}", json={"state_event": "close"})

    def reopen(self, project: str, key: str) -> None:
        """Reopen the issue (a no-op when it's open)."""
        self.call("PUT", f"{self._p(project)}/issues/{int(key)}", json={"state_event": "reopen"})

    def find(self, project: str, label: str) -> str | None:
        """The issue in project carrying label, if any."""
        d = self.call("GET", f"{self._p(project)}/issues", params={"labels": label, "state": "all", "per_page": "1"})
        iids = [i.get("iid") for i in d or [] if isinstance(i, dict)] if isinstance(d, list) else []
        return next((str(i) for i in iids if isinstance(i, int) and not isinstance(i, bool) and i > 0), None)


KINDS = {"jira": Jira, "gitlab": GitLab}


def client_for(cfg: TicketSettings, http: httpx.Client | None = None) -> Client:
    """The org's tracker client with its token unsealed. Raise TrackerError when no token is saved."""
    if not cfg.token or not cfg.site:
        raise TrackerError("no site and token saved")
    return KINDS[cfg.kind](cfg.site, cfg.user, sso.unseal(cfg.token), http)


def test_connection(cfg: TicketSettings) -> str:
    """Sign in and look up every project tickets can go to; return what was found, in words. Raise TrackerError."""
    c = client_for(cfg)
    try:
        who = c.whoami()
        projects = sorted({cfg.default_project, *(r["project"] for r in cfg.routes)} - {""})
        found = []
        for p in projects[:20]:
            try:
                c.project(p)
            except Missing:
                raise TrackerError(f"Signed in as {who}, but project {p} wasn't found or {who} can't see it") from None
            found.append(p)
        name = "Jira" if cfg.kind == "jira" else "GitLab"
        return f"Signed in to {name} as {who}" + (f"; project{'s' if len(found) > 1 else ''} {', '.join(found)} found." if found else "; no project set yet.")
    finally:
        c.shutdown()


# --- the sync ----------------------------------------------------------------------------------------------------------

def _why_left(s: Session, org_id: str, asset_id: str, t: Ticket, cfg: TicketSettings) -> str:
    """Why a machine is no longer in a ticket, from the evidence: fixed (and when), risk accepted (until when), moved to
    another team or project, below the threshold now, or removed."""
    a = s.get(Asset, asset_id)
    if a is None or a.org_id != org_id:
        return "removed from Nimstead"
    act = t.action
    q = select(Finding).where(Finding.asset_id == asset_id)
    if act["kind"] == "package":
        q = q.where(Finding.ecosystem == act["ecosystem"], Finding.package == act["package"])
    fs = s.scalars(q).all()
    open_ = [f for f in fs if f.status == "open"]
    if any(f.priority in wanted_priorities(cfg) for f in open_):  # still to fix, but not in this ticket
        if (a.owner or "").casefold() != (t.owner or "").casefold():
            return f"now owned by {clean(a.owner, 100) or 'nobody'}"
        return f"now tracked in project {clean(route(cfg, a.owner) or 'none', 100)}"
    fixed = [f.resolved_at for f in fs if f.status == "resolved" and f.resolved_at and f.resolved_at >= t.opened_at]
    accepted = [f.accepted_until for f in fs if f.status == "accepted"]
    rest = f"; {_n(len(open_), 'lower-priority finding')} still open" if open_ else ""
    if accepted and not fixed:
        until = max((u for u in accepted if u), default=None)
        return "risk accepted in Nimstead" + (f" until {until:%d %b %Y}" if until else "") + rest
    if open_ and not fixed:
        return f"priority now below {LABEL.get(cfg.min_priority, cfg.min_priority)}"
    resolved = max(fixed, default=None) or max((f.resolved_at for f in fs if f.resolved_at), default=None)
    when = f" {resolved:%d %b %H:%M} UTC" if resolved else ""
    if act["kind"] == "package" and a.kind == "host":  # the package itself, else a binary built from it (Debian source names)
        v = (s.scalar(select(InstalledPackage.version).where(InstalledPackage.asset_id == asset_id, InstalledPackage.name == act["package"]).limit(1))
             or s.scalar(select(InstalledPackage.version).where(InstalledPackage.asset_id == asset_id, InstalledPackage.source == act["package"]).limit(1)))
        return (f"fixed{when}: {v} in the machine's inventory" if v else f"fixed{when}: removed, per the machine's inventory") + rest
    return f"resolved{when} on fresh evidence{rest}"


WHY = {"fixed": "fixed", "resolved": "fixed", "risk": "accepted", "now": "moved", "priority": "below_threshold", "removed": "removed"}


def _why_code(text: str) -> str:
    """The ledger's word for a _why_left reason."""
    return WHY.get(re.split(r"[ :]", text, maxsplit=1)[0], "other")


def _lines(machines: dict, ids, reason) -> list[str]:
    return [f"{machines[a][0]}  {reason(a)}" for a in sorted(ids, key=lambda a: machines[a][0])][:LIST_CAP]


def plan(want: dict, rows: dict, done_in_tracker: set) -> list[tuple[str, str]]:
    """The changes that make the tracker match, in the order they're made: closes, reopens, updates, then opens, each
    most urgent first. Updates are decided at write time (a content digest); here every open, keyed, wanted ticket is a
    candidate."""
    closes = [("close", fp) for fp, t in rows.items() if t.state == "open" and fp not in want]
    reopens, updates, opens = [], [], []
    for fp in want:
        t = rows.get(fp)
        if t is None or t.key is None:
            opens.append(("open", fp))
        elif t.state == "closed" or fp in done_in_tracker:
            reopens.append(("reopen", fp))
        else:
            updates.append(("update", fp))
    return closes + reopens + updates + opens


def preview(s: Session, org_id: str, cfg: TicketSettings) -> dict:
    """What a sync would do now, with no tracker call (so a ticket closed by hand in the tracker shows as an update
    here and is reopened by the sync). Counts, the tickets that would be opened by project (titles), and the findings
    not sent for want of a route."""
    want, skipped = desired(s, org_id, cfg)
    rows = {t.fingerprint: t for t in s.scalars(select(Ticket).where(Ticket.org_id == org_id))}
    st = KINDS.get(cfg.kind, Jira).style
    out = {"open": [], "update": 0, "close": 0, "reopen": 0}
    for op, fp in plan(want, rows, set()):
        if op == "open":
            out["open"].append({"project": want[fp]["project"], "title": title(want[fp], st), "priority": want[fp]["priority"]})
        elif op == "update":
            out["update"] += digest(payload(want[fp], cfg, st)) != rows[fp].body_sha
        else:
            out[op] += 1
    return out | {"tickets": len(want), "findings": sum(g["findings"] for g in want.values()),
                  "skipped": [{"owner": o or None, "findings": n} for o, n in skipped.most_common()]}


def _claim(s: Session, org_id: str) -> TicketSettings | None:
    cfg = s.get(TicketSettings, org_id, with_for_update=True, populate_existing=True)
    if cfg is None or not cfg.enabled or (cfg.sync_started and now() - cfg.sync_started < STALE_CLAIM):
        s.rollback()
        return None
    cfg.sync_started = now()
    s.commit()  # the lock is released here: it's never held across a tracker call
    return cfg


def sync(s: Session, org_id: str, http: httpx.Client | None = None) -> dict:
    """Make the org's tracker match its open findings (DECISIONS 150-152). Commits after each ticket, so one failure
    costs only that ticket; returns and records what was done in TicketSettings.last_sync.

    Skips when ticketing is off or another sync holds the org (a claim younger than 15 minutes)."""
    cfg = _claim(s, org_id)
    if cfg is None:
        return {"skipped": True}
    stats: Counter = Counter()
    errors: list[dict] = []
    try:
        client = client_for(cfg, http)
    except Exception as e:
        cfg.sync_started, cfg.last_sync = None, {"at": now().isoformat(), "error": clean(str(e), 300)}
        s.commit()
        return {"error": str(e)}
    try:
        _sync(s, org_id, cfg, client, stats, errors)
    except Exception as e:  # the org's own failure (its database rows, a bug): recorded, not raised into the hourly run
        s.rollback()
        log.exception("ticket sync for org %s stopped", org_id)
        errors.append({"ticket": None, "error": clean(f"{type(e).__name__}: {e}", 300)})
    finally:
        client.shutdown()
    cfg = s.get(TicketSettings, org_id, populate_existing=True)
    cfg.sync_started = None
    cfg.last_sync = {"at": now().isoformat(), **{k: stats[k] for k in ("opened", "updated", "closed", "reopened", "failed", "waiting")},
                     "errors": errors[-5:]}
    s.commit()
    return dict(cfg.last_sync)


def _fail(t: Ticket, e: Exception, stats: Counter, errors: list) -> None:
    t.error = clean(str(e), 500)
    stats["failed"] += 1
    errors.append({"ticket": t.key, "title": t.title, "error": t.error})


SYNC_DEADLINE = timedelta(minutes=5)  # a slow tracker can't hold the hourly run: what's left waits for the next sync
MAX_FAILURES_IN_A_ROW = 5  # a tracker that's down: stop and try next hour rather than fail every ticket


def _sync(s: Session, org_id: str, cfg: TicketSettings, c: Client, stats: Counter, errors: list) -> None:
    want, _ = desired(s, org_id, cfg)
    rows = {t.fingerprint: t for t in s.scalars(select(Ticket).where(Ticket.org_id == org_id))}
    done, start, streak = set(), now(), 0

    def stop() -> bool:
        return now() - start > SYNC_DEADLINE or streak >= MAX_FAILURES_IN_A_ROW

    keyed = [t for t in rows.values() if t.state == "open" and t.key]
    for t in sorted(keyed, key=lambda t: t.checked_at or datetime.min)[:MAX_CHECKS]:  # a hand close is seen before writing
        if stop():
            break
        try:
            if c.is_done(t.project, t.key):
                done.add(t.fingerprint)
            t.checked_at, streak = now(), 0
        except Missing:  # deleted in the tracker: opened afresh if still wanted (the label search first finds nothing)
            t.key = None
        except TrackerError as e:
            _fail(t, e, stats, errors)
            streak += 1
    s.commit()  # once: the reads changed only when each ticket was checked
    ops = plan(want, rows, done)
    writes = 0
    for i, (op, fp) in enumerate(ops):
        if writes >= MAX_WRITES or stop():
            stats["waiting"] = sum(1 for o, f in ops[i:] if o != "update" or digest(payload(want[f], cfg, c.style)) != rows[f].body_sha)
            break
        t, recover = rows.get(fp), False
        if op == "open":
            recover = t is not None  # a keyless row: its create may have reached the tracker before a crash, or it was deleted there
            if t is None:
                g = want[fp]
                t = rows[fp] = Ticket(org_id=org_id, fingerprint=fp, owner=g["owner"], action=g["action"], project=g["project"], machines={})
                s.add(t)
            t.state, t.error = "open", None
            s.commit()  # the row before the tracker call: a crash after the create is found by its label next time
        try:
            if op == "close":
                n = _close(s, org_id, cfg, c, t, fp in done, stats)
            elif op == "reopen":
                n = _reopen(s, org_id, cfg, c, t, want[fp], "closed_in_tracker" if fp in done else "regression", stats)
            elif op == "update":
                n = _update(s, org_id, cfg, c, t, want[fp], stats)
            else:
                n = _open(s, org_id, cfg, c, t, want[fp], recover, stats)
            writes, streak = writes + n, 0 if n else streak  # an unchanged ticket made no call: it proves nothing
        except TrackerError as e:
            if isinstance(e, Missing) and op != "open":
                t.key = None  # deleted between the read and the write: opened afresh next sync
            _fail(t, e, stats, errors)
            writes, streak = writes + 1, streak + 1
        s.commit()


def _open(s, org_id, cfg, c: Client, t: Ticket, g: dict, recover: bool, stats) -> int:
    p = payload(g, cfg, c.style)
    key = c.find(t.project, f"nimstead-{t.fingerprint}") if recover else None
    if key:
        c.update(t.project, key, p)
        c.reopen(t.project, key)  # no-op when it's open
    else:
        key = c.create(t.project, p)
    t.key, t.title, t.body_sha, t.machines = key, p["title"][:300], digest(p), dict(g["machines"])
    t.opened_at, t.closed_at, t.checked_at = now(), None, now()
    evidence.append(s, org_id, "ticket_opened", t.id, {"key": key, "project": t.project, "owner": t.owner, "action": t.action,
                                                       "findings": g["findings"], "machines": len(g["machines"]),
                                                       "link": c.link(t.project, key)})
    stats["opened"] += 1
    return 1


def _change_comment(s, org_id, cfg, c: Client, t: Ticket, g: dict) -> str | None:
    old, new = t.machines or {}, g["machines"]
    left, joined = set(old) - set(new), set(new) - set(old)
    if not left and not joined:
        return None
    st, parts = c.style, []
    if left:
        parts += [f"No longer in this ticket ({len(left):,}):", st.block(_lines(old, left, lambda a: _why_left(s, org_id, a, t, cfg)))]
    if joined:
        parts += [f"Now also on ({len(joined):,}):", st.block(_lines(new, joined, lambda a: new[a][1]))]
    parts.append(f"{_n(len(new), _noun(g))} left.")
    return "\n\n".join(parts)


def _update(s, org_id, cfg, c: Client, t: Ticket, g: dict, stats) -> int:
    p = payload(g, cfg, c.style)
    if digest(p) == t.body_sha:
        return 0
    c.update(t.project, t.key, p)
    if text := _change_comment(s, org_id, cfg, c, t, g):
        c.comment(t.project, t.key, text)
    t.title, t.body_sha, t.machines, t.error = p["title"][:300], digest(p), dict(g["machines"]), None
    stats["updated"] += 1
    return 1


def _close(s, org_id, cfg, c: Client, t: Ticket, done_in_tracker: bool, stats) -> int:
    key = t.key or c.find(t.project, f"nimstead-{t.fingerprint}")
    if not key:  # never reached the tracker
        t.state, t.closed_at = "closed", now()
        return 0
    old = t.machines or {}
    reasons = {a: _why_left(s, org_id, a, t, cfg) for a in old}
    c.comment(t.project, key, "No finding in this ticket is open any more, so Nimstead is closing it.\n\n"
              + c.style.block(_lines(old, old, reasons.get)))
    if not done_in_tracker:
        c.close(t.project, key)
    t.key, t.state, t.closed_at, t.error = key, "closed", now(), None
    evidence.append(s, org_id, "ticket_closed", t.id, {"key": key, "project": t.project, "owner": t.owner, "action": t.action,
                                                       "why": dict(Counter(map(_why_code, reasons.values())))})
    stats["closed"] += 1
    return 1


def _reopen(s, org_id, cfg, c: Client, t: Ticket, g: dict, why: str, stats) -> int:
    p = payload(g, cfg, c.style)
    c.update(t.project, t.key, p)
    c.reopen(t.project, t.key)
    new = g["machines"]
    head = ("This ticket was closed in the tracker while findings are still open, so Nimstead has reopened it."
            if why == "closed_in_tracker" else "Findings in this ticket are open again, so Nimstead has reopened it.")
    c.comment(t.project, t.key, f"{head}\n\nExposed now ({len(new):,}):\n\n" + c.style.block(_lines(new, new, lambda a: new[a][1]))
              + "\n\nNimstead closes it when the machines' own inventory shows the fix. To stop tracking a finding, accept the "
                "risk in Nimstead: that's recorded and has an end date.")
    t.state, t.closed_at, t.title, t.body_sha, t.machines, t.error = "open", None, p["title"][:300], digest(p), dict(new), None
    t.checked_at = now()
    evidence.append(s, org_id, "ticket_reopened", t.id, {"key": t.key, "project": t.project, "owner": t.owner, "action": t.action,
                                                         "reason": why, "machines": len(new)})
    stats["reopened"] += 1
    return 1


def sync_all(s: Session) -> dict:
    """The hourly run: sync every org with ticketing on, each isolated (one org's failure costs no other org its sync)."""
    out = Counter()
    for org_id in s.scalars(select(TicketSettings.org_id).where(TicketSettings.enabled.is_(True))).all():
        try:
            r = sync(s, org_id)
            out["orgs"] += "skipped" not in r
            for k in ("opened", "updated", "closed", "reopened", "failed"):
                out[k] += r.get(k, 0)
        except Exception:
            s.rollback()
            log.exception("ticket sync for org %s failed", org_id)
            out["orgs_failed"] += 1
    return dict(out)


def links(s: Session, org_id: str) -> tuple[TicketSettings | None, dict]:
    """What ticket_for needs, read once per request: the settings and the org's tickets that reached the tracker."""
    cfg = s.get(TicketSettings, org_id)
    if cfg is None or not cfg.site:
        return None, {}
    return cfg, {t.fingerprint: t for t in s.scalars(select(Ticket).where(Ticket.org_id == org_id, Ticket.key.is_not(None)))}


def ticket_for(index: tuple, owner: str | None, action: dict) -> dict | None:
    """The ticket a finding is in ({key, url, state, project}), or None. The link is built from the site URL."""
    cfg, rows = index
    if not cfg or not rows or not (project := route(cfg, owner)):
        return None
    t = rows.get(fingerprint(project, owner, action))
    if t is None:
        return None
    site = cfg.site.rstrip("/")
    url = f"{site}/browse/{t.key}" if cfg.kind == "jira" else f"{site}/{t.project}/-/issues/{t.key}"
    return {"key": t.key if cfg.kind == "jira" else f"#{t.key}", "url": url, "state": t.state, "project": t.project}
