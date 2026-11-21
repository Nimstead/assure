"""Stateful fakes of Jira (REST API v2, Cloud and Data Center) and GitLab (API v4) for the ticket tests, following each
tracker's documented contract: auth headers, status categories and transitions (Jira), state events (GitLab), label
search, field validation. Mounted with httpx.MockTransport."""

import base64
import json
import re
from urllib.parse import unquote

import httpx


def reply(status: int, body=None) -> httpx.Response:
    return httpx.Response(status, json=body) if body is not None else httpx.Response(status)


class FakeJira:
    """Statuses: To Do (new), In Progress (indeterminate) and a Done-category status named done_name. Cloud serves
    /rest/api/2/search/jql and 410s /search; Data Center serves /search only."""

    def __init__(self, cloud=True, done_name="Done", due_on_screen=True, projects=("PAY", "OPS", "SEC"), email="bot@example.com", token="tok"):  # noqa: S107 (a fake's test value)
        self.cloud, self.done_name, self.due_on_screen = cloud, done_name, due_on_screen
        self.projects = set(projects)
        self.auth = ("Basic " + base64.b64encode(f"{email}:{token}".encode()).decode()) if cloud else f"Bearer {token}"
        self.issues: dict[str, dict] = {}
        self.calls: list[tuple[str, str]] = []
        self.next = 1
        self.fail: dict[str, int] = {}  # path regex -> status to answer with
        self.override: dict[str, object] = {}  # path regex -> raw JSON reply

    @property
    def writes(self):
        return [c for c in self.calls if c[0] != "GET"]

    def status(self, key: str) -> str:
        return self.issues[key]["status"]

    def close_by_hand(self, key: str) -> None:
        self.issues[key]["status"] = "done"

    def handler(self, req: httpx.Request) -> httpx.Response:
        path, m = req.url.path, req.method
        self.calls.append((m, path))
        if req.headers.get("authorization") != self.auth:
            return reply(401, {"errorMessages": ["You are not authenticated."]})
        for pat, status in self.fail.items():
            if re.search(pat, path):
                return reply(status, {"errorMessages": ["Internal server error"]})
        for pat, raw in self.override.items():
            if re.search(pat, path):
                return httpx.Response(200, content=raw if isinstance(raw, bytes) else json.dumps(raw).encode())
        body = json.loads(req.content) if req.content else {}
        if path == "/rest/api/2/myself":
            return reply(200, {"displayName": "Nimstead bot", "accountId": "abc"})
        if mm := re.fullmatch(r"/rest/api/2/project/([^/]+)", path):
            key = unquote(mm[1])
            if key not in self.projects:
                return reply(404, {"errorMessages": [f"No project could be found with key '{key}'."]})
            return reply(200, {"key": key, "name": f"Project {key}", "issueTypes": [
                {"id": "10002", "name": "Sub-task", "subtask": True}, {"id": "10001", "name": "Story", "subtask": False},
                {"id": "10000", "name": "Task", "subtask": False}]})
        if path in ("/rest/api/2/search/jql", "/rest/api/3/search/jql", "/rest/api/2/search"):
            if path.endswith("/jql") != self.cloud:
                return reply(410 if self.cloud else 404, {"errorMessages": ["gone"]})
            q = re.fullmatch(r'project = "([^"]+)" AND labels = "([^"]+)"', req.url.params["jql"])
            hits = [k for k, i in self.issues.items() if i["project"] == q[1] and q[2] in i["labels"]]
            return reply(200, {"issues": [{"key": k} for k in hits[: int(req.url.params.get("maxResults", 50))]]})
        if path == "/rest/api/2/issue" and m == "POST":
            f = body["fields"]
            if f["project"]["key"] not in self.projects:
                return reply(400, {"errors": {"project": "project is required"}})
            if f["issuetype"]["id"] not in ("10000", "10001"):
                return reply(400, {"errors": {"issuetype": "valid issue type is required"}})
            if err := self._check(f):
                return err
            key = f"{f['project']['key']}-{self.next}"
            self.next += 1
            self.issues[key] = {"project": f["project"]["key"], "summary": f["summary"], "description": f["description"],
                                "labels": list(f["labels"]), "duedate": f.get("duedate"), "status": "new", "comments": []}
            return reply(201, {"id": str(self.next), "key": key, "self": f"https://evil.example/{key}"})
        if mm := re.fullmatch(r"/rest/api/2/issue/([A-Z]+-\d+)(/comment|/transitions)?", path):
            key, sub = mm[1], mm[2]
            if key not in self.issues:
                return reply(404, {"errorMessages": ["Issue does not exist or you do not have permission to see it."]})
            i = self.issues[key]
            if sub == "/comment":
                i["comments"].append(body["body"])
                return reply(201, {"id": "1"})
            if sub == "/transitions" and m == "GET":
                cats = {"new": "To Do", "indeterminate": "In Progress", "done": self.done_name}
                to = ["indeterminate", "done"] if i["status"] != "done" else ["new"]
                return reply(200, {"transitions": [{"id": {"new": "11", "indeterminate": "21", "done": "31"}[c], "name": f"Go {c}",
                                                    "to": {"name": cats[c], "statusCategory": {"key": c}}} for c in to]})
            if sub == "/transitions":
                tid = body["transition"]["id"]
                allowed = {"11": "new", "21": "indeterminate", "31": "done"}
                if tid not in allowed or (i["status"] == "done") != (allowed[tid] == "new"):
                    return reply(400, {"errorMessages": ["Transition is not valid for this issue's status."]})
                i["status"] = allowed[tid]
                return reply(204)
            if m == "GET":
                cat = i["status"]
                return reply(200, {"key": key, "fields": {"status": {"name": "x", "statusCategory": {"key": cat}}}})
            if m == "PUT":
                f = body["fields"]
                if "labels" in f:
                    return reply(400, {"errors": {"labels": "not expected on update in this test"}})
                if err := self._check(f, create=False):
                    return err
                i.update({k: v for k, v in f.items()})
                return reply(204)
        return reply(404, {"errorMessages": [f"no route {m} {path}"]})

    def _check(self, f: dict, create: bool = True):
        if "duedate" in f and not self.due_on_screen:
            return reply(400, {"errors": {"duedate": "Field 'duedate' cannot be set. It is not on the appropriate screen, or unknown."}})
        if create and (not f.get("summary") or len(f["summary"]) > 255 or "\n" in f["summary"]):
            return reply(400, {"errors": {"summary": "You must specify a summary of the issue (one line, 255 at most)."}})
        if create and any(not re.fullmatch(r"\S+", lab) for lab in f.get("labels", [])):
            return reply(400, {"errors": {"labels": "labels can't contain spaces"}})
        if not isinstance(f.get("description", ""), str):
            return reply(400, {"errors": {"description": "Operation value must be a string"}})
        return None


class FakeGitLab:
    """Projects by path; issues by (project, iid) with state opened/closed, comma-separated labels and notes."""

    def __init__(self, projects=("payments/app", "platform/ops"), token="glpat-tok"):  # noqa: S107 (a fake's test value)
        self.projects = {p: n + 1 for n, p in enumerate(projects)}
        self.token = token
        self.issues: dict[tuple[str, int], dict] = {}
        self.calls: list[tuple[str, str]] = []
        self.fail: dict[str, int] = {}

    @property
    def writes(self):
        return [c for c in self.calls if c[0] != "GET"]

    def close_by_hand(self, project: str, iid: int) -> None:
        self.issues[(project, iid)]["state"] = "closed"

    def handler(self, req: httpx.Request) -> httpx.Response:
        raw, m = req.url.raw_path.decode().split("?")[0], req.method
        self.calls.append((m, raw))
        if req.headers.get("private-token") != self.token:
            return reply(401, {"message": "401 Unauthorized"})
        for pat, status in self.fail.items():
            if re.search(pat, raw):
                return reply(status, {"message": "500 Internal Server Error"})
        body = json.loads(req.content) if req.content else {}
        if raw == "/api/v4/user":
            return reply(200, {"username": "nimstead-bot", "id": 7})
        mm = re.fullmatch(r"/api/v4/projects/([^/]+)(/issues(?:/(\d+))?(/notes)?)?", raw)
        if not mm:
            return reply(404, {"error": "404 Not Found"})
        project = unquote(mm[1])
        if "/" in mm[1] or project not in self.projects:  # the path must be URL-encoded as one segment
            return reply(404, {"message": "404 Project Not Found"})
        if not mm[2]:
            return reply(200, {"id": self.projects[project], "path_with_namespace": project, "web_url": "https://evil.example/x"})
        iid = int(mm[3]) if mm[3] else None
        if iid is None and m == "POST":
            if not body.get("title") or len(body["title"]) > 255:
                return reply(400, {"message": {"title": ["is too long (maximum is 255 characters)"]}})
            n = 1 + max((i for p, i in self.issues if p == project), default=0)
            self.issues[(project, n)] = {"title": body["title"], "description": body.get("description", ""), "state": "opened",
                                         "labels": body.get("labels", "").split(","), "due_date": body.get("due_date"), "notes": []}
            return reply(201, {"iid": n, "id": 1000 + n, "state": "opened", "web_url": "javascript:alert(1)"})
        if iid is None and m == "GET":
            label = req.url.params.get("labels")
            hits = [{"iid": i} for (p, i), v in self.issues.items() if p == project and (not label or label in v["labels"])]
            return reply(200, hits[: int(req.url.params.get("per_page", 20))])
        if (project, iid) not in self.issues:
            return reply(404, {"message": "404 Not found"})
        issue = self.issues[(project, iid)]
        if mm[4]:
            issue["notes"].append(body["body"])
            return reply(201, {"id": 1})
        if m == "GET":
            return reply(200, {"iid": iid, "state": issue["state"]})
        if m == "PUT":
            ev = body.pop("state_event", None)
            if ev:
                issue["state"] = {"close": "closed", "reopen": "opened"}[ev]
            issue.update(body)
            return reply(200, {"iid": iid, "state": issue["state"]})
        return reply(405, {"error": "405 Method Not Allowed"})


def client_for(fake) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(fake.handler))
