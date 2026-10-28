import { aiFilterToPatch, dependenciesNeeded, looksLikeQuestion, filtersToApi, filtersToSearch, groupJobs, humaniseKind, installCommands, isActiveJob, parseFilters, priorityOf, relativeTime, whyMatched, type Job } from "./lib";

describe("priorityOf", () => {
  it("mirrors the server thresholds and lets KEV override", () => {
    expect([priorityOf(80, false), priorityOf(60, false), priorityOf(30, false), priorityOf(5, false)]).toEqual(["fix-now", "next", "planned", "low"]);
    expect(priorityOf(10, true)).toBe("fix-now");
  });
});

describe("formatting", () => {
  const now = Date.parse("2026-10-25T12:00:00Z");
  it("treats zone-less API timestamps as UTC", () => {
    expect(relativeTime("2026-10-25T09:00:00", now)).toBe("3 hours ago");
    expect(relativeTime("2026-10-24T12:00:00", now)).toBe("yesterday");
    expect(relativeTime("2026-10-25T11:59:50", now)).toBe("just now");
  });
  it("explains why a finding matched", () => {
    expect(whyMatched({ installed_version: "3.0.11-1~deb12u1", fixed_version: "3.0.11-1~deb12u2", advisory_ids: ["DSA-5532"], vuln_id: "CVE-1" }))
      .toBe("Installed 3.0.11-1~deb12u1 < fixed 3.0.11-1~deb12u2 per DSA-5532");
    expect(whyMatched({ installed_version: "1", fixed_version: null, advisory_ids: [], vuln_id: "CVE-1" })).toMatch(/No fixed version/);
  });
});

describe("findings filters <-> URL", () => {
  it("defaults to open + fixable only with a clean URL", () => {
    const f = parseFilters({});
    expect(f).toMatchObject({ status: "open", fixable: true, priority: [], q: "" });
    expect(filtersToSearch(f)).toEqual({ q: undefined, priority: undefined, fixable: undefined, status: undefined, asset: undefined, f: undefined });
  });
  it("round-trips non-default state", () => {
    const raw = { q: "openssl", priority: "fix-now,next", fixable: "0", status: "resolved", asset: "a1", f: "x9", kev: "1" };
    const f = parseFilters(raw);
    expect(f).toEqual({ q: "openssl", priority: ["fix-now", "next"], fixable: false, kev: true, status: "resolved", asset: "a1", open: "x9" });
    expect(filtersToSearch(f)).toEqual(raw);
  });
  it("ignores junk and builds the API query", () => {
    expect(parseFilters({ priority: "bogus,low", status: "nope" })).toMatchObject({ priority: ["low"], status: "open" });
    const qs = new URLSearchParams(filtersToApi(parseFilters({ q: "ssl", priority: "next", asset: "a1" })));
    expect(Object.fromEntries(qs)).toMatchObject({ status: "open", q: "ssl", priority: "next", asset_id: "a1", fixable: "true" });
    expect(new URLSearchParams(filtersToApi(parseFilters({ fixable: "0" }))).has("fixable")).toBe(false);
  });
});

describe("install commands", () => {
  it("renders every command with origin and token, the token never in a program's arguments", () => {
    const c = installCommands("https://nim.example", "nme_abc");
    expect(c.curl).toBe("export NIMSTEAD_TOKEN=nme_abc; curl -fsSL https://nim.example/install.sh | sudo --preserve-env=NIMSTEAD_TOKEN sh; unset NIMSTEAD_TOKEN");
    expect(c.windows).toBe('$env:NIMSTEAD_TOKEN = "nme_abc"; irm https://nim.example/install.ps1 | iex');
    expect(c.python).toBe("export NIMSTEAD_TOKEN=nme_abc; python3 nimstead_agent.py enroll --server https://nim.example && python3 nimstead_agent.py report; unset NIMSTEAD_TOKEN");
    for (const cmd of Object.values(c)) expect(cmd).not.toContain("--token"); // ps and sudo logs show every argument
  });
});

describe("remediation helpers", () => {
  const job = (status: string) => ({ id: status, status }) as unknown as Job;
  it("groups jobs by state and drops nothing", () => {
    const jobs = ["planned", "approved", "dispatched", "verifying", "succeeded", "failed", "rolled_back", "rollback_failed", "not_fixed", "aborted"].map(job);
    const g = Object.fromEntries(groupJobs(jobs).map((x) => [x.key, x.jobs.map((j) => j.status)]));
    expect(g.approval).toEqual(["planned"]);
    expect(g.progress).toEqual(["approved", "dispatched", "verifying"]);
    expect(g.done).toEqual(["succeeded"]);
    expect(g.attention).toEqual(["failed", "rolled_back", "rollback_failed", "not_fixed", "aborted"]);
    expect(isActiveJob(job("verifying"))).toBe(true);
    expect(isActiveJob(job("planned"))).toBe(false);
  });
  it("humanises ledger kinds", () => {
    expect(humaniseKind("remediation_not_fixed")).toBe("Remediation not fixed");
    expect(humaniseKind("inventory_received")).toBe("Inventory received");
    expect(humaniseKind("policy_changed")).toBe("Policy changed");
  });
});

describe("AI search helpers", () => {
  it("detects questions", () => {
    expect(looksLikeQuestion("openssl")).toBe(false);
    expect(looksLikeQuestion("CVE-2024-1")).toBe(false);
    expect(looksLikeQuestion("what is exploited?")).toBe(true);
    expect(looksLikeQuestion("show me exploited openssl bugs")).toBe(true);
  });
  it("maps an AI filter to URL filters, dropping junk", () => {
    expect(aiFilterToPatch({ q: "ssl", priority: ["fix-now", "bogus"], status: "resolved", fixable: null, kev: true }))
      .toEqual({ q: "ssl", priority: ["fix-now"], kev: true, fixable: false, status: "resolved" });
  });
});

it("reads the dependencies a refused dry run needs", () => {
  expect(dependenciesNeeded("No changes made: change limited to planned packages failed: would also change: musl, libcrypto3")).toEqual(["musl", "libcrypto3"]);
  expect(dependenciesNeeded("No changes made: drifted: openssl")).toEqual([]);
  expect(dependenciesNeeded(null)).toEqual([]);
});
