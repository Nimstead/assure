import { filtersToApi, filtersToSearch, installCommands, parseFilters, priorityOf, relativeTime, whyMatched } from "./lib";

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
    const raw = { q: "openssl", priority: "fix-now,next", fixable: "0", status: "resolved", asset: "a1", f: "x9" };
    const f = parseFilters(raw);
    expect(f).toEqual({ q: "openssl", priority: ["fix-now", "next"], fixable: false, status: "resolved", asset: "a1", open: "x9" });
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
  it("renders both commands with origin and token", () => {
    const c = installCommands("https://nim.example", "nme_abc");
    expect(c.curl).toBe("curl -fsSL https://nim.example/install.sh | sudo sh -s -- --token nme_abc");
    expect(c.python).toBe("python3 nimstead_agent.py enroll --server https://nim.example --token nme_abc && python3 nimstead_agent.py report");
  });
});
