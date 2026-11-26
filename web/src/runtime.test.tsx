// What runs (tasks/spec-runtime.md Module 4, DECISIONS 161-163): a finding says which programs load its package and where they
// listen, a fix on disk still running says to restart, Fix first counts machines and lists restarts, and an approval names the
// services a fix will restart.
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, vi } from "vitest";
import { filtersToApi, filtersToSearch, meQ, parseFilters, type Action, type FindingRunning, type Job } from "./lib";
import { Running } from "./findings";
import { ActionCard, RestartsToFinish } from "./home";
import { JobCard, RestartNote } from "./remediation";

vi.mock("@tanstack/react-router", () => ({
  Link: ({ children, to, search, hash, className }: { children: ReactNode; to: string; search?: Record<string, string | undefined>; hash?: string; className?: string }) => {
    const qs = new URLSearchParams(Object.entries(search ?? {}).filter((e): e is [string, string] => e[1] !== undefined)).toString();
    return <a href={`${to}${qs ? `?${qs}` : ""}${hash ? `#${hash}` : ""}`} className={className}>{children}</a>;
  },
  useNavigate: () => vi.fn(),
  useSearch: () => ({}),
  useRouterState: ({ select }: { select: (r: { location: { pathname: string } }) => unknown }) => select({ location: { pathname: "/" } }),
}));
function wrap(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  qc.setQueryData(meQ.queryKey, { email: "a@example.com", org: "Acme", admin: true, origin: "password", mfa: true, recovery_codes_left: 10 });
  vi.stubGlobal("fetch", vi.fn(async () => new Response("[]", { status: 200 })));
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}
afterEach(() => vi.unstubAllGlobals());

const NOW = new Date().toISOString().slice(0, 19);
const R: FindingRunning = {
  state: "listening", binary: "libssl3t64", binaries: ["libssl3t64", "openssl"], reason: "…", read_at: NOW, read_state: "ok", read_problem: null,
  since: "2026-11-20T10:00:00", covered: false,
  programs: [{ name: "nginx.service", users: ["root", "www-data"], listen: ["0.0.0.0:443/tcp", "[::]:443/tcp"], loads: ["libssl3t64"], replaced: [] },
    { name: "postgresql@17-main.service", users: ["postgres"], listen: ["127.0.0.1:5432/tcp"], loads: ["libssl3t64"], replaced: [] }],
};

it("a finding names the programs that load its package and where each listens", () => {
  wrap(<Running r={R} pkg="openssl" />);
  const block = screen.getByRole("heading", { name: "What runs it" }).nextElementSibling as HTMLElement;
  expect(block).toHaveTextContent("libssl3t64 (from openssl) is loaded by a program listening on the network.");
  const [nginx, pg] = within(block).getAllByRole("listitem");
  expect(nginx).toHaveTextContent("nginx.service as root, www-data · listening on 0.0.0.0:443/tcp, [::]:443/tcp");
  expect(pg).toHaveTextContent("postgresql@17-main.service as postgres · listening on this machine only (127.0.0.1:5432/tcp)");
  expect(block).toHaveTextContent(/Read (just now|\d+ (seconds?|minutes?) ago)\./);
});

it("a fix on disk that a program still runs says to restart it", () => {
  wrap(<Running r={{ ...R, state: "restart", programs: [{ ...R.programs[0]!, replaced: ["libssl3t64"] }] }} pkg="openssl" />);
  expect(screen.getByText(/Fixed on disk, still running\./).parentElement).toHaveTextContent(
    "Fixed on disk, still running. nginx.service still runs the copy the fix replaced, so the vulnerable code is still in memory. Restart it (or the machine) and this closes on the next report.");
  expect(screen.getByRole("listitem")).toHaveTextContent("runs a replaced copy");
});

it("not loaded says what a sample can't see, and an unproven one says how long it has watched", () => {
  const { unmount } = wrap(<Running r={{ ...R, state: "not_loaded", programs: [], covered: true }} pkg="openssl" />);
  expect(screen.getByText(/No long-running program/)).toHaveTextContent(
    "No long-running program has loaded openssl in seven days of reads. Programs that run for a moment, like cron jobs and commands, aren't seen, so this lowers only flaws reached over the network, never known-exploited ones or local ones.");
  unmount();
  wrap(<Running r={{ ...R, state: null, programs: [], read_state: "partial", read_problem: "not run as root" }} pkg="openssl" />);
  expect(screen.getByText(/No program was seen loading openssl/)).toHaveTextContent(/only after seven days of complete reads; it has been watching since 20 Nov/);
  expect(screen.getByText(/in part: not run as root/)).toBeInTheDocument();
});

it("the Running filter lives in the URL and reaches the API", () => {
  const f = parseFilters({ running: "restart" });
  expect(f.running).toBe("restart");
  expect(filtersToSearch(f).running).toBe("restart");
  expect(new URLSearchParams(filtersToApi(f)).get("runtime")).toBe("restart");
  expect(parseFilters({ running: "bogus" }).running).toBe("");
  expect(new URLSearchParams(filtersToApi(parseFilters({}))).has("runtime")).toBe(false);
});

it("Fix first lists fixes waiting for a restart, each linked to its findings", () => {
  wrap(<RestartsToFinish rows={[{ package: "openssl", findings: 42, kev: false, max_score: 61, hosts: ["web-1", "web-2", "web-3"], asset_ids: ["a", "b", "c"],
    programs: ["nginx.service", "php8.2-fpm.service"] }]} />);
  const card = screen.getByRole("region", { name: "Restart to finish" });
  expect(card).toHaveTextContent("42 findings are fixed on disk, but a running program still uses the copy the fix replaced");
  expect(within(card).getByRole("listitem")).toHaveTextContent("openssl on web-1, web-2 and 1 more machine: restart nginx.service, php8.2-fpm.service");
  expect(within(card).getByRole("link")).toHaveAttribute("href", "/findings?q=openssl&running=restart");
});

const ACTION: Action = {
  ecosystem: "Debian:13", package: "openssl", fixed_version: "3.5.4-1~deb13u2", hosts: ["web-1", "web-2", "db-1"], asset_ids: ["a", "b", "c"], vulns: ["CVE-2025-1"],
  kev: false, max_score: 70, summary: null, fix: "apt", plannable: true, person_only: false, forward_only: false, job: null, busy_asset_ids: [], last_attempt: null,
  runtime: { listening: 2, loaded: 3, not_loaded: 0 },
};

it("an upgrade on Fix first says how many machines load it, and listen", () => {
  wrap(<ol><ActionCard a={ACTION} /></ol>);
  const link = screen.getByRole("link", { name: "Loaded by a program listening on the network on 2 machines" });
  expect(link).toHaveAttribute("href", "/findings?q=openssl&eco=Debian%3A13&running=listening");
  expect(link.parentElement).toHaveTextContent(", by one not listening on 1 more");
});

it("an upgrade nothing loads says so, and one with no read says nothing", () => {
  const { unmount } = wrap(<ol><ActionCard a={{ ...ACTION, runtime: { listening: 0, loaded: 0, not_loaded: 3 } }} /></ol>);
  expect(screen.getByText("Not loaded by any long-running program on these machines in a week of reads.")).toBeInTheDocument();
  unmount();
  wrap(<ol><ActionCard a={{ ...ACTION, runtime: undefined }} /></ol>);
  expect(screen.queryByText(/Loaded by|Not loaded/)).toBeNull();
});

const JOB: Job = {
  id: "j1", asset_id: "a", hostname: "web-1", status: "planned", manager: "apt", action_key: "Debian:13|openssl", packages: [{ name: "libssl3t64", from: "3.5.1-1" }],
  finding_ids: ["f1"], summary: "Upgrade openssl to 3.5.4-1~deb13u2 on web-1", created_by: "a@example.com", approved_by: null, created: NOW, updated: NOW, steps: [], error: null,
  restarts: { services: ["nginx.service", "php8.2-fpm.service"], left: ["dbus.service"] },
};

it("an approval names the services the fix restarts, and what it leaves running", () => {
  wrap(<RestartNote r={JOB.restarts!} />);
  expect(screen.getByTestId("restarts")).toHaveTextContent(
    "Restarts nginx.service and php8.2-fpm.service after the upgrade: they ran these packages at the last report, so the fix takes effect, and the health checks include them. Won't restart dbus.service: the fix waits until it restarts (or the machine does).");
});

it("a fix waiting for a restart reads as waiting, not as a failure", () => {
  wrap(<ul><JobCard job={{ ...JOB, status: "verifying", error: "Waiting for a restart: the fix is installed, but dbus.service still runs the copy it replaced" }} /></ul>);
  expect(screen.getByText(/Waiting for a restart/)).toHaveTextContent(
    "Waiting for a restart: the fix is installed, but dbus.service still runs the copy it replaced. It succeeds on the first report after the restart.");
  expect(screen.queryByRole("alert")).toBeNull();
});

it("a finding waiting for a restart says to restart, not to plan the fix again", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => new Response("[]", { status: 200 })));
  const { FindingDetail } = await import("./findings");
  const f = { id: "f1", asset_id: "a", hostname: "web-1", asset_kind: "host", ecosystem: "Debian:13", package: "openssl", installed_version: "3.5.1-1",
    fixed_version: "3.5.4-1", setting_fix: false, plannable: false, vuln_id: "CVE-2025-1", advisory_ids: [], summary: null, cvss: null, epss: null, kev: false,
    score: 45, priority: "planned", reasons: ["Still open: the fixed version is installed, but nginx.service still runs the copy it replaced: restart it (or the machine)"],
    status: "open", first_seen: NOW, last_seen: NOW, resolved_at: null, due: null, runtime: "restart",
    running: { ...R, state: "restart", programs: [{ ...R.programs[0]!, replaced: ["libssl3t64"] }] } } as unknown as Parameters<typeof FindingDetail>[0]["f"];
  wrap(<FindingDetail f={f} />);
  expect(await screen.findByText(/The fix is installed\. Restart the programs/)).toBeInTheDocument();
  expect(screen.queryByText(/can't plan this one/)).toBeNull();
  expect(screen.queryByRole("button", { name: /Plan fix/ })).toBeNull();
});
