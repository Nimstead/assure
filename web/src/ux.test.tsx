// UX rounds 1 and 2 (tasks/plan-0.5-ux.md, plan-0.6-ux.md): behaviour that keeps the reviews' fixes fixed.
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { afterEach, vi } from "vitest";
import { SsoSection } from "./integrations";
import { ApiError, meQ, type Action, type Asset, type Job, type Settings } from "./lib";
import { ActionCard } from "./home";
import { AssetRow, AttackPaths, Baselines, baselineSummary, NotAssessed } from "./assets";
import { Palette } from "./shell";
import { Done, errorLead } from "./ui";
import { Onboarding, TROUBLESHOOT_AFTER_MS } from "./onboarding";
import { ApiTokensSection, QrCode, UsersSection } from "./people";
import { JobCard, KbFleet } from "./remediation";
import { SettingsPage } from "./settings";

// Link keeps its search and hash in the href, so tests can check where a link really goes.
vi.mock("@tanstack/react-router", () => ({
  Link: ({ children, to, search, hash, className }: { children: ReactNode; to: string; search?: Record<string, string | undefined>; hash?: string; className?: string }) => {
    const qs = new URLSearchParams(Object.entries(search ?? {}).filter((e): e is [string, string] => e[1] !== undefined)).toString();
    return <a href={`${to}${qs ? `?${qs}` : ""}${hash ? `#${hash}` : ""}`} className={className}>{children}</a>;
  },
  useNavigate: () => vi.fn(),
  useSearch: () => ({}),
  useRouterState: ({ select }: { select: (r: { location: { pathname: string } }) => unknown }) => select({ location: { pathname: "/" } }),
}));

/** fetch mock answering by "METHOD /path" (query string ignored); records every call. */
function serve(routes: Record<string, unknown>) {
  const calls: { method: string; path: string; body?: unknown }[] = [];
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? "GET", path = String(url).split("?")[0]!;
    calls.push({ method, path, body: init?.body ? JSON.parse(String(init.body)) : undefined });
    const hit = routes[`${method} ${path}`];
    return hit === undefined ? new Response("{}", { status: 404 }) : new Response(JSON.stringify(hit), { status: 200 });
  }));
  return calls;
}
const ME = { email: "admin@example.com", org: "Acme", admin: true, origin: "password" as const, mfa: true, recovery_codes_left: 10 };
function wrap(ui: ReactNode, me = ME) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  qc.setQueryData(meQ.queryKey, me);
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}
afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers(); });

const SETTINGS: Settings = {
  remediation_mode: "approve", canary_soak_hours: 24, sla_days: { "fix-now": 14, next: 30, planned: 90, low: 180 },
  agent_updates_paused: false, signed_agent_release: true, production_remediation_allowed: false,
  platform: { version: "0.4.0", latest: "0.4.0", latest_url: null, update_available: false, checked: null, last_update: null, channel: "stable", running_channel: "stable", latest_channel: null },
} as unknown as Settings;
const HOSTS = [{ id: "h1", kind: "host", ring: 0 }, { id: "h2", kind: "host", ring: 1 }, { id: "h3", kind: "host", ring: 1 }];

it("trust ladder: choosing only selects; Auto needs a confirmation naming the machines", async () => {
  const calls = serve({ "GET /api/settings": SETTINGS, "GET /api/assets": HOSTS, "GET /api/enroll-tokens": [], "GET /api/users": [], "GET /api/tokens": [],
    "GET /api/settings/notifications": { recent: [], emails: [], emails_confirmed: [] }, "GET /api/settings/sso": { domains: [], domain_checks: [] },
    "PATCH /api/settings": { ...SETTINGS, remediation_mode: "auto" } });
  wrap(<SettingsPage />);
  const ladder = await screen.findByRole("radiogroup", { name: "Trust ladder" });
  // Selecting (by click here; e2e covers arrow keys in a real browser) only changes the selection.
  await userEvent.click(within(ladder).getByRole("radio", { name: /Auto/ }));
  expect(within(ladder).getByRole("radio", { name: /Auto/ })).toBeChecked();
  expect(calls.filter((c) => c.method === "PATCH")).toHaveLength(0);  // selecting saves nothing

  const save = within(ladder.parentElement!).getByRole("button", { name: "Save" });
  await userEvent.click(save);
  const dialog = await screen.findByRole("alertdialog", { name: "Let Nimstead fix machines without asking?" });
  expect(dialog).toHaveTextContent("your 3 machines");
  expect(dialog).toHaveTextContent("1 canary machine first");
  expect(calls.filter((c) => c.method === "PATCH")).toHaveLength(0);
  await userEvent.click(within(dialog).getByRole("button", { name: "Switch to Auto" }));
  await waitFor(() => expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({ remediation_mode: "auto" }));
});

it("trust ladder: Suggest saves without a dialog", async () => {
  const calls = serve({ "GET /api/settings": SETTINGS, "GET /api/assets": HOSTS, "GET /api/enroll-tokens": [], "GET /api/users": [], "GET /api/tokens": [],
    "GET /api/settings/notifications": { recent: [], emails: [], emails_confirmed: [] }, "GET /api/settings/sso": { domains: [], domain_checks: [] },
    "PATCH /api/settings": { ...SETTINGS, remediation_mode: "suggest" } });
  wrap(<SettingsPage />);
  const ladder = await screen.findByRole("radiogroup", { name: "Trust ladder" });
  await userEvent.click(within(ladder).getByRole("radio", { name: /Suggest/ }));
  await userEvent.click(within(ladder.parentElement!).getByRole("button", { name: "Save" }));
  expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
  await waitFor(() => expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({ remediation_mode: "suggest" }));
  expect(await within(ladder.parentElement!).findByText("Saved")).toBeInTheDocument();
});

it("revoking an API token asks first, then revokes", async () => {
  const calls = serve({ "GET /api/tokens": [{ id: "t1", name: "ci export", created_by: "a@b.c", created: "2026-10-01T00:00:00", expires: "2027-01-01T00:00:00", last_used: null }], "DELETE /api/tokens/t1": {} });
  wrap(<ApiTokensSection />);
  await userEvent.click(await screen.findByRole("button", { name: /^Revoke\s*ci export$/ }));
  const dialog = screen.getByRole("alertdialog", { name: /Revoke “ci export”/ });
  expect(calls.some((c) => c.method === "DELETE")).toBe(false);
  await userEvent.click(within(dialog).getByRole("button", { name: "Revoke token" }));
  await waitFor(() => expect(calls.some((c) => c.method === "DELETE" && c.path === "/api/tokens/t1")).toBe(true));
});

it("people: no role or remove buttons on your own row; role changes are confirmed", async () => {
  const calls = serve({ "GET /api/users": [
    { id: "u1", email: "admin@example.com", admin: true, origin: "password", mfa: true, created: "" },
    { id: "u2", email: "member@example.com", admin: false, origin: "password", mfa: false, created: "" },
  ], "PATCH /api/users/u2": {} });
  wrap(<UsersSection />);
  const mine = (await screen.findByText(/\(you\)/)).closest("li")!;
  expect(within(mine).queryByRole("button")).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: /^Make admin\s*member@example\.com$/ }));
  const dialog = screen.getByRole("alertdialog", { name: "Make member@example.com an admin?" });
  expect(calls.some((c) => c.method === "PATCH")).toBe(false);
  await userEvent.click(within(dialog).getByRole("button", { name: "Make admin" }));
  await waitFor(() => expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({ admin: true }));
});

it("a verified SSO domain is visibly marked, not ink-on-ink", async () => {
  serve({ "GET /api/settings/sso": { issuer: "", client_id: "", client_secret_set: false, domains: ["example.com"], required: false, redirect_uri: "/cb",
    domain_checks: [{ domain: "example.com", verified: true, txt_name: "", txt_value: "" }] } });
  wrap(<SsoSection />);
  const verified = await screen.findByText("Verified");
  expect(verified).toHaveClass("text-ink");
  expect(verified).not.toHaveClass("text-accent-ink");  // #FFF on #F6F6F5 / #111 on #111: invisible
  expect(verified.querySelector("svg")).not.toBeNull();
});

const job = (status: Job["status"]) => ({ id: "j1", asset_id: "a1", hostname: "web-1", status, manager: "apt", action_key: "Debian:12|openssl", packages: [], finding_ids: [],
  summary: "Upgrade openssl", created_by: "a@b.c", approved_by: null, created: "2026-10-28T00:00:00", updated: "2026-10-28T00:00:00", steps: null, error: null }) as Job;

it("only fixes no machine has picked up can be cancelled", () => {
  serve({});
  const cancellable = ["planned", "approved"] as const;
  for (const status of ["planned", "approved", "dispatched", "verifying", "succeeded", "failed"] as const) {
    const r = wrap(<ul><JobCard job={job(status)} onCancel={() => {}} onApprove={() => {}} /></ul>);
    expect(!!screen.queryByRole("button", { name: /^Cancel/ })).toBe((cancellable as readonly string[]).includes(status));
    r.unmount();
  }
});

it("a job card links its summary and host to that machine's findings, and has an address", () => {
  serve({});
  const { container } = wrap(<ul><JobCard job={job("planned")} /></ul>);
  const summary = new URL(screen.getByRole("link", { name: "Upgrade openssl" }).getAttribute("href")!, "http://x");
  expect(summary.pathname).toBe("/findings");
  expect(summary.searchParams.get("asset")).toBe("a1");
  expect(summary.searchParams.get("q")).toBe("openssl");
  const host = new URL(screen.getByRole("link", { name: "web-1" }).getAttribute("href")!, "http://x");
  expect(host.pathname).toBe("/findings");
  expect(host.searchParams.get("asset")).toBe("a1");
  expect(container.querySelector("li#job-j1")).not.toBeNull();
});

it("onboarding asks test or production with no default, then posts that choice", async () => {
  const calls = serve({ "GET /api/assets": [], "POST /api/enroll-tokens": { token: "nme_t" } });
  wrap(<Onboarding />);
  const create = screen.getByRole("button", { name: "Create install command" });
  expect(create).toBeDisabled();
  expect(screen.getByRole("radio", { name: /Test machines/ })).not.toBeChecked();
  expect(screen.getByRole("radio", { name: /Production machines/ })).not.toBeChecked();
  await userEvent.click(screen.getByRole("radio", { name: /Production machines/ }));
  await userEvent.click(create);
  await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toEqual({ sandbox: false }));
  expect(await screen.findByText(/Waiting for the first report/)).toBeInTheDocument();
});

it("onboarding shows troubleshooting when no report arrives", async () => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  serve({ "GET /api/assets": [] as Asset[], "POST /api/enroll-tokens": { token: "nme_t" } });
  wrap(<Onboarding />);
  const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
  await user.click(screen.getByRole("radio", { name: /Test machines/ }));
  await user.click(screen.getByRole("button", { name: "Create install command" }));
  await screen.findByText(/Waiting for the first report/);
  expect(screen.queryByText("Nothing yet? Check these:")).not.toBeInTheDocument();
  await act(async () => { vi.advanceTimersByTime(TROUBLESHOOT_AFTER_MS + 100); });
  expect(screen.getByText("Nothing yet? Check these:")).toBeInTheDocument();
  expect(screen.getAllByText("doctor").length).toBeGreaterThan(0);
  expect(screen.getByText("/var/lib/nimstead/agent.log")).toBeInTheDocument();
  expect(screen.getByText("C:\\ProgramData\\Nimstead\\agent.log")).toBeInTheDocument();
});

it("TOTP setup draws a QR code of the otpauth URI, dark on white in any theme", () => {
  render(<QrCode text="otpauth://totp/Nimstead:a%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Nimstead" />);
  const img = screen.getByRole("img", { name: "QR code for your authenticator app" });
  const path = img.querySelector("path")!;
  expect(path).toHaveAttribute("fill", "#111");
  expect(img.getAttribute("viewBox")).toMatch(/^0 0 \d+ \d+$/);
  expect(path.getAttribute("d")).toMatchSnapshot();
});

// ---- round 2 ---------------------------------------------------------------------------------------------------------
const HOST = { id: "a1", hostname: "web-1", kind: "host", os_name: "Debian 13", criticality: "high", internet_facing: true, sandbox: false, ring: 0,
  health_units: ["nginx"], open_by_priority: {}, last_seen: "2026-01-01T00:00:00", agent_version: "0.3.0", agent_update: "current" } as unknown as Asset;
const SETTINGS_API = {
  "GET /api/settings": SETTINGS, "GET /api/assets": HOSTS, "GET /api/enroll-tokens": [], "GET /api/users": [], "GET /api/tokens": [],
  "GET /api/settings/notifications": { recent: [], emails: [], emails_confirmed: [] }, "GET /api/settings/sso": { domains: [], domain_checks: [] },
};

it("non-admins read an asset's settings instead of getting controls the API refuses", () => {
  serve({});
  wrap(<ul><AssetRow a={HOST} onPatch={() => {}} onDelete={() => {}} /></ul>, { ...ME, admin: false });
  expect(screen.queryByRole("combobox")).not.toBeInTheDocument();
  expect(screen.queryByRole("switch")).not.toBeInTheDocument();
  expect(screen.queryByRole("textbox")).not.toBeInTheDocument();
  expect(screen.getByText(/Ring:/)).toHaveTextContent("Ring: Canary");
  expect(screen.getByText(/Health units:/)).toHaveTextContent("nginx");
});

it("Settings and onboarding name the setting that turns production remediation on", async () => {
  serve(SETTINGS_API);
  const r = wrap(<SettingsPage />);
  expect(await screen.findByText(/NIMSTEAD_ALLOW_PRODUCTION_REMEDIATION=1/)).toBeInTheDocument();
  r.unmount();
  serve({ "GET /api/assets": [] });
  wrap(<Onboarding />);
  expect(screen.getByRole("radio", { name: /Production machines/ })).toHaveTextContent("NIMSTEAD_ALLOW_PRODUCTION_REMEDIATION=1");
});

const ACTION: Action = { ecosystem: "Debian:12", package: "openssl", fixed_version: "3.0.19", hosts: ["web-1", "web-2"], asset_ids: ["a1", "a2"],
  busy_asset_ids: [], vulns: ["CVE-1"], kev: false, max_score: 80, job: null, last_attempt: null,
  summary: null, fix: "apt", plannable: true, person_only: false, forward_only: false };

it("Home: a setting fix reads as a setting, says a person approves it, and plans like any other", async () => {
  const calls = serve({ "POST /api/remediation/jobs": { id: "j2" } });
  wrap(<ol><ActionCard a={{ ...ACTION, ecosystem: "WinConfig", package: "wdigest", fixed_version: null, vulns: ["CFG:wdigest"], summary: "WDigest keeps passwords in memory.", fix: "winconfig", person_only: true }} /></ol>);
  expect(screen.getByText(/Change setting/)).toHaveTextContent("Change setting wdigest");
  expect(screen.getByText("WDigest keeps passwords in memory.")).toBeInTheDocument();
  expect(screen.getByText(/Fixes 1 finding on 2 hosts/)).toBeInTheDocument();
  expect(screen.getByText(/A person approves this one/)).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: /Plan fix/ }));
  await waitFor(() => expect(calls.filter((c) => c.method === "POST")).toHaveLength(2));
  expect(calls.find((c) => c.method === "POST")?.body).toEqual({ asset_id: "a1", ecosystem: "WinConfig", package: "wdigest" });
});

it("Home: a winget fix says it can't be undone; a product with no fix path offers no plan", () => {
  serve({});
  const r = wrap(<ol><ActionCard a={{ ...ACTION, ecosystem: "WinApp", package: "7-zip:7-zip", fix: "winget", person_only: true, forward_only: true }} /></ol>);
  expect(screen.getByText(/A person approves this one.*can't be undone/)).toBeInTheDocument();
  r.unmount();
  wrap(<ol><ActionCard a={{ ...ACTION, ecosystem: "Microsoft", package: "SQL Server", fix: "winget", plannable: false, person_only: true }} /></ol>);
  expect(screen.queryByRole("button", { name: /Plan fix/ })).not.toBeInTheDocument();
  expect(screen.getByText(/update it with its own updater/)).toBeInTheDocument();
});

it("Home: a fix in flight on one host still lets you plan the others", () => {
  serve({});
  wrap(<ol><ActionCard a={{ ...ACTION, busy_asset_ids: ["a1"], job: { id: "j1", status: "approved" } }} /></ol>);
  expect(screen.getByRole("link", { name: /View fix/ })).toHaveAttribute("href", "/remediation#job-j1");
  expect(screen.getByRole("button", { name: /Plan fix for 1 more host/ })).toBeInTheDocument();
});

it("Home: after an aborted attempt that needs more packages, it points to the job instead of re-planning blind", () => {
  serve({});
  const aborted = { id: "j9", status: "aborted" as const, error: "No changes made: would also change: musl" };
  const r = wrap(<ol><ActionCard a={{ ...ACTION, last_attempt: aborted }} /></ol>);
  expect(screen.getByRole("link", { name: /Last attempt aborted: review/ })).toHaveAttribute("href", "/remediation#job-j9");
  expect(screen.queryByRole("button", { name: /Plan fix/ })).not.toBeInTheDocument();
  r.unmount();
  wrap(<ol><ActionCard a={{ ...ACTION, last_attempt: { ...aborted, status: "rolled_back", error: "health check failed" } }} /></ol>);
  expect(screen.getByRole("button", { name: /Plan fix again/ })).toBeInTheDocument();  // nothing extra needed: trying again is fine
});

it("Windows updates: a count per KB opens to why each machine hasn't got it, and plans only who the rollout allows", async () => {
  const row = { kb: "5127648", product: "Windows 11", title: "October 2026 cumulative KB5127648", released: "2026-10-14", build: "10.0.26200.9711", hosts: 50, fixed: 48, plan_note: "Canary machines first." };
  const calls = serve({
    "GET /api/windows-updates": [row, { ...row, kb: "5120000", title: "September 2026 cumulative KB5120000", fixed: 50 }],
    "GET /api/windows-updates/5127648": { ...row, plan_asset_ids: ["c1"], missing: [
      { asset_id: "c1", hostname: "canary-1", build: "10.0.26200.6899", ring: 0, why: "No job yet", notes: ["A restart is pending, which can change its build"], job: null },
      { asset_id: "h2", hostname: "pc-2", build: "10.0.26200.6899", ring: 1, why: "Last attempt rolled back: health check failed", notes: [], job: { id: "j7", status: "rolled_back" } },
    ] },
    "POST /api/remediation/jobs": { id: "j8" },
  });
  wrap(<KbFleet />);
  expect(await screen.findByText("48 of 50 hosts")).toBeInTheDocument();
  expect(screen.getByText("50 of 50 hosts")).toBeInTheDocument();
  expect(screen.getAllByText(/machines? without it/)).toHaveLength(1);  // a fully patched update has nothing to open
  expect(calls.some((c) => c.path.endsWith("/5127648"))).toBe(false);  // the hosts load when asked for
  await userEvent.click(screen.getByText(/Show 2 machines without it/));
  expect(await screen.findByText("No job yet")).toBeInTheDocument();
  expect(screen.getByText("(canary)", { exact: false })).toBeInTheDocument();
  expect(screen.getByText(/restart is pending/)).toBeInTheDocument();
  expect(screen.getByRole("link", { name: /rolled back: health check failed/ })).toHaveAttribute("href", "/remediation#job-j7");
  expect(screen.getByText("Canary machines first.")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: /Plan 1 machine now/ }));
  await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toEqual({ asset_id: "c1", ecosystem: "Windows", package: "Windows 11" }));
  expect(calls.filter((c) => c.method === "POST")).toHaveLength(1);
});

it("Windows updates: nothing shows on a fleet with no Windows", async () => {
  const calls = serve({ "GET /api/windows-updates": [] });
  const r = wrap(<KbFleet />);
  await waitFor(() => expect(calls).toHaveLength(1));
  expect(r.container).toBeEmptyDOMElement();
});

it("Done is announced through the shell's live region", async () => {
  const live = document.createElement("div");
  live.id = "live";
  document.body.append(live);
  render(<Done>Saved</Done>);
  await waitFor(() => expect(live).toHaveTextContent("Saved"));
  live.remove();
});

it("an out-of-range deadline is marked invalid and says why, on that field", async () => {
  serve(SETTINGS_API);
  wrap(<SettingsPage />);
  const next = await screen.findByRole("spinbutton", { name: "Next" });
  await userEvent.clear(next);
  await userEvent.type(next, "900");
  expect(next).toHaveAttribute("aria-invalid", "true");
  expect(next).toHaveAccessibleDescription("1 to 365 days");
});

it("saving one Settings section keeps what you typed in another", async () => {
  const calls = serve({ ...SETTINGS_API, "PATCH /api/settings": { ...SETTINGS, agent_updates_paused: true } });
  wrap(<SettingsPage />);
  const next = await screen.findByRole("spinbutton", { name: "Next" });
  await userEvent.clear(next);
  await userEvent.type(next, "21");
  await userEvent.click(screen.getByRole("switch"));
  await waitFor(() => expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({ agent_updates_paused: true }));
  await screen.findByText("Saved");
  expect(screen.getByRole("spinbutton", { name: "Next" })).toHaveValue(21);
});

it("the palette keeps the highlighted command when late results arrive, and finds hosts", async () => {
  let release: ((v: Response) => void) | null = null;
  vi.stubGlobal("fetch", vi.fn(async (url: string) => String(url).startsWith("/api/assets")
    ? new Response(JSON.stringify([{ ...HOST, hostname: "go-web-1" }]), { status: 200 })
    : new Promise<Response>((r) => { release = r; })));
  wrap(<Palette open onOpenChange={() => {}} signOut={() => {}} nextTheme={() => {}} />);
  const box = screen.getByRole("combobox");
  await userEvent.type(box, "go");
  await screen.findByRole("option", { name: /Host: go-web-1/ });
  await userEvent.keyboard("{ArrowDown}{ArrowDown}");
  const chosen = box.getAttribute("aria-activedescendant");
  expect(chosen).toBeTruthy();
  await waitFor(() => expect(release).not.toBeNull());  // the debounced findings search has been sent
  await act(async () => { release!(new Response(JSON.stringify([{ id: "f1", vuln_id: "CVE-1", package: "go", hostname: "h" }]), { status: 200 })); });
  await screen.findByRole("option", { name: /CVE-1/ });
  expect(box.getAttribute("aria-activedescendant")).toBe(chosen);  // a new row arriving above didn't move the highlight
});

it("the palette never dead-ends: any text offers a findings search, and the list is a valid listbox", async () => {
  serve({ "GET /api/assets": [], "GET /api/findings": [] });
  wrap(<Palette open onOpenChange={() => {}} signOut={() => {}} nextTheme={() => {}} />);
  await userEvent.type(screen.getByRole("combobox"), "zzzzzz");
  expect(await screen.findByRole("option", { name: 'Search findings for "zzzzzz"' })).toBeInTheDocument();
  expect(screen.getByRole("combobox")).toHaveAttribute("aria-expanded", "true");
  expect(within(screen.getByRole("listbox")).getAllByRole("option").length).toBeGreaterThan(0);
});

it("error states say what kind of problem it is", () => {
  expect(errorLead(new ApiError(0, "x"))).toMatch(/Can't reach the server/);
  expect(errorLead(new ApiError(403, "x"))).toMatch(/don't have access/);
  expect(errorLead(new ApiError(502, "x"))).toMatch(/server had a problem/);
});

it("a token without an expiry says so instead of crashing Settings", async () => {
  serve({ "GET /api/tokens": [{ id: "t1", name: "old", created_by: "a@b.c", created: "2026-01-01T00:00:00", expires: null, last_used: null }] });
  wrap(<ApiTokensSection />);
  expect(await screen.findByText(/never expires/)).toBeInTheDocument();
});

it("Assets: says which installed apps weren't checked, and a host with none checked says so", async () => {
  serve({ "GET /api/coverage": { assessed: 1, inventory_only: 3, not_assessed: [{ name: "Acme Widget", publisher: "Acme", hosts: 2 }] } });
  wrap(<NotAssessed />);
  expect(await screen.findByRole("heading", { name: "3 installed apps aren't checked for vulnerabilities" })).toBeInTheDocument();
  expect(screen.getByText("Acme Widget")).toBeInTheDocument();
  wrap(<ul><AssetRow a={{ ...HOST, apps: { assessed: 0, inventory_only: 2 } }} onPatch={() => {}} onDelete={() => {}} /></ul>);
  expect(screen.getByText("None of its 2 installed apps could be checked.")).toBeInTheDocument();
});

it("Assets: nothing shows when every installed app was checked", async () => {
  const calls = serve({ "GET /api/coverage": { assessed: 4, inventory_only: 0, not_assessed: [] } });
  wrap(<NotAssessed />);
  await waitFor(() => expect(calls.some((c) => c.path === "/api/coverage")).toBe(true));
  expect(screen.queryByRole("heading")).toBeNull();
});

it("Assets: attack paths say how sure, where to cut each edge, and nothing shows without a path", async () => {
  const path = { kind: "network", start: "from the network", grade: "reasonable", steps: ["Getting in", "Taking credentials"],
                 break_at: { label: "Getting in", fixes: 1, refs: ["CFG:rdp-nla"] } };
  serve({ "GET /api/attack-paths": { hosts: { a: { hostname: "ws-1", judged: true, paths: [path] }, b: { hostname: "srv-1", judged: true, paths: [] },
                                              c: { hostname: "new-1", judged: false, paths: [] } },
                                     chains: [{ start: "a", why_start: "a path from the network", reach: [{ host: "b", hops: ["b"], grade: "reasonable", fix_on_host: ["CFG:remote-uac"] }] }] } });
  wrap(<AttackPaths />);
  expect(await screen.findByText(/From ws-1 \(a path from the network\), an attacker can reach 1 other host/)).toBeInTheDocument();
  expect(screen.getByText(/ws-1 → srv-1 · how sure: reasonable · cut it on srv-1: CFG:remote-uac/)).toBeInTheDocument();
  expect(screen.getByText(/1 host hasn't been judged yet/)).toBeInTheDocument();
  expect(screen.getByText(/Break it: fix 1 way of getting in \(CFG:rdp-nla\)/)).toBeInTheDocument();
});

it("Assets: no attack paths, no section", async () => {
  const calls = serve({ "GET /api/attack-paths": { hosts: { a: { hostname: "ws-1", judged: true, paths: [] } }, chains: [] } });
  wrap(<AttackPaths />);
  await waitFor(() => expect(calls.some((c) => c.path === "/api/attack-paths")).toBe(true));
  expect(screen.queryByRole("heading")).toBeNull();
});

const BASE = { name: "DISA STIG for Windows Server 2025", version: "V1R4", automated: 156, manual: 135, pass: 100, fail: 20, not_assessed: 16, not_applicable: 20 };

it("Assets: a baseline reads as a share of the checks we can automate, never as conformance", async () => {
  expect(baselineSummary(BASE)).toBe("100 of 136 checks we can automate pass, 20 fail, 16 not assessed");
  serve({ "GET /api/baselines": { no_baseline: 1, baselines: [{ ...BASE, baseline_id: "x", hosts: 1 }], hosts: [{ ...BASE, asset_id: "a", hostname: "srv-1" }] } });
  wrap(<Baselines />);
  expect(await screen.findByText(/A reference, not a conformance result/)).toBeInTheDocument();
  expect(screen.getByText(/manual checks are not assessed/)).toBeInTheDocument();
  expect(screen.getByText(/135 manual checks not assessed/)).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Download as CSV" })).toHaveAttribute("href", "/api/baselines.csv");
  expect(document.body.textContent).not.toMatch(/compliant/i);
});
