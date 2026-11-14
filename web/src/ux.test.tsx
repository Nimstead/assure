// UX rounds 1 and 2 (tasks/plan-0.5-ux.md, plan-0.6-ux.md): behaviour that keeps the reviews' fixes fixed.
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState, type ReactNode } from "react";
import { afterEach, vi } from "vitest";
import { SsoSection } from "./integrations";
import { ApiError, meQ, type Action, type Asset, type Finding, type Job, type Settings } from "./lib";
import { ActionCard, Home } from "./home";
import { PlanFixButton } from "./planfix";
import { foldRuns } from "./evidence";
import { ApproveDialog, byPackage, RemediationPage, RolloutCard, sections } from "./remediation";
import { AgentUpdateSummary, AssetRow, AssetsPage, AttackPaths, Baselines, baselineSummary, filterAssets, NotAssessed, UnmanagedDevices } from "./assets";
import { cmdGroup, KeyboardShortcuts, Palette } from "./shell";
import { Done, errorLead } from "./ui";
import { Onboarding, TROUBLESHOOT_AFTER_MS } from "./onboarding";
import { ApiTokensSection, QrCode, UsersSection } from "./people";
import { JobCard, KbFleet, machineContext, stepState } from "./remediation";
import { AcceptRisk, FindingsPage } from "./findings";
import { EvidencePage } from "./evidence";
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

it("a job card links its summary to that machine's findings, its host to the machine, and has an address", () => {
  serve({});
  const { container } = wrap(<ul><JobCard job={job("planned")} /></ul>);
  const summary = new URL(screen.getByRole("link", { name: "Upgrade openssl" }).getAttribute("href")!, "http://x");
  expect(summary.pathname).toBe("/findings");
  expect(summary.searchParams.get("asset")).toBe("a1");
  expect(summary.searchParams.get("q")).toBe("openssl");
  const host = new URL(screen.getByRole("link", { name: "web-1" }).getAttribute("href")!, "http://x");
  expect(host.pathname).toBe("/assets");  // a name opens that thing's detail (DESIGN.md)
  expect(host.searchParams.get("machine")).toBe("a1");
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
  const calls = serve({ "POST /api/remediation/jobs/batch": { jobs: [{ id: "j2" }], errors: [] } });
  wrap(<ol><ActionCard a={{ ...ACTION, ecosystem: "WinConfig", package: "wdigest", fixed_version: null, vulns: ["CFG:wdigest"], summary: "WDigest keeps passwords in memory.", fix: "winconfig", person_only: true }} /></ol>);
  expect(screen.getByText(/Change setting/)).toHaveTextContent("Change setting wdigest");
  expect(screen.getByText("WDigest keeps passwords in memory.")).toBeInTheDocument();
  expect(screen.getByText(/Fixes 1 finding on 2 machines/)).toBeInTheDocument();
  expect(screen.getByText(/A person approves this one/)).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: /Plan fix/ }));
  await waitFor(() => expect(calls.filter((c) => c.method === "POST")).toHaveLength(1));  // both hosts in one request
  expect(calls.find((c) => c.method === "POST")?.body).toEqual({ asset_ids: ["a1", "a2"], ecosystem: "WinConfig", package: "wdigest" });
  // it stays on the page and says what it planned, with the way to approve it
  expect(await screen.findByText("Planned: awaiting approval.")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: /Review and approve/ })).toHaveAttribute("href", "/remediation#job-j2");
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

it("Home: with production remediation off, a fix says how many of its machines can be fixed from here", async () => {
  serve({ "GET /api/settings": { production_remediation_allowed: false },
    "GET /api/assets": [{ id: "a1", hostname: "web-1", sandbox: true }, { id: "a2", hostname: "web-2", sandbox: false }] });
  // the test machine already has a fix in flight: it still counts as one this server may change
  wrap(<ol><ActionCard a={{ ...ACTION, busy_asset_ids: ["a1"], job: { id: "j1", status: "planned" } }} /></ol>);
  expect(await screen.findByText(/1 of 2 fixable here/)).toBeInTheDocument();
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
    "POST /api/remediation/jobs/batch": { jobs: [{ id: "j8" }], errors: [] },
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
  await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toEqual({ asset_ids: ["c1"], ecosystem: "Windows", package: "Windows 11" }));
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
    : String(url).includes("by=package") ? new Response(JSON.stringify([{ key: "go", package: "go", ecosystem: "Go", packages: 1, vulns: 2, hosts: 3, findings: 6 },
        { key: "go", package: "go", ecosystem: "Debian:13", packages: 1, vulns: 1, hosts: 1, findings: 1 }]), { status: 200 })  // one package, two distributions
    : new Promise<Response>((r) => { release = r; })));
  wrap(<Palette open onOpenChange={() => {}} signOut={() => {}} nextTheme={() => {}} />);
  const box = screen.getByRole("combobox");
  await userEvent.type(box, "go");
  await screen.findByRole("option", { name: /Machine: go-web-1/ });
  await userEvent.keyboard("{ArrowDown}{ArrowDown}");
  const chosen = box.getAttribute("aria-activedescendant");
  expect(chosen).toBeTruthy();
  await waitFor(() => expect(release).not.toBeNull());  // the debounced findings search has been sent
  await act(async () => { release!(new Response(JSON.stringify([{ key: "CVE-1", vuln_id: "CVE-1", package: "go", packages: 1, hosts: 34, findings: 34 }]), { status: 200 })); });
  await screen.findByRole("option", { name: /CVE-1.*34 hosts/ });  // the real total, from the grouped count
  expect(screen.getByRole("option", { name: /Package: go.*2 distributions · 4 hosts/ })).toBeInTheDocument();  // one row, both distributions
  const ids = within(screen.getByRole("listbox")).getAllByRole("option").map((o) => o.id);
  expect(new Set(ids).size).toBe(ids.length);  // every option has its own id, so the arrow keys can reach each
  expect(box.getAttribute("aria-activedescendant")).toBe(chosen);  // a new row arriving above didn't move the highlight
});

it("the palette offers a device as a device, never as a machine", async () => {
  serve({ "GET /api/assets": [{ ...HOST, hostname: "go-web-1" }, { ...HOST, id: "d1", kind: "device", hostname: "192.168.1.64", os_name: "Hikvision", facts: { mac: "bc:ba:c2:11:22:33", vendor: "Hikvision" } }], "GET /api/findings/groups": [] });
  wrap(<Palette open onOpenChange={() => {}} signOut={() => {}} nextTheme={() => {}} />);
  await userEvent.type(screen.getByRole("combobox"), "go");
  await screen.findByRole("option", { name: /Machine: go-web-1/ });
  await userEvent.clear(screen.getByRole("combobox"));
  await userEvent.type(screen.getByRole("combobox"), "192.168");
  await screen.findByRole("option", { name: /Search findings/ });
  expect(screen.queryByRole("option", { name: /Machine: 192\.168\.1\.64/ })).toBeNull();
  expect(screen.getByRole("option", { name: /Device: 192\.168\.1\.64/ })).toBeInTheDocument();
});

it("the palette never dead-ends: any text offers a findings search, and the list is a valid listbox", async () => {
  serve({ "GET /api/assets": [], "GET /api/findings/groups": [] });
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

it("Findings: Accept risk opens its form, asks for a reason and records the acceptance", async () => {
  const calls = serve({ "POST /api/findings/f1/accept": {} });
  wrap(<AcceptRisk f={{ id: "f1", vuln_id: "CVE-1" } as Finding} />);
  await userEvent.click(screen.getByRole("button", { name: "Accept risk" }));  // used to throw: a hook after the early return
  const reason = screen.getByRole("textbox", { name: /Reason/ });
  await userEvent.type(reason, "isolated lab box, no network");
  await userEvent.click(screen.getByRole("button", { name: /^Accept/ }));
  await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toEqual({ reason: "isolated lab box, no network", days: 90 }));
});

it("Settings: when the settings can't load, This server says so instead of loading forever", async () => {
  serve({ ...SETTINGS_API, "GET /api/settings": undefined });
  wrap(<SettingsPage />);
  const server = document.getElementById("server")!;
  expect(await within(server).findByRole("button", { name: "Try again" })).toBeInTheDocument();
});

it("Findings: the search box keeps a trailing space while the URL catches up with the trimmed text", async () => {
  serve({ "GET /api/findings": [], "GET /api/assets": [] });
  const r = wrap(<FindingsPage search={{}} />);
  const box = screen.getByRole("searchbox", { name: /Search findings/ });
  await userEvent.type(box, "open ");
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  qc.setQueryData(meQ.queryKey, ME);
  r.rerender(<QueryClientProvider client={qc}><FindingsPage search={{ q: "open" }} /></QueryClientProvider>);  // the debounce wrote "open"
  expect(screen.getByRole("searchbox", { name: /Search findings/ })).toHaveValue("open ");
  r.rerender(<QueryClientProvider client={qc}><FindingsPage search={{ q: "ssl" }} /></QueryClientProvider>);  // a real change (back button) still wins
  expect(screen.getByRole("searchbox", { name: /Search findings/ })).toHaveValue("ssl");
});

it("Findings: the drawer finds a fix in progress among active jobs only, however many finished jobs there are", async () => {
  const f = { id: "f1", asset_id: "a1", hostname: "web-1", ecosystem: "Debian:12", package: "openssl", installed_version: "1", fixed_version: "2",
    vuln_id: "CVE-1", advisory_ids: [], summary: "", cvss: null, epss: null, kev: false, score: 50, priority: "next", reasons: [], status: "open",
    first_seen: "2026-11-01T00:00:00", last_seen: "2026-11-08T00:00:00", resolved_at: null, due: null, setting_fix: false, rule_evidence: null };
  serve({ "GET /api/findings": [f], "GET /api/assets": [{ id: "a1", hostname: "web-1", kind: "host" }], "GET /api/findings/f1": f,
    "GET /api/remediation/jobs": [{ id: "j1", asset_id: "a1", action_key: "Debian:12|openssl", status: "planned" }] });
  wrap(<FindingsPage search={{ f: "f1" }} />);
  expect(await screen.findByText("Fix in progress:")).toBeInTheDocument();
  const urls = vi.mocked(fetch).mock.calls.map(([u]) => String(u)).filter((u) => u.startsWith("/api/remediation/jobs"));
  expect(urls).toEqual(["/api/remediation/jobs?status=planned,approved,dispatched,verifying"]);
});

it("Evidence: the ledger note counts the whole ledger, and says how much of it the period's pack holds", async () => {
  serve({ "GET /api/evidence/ledger": { problems: [], entries: [], total: 900 },
    "GET /api/evidence/report": { controls: [], period: { from: "2026-08-10T00:00:00+00:00", to: "2026-11-08T00:00:00+00:00" },
      metrics: { resolved: 0, resolved_within_sla: 0, overdue_open: 0, mttr_days: null }, ledger: { head_hash: "x", entries: 40 } },
    "GET /api/evidence/public-key": { pem: "", fingerprint_sha256: "ab", verifier_sha256: "cd" } });
  wrap(<EvidencePage />);
  expect(await screen.findByText(/Latest 50 of 900 entries, newest first\./)).toBeInTheDocument();
  expect(await screen.findByText(/holds all 40 entries of that period/)).toBeInTheDocument();
});

it("a step that fell back is shown as recovered, not as a plain pass", () => {
  expect(stepState({ step: "archive copy of openssl=3.5 not available (superseded); rebuilding", ok: true })).toBe("recovered");
  expect(stepState({ step: "upgrade", ok: true })).toBe("passed");
  expect(stepState({ step: "billing-api.service active after change", ok: false })).toBe("failed");
});

it("a plan awaiting approval lists the packages it changes, and self-approval is flagged", () => {
  serve({});
  const r = wrap(<ul><JobCard job={{ ...job("planned"), summary: "Upgrade acl to 2.4.0-1 on web-1", packages: [{ name: "acl", from: "2.3.1-4" }], finding_ids: ["f1"] }} onApprove={() => {}} /></ul>);
  expect(screen.getByRole("list", { name: "Packages this fix changes" })).toHaveTextContent(/acl 2.3.1-4 → 2.4.0-1 or the repository's newer/);
  r.unmount();
});

it("self-approval is said once per Remediation section, with who planned and approved still on each card", async () => {
  const mine = { ...job("succeeded"), created_by: "a@b.c", approved_by: "a@b.c" };
  serve({ "GET /api/remediation/jobs": [mine, { ...mine, id: "j2", approved_by: "x@y.z" }], "GET /api/assets": [], "GET /api/settings": {}, "GET /api/me": { email: "a@b.c" },
    "GET /api/windows-updates": [] });
  wrap(<RemediationPage />);
  expect(await screen.findByText(/1 of 2 self-approved: approved by the person who planned it/)).toBeInTheDocument();
  expect(screen.queryByText("Self-approved")).toBeNull();  // no label on each card
});

it("the machine list searches, filters and sorts the fleet", () => {
  const base = { kind: "host", os_name: "Debian 13", criticality: "medium", internet_facing: false, sandbox: false, ring: 1, health_units: [], open_by_priority: {}, last_seen: "2026-01-02T00:00:00" };
  const fleet = [
    { ...base, id: "1", hostname: "db-prod-01", criticality: "critical", open_by_priority: { low: 40 } },
    { ...base, id: "2", hostname: "web-prod-01", open_by_priority: { "fix-now": 1 }, internet_facing: true },
    { ...base, id: "3", hostname: "web-dev-02", not_reporting: true, last_seen: "2025-12-01T00:00:00" },
  ] as unknown as Asset[];
  expect(filterAssets(fleet, "", [], "", "urgent").map((a) => a.id)).toEqual(["2", "1", "3"]);  // one fix-now outranks 40 low
  expect(filterAssets(fleet, "web", [], "", "name").map((a) => a.id)).toEqual(["3", "2"]);
  expect(filterAssets(fleet, "", ["quiet"], "", "urgent").map((a) => a.id)).toEqual(["3"]);
  expect(filterAssets(fleet, "", [], "critical", "urgent").map((a) => a.id)).toEqual(["1"]);
  expect(filterAssets(fleet, "", [], "", "seen")[0]!.id).toBe("3");
});

it("closing the palette hands focus back to what opened it", async () => {
  serve({});
  function Harness() {
    const [open, setOpen] = useState(false);
    return <><button onClick={() => setOpen(true)}>Search</button><Palette open={open} onOpenChange={setOpen} signOut={() => {}} nextTheme={() => {}} /></>;
  }
  wrap(<Harness />);
  const opener = screen.getByRole("button", { name: "Search" });
  await userEvent.click(opener);
  await waitFor(() => expect(screen.getByRole("combobox")).toHaveFocus());
  await userEvent.keyboard("{Escape}");
  await waitFor(() => expect(opener).toHaveFocus());
});

it("the approval names the target machine's criticality, ring, kind and health checks", () => {
  const a = { hostname: "db-1", criticality: "critical", ring: 0, sandbox: false, health_units: ["postgresql"] } as unknown as Asset;
  expect(machineContext(a)).toBe("db-1 · critical criticality · canary (fixed first) · production · health checks: postgresql");
  expect(machineContext(undefined)).toBeUndefined();
});

it("devices with no agent: hidden while there are none, then counted, named and said to be passive", async () => {
  const rows = [{ mac: "bc:ba:c2:11:22:33", vendor: "Hangzhou Hikvision Digital Technology Co.,Ltd.", addresses: ["192.168.1.64"], seen_by: ["web-1"], first_seen: "2026-11-01T00:00:00", last_seen: "2026-11-11T00:00:00",
                  checked: { asset_id: "d1", at: "2026-11-11T00:00:00", from: "web-1", open: ["NIM-EXPOSED-TELNET"] } },
                { mac: "da:a1:19:00:00:01", vendor: "randomised MAC", addresses: ["192.168.1.70"], seen_by: ["web-1", "db-1"], first_seen: "2026-11-10T00:00:00", last_seen: "2026-11-11T00:00:00", checked: null }];
  vi.stubGlobal("fetch", vi.fn(async () => new Response("[]", { status: 200 })));
  const empty = render(<QueryClientProvider client={new QueryClient()}><UnmanagedDevices /></QueryClientProvider>);
  await new Promise((r) => setTimeout(r, 20));
  expect(empty.container).toBeEmptyDOMElement();
  empty.unmount();
  vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(rows), { status: 200 })));
  render(<QueryClientProvider client={new QueryClient()}><UnmanagedDevices /></QueryClientProvider>);
  expect(await screen.findByRole("heading", { name: "2 devices on your networks have no agent" })).toBeInTheDocument();
  expect(screen.getByText(/1 checked for exposed services/)).toBeInTheDocument();
  expect(screen.getByRole("link", { name: /^1 issue ?on 192.168.1.64$/ }).getAttribute("href")).toMatch(/^\/findings\?.*asset=d1/);
  // issues first, then the rest; a device opens its own drawer with what the check found
  expect(screen.getAllByRole("row").slice(1).map((r) => r.textContent)).toEqual([expect.stringMatching(/^192\.168\.1\.64/), expect.stringMatching(/^192\.168\.1\.70/)]);
  fireEvent.click(screen.getByRole("button", { name: "192.168.1.64: device details" }));
  const drawer = await screen.findByRole("dialog");
  expect(drawer).toHaveTextContent("NIM-EXPOSED-TELNET");
  expect(drawer).toHaveTextContent("Checked by web-1");
  fireEvent.click(screen.getByRole("button", { name: "Close" }));
  expect(screen.getByText(/Nothing is sent to a device to find it/)).toBeInTheDocument();  // behind "How this is judged"
  expect(screen.getByText(/1 is named by their network card's maker/)).toBeInTheDocument();
  expect(screen.getByText(/Hangzhou Hikvision/)).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Download as CSV" })).toHaveAttribute("href", "/api/network/unmanaged?format=csv");
  // search covers the machines that saw a device: only the second was seen by db-1
  fireEvent.change(screen.getByRole("searchbox", { name: "Search devices" }), { target: { value: "db-1" } });
  await waitFor(() => expect(screen.getAllByRole("row")).toHaveLength(2));
  expect(screen.getByRole("row", { name: /192\.168\.1\.70/ })).toBeInTheDocument();
  vi.unstubAllGlobals();
});

it("devices with no agent: a device checked with nothing found says who checked it (ship review 3)", async () => {
  serve({ "GET /api/network/unmanaged": [{ mac: "bc:ba:c2:11:22:33", vendor: "", addresses: ["192.168.1.64"], seen_by: ["web-1"], first_seen: "2026-11-01T00:00:00",
    last_seen: "2026-11-11T00:00:00", checked: { asset_id: "d1", at: "2026-11-11T00:00:00", from: "db-1", open: [] } }] });
  wrap(<UnmanagedDevices />);
  expect(await screen.findByText("Nothing found")).toBeInTheDocument();
  expect(screen.getByText("db-1")).toBeInTheDocument();
  expect(screen.getByText(/Unknown maker/)).toBeInTheDocument();
  expect(screen.queryByRole("link", { name: /issue/ })).toBeNull();
});

it("assets: an org whose only assets are devices still shows the add-your-first-machine state (ship review 3)", async () => {
  serve({ "GET /api/assets": [{ id: "d1", kind: "device", hostname: "192.168.1.64", ring: 1 }], "GET /api/network/unmanaged": [] });
  wrap(<AssetsPage />);
  expect(await screen.findByText("No machines yet")).toBeInTheDocument();
  expect(screen.queryByText("192.168.1.64")).toBeNull();
});

it("devices with no agent: a list that couldn't be read says so, never reads as none (ship review 2)", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ detail: "The device list was read too often this hour; try again later" }), { status: 429 })));
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><UnmanagedDevices /></QueryClientProvider>);
  expect(await screen.findByRole("alert")).toHaveTextContent(/devices with no agent.*too often this hour/);
  vi.unstubAllGlobals();
});

it("rollouts: one package across machines shows canary and broad progress, and holds the rest when a canary fails", () => {
  const job = (id: string, asset_id: string, status: Job["status"]) => ({ id, asset_id, status, action_key: "Debian:12|openssl", hostname: asset_id } as Job);
  const assets = [{ id: "c1", ring: 0 }, { id: "b1", ring: 1 }, { id: "b2", ring: 1 }] as Asset[];
  const r = render(<ul><RolloutCard jobs={[job("1", "c1", "succeeded"), job("2", "b1", "verifying"), job("3", "b2", "planned")]} assets={assets} /></ul>);
  expect(screen.getByRole("listitem", { name: "openssl rollout" })).toHaveTextContent(/Canary 1 of 1 fixed.*Broad 0 of 2 fixed · 1 running · 1 awaiting approval.*Canary fixed: approve the broad machines/);
  r.unmount();
  render(<ul><RolloutCard jobs={[job("1", "c1", "rolled_back"), job("2", "b1", "planned")]} assets={assets} /></ul>);
  expect(screen.getByRole("listitem", { name: "openssl rollout" })).toHaveTextContent(/didn't work.*A canary didn't work: review it before the rest go/);
});

it("rollouts: each rollout shows once, in the section of its most urgent machine; a fix on one machine is a plain job", () => {
  const job = (id: string, asset_id: string, status: Job["status"], pkg = "openssl") => ({ id, asset_id, status, action_key: `Debian:12|${pkg}` } as Job);
  const s = sections([job("1", "c1", "succeeded"), job("2", "b1", "planned"), job("3", "b2", "rolled_back"), job("4", "a1", "planned", "curl"), job("5", "a2", "cancelled", "zlib")]);
  expect(s.map((g) => [g.key, g.rollouts.map((r) => r.map((j) => j.id)), g.singles.map((j) => j.id)])).toEqual([
    ["attention", [["1", "2", "3"]], []], ["approval", [], ["4"]], ["done", [], ["5"]]]);
  expect(s[0]!.jobs.map((j) => j.id)).toEqual(["3"]);  // the section counts its own status only, not the rollout's fixed or waiting machines
});

it("rollouts: each ring's waiting machines are approved in one review; held machines are left out and say why", async () => {
  const job = (id: string, asset_id: string, status: Job["status"]) => ({ id, asset_id, status, action_key: "Debian:12|openssl", hostname: asset_id, summary: "s", packages: [], created_by: "x" } as unknown as Job);
  const assets = [{ id: "c1", ring: 0 }, { id: "b1", ring: 1 }, { id: "b2", ring: 1 }, { id: "b3", ring: 1 }] as Asset[];
  const onApprove = vi.fn();
  render(<ul><RolloutCard jobs={[job("1", "c1", "succeeded"), job("2", "b1", "planned"), job("3", "b2", "planned"), job("4", "b3", "planned")]} assets={assets}
    hold={(j) => j.asset_id === "b3" ? "production remediation is off" : null} onApprove={onApprove} /></ul>);
  expect(screen.getByText("1 waiting machine left out: production remediation is off")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: /Approve broad \(2\)/ }));
  expect(onApprove.mock.calls[0]![0].map((j: Job) => j.id)).toEqual(["2", "3"]);
  expect(screen.queryByRole("button", { name: /Approve canary/ })).toBeNull();  // the canary is already fixed
});

it("rollouts: the broad ring's approval waits until the canary machines are fixed (test first, then production)", () => {
  const job = (id: string, asset_id: string, status: Job["status"]) => ({ id, asset_id, status, action_key: "Debian:12|openssl", hostname: asset_id } as unknown as Job);
  const assets = [{ id: "c1", ring: 0 }, { id: "b1", ring: 1 }] as Asset[];
  for (const canary of ["rolled_back", "verifying", "planned"] as const) {
    const r = render(<ul><RolloutCard jobs={[job("1", "c1", canary), job("2", "b1", "planned")]} assets={assets} onApprove={() => {}} /></ul>);
    expect(screen.getByRole("button", { name: /Approve broad \(1\)/ })).toBeDisabled();
    r.unmount();
  }
  render(<ul><RolloutCard jobs={[job("1", "c1", "succeeded"), job("2", "b1", "planned")]} assets={assets} onApprove={() => {}} /></ul>);
  expect(screen.getByRole("button", { name: /Approve broad \(1\)/ })).toBeEnabled();
});

it("approve: a production machine while production remediation is off can't be approved, and says why", () => {
  render(<ApproveDialog job={{ summary: "Upgrade curl", hostname: "api-dev-04" }} production onOpenChange={() => {}} onConfirm={() => {}} />);
  expect(screen.getByText(/api-dev-04 is a production machine/)).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Approve and run" })).toBeDisabled();
});

it("approve: a broad machine ahead of its canary may be approved by a person, and the dialog says so", () => {
  render(<ApproveDialog job={{ summary: "Upgrade curl", hostname: "web-9" }} ahead onOpenChange={() => {}} onConfirm={() => {}} />);
  expect(screen.getByText(/hasn't succeeded on a canary machine yet/)).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Approve and run" })).toBeEnabled();
});

it("? lists every keyboard shortcut", () => {
  render(<KeyboardShortcuts open onOpenChange={() => {}} />);
  expect(screen.getByRole("dialog", { name: "Keyboard shortcuts" })).toHaveTextContent(/Ctrl K.*Jump to.*j k.*Esc/);
});

it("the ledger folds a run of one kind into one row, and never folds a failure", () => {
  const e = (seq: number, kind: string) => ({ seq, kind, ts: "2026-11-13T10:00:00", subject: "x", data: {}, hash: "h", prev_hash: "p" });
  const runs = foldRuns([e(9, "password_login"), e(8, "password_login"), e(7, "sso_login"), e(6, "remediation_approved"), e(5, "password_login")] as never);
  expect(runs.map((r) => r.length)).toEqual([3, 1, 1]);
  const more = foldRuns([e(4, "remediation_approved"), e(3, "remediation_approved"), e(2, "remediation_failed"), e(1, "remediation_failed")] as never);
  expect(more.map((r) => r.length)).toEqual([2, 1, 1]);  // same kind folds; a failure never hides in a fold
});

it("remediation: jobs for one package stay together, in the order they arrived", () => {
  const j = (id: string, k: string) => ({ id, action_key: k } as Job);
  expect(byPackage([j("1", "a"), j("2", "b"), j("3", "a")]).map((g) => g.map((x) => x.id))).toEqual([["1", "3"], ["2"]]);
});

it("the palette's commands sit under headings", () => {
  expect(["home", "fixnow", "out", "view-x", "machine-1", "host-1", "device-m", "pkg-p", "vuln-CVE-1", "search"].map(cmdGroup))
    .toEqual(["Go to", "Shortcuts", "Account and help", "Saved views", "Machines", "Machines", "Devices", "Packages", "Vulnerabilities", "Search"]);
});

it("planning a fix on more than two machines lists them all first", async () => {
  const calls = serve({ "POST /api/remediation/jobs/batch": { jobs: [{ id: "j3" }], errors: [] } });
  wrap(<PlanFixButton ecosystem="deb" pkg="curl" assetIds={["a", "b", "c"]} names={["web-1", "web-2", "web-3"]} label="Plan fix on 3 test machines" />);
  await userEvent.click(screen.getByRole("button", { name: /Plan fix on 3 test machines/ }));
  expect(calls.some((c) => c.method === "POST")).toBe(false);  // nothing yet
  expect(screen.getByRole("alertdialog")).toHaveTextContent(/web-1, web-2, web-3/);
  await userEvent.click(screen.getByRole("button", { name: "Plan on 3 machines" }));
  await waitFor(() => expect(calls.filter((c) => c.method === "POST")).toHaveLength(1));
});

it("Fix first names the top fixes it can't plan, with their priority", async () => {
  serve({ "GET /api/summary": { assets: 2, open_by_priority: { "fix-now": 1 }, attention: [], hosts_not_reporting: 0, agents_need_attention: 0,
    top_actions: [{ ...ACTION, ecosystem: "Maven", package: "org.apache.logging.log4j:log4j-core", plannable: false, kev: true, max_score: 100 }] },
    "GET /api/settings": { production_remediation_allowed: true }, "GET /api/assets": [], "GET /api/coverage": { assessed: 0, inventory_only: 0, not_assessed: [] } });
  wrap(<Home />);
  expect(await screen.findByRole("link", { name: "log4j-core" })).toHaveAttribute("href", expect.stringMatching(/q=org\.apache\.logging\.log4j/));
  expect(screen.getAllByText("Fix now").length).toBeGreaterThan(0);  // its priority as a pill, with KEV beside it
});

it("agent updates: an agent with no version reported is named, never an empty label", () => {
  const a = (id: string, v: string | null) => ({ id, hostname: id, kind: "host", agent_update: "reinstall", agent_version: v } as unknown as Asset);
  render(<AgentUpdateSummary assets={[a("h1", "0.6.9"), a("h2", ""), a("h3", null)]} />);
  expect(screen.getByRole("listitem")).toHaveTextContent("3 machines: Agent versions 0.6.9 (1 machine) and unknown (2 machines) predate self-update.");
});
