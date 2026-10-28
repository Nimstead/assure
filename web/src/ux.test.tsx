// UX round 1 (tasks/plan-0.5-ux.md): behaviour that keeps the review's fixes fixed.
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { afterEach, vi } from "vitest";
import { SsoSection } from "./integrations";
import { meQ, type Asset, type Job, type Settings } from "./lib";
import { Onboarding, TROUBLESHOOT_AFTER_MS } from "./onboarding";
import { ApiTokensSection, QrCode, UsersSection } from "./people";
import { JobCard } from "./remediation";
import { SettingsPage } from "./settings";

vi.mock("@tanstack/react-router", () => ({
  Link: ({ children, to }: { children: ReactNode; to: string }) => <a href={to}>{children}</a>,
  useNavigate: () => vi.fn(),
  useSearch: () => ({}),
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
  expect(await within(ladder.parentElement!).findByRole("status")).toHaveTextContent("Saved");
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

it("a job card links its summary and host to that machine's findings", () => {
  serve({});
  wrap(<ul><JobCard job={job("planned")} /></ul>);
  expect(screen.getByRole("link", { name: "Upgrade openssl" })).toHaveAttribute("href", "/findings");
  expect(screen.getByRole("link", { name: "web-1" })).toHaveAttribute("href", "/findings");
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
});

it("TOTP setup draws a QR code of the otpauth URI, dark on white in any theme", () => {
  render(<QrCode text="otpauth://totp/Nimstead:a%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Nimstead" />);
  const img = screen.getByRole("img", { name: "QR code for your authenticator app" });
  const path = img.querySelector("path")!;
  expect(path).toHaveAttribute("fill", "#111");
  expect(img.getAttribute("viewBox")).toMatch(/^0 0 \d+ \d+$/);
  expect(path.getAttribute("d")).toMatchSnapshot();
});
