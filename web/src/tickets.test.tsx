// Tickets (tasks/plan-tickets.md T7): Settings → Ticketing saves a write-only token, routes teams, previews before
// anything is sent and says what the last sync did; a fix's ticket is a link wherever the fix is shown.
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, vi } from "vitest";
import type { TicketPreview, TicketSettings } from "./lib";
import { TicketLinks, TicketsSection } from "./tickets";

const SAVED: TicketSettings = {
  kind: "jira", site: "https://acme.atlassian.net", user: "bot@example.com", token_set: true, default_project: "OPS",
  routes: [{ owner: "Payments", project: "PAY" }], min_priority: "fix-now", enabled: true, public_url: true,
  last_sync: { at: "2026-11-21T10:00:00", opened: 3, updated: 1, closed: 2, reopened: 0, failed: 1, waiting: 4, errors: [] },
  open_by_project: { PAY: 2, OPS: 1 }, closed: 5, owners: ["Payments", "Platform"],
  failing: [{ key: null, project: "SEC", title: "Upgrade curl to 8.14 on 2 machines", error: "HTTP 400: project is required" }],
};
const PREVIEW: TicketPreview = {
  open: [{ project: "PAY", title: "Upgrade openssl to 3.0.15 on 14 machines (Payments)", priority: "fix-now" },
         { project: "OPS", title: "Rebuild image api:1.4 (3 findings)", priority: "next" }],
  update: 1, close: 0, reopen: 0, tickets: 3, findings: 312, skipped: [{ owner: "Platform", findings: 4 }],
};

let calls: { method: string; path: string; body: unknown }[] = [];
function serve(routes: Record<string, unknown>) {
  calls = [];
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? "GET", path = String(url);
    calls.push({ method, path, body: init?.body ? JSON.parse(String(init.body)) : undefined });
    const hit = routes[`${method} ${path}`];
    return hit instanceof Response ? hit : new Response(JSON.stringify(hit ?? {}), { status: method === "POST" && path.endsWith("/sync") ? 202 : 200 });
  }));
}
function wrap(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}
afterEach(() => vi.unstubAllGlobals());

it("says what the last sync did, the open tickets by project and the errors in the tracker's words", async () => {
  serve({ "GET /api/settings/tickets": SAVED });
  wrap(<TicketsSection />);
  expect(await screen.findByText(/3 opened, 1 updated, 2 closed, 0 reopened/)).toBeInTheDocument();
  expect(screen.getByText("1 failed")).toBeInTheDocument();
  expect(screen.getByText(/4 changes wait for the next run/)).toBeInTheDocument();
  expect(screen.getByText(/Open tickets:/).textContent).toBe("Open tickets: PAY 2 · OPS 1");
  expect(screen.getByText(/project is required/).textContent).toBe("SEC Upgrade curl to 8.14 on 2 machines: HTTP 400: project is required");  // which project refuses
  expect(screen.getByLabelText("API token")).toHaveAttribute("placeholder", "Unchanged");  // never shown, only "saved"
  expect(screen.getByRole("button", { name: "Save ticket settings" })).toBeDisabled();  // nothing changed yet
});

it("saves routes and keeps the token unless a new one is typed", async () => {
  serve({ "GET /api/settings/tickets": SAVED, "PUT /api/settings/tickets": SAVED });
  wrap(<TicketsSection />);
  fireEvent.click(await screen.findByRole("button", { name: "Add a route" }));
  const owners = screen.getAllByLabelText("Owner"), projects = screen.getAllByLabelText("Project");
  fireEvent.change(owners[1]!, { target: { value: "Platform" } });
  fireEvent.change(projects[1]!, { target: { value: "plat" } });
  fireEvent.change(screen.getByLabelText("Which findings become tickets"), { target: { value: "next" } });
  expect(screen.getByRole("button", { name: "Test connection" })).toBeDisabled();  // tests the saved settings: save first
  fireEvent.click(screen.getByRole("button", { name: "Save ticket settings" }));
  await waitFor(() => expect(calls.some((c) => c.method === "PUT")).toBe(true));
  const put = calls.find((c) => c.method === "PUT")!.body as Record<string, unknown>;
  expect(put.routes).toEqual([{ owner: "Payments", project: "PAY" }, { owner: "Platform", project: "plat" }]);
  expect(put.min_priority).toBe("next");
  expect(put.token).toBeUndefined();  // omitted: the saved token stays
});

it("asks before moving to another tracker, which forgets the tickets opened in the old one", async () => {
  serve({ "GET /api/settings/tickets": SAVED, "PUT /api/settings/tickets": { ...SAVED, kind: "gitlab" } });
  wrap(<TicketsSection />);
  fireEvent.change(await screen.findByLabelText("Tracker"), { target: { value: "gitlab" } });
  expect(screen.queryByLabelText("Account email")).toBeNull();  // GitLab signs in with the token alone
  expect(screen.getByLabelText("Access token")).not.toHaveAttribute("placeholder", "Unchanged");
  fireEvent.click(screen.getByRole("button", { name: "Save ticket settings" }));
  expect(await screen.findByText(/stop updating the 8 tickets it opened in https:\/\/acme.atlassian.net/)).toBeInTheDocument();
  expect(calls.some((c) => c.method === "PUT")).toBe(false);
  fireEvent.click(screen.getByRole("button", { name: "Save and start afresh" }));
  await waitFor(() => expect(calls.some((c) => c.method === "PUT")).toBe(true));
});

it("previews by project before anything is sent, and says what isn't sent", async () => {
  serve({ "GET /api/settings/tickets": SAVED, "GET /api/settings/tickets/preview": PREVIEW,
          "POST /api/settings/tickets/test": { ok: false, message: "HTTP 401: You are not authenticated." } });
  wrap(<TicketsSection />);
  fireEvent.click(await screen.findByRole("button", { name: "Preview" }));
  expect(await screen.findByText(/A sync now would open 2 tickets, update 1, close 0 and reopen 0/)).toBeInTheDocument();
  expect(screen.getByText("Upgrade openssl to 3.0.15 on 14 machines (Payments)")).toBeInTheDocument();
  expect(screen.getByText("PAY (1)")).toBeInTheDocument();
  expect(screen.getByText(/Not sent, for want of a route or a default project: Platform \(4 findings\)/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Test connection" }));
  expect(await screen.findByText(/Connection failed: HTTP 401: You are not authenticated/)).toBeInTheDocument();
});

it("links a fix to its tickets, opening the tracker in a new tab", () => {
  wrap(<TicketLinks tickets={[{ key: "PAY-12", url: "https://acme.atlassian.net/browse/PAY-12", state: "open", project: "PAY" }]} />);
  const a = screen.getByRole("link", { name: /PAY-12/ });
  expect(a).toHaveAttribute("href", "https://acme.atlassian.net/browse/PAY-12");
  expect(a).toHaveAttribute("target", "_blank");
  expect(a).toHaveAttribute("rel", "noopener noreferrer");
  const { container } = wrap(<TicketLinks tickets={[]} />);
  expect(container).toBeEmptyDOMElement();
});
