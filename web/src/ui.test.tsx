import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { NotificationsSection } from "./integrations";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { vi } from "vitest";
import { AssetRow, SbomUpload } from "./assets";
import { ApproveDialog, PlanFixButton } from "./remediation";
import { APPROVE_COPY, meQ, type Asset } from "./lib";
import { InstallCommands } from "./onboarding";
import { PlatformSection } from "./settings";
import { TargetRow } from "./targets";
import { PriorityPill } from "./ui";

it("priority pill carries a text label, not just colour", () => {
  render(<PriorityPill priority="fix-now" count={3} />);
  expect(screen.getByText("Fix now")).toBeInTheDocument();
  expect(screen.getByText("3")).toBeInTheDocument();
});

it("onboarding shows the Linux, Windows and Python commands", () => {
  render(<InstallCommands origin="http://localhost:5173" token="nme_t0k" />);
  expect(screen.getByText(/export NIMSTEAD_TOKEN=nme_t0k; curl -fsSL http:\/\/localhost:5173\/install\.sh \| sudo --preserve-env=NIMSTEAD_TOKEN sh/)).toBeInTheDocument();
  expect(screen.getByText(/export NIMSTEAD_TOKEN=nme_t0k; python3 nimstead_agent\.py enroll --server http:\/\/localhost:5173 &&/)).toBeInTheDocument();
  expect(screen.getAllByRole("button", { name: "Copy" })).toHaveLength(3);
});

it("approve dialog states exactly what will happen", () => {
  render(<ApproveDialog job={{ summary: "Upgrade openssl", hostname: "web-1" }} onOpenChange={() => {}} onConfirm={() => {}} error="Production remediation is disabled" />);
  expect(screen.getByRole("dialog", { name: "Approve this fix?" })).toBeInTheDocument();
  expect(screen.getByText(APPROVE_COPY)).toBeInTheDocument();
  expect(screen.getByText(/Saves a rollback copy of each package, upgrades, checks health, rolls back automatically on failure\. Success is confirmed by the next inventory\./)).toBeInTheDocument();
  expect(screen.getByRole("alert")).toHaveTextContent("Production remediation is disabled");
  expect(screen.getByRole("button", { name: "Approve and run" })).toBeEnabled();
});

it("settings show when the last alert delivery failed", async () => {
  const body = { webhook_set: true, webhook_host: "hooks.slack.com", webhook_format: "slack", emails: [], email_available: false, last_delivery_failed: true,
    recent: [{ ts: new Date().toISOString(), kind: "remediation_rolled_back", channel: "webhook", urgent: false, ok: false, error: "RuntimeError: webhook returned HTTP 500" }] };
  vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(body), { status: 200 })));
  render(<QueryClientProvider client={new QueryClient()}><NotificationsSection /></QueryClientProvider>);
  expect(await screen.findByText("Last delivery failed")).toBeInTheDocument();
  expect(screen.getByText(/webhook returned HTTP 500/)).toBeInTheDocument();
  expect(screen.getByLabelText(/^Webhook URL/)).toHaveAttribute("placeholder", "Unchanged"); // the saved URL is never echoed back
  vi.unstubAllGlobals();
});

const signedIn = (admin: boolean) => {
  const qc = new QueryClient();
  qc.setQueryData(meQ.queryKey, { email: "a@example.com", org: "Acme", admin });
  return qc;
};

it("SBOM upload is for admins only: replacing an SBOM resolves findings", () => {
  render(<QueryClientProvider client={signedIn(false)}><SbomUpload a={{ id: "a1", hostname: "billing" } as Asset} /></QueryClientProvider>);
  expect(screen.getByRole("button", { name: "Upload SBOM for billing" })).toBeDisabled();
});

it("SBOM upload posts the raw file and announces the counts", async () => {
  const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ components: 5, mapped: 4, unique_packages: 3, skipped: {}, open: 2, resolved: 1 }), { status: 200 }));
  vi.stubGlobal("fetch", fetchMock);
  const asset = { id: "a1", hostname: "billing", kind: "application" } as Asset;
  render(<QueryClientProvider client={signedIn(true)}><SbomUpload a={asset} /></QueryClientProvider>);
  expect(screen.getByRole("button", { name: "Upload SBOM for billing" })).toBeEnabled();
  const bom = '{"bomFormat":"CycloneDX"}';
  await userEvent.upload(screen.getByTestId("sbom-file-a1"), new File([bom], "bom.json", { type: "application/json" }));
  expect(await screen.findByRole("status")).toHaveTextContent("4 of 5 components recognised (3 unique packages), 1 skipped. 2 open findings, 1 resolved.");
  expect(fetchMock).toHaveBeenCalledWith("/api/assets/a1/sbom", expect.objectContaining({ method: "POST", body: bom }));
  vi.unstubAllGlobals();
});

it("SBOM upload shows the server's rejection", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ detail: "Invalid SBOM: Not a CycloneDX JSON document" }), { status: 422 })));
  render(<QueryClientProvider client={signedIn(true)}><SbomUpload a={{ id: "a1", hostname: "billing" } as Asset} /></QueryClientProvider>);
  await userEvent.upload(screen.getByTestId("sbom-file-a1"), new File(["{}"], "x.json"));
  expect(await screen.findByRole("alert")).toHaveTextContent("Not a CycloneDX JSON document");
  vi.unstubAllGlobals();
});

it("unverified target shows the TXT record and a Verify button", () => {
  vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ email: "a@b.c", org: "o", admin: true }), { status: 200 })));
  const t = { id: "t1", hostname: "www.example.com", kind: "external", verified: false, txt_name: "_nimstead-verify.www.example.com", txt_value: "nimstead-verify=abc", open_by_priority: {}, last_seen: "2026-01-01T00:00:00" } as Asset;
  render(<QueryClientProvider client={new QueryClient()}><TargetRow t={t} onDelete={() => {}} /></QueryClientProvider>);
  expect(screen.getByText("Unverified")).toBeInTheDocument();
  expect(screen.getByText("_nimstead-verify.www.example.com")).toBeInTheDocument();
  expect(screen.getByText("nimstead-verify=abc")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /^Verify/ })).toBeInTheDocument();
  vi.unstubAllGlobals();
});

it("admin-only buttons are disabled with an explanation while /api/me loads and for non-admins", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ email: "a@b.c", org: "o", admin: false }), { status: 200 })));
  render(<QueryClientProvider client={new QueryClient()}><PlanFixButton ecosystem="deb" pkg="openssl" hosts={["web-1"]} /></QueryClientProvider>);
  const btn = screen.getByRole("button", { name: /Plan fix/ });
  expect(btn).toBeDisabled();
  expect(btn).toHaveAttribute("title", "Only organisation admins can do this");
  vi.unstubAllGlobals();
});

it("asset row says why an agent is outdated and what happens next", () => {
  vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ email: "a@b.c", org: "o", admin: true }), { status: 200 })));
  const base = { id: "a1", hostname: "web-1", kind: "host", os_name: "Debian 13", criticality: "medium", internet_facing: false, sandbox: false, ring: 1, health_units: [], open_by_priority: {}, last_seen: "2026-01-01T00:00:00", agent_version: "0.2.0" } as unknown as Asset;
  const row = (a: Partial<Asset>) => render(<QueryClientProvider client={new QueryClient()}><ul><AssetRow a={{ ...base, ...a }} onPatch={() => {}} onDelete={() => {}} /></ul></QueryClientProvider>);
  const failed = row({ agent_update: "failed", agent_update_error: "self-update failed: new agent 0.3.0 failed its self-test" });
  expect(screen.getByText("Agent update failed")).toBeInTheDocument();
  expect(screen.getByText(/failed its self-test/)).toBeInTheDocument();
  failed.unmount();
  const reinstall = row({ agent_update: "reinstall", agent_version: "0.1.3" });
  expect(screen.getByText(/can't update itself. Rerun the install command/)).toBeInTheDocument();
  reinstall.unmount();
  row({ agent_update: "current" });
  expect(screen.queryByText(/Agent (outdated|update)/)).not.toBeInTheDocument();
  vi.unstubAllGlobals();
});

it("settings say when a platform update is available and when one failed", () => {
  const base = { version: "0.3.0", latest: "0.3.1", latest_url: "https://github.com/Nimstead/assure/releases/tag/v0.3.1", update_available: true,
    checked: "2026-10-28T12:00:00", last_update: null, channel: "beta" as const, running_channel: "preview" as const, latest_channel: "beta" };
  const r = render(<PlatformSection p={base} />);
  expect(screen.getByRole("link", { name: "0.3.1 (beta) is available" })).toHaveAttribute("href", base.latest_url);
  expect(screen.getByText(/beta and stable releases/)).toBeInTheDocument();
  r.unmount();
  render(<PlatformSection p={{ ...base, update_available: false, latest: "0.3.0", last_update: { outcome: "rolled_back", from: "0.3.0", to: "0.3.1", error: "health check failed" } }} />);
  expect(screen.getByRole("alert")).toHaveTextContent("Update failed and was rolled back (0.3.0 → 0.3.1): health check failed");
});
