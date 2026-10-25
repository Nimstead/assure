import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { NotificationsSection } from "./integrations";
import { render, screen } from "@testing-library/react";
import { ApproveDialog } from "./remediation";
import { APPROVE_COPY } from "./lib";
import { InstallCommands } from "./onboarding";
import { PriorityPill } from "./ui";

it("priority pill carries a text label, not just colour", () => {
  render(<PriorityPill priority="fix-now" count={3} />);
  expect(screen.getByText("Fix now")).toBeInTheDocument();
  expect(screen.getByText("3")).toBeInTheDocument();
});

it("onboarding shows both copyable commands", () => {
  render(<InstallCommands origin="http://localhost:5173" token="nme_t0k" />);
  expect(screen.getByText(/curl -fsSL http:\/\/localhost:5173\/install\.sh \| sudo sh -s -- --token nme_t0k/)).toBeInTheDocument();
  expect(screen.getByText(/enroll --server http:\/\/localhost:5173 --token nme_t0k/)).toBeInTheDocument();
  expect(screen.getAllByRole("button", { name: "Copy" })).toHaveLength(2);
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
