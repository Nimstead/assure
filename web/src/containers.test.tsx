// Containers (tasks/plan-containers.md C7-C8): images listed once wherever they run, never shown as clean when unread,
// fixed by a rebuild and never offered a plan.
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { afterEach, vi } from "vitest";
import { meQ, type Asset, type Finding, type ImageToRebuild } from "./lib";
import { AssetRow, ContainerImages, sortImages } from "./assets";
import { FindingDetail } from "./findings";
import { RebuildImages } from "./home";
import { Palette } from "./shell";

const search: { current: Record<string, string> } = { current: {} };
vi.mock("@tanstack/react-router", () => ({
  Link: ({ children, to, search, className }: { children: ReactNode; to: string; search?: Record<string, string | undefined>; className?: string }) => {
    const qs = new URLSearchParams(Object.entries(search ?? {}).filter((e): e is [string, string] => e[1] !== undefined)).toString();
    return <a href={`${to}${qs ? `?${qs}` : ""}`} className={className}>{children}</a>;
  },
  useNavigate: () => vi.fn(),
  useSearch: () => search.current,
  useRouterState: ({ select }: { select: (r: { location: { pathname: string } }) => unknown }) => select({ location: { pathname: "/" } }),
}));

function serve(routes: Record<string, unknown>) {
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    const hit = routes[`${init?.method ?? "GET"} ${String(url).split("?")[0]}`];
    return hit === undefined ? new Response("{}", { status: 404 }) : new Response(JSON.stringify(hit), { status: 200 });
  }));
}
function wrap(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  qc.setQueryData(meQ.queryKey, { email: "a@example.com", org: "Acme", admin: true, origin: "password", mfa: true, recovery_codes_left: 10 });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}
afterEach(() => { vi.unstubAllGlobals(); search.current = {}; });

const BASE = { os_name: "Debian GNU/Linux 12 (bookworm)", ecosystem: "Debian:12", criticality: "high", internet_facing: false, sandbox: false, ring: 1, health_units: [],
  first_seen: "2026-11-19T09:00:00", last_seen: "2026-11-19T10:00:00", kind: "image" } as const;
const run = (hostname: string, name: string) => ({ name, runtime: "docker", ref: "nginx:1.25", since: "2026-11-19T09:00:00", host_id: `id-${hostname}`, hostname });
const NGINX = { ...BASE, id: "i1", hostname: "nginx:1.25", image_id: "sha256:" + "ab".repeat(32), open_by_priority: { next: 3 }, packages_read: true, not_read_why: null,
  running_on: [run("web-1", "web"), run("web-1", "web-replica"), run("web-2", "web")], containers_total: 3, hosts_total: 2 } as unknown as Asset;
const BUSYBOX = { ...BASE, id: "i2", hostname: "busybox:1.36", os_name: "", ecosystem: "", open_by_priority: {}, packages_read: false,
  not_read_why: "no package database found (apk, dpkg or rpm SQLite)", running_on: [run("web-2", "tools")], containers_total: 1, hosts_total: 1 } as unknown as Asset;
const OLD = { ...BASE, id: "i3", hostname: "nginx:1.23", open_by_priority: {}, packages_read: true, running_on: [], containers_total: 0, hosts_total: 0 } as unknown as Asset;
const CLEAN = { ...BASE, id: "i4", hostname: "alpine:3.21", open_by_priority: {}, packages_read: true, running_on: [run("db-1", "x")], containers_total: 1, hosts_total: 1 } as unknown as Asset;

it("images sort by urgency, then an unread one before a clean one, and one nothing runs last", () => {
  expect(sortImages([OLD, CLEAN, BUSYBOX, NGINX]).map((a) => a.hostname)).toEqual(["nginx:1.25", "busybox:1.36", "alpine:3.21", "nginx:1.23"]);
});

it("the image list says where each runs, marks an unread image as not assessed, and one nothing runs as not running", () => {
  wrap(<ContainerImages images={[OLD, BUSYBOX, NGINX]} />);
  expect(screen.getByRole("heading", { name: "3 container images on 2 machines" })).toBeInTheDocument();
  const rows = screen.getAllByRole("listitem").filter((li) => li.querySelector("button"));
  expect(rows[0]).toHaveTextContent(/nginx:1\.25.*runs on web-1, web-2 · 3 containers/);
  expect(within(rows[1]!).getByText("Not assessed")).toHaveAttribute("title", "no package database found (apk, dpkg or rpm SQLite)");
  expect(within(rows[2]!).getByText("Not running")).toBeInTheDocument();
});

it("an image's drawer says how it's fixed and lists every container by machine; no plan anywhere", () => {
  search.current = { image: "i1" };
  wrap(<ContainerImages images={[NGINX, BUSYBOX]} />);
  const drawer = screen.getByRole("dialog", { name: "nginx:1.25" });
  expect(drawer).toHaveTextContent("Rebuild it from a fixed base image");
  expect(drawer).toHaveTextContent("Runs on 2 machines");
  expect(within(drawer).getByRole("link", { name: "web-1" })).toHaveAttribute("href", "/assets?machine=id-web-1");
  expect(drawer).toHaveTextContent("web-replica");
  expect(within(drawer).queryByRole("button", { name: /Plan/ })).toBeNull();
  expect(within(drawer).getByRole("link", { name: /What the rebuild must fix/ }).getAttribute("href")).toContain("asset=i1");
});

it("an unread image's drawer says it isn't assessed, and that no findings isn't clean", () => {
  search.current = { image: "i2" };
  wrap(<ContainerImages images={[NGINX, BUSYBOX]} />);
  expect(screen.getByRole("dialog", { name: "busybox:1.36" })).toHaveTextContent("Not assessed: no package database found (apk, dpkg or rpm SQLite). No findings here doesn't mean it's clean.");
});

it("a machine's drawer lists the containers running on it, each linking to its image", () => {
  const host = { ...BASE, kind: "host", id: "h1", hostname: "web-1", os_name: "Debian 12", open_by_priority: {}, agent_version: "0.8.0", agent_update: "current",
    containers: [{ name: "web", runtime: "docker", ref: "nginx:1.25", since: "2026-11-19T09:00:00", image_id: "i1" }], containers_total: 1 } as unknown as Asset;
  wrap(<ul><AssetRow a={host} onPatch={() => {}} onDelete={() => {}} inDrawer /></ul>);
  expect(screen.getByText("1 container running here")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "nginx:1.25" })).toHaveAttribute("href", "/assets?view=containers&image=i1");
});

const FINDING: Finding = {
  id: "f1", asset_id: "i1", hostname: "nginx:1.25", asset_kind: "image", rebuild: "A container image is fixed by rebuilding it", runs_on: ["web-1", "web-2"],
  ecosystem: "Debian:12", package: "openssl", installed_version: "3.0.11-1~deb12u2", fixed_version: "3.0.15-1~deb12u1", setting_fix: false, plannable: false,
  package_fix: { version: "3.0.15-1~deb12u1", open: 4 }, vuln_id: "CVE-2024-5535", advisory_ids: ["DSA-5764-1"], rule_evidence: null, summary: "openssl: an issue",
  cvss: 9.1, epss: 0.01, kev: false, score: 70, priority: "next", reasons: ["CVSS 9.1"], status: "open", first_seen: "2026-11-19T09:00:00",
  last_seen: "2026-11-19T10:00:00", resolved_at: null, due: "2026-12-19",
} as Finding;

it("an image finding says to rebuild with the fixed package and where it runs, and offers no plan", async () => {
  serve({ "GET /api/ai/status": { enabled: false }, "GET /api/settings": {}, "GET /api/assets": [NGINX], "GET /api/remediation/jobs": [] });
  wrap(<FindingDetail f={FINDING} />);
  expect(await screen.findByText(/Rebuild this image\./)).toBeInTheDocument();
  expect(screen.getByText(/Rebuild this image\./).parentElement).toHaveTextContent("Bring openssl to 3.0.15-1~deb12u1 or later, from a fixed base image or the package itself, and redeploy it on web-1, web-2.");
  expect(screen.queryByRole("button", { name: /Plan fix/ })).toBeNull();
  expect(screen.queryByText(/Nimstead can't plan this one/)).toBeNull();
  expect(screen.getByText(/in container image/)).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "The image" })).toHaveAttribute("href", "/assets?view=containers&image=i1");
});

it("Fix first lists images to rebuild with the packages each must bring, apart from fixes it can plan", () => {
  const img: ImageToRebuild = { asset_id: "i1", name: "nginx:1.25", os_name: "Debian GNU/Linux 12 (bookworm)", ecosystem: "Debian:12", kev: true, max_score: 92,
    findings: 9, priority: "fix-now", hosts: ["web-1", "web-2"], unfixed: 2,
    fixes: [{ package: "openssl", fixed_version: "3.0.15-1~deb12u1", vulns: 5 }, { package: "glibc", fixed_version: "2.36-9+deb12u9", vulns: 2 }] };
  wrap(<RebuildImages images={[img]} />);
  expect(screen.getByRole("heading", { name: "Container images to rebuild" })).toBeInTheDocument();
  const card = screen.getByRole("listitem");
  expect(card).toHaveTextContent("Bring openssl to 3.0.15-1~deb12u1 and glibc to 2.36-9+deb12u9.");
  expect(card).toHaveTextContent("9 findings on 2 machines");
  expect(card).toHaveTextContent("2 findings with no fix published yet.");
  expect(within(card).queryByRole("button")).toBeNull();
  expect(within(card).getByRole("link", { name: /View image/ })).toHaveAttribute("href", "/assets?view=containers&image=i1");
});

it("the palette offers an image as an image, never as a machine", async () => {
  serve({ "GET /api/assets": [NGINX], "GET /api/findings/groups": [] });
  wrap(<Palette open onOpenChange={() => {}} signOut={() => {}} nextTheme={() => {}} />);
  await userEvent.type(screen.getByRole("combobox"), "nginx");
  expect(await screen.findByRole("option", { name: /Image: nginx:1\.25/ })).toBeInTheDocument();
  expect(screen.queryByRole("option", { name: /Machine: nginx/ })).toBeNull();
});
