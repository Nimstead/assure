// Workloads (tasks/spec-workloads.md, DECISIONS 155-159): what was read in an image, application packages by where they
// sit in it, and Kubernetes containers named as the kubelet names them.
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, vi } from "vitest";
import { meQ, type Asset, type Finding, type ImageToRebuild } from "./lib";
import { ContainerImages } from "./assets";
import { FindingDetail } from "./findings";
import { RebuildImages } from "./home";

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

const API = {
  id: "i1", hostname: "registry.example/payments-api:1.4", kind: "image", os_name: "Debian GNU/Linux 12 (bookworm)", ecosystem: "Debian:12",
  criticality: "high", internet_facing: false, sandbox: false, ring: 1, health_units: [], first_seen: "2026-11-21T09:00:00", last_seen: "2026-11-21T10:00:00",
  image_id: "sha256:" + "78".repeat(32), open_by_priority: { "fix-now": 2 }, packages_read: true, not_read_why: null, containers_total: 2, hosts_total: 2,
  running_on: [{ name: "payments/api-7d9f4-x2k/app", runtime: "containerd", ref: "registry.example/payments-api:1.4", since: "2026-11-21T09:00:00", host_id: "n1", hostname: "node-1" },
    { name: "api", runtime: "docker", ref: "registry.example/payments-api:1.4", since: "2026-11-21T09:00:00", host_id: "d1", hostname: "docker-1" }],
  read: [{ source: "package_db", state: "ok", count: 96 }, { source: "python_packages", state: "ok", count: 41 }, { source: "npm_packages", state: "ok", count: 0 },
    { source: "java_archives", state: "partial", count: 3, error: "1 installs' metadata couldn't be read" }, { source: "go_modules", state: "off", count: 0 }],
} as unknown as Asset;

it("an image's drawer says what was read, source by source, and why any of it wasn't read in full", () => {
  search.current = { image: "i1" };
  wrap(<ContainerImages images={[API]} />);
  const drawer = screen.getByRole("dialog", { name: API.hostname });
  const read = within(drawer).getByRole("heading", { name: "What was read" }).parentElement!;
  expect(within(within(read).getByRole("list", { name: "Read in this image" })).getAllByRole("listitem").map((li) => li.textContent)).toEqual(["Debian packages 96", "Python 41", "npm 0", "Java 3", "Go off"]);
  expect(read).toHaveTextContent("Java: partly read: 1 installs' metadata couldn't be read.");
  expect(read).toHaveTextContent("Go: not looked for: turned off on the machine that read it.");
  expect(read).not.toHaveTextContent("older than 0.9.0");
  expect(drawer).toHaveTextContent("payments/api-7d9f4-x2k/app · containerd");  // a pod's container, as the kubelet names it
});

it("an image an older agent read says its applications weren't looked for", () => {
  search.current = { image: "i1" };
  wrap(<ContainerImages images={[{ ...API, read: [{ source: "package_db", state: "ok", count: 96 }] } as Asset]} />);
  expect(screen.getByRole("heading", { name: "What was read" }).parentElement).toHaveTextContent(
    "Debian packages 96Its applications (Python, npm, Java and Go packages) weren't looked for: the machine that read it runs an agent older than 0.9.0.");
});

const LOG4J: Finding = {
  id: "f1", asset_id: "i1", hostname: API.hostname, asset_kind: "image", rebuild: "A container image is fixed by rebuilding it", runs_on: ["docker-1", "node-1"],
  ecosystem: "Maven", package: "org.apache.logging.log4j:log4j-core", installed_version: "2.14.1", fixed_version: "2.15.0", setting_fix: false, plannable: false,
  package_fix: { version: "2.17.1", open: 4 }, vuln_id: "CVE-2021-44228", advisory_ids: ["GHSA-jfh8-c2jp-5v3q"], rule_evidence: null, summary: "Log4Shell",
  cvss: 10, epss: 0.94, kev: true, score: 100, priority: "fix-now", reasons: ["CISA KEV"], status: "open", first_seen: "2026-11-21T09:00:00",
  last_seen: "2026-11-21T10:00:00", resolved_at: null, due: "2026-11-28",
  locations: ["/app/app.jar!/BOOT-INF/lib/log4j-core-2.14.1.jar", "/opt/legacy/log4j-core-2.14.1.jar"],
} as Finding;

it("an application finding in an image says to change the image's build and where the package is", async () => {
  serve({ "GET /api/ai/status": { enabled: false }, "GET /api/settings": {}, "GET /api/assets": [API], "GET /api/remediation/jobs": [] });
  wrap(<FindingDetail f={LOG4J} />);
  const how = (await screen.findByText(/Rebuild this image\./)).parentElement!.parentElement!;
  expect(how).toHaveTextContent("Bring org.apache.logging.log4j:log4j-core to 2.17.1 or later, in the image's build (its lock file, pom.xml or go.mod), and redeploy it on docker-1, node-1.");
  expect(how).toHaveTextContent("Where it is in the image (2 places): /app/app.jar!/BOOT-INF/lib/log4j-core-2.14.1.jar, /opt/legacy/log4j-core-2.14.1.jar");
  expect(screen.queryByRole("button", { name: /Plan fix/ })).toBeNull();
});

it("Fix first names an application package's ecosystem beside it", () => {
  const img: ImageToRebuild = { asset_id: "i1", name: API.hostname, os_name: API.os_name, ecosystem: "Debian:12", kev: true, max_score: 100,
    findings: 6, priority: "fix-now", hosts: ["docker-1", "node-1"], unfixed: 0,
    fixes: [{ package: "org.apache.logging.log4j:log4j-core", ecosystem: "Maven", fixed_version: "2.17.1", vulns: 4 }, { package: "openssl", ecosystem: "Debian:12", fixed_version: "3.0.15-1~deb12u1", vulns: 2 }] };
  wrap(<RebuildImages images={[img]} />);
  expect(screen.getByRole("listitem")).toHaveTextContent("Bring org.apache.logging.log4j:log4j-core (Java) to 2.17.1 and openssl to 3.0.15-1~deb12u1.");
});
