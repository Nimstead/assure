/** Browser entry point: mount the router inside StrictMode and a query provider.
 * Requires an existing #root element. Missing mount target throws.
 * Search values are plain strings. Duplicate URL keys retain their last value.
 * Query defaults are staleTime=15000ms, no focus refetch and one retry.
 * Individual query options can override these defaults.
 */
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createRootRoute, createRoute, createRouter, lazyRouteComponent, Outlet, RouterProvider } from "@tanstack/react-router";
import "./index.css";
import { FindingsPage } from "./findings";
import { Home } from "./home";
import { Shell } from "./shell";
import type { RawSearch } from "./lib";

const queryClient = new QueryClient({ defaultOptions: { queries: { staleTime: 15_000, refetchOnWindowFocus: false, retry: 1 } } });

// Pages used rarely or once (sign-in, settings, evidence) load on demand, keeping the everyday bundle small.
const SignIn = lazyRouteComponent(() => import("./auth"), "SignInPage");
const SignUp = lazyRouteComponent(() => import("./auth"), "SignUpPage");

function NotFound() {
  return (
    <main id="main" className="mx-auto flex max-w-xl flex-col gap-4 px-4 py-16">
      <h1 className="text-3xl font-semibold">There's no page here</h1>
      <p className="text-muted">The address may be mistyped, or the page moved. Use a link below to continue.</p>
      <p className="flex flex-wrap gap-4"><a href="/" className="font-medium underline">Go to Fix first</a><a href="/findings" className="font-medium underline">Findings</a><a href="/assets" className="font-medium underline">Assets</a></p>
    </main>
  );
}

const root = createRootRoute({ component: Outlet, notFoundComponent: NotFound });
const signin = createRoute({ getParentRoute: () => root, path: "/signin", component: SignIn });
const signup = createRoute({ getParentRoute: () => root, path: "/signup", component: SignUp });
const shell = createRoute({ getParentRoute: () => root, id: "app", component: Shell });
const home = createRoute({ getParentRoute: () => shell, path: "/", component: Home });
const add = createRoute({ getParentRoute: () => shell, path: "/add", component: lazyRouteComponent(() => import("./onboarding"), "Onboarding") });
const assets = createRoute({ getParentRoute: () => shell, path: "/assets", component: lazyRouteComponent(() => import("./assets"), "AssetsPage") });
const remediation = createRoute({ getParentRoute: () => shell, path: "/remediation", component: lazyRouteComponent(() => import("./remediation"), "RemediationPage") });
const evidence = createRoute({
  getParentRoute: () => shell, path: "/evidence",
  validateSearch: (raw: Record<string, unknown>): { period?: string; show?: string } => ({ ...(raw.period ? { period: String(raw.period) } : {}), ...(raw.show ? { show: String(raw.show) } : {}) }),
  component: lazyRouteComponent(() => import("./evidence"), "EvidencePage"),
});
const settings = createRoute({ getParentRoute: () => shell, path: "/settings", component: lazyRouteComponent(() => import("./settings"), "SettingsPage") });
const findings = createRoute({
  getParentRoute: () => shell, path: "/findings",
  validateSearch: (raw: Record<string, unknown>): RawSearch => Object.fromEntries(Object.entries(raw).filter(([, v]) => v != null).map(([k, v]) => [k, String(v)])),
  component: function Findings() { return <FindingsPage search={findings.useSearch()} />; },
});

// Plain `?q=openssl&priority=fix-now,next` URLs instead of JSON-encoded values.
const router = createRouter({
  routeTree: root.addChildren([signin, signup, shell.addChildren([home, add, assets, findings, remediation, evidence, settings])]),
  parseSearch: (s) => Object.fromEntries(new URLSearchParams(s)),
  stringifySearch: (o) => {
    const p = new URLSearchParams();
    for (const [k, v] of Object.entries(o)) if (v !== undefined && v !== "") p.set(k, String(v));
    const s = p.toString();
    return s ? `?${s}` : "";
  },
  defaultPreload: "intent",
});

declare module "@tanstack/react-router" {
  interface Register { router: typeof router }
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </StrictMode>,
);
