import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import { Link, Navigate, Outlet, useNavigate, useRouterState } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Dialog, DropdownMenu } from "radix-ui";
import { CircleHelp, FileCheck2, ListChecks, LogOut, Monitor, MoreHorizontal, Moon, Plus, Search, Server, Settings, ShieldAlert, Sun, Wrench, type LucideIcon } from "lucide-react";
import clsx from "clsx";
import { savedViews, ADMIN_ONLY_ID, announce, api, ApiError, assetsQ, filtersToSearch, meQ, NEXT_THEME, parseFilters, setTheme, THEME_LABEL, themeChoice, type FindingGroupRow, type ThemeChoice, plural } from "./lib";
import { ErrorState, LiveRegions, Loading, useReturnFocus } from "./ui";

/** Render the Assure wordmark. */
export const Logo = () => (
  // product lockup: company in ExtraBold, product word in Regular; the seal belongs to the company mark only
  <span className="text-xl leading-none tracking-[-0.045em] text-ink">
    <span className="font-extrabold">Nimstead</span> <span className="font-normal">Assure</span>
  </span>
);

type NavTo = "/" | "/findings" | "/assets" | "/remediation" | "/evidence" | "/settings";
const NAV: { to: NavTo; label: string; icon: LucideIcon }[] = [
  { to: "/", label: "Fix first", icon: ListChecks },
  { to: "/findings", label: "Findings", icon: ShieldAlert },
  { to: "/assets", label: "Assets", icon: Server },
  { to: "/remediation", label: "Remediation", icon: Wrench },
  { to: "/evidence", label: "Evidence", icon: FileCheck2 },
  { to: "/settings", label: "Settings", icon: Settings },
];
// Phones: triage → fix → prove in the tab bar (auditors reach Evidence in one tap); configuration lives under "More".
const TAB_ROUTES: NavTo[] = ["/", "/findings", "/remediation", "/evidence"];
const TABS = NAV.filter((n) => TAB_ROUTES.includes(n.to));
const DOCS = "https://github.com/Nimstead/assure/tree/main/docs";
const MORE = NAV.filter((n) => !TAB_ROUTES.includes(n.to));
// Keyboard/pointer highlight that reads at ≥3:1 on any surface, not just a tint.
const highlight = "outline-none data-[highlighted]:shadow-[inset_0_0_0_2px_var(--ink)]";

function useSignOut() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  return useMutation({
    mutationFn: () => api("/api/auth/logout", { method: "POST" }),
    onSettled: async () => { qc.clear(); await navigate({ to: "/signin" }); },
  });
}

/**
 * After a route change, move focus to the new page's h1 and say its title, so keyboard and screen-reader users don't
 * stay on a link that's gone (WCAG 2.4.3). Pages load lazily and their h1 can follow their data, so wait for it briefly.
 */
function useFocusOnNavigate() {
  const path = useRouterState({ select: (r) => r.location.pathname });
  const first = useRef(true);
  // read while rendering the new path, before the new page's own effects run: the old page's title is still set
  const before = useMemo(() => document.title, [path]);
  useEffect(() => {
    if (first.current) { first.current = false; return; }
    if (location.hash) return;  // a #target (a job, a settings section) takes focus itself (useHashScroll)
    let tries = 0, raf = 0;
    const go = () => {
      // a lazy page's chunk may still be loading, with the old page's h1 on screen: wait for the new page's title
      const h1 = document.title !== before ? document.querySelector<HTMLElement>("main h1") : null;
      if (!h1 && tries++ < 180) { raf = requestAnimationFrame(go); return; }
      if (h1 && !h1.closest("[role=dialog],[role=alertdialog]") && !document.querySelector("[role=dialog],[role=alertdialog]")) {
        h1.tabIndex = -1;
        h1.focus({ preventScroll: true });
      }
      announce(document.title.replace(/ · Nimstead Assure$/, ""));
    };
    raf = requestAnimationFrame(go);
    return () => cancelAnimationFrame(raf);
  }, [path, before]);
}

function useTheme() {
  const [theme, set] = useState<ThemeChoice>(themeChoice);
  return { theme, next: () => { const t = NEXT_THEME[theme]; setTheme(t); set(t); } };
}

const ThemeIcon = ({ theme, className }: { theme: ThemeChoice; className: string }) =>
  theme === "system" ? <Monitor className={className} aria-hidden /> : theme === "dark" ? <Moon className={className} aria-hidden /> : <Sun className={className} aria-hidden />;

/** Render authenticated navigation, shared live regions, command palette, and the current route. */
export function Shell() {
  const me = useQuery(meQ);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [keysOpen, setKeysOpen] = useState(false);
  const signOut = useSignOut();
  const { theme, next } = useTheme();
  const themeLabel = `Theme: ${THEME_LABEL[theme]}. Switch to ${THEME_LABEL[NEXT_THEME[theme]]}`;
  useFocusOnNavigate();

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); setPaletteOpen((o) => (o ? false : !document.querySelector("[role=dialog], [role=alertdialog]"))); }  // never over an open drawer
      // "/" jumps to the page's search box, as in most tools, unless you're typing somewhere
      else if (e.key === "?" && !(e.target instanceof HTMLElement && e.target.closest("input, textarea, select, [contenteditable]")) && !document.querySelector("[role=dialog], [role=alertdialog]")) {
        e.preventDefault(); setKeysOpen(true);
      }
      else if (e.key === "/" && !(e.target instanceof HTMLElement && e.target.closest("input, textarea, select, [contenteditable]"))) {
        const box = document.querySelector<HTMLInputElement>('main input[type="search"]');
        if (box) { e.preventDefault(); box.focus(); }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // the phone header's real height, for things that stick under it (it grows with the text size)
  const header = useRef<HTMLElement>(null);
  const tabbar = useRef<HTMLElement>(null);
  const [large, setLarge] = useState(false);
  useEffect(() => {
    const el = header.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(() => {
      document.documentElement.style.setProperty("--header-h", `${el.offsetHeight}px`);
      // the header is 53px at default text; well past that, five tab labels can't fit side by side
      setLarge(el.offsetHeight > 72);
    });
    ro.observe(el);
    // the tab bar's real height (safe-area inset included), for what floats above it
    const tb = tabbar.current;
    const rt = tb ? new ResizeObserver(() => document.documentElement.style.setProperty("--tabbar-h", `${tb.offsetHeight}px`)) : null;
    if (tb) rt!.observe(tb);
    return () => { ro.disconnect(); rt?.disconnect(); };
  }, [me.data]);  // the header renders once the account has loaded
  if (me.error instanceof ApiError && me.error.status === 401) return <Navigate to="/signin" />;
  if (me.isPending) return <div className="p-8"><Loading className="h-8 w-48" /></div>;
  if (me.error) return <div className="p-8"><ErrorState error={me.error} retry={() => me.refetch()} /></div>;

  const iconBtn = "inline-flex size-[44px] cursor-pointer items-center justify-center text-muted hover:bg-sunken hover:text-ink";
  return (
    <div className="min-h-dvh md:grid md:grid-cols-[var(--sidebar-w)_minmax(0,1fr)]">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-2 focus:z-50 focus:bg-surface focus:px-3 focus:py-2">Skip to content</a>
      {/* One place that says things (DECISIONS 49): polite for "Saved" and page changes, assertive for failures. */}
      <LiveRegions />

      <aside className="sticky top-0 hidden h-dvh flex-col gap-6 border-r border-line bg-surface p-4 md:flex">
        <Link to="/" className="px-2 no-underline"><Logo /></Link>
        <button onClick={() => setPaletteOpen(true)} className="flex min-h-9 cursor-pointer items-center gap-2 border border-line-strong px-3 text-sm text-muted hover:text-ink">
          <Search className="size-4" aria-hidden />Search<kbd className="ml-auto font-mono text-xs">Ctrl K</kbd>
        </button>
        <nav aria-label="Main" className="flex flex-col gap-0.5">
          {NAV.map((n) => <NavLink key={n.to} {...n} />)}
          <Link to="/add" className="mt-3 flex min-h-9 items-center gap-3 px-3 text-sm text-muted no-underline hover:bg-sunken hover:text-ink" activeProps={{ "aria-current": "page", className: "bg-accent-soft !text-ink font-medium shadow-[inset_2px_0_0_var(--ink)]" }}>
            <Plus className="size-4" aria-hidden />Add machine
          </Link>
        </nav>
        {/* help opens in the app (the words, priorities, rollouts, keys); the full docs are one link inside */}
        <button type="button" onClick={() => setKeysOpen(true)} className="mt-auto flex min-h-9 cursor-pointer items-center gap-3 px-3 text-left text-sm text-muted hover:bg-sunken hover:text-ink">
          <CircleHelp className="size-4" aria-hidden />Help<span className="ml-auto font-mono text-xs">?</span>
        </button>
        <div className="flex flex-col gap-1 border-t border-line pt-3">
          <p className="truncate px-2 text-sm font-medium">{me.data.org}</p>
          <p className="truncate px-2 text-xs text-muted">{me.data.email}</p>
          <div className="mt-1 flex items-center">
            <button className={clsx(iconBtn, "md:size-10")} onClick={next} aria-label={themeLabel} title={themeLabel}><ThemeIcon theme={theme} className="size-4" /></button>
            <button className={clsx(iconBtn, "md:size-10")} onClick={() => signOut.mutate()} aria-label="Sign out" title="Sign out"><LogOut className="size-4" aria-hidden /></button>
          </div>
        </div>
      </aside>

      <header ref={header} className="sticky top-0 z-10 flex items-center justify-between border-b border-line bg-surface px-4 py-1 md:hidden">
        <Link to="/" className="inline-flex min-h-[44px] items-center no-underline"><Logo /></Link>
        <div className="flex">
          <button className={iconBtn} onClick={() => setPaletteOpen(true)} aria-label="Search"><Search className="size-5" aria-hidden /></button>
          <button className={iconBtn} onClick={next} aria-label={themeLabel}><ThemeIcon theme={theme} className="size-5" /></button>
        </div>
      </header>

      <main id="main" className="mx-auto w-full min-w-0 max-w-6xl px-4 pb-28 pt-6 md:px-8 md:pb-12 md:pt-8">
        {!me.data.admin && (
          <p id={ADMIN_ONLY_ID} className="mb-6 border border-line-strong bg-surface px-3 py-2 text-sm text-muted">
            <strong className="font-semibold text-ink">Read-only.</strong> You can see everything here; ask an organisation admin to change anything.
          </p>
        )}
        <Outlet />
      </main>

      <nav ref={tabbar} aria-label="Main" className={clsx("fixed inset-x-0 bottom-0 z-10 grid border-t border-line bg-surface pb-[env(safe-area-inset-bottom)] md:hidden", large ? "grid-cols-3" : "grid-cols-5")}>
        {(large ? TABS.slice(0, 2) : TABS).map((n) => <NavLink key={n.to} {...n} tab />)}
        <MoreMenu signOut={() => signOut.mutate()} extra={large ? TABS.slice(2) : []} />
      </nav>

      <Palette open={paletteOpen} onOpenChange={setPaletteOpen} signOut={() => signOut.mutate()} nextTheme={next} />
      <HelpPanel open={keysOpen} onOpenChange={setKeysOpen} />
    </div>
  );
}

function NavLink({ to, label, icon: Icon, tab }: (typeof NAV)[number] & { tab?: boolean }) {
  return (
    <Link to={to} activeOptions={{ exact: to === "/" }} activeProps={{ "aria-current": "page", className: tab ? "!text-ink font-semibold shadow-[inset_0_2px_0_var(--ink)]" : "bg-accent-soft !text-ink font-medium shadow-[inset_2px_0_0_var(--ink)]" }}
      className={clsx("flex items-center text-sm text-muted no-underline", tab ? "min-h-14 min-w-0 flex-col justify-center gap-0.5 px-0.5 text-xs [&>span]:max-w-full [&>span]:text-center [&>span]:leading-tight [&>span]:line-clamp-2" : "min-h-9 gap-3 px-3 hover:bg-sunken hover:text-ink")}>
      <Icon className="size-4 shrink-0" aria-hidden /><span>{label}</span>
    </Link>
  );
}

function MoreMenu({ signOut, extra }: { signOut: () => void; extra: typeof NAV }) {
  const navigate = useNavigate();
  const path = useRouterState({ select: (r) => r.location.pathname });
  // On a page that lives under More, the tab says so, like the others do for theirs.
  const here = [...extra, ...MORE].map((m) => m.to as string).concat("/add").includes(path);
  const item = clsx("flex min-h-[44px] cursor-pointer items-center gap-3 px-3 text-sm", highlight);
  return (
    <DropdownMenu.Root modal={false}>
      <DropdownMenu.Trigger className={clsx("flex min-h-14 cursor-pointer flex-col items-center justify-center gap-0.5 text-xs text-muted data-[state=open]:text-ink",
        here && "!text-ink font-semibold shadow-[inset_0_2px_0_var(--ink)]")}>
        <MoreHorizontal className="size-4" aria-hidden />More{here && <span className="sr-only"> (current page is in here)</span>}
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content side="top" align="end" sideOffset={8} className="z-[51] min-w-48 border border-line bg-surface p-1.5 shadow-[0_24px_48px_-12px_var(--shadow)]">
          {[...extra, ...MORE].map(({ to, label, icon: Icon }) => (
            <DropdownMenu.Item key={to} onSelect={() => void navigate({ to })} className={item}>
              <Icon className="size-4" aria-hidden />{label}
            </DropdownMenu.Item>
          ))}
          <DropdownMenu.Item onSelect={() => void navigate({ to: "/add" })} className={item}>
            <Plus className="size-4" aria-hidden />Add machine
          </DropdownMenu.Item>
          <DropdownMenu.Separator className="my-1.5 h-px bg-line" />
          <DropdownMenu.Item onSelect={signOut} className={item}>
            <LogOut className="size-4" aria-hidden />Sign out
          </DropdownMenu.Item>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}

// ---- command palette -------------------------------------------------------------
interface Cmd { id: string; label: string; code?: string; hint?: string; run: () => void }  // code: an ID shown in mono before the label
/** The heading a command sits under, from its id: the list reads in groups, not as one long column. */
export function cmdGroup(id: string): string {
  if (["home", "findings", "assets", "remediation", "evidence", "settings"].includes(id)) return "Go to";
  if (["approve", "fixnow", "quiet", "add"].includes(id)) return "Shortcuts";
  if (["theme", "keys", "help", "out"].includes(id)) return "Account and help";
  const prefix = id.split("-")[0] ?? "";
  const groups: Record<string, string> = { view: "Saved views", machine: "Machines", host: "Machines", device: "Devices", pkg: "Packages", vuln: "Vulnerabilities", search: "Search" };
  return groups[prefix] ?? "";
}

function useDebounced<T>(value: T, ms: number) {
  const [v, setV] = useState(value);
  useEffect(() => { const t = setTimeout(() => setV(value), ms); return () => clearTimeout(t); }, [value, ms]);
  return v;
}

/** Render the controlled command/search palette. onOpenChange closes it; signOut and nextTheme run the supplied actions. */
export function Palette({ open, onOpenChange, signOut, nextTheme }: { open: boolean; onOpenChange: (o: boolean) => void; signOut: () => void; nextTheme: () => void }) {
  const navigate = useNavigate();
  const [text, setText] = useState("");
  // The highlight follows a command, not a position: results that arrive late can't change what Enter runs.
  const [activeId, setActiveId] = useState("");
  const term = text.trim();
  const assets = useQuery({ ...assetsQ, enabled: open });
  const focus = useReturnFocus();
  const query = useDebounced(term, 150);
  const found = useQuery({
    queryKey: ["palette", query],
    // grouped by vulnerability: each hit's host count is the real total, not a count within a sample
    queryFn: () => api<FindingGroupRow[]>(`/api/findings/groups?${new URLSearchParams({ by: "vuln", q: query })}`),
    enabled: open && query.length > 1,
  });
  // a package is what you fix: "curl" finds the package row as well as its vulnerabilities
  const pkgs = useQuery({
    queryKey: ["palette-packages", query],
    queryFn: () => api<FindingGroupRow[]>(`/api/findings/groups?${new URLSearchParams({ by: "package", q: query })}`),
    enabled: open && query.length > 1,
  });

  const cmds = useMemo<Cmd[]>(() => {
    const done = (fn: () => unknown) => () => { onOpenChange(false); void fn(); };
    const pages: Cmd[] = [
      { id: "home", label: "Go to Fix first", run: done(() => navigate({ to: "/" })) },
      { id: "findings", label: "Go to Findings", run: done(() => navigate({ to: "/findings" })) },
      { id: "assets", label: "Go to Assets", run: done(() => navigate({ to: "/assets" })) },
      { id: "remediation", label: "Go to Remediation", run: done(() => navigate({ to: "/remediation" })) },
      { id: "evidence", label: "Go to Evidence", run: done(() => navigate({ to: "/evidence" })) },
      { id: "settings", label: "Go to Settings", run: done(() => navigate({ to: "/settings" })) },
      { id: "approve", label: "Fixes waiting for approval", run: done(() => navigate({ to: "/remediation" })) },
      { id: "fixnow", label: "Fix now findings", run: done(() => navigate({ to: "/findings", search: filtersToSearch({ ...parseFilters({}), priority: ["fix-now"], fixable: false }) })) },
      { id: "quiet", label: "Machines not reporting", run: done(() => navigate({ to: "/assets", search: { show: "quiet" } })) },
      { id: "add", label: "Add a machine", run: done(() => navigate({ to: "/add" })) },
      { id: "theme", label: "Change theme (system, light, dark)", run: done(nextTheme) },
      { id: "keys", label: "Help: words used here and keyboard shortcuts", hint: "?", run: done(() => setTimeout(() => window.dispatchEvent(new KeyboardEvent("keydown", { key: "?" })), 0)) },  // after the palette has closed: "?" is ignored while a dialog is open
      { id: "help", label: "Help: documentation", hint: "opens a new tab", run: done(() => window.open(DOCS, "_blank", "noopener")) },
      { id: "out", label: "Sign out", run: done(signOut) },
    ].filter((c) => { const t = term.toLowerCase(); return !t || c.label.toLowerCase().includes(t) || c.label.toLowerCase().split(/\W+/).some((w) => w.startsWith(t.slice(0, 4)) && t.length >= 3); });
    // one row per package: Findings can't narrow to one distribution, so its rows would all lead to the same place.
    // The row says how many distributions it spans; Findings, grouped by package, lists each.
    const byName = new Map<string, { hosts: number; dists: number }>();
    for (const g of query === term ? pkgs.data ?? [] : []) {
      if (!g.package.toLowerCase().includes(term.toLowerCase())) continue;
      const e = byName.get(g.package) ?? { hosts: 0, dists: 0 };
      byName.set(g.package, { hosts: e.hosts + g.hosts, dists: e.dists + 1 });  // a machine runs one distribution: hosts add up
    }
    const packages: Cmd[] = [...byName].slice(0, 3).map(([name, e]) => ({
      id: `pkg-${name}`, label: `Package: ${name}`, hint: `${e.dists > 1 ? `${e.dists} distributions · ` : ""}${plural(e.hosts, "host")}`,
      run: done(() => navigate({ to: "/findings", search: filtersToSearch({ ...parseFilters({}), fixable: false, q: name, group: "package" }) })),
    }));
    const hits: Cmd[] = (query === term ? found.data ?? [] : []).slice(0, 8).map((g) => ({
      // a search can match on host names too: then the count is on those hosts only, and says so
      id: `vuln-${g.key}`, code: g.key, label: g.packages > 1 ? `${g.packages} packages` : g.package,
      hint: `${g.hosts.toLocaleString("en")} ${g.hosts === 1 ? "host" : "hosts"}${`${g.key} ${g.package}`.toLowerCase().includes(term.toLowerCase()) ? "" : ` matching “${term}”`}`,
      run: done(() => navigate({ to: "/findings", search: filtersToSearch({ ...parseFilters({}), fixable: false, q: g.key }) })),
    }));
    // Hosts come from the already-cached asset list: no extra request, and a host is one jump from its findings.
    const hosts: Cmd[] = term.length > 1 ? (assets.data ?? []).filter((a) => a.kind !== "external" && a.kind !== "device" && a.hostname.toLowerCase().includes(term.toLowerCase())).slice(0, 5)
      .flatMap((a) => [
        // the machine first: a typed name usually means the machine; its findings are one row down
        { id: `machine-${a.id}`, label: `Machine: ${a.hostname}`, hint: "details", run: done(() => navigate({ to: "/assets", search: { machine: a.id } })) },
        { id: `host-${a.id}`, label: `Findings on ${a.hostname}`, run: done(() => navigate({ to: "/findings", search: filtersToSearch({ ...parseFilters({}), asset: a.id, fixable: false }) })) },
      ]) : [];
    // a device a network check looked at, by address or maker: one per MAC, however many machines checked it
    const byMac = new Map((assets.data ?? []).filter((a) => a.kind === "device" && term.length > 1
      && `${a.hostname} ${a.facts?.vendor ?? ""}`.toLowerCase().includes(term.toLowerCase())).map((a) => [String(a.facts?.mac ?? a.id), a]));
    const devices: Cmd[] = [...byMac].slice(0, 5).map(([mac, a]) => ({ id: `device-${mac}`, label: `Device: ${a.hostname}`, hint: String(a.facts?.vendor || "no agent"),
      run: done(() => navigate({ to: "/assets", search: { device: mac } })) }));
    const views: Cmd[] = savedViews().filter((v) => !term || v.name.toLowerCase().includes(term.toLowerCase()))
      .map((v) => ({ id: `view-${v.name}`, label: `View: ${v.name}`, hint: "saved", run: done(() => navigate({ to: "/findings", search: v.search })) }));
    const all: Cmd[] = term ? [{ id: "search", label: `Search findings for "${term}"`, run: done(() => navigate({ to: "/findings", search: filtersToSearch({ ...parseFilters({}), q: term }) })) }] : [];
    return term ? [...pages, ...views, ...hosts, ...devices, ...packages, ...hits, ...all] : [...views, ...pages];
  }, [found.data, pkgs.data, assets.data, term, query, navigate, onOpenChange, signOut, nextTheme]);

  useEffect(() => setActiveId(""), [term]);
  useEffect(() => { if (!open) setText(""); }, [open]);
  const active = Math.max(0, cmds.findIndex((c) => c.id === activeId));
  const move = (by: number) => setActiveId(cmds[Math.min(Math.max(active + by, 0), cmds.length - 1)]?.id ?? "");

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") { e.preventDefault(); move(1); }
    else if (e.key === "ArrowUp") { e.preventDefault(); move(-1); }
    else if (e.key === "Enter") { e.preventDefault(); cmds[active]?.run(); }
  };

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="overlay" />
        <Dialog.Content aria-describedby={undefined} {...focus} className="fixed z-[51] left-1/2 top-[12vh] w-[min(36rem,calc(100%-2rem))] -translate-x-1/2 overflow-hidden border border-line bg-surface shadow-[0_24px_48px_-12px_var(--shadow)]">
          <Dialog.Title className="sr-only">Command palette</Dialog.Title>
          <input
            role="combobox" aria-expanded={cmds.length > 0} aria-controls="palette-list" aria-activedescendant={cmds[active] ? `cmd-${cmds[active].id}` : undefined}
            aria-label="Jump to a page or search findings" placeholder="Jump to a page or search findings…"
            className="min-h-12 w-full border-b border-line bg-transparent px-4 text-base outline-none placeholder:text-muted focus:border-ink focus:shadow-[inset_0_-1px_0_var(--ink)]" value={text} onChange={(e) => setText(e.target.value)} onKeyDown={onKey}
          />
          {cmds.length > 0 ? (
            <ul id="palette-list" role="listbox" aria-label="Results" className="max-h-[60vh] overflow-y-auto p-1.5">
              {term && cmds.every((c) => c.id === "search") && <li role="presentation" className="px-3 py-2 text-sm text-muted">No matches.</li>}
              {cmds.map((c, i) => (
                <Fragment key={c.id}>
                {cmdGroup(c.id) && cmdGroup(c.id) !== cmdGroup(cmds[i - 1]?.id ?? "") &&
                  <li role="presentation" className="px-3 pb-1 pt-2.5 text-xs font-medium text-muted first:pt-1">{cmdGroup(c.id)}</li>}
                <li id={`cmd-${c.id}`} role="option" aria-selected={i === active} data-highlighted={i === active ? "" : undefined} onMouseMove={() => setActiveId(c.id)} onClick={c.run}
                  className={clsx("flex min-h-[44px] cursor-pointer items-center justify-between gap-3 px-3 text-sm", highlight, i === active && "bg-accent-soft")}>
                  <span className="truncate">{c.code && <span className="font-mono">{c.code} </span>}{c.label}</span>{c.hint && <span className="shrink-0 text-xs text-muted">{c.hint}</span>}
                </li>
                </Fragment>
              ))}
            </ul>
          ) : <p id="palette-list" className="px-3 py-6 text-center text-sm text-muted">Nothing matches.</p>}
          <p className="hidden border-t border-line px-4 py-2 text-xs text-muted md:block">Keys: <kbd>↑</kbd> <kbd>↓</kbd> move · <kbd>Enter</kbd> open · <kbd>Esc</kbd> close · <kbd>?</kbd> every shortcut</p>
          {/* the "Search findings for …" row is always there: it isn't a match, so it isn't counted */}
          <p role="status" className="sr-only">{term ? (() => { const n = cmds.filter((c) => c.id !== "search").length; return n ? `${n} result${n === 1 ? "" : "s"}` : "No matches; search findings instead"; })() : ""}</p>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

const KEYS: [string, string][] = [
  ["Ctrl K", "Search everything: pages, machines, devices, packages, vulnerabilities"],
  ["/", "Jump to this page's search box"],
  ["j  k  or  ↓  ↑", "Next and previous finding, in the table and in its drawer"],
  ["Enter", "Open the highlighted finding or command"],
  ["p  then  Enter", "Plan the fix, in a finding's drawer"],
  ["a", "Accept the risk, in a finding's drawer"],
  ["Esc", "Close a drawer or dialog; focus goes back to where you were"],
  ["?", "This list"],
];

/** The keyboard shortcuts, on "?": every key the app answers to, in one place. */
// DESIGN.md's glossary, said where people work: one word per idea, the same everywhere
const GLOSSARY: [string, string][] = [
  ["Asset", "Anything findings are tracked on: a machine with an agent, an application, an internet target."],
  ["Finding", "A vulnerability or exposure on one asset."],
  ["Fix", "An upgrade or setting change that removes findings."],
  ["Job", "One machine's planned fix: planned, approved, run, then verified."],
  ["Rollout", "One fix across machines: canary machines first, the broad ring once the canary is fixed."],
  ["Ring", "Canary (ring 0) machines get a change first; broad (ring 1) machines after it worked there. Set per machine on Assets."],
  ["Resolved", "A finding the next inventory proved gone. A job is “Fixed and verified” only then."],
  ["Has a fix", "A fix exists, whether or not Nimstead can apply it."],
  ["Overdue", "Open past its priority's deadline (Settings, Remediation deadlines). Standards call this past SLA."],
  ["Test machine", "A machine fixes may run on while production remediation is off."],
  ["Device", "Something on the network with no agent, seen by the machines around it."],
];

/** Help in the app (?): the words used here, how priority and rollouts work, and every key; the full docs one link away. */
export function HelpPanel({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const title = useRef<HTMLHeadingElement>(null);
  const focus = useReturnFocus(title);  // focus lands on the title (DESIGN.md), not on Close
  const h = "mt-5 text-sm font-semibold";
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="overlay" />
        <Dialog.Content className="fixed left-1/2 top-[8vh] z-[51] max-h-[84vh] w-[min(38rem,calc(100%-2rem))] -translate-x-1/2 overflow-y-auto border border-line bg-surface p-5 shadow-[0_24px_48px_-12px_var(--shadow)]" aria-describedby={undefined} {...focus}>
          <Dialog.Title ref={title} tabIndex={-1} className="text-lg font-semibold outline-none">Help</Dialog.Title>
          <h3 className={h}>Words used here</h3>
          <dl className="mt-1 divide-y divide-line text-sm">
            {GLOSSARY.map(([k, what]) => <div key={k} className="grid grid-cols-[8rem_1fr] gap-3 py-2"><dt className="font-medium">{k}</dt><dd className="text-muted">{what}</dd></div>)}
          </dl>
          <h3 className={h}>How priority works</h3>
          <p className="mt-1 max-w-prose text-sm text-muted">Each finding scores 0 to 100 from its advisory's severity, how likely it is to be exploited soon (EPSS), whether it is exploited now (KEV), and the machine's criticality and exposure. Fix now is 80 or more, or any KEV; Next, Routine and Low follow, each with its own deadline.</p>
          <h3 className={h}>How rollouts work</h3>
          <p className="mt-1 max-w-prose text-sm text-muted">Plan a fix, approve it, and the machine's agent runs it at its next check-in, rolling back if a health check fails. Approve the canary ring first; the broad ring's approval opens once every canary machine is fixed. Each machine is approved and recorded on its own.</p>
          <h3 className={h} id="help-keys">Keyboard shortcuts</h3>
          <dl className="mt-1 divide-y divide-line text-sm">
            {KEYS.map(([k, what]) => (
              <div key={k} className="grid grid-cols-[8rem_1fr] gap-3 py-2"><dt className="num whitespace-pre font-mono text-ink">{k}</dt><dd className="text-muted">{what}</dd></div>
            ))}
          </dl>
          <div className="mt-5 flex flex-wrap items-center gap-4">
            <Dialog.Close className="inline-flex min-h-[44px] items-center border border-line-strong px-3.5 text-sm font-medium md:min-h-9">Close</Dialog.Close>
            <a href={DOCS} target="_blank" rel="noopener noreferrer" className="text-sm font-medium underline">Full documentation<span className="sr-only"> (opens in a new tab)</span></a>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
