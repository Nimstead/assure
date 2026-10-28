import { useEffect, useMemo, useState } from "react";
import { Link, Navigate, Outlet, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Dialog, DropdownMenu } from "radix-ui";
import { FileCheck2, ListChecks, LogOut, Monitor, MoreHorizontal, Moon, Plus, Search, Server, Settings, ShieldAlert, Sun, Wrench, type LucideIcon } from "lucide-react";
import clsx from "clsx";
import { ADMIN_ONLY_ID, api, ApiError, filtersToSearch, meQ, NEXT_THEME, parseFilters, setTheme, THEME_LABEL, themeChoice, type Finding, type ThemeChoice } from "./lib";
import { Loading } from "./ui";

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

function useTheme() {
  const [theme, set] = useState<ThemeChoice>(themeChoice);
  return { theme, next: () => { const t = NEXT_THEME[theme]; setTheme(t); set(t); } };
}

const ThemeIcon = ({ theme, className }: { theme: ThemeChoice; className: string }) =>
  theme === "system" ? <Monitor className={className} aria-hidden /> : theme === "dark" ? <Moon className={className} aria-hidden /> : <Sun className={className} aria-hidden />;

export function Shell() {
  const me = useQuery(meQ);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const signOut = useSignOut();
  const { theme, next } = useTheme();
  const themeLabel = `Theme: ${THEME_LABEL[theme]}. Switch to ${THEME_LABEL[NEXT_THEME[theme]]}`;

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); setPaletteOpen((o) => !o); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  if (me.error instanceof ApiError && me.error.status === 401) return <Navigate to="/signin" />;
  if (me.isPending) return <div className="p-8"><Loading className="h-8 w-48" /></div>;
  if (me.error) return <p role="alert" className="p-8">{me.error.message} <button className="underline" onClick={() => me.refetch()}>Try again</button></p>;

  const iconBtn = "inline-flex size-[44px] cursor-pointer items-center justify-center text-muted hover:bg-sunken hover:text-ink";
  return (
    <div className="min-h-dvh md:grid md:grid-cols-[15rem_1fr]">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-2 focus:z-50 focus:bg-surface focus:px-3 focus:py-2">Skip to content</a>

      <aside className="sticky top-0 hidden h-dvh flex-col gap-6 border-r border-line bg-surface p-4 md:flex">
        <Link to="/" className="px-2 no-underline"><Logo /></Link>
        <button onClick={() => setPaletteOpen(true)} className="flex min-h-9 cursor-pointer items-center gap-2 border border-line-strong px-3 text-sm text-muted hover:text-ink">
          <Search className="size-4" aria-hidden />Search<kbd className="ml-auto font-mono text-xs">Ctrl K</kbd>
        </button>
        <nav aria-label="Main" className="flex flex-col gap-0.5">
          {NAV.map((n) => <NavLink key={n.to} {...n} />)}
          <Link to="/add" className="mt-3 flex min-h-9 items-center gap-3 px-3 text-sm text-muted no-underline hover:bg-sunken hover:text-ink" activeProps={{ className: "bg-accent-soft !text-ink" }}>
            <Plus className="size-4" aria-hidden />Add machine
          </Link>
        </nav>
        <div className="mt-auto flex flex-col gap-1 border-t border-line pt-3">
          <p className="truncate px-2 text-sm font-medium">{me.data.org}</p>
          <p className="truncate px-2 text-xs text-muted">{me.data.email}</p>
          <div className="mt-1 flex items-center">
            <button className={clsx(iconBtn, "md:size-10")} onClick={next} aria-label={themeLabel} title={themeLabel}><ThemeIcon theme={theme} className="size-4" /></button>
            <button className={clsx(iconBtn, "md:size-10")} onClick={() => signOut.mutate()} aria-label="Sign out" title="Sign out"><LogOut className="size-4" aria-hidden /></button>
          </div>
        </div>
      </aside>

      <header className="sticky top-0 z-10 flex items-center justify-between border-b border-line bg-surface px-4 py-1 md:hidden">
        <Link to="/" className="no-underline"><Logo /></Link>
        <div className="flex">
          <button className={iconBtn} onClick={() => setPaletteOpen(true)} aria-label="Search"><Search className="size-5" aria-hidden /></button>
          <button className={iconBtn} onClick={next} aria-label={themeLabel}><ThemeIcon theme={theme} className="size-5" /></button>
        </div>
      </header>

      <main id="main" className="mx-auto w-full max-w-6xl px-4 pb-28 pt-6 md:px-8 md:pb-12 md:pt-8">
        {!me.data.admin && (
          <p id={ADMIN_ONLY_ID} className="mb-6 border border-line-strong bg-surface px-3 py-2 text-sm text-muted">
            <strong className="font-semibold text-ink">Read-only.</strong> You can see everything here; ask an organisation admin to change anything.
          </p>
        )}
        <Outlet />
      </main>

      <nav aria-label="Main" className="fixed inset-x-0 bottom-0 z-10 grid grid-cols-5 border-t border-line bg-surface pb-[env(safe-area-inset-bottom)] md:hidden">
        {TABS.map((n) => <NavLink key={n.to} {...n} tab />)}
        <MoreMenu signOut={() => signOut.mutate()} />
      </nav>

      <Palette open={paletteOpen} onOpenChange={setPaletteOpen} signOut={() => signOut.mutate()} nextTheme={next} />
    </div>
  );
}

function NavLink({ to, label, icon: Icon, tab }: (typeof NAV)[number] & { tab?: boolean }) {
  return (
    <Link to={to} activeOptions={{ exact: to === "/" }} activeProps={{ "aria-current": "page", className: tab ? "!text-ink font-semibold shadow-[inset_0_2px_0_var(--ink)]" : "bg-accent-soft !text-ink font-medium shadow-[inset_2px_0_0_var(--ink)]" }}
      className={clsx("flex items-center text-sm text-muted no-underline", tab ? "min-h-14 flex-col justify-center gap-0.5 text-xs" : "min-h-9 gap-3 px-3 hover:bg-sunken hover:text-ink")}>
      <Icon className="size-4" aria-hidden />{label}
    </Link>
  );
}

function MoreMenu({ signOut }: { signOut: () => void }) {
  const navigate = useNavigate();
  const item = clsx("flex min-h-[44px] cursor-pointer items-center gap-3 px-3 text-sm", highlight);
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger className="flex min-h-14 cursor-pointer flex-col items-center justify-center gap-0.5 text-xs text-muted data-[state=open]:text-ink">
        <MoreHorizontal className="size-4" aria-hidden />More
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content side="top" align="end" sideOffset={8} className="z-[51] min-w-48 border border-line bg-surface p-1.5 shadow-2xl">
          {MORE.map(({ to, label, icon: Icon }) => (
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
interface Cmd { id: string; label: string; hint?: string; run: () => void }

function useDebounced<T>(value: T, ms: number) {
  const [v, setV] = useState(value);
  useEffect(() => { const t = setTimeout(() => setV(value), ms); return () => clearTimeout(t); }, [value, ms]);
  return v;
}

function Palette({ open, onOpenChange, signOut, nextTheme }: { open: boolean; onOpenChange: (o: boolean) => void; signOut: () => void; nextTheme: () => void }) {
  const navigate = useNavigate();
  const [text, setText] = useState("");
  const [active, setActive] = useState(0);
  const term = text.trim();
  const query = useDebounced(term, 150);
  const found = useQuery({
    queryKey: ["palette", query],
    queryFn: () => api<Finding[]>(`/api/findings?${new URLSearchParams({ q: query, limit: "6" })}`),
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
      { id: "add", label: "Add a machine", run: done(() => navigate({ to: "/add" })) },
      { id: "theme", label: "Change theme (system, light, dark)", run: done(nextTheme) },
      { id: "out", label: "Sign out", run: done(signOut) },
    ].filter((c) => c.label.toLowerCase().includes(term.toLowerCase()));
    const hits: Cmd[] = (query === term ? found.data ?? [] : []).map((f) => ({
      id: f.id, label: `${f.vuln_id}  ${f.package}`, hint: f.hostname,
      run: done(() => navigate({ to: "/findings", search: filtersToSearch({ ...parseFilters({}), fixable: false, q: term, open: f.id }) })),
    }));
    const all: Cmd[] = term ? [{ id: "search", label: `Search findings for "${term}"`, run: done(() => navigate({ to: "/findings", search: filtersToSearch({ ...parseFilters({}), q: term }) })) }] : [];
    return [...hits, ...all, ...pages];
  }, [found.data, term, query, navigate, onOpenChange, signOut, nextTheme]);

  useEffect(() => setActive(0), [term]);
  useEffect(() => { if (!open) setText(""); }, [open]);

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setActive((a) => Math.min(a + 1, cmds.length - 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setActive((a) => Math.max(a - 1, 0)); }
    else if (e.key === "Enter") { e.preventDefault(); cmds[active]?.run(); }
  };

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="overlay" />
        <Dialog.Content aria-describedby={undefined} className="fixed z-[51] left-1/2 top-[12vh] w-[min(36rem,calc(100%-2rem))] -translate-x-1/2 overflow-hidden border border-line bg-surface shadow-2xl">
          <Dialog.Title className="sr-only">Command palette</Dialog.Title>
          <input
            autoFocus role="combobox" aria-expanded={cmds.length > 0} aria-controls="palette-list" aria-activedescendant={cmds[active] ? `cmd-${cmds[active].id}` : undefined}
            aria-label="Jump to a page or search findings" placeholder="Jump to a page or search findings…"
            className="min-h-12 w-full border-b border-line bg-transparent px-4 text-base outline-none placeholder:text-muted" value={text} onChange={(e) => setText(e.target.value)} onKeyDown={onKey}
          />
          <ul id="palette-list" role="listbox" aria-label="Results" className="max-h-80 overflow-y-auto p-1.5">
            {cmds.map((c, i) => (
              <li key={c.id} id={`cmd-${c.id}`} role="option" aria-selected={i === active} data-highlighted={i === active ? "" : undefined} onMouseMove={() => setActive(i)} onClick={c.run}
                className={clsx("flex min-h-[44px] cursor-pointer items-center justify-between gap-3 px-3 text-sm", highlight, i === active && "bg-accent-soft")}>
                <span className="truncate">{c.label}</span>{c.hint && <span className="shrink-0 text-xs text-muted">{c.hint}</span>}
              </li>
            ))}
            {cmds.length === 0 && <li className="px-3 py-6 text-center text-sm text-muted">Nothing matches.</li>}
          </ul>
          <p role="status" className="sr-only">{term ? `${cmds.length} result${cmds.length === 1 ? "" : "s"}` : ""}</p>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
