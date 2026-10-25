import { useEffect, useMemo, useState } from "react";
import { Link, Navigate, Outlet, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Dialog, DropdownMenu } from "radix-ui";
import { FileCheck2, ListChecks, LogOut, MoreHorizontal, Moon, Plus, Search, Server, Settings, ShieldAlert, Sun, Wrench, type LucideIcon } from "lucide-react";
import clsx from "clsx";
import { api, ApiError, filtersToSearch, isDark, meQ, parseFilters, setTheme, type Finding } from "./lib";
import { Skeleton } from "./ui";

export const Logo = () => (
  <span className="flex items-center gap-2 text-lg font-semibold tracking-tight">
    <svg viewBox="0 0 32 32" className="size-7" aria-hidden><rect width="32" height="32" rx="8" fill="var(--accent)" /><path d="M9 23V9l14 14V9" stroke="var(--accent-ink)" strokeWidth="3" fill="none" strokeLinejoin="round" /></svg>
    Nimstead
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
const TABS = NAV.slice(0, 4); // the rest live under "More" on small screens
const MORE = NAV.slice(4);

function useSignOut() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  return useMutation({
    mutationFn: () => api("/api/auth/logout", { method: "POST" }),
    onSettled: async () => { qc.clear(); await navigate({ to: "/signin" }); },
  });
}

function toggleTheme() { setTheme(isDark() ? "light" : "dark"); }

export function Shell() {
  const me = useQuery(meQ);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const signOut = useSignOut();

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); setPaletteOpen((o) => !o); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  if (me.error instanceof ApiError && me.error.status === 401) return <Navigate to="/signin" />;
  if (me.isPending) return <div className="p-8" aria-busy="true"><Skeleton className="h-8 w-48" /></div>;
  if (me.error) return <p role="alert" className="p-8">{me.error.message} <button className="underline" onClick={() => me.refetch()}>Try again</button></p>;

  const iconBtn = "inline-flex size-10 cursor-pointer items-center justify-center rounded-md text-muted hover:bg-sunken hover:text-ink";
  return (
    <div className="min-h-dvh md:grid md:grid-cols-[15rem_1fr]">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-2 focus:z-50 focus:rounded focus:bg-surface focus:px-3 focus:py-2">Skip to content</a>

      <aside className="sticky top-0 hidden h-dvh flex-col gap-6 border-r border-line bg-surface p-4 md:flex">
        <Link to="/" className="px-2 no-underline"><Logo /></Link>
        <button onClick={() => setPaletteOpen(true)} className="flex min-h-9 cursor-pointer items-center gap-2 rounded-md border border-line-strong px-3 text-sm text-muted hover:text-ink">
          <Search className="size-4" aria-hidden />Search<kbd className="ml-auto font-mono text-xs">Ctrl K</kbd>
        </button>
        <nav aria-label="Main" className="flex flex-col gap-0.5">
          {NAV.map((n) => <NavLink key={n.to} {...n} />)}
          <Link to="/add" className="mt-3 flex min-h-9 items-center gap-3 rounded-md px-3 text-sm text-muted no-underline hover:bg-sunken hover:text-ink" activeProps={{ className: "bg-accent-soft !text-ink" }}>
            <Plus className="size-4" aria-hidden />Add machine
          </Link>
        </nav>
        <div className="mt-auto flex flex-col gap-1 border-t border-line pt-3">
          <p className="truncate px-2 text-sm font-medium">{me.data.org}</p>
          <p className="truncate px-2 text-xs text-muted">{me.data.email}</p>
          <div className="mt-1 flex">
            <button className={iconBtn} onClick={toggleTheme} aria-label="Toggle light or dark theme"><Sun className="hidden size-4 dark:block" aria-hidden /><Moon className="size-4 dark:hidden" aria-hidden /></button>
            <button className={iconBtn} onClick={() => signOut.mutate()} aria-label="Sign out"><LogOut className="size-4" aria-hidden /></button>
          </div>
        </div>
      </aside>

      <header className="sticky top-0 z-10 flex items-center justify-between border-b border-line bg-surface px-4 py-1.5 md:hidden">
        <Link to="/" className="no-underline"><Logo /></Link>
        <div className="flex">
          <button className={iconBtn} onClick={() => setPaletteOpen(true)} aria-label="Search"><Search className="size-5" aria-hidden /></button>
          <button className={iconBtn} onClick={toggleTheme} aria-label="Toggle light or dark theme"><Sun className="hidden size-5 dark:block" aria-hidden /><Moon className="size-5 dark:hidden" aria-hidden /></button>
          <button className={iconBtn} onClick={() => signOut.mutate()} aria-label="Sign out"><LogOut className="size-5" aria-hidden /></button>
        </div>
      </header>

      <main id="main" className="mx-auto w-full max-w-6xl px-4 pb-28 pt-6 md:px-8 md:pb-12 md:pt-8"><Outlet /></main>

      <nav aria-label="Main" className="fixed inset-x-0 bottom-0 z-10 grid grid-cols-5 border-t border-line bg-surface pb-[env(safe-area-inset-bottom)] md:hidden">
        {TABS.map((n) => <NavLink key={n.to} {...n} tab />)}
        <MoreMenu />
      </nav>

      <Palette open={paletteOpen} onOpenChange={setPaletteOpen} signOut={() => signOut.mutate()} />
    </div>
  );
}

function NavLink({ to, label, icon: Icon, tab }: (typeof NAV)[number] & { tab?: boolean }) {
  return (
    <Link to={to} activeOptions={{ exact: to === "/" }} activeProps={{ "aria-current": "page", className: tab ? "!text-accent font-medium" : "bg-accent-soft !text-ink font-medium" }}
      className={clsx("flex items-center text-sm text-muted no-underline", tab ? "min-h-14 flex-col justify-center gap-0.5 text-xs" : "min-h-9 gap-3 rounded-md px-3 hover:bg-sunken hover:text-ink")}>
      <Icon className="size-4" aria-hidden />{label}
    </Link>
  );
}

function MoreMenu() {
  const navigate = useNavigate();
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger className="flex min-h-14 cursor-pointer flex-col items-center justify-center gap-0.5 text-xs text-muted data-[state=open]:text-ink">
        <MoreHorizontal className="size-4" aria-hidden />More
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content side="top" align="end" sideOffset={8} className="z-[51] min-w-44 rounded-lg border border-line bg-surface p-1.5 shadow-2xl">
          {MORE.map(({ to, label, icon: Icon }) => (
            <DropdownMenu.Item key={to} onSelect={() => void navigate({ to })} className="flex min-h-11 cursor-pointer items-center gap-3 rounded-md px-3 text-sm outline-none data-[highlighted]:bg-accent-soft">
              <Icon className="size-4" aria-hidden />{label}
            </DropdownMenu.Item>
          ))}
          <DropdownMenu.Item onSelect={() => void navigate({ to: "/add" })} className="flex min-h-11 cursor-pointer items-center gap-3 rounded-md px-3 text-sm outline-none data-[highlighted]:bg-accent-soft">
            <Plus className="size-4" aria-hidden />Add machine
          </DropdownMenu.Item>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}

// ---- command palette -------------------------------------------------------------
interface Cmd { id: string; label: string; hint?: string; run: () => void }

function Palette({ open, onOpenChange, signOut }: { open: boolean; onOpenChange: (o: boolean) => void; signOut: () => void }) {
  const navigate = useNavigate();
  const [text, setText] = useState("");
  const [active, setActive] = useState(0);
  const term = text.trim();
  const found = useQuery({
    queryKey: ["palette", term],
    queryFn: () => api<Finding[]>(`/api/findings?${new URLSearchParams({ q: term, limit: "6" })}`),
    enabled: open && term.length > 1,
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
      { id: "theme", label: "Toggle light or dark theme", run: done(toggleTheme) },
      { id: "out", label: "Sign out", run: done(signOut) },
    ].filter((c) => c.label.toLowerCase().includes(term.toLowerCase()));
    const hits: Cmd[] = (found.data ?? []).map((f) => ({
      id: f.id, label: `${f.vuln_id}  ${f.package}`, hint: f.hostname,
      run: done(() => navigate({ to: "/findings", search: filtersToSearch({ ...parseFilters({}), fixable: false, q: term, open: f.id }) })),
    }));
    const all: Cmd[] = term ? [{ id: "search", label: `Search findings for "${term}"`, run: done(() => navigate({ to: "/findings", search: filtersToSearch({ ...parseFilters({}), q: term }) })) }] : [];
    return [...hits, ...all, ...pages];
  }, [found.data, term, navigate, onOpenChange, signOut]);

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
        <Dialog.Content aria-describedby={undefined} className="fixed z-[51] left-1/2 top-[12vh] w-[min(36rem,calc(100%-2rem))] -translate-x-1/2 overflow-hidden rounded-xl border border-line bg-surface shadow-2xl">
          <Dialog.Title className="sr-only">Command palette</Dialog.Title>
          <input
            autoFocus role="combobox" aria-expanded aria-controls="palette-list" aria-activedescendant={cmds[active] ? `cmd-${cmds[active].id}` : undefined}
            aria-label="Jump to a page or search findings" placeholder="Jump to a page or search findings…"
            className="min-h-12 w-full border-b border-line bg-transparent px-4 text-base outline-none placeholder:text-muted" value={text} onChange={(e) => setText(e.target.value)} onKeyDown={onKey}
          />
          <ul id="palette-list" role="listbox" aria-label="Results" className="max-h-80 overflow-y-auto p-1.5">
            {cmds.map((c, i) => (
              <li key={c.id} id={`cmd-${c.id}`} role="option" aria-selected={i === active} onMouseMove={() => setActive(i)} onClick={c.run}
                className={clsx("flex min-h-10 cursor-pointer items-center justify-between gap-3 rounded-md px-3 text-sm", i === active && "bg-accent-soft")}>
                <span className="truncate">{c.label}</span>{c.hint && <span className="shrink-0 text-xs text-muted">{c.hint}</span>}
              </li>
            ))}
            {cmds.length === 0 && <li className="px-3 py-6 text-center text-sm text-muted">Nothing matches.</li>}
          </ul>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
