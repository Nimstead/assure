import { memo, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Link, useNavigate, useRouterState } from "@tanstack/react-router";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useWindowVirtualizer } from "@tanstack/react-virtual";
import { Dialog } from "radix-ui";
import { ArrowDown, ArrowRight, ArrowUpDown, Bookmark, ChevronDown, ChevronUp, ExternalLink, Search, SlidersHorizontal, Sparkles, Wrench, X } from "lucide-react";
import clsx from "clsx";
import {
  ACTIVE_JOB_STATUSES, adminGate, announce, ApiError, savedViews, saveViews, settingsQ, type SavedView, aiFilterToPatch, aiStatusQ, api, assetsQ, FINDINGS_CAP, filtersToApi, filtersToSearch, jobAnchor, looksLikeQuestion, parseFilters, pct, plural,
  PRIORITIES, PRIORITY_LABEL, refresh, relativeTime, parseUtc, useIsAdmin, useTitle, whyMatched, fixLabel, type AiFilter, type Finding, type FindingGroup, type FindingGroupRow, type FindingSort, type FindingsFilters, type Job, type RawSearch, type Status,
} from "./lib";
import { PlanFixButton } from "./planfix";
import { Alert, btnPrimary, btnQuiet, chip, ConfirmDialog, Done, EmptyState, ErrorState, Field, input, KevBadge, Loading, PriorityPill, StatusPill, useReturnFocus } from "./ui";

/** "org.apache.logging.log4j:log4j-core" → "log4j-core" then the group, muted: the part that tells packages apart comes
 *  first, so it survives truncation; the cell's title has the full name. */
function PackageName({ name }: { name: string }) {
  const i = Math.max(name.lastIndexOf(":"), name.lastIndexOf("/"));
  return i > 0 && i < name.length - 1
    ? <>{name.slice(i + 1)} <span className="font-normal text-muted">{name.slice(0, i)}</span></>
    : <>{name}</>;
}

const STATUSES: Status[] = ["open", "resolved", "accepted"];
// phones have no "/" key to speak of
const COARSE = typeof matchMedia !== "undefined" && matchMedia("(pointer: coarse), (max-width: 47.99em)").matches;

/** Render paginated, sortable findings using URL search filters, grouping, selection, and the finding drawer. */
export function FindingsPage({ search }: { search: RawSearch }) {
  useTitle("Findings");
  const f = parseFilters(search);
  const navigate = useNavigate();
  const set = (patch: Partial<FindingsFilters>, push = false) =>
    navigate({ to: "/findings", search: filtersToSearch({ ...f, ...patch }), replace: !push });

  // The search box is local state, debounced into the URL.
  const [text, setText] = useState(f.q);
  useEffect(() => { setText((t) => (t.trim() === f.q ? t : f.q)); }, [f.q]);  // our own debounced, trimmed text coming back keeps "open " as typed
  const ai = useQuery(aiStatusQ).data?.enabled === true;
  const question = ai && looksLikeQuestion(text);
  const [asked, setAsked] = useState(false);
  const path = useRouterState({ select: (r) => r.location.pathname });
  const here = useRef(path);
  here.current = path;
  const ask = useMutation({
    mutationFn: () => api<AiFilter>("/api/ai/search", { method: "POST", body: { text: text.trim() } }),
    // only if the user is still on Findings when the answer arrives
    onSuccess: (a) => { if (here.current !== "/findings") return; const p = aiFilterToPatch(a); setText(p.q ?? ""); setAsked(true); set(p); },
  });
  const [showFilters, setShowFilters] = useState(false);
  const active = f.priority.length + Number(f.kev) + Number(f.overdue) + Number(f.fixable) + Number(!!f.asset) + Number(!!f.ecosystem);
  useEffect(() => {
    if (text === f.q || question) return; // a question is sent on Ask, not searched literally
    const t = setTimeout(() => set({ q: text.trim() }), 250);
    return () => clearTimeout(t);
  });

  const apiQs = filtersToApi(f);
  const filterQs = filtersToApi(f, false);
  const list = useInfiniteQuery({
    queryKey: ["findings", apiQs], initialPageParam: 0, placeholderData: (p) => p, enabled: !f.group,
    queryFn: ({ pageParam }) => api<Finding[]>(`/api/findings?${apiQs}&offset=${pageParam}`),
    getNextPageParam: (last: Finding[], all: Finding[][]) => (last.length < FINDINGS_CAP ? undefined : all.length * FINDINGS_CAP),
  });
  const rows = useMemo(() => list.data?.pages.flat(), [list.data]);
  const admin = useIsAdmin();
  const [picked, setPicked] = useState<Set<string>>(new Set());
  useEffect(() => setPicked(new Set()), [apiQs]);
  // what the last bulk action did; it outlives the bar, which closes with the selection
  const [bulkNote, setBulkNote] = useState<{ text: string; planned: boolean } | null>(null);
  useEffect(() => {
    if (!picked.size) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape" && !document.querySelector("[role=dialog],[role=alertdialog]")) setPicked(new Set()); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [picked.size]);
  const pick = useCallback((id: string, v: boolean) => setPicked((s) => { const n = new Set(s); if (v) n.add(id); else n.delete(id); return n; }), []);
  // j/k from anywhere on the page start at the first finding: no need to tab into the table first
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.key !== "j" && e.key !== "k") || e.altKey || e.ctrlKey || e.metaKey) return;
      const t = e.target as HTMLElement;
      if (t.closest("input, textarea, select, [contenteditable], [role=dialog], [role=alertdialog], [role=rowgroup]")) return;
      const first = document.querySelector<HTMLElement>('[role=rowgroup] [data-index="0"] [data-c=vuln] button');
      if (first) { e.preventDefault(); first.focus(); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  // the total, asked for alongside the first page
  const count = useQuery({ queryKey: ["findings", "count", filterQs], queryFn: () => api<{ total: number }>(`/api/findings/count?${filterQs}`), enabled: !f.group, placeholderData: (p) => p });
  // "16,872 with a fix, of 43,970": the same filters without "Has a fix", so the number matches Fix first's
  const allQs = filtersToApi({ ...f, fixable: false }, false);
  const all = useQuery({ queryKey: ["findings", "count", allQs], queryFn: () => api<{ total: number }>(`/api/findings/count?${allQs}`), enabled: !f.group && f.fixable, placeholderData: (p) => p });
  const groups = useQuery({ queryKey: ["findings", "groups", f.group, filterQs], queryFn: () => api<FindingGroupRow[]>(`/api/findings/groups?by=${f.group}&${filterQs}`),
    enabled: !!f.group, placeholderData: (p) => p });
  const typing = text.trim() !== f.q && !question;
  const assets = useQuery(assetsQ);
  const host = assets.data?.find((a) => a.id === f.asset)?.hostname;
  const updating = f.group ? groups.isPlaceholderData : list.isPlaceholderData;
  // back to the default view: every open finding, by risk
  const clearAll = () => { setAsked(false); setText(""); set({ fixable: false, kev: false, overdue: false, q: "", priority: [], asset: "", ecosystem: "" }); };

  return (
    <div className="flex flex-col gap-4">
      <header className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-2">
        <h1 className="text-3xl font-semibold">Findings</h1>
        <div className="flex flex-wrap items-baseline gap-x-4 gap-y-2">
          <p className="num text-sm text-muted" aria-live="polite">
            {typing || updating ? "Updating…"
              : f.group ? groups.data && `${plural(groups.data.length, f.group === "vuln" ? "vulnerability" : "package", f.group === "vuln" ? "vulnerabilities" : undefined)}${groups.data.length === 500 ? " (worst 500)" : ""}`
              : rows && (f.fixable && all.data && count.data ? `${count.data.total.toLocaleString("en")} with a fix, of ${plural(all.data.total, "result")}` : plural(count.data?.total ?? rows.length, "result"))}
            {f.fixable && !typing && !updating && (all.data?.total ?? 1) > 0 && <> (<button className="inline-flex tap cursor-pointer items-center underline" onClick={() => set({ fixable: false })}>include those with no fix</button>)</>}
          </p>
          <a className={btnQuiet} href={`/api/findings.csv?${apiQs}`} download>Download as CSV</a>
        </div>
      </header>

      <div className="flex flex-col gap-3">
        <div className="relative">
          <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted" aria-hidden />
          <input
            type="search" aria-label="Search findings by package, vulnerability ID or host" placeholder={COARSE ? "Search package, CVE or host" : "Search package, CVE or host (press /)"}
            className={clsx(input, "pl-9", (typing || updating) && "pr-24 [&::-webkit-search-cancel-button]:hidden")} value={text} onChange={(e) => { setText(e.target.value); setAsked(false); }}
            onKeyDown={(e) => {
              if (e.key === "Enter" && question && !ask.isPending) ask.mutate();
              if (e.key === "Escape" && text) { e.preventDefault(); setText(""); set({ q: "" }); }
            }}
          />
          {(typing || updating) && <span aria-hidden className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-xs text-muted">Searching…</span>}
        </div>
        {question && (
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
            <button className={btnPrimary} disabled={ask.isPending} onClick={() => ask.mutate()}>
              <Sparkles className="size-4" aria-hidden />{ask.isPending ? "Asking…" : "Ask"}
            </button>
            <span className="text-sm text-muted">Press Enter to turn this question into filters (uses AI).</span>
          </div>
        )}
        <Alert error={ask.error} />
        {asked && !question && <AppliedChips f={f} set={set} clearText={() => setText("")} />}
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2.5">
          <div role="group" aria-label="Status" className="flex flex-wrap border border-line-strong bg-surface p-0.5">
            {STATUSES.map((s) => (
              <button key={s} aria-pressed={f.status === s} onClick={() => set({ status: s })}
                className={clsx("min-h-[44px] cursor-pointer px-3 text-sm capitalize md:min-h-8", f.status === s ? "bg-ink font-medium text-accent-ink" : "text-muted hover:text-ink")}>
                {s.charAt(0).toUpperCase() + s.slice(1)}
              </button>
            ))}
          </div>
          {/* On phones the rarer filters fold away so results start on the first screen. */}
          <button className={clsx(chip(active > 0), "md:hidden")} aria-expanded={showFilters} aria-controls="more-filters" onClick={() => setShowFilters((x) => !x)}>
            <SlidersHorizontal className="size-4" aria-hidden />Filters ({active})
          </button>
          <div id="more-filters" className={clsx("w-full flex-wrap items-center gap-x-4 gap-y-2.5 md:contents", showFilters ? "flex" : "hidden")}>
          <ViewControls f={f} set={set} />
          <SavedViews search={filtersToSearch({ ...f, open: "" })} />
          {/* two rows: what you're looking at (status, view), then what narrows it */}
          <span aria-hidden className="hidden basis-full md:block" />
          <span className="text-sm text-muted">Filter</span>
          <div role="group" aria-label="Priority" className="flex flex-wrap gap-1.5">
            {PRIORITIES.map((p) => {
              const on = f.priority.includes(p);
              return (
                <button key={p} aria-pressed={on} onClick={() => set({ priority: on ? f.priority.filter((x) => x !== p) : [...f.priority, p] })} className={chip(on)}>
                  {PRIORITY_LABEL[p]}
                </button>
              );
            })}
          </div>
          <button aria-pressed={f.kev} onClick={() => set({ kev: !f.kev })} className={chip(f.kev)}>
            Exploited (KEV)
          </button>
          <button aria-pressed={f.overdue} onClick={() => set({ overdue: !f.overdue })} className={chip(f.overdue)}>
            Overdue
          </button>
          <button aria-pressed={f.fixable} onClick={() => set({ fixable: !f.fixable })} className={chip(f.fixable)}
            title="A fix exists: a fixed version to upgrade to, a setting to change, or a service to close. Not only fixes Nimstead can apply for you">
            Has a fix{f.fixable && all.data && count.data && all.data.total > count.data.total && <span className="num text-muted">hides {(all.data.total - count.data.total).toLocaleString("en")}</span>}
          </button>
          {(f.priority.length > 0 || f.kev || f.overdue || !!f.asset || !!f.ecosystem || !!f.q) && (
            <button className="tap cursor-pointer text-sm underline" onClick={clearAll}>Clear filters</button>
          )}
          {f.ecosystem && (
            <button className={clsx(chip(true), "max-w-full")} onClick={() => set({ ecosystem: "" })}>
              <span className="min-w-0 truncate">Distribution: {f.ecosystem}</span> <X className="size-3.5 shrink-0" aria-hidden /><span className="sr-only">(clear distribution filter)</span>
            </button>
          )}
          {f.asset && (
            <button className={clsx(chip(true), "max-w-full")} onClick={() => set({ asset: "" })}>
              <span className="min-w-0 truncate">Host: {host ?? "…"}</span> <X className="size-3.5 shrink-0" aria-hidden /><span className="sr-only">(clear host filter)</span>
            </button>
          )}
          </div>
        </div>
      </div>

      {bulkNote && (
        <p className="flex flex-wrap items-center gap-x-3 gap-y-1 border border-line-strong bg-surface px-3 py-2 text-sm">
          <Done>{bulkNote.text}</Done>
          {bulkNote.planned && <Link to="/remediation" className="font-medium underline">Review them in Remediation</Link>}
          <button className="ml-auto cursor-pointer text-muted underline" onClick={() => setBulkNote(null)}>Dismiss</button>
        </p>
      )}
      {f.group ? (
        groups.isPending ? <TableSkeleton /> : groups.error ? <ErrorState error={groups.error} retry={() => groups.refetch()} /> : (
          <div aria-busy={updating} className={clsx("transition-opacity", updating && "opacity-60")}>
            {groups.data.length ? <Groups rows={groups.data} by={f.group} onPick={(key, ecosystem) => { setText(key); set({ q: key, group: "", ecosystem }, true); }} />
              : <Results rows={[]} f={f} noAssets={assets.data?.length === 0} onClear={clearAll} onClearText={() => { setText(""); set({ q: "" }); }} onShowUnfixable={() => set({ fixable: false })} onPick={() => {}} />}
          </div>
        )
      ) : list.isPending || !rows ? <TableSkeleton /> : list.error ? <ErrorState error={list.error} retry={() => list.refetch()} /> : (
        <div aria-busy={updating} className={clsx("transition-opacity", updating && "opacity-60")}>
          <Results rows={rows} total={count.data?.total} picked={admin && f.status === "open" ? picked : undefined} onPickRow={pick}
            onPickAll={(v) => setPicked(v ? new Set(rows.map((r) => r.id)) : new Set())} more={list.hasNextPage && !list.isFetchingNextPage ? () => void list.fetchNextPage() : undefined} f={f} noAssets={assets.data?.length === 0} onClear={clearAll} onClearText={() => { setText(""); set({ q: "" }); }}
            onShowUnfixable={() => set({ fixable: false })} onPick={(open) => set({ open }, true)} onSort={(sort) => set({ sort })} />
        </div>
      )}

      {admin && picked.size > 0 && <div aria-hidden className="h-24" />}
      {admin && picked.size > 0 && rows && <BulkBar rows={rows.filter((r) => picked.has(r.id))} onClear={() => setPicked(new Set())} onDone={(note) => { setPicked(new Set()); setBulkNote(note); }} />}
      <FindingDrawer id={f.open} ids={rows?.map((r) => r.id)} onMove={(open) => set({ open })} onClose={() => set({ open: "" }, true)} />
    </div>
  );
}

/** Each finding, or one row per vulnerability or package; and the order. Kept in the URL like the filters. */
function ViewControls({ f, set }: { f: FindingsFilters; set: (p: Partial<FindingsFilters>) => void }) {
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-2.5">
      <label className="flex items-center gap-2 text-sm">
        <span className="text-muted">Show</span>
        <select className={clsx(input, "w-auto md:min-h-8")} value={f.group} onChange={(e) => set({ group: e.target.value as FindingGroup, open: "" })}>
          <option value="">Each finding</option><option value="vuln">By vulnerability</option><option value="package">By package</option>
        </select>
      </label>
      {!f.group && (
        <label className="flex items-center gap-2 text-sm md:hidden">
          <span className="text-muted">Sort</span>
          <select className={clsx(input, "w-auto")} value={f.sort} onChange={(e) => set({ sort: e.target.value as FindingSort })}>
            {SORT_OPTIONS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        </label>
      )}
    </div>
  );
}
const SORT_OPTIONS: [FindingSort, string][] = [["score", "Highest score"], ["vuln", "Vulnerability"], ["package", "Package"], ["host", "Host"], ["newest", "Newest"]];

/** One row per vulnerability or package: how far it reaches, and the worst of it. Opening one lists its findings. */
function Groups({ rows, by, onPick }: { rows: FindingGroupRow[]; by: "vuln" | "package"; onPick: (key: string, ecosystem: string) => void }) {
  return (
    <ul className="flex flex-col divide-y divide-line border border-line bg-surface" aria-label={by === "vuln" ? "Vulnerabilities" : "Packages"}>
      {rows.map((g) => (
        <li key={g.key + (g.ecosystem ?? "")} className="flex flex-wrap items-center gap-x-4 gap-y-1 px-3 py-2 text-sm md:flex-nowrap">
          <span className="w-[6.75rem] shrink-0"><PriorityPill priority={g.priority} /></span>
          <div className="min-w-0 flex-1 basis-60">
            <button className={clsx("min-h-[44px] cursor-pointer break-all text-left font-medium underline decoration-line-strong underline-offset-4 hover:decoration-ink md:min-h-0", by === "vuln" && "text-mono font-mono", "min-w-[44px]")} onClick={() => onPick(g.key, by === "package" ? g.ecosystem ?? "" : "")}>
              {by === "vuln" ? g.key : <PackageName name={g.key} />}<span className="sr-only">: list its findings</span>
            </button>
            {by === "package" && g.ecosystem && <span className="ml-2 text-muted">{g.ecosystem}</span>}
            {g.kev && <span className="ml-2 align-middle"><KevBadge /></span>}
            <p className="truncate text-muted">{by === "vuln" ? (g.packages > 1 ? `${g.packages} packages` : g.package) : plural(g.vulns, "vulnerability", "vulnerabilities")}{g.fixed_version && (g.ecosystem ? <> · fixed in <span className="font-mono">{g.fixed_version}</span></> : " · fixed versions differ by distro")}</p>
          </div>
          <span className="num shrink-0 text-muted">{plural(g.hosts, "host")}</span>
          <span className="num w-16 shrink-0 text-right text-muted">score {g.score}</span>
        </li>
      ))}
    </ul>
  );
}

function Results({ rows, total, more, f, noAssets, onClear, onClearText, onShowUnfixable, onPick, onSort, picked, onPickRow, onPickAll }: {
  rows: Finding[]; total?: number; more?: () => void; f: FindingsFilters; picked?: Set<string>; onPickRow?: (id: string, v: boolean) => void; onPickAll?: (v: boolean) => void; noAssets: boolean; onClear: () => void; onClearText: () => void; onShowUnfixable: () => void; onPick: (id: string) => void; onSort?: (s: FindingSort) => void;
}) {
  if (rows.length > 0) return <Table rows={rows} total={total ?? rows.length} more={more} sort={f.sort} onPick={onPick} onSort={onSort ?? (() => {})} picked={picked} onPickRow={onPickRow} onPickAll={onPickAll} />;
  if (noAssets) {
    return <EmptyState title="No machines yet" action={<Link to="/add" className={clsx(btnQuiet, "no-underline")}>Add a machine <ArrowRight className="size-4" aria-hidden /></Link>}>Findings appear once a machine reports its installed software.</EmptyState>;
  }
  const narrowed = !!(f.kev || f.overdue || f.priority.length || f.asset);
  const filtered = f.q || narrowed || f.fixable || f.status !== "open";
  const why = [f.q && `the search “${f.q}”`, narrowed && "the filters", f.fixable && "Has a fix (it hides findings with no fix yet)"].filter(Boolean);
  return (
    <EmptyState title={f.status === "open" && !filtered ? "No open findings" : "Nothing matches"}
      action={filtered ? (
        <div className="flex flex-wrap gap-2">
          {f.q && <button className={btnQuiet} onClick={onClearText}>Clear search</button>}
          {f.fixable && <button className={btnQuiet} onClick={onShowUnfixable}>Show findings with no fix too</button>}
          {(narrowed || (f.q && f.fixable)) && <button className={btnQuiet} onClick={() => { onClear(); onShowUnfixable(); }}>Clear everything</button>}
        </div>
      ) : undefined}>
      {f.status === "open" && !filtered ? "Everything reported is clean." : why.length ? `Narrowed by ${why.join(", ")}.` : "Try another status."}
    </EmptyState>
  );
}

/** How far the curated rule behind a Windows app finding was proven (W13): said, so a match from a name pattern isn't read as proven. */
const RULE_EVIDENCE = {
  proven: "This app's rule was proven on a real install: an old version found by its registry entry, then the upgrade seen.",
  "real name": "This app's rule was checked against a real install's registry entry, but no upgrade was seen yet.",
  pattern: "This app's rule matches by its installer's name only; it hasn't been seen on a real install yet.",
} as const;

const COLS = ["prio", "vuln", "pkg", "ver", "host", "score", "reason"] as const;
const HEADS = ["Priority", "Vulnerability", "Package", "Installed → fixed", "Host", "Score", "Why"];
// the column each header sorts by; priority follows score
const SORT_BY: (FindingSort | null)[] = ["score", "vuln", "package", null, "host", "score", null];
// Phones hide the header row, so each cell names its column for screen readers there.
const CellLabel = ({ i }: { i: number }) => <span className="sr-only md:hidden">{HEADS[i]}: </span>;

function Table({ rows, total, more, sort, onPick, onSort, picked, onPickRow, onPickAll }: {
  rows: Finding[]; total: number; more?: () => void; sort: FindingSort; onPick: (id: string) => void; onSort: (s: FindingSort) => void;
  picked?: Set<string>; onPickRow?: (id: string, v: boolean) => void; onPickAll?: (v: boolean) => void;
}) {
  const allPicked = !!picked && rows.length > 0 && rows.every((r) => picked.has(r.id));
  const ref = useRef<HTMLDivElement>(null);
  const [margin, setMargin] = useState(0);
  useLayoutEffect(() => { setMargin(ref.current?.offsetTop ?? 0); });  // measured after layout, not read during render
  const v = useWindowVirtualizer({
    count: rows.length, overscan: 12, scrollMargin: margin,
    estimateSize: () => (window.innerWidth < 768 ? 104 : 44),
  });
  const last = v.getVirtualItems().at(-1)?.index ?? 0;
  useEffect(() => { if (more && last >= rows.length - 40) more(); }, [more, last, rows.length]);
  return (
    <div role="table" aria-label="Findings" aria-rowcount={total + 1} className="@container border border-line bg-surface">
      {/* stays in view while the list scrolls */}
      <div role="row" aria-rowindex={1} className="frow sticky top-0 z-[5] hidden border-b border-line bg-sunken px-3 py-1 text-xs font-medium text-muted @min-[48em]:grid">
        {HEADS.map((h, i) => {
          const by = SORT_BY[i];
          const on = !!by && sort === by && (i !== 0 || sort !== "score");  // score sorts once, shown on the Score column
          return (
            <div key={h} role="columnheader" data-c={COLS[i]} aria-sort={on ? (by === "score" ? "descending" : "ascending") : undefined} className={i === 5 ? "text-right" : ""}
              title={i === 5 ? "0 to 100: severity, exploit likelihood (EPSS), known exploitation (KEV), and the machine's criticality and exposure" : undefined}>
              {i === 0 && picked && onPickAll && (
                <input type="checkbox" className="mr-2 size-4 align-middle accent-[var(--ink)]" checked={allPicked} onChange={(e) => onPickAll(e.target.checked)}
                  aria-label={`Select all ${rows.length.toLocaleString()} loaded findings`} title="Select all loaded" />
              )}
              {by && i !== 0 ? (
                <button className={clsx("inline-flex min-h-8 cursor-pointer items-center gap-1 hover:text-ink", on && "text-ink")} onClick={() => onSort(by)}>
                  {h}{on ? <ArrowDown className={clsx("size-3", by !== "score" && "rotate-180")} aria-hidden /> : <ArrowUpDown className="size-3 opacity-50" aria-hidden />}
                </button>
              ) : <span className="inline-flex min-h-8 items-center">{h}</span>}
            </div>
          );
        })}
      </div>
      {/* j/k or the arrow keys move between rows, as they do between findings in the drawer */}
      <div role="rowgroup" ref={ref} className="relative" style={{ height: v.getTotalSize() }} onKeyDown={(e) => {
        const step = { j: 1, ArrowDown: 1, k: -1, ArrowUp: -1 }[e.key];
        const row = (e.target as HTMLElement).closest<HTMLElement>("[data-c=vuln]")?.closest<HTMLElement>("[data-index]");
        if (!step || !row || e.altKey || e.ctrlKey || e.metaKey) return;
        const to = Number(row.dataset.index) + step;
        if (to < 0 || to >= rows.length) return;
        e.preventDefault();
        const target = () => ref.current?.querySelector<HTMLElement>(`[data-index="${to}"] [data-c=vuln] button`);
        v.scrollToIndex(to, { align: "auto" });
        const now = target();  // usually already rendered (overscan): move at once, so fast presses each count
        if (now) now.focus(); else requestAnimationFrame(() => target()?.focus());
      }}>
        {v.getVirtualItems().map((vi) => <FindingRow key={rows[vi.index]!.id} r={rows[vi.index]!} index={vi.index} y={vi.start - v.options.scrollMargin} measure={v.measureElement} onPick={onPick}
          picked={picked ? picked.has(rows[vi.index]!.id) : undefined} onPickRow={onPickRow} />)}
      </div>
    </div>
  );
}

const FindingRow = memo(function FindingRow({ r, index, y, measure, onPick, picked, onPickRow }: {
  r: Finding; index: number; y: number; measure: (el: Element | null) => void; onPick: (id: string) => void; picked?: boolean; onPickRow?: (id: string, v: boolean) => void;
}) {
  return (
            <div role="row" aria-rowindex={index + 2} data-index={index} data-id={r.id} ref={measure}
              onClick={(e) => { e.currentTarget.querySelector<HTMLElement>("[data-c=vuln] button")?.focus(); onPick(r.id); }}
              className="frow absolute inset-x-0 top-0 cursor-pointer border-b border-line px-3 py-2.5 text-sm last:border-0 hover:bg-sunken @min-[48em]:py-0"
              style={{ transform: `translateY(${y}px)`, minHeight: 44 }}>
              {/* on phones the checkbox sits at the row's edge, not between the ID and its priority */}
              <div role="cell" data-c="prio" className="flex flex-row-reverse items-center gap-2 @min-[48em]:flex-row"><CellLabel i={0} />
                {picked !== undefined && onPickRow && (
                  // the label is the 44px target on phones; clicking it doesn't open the drawer
                  <label className="-m-2 flex min-h-[44px] min-w-[44px] cursor-pointer items-center justify-center p-2 md:min-h-0 md:min-w-0" onClick={(e) => e.stopPropagation()}>
                    <input type="checkbox" className="size-4 accent-[var(--ink)]" checked={picked} onChange={(e) => onPickRow(r.id, e.target.checked)} aria-label={`Select ${r.vuln_id} on ${r.hostname}`} />
                  </label>
                )}
                <PriorityPill priority={r.priority} /></div>
              <div role="cell" data-c="vuln" className="flex min-w-0 flex-wrap items-center gap-x-2 @min-[48em]:flex-nowrap">
                <button title={r.vuln_id} className="text-mono cursor-pointer break-all text-left font-mono font-medium underline-offset-2 hover:underline @min-[48em]:truncate"
                  onClick={(e) => { e.stopPropagation(); onPick(r.id); }}>{r.vuln_id}<span className="sr-only"> in {r.package} on {r.hostname}</span></button>
                {r.kev && <KevBadge />}
              </div>
              {/* every cell that can be cut off carries its full text as a title */}
              <div role="cell" data-c="pkg" className="break-all font-medium @min-[48em]:truncate" title={r.package}><CellLabel i={2} /><PackageName name={r.package} /></div>
              {/* the installed version gives way first: the fixed one is what you act on */}
              {/* installed above fixed: each version gets the whole width, so neither is cut */}
              <div role="cell" data-c="ver" className="text-mono-sm flex min-w-0 flex-col font-mono leading-tight text-muted" title={`${r.installed_version} → ${fixLabel(r)}`}>
                <CellLabel i={3} /><span className="break-all @min-[48em]:truncate">{r.installed_version}</span>
                <span className="break-all @min-[48em]:truncate">→ {r.fixed_version ? <span className="text-ink">{r.fixed_version}</span> : fixLabel(r)}</span>
              </div>
              <div role="cell" data-c="host" className="min-w-0 break-all text-muted @min-[48em]:truncate" title={r.hostname}><CellLabel i={4} />{r.hostname}</div>
              <div role="cell" data-c="score" className="num text-right text-muted"><span className="sr-only">Score </span>{r.score}</div>
              <div role="cell" data-c="reason" className="truncate text-muted" title={r.reasons[0]}>{r.reasons[0]}</div>
            </div>
  );
});

function TableSkeleton() {
  return <Loading className="h-11" rows={8} label="Loading findings…" />;
}

function FindingDrawer({ id, ids = [], onMove, onClose }: { id: string; ids?: string[]; onMove: (id: string) => void; onClose: () => void }) {
  const at = ids.indexOf(id);
  const prev = at > 0 ? ids[at - 1] : undefined, next = at >= 0 && at < ids.length - 1 ? ids[at + 1] : undefined;
  // j / k step through the list without closing the drawer
  const onKey = (e: React.KeyboardEvent) => {
    if (e.target instanceof HTMLElement && e.target.closest("input, textarea, select")) return;
    if (e.key === "a" || e.key === "p") {
      const b = (e.currentTarget as HTMLElement).querySelector<HTMLButtonElement>(`[data-act=${e.key === "a" ? "accept" : "plan"}] button:not(:disabled):not([aria-disabled=true])`);
      if (b) { e.preventDefault(); if (e.key === "p") b.focus(); else b.click(); }  // p only moves to Plan fix: Enter plans, so a stray key changes nothing
    }
    if (e.key === "j" && next) { e.preventDefault(); moved.current = true; onMove(next); }
    if (e.key === "k" && prev) { e.preventDefault(); moved.current = true; onMove(prev); }
  };
  const q = useQuery({ queryKey: ["finding", id], queryFn: () => api<Finding>(`/api/findings/${id}`), enabled: !!id });
  const title = useRef<HTMLHeadingElement>(null);
  const moved = useRef(false);
  useEffect(() => {
    if (moved.current && q.data) { moved.current = false; announce(`${q.data.vuln_id} on ${q.data.hostname}, ${at + 1} of ${ids.length}`); }
  }, [q.data, at, ids.length]);
  // Focus starts on the title (no ring: the user didn't move it there) and goes back to the row that opened the drawer.
  // after stepping with j/k, Esc goes back to the finding you were on, not the one you opened
  const shown = useRef(id);  // closing clears id before focus returns, so keep the last one shown
  if (id) shown.current = id;
  const focus = useReturnFocus(title, () => document.querySelector<HTMLElement>(`[data-id="${shown.current}"] [data-c=vuln] button`));
  return (
    <Dialog.Root open={!!id} onOpenChange={(o) => !o && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay className="overlay" />
        <Dialog.Content className="drawer p-5 md:p-6" aria-describedby={undefined} onKeyDown={onKey} {...focus}>
          <div className="mb-4 flex items-start justify-between gap-3">
            {/* stepping with j/k changes the host as often as the ID: both sit in the title, with where you are in the list */}
            <div className="min-w-0">
              <Dialog.Title ref={title} tabIndex={-1} className="break-all font-mono text-lg font-semibold">{q.data?.vuln_id ?? "Finding"}</Dialog.Title>
              {q.data && <p className="break-all text-sm"><span className="font-medium">{q.data.hostname}</span>{ids.length > 1 && at >= 0 && <span className="num text-muted"> · {at + 1} of {ids.length.toLocaleString("en")}{ids.length >= FINDINGS_CAP && " loaded"}</span>}</p>}
            </div>
            {ids.length > 1 && at >= 0 && (
              <span className="ml-auto flex shrink-0 gap-1">
                <button className={clsx(btnQuiet, "size-[44px] !px-0 md:size-9")} disabled={!prev} onClick={() => { if (prev) { moved.current = true; onMove(prev); } }} aria-label="Previous finding (k)" title="Previous finding (k)"><ChevronUp className="size-4" aria-hidden /></button>
                <button className={clsx(btnQuiet, "size-[44px] !px-0 md:size-9")} disabled={!next} onClick={() => { if (next) { moved.current = true; onMove(next); } }} aria-label="Next finding (j)" title="Next finding (j)"><ChevronDown className="size-4" aria-hidden /></button>
              </span>
            )}
            <Dialog.Close className={clsx(btnQuiet, "size-[44px] shrink-0 !px-0 md:size-9")} aria-label="Close"><X className="size-4" aria-hidden /></Dialog.Close>
          </div>
          {q.isPending ? <Loading className="h-20" rows={3} label="Loading finding…" />
            : q.error instanceof ApiError && q.error.status === 404 ? (
              <EmptyState title="This finding no longer exists" action={<Dialog.Close className={btnQuiet}>Back to the list</Dialog.Close>}>
                It was probably resolved by a later inventory, or its machine was removed. The evidence ledger keeps its history.
              </EmptyState>
            ) : q.error ? <ErrorState error={q.error} retry={() => q.refetch()} /> : <FindingDetail f={q.data} />}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function FindingDetail({ f }: { f: Finding }) {
  const ai = useQuery(aiStatusQ).data?.enabled === true;
  const prodOk = useQuery(settingsQ).data?.production_remediation_allowed ?? true;
  const testMachine = useQuery(assetsQ).data?.find((a) => a.id === f.asset_id)?.sandbox;
  const refused = !prodOk && testMachine === false;  // the server would refuse a plan for this machine
  const job = useJobFor(f);
  const ids = [...new Set([f.vuln_id, ...f.advisory_ids])].filter((i) => !/^(CFG:|EOL:|NIM-)/.test(i)); // our own ids: OSV has no page for them
  const when = (s: string) => <time dateTime={parseUtc(s).toISOString()} title={parseUtc(s).toLocaleString()}>{relativeTime(s)}</time>;
  return (
    <div>
      <div className="flex flex-wrap items-center gap-2"><PriorityPill priority={f.priority} />{f.kev && <KevBadge />}<span className="num text-sm text-muted">Score {f.score}/100</span></div>
      <details className="mt-1 text-sm text-muted"><summary className="flex tap w-fit cursor-pointer items-center">How the score works</summary>
        <p className="mt-1 max-w-prose">0 to 100, from the advisory's severity, how likely it is to be exploited in the next 30 days (EPSS), whether it is being exploited now (KEV), and this machine's criticality and exposure. Fix now is 80 or more, or any KEV.</p></details>
      {f.due && <Due due={f.due} />}
      {f.summary && <p className="mt-3 max-w-prose text-sm">{f.summary}{f.summary.length >= 200 && !/[.!?…]$/.test(f.summary) && <>… <span className="text-muted">The advisory has the full text.</span></>}</p>}
      {ai && <Explain key={f.id} id={f.id} />}

      <H>Why it matched</H>
      <p className="break-words text-sm"><strong className="break-all font-semibold">{f.package}</strong> on <strong className="break-all font-semibold">{f.hostname}</strong></p>
      <p className="text-mono mt-1 break-words bg-sunken p-3 font-mono">{whyMatched(f)}</p>
      {f.fixed_version && (f.package_fix && f.package_fix.open > 1
        ? <p className="mt-2 text-sm text-muted">Fix: upgrade {f.package} to {f.package_fix.version} or later. That clears all {f.package_fix.open} open findings for {f.package} on this host; {f.fixed_version} fixes only this one.</p>
        : <p className="mt-2 text-sm text-muted">Fix: upgrade {f.package} to {f.fixed_version} or later.</p>)}
      {f.rule_evidence && <p className="mt-2 text-sm text-muted">{RULE_EVIDENCE[f.rule_evidence]}</p>}

      <H>Why it's ranked here</H>
      <ul className="list-disc space-y-1 pl-5 text-sm">{f.reasons.map((r) => <li key={r}>{r}</li>)}</ul>

      <H>Risk signals</H>
      <dl className="num grid grid-cols-3 gap-3 text-sm">
        <div><dt className="text-muted">CVSS</dt><dd className="font-medium">{f.cvss ?? "n/a"}</dd></div>
        <div><dt className="text-muted">EPSS (30 days)</dt><dd className="font-medium">{f.epss === null ? "n/a" : pct(f.epss)}</dd></div>
        <div><dt className="text-muted">Known exploited</dt><dd className="font-medium">{f.kev ? "Yes (KEV)" : "No"}</dd></div>
      </dl>

      {ids.length > 0 && <H>Advisories</H>}
      <ul className="flex flex-wrap gap-2">
        {ids.map((i) => (
          <li key={i}>
            <a href={`https://osv.dev/vulnerability/${encodeURIComponent(i)}`} target="_blank" rel="noopener noreferrer" className="inline-flex tap items-center gap-1 border border-line-strong px-2.5 py-1 font-mono text-xs hover:bg-sunken">
              {i} <ExternalLink className="size-3" aria-label="(opens in a new tab)" />
            </a>
          </li>
        ))}
      </ul>

      {f.status === "open" && (
        <>
          {/* only the keys that do something here */}
          <H>Act on it <span className="ml-2 hidden text-xs font-normal text-muted md:inline">keys: {[(f.fixed_version || f.setting_fix) && !job && f.plannable !== false && !refused && "p then Enter plan", "a accept", "j k next/previous"].filter(Boolean).join(" · ")}</span></H>
          {job && <FixInProgress job={job} />}
          {f.fixed_version && f.plannable === false && <p className="mb-3 text-sm text-muted">Nimstead can't plan this one: update it with its own updater or by policy.</p>}
          {refused && f.plannable !== false && <p className="mb-3 text-sm text-muted">This is a production machine, and production remediation is off on this server, so a fix can't be planned here yet. <Link to="/settings" hash="remediation" className="font-medium text-ink underline">How to turn it on</Link></p>}
          <div className="flex flex-wrap items-start gap-2">
            {(f.fixed_version || f.setting_fix) && !job && f.plannable !== false && !refused && <span data-act="plan"><PlanFixButton ecosystem={f.ecosystem} pkg={f.package} assetIds={[f.asset_id]} /></span>}
            <span data-act="accept" className="contents"><AcceptRisk f={f} /></span>
          </div>
        </>
      )}
      {f.status === "accepted" && (
        <>
          <H>Accepted risk</H>
          <RevokeAcceptance id={f.id} />
        </>
      )}

      <p className="mt-6 text-sm text-muted">
        First seen {when(f.first_seen)}, last seen {when(f.last_seen)}{f.resolved_at && <>, resolved {when(f.resolved_at)}</>}.
      </p>
    </div>
  );
}

const H = ({ children }: { children: ReactNode }) => <h3 className="mb-1.5 mt-6 text-sm font-semibold">{children}</h3>;

/** "Due 3 Nov (in 6 days)" or "12 days overdue", from the deadline in force when it was first detected. */
function Due({ due }: { due: string }) {
  const d = parseUtc(due), days = Math.round((d.getTime() - Date.now()) / 86_400_000);
  const date = d.toLocaleDateString(undefined, { day: "numeric", month: "short" });
  return days < 0
    ? <p className="mt-2 text-sm font-medium text-now-fg">{plural(-days, "day")} overdue (was due {date})</p>
    : <p className="mt-2 text-sm text-muted">Due {date} ({days === 0 ? "today" : `in ${plural(days, "day")}`})</p>;
}

/** A fix already planned or running for this package on this machine, from the jobs list Remediation keeps. */
function useJobFor(f: Finding) {
  // the active ones only: the full list is the newest 500, and an older planned job would be missed
  const jobs = useQuery({ queryKey: ["jobs", "active"], queryFn: () => api<Job[]>(`/api/remediation/jobs?status=${ACTIVE_JOB_STATUSES.join(",")}`) });
  return jobs.data?.find((j) => j.asset_id === f.asset_id && j.action_key === `${f.ecosystem}|${f.package}` && ACTIVE_JOB_STATUSES.includes(j.status));
}

function FixInProgress({ job }: { job: Job }) {
  return (
    <p className="mb-3 flex flex-wrap items-center gap-2 border border-line-strong p-3 text-sm">
      <span className="font-medium">Fix in progress:</span><StatusPill status={job.status} />
      <Link to="/remediation" hash={jobAnchor(job.id)} className="inline-flex tap items-center font-medium text-accent underline">View this fix</Link>
    </p>
  );
}

const refreshFindings = (qc: ReturnType<typeof useQueryClient>) => refresh(qc, "findings");

function RevokeAcceptance({ id }: { id: string }) {
  const admin = useIsAdmin();
  const qc = useQueryClient();
  const [reason, setReason] = useState("");
  const revoke = useMutation({
    mutationFn: () => api(`/api/findings/${id}/revoke-acceptance`, { method: "POST", body: { reason: reason.trim() } }),
    onSuccess: () => refreshFindings(qc),
  });
  return (
    <form className="flex flex-wrap items-end gap-2" onSubmit={(e) => { e.preventDefault(); revoke.mutate(); }}>
      <Field label="Why it needs fixing after all" className="min-w-60 flex-1">
        <input className={input} value={reason} onChange={(e) => setReason(e.target.value)} minLength={3} required />
      </Field>
      <button className={btnQuiet} disabled={revoke.isPending || reason.trim().length < 3} {...adminGate(admin)}>Revoke acceptance</button>
      <Alert error={revoke.error} className="w-full" />
    </form>
  );
}

/** Render risk-acceptance controls for finding f; successful changes invalidate related queries. */
export function AcceptRisk({ f }: { f: Finding }) {
  const admin = useIsAdmin();
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [days, setDays] = useState(90);
  const [everywhere, setEverywhere] = useState(false);
  const accept = useMutation({
    mutationFn: () => everywhere
      ? api("/api/findings/accept", { method: "POST", body: { vuln_id: f.vuln_id, reason: reason.trim(), days } })
      : api(`/api/findings/${f.id}/accept`, { method: "POST", body: { reason: reason.trim(), days } }),
    onSuccess: () => refreshFindings(qc),
  });
  const [tried, setTried] = useState(false);  // say what's wrong once they've tried, not while they type
  if (!open) return <button className={btnQuiet} onClick={() => setOpen(true)} {...adminGate(admin)}>Accept risk</button>;
  const ok = reason.trim().length >= 10;
  return (
    <form className="w-full border border-line-strong p-3" onSubmit={(e) => { e.preventDefault(); setTried(true); if (ok) accept.mutate(); }}>
      <p className="text-sm text-muted">Accepting hides this finding for a limited time, then it comes back for review. Your reason, your name and the expiry are recorded in the tamper-evident evidence ledger and shown to auditors.</p>
      <Field label="Reason" hint="At least 10 characters. Auditors will read it." error={tried && !ok ? "Say why in at least 10 characters." : null} className="mt-3">
        <textarea autoFocus rows={3} className={clsx(input, "py-2")} value={reason} onChange={(e) => setReason(e.target.value)} />
      </Field>
      <label className="mt-3 flex items-center gap-2 text-sm">
        <span className="font-medium">Accept for</span>
        <select className={clsx(input, "w-auto md:min-h-9")} value={days} onChange={(e) => setDays(Number(e.target.value))}>
          {[30, 90, 180].map((d) => <option key={d} value={d}>{d} days</option>)}
        </select>
      </label>
      <label className="mt-3 flex tap items-center gap-2 text-sm">
        <input type="checkbox" checked={everywhere} onChange={(e) => setEverywhere(e.target.checked)} />
        On every host where {f.vuln_id} is open now, not just {f.hostname}
      </label>
      <Alert error={accept.error} className="mt-2" />
      <div className="mt-3 flex gap-2">
        <button className={btnPrimary} disabled={accept.isPending}>{accept.isPending ? "Saving…" : "Accept risk"}</button>
        <button type="button" className={btnQuiet} onClick={() => setOpen(false)}>Cancel</button>
      </div>
    </form>
  );
}

/** Shows exactly what an AI question was turned into; each chip removes that part. */
function AppliedChips({ f, set, clearText }: { f: FindingsFilters; set: (p: Partial<FindingsFilters>) => void; clearText: () => void }) {
  const chips: [string, () => void][] = [];
  if (f.q) chips.push([`Text: ${f.q}`, () => { clearText(); set({ q: "" }); }]);
  f.priority.forEach((p) => chips.push([PRIORITY_LABEL[p], () => set({ priority: f.priority.filter((x) => x !== p) })]));
  if (f.kev) chips.push(["Exploited (KEV)", () => set({ kev: false })]);
  if (f.status !== "open") chips.push([`Status: ${f.status}`, () => set({ status: "open" })]);
  chips.push([f.fixable ? "Has a fix" : "Fix or no fix", () => set({ fixable: !f.fixable })]);
  return (
    <div role="group" aria-label="Filters applied from your question" className="flex flex-wrap items-center gap-1.5">
      <span className="text-sm text-muted">Interpreted as:</span>
      {chips.map(([label, remove]) => (
        <button key={label} className={chip(true)} onClick={remove}>
          {label}<X className="size-3.5" aria-hidden /><span className="sr-only">(remove filter)</span>
        </button>
      ))}
    </div>
  );
}

/** Rendered only when AI is enabled on the server. */
function Explain({ id }: { id: string }) {
  const ex = useMutation({ mutationFn: () => api<{ text: string; model: string }>(`/api/ai/explain/${id}`, { method: "POST" }) });
  return (
    <div className="mt-6">
      {!ex.data && (
        <button className={btnQuiet} disabled={ex.isPending} onClick={() => ex.mutate()}>
          <Sparkles className="size-4" aria-hidden />{ex.isPending ? "Explaining…" : "Explain in plain English"}
        </button>
      )}
      <Alert error={ex.error} className="mt-2" />
      {ex.data && (
        <section aria-label="Plain-English explanation" className="border border-line-strong bg-surface p-4">
          <p className="whitespace-pre-line text-sm">{ex.data.text}</p>
          <p className="mt-2 text-xs text-muted">AI-generated, check before acting.</p>
        </section>
      )}
    </div>
  );
}

/** What to do with a selection: plan the fix (one plan per package, on every selected machine) or accept the risk with one reason. */
function BulkBar({ rows, onClear, onDone }: { rows: Finding[]; onClear: () => void; onDone: (note: { text: string; planned: boolean }) => void }) {
  const qc = useQueryClient();
  const [accepting, setAccepting] = useState(false);
  const [reason, setReason] = useState("");
  const [days, setDays] = useState(90);
  const [result, setResult] = useState("");
  // only what this server may change: with production remediation off, test machines only (the drawer says the same)
  const prodOk = useQuery(settingsQ).data?.production_remediation_allowed ?? true;
  const sandbox = new Set((useQuery(assetsQ).data ?? []).filter((a) => a.sandbox).map((a) => a.id));
  const withFix = rows.filter((r) => r.fixed_version);
  const fixable = prodOk ? withFix : withFix.filter((r) => sandbox.has(r.asset_id));
  const machines = new Set(fixable.map((r) => r.asset_id)).size;
  const groups = [...fixable.reduce((m, r) => m.set(`${r.ecosystem}|${r.package}`, [...(m.get(`${r.ecosystem}|${r.package}`) ?? []), r.asset_id]), new Map<string, string[]>())];
  const plan = useMutation({
    mutationFn: async () => {
      let planned = 0; const refused = new Set<string>();
      for (const [key, ids] of groups) {
        const [ecosystem, pkg] = key.split("|");
        const r = await api<{ jobs: Job[]; errors: { error: string }[] }>("/api/remediation/jobs/batch", { method: "POST", body: { asset_ids: [...new Set(ids)], ecosystem, package: pkg } });
        planned += r.jobs.length; r.errors.forEach((e) => refused.add(e.error));
      }
      return { planned, refused: [...refused] };
    },
    onSettled: () => refresh(qc, "jobs"),
    onSuccess: ({ planned, refused }) => {
      const text = `${plural(planned, "fix", "fixes")} planned.${refused.length ? ` Refused: ${refused.join(" ")}` : ""}`;
      if (planned) onDone({ text, planned: true }); else setResult(text);  // nothing planned: keep the selection to try something else
    },
  });
  const accept = useMutation({
    mutationFn: () => api<{ accepted: number; skipped: number }>("/api/findings/accept-many", { method: "POST", body: { ids: rows.map((r) => r.id), reason: reason.trim(), days } }),
    onSuccess: (r) => { setAccepting(false); setReason(""); onDone({ text: `${plural(r.accepted, "finding")} accepted for ${days} days.`, planned: false }); void refresh(qc, "findings"); },
  });
  return (
    <div role="region" aria-label="Act on selected findings" className="fixed inset-x-2 bottom-[calc(var(--tabbar-h,3.5rem)+0.5rem)] z-10 flex max-h-[40dvh] flex-wrap items-center gap-x-4 gap-y-2 overflow-y-auto border border-ink bg-surface px-3 py-2 text-sm shadow-[0_6px_16px_var(--shadow)] md:bottom-4 md:left-[calc(var(--sidebar-w)+2rem)] md:right-8">
      <strong className="num font-semibold">{plural(rows.length, "finding")} selected</strong>
      <span className="text-muted">{groups.length ? `${plural(groups.length, "package")} to upgrade on ${plural(machines, prodOk ? "machine" : "test machine")}${withFix.length > fixable.length ? `; production machines wait until production remediation is on` : ""}`
        : withFix.length ? "None is on a test machine, and production remediation is off" : "None has a fix yet"}</span>
      <div className="ml-auto flex flex-wrap gap-2">
        <button className={btnQuiet} onClick={onClear}>Clear selection</button>
        <button className={btnQuiet} onClick={() => { accept.reset(); setAccepting(true); }}>Accept risk…</button>
        <button className={btnPrimary} disabled={!groups.length || plan.isPending} onClick={() => plan.mutate()}><Wrench className="size-4" aria-hidden />{plan.isPending ? "Planning…" : (groups.length ? `Plan ${plural(groups.length, "fix", "fixes")}${prodOk ? "" : ` on ${plural(machines, "test machine")}`}` : "Plan fix")}</button>
      </div>
      {result && <p role="status" className="w-full text-muted">{result}</p>}
      <Alert error={plan.error ?? null} className="w-full" />
      <ConfirmDialog open={accepting} onOpenChange={setAccepting} title={`Accept the risk of ${plural(rows.length, "finding")}?`}
        description="Each is hidden for the period you choose, then comes back for review. Your reason, your name and the expiry are recorded for each in the evidence ledger."
        confirmLabel="Accept risk" pendingLabel="Saving…" pending={accept.isPending} error={accept.error} onConfirm={() => { if (reason.trim().length >= 10) accept.mutate(); }}>
        <Field label="Reason" hint="At least 10 characters. Auditors will read it." className="mt-3">
          <textarea rows={3} className={clsx(input, "py-2")} value={reason} onChange={(e) => setReason(e.target.value)} />
        </Field>
        <label className="mt-3 flex items-center gap-2 text-sm"><span className="font-medium">Accept for</span>
          <select className={clsx(input, "w-auto md:min-h-9")} value={days} onChange={(e) => setDays(Number(e.target.value))}>{[30, 90, 180].map((d) => <option key={d} value={d}>{d} days</option>)}</select>
        </label>
      </ConfirmDialog>
    </div>
  );
}

/** Name the current filters and come back to them from here or the palette. */
function SavedViews({ search }: { search: RawSearch }) {
  const navigate = useNavigate();
  const [views, setViews] = useState<SavedView[]>(savedViews);
  const [naming, setNaming] = useState(false);
  const [name, setName] = useState("");
  useEffect(() => { const on = () => setViews(savedViews()); window.addEventListener("nimstead-views", on); return () => window.removeEventListener("nimstead-views", on); }, []);
  const clean = Object.fromEntries(Object.entries(search).filter(([k, v]) => v !== undefined && k !== "f"));
  const same = (v: SavedView) => JSON.stringify(Object.entries(v.search).sort()) === JSON.stringify(Object.entries(clean).sort());
  const current = views.find(same);
  const save = () => { const n = name.trim(); if (!n) return; saveViews([...views.filter((v) => v.name !== n), { name: n, search: clean }]); setNaming(false); setName(""); announce(`Saved view ${n}`); };
  return (
    <div className="flex flex-wrap items-center gap-2 text-sm">
      {views.length > 0 && (
        <label className="flex items-center gap-2"><span className="text-muted">View</span>
          <select className={clsx(input, "w-auto md:min-h-8")} value={current?.name ?? ""} onChange={(e) => { const v = views.find((x) => x.name === e.target.value); if (v) void navigate({ to: "/findings", search: v.search }); }}>
            <option value="">{current ? "" : "Unsaved"}</option>{views.map((v) => <option key={v.name} value={v.name}>{v.name}</option>)}
          </select>
        </label>
      )}
      {current ? (
        <button className="tap cursor-pointer underline" onClick={() => saveViews(views.filter((v) => v !== current))}>Remove “{current.name}”</button>
      ) : naming ? (
        <form className="flex items-center gap-2" onSubmit={(e) => { e.preventDefault(); save(); }}>
          <input autoFocus aria-label="Name for this view" className={clsx(input, "w-44 md:min-h-8")} value={name} maxLength={60} onChange={(e) => setName(e.target.value)} placeholder="e.g. Internet-facing KEV"
            onKeyDown={(e) => e.key === "Escape" && setNaming(false)} />
          <button className={btnQuiet} disabled={!name.trim()}>Save</button>
        </form>
      ) : (
        <button className={clsx(btnQuiet, "md:min-h-8")} onClick={() => setNaming(true)}><Bookmark className="size-4" aria-hidden />Save view</button>
      )}
    </div>
  );
}
