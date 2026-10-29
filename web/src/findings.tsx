import { useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { Link, useNavigate, useRouterState } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useWindowVirtualizer } from "@tanstack/react-virtual";
import { Dialog, Switch } from "radix-ui";
import { ArrowRight, ExternalLink, Search, SlidersHorizontal, Sparkles, X } from "lucide-react";
import clsx from "clsx";
import {
  ACTIVE_JOB_STATUSES, adminGate, aiFilterToPatch, aiStatusQ, api, assetsQ, FINDINGS_CAP, filtersToApi, filtersToSearch, jobAnchor, jobsQ, looksLikeQuestion, parseFilters, pct, plural,
  PRIORITIES, PRIORITY_LABEL, refresh, relativeTime, parseUtc, useIsAdmin, useTitle, whyMatched, type AiFilter, type Finding, type FindingsFilters, type Job, type RawSearch, type Status,
} from "./lib";
import { PlanFixButton } from "./remediation";
import { Alert, btnPrimary, btnQuiet, chip, EmptyState, ErrorState, Field, input, KevBadge, Loading, PriorityPill, StatusPill, switchRoot, switchThumb, useReturnFocus } from "./ui";

/** "org.apache.logging.log4j:log4j-core" → "log4j-core" then the group, muted: the part that tells packages apart comes
 *  first, so it survives truncation; the cell's title has the full name. */
function PackageName({ name }: { name: string }) {
  const i = Math.max(name.lastIndexOf(":"), name.lastIndexOf("/"));
  return i > 0 && i < name.length - 1
    ? <>{name.slice(i + 1)} <span className="font-normal text-muted">{name.slice(0, i)}</span></>
    : <>{name}</>;
}

const STATUSES: Status[] = ["open", "resolved", "accepted"];

export function FindingsPage({ search }: { search: RawSearch }) {
  useTitle("Findings");
  const f = parseFilters(search);
  const navigate = useNavigate();
  const set = (patch: Partial<FindingsFilters>, push = false) =>
    navigate({ to: "/findings", search: filtersToSearch({ ...f, ...patch }), replace: !push });

  // The search box is local state, debounced into the URL.
  const [text, setText] = useState(f.q);
  useEffect(() => setText(f.q), [f.q]);
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
  const active = f.priority.length + Number(f.kev) + Number(f.overdue) + Number(!f.fixable) + Number(!!f.asset);
  useEffect(() => {
    if (text === f.q || question) return; // a question is sent on Ask, not searched literally
    const t = setTimeout(() => set({ q: text.trim() }), 250);
    return () => clearTimeout(t);
  });

  const apiQs = filtersToApi(f);
  const list = useQuery({ queryKey: ["findings", apiQs], queryFn: () => api<Finding[]>(`/api/findings?${apiQs}`), placeholderData: (p) => p });
  const assets = useQuery(assetsQ);
  const host = assets.data?.find((a) => a.id === f.asset)?.hostname;
  const updating = list.isPlaceholderData;

  return (
    <div className="flex flex-col gap-4">
      <header className="flex items-baseline justify-between gap-4">
        <h1 className="text-3xl font-semibold">Findings</h1>
        <div className="flex items-baseline gap-4">
          {list.data && <p className="num text-sm text-muted" aria-live="polite">{updating ? "Updating…" : plural(list.data.length, "result")}</p>}
          <a className={btnQuiet} href={`/api/findings.csv?${apiQs}`} download>Export CSV</a>
        </div>
      </header>

      <div className="flex flex-col gap-3">
        <div className="relative">
          <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted" aria-hidden />
          <input
            type="search" aria-label="Search findings by package, vulnerability ID or host" placeholder="Search package, CVE or host"
            className={clsx(input, "pl-9")} value={text} onChange={(e) => { setText(e.target.value); setAsked(false); }}
            onKeyDown={(e) => { if (e.key === "Enter" && question && !ask.isPending) ask.mutate(); }}
          />
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
          <div role="group" aria-label="Status" className="flex border border-line-strong bg-surface p-0.5">
            {STATUSES.map((s) => (
              <button key={s} aria-pressed={f.status === s} onClick={() => set({ status: s })}
                className={clsx("min-h-[44px] cursor-pointer px-3 text-sm capitalize md:min-h-8", f.status === s ? "bg-accent-soft font-medium text-ink shadow-[inset_0_0_0_1px_var(--ink)]" : "text-muted hover:text-ink")}>
                {s}
              </button>
            ))}
          </div>
          {/* On phones the rarer filters fold away so results start on the first screen. */}
          <button className={clsx(chip(active > 0), "md:hidden")} aria-expanded={showFilters} aria-controls="more-filters" onClick={() => setShowFilters((x) => !x)}>
            <SlidersHorizontal className="size-4" aria-hidden />Filters{active > 0 && ` (${active})`}
          </button>
          <div id="more-filters" className={clsx("w-full flex-wrap items-center gap-x-4 gap-y-2.5 md:flex md:w-auto", showFilters ? "flex" : "hidden")}>
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
          <label className="flex min-h-[44px] cursor-pointer items-center gap-2 text-sm md:min-h-0">
            <Switch.Root checked={f.fixable} onCheckedChange={(fixable) => set({ fixable })} className={switchRoot}>
              <Switch.Thumb className={switchThumb} />
            </Switch.Root>
            Fixable only
          </label>
          {f.asset && (
            <button className={clsx(chip(true), "max-w-full")} onClick={() => set({ asset: "" })}>
              <span className="min-w-0 truncate">Host: {host ?? "…"}</span> <X className="size-3.5 shrink-0" aria-hidden /><span className="sr-only">(clear host filter)</span>
            </button>
          )}
          </div>
        </div>
      </div>

      {list.data?.length === FINDINGS_CAP && (
        <p className="border border-line-strong bg-surface px-3 py-2 text-sm">Showing the first {FINDINGS_CAP.toLocaleString()}. Narrow the filters, or export CSV for all of them.</p>
      )}
      {list.isPending ? <TableSkeleton /> : list.error ? <ErrorState error={list.error} retry={() => list.refetch()} /> : (
        <div aria-busy={updating} className={clsx("transition-opacity", updating && "opacity-60")}>
          <Results rows={list.data} f={f} noAssets={assets.data?.length === 0} onClear={() => { setAsked(false); set({ fixable: false, kev: false, overdue: false, q: "", priority: [], asset: "" }); }} onPick={(open) => set({ open }, true)} />
        </div>
      )}

      <FindingDrawer id={f.open} onClose={() => set({ open: "" }, true)} />
    </div>
  );
}

function Results({ rows, f, noAssets, onClear, onPick }: { rows: Finding[]; f: FindingsFilters; noAssets: boolean; onClear: () => void; onPick: (id: string) => void }) {
  if (rows.length > 0) return <Table rows={rows} onPick={onPick} />;
  if (noAssets) {
    return <EmptyState title="No machines yet" action={<Link to="/add" className={clsx(btnQuiet, "no-underline")}>Add a machine <ArrowRight className="size-4" aria-hidden /></Link>}>Findings appear once a machine reports its installed software.</EmptyState>;
  }
  const filtered = f.q || f.kev || f.overdue || f.priority.length || f.asset || f.fixable || f.status !== "open";
  return (
    <EmptyState title={f.status === "open" && !filtered ? "No open findings" : "Nothing matches"}
      action={filtered ? <button className={btnQuiet} onClick={onClear}>{f.fixable ? "Show findings with no fix too" : "Clear filters"}</button> : undefined}>
      {f.status === "open" && !filtered ? "Everything reported is clean." : f.fixable ? "Fixable-only is on, which hides findings that have no upgrade yet." : "Try fewer filters or a different search."}
    </EmptyState>
  );
}

const COLS = ["prio", "vuln", "pkg", "ver", "host", "score", "reason"] as const;
const HEADS = ["Priority", "Vulnerability", "Package", "Installed → fixed", "Host", "Score", "Why"];
// Phones hide the header row, so each cell names its column for screen readers there.
const CellLabel = ({ i }: { i: number }) => <span className="sr-only md:hidden">{HEADS[i]}: </span>;

function Table({ rows, onPick }: { rows: Finding[]; onPick: (id: string) => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const [margin, setMargin] = useState(0);
  useLayoutEffect(() => { setMargin(ref.current?.offsetTop ?? 0); });  // measured after layout, not read during render
  const v = useWindowVirtualizer({
    count: rows.length, overscan: 12, scrollMargin: margin,
    estimateSize: () => (window.innerWidth < 768 ? 104 : 44),
  });
  return (
    <div role="table" aria-label="Findings" aria-rowcount={rows.length + 1} className="overflow-hidden border border-line bg-surface">
      <div role="row" aria-rowindex={1} className="frow hidden border-b border-line bg-sunken px-3 py-2 text-xs font-medium text-muted md:grid">
        {HEADS.map((h, i) => <div key={h} role="columnheader" data-c={COLS[i]} className={i === 5 ? "text-right" : ""}>{h}</div>)}
      </div>
      <div role="rowgroup" ref={ref} className="relative" style={{ height: v.getTotalSize() }}>
        {v.getVirtualItems().map((vi) => {
          const r = rows[vi.index]!;
          return (
            <div key={r.id} role="row" aria-rowindex={vi.index + 2} data-index={vi.index} ref={v.measureElement}
              onClick={() => onPick(r.id)}
              className="frow absolute inset-x-0 top-0 cursor-pointer border-b border-line px-3 py-2.5 text-sm last:border-0 hover:bg-sunken md:py-0"
              style={{ transform: `translateY(${vi.start - v.options.scrollMargin}px)`, minHeight: 44 }}>
              <div role="cell" data-c="prio"><CellLabel i={0} /><PriorityPill priority={r.priority} /></div>
              <div role="cell" data-c="vuln" className="flex min-w-0 items-center gap-2">
                <button className="cursor-pointer truncate text-left font-mono text-[13px] font-medium underline-offset-2 hover:underline"
                  onClick={(e) => { e.stopPropagation(); onPick(r.id); }}>{r.vuln_id}</button>
                {r.kev && <KevBadge />}
              </div>
              {/* every cell that can be cut off carries its full text as a title */}
              <div role="cell" data-c="pkg" className="truncate font-medium" title={r.package}><CellLabel i={2} /><PackageName name={r.package} /></div>
              <div role="cell" data-c="ver" className="truncate font-mono text-xs text-muted" title={`${r.installed_version} → ${r.fixed_version ?? "no fix yet"}`}>
                <CellLabel i={3} />{r.installed_version} → {r.fixed_version ? <span className="text-ink">{r.fixed_version}</span> : "no fix yet"}
              </div>
              <div role="cell" data-c="host" className="truncate text-muted" title={r.hostname}><CellLabel i={4} />{r.hostname}</div>
              <div role="cell" data-c="score" className="num text-right text-muted"><span className="sr-only">Score </span>{r.score}</div>
              <div role="cell" data-c="reason" className="truncate text-muted" title={r.reasons[0]}>{r.reasons[0]}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function TableSkeleton() {
  return <Loading className="h-11" rows={8} label="Loading findings…" />;
}

function FindingDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const q = useQuery({ queryKey: ["finding", id], queryFn: () => api<Finding>(`/api/findings/${id}`), enabled: !!id });
  const title = useRef<HTMLHeadingElement>(null);
  // Focus starts on the title (no ring: the user didn't move it there) and goes back to the row that opened the drawer.
  const focus = useReturnFocus(title);
  return (
    <Dialog.Root open={!!id} onOpenChange={(o) => !o && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay className="overlay" />
        <Dialog.Content className="drawer p-5 md:p-6" aria-describedby={undefined} {...focus}>
          <div className="mb-4 flex items-start justify-between gap-3">
            <Dialog.Title ref={title} tabIndex={-1} className="break-all font-mono text-lg font-semibold">{q.data?.vuln_id ?? "Finding"}</Dialog.Title>
            <Dialog.Close className={clsx(btnQuiet, "size-[44px] shrink-0 !px-0 md:size-9")} aria-label="Close"><X className="size-4" aria-hidden /></Dialog.Close>
          </div>
          {q.isPending ? <Loading className="h-20" rows={3} label="Loading finding…" />
            : q.error ? <ErrorState error={q.error} retry={() => q.refetch()} /> : <FindingDetail f={q.data} />}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function FindingDetail({ f }: { f: Finding }) {
  const ai = useQuery(aiStatusQ).data?.enabled === true;
  const job = useJobFor(f);
  const ids = [...new Set([f.vuln_id, ...f.advisory_ids])];
  const when = (s: string) => <time dateTime={parseUtc(s).toISOString()} title={parseUtc(s).toLocaleString()}>{relativeTime(s)}</time>;
  return (
    <div>
      <div className="flex flex-wrap items-center gap-2"><PriorityPill priority={f.priority} />{f.kev && <KevBadge />}<span className="num text-sm text-muted">Score {f.score}/100</span></div>
      {f.due && <Due due={f.due} />}
      {f.summary && <p className="mt-3 text-sm">{f.summary}</p>}
      {ai && <Explain key={f.id} id={f.id} />}

      <H>Why it matched</H>
      <p className="break-words text-sm"><strong className="break-all font-semibold">{f.package}</strong> on <strong className="break-all font-semibold">{f.hostname}</strong></p>
      <p className="mt-1 break-words bg-sunken p-3 font-mono text-[13px]">{whyMatched(f)}</p>
      {f.fixed_version && <p className="mt-2 text-sm text-muted">Fix: upgrade {f.package} to {f.fixed_version} or later.</p>}

      <H>Why it's ranked here</H>
      <ul className="list-disc space-y-1 pl-5 text-sm">{f.reasons.map((r) => <li key={r}>{r}</li>)}</ul>

      <H>Risk signals</H>
      <dl className="num grid grid-cols-3 gap-3 text-sm">
        <div><dt className="text-muted">CVSS</dt><dd className="font-medium">{f.cvss ?? "n/a"}</dd></div>
        <div><dt className="text-muted">EPSS (30 days)</dt><dd className="font-medium">{f.epss === null ? "n/a" : pct(f.epss)}</dd></div>
        <div><dt className="text-muted">Known exploited</dt><dd className="font-medium">{f.kev ? "Yes (KEV)" : "No"}</dd></div>
      </dl>

      <H>Advisories</H>
      <ul className="flex flex-wrap gap-2">
        {ids.map((i) => (
          <li key={i}>
            <a href={`https://osv.dev/vulnerability/${encodeURIComponent(i)}`} target="_blank" rel="noopener noreferrer" className="inline-flex min-h-[44px] items-center gap-1 border border-line-strong px-2 py-1 font-mono text-xs hover:bg-sunken md:min-h-0">
              {i} <ExternalLink className="size-3" aria-label="(opens in a new tab)" />
            </a>
          </li>
        ))}
      </ul>

      {f.status === "open" && (
        <>
          <H>Act on it</H>
          {job && <FixInProgress job={job} />}
          <div className="flex flex-wrap items-start gap-2">
            {f.fixed_version && !job && <PlanFixButton ecosystem={f.ecosystem} pkg={f.package} assetIds={[f.asset_id]} />}
            <AcceptRisk f={f} />
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
  const jobs = useQuery(jobsQ);
  return jobs.data?.find((j) => j.asset_id === f.asset_id && j.action_key === `${f.ecosystem}|${f.package}` && ACTIVE_JOB_STATUSES.includes(j.status));
}

function FixInProgress({ job }: { job: Job }) {
  return (
    <p className="mb-3 flex flex-wrap items-center gap-2 border border-line-strong p-3 text-sm">
      <span className="font-medium">Fix in progress:</span><StatusPill status={job.status} />
      <Link to="/remediation" hash={jobAnchor(job.id)} className="inline-flex min-h-[44px] items-center font-medium text-accent underline md:min-h-0">View this fix</Link>
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

function AcceptRisk({ f }: { f: Finding }) {
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
  if (!open) return <button className={btnQuiet} onClick={() => setOpen(true)} {...adminGate(admin)}>Accept risk</button>;
  const ok = reason.trim().length >= 10;
  const [tried, setTried] = useState(false);  // say what's wrong once they've tried, not while they type
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
      <label className="mt-3 flex min-h-[44px] items-center gap-2 text-sm md:min-h-0">
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
  chips.push([f.fixable ? "Fixable only" : "Fix or no fix", () => set({ fixable: !f.fixable })]);
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
