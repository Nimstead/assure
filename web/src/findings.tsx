import { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useWindowVirtualizer } from "@tanstack/react-virtual";
import { Dialog, Switch } from "radix-ui";
import { ArrowRight, ExternalLink, Search, Sparkles, X } from "lucide-react";
import clsx from "clsx";
import {
  adminGate, aiFilterToPatch, aiStatusQ, api, assetsQ, filtersToApi, filtersToSearch, looksLikeQuestion, parseFilters, pct, plural, PRIORITIES, PRIORITY_LABEL, relativeTime,
  parseUtc, useIsAdmin, useTitle, whyMatched, type AiFilter, type Finding, type FindingsFilters, type RawSearch, type Status,
} from "./lib";
import { PlanFixButton } from "./remediation";
import { btnPrimary, btnQuiet, EmptyState, ErrorState, input, KevBadge, PriorityPill, Skeleton } from "./ui";

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
  const ask = useMutation({
    mutationFn: () => api<AiFilter>("/api/ai/search", { method: "POST", body: { text: text.trim() } }),
    onSuccess: (a) => { const p = aiFilterToPatch(a); setText(p.q ?? ""); setAsked(true); set(p); },
  });
  useEffect(() => {
    if (text === f.q || question) return; // a question is sent on Ask, not searched literally
    const t = setTimeout(() => set({ q: text.trim() }), 250);
    return () => clearTimeout(t);
  });

  const apiQs = filtersToApi(f);
  const list = useQuery({ queryKey: ["findings", apiQs], queryFn: () => api<Finding[]>(`/api/findings?${apiQs}`), placeholderData: (p) => p });
  const assets = useQuery(assetsQ);
  const host = assets.data?.find((a) => a.id === f.asset)?.hostname;

  return (
    <div className="flex flex-col gap-4">
      <header className="flex items-baseline justify-between gap-4">
        <h1 className="text-3xl font-semibold">Findings</h1>
        {list.data && <p className="num text-sm text-muted" aria-live="polite">{plural(list.data.length, "result")}</p>}
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
        {ask.error && <p role="alert" className="text-sm text-now-fg">{ask.error.message}</p>}
        {asked && !question && <AppliedChips f={f} set={set} clearText={() => setText("")} />}
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2.5">
          <div role="group" aria-label="Status" className="flex rounded-md border border-line-strong bg-surface p-0.5">
            {STATUSES.map((s) => (
              <button key={s} aria-pressed={f.status === s} onClick={() => set({ status: s })}
                className={clsx("min-h-8 cursor-pointer px-3 text-sm capitalize", f.status === s ? "bg-accent-soft font-medium text-ink" : "text-muted hover:text-ink")}>
                {s}
              </button>
            ))}
          </div>
          <div role="group" aria-label="Priority" className="flex flex-wrap gap-1.5">
            {PRIORITIES.map((p) => {
              const on = f.priority.includes(p);
              return (
                <button key={p} aria-pressed={on} onClick={() => set({ priority: on ? f.priority.filter((x) => x !== p) : [...f.priority, p] })}
                  className={clsx("min-h-8 cursor-pointer rounded-full border px-3 text-sm", on ? "border-accent bg-accent-soft font-medium" : "border-line-strong text-muted hover:text-ink")}>
                  {PRIORITY_LABEL[p]}
                </button>
              );
            })}
          </div>
          <button aria-pressed={f.kev} onClick={() => set({ kev: !f.kev })}
            className={clsx("min-h-8 cursor-pointer rounded-full border px-3 text-sm", f.kev ? "border-accent bg-accent-soft font-medium" : "border-line-strong text-muted hover:text-ink")}>
            Exploited (KEV)
          </button>
          <label className="flex cursor-pointer items-center gap-2 text-sm">
            <Switch.Root checked={f.fixable} onCheckedChange={(fixable) => set({ fixable })}
              className="relative h-5 w-9 cursor-pointer rounded-full bg-line-strong data-[state=checked]:bg-accent">
              <Switch.Thumb className="block size-4 translate-x-0.5 rounded-full bg-surface transition-transform data-[state=checked]:translate-x-[18px]" />
            </Switch.Root>
            Fixable only
          </label>
          {f.asset && (
            <button className={clsx(btnQuiet, "min-h-8 rounded-full !px-3")} onClick={() => set({ asset: "" })}>
              Host: {host ?? "…"} <X className="size-3.5" aria-label="Clear host filter" />
            </button>
          )}
        </div>
      </div>

      {list.isPending ? <TableSkeleton /> : list.error ? <ErrorState error={list.error} retry={() => list.refetch()} /> : (
        <Results rows={list.data} f={f} noAssets={assets.data?.length === 0} onClear={() => { setAsked(false); set({ fixable: false, kev: false, q: "", priority: [], asset: "" }); }} onPick={(open) => set({ open }, true)} />
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
  const filtered = f.q || f.kev || f.priority.length || f.asset || f.fixable || f.status !== "open";
  return (
    <EmptyState title={f.status === "open" && !filtered ? "No open findings" : "Nothing matches"}
      action={filtered ? <button className={btnQuiet} onClick={onClear}>{f.fixable ? "Show findings with no fix too" : "Clear filters"}</button> : undefined}>
      {f.status === "open" && !filtered ? "Everything reported is clean." : f.fixable ? "Fixable-only is on, which hides findings that have no upgrade yet." : "Try fewer filters or a different search."}
    </EmptyState>
  );
}

const COLS = ["prio", "vuln", "pkg", "ver", "host", "score", "reason"] as const;
const HEADS = ["Priority", "Vulnerability", "Package", "Installed → fixed", "Host", "Score", "Why"];

function Table({ rows, onPick }: { rows: Finding[]; onPick: (id: string) => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const v = useWindowVirtualizer({
    count: rows.length, overscan: 12, scrollMargin: ref.current?.offsetTop ?? 0,
    estimateSize: () => (window.innerWidth < 768 ? 104 : 44),
  });
  return (
    <div role="table" aria-label="Findings" aria-rowcount={rows.length} className="overflow-hidden rounded-lg border border-line bg-surface">
      <div role="row" className="frow hidden border-b border-line bg-sunken px-3 py-2 text-xs font-medium text-muted md:grid">
        {HEADS.map((h, i) => <div key={h} role="columnheader" data-c={COLS[i]} className={i === 5 ? "text-right" : ""}>{h}</div>)}
      </div>
      <div role="rowgroup" ref={ref} className="relative" style={{ height: v.getTotalSize() }}>
        {v.getVirtualItems().map((vi) => {
          const r = rows[vi.index]!;
          return (
            <div key={r.id} role="row" aria-rowindex={vi.index + 1} data-index={vi.index} ref={v.measureElement}
              onClick={() => onPick(r.id)}
              className="frow absolute inset-x-0 top-0 cursor-pointer border-b border-line px-3 py-2.5 text-sm last:border-0 hover:bg-sunken md:py-0"
              style={{ transform: `translateY(${vi.start - v.options.scrollMargin}px)`, minHeight: 44 }}>
              <div role="cell" data-c="prio"><PriorityPill priority={r.priority} /></div>
              <div role="cell" data-c="vuln" className="flex min-w-0 items-center gap-2">
                <button className="cursor-pointer truncate text-left font-mono text-[13px] font-medium underline-offset-2 hover:underline"
                  onClick={(e) => { e.stopPropagation(); onPick(r.id); }}>{r.vuln_id}</button>
                {r.kev && <KevBadge />}
              </div>
              <div role="cell" data-c="pkg" className="truncate font-medium">{r.package}</div>
              <div role="cell" data-c="ver" className="truncate font-mono text-xs text-muted">
                {r.installed_version} → {r.fixed_version ? <span className="text-ink">{r.fixed_version}</span> : "no fix yet"}
              </div>
              <div role="cell" data-c="host" className="truncate text-muted">{r.hostname}</div>
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
  return <div aria-busy="true" aria-label="Loading findings" className="flex flex-col gap-px overflow-hidden rounded-lg border border-line">{Array.from({ length: 8 }, (_, i) => <Skeleton key={i} className="h-11 rounded-none" />)}</div>;
}

function FindingDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const q = useQuery({ queryKey: ["finding", id], queryFn: () => api<Finding>(`/api/findings/${id}`), enabled: !!id });
  return (
    <Dialog.Root open={!!id} onOpenChange={(o) => !o && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay className="overlay" />
        <Dialog.Content className="drawer p-5 md:p-6" aria-describedby={undefined}>
          <div className="mb-4 flex items-start justify-between gap-3">
            <Dialog.Title className="break-all font-mono text-lg font-semibold">{q.data?.vuln_id ?? "Finding"}</Dialog.Title>
            <Dialog.Close className={clsx(btnQuiet, "size-9 shrink-0 !px-0")} aria-label="Close"><X className="size-4" aria-hidden /></Dialog.Close>
          </div>
          {q.isPending ? <div className="flex flex-col gap-3"><Skeleton className="h-6 w-40" /><Skeleton className="h-20" /><Skeleton className="h-32" /></div>
            : q.error ? <ErrorState error={q.error} retry={() => q.refetch()} /> : <FindingDetail f={q.data} />}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function FindingDetail({ f }: { f: Finding }) {
  const ai = useQuery(aiStatusQ).data?.enabled === true;
  const ids = [...new Set([f.vuln_id, ...f.advisory_ids])];
  const when = (s: string) => <time dateTime={parseUtc(s).toISOString()} title={parseUtc(s).toLocaleString()}>{relativeTime(s)}</time>;
  const H = ({ children }: { children: string }) => <h3 className="mb-1.5 mt-6 text-sm font-semibold">{children}</h3>;
  return (
    <div>
      <div className="flex flex-wrap items-center gap-2"><PriorityPill priority={f.priority} />{f.kev && <KevBadge />}<span className="num text-sm text-muted">Score {f.score}/100</span></div>
      {f.summary && <p className="mt-3 text-sm">{f.summary}</p>}
      {ai && <Explain key={f.id} id={f.id} />}

      <H>Why it matched</H>
      <p className="text-sm"><strong className="font-semibold">{f.package}</strong> on <strong className="font-semibold">{f.hostname}</strong></p>
      <p className="mt-1 break-words rounded-md bg-sunken p-3 font-mono text-[13px]">{whyMatched(f)}</p>
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
            <a href={`https://osv.dev/vulnerability/${encodeURIComponent(i)}`} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 border border-line-strong px-2 py-1 font-mono text-xs hover:bg-sunken">
              {i} <ExternalLink className="size-3" aria-label="(opens in a new tab)" />
            </a>
          </li>
        ))}
      </ul>

      {f.status === "open" && (
        <>
          <H>Act on it</H>
          <div className="flex flex-wrap items-start gap-2">
            {f.fixed_version && <PlanFixButton ecosystem={f.ecosystem} pkg={f.package} hosts={[f.hostname]} />}
            <AcceptRisk id={f.id} />
          </div>
        </>
      )}

      <p className="mt-6 text-sm text-muted">
        First seen {when(f.first_seen)}, last seen {when(f.last_seen)}{f.resolved_at && <>, resolved {when(f.resolved_at)}</>}.
      </p>
    </div>
  );
}

function AcceptRisk({ id }: { id: string }) {
  const admin = useIsAdmin();
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [days, setDays] = useState(90);
  const accept = useMutation({
    mutationFn: () => api(`/api/findings/${id}/accept`, { method: "POST", body: { reason: reason.trim(), days } }),
    onSuccess: () => Promise.all(["finding", "findings", "summary", "ledger"].map((k) => qc.invalidateQueries({ queryKey: [k] }))),
  });
  if (!open) return <button className={btnQuiet} onClick={() => setOpen(true)} {...adminGate(admin)}>Accept risk</button>;
  const ok = reason.trim().length >= 10;
  return (
    <form className="w-full rounded-lg border border-line-strong p-3" onSubmit={(e) => { e.preventDefault(); if (ok) accept.mutate(); }}>
      <p className="text-sm text-muted">Accepting hides this finding for a limited time, then it comes back for review. Your reason, your name and the expiry are recorded in the tamper-evident evidence ledger and shown to auditors.</p>
      <label className="mt-3 block text-sm font-medium" htmlFor="accept-reason">Reason (at least 10 characters)</label>
      <textarea id="accept-reason" autoFocus rows={3} className={clsx(input, "mt-1 py-2")} value={reason} onChange={(e) => setReason(e.target.value)} />
      <label className="mt-3 flex items-center gap-2 text-sm">
        <span className="font-medium">Accept for</span>
        <select className={clsx(input, "min-h-9 w-auto")} value={days} onChange={(e) => setDays(Number(e.target.value))}>
          {[30, 90, 180].map((d) => <option key={d} value={d}>{d} days</option>)}
        </select>
      </label>
      {accept.error && <p role="alert" className="mt-2 text-sm text-now-fg">{accept.error.message}</p>}
      <div className="mt-3 flex gap-2">
        <button className={btnPrimary} disabled={!ok || accept.isPending}>{accept.isPending ? "Saving…" : "Accept risk"}</button>
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
        <button key={label} className="inline-flex min-h-8 cursor-pointer items-center gap-1.5 rounded-full border border-accent bg-accent-soft px-3 text-sm" onClick={remove}>
          {label}<X className="size-3.5" aria-label="Remove filter" />
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
      {ex.error && <p role="alert" className="mt-2 text-sm text-now-fg">{ex.error.message}</p>}
      {ex.data && (
        <section aria-label="Plain-English explanation" className="rounded-lg border border-line-strong bg-sunken p-4">
          <p className="whitespace-pre-line text-sm">{ex.data.text}</p>
          <p className="mt-2 text-xs text-muted">AI-generated, check before acting.</p>
        </section>
      )}
    </div>
  );
}
