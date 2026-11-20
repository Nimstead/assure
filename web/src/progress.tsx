import { useMemo, useState, type KeyboardEvent, type PointerEvent, type ReactNode } from "react";
import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Download, TriangleAlert } from "lucide-react";
import clsx from "clsx";
import { filtersToSearch, parseFilters, plural, PRIORITIES, progressQ, PROGRESS_RANGES, useTitle, type FindingsFilters, type Progress, type ProgressDay, type ProgressOwner } from "./lib";
import { btnQuiet, EmptyState, ErrorState, HowJudged, Loading } from "./ui";

const n = (v: number) => v.toLocaleString("en");
/** "23 Aug" for a UTC calendar day ("2026-08-23"); the year only when it isn't this one. */
export function dayLabel(date: string, year = new Date().getUTCFullYear()): string {
  const d = new Date(`${date}T00:00:00Z`);
  return d.toLocaleDateString("en-GB", { day: "numeric", month: "short", timeZone: "UTC", ...(d.getUTCFullYear() !== year ? { year: "numeric" } : {}) });
}
const openTotal = (d: ProgressDay) => PRIORITIES.reduce((t, p) => t + d.open[p], 0);
const signed = (v: number) => (v > 0 ? `+${n(v)}` : v < 0 ? `−${n(-v)}` : "0");

/** The page's answer to "better or worse?": the open total over the range, what's overdue now, and the pace on fix now
 * over the last four weeks. Pure, so its wording is tested. */
export function progressSentences(p: Pick<Progress, "days">): [string, string] {
  const first = p.days[0], last = p.days[p.days.length - 1];
  if (!first || !last) return ["Nothing to report yet.", ""];
  const span = `the last ${p.days.length} days`;
  const a = openTotal(first), b = openTotal(last);
  const lead = a === b ? `Open findings held at ${n(b)} over ${span}` : `Open findings ${b < a ? "fell" : "rose"} from ${n(a)} to ${n(b)} in ${span}`;
  const overdue = last.overdue ? `; ${n(last.overdue)} ${last.overdue === 1 ? "is" : "are"} overdue.` : "; none are overdue.";
  const from = Math.max(0, p.days.length - 29);  // four weeks back, or the start of a shorter range
  const weeks = (p.days.length - 1 - from) / 7;
  const now = last.open["fix-now"], change = now - p.days[from]!.open["fix-now"];
  let pace: string;
  if (now === 0) pace = change < 0 ? "Every fix-now finding is closed." : "No fix-now findings are open.";
  else if (change < 0 && weeks > 0) {
    const toClear = Math.ceil(now / (-change / weeks));
    pace = toClear > 52 ? `At the last four weeks' pace, the ${plural(now, "fix-now finding")} would take more than a year to clear.`
      : `At the last four weeks' pace, the ${plural(now, "fix-now finding")} would clear in about ${plural(toClear, "week")}.`;
  } else if (change > 0) pace = `Fix-now findings grew by ${n(change)} in the last four weeks.`;
  else pace = `Fix-now findings haven't fallen in the last four weeks (${n(now)} open).`;
  return [lead + overdue, pace];
}

interface Series { key: string; label: string; value: (d: ProgressDay) => number; tone: string; mark?: string; filter: Partial<FindingsFilters> }
// what broke first (DESIGN.md): overdue, then the priority ramp, then what was accepted rather than fixed
const SERIES: Series[] = [
  { key: "overdue", label: "Overdue", value: (d) => d.overdue, tone: "text-now-fg", filter: { overdue: true } },
  { key: "fix-now", label: "Fix now", value: (d) => d.open["fix-now"], tone: "text-now-fg", mark: "size-2 bg-now-fg", filter: { priority: ["fix-now"] } },
  { key: "next", label: "Next", value: (d) => d.open.next, tone: "text-ink", mark: "size-2 bg-ink", filter: { priority: ["next"] } },
  { key: "planned", label: "Routine", value: (d) => d.open.planned, tone: "text-ink", mark: "size-2 border-[1.5px] border-ink", filter: { priority: ["planned"] } },
  { key: "low", label: "Low", value: (d) => d.open.low, tone: "text-muted", filter: { priority: ["low"] } },
  { key: "accepted", label: "Accepted risk", value: (d) => d.accepted, tone: "text-muted", filter: { status: "accepted" } },
];
const findingsLink = (filter: Partial<FindingsFilters>) => filtersToSearch({ ...parseFilters({}), ...filter });

/** Progress over time (DESIGN.md "Read" surface): one answer, small multiples, the weekly flow, and who is behind. */
export function ProgressPage() {
  useTitle("Progress");
  const sp = useSearch({ strict: false }) as { days?: string };
  const days = (PROGRESS_RANGES as readonly number[]).includes(Number(sp.days)) ? Number(sp.days) : 90;
  const navigate = useNavigate();
  const q = useQuery({ ...progressQ(days), placeholderData: (prev) => prev });
  return (
    <div className="flex flex-col gap-6">
      <header className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-3">
        <h1 className="text-3xl font-semibold">Progress</h1>
        <div className="flex flex-wrap items-center gap-2">
          <div role="group" aria-label="Range" className="flex border border-line-strong bg-surface p-0.5">
            {PROGRESS_RANGES.map((r) => (
              <button key={r} aria-pressed={days === r} onClick={() => void navigate({ to: "/progress", search: { days: r === 90 ? undefined : String(r) }, replace: true })}
                className={clsx("min-h-[44px] cursor-pointer px-3 text-sm md:min-h-8", days === r ? "bg-ink font-medium text-accent-ink" : "text-muted hover:text-ink")}>
                {r === 365 ? "1 year" : `${r} days`}
              </button>
            ))}
          </div>
        </div>
      </header>
      {q.isPending ? <Loading className="h-40" rows={4} label="Rebuilding progress from the ledger…" />
        : q.error ? <ErrorState error={q.error} retry={() => q.refetch()} />
        : q.data.basis.findings === 0 ? (
          <EmptyState title="Nothing to chart yet" action={<Link to="/add" className={clsx(btnQuiet, "no-underline")}>Add a machine</Link>}>
            Progress fills in as machines report and their findings open and close.
          </EmptyState>
        ) : <ProgressView p={q.data} days={days} updating={q.isPlaceholderData} />}
    </div>
  );
}

function ProgressView({ p, days, updating }: { p: Progress; days: number; updating: boolean }) {
  const [lead, pace] = progressSentences(p);
  const left = p.basis.no_ledger_record + p.basis.mismatched;
  return (
    <div className={clsx("flex flex-col gap-8 transition-opacity", updating && "opacity-60")} aria-busy={updating}>
      <div className="-mt-3 flex flex-col gap-1">
        <p className="max-w-[70ch] text-lg">{lead}</p>
        {pace && <p className="max-w-[70ch] text-muted">{pace}</p>}
      </div>
      <Multiples days={p.days} />
      <Flow weeks={p.weeks} />
      <Owners owners={p.owners} totals={p.totals} days={days} />
      <section aria-labelledby="progress-export" className="flex flex-col gap-3">
        <h2 id="progress-export" className="sr-only">Download and basis</h2>
        {p.basis.problems.length > 0 && (
          <p className="flex max-w-prose items-start gap-2 bg-now-bg px-3 py-2 text-sm text-now-fg">
            <TriangleAlert className="mt-0.5 size-4 shrink-0" aria-hidden />
            <span><strong className="font-semibold">The evidence ledger failed its integrity check</strong>, so these numbers may have been changed in the database and can't be trusted. <Link to="/evidence" className="font-medium underline">See Evidence</Link></span>
          </p>
        )}
        <div className="flex flex-wrap gap-2">
          <a className={btnQuiet} href={`/api/progress.csv?days=${days}`} download><Download className="size-4" aria-hidden />Daily counts (CSV)</a>
          <a className={btnQuiet} href={`/api/progress.csv?days=${days}&table=owners`} download><Download className="size-4" aria-hidden />Owners (CSV)</a>
        </div>
        <HowJudged lead={<>Rebuilt from {plural(p.basis.entries, "ledger entry", "ledger entries")} up to entry {n(p.basis.head_seq)}{" "}
          (<span className="font-mono" title={p.basis.head_hash}>{p.basis.head_hash.slice(0, 10)}</span>){p.basis.problems.length ? "." : ", the record your evidence packs are signed from."}
          {left > 0 && <> {plural(left, "finding")} {left === 1 ? "isn't" : "aren't"} charted.</>}</>}>
          <p>Each finding counts at its current priority and is overdue once it has been open longer than the deadline in force when it was detected, as the evidence pack judges it. Accepted findings aren't open: they're shown on their own.</p>
          <p>A past day counts what was open at its end (midnight UTC); today counts what is open now, which is what Findings shows. Findings on deleted assets aren't counted, as in the evidence pack.</p>
          <p>Resolved on time and mean days to resolve cover findings resolved in the range and still resolved now, the evidence pack's rule for a period.</p>
          {p.basis.no_ledger_record > 0 && <p>{plural(p.basis.no_ledger_record, "finding")} {p.basis.no_ledger_record === 1 ? "has" : "have"} no ledger record (stored before the ledger began), so {p.basis.no_ledger_record === 1 ? "it isn't" : "they aren't"} charted.</p>}
          {p.basis.mismatched > 0 && <p>{plural(p.basis.mismatched, "finding")} {p.basis.mismatched === 1 ? "has" : "have"} a ledger history that disagrees with {p.basis.mismatched === 1 ? "its" : "their"} current state, so {p.basis.mismatched === 1 ? "it isn't" : "they aren't"} charted. Check the ledger's chain on Evidence.</p>}
        </HowJudged>
      </section>
    </div>
  );
}

/** Step a shared day index with the arrow keys, as the pointer does: Home and End jump, Escape lets go. */
function stepper(count: number, at: number | null, set: (i: number | null) => void) {
  return (e: KeyboardEvent) => {
    const i = at ?? count - 1;
    const next = { ArrowLeft: i - 1, ArrowRight: i + 1, Home: 0, End: count - 1, PageUp: i - 7, PageDown: i + 7 }[e.key];
    if (e.key === "Escape") set(null);
    else if (next !== undefined) { e.preventDefault(); set(Math.min(count - 1, Math.max(0, next))); }
  };
}
const pointAt = (e: PointerEvent<Element>, count: number) => {
  const r = e.currentTarget.getBoundingClientRect();
  return Math.min(count - 1, Math.max(0, Math.round(((e.clientX - r.left) / Math.max(1, r.width)) * (count - 1))));
};

/** One small chart per series, each from zero on its own scale, read together: one crosshair moves them all. */
function Multiples({ days }: { days: ProgressDay[] }) {
  const [at, setAt] = useState<number | null>(null);
  const i = at ?? days.length - 1;
  const day = days[i]!;
  return (
    <section aria-labelledby="over-time" className="flex flex-col gap-3">
      <div className="flex flex-wrap items-baseline justify-between gap-x-4">
        <h2 id="over-time" className="text-lg font-semibold">Open findings, day by day</h2>
        <p className="num text-sm text-muted" aria-live="polite">{at === null ? `Today, ${dayLabel(day.date)}` : dayLabel(day.date)}</p>
      </div>
      <div role="group" tabIndex={0} aria-label={`Open findings by day, ${dayLabel(days[0]!.date)} to today. Left and right arrows step through the days.`}
        onKeyDown={stepper(days.length, at, setAt)} onBlur={() => setAt(null)} className="outline-offset-4">
        <ul className="grid grid-cols-2 gap-2 lg:grid-cols-3">
          {SERIES.map((s) => <Panel key={s.key} s={s} days={days} at={at} onPoint={setAt} />)}
        </ul>
      </div>
      <p className="text-xs text-muted">Each line runs from {dayLabel(days[0]!.date)} on the left to today on the right, in UTC days, on its own scale from zero.</p>
      <details className="text-sm">
        <summary className="tap flex w-fit cursor-pointer items-center md:min-h-0">Show these numbers as a table</summary>
        <div className="mt-2 max-h-96 overflow-auto border border-line bg-surface">
          <table className="num w-full text-right text-sm">
            <caption className="sr-only">Open findings by day, newest first</caption>
            <thead className="sticky top-0 bg-surface text-xs text-muted"><tr><th scope="col" className="px-3 py-2 text-left font-medium">Day</th>
              {SERIES.map((s) => <th key={s.key} scope="col" className="px-3 py-2 font-medium">{s.label}</th>)}</tr></thead>
            <tbody className="divide-y divide-line">
              {[...days].reverse().map((d) => <tr key={d.date}><th scope="row" className="px-3 py-1.5 text-left font-normal">{dayLabel(d.date)}</th>
                {SERIES.map((s) => <td key={s.key} className="px-3 py-1.5">{n(s.value(d))}</td>)}</tr>)}
            </tbody>
          </table>
        </div>
      </details>
    </section>
  );
}

const W = 300, H = 64;
function Panel({ s, days, at, onPoint }: { s: Series; days: ProgressDay[]; at: number | null; onPoint: (i: number | null) => void }) {
  const vals = useMemo(() => days.map(s.value), [days, s]);
  const max = Math.max(1, ...vals);
  const x = (i: number) => (vals.length > 1 ? (i / (vals.length - 1)) * W : W);
  const y = (v: number) => H - 1 - (v / max) * (H - 4);  // the 2px line never clips at the top or the baseline
  const line = vals.map((v, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join("");
  const i = at ?? vals.length - 1;
  const change = vals[vals.length - 1]! - vals[0]!;
  const since = `since ${dayLabel(days[0]!.date)}`;
  return (
    <li className="flex min-w-0 flex-col border border-line bg-surface px-3 pb-3 pt-2.5">
      <Link to="/findings" search={findingsLink(s.filter)} className="tap flex w-fit items-center gap-1.5 text-sm font-medium text-ink underline decoration-line-strong underline-offset-4 hover:decoration-ink">
        {s.mark && <span aria-hidden className={s.mark} />}{s.label}
      </Link>
      <p className="mt-1 text-2xl font-semibold">{n(vals[i]!)}</p>
      <p className="text-xs text-muted">{at !== null ? dayLabel(days[i]!.date) : change === 0 ? `no change ${since}` : `${change < 0 ? "down" : "up"} ${n(Math.abs(change))} ${since}`}</p>
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" aria-hidden className={clsx("mt-2 h-16 w-full touch-none", s.tone)}
        onPointerMove={(e) => onPoint(pointAt(e, vals.length))} onPointerLeave={() => onPoint(null)}>
        <line x1={0} x2={W} y1={H - 0.5} y2={H - 0.5} stroke="var(--line)" strokeWidth={1} vectorEffect="non-scaling-stroke" />
        <path d={`${line}L${W},${H}L0,${H}Z`} fill="currentColor" opacity={0.1} />
        <path d={line} fill="none" stroke="currentColor" strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" vectorEffect="non-scaling-stroke" />
        {at !== null && <line x1={x(i)} x2={x(i)} y1={0} y2={H} stroke="var(--line-strong)" strokeWidth={1} vectorEffect="non-scaling-stroke" />}
      </svg>
    </li>
  );
}

/** Opened and resolved per week, side by side: are fixes keeping up with what's found? */
function Flow({ weeks }: { weeks: Progress["weeks"] }) {
  const [at, setAt] = useState<number | null>(null);
  const max = Math.max(1, ...weeks.flatMap((w) => [w.opened, w.resolved]));
  const top = niceCeil(max);
  const opened = weeks.reduce((t, w) => t + w.opened, 0), resolved = weeks.reduce((t, w) => t + w.resolved, 0);
  const w = at === null ? null : weeks[at]!;
  return (
    <section aria-labelledby="flow" className="flex flex-col gap-3">
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <h2 id="flow" className="text-lg font-semibold">Found and fixed, week by week</h2>
        <p className="num text-sm text-muted" aria-live="polite">
          {w ? `Week of ${dayLabel(w.start)}${w.partial ? " (so far)" : ""}: ${n(w.opened)} opened, ${n(w.resolved)} resolved`
            : `${plural(weeks.length, "week")}: ${n(opened)} opened, ${n(resolved)} resolved`}
        </p>
      </div>
      <div className="flex items-center gap-4 text-xs text-muted">
        <span className="flex items-center gap-1.5"><span aria-hidden className="size-2.5 bg-line-strong" />Opened (found or back again)</span>
        <span className="flex items-center gap-1.5"><span aria-hidden className="size-2.5 bg-ink" />Resolved (proven gone)</span>
      </div>
      <div className="flex gap-2">
        <div aria-hidden className="num flex h-36 flex-col justify-between text-right text-xs text-muted"><span>{n(top)}</span>{Number.isInteger(top / 2) && <span>{n(top / 2)}</span>}<span>0</span></div>
        <div role="group" tabIndex={0} aria-label={`Findings opened and resolved each week, ${plural(weeks.length, "week")}. Left and right arrows step through the weeks.`}
          onKeyDown={stepper(weeks.length, at, setAt)} onBlur={() => setAt(null)}
          onPointerMove={(e) => setAt(pointAt(e, weeks.length))} onPointerLeave={() => setAt(null)}
          className="relative flex h-36 min-w-0 flex-1 touch-none items-end gap-px border-b border-line outline-offset-4 [background:linear-gradient(var(--line),var(--line))_0_0/100%_1px_no-repeat]">
          {weeks.map((wk, k) => (
            <div key={wk.start} className={clsx("flex h-full min-w-0 flex-1 items-end justify-center gap-[2px]", at === k && "bg-sunken")}>
              <span className="w-full max-w-3 bg-line-strong" style={{ height: `${(wk.opened / top) * 100}%` }} />
              <span className="w-full max-w-3 bg-ink" style={{ height: `${(wk.resolved / top) * 100}%` }} />
            </div>
          ))}
        </div>
      </div>
      <p className="ml-8 flex justify-between text-xs text-muted" aria-hidden><span>Week of {dayLabel(weeks[0]!.start)}</span><span>This week</span></p>
      <details className="text-sm">
        <summary className="tap flex w-fit cursor-pointer items-center md:min-h-0">Show these numbers as a table</summary>
        <div className="mt-2 max-h-96 overflow-auto border border-line bg-surface">
          <table className="num w-full text-right text-sm">
            <caption className="sr-only">Findings opened and resolved each week, newest first</caption>
            <thead className="sticky top-0 bg-surface text-xs text-muted"><tr><th scope="col" className="px-3 py-2 text-left font-medium">Week of</th>
              <th scope="col" className="px-3 py-2 font-medium">Opened</th><th scope="col" className="px-3 py-2 font-medium">Resolved</th></tr></thead>
            <tbody className="divide-y divide-line">
              {[...weeks].reverse().map((wk) => <tr key={wk.start}><th scope="row" className="px-3 py-1.5 text-left font-normal">{dayLabel(wk.start)}{wk.partial && " (so far)"}</th>
                <td className="px-3 py-1.5">{n(wk.opened)}</td><td className="px-3 py-1.5">{n(wk.resolved)}</td></tr>)}
            </tbody>
          </table>
        </div>
      </details>
    </section>
  );
}

/** The smallest of 1, 2 or 5 times a power of ten at or above v, so the axis reads in round numbers. */
export function niceCeil(v: number): number {
  const p = 10 ** Math.floor(Math.log10(Math.max(1, v)));
  return [1, 2, 5, 10].map((m) => m * p).find((c) => c >= v) ?? 10 * p;
}

const days1 = (d: number | null) => (d === null ? "" : d < 1 ? "under a day" : `${d.toLocaleString("en")} days`);

/** Who is behind: each owner's overdue, fix-now and open findings now, and how they did in the range. */
function Owners({ owners, totals, days }: { owners: ProgressOwner[]; totals: Progress["totals"]; days: number }) {
  const named = owners.some((o) => o.owner);
  const cell = "px-3 py-2 max-md:flex max-md:justify-between max-md:gap-4 max-md:px-0 max-md:py-0.5 max-md:before:text-muted max-md:before:content-[attr(data-label)]";
  const row = (o: Omit<ProgressOwner, "owner">, name: ReactNode, key: string, foot?: boolean) => (
    <tr key={key} className={clsx("max-md:block max-md:border-b max-md:border-line max-md:p-3", foot && "font-semibold")}>
      <th scope="row" className="px-3 py-2 text-left font-medium max-md:block max-md:px-0">{name}</th>
      <td data-label="Overdue" className={cell}><span>{o.overdue > 0 && <span aria-hidden className="mr-1.5 inline-block size-2 bg-now-fg" />}{n(o.overdue)}</span></td>
      <td data-label="Fix now" className={cell}>{n(o.fix_now)}</td>
      <td data-label="Open" className={cell}>{n(o.open)}</td>
      <td data-label={`Change in ${days} days`} className={cell}>{signed(o.open - o.open_at_start)}</td>
      <td data-label="Resolved on time" className={cell}>{o.resolved ? `${n(o.resolved_on_time)} of ${n(o.resolved)}` : <span className="text-muted">none resolved</span>}</td>
      <td data-label="Mean time to resolve" className={cell}>{days1(o.mean_days_to_resolve) || <span className="text-muted">n/a</span>}</td>
    </tr>
  );
  return (
    <section aria-labelledby="owners" className="flex flex-col gap-3">
      <div>
        <h2 id="owners" className="text-lg font-semibold">By owner</h2>
        <p className="mt-1 text-sm text-muted">{named ? "Most overdue first. An owner's name opens their findings." : <>No asset has an owner yet. Set one in <Link to="/assets" className="font-medium text-ink underline">Assets</Link>, or on the install command when you add machines, to see which team is behind.</>}</p>
      </div>
      <div className="border border-line bg-surface max-md:border-0 max-md:bg-transparent">
        <table className="num w-full text-right text-sm max-md:block max-md:text-left">
          <thead className="text-xs text-muted max-md:sr-only"><tr className="border-b border-line">
            <th scope="col" className="px-3 py-2 text-left font-medium">Owner</th><th scope="col" className="px-3 py-2 font-medium">Overdue</th>
            <th scope="col" className="px-3 py-2 font-medium">Fix now</th><th scope="col" className="px-3 py-2 font-medium">Open</th>
            <th scope="col" className="px-3 py-2 font-medium">Change in {days} days</th><th scope="col" className="px-3 py-2 font-medium">Resolved on time</th>
            <th scope="col" className="px-3 py-2 font-medium">Mean time to resolve</th></tr></thead>
          <tbody className="divide-y divide-line max-md:block max-md:divide-y-0 max-md:border max-md:border-line max-md:bg-surface">
            {owners.map((o) => row(o, <Link to="/findings" search={findingsLink(o.owner ? { owner: o.owner } : { noOwner: true })}
              className="break-words underline decoration-line-strong underline-offset-4 hover:decoration-ink">{o.owner ?? "No owner"}</Link>, o.owner ?? "\u0000"))}
          </tbody>
          {owners.length > 1 && <tfoot className="max-md:mt-2 max-md:block max-md:border max-md:border-line max-md:bg-surface">{row(totals, "Everyone", "all", true)}</tfoot>}
        </table>
      </div>
    </section>
  );
}
