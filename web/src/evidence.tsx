import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { CircleCheck, CircleX, Download, ShieldAlert, ShieldCheck } from "lucide-react";
import clsx from "clsx";
import { api, humaniseKind, parseUtc, relativeTime, useTitle, type EvidenceReport, type LedgerEntry } from "./lib";
import { btnPrimary, ErrorState, input, Skeleton } from "./ui";

const PERIODS = [30, 90, 365];

export function EvidencePage() {
  useTitle("Evidence");
  const [days, setDays] = useState(90);
  const report = useQuery({ queryKey: ["evidence-report", days], queryFn: () => api<EvidenceReport>(`/api/evidence/report?days=${days}`) });
  const ledger = useQuery({ queryKey: ["ledger"], queryFn: () => api<{ problems: string[]; entries: LedgerEntry[] }>("/api/evidence/ledger?limit=50") });

  return (
    <div className="flex flex-col gap-8">
      <header className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-3xl font-semibold">Evidence</h1>
          <p className="mt-1 max-w-prose text-muted">What you can show an auditor: how each control is doing, and a tamper-evident record of every detection, fix and decision.</p>
        </div>
        <label className="flex items-center gap-2 text-sm">
          <span className="text-muted">Period</span>
          <select className={clsx(input, "min-h-9 w-auto")} value={days} onChange={(e) => setDays(Number(e.target.value))}>
            {PERIODS.map((d) => <option key={d} value={d}>Last {d} days</option>)}
          </select>
        </label>
      </header>

      {report.isPending ? <div className="grid gap-2 sm:grid-cols-2">{[0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-28" />)}</div>
        : report.error ? <ErrorState error={report.error} retry={() => report.refetch()} />
        : <ReportView r={report.data} days={days} />}

      <section aria-labelledby="ledger">
        <h2 id="ledger" className="mb-3 text-lg font-semibold">Ledger</h2>
        {ledger.isPending ? <Skeleton className="h-40" /> : ledger.error ? <ErrorState error={ledger.error} retry={() => ledger.refetch()} /> : <LedgerView problems={ledger.data.problems} entries={ledger.data.entries} />}
      </section>
    </div>
  );
}

function ReportView({ r, days }: { r: EvidenceReport; days: number }) {
  const m = r.metrics;
  const stats: [string, string][] = [
    ["Mean time to remediate", m.mttr_days === null ? "n/a" : `${m.mttr_days} days`],
    ["Resolved within SLA", `${m.resolved_within_sla} of ${m.resolved}`],
    ["Overdue and still open", String(m.overdue_open)],
  ];
  return (
    <>
      <dl className="grid grid-cols-1 gap-2 sm:grid-cols-3">
        {stats.map(([k, v]) => (
          <div key={k} className="rounded-lg border border-line bg-surface px-4 py-3">
            <dt className="text-sm text-muted">{k}</dt><dd className="num mt-0.5 text-2xl font-semibold">{v}</dd>
          </div>
        ))}
      </dl>

      <section aria-labelledby="controls">
        <h2 id="controls" className="mb-3 text-lg font-semibold">Control status</h2>
        <ul className="grid gap-2 md:grid-cols-2">
          {r.controls.map((c) => (
            <li key={c.framework + c.control} className="rounded-lg border border-line bg-surface p-4">
              <p className="text-sm text-muted">{c.framework}</p>
              <h3 className="font-semibold">{c.control}</h3>
              <p className="mt-1 text-sm">{c.requirement}</p>
              <p className={clsx("mt-3 inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium", c.status === "met" ? "bg-accent-soft text-ink" : "bg-now-bg text-now-fg")}>
                {c.status === "met" ? <CircleCheck className="size-3.5" aria-hidden /> : <CircleX className="size-3.5" aria-hidden />}
                {c.status === "met" ? "Met" : "Not met"}
              </p>
              <p className="mt-2 text-sm text-muted">{c.evidence}</p>
            </li>
          ))}
        </ul>
      </section>

      <section className="flex flex-col items-start gap-2 rounded-lg border border-line bg-surface p-4">
        <h2 className="text-lg font-semibold">Signed evidence pack</h2>
        <p className="max-w-prose text-sm text-muted">Auditors can verify this pack offline with the included script. No access to Nimstead needed.</p>
        <a className={clsx(btnPrimary, "no-underline")} href={`/api/evidence/pack?days=${days}`} download><Download className="size-4" aria-hidden />Download signed evidence pack (last {days} days)</a>
      </section>
    </>
  );
}

export function LedgerView({ problems, entries }: { problems: string[]; entries: LedgerEntry[] }) {
  return (
    <div className="flex flex-col gap-3">
      {problems.length === 0 ? (
        <p role="status" className="flex items-center gap-2 rounded-md bg-accent-soft px-3 py-2 text-sm font-medium"><ShieldCheck className="size-4" aria-hidden />Chain verified. Every entry links unbroken back to the first.</p>
      ) : (
        <div role="alert" className="rounded-md bg-now-bg px-3 py-2 text-sm text-now-fg">
          <p className="flex items-center gap-2 font-medium"><ShieldAlert className="size-4" aria-hidden />Ledger problems found. Evidence packs won't be signed until this is resolved.</p>
          <ul className="mt-1 list-disc pl-6">{problems.slice(0, 5).map((p) => <li key={p}>{p}</li>)}</ul>
        </div>
      )}
      {entries.length === 0 ? <p className="text-sm text-muted">Nothing recorded yet.</p> : (
        <ol className="flex flex-col divide-y divide-line overflow-hidden rounded-lg border border-line bg-surface">
          {entries.map((e) => (
            <li key={e.seq} className="flex flex-wrap items-baseline gap-x-4 gap-y-0.5 px-4 py-2.5 text-sm">
              <span className="min-w-0 flex-1 basis-48 font-medium">{humaniseKind(e.kind)}</span>
              <span className="font-mono text-xs text-muted" title={e.subject}><span className="sr-only">Subject </span>{e.subject.slice(0, 8)}</span>
              <code className="font-mono text-xs text-muted" title={e.hash}><span className="sr-only">Hash </span>{e.hash.slice(0, 10)}</code>
              <time className="w-24 text-right text-muted" dateTime={parseUtc(e.ts).toISOString()} title={parseUtc(e.ts).toLocaleString()}>{relativeTime(e.ts)}</time>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}
