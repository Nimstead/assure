import { useNavigate, useSearch } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { CircleCheck, CircleMinus, CircleX, Download, ShieldAlert, ShieldCheck } from "lucide-react";
import clsx from "clsx";
import { api, humaniseKind, parseUtc, relativeTime, useTitle, type ControlStatus, type EvidenceReport, type LedgerEntry } from "./lib";
import { btnPrimary, CopyBlock, ErrorState, input, Loading } from "./ui";

const PERIODS = [30, 90, 365];
const STATUS: Record<ControlStatus, { label: string; className: string; Icon: typeof CircleCheck }> = {
  met: { label: "Met", className: "border-ink text-ink", Icon: CircleCheck },
  not_met: { label: "Not met", className: "border-now-fg bg-now-bg text-now-fg", Icon: CircleX },
  // Nothing to assess is said plainly, never shown as a pass (DECISIONS 45).
  no_activity: { label: "No activity in period", className: "border-line-strong text-muted", Icon: CircleMinus },
};
const date = (s: string) => parseUtc(s).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });

/** `period` comes from the URL (?period=30), so a link or reload keeps it. */
export function EvidencePage() {
  useTitle("Evidence");
  const { period } = useSearch({ strict: false }) as { period?: string };
  const navigate = useNavigate();
  const days = PERIODS.includes(Number(period)) ? Number(period) : 90;
  const setDays = (d: number) => navigate({ to: "/evidence", search: d === 90 ? {} : { period: String(d) }, replace: true });
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
          <select className={clsx(input, "w-auto md:min-h-9")} value={days} onChange={(e) => setDays(Number(e.target.value))}>
            {PERIODS.map((d) => <option key={d} value={d}>Last {d} days</option>)}
          </select>
        </label>
      </header>

      {report.isPending ? <Loading className="h-28" rows={3} label="Loading control status…" />
        : report.error ? <ErrorState error={report.error} retry={() => report.refetch()} />
        : <ReportView r={report.data} days={days} />}

      <section aria-labelledby="ledger">
        <h2 id="ledger" className="mb-3 text-lg font-semibold">Ledger</h2>
        {ledger.isPending ? <Loading className="h-40" label="Loading ledger…" /> : ledger.error ? <ErrorState error={ledger.error} retry={() => ledger.refetch()} /> : <LedgerView problems={ledger.data.problems} entries={ledger.data.entries} />}
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
  const counts = r.controls.reduce((n, c) => ({ ...n, [c.status]: (n[c.status] ?? 0) + 1 }), {} as Partial<Record<ControlStatus, number>>);
  return (
    <>
      <p className="-mt-4 text-sm text-muted">
        {date(r.period.from)} to {date(r.period.to)} · as of <time dateTime={parseUtc(r.period.to).toISOString()}>{parseUtc(r.period.to).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })}</time>
      </p>
      <dl className="grid grid-cols-1 gap-2 sm:grid-cols-3">
        {stats.map(([k, v]) => (
          <div key={k} className="border border-line bg-surface px-4 py-3">
            <dt className="text-sm text-muted">{k}</dt><dd className="num mt-0.5 text-2xl font-semibold">{v}</dd>
          </div>
        ))}
      </dl>

      <section aria-labelledby="controls">
        <h2 id="controls" className="text-lg font-semibold">Control status</h2>
        <p className="mb-3 mt-1 text-sm text-muted">
          {counts.met ?? 0} met · {counts.not_met ?? 0} not met · {counts.no_activity ?? 0} with no activity in this period
        </p>
        <ul className="grid gap-2 md:grid-cols-2">
          {r.controls.map((c) => {
            const st = STATUS[c.status] ?? STATUS.not_met;
            return (
              <li key={c.framework + c.control} className="flex flex-col border border-line bg-surface p-4">
                <p className="text-sm text-muted">{c.framework}</p>
                <h3 className="font-semibold">{c.control}</h3>
                <p className="mt-1 text-sm">{c.requirement}</p>
                <p className={clsx("mt-3 inline-flex w-fit items-center gap-1.5 border px-2 py-0.5 text-xs font-medium", st.className)}>
                  <st.Icon className="size-3.5" aria-hidden />{st.label}
                </p>
                <p className="mt-2 font-mono text-[13px] text-ink">{c.evidence}</p>
              </li>
            );
          })}
        </ul>
      </section>

      <section className="flex flex-col items-start gap-2 border border-line bg-surface p-4">
        <h2 className="text-lg font-semibold">Signed evidence pack</h2>
        <p className="max-w-prose text-sm text-muted">Auditors verify this pack offline with the verifier and fingerprint below, which you give them separately from the pack. No access to Nimstead needed.</p>
        <a className={clsx(btnPrimary, "no-underline")} href={`/api/evidence/pack?days=${days}`} download><Download className="size-4" aria-hidden />Download signed evidence pack (last {days} days)</a>
        <SigningKey />
      </section>
    </>
  );
}

function SigningKey() {
  const q = useQuery({ queryKey: ["public-key"], queryFn: () => api<{ pem: string; fingerprint_sha256: string; verifier_sha256: string }>("/api/evidence/public-key"), staleTime: Infinity });
  if (!q.data) return null;
  return (
    <div className="mt-2 w-full max-w-2xl">
      <CopyBlock label="Signing key fingerprint (SHA-256)" text={q.data.fingerprint_sha256} />
      <CopyBlock label="Verifier script SHA-256" text={q.data.verifier_sha256} />
      <p className="mt-2 text-sm text-muted">
        Give auditors these separately from the pack, with the <a className="underline" href="/api/evidence/verify.py" download>verifier script</a>.
        The pack doesn't include a verifier: a script inside it could have been swapped by whoever handed it over.
      </p>
    </div>
  );
}

export function LedgerView({ problems, entries }: { problems: string[]; entries: LedgerEntry[] }) {
  return (
    <div className="flex flex-col gap-3">
      {problems.length === 0 ? (
        <p role="status" className="flex items-center gap-2 border border-line-strong bg-surface px-3 py-2 text-sm font-medium"><ShieldCheck className="size-4" aria-hidden />Chain verified. Every entry links unbroken back to the first.</p>
      ) : (
        <div role="alert" className="bg-now-bg px-3 py-2 text-sm text-now-fg">
          <p className="flex items-center gap-2 font-medium"><ShieldAlert className="size-4" aria-hidden />Ledger problems found. Evidence packs won't be signed until this is resolved.</p>
          <ul className="mt-1 list-disc pl-6">{problems.slice(0, 5).map((p) => <li key={p}>{p}</li>)}</ul>
        </div>
      )}
      {entries.length === 0 ? <p className="text-sm text-muted">Nothing recorded yet.</p> : (
        <ol className="flex flex-col divide-y divide-line overflow-hidden border border-line bg-surface">
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
