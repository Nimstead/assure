import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { CircleAlert, CircleCheck, CircleMinus, CircleX, Download, ShieldAlert, ShieldCheck } from "lucide-react";
import clsx from "clsx";
import { api, assetsQ, filtersToSearch, jobsQ, humaniseKind, parseFilters, parseUtc, plural, relativeTime, summaryQ, useTitle, type ControlStatus, type EvidenceReport, type LedgerEntry } from "./lib";
import { btnPrimary, CopyBlock, ErrorState, input, Loading } from "./ui";

const LEDGER_SHOWN = 50;
/** Below this many fixes in the period, a "Met" timeliness control is said to rest on little evidence. */
const SMALL_SAMPLE = 5;
const LEDGER_GROUPS = [["", "Everything"], ["decisions", "Decisions"], ["fixes", "Fixes"], ["detections", "Detections"], ["access", "Sign-ins and access"]] as const;

/** What a ledger entry is about, from its own data: "CVE-2024-1234 · openssl · web-1" rather than an 8-character id. */
function ledgerSubject(e: LedgerEntry): string {
  const d = e.data ?? {};
  const str = (k: string) => (typeof d[k] === "string" ? (d[k] as string) : "");
  const parts = [str("vuln_id"), str("package") || str("action").split("|")[1] || "", str("host") || str("hostname") || str("name") || str("email"), str("by") && `by ${str("by")}`].filter(Boolean);
  return parts.length ? [...new Set(parts)].join(" · ") : e.subject.slice(0, 8);
}

/** "0.0 days" reads as a bug; under a day is what it means. */
const mttr = (days: number | null) => (days === null ? "n/a" : days < 1 ? "under a day" : `${days} days`);

const PERIODS = [30, 90, 365];
const STATUS: Record<ControlStatus, { label: string; className: string; Icon: typeof CircleCheck }> = {
  met: { label: "Met", className: "border-ink text-ink", Icon: CircleCheck },
  not_met: { label: "Not met", className: "border-now-fg bg-now-bg text-now-fg", Icon: CircleX },
  // Nothing to assess is said plainly, never shown as a pass (DECISIONS 45).
  no_activity: { label: "No activity in period", className: "border-line-strong text-muted", Icon: CircleMinus },
};
// met on the period's own terms, with something that would worry an auditor now: not a clean pass
const EXCEPTED = { label: "Met", className: "border-warn-fg bg-warn-bg text-warn-fg", Icon: CircleAlert };
const date = (s: string) => parseUtc(s).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });

/** `period` comes from the URL (?period=30), so a link or reload keeps it. */
export function EvidencePage() {
  useTitle("Evidence");
  const { period } = useSearch({ strict: false }) as { period?: string };
  const navigate = useNavigate();
  const days = PERIODS.includes(Number(period)) ? Number(period) : 90;
  const setDays = (d: number) => navigate({ to: "/evidence", search: (s: Record<string, unknown>) => ({ ...s, period: d === 90 ? undefined : String(d) }), replace: true, resetScroll: false });
  const report = useQuery({ queryKey: ["evidence-report", days], queryFn: () => api<EvidenceReport>(`/api/evidence/report?days=${days}&summary=true`) });
  const group = (useSearch({ strict: false }) as { show?: string }).show ?? "";
  const setGroup = (g: string) => navigate({ to: "/evidence", search: (s: Record<string, unknown>) => ({ ...s, show: g || undefined }), replace: true, resetScroll: false });
  const ledger = useQuery({ queryKey: ["ledger", group], queryFn: () => api<{ problems: string[]; entries: LedgerEntry[]; total: number }>(`/api/evidence/ledger?limit=${LEDGER_SHOWN}${group ? `&group=${group}` : ""}`),
    placeholderData: (p) => p });

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
        <h2 id="ledger" className="text-lg font-semibold">Ledger</h2>
        {/* say what's shown: the page promises every decision, and the full chain is in the signed pack */}
        <p role="status" className="mb-3 mt-1 text-sm text-muted">
          {ledger.data && ledger.data.total > LEDGER_SHOWN ? `Latest ${LEDGER_SHOWN} of ${ledger.data.total.toLocaleString()} ${group ? "matching " : ""}entries, newest first.` : "Newest first."}
          {report.data && ` The signed pack for the last ${days} days holds all ${report.data.ledger.entries.toLocaleString()} entries of that period, with every checkpoint.`}
        </p>
        <div role="group" aria-label="Show" className="mb-3 inline-flex flex-wrap border border-line-strong bg-surface p-0.5">
          {LEDGER_GROUPS.map(([g, label]) => <button key={g} aria-pressed={group === g} onClick={() => setGroup(g)}
            className={clsx("min-h-[44px] cursor-pointer px-3 text-sm md:min-h-8", group === g ? "bg-ink font-medium text-accent-ink" : "text-muted hover:text-ink")}>{label}</button>)}
        </div>
        {ledger.isPending ? <Loading className="h-40" label="Loading ledger…" /> : ledger.error ? <ErrorState error={ledger.error} retry={() => ledger.refetch()} /> : <LedgerView problems={ledger.data.problems} entries={ledger.data.entries} />}
      </section>
    </div>
  );
}

function ReportView({ r, days }: { r: EvidenceReport; days: number }) {
  const m = r.metrics;
  const stats: [string, string][] = [
    ["Mean time to remediate", mttr(m.mttr_days)],
    ["Resolved within SLA", `${m.resolved_within_sla} of ${m.resolved}`],
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
        {/* the number an auditor asks about leads to the findings behind it */}
        <div className="border border-line bg-surface px-4 py-3">
          <dt className="text-sm text-muted">Overdue and still open</dt>
          <dd className="num mt-0.5 flex items-baseline justify-between gap-2 text-2xl font-semibold">
            <span className={m.overdue_open > 0 ? "text-now-fg" : undefined}>{m.overdue_open}</span>
            {m.overdue_open > 0 && (
              <Link to="/findings" search={filtersToSearch({ ...parseFilters({}), overdue: true, fixable: false })}
                className="inline-flex tap items-center text-sm font-medium text-accent underline">
                View {plural(m.overdue_open, "finding")}
              </Link>
            )}
          </dd>
        </div>
      </dl>

      <section aria-labelledby="controls">
        <h2 id="controls" className="text-lg font-semibold">Control status</h2>
        <p className="mb-3 mt-1 text-sm text-muted">
          {r.controls.filter((c) => c.status === "met" && !c.exceptions).length} met · {r.controls.filter((c) => c.status === "met" && c.exceptions).length} met with exceptions · {counts.not_met ?? 0} not met · {counts.no_activity ?? 0} with no activity in this period
        </p>
        <Exceptions resolved={m.resolved} />
        <ul className="grid gap-2 md:grid-cols-2">
          {r.controls.map((c) => {
            const st = c.status === "met" && c.exceptions ? EXCEPTED : STATUS[c.status] ?? STATUS.not_met;
            return (
              <li key={c.framework + c.control} className="flex flex-col border border-line bg-surface p-4">
                <p className="text-sm text-muted">{c.framework}</p>
                <h3 className="font-semibold">{c.control}</h3>
                <p className="mt-1 text-sm">{c.requirement}</p>
                <p className={clsx("mt-3 inline-flex w-fit items-center gap-1.5 border px-2 py-0.5 text-xs font-medium", st.className)}>
                  <st.Icon className="size-3.5" aria-hidden />{st.label}{c.status === "met" && !!c.exceptions && `, with ${plural(c.exceptions, "exception")}`}
                </p>
                <p className="mt-2 text-sm text-ink">{c.evidence}</p>
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

/** What a "Met" doesn't say: how little it may rest on, and what is wrong right now. */
function Exceptions({ resolved }: { resolved: number }) {
  const s = useQuery(summaryQ).data;
  const now = s?.open_by_priority["fix-now"] ?? 0;
  const quiet = s?.hosts_not_reporting ?? 0;
  if (resolved >= SMALL_SAMPLE && !now && !quiet) return null;
  return (
    <div className="mb-3 flex flex-col gap-1 border border-line-strong bg-surface px-3 py-2 text-sm">
      {resolved < SMALL_SAMPLE && <p>Timeliness controls here rest on {plural(resolved, "fix", "fixes")} in this period, too few to show a trend. Read “Met” as “nothing late so far”.</p>}
      {(now > 0 || quiet > 0) && (
        <p>Right now:{" "}
          {now > 0 && <Link to="/findings" search={filtersToSearch({ ...parseFilters({}), priority: ["fix-now"], fixable: false })} className="font-medium underline">{plural(now, "Fix now finding")} open</Link>}
          {now > 0 && quiet > 0 && ", "}
          {quiet > 0 && <Link to="/assets" className="font-medium underline">{plural(quiet, "machine")} not reporting</Link>}.
          {" "}Controls are judged on the period, so these may not show above yet.
        </p>
      )}
    </div>
  );
}

function SigningKey() {
  const q = useQuery({ queryKey: ["public-key"], queryFn: () => api<{ pem: string; fingerprint_sha256: string; verifier_sha256: string }>("/api/evidence/public-key"), staleTime: Infinity });
  if (q.isPending) return <div className="mt-2 w-full max-w-2xl"><Loading className="h-12" rows={2} label="Loading the signing key fingerprint…" /></div>;
  if (q.error) return <div className="mt-2 w-full max-w-2xl"><ErrorState error={q.error} retry={() => q.refetch()} /></div>;
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

const FAILED_KIND = /rolled_back|failed|aborted|not_fixed|revoked|guessing|break_glass/;

function LedgerView({ problems, entries }: { problems: string[]; entries: LedgerEntry[] }) {
  // entries name their subject by id (a job, a machine): say which machine
  const jobHost = new Map([...(useQuery(jobsQ).data ?? []).map((j) => [j.id, j.hostname] as const), ...(useQuery(assetsQ).data ?? []).map((a) => [a.id, a.hostname] as const)]);
  return (
    <div className="flex flex-col gap-3">
      {problems.length === 0 ? (
        <p role="status" className="flex items-center gap-2 border border-line-strong bg-surface px-3 py-2 text-sm font-medium"><ShieldCheck className="size-4" aria-hidden />Chain verified. Every entry links unbroken back to the first.</p>
      ) : (
        // stored state, shown plainly rather than announced on every visit (as settings' last update is)
        <div className="bg-now-bg px-3 py-2 text-sm text-now-fg">
          <p className="flex items-center gap-2 font-medium"><ShieldAlert className="size-4" aria-hidden />Ledger problems found. Evidence packs won't be signed until this is resolved.</p>
          <ul className="mt-1 list-disc pl-6">{problems.slice(0, 5).map((p) => <li key={p}>{p}</li>)}</ul>
        </div>
      )}
      {entries.length === 0 ? <p className="text-sm text-muted">Nothing recorded yet.</p> : (
        <ol className="flex flex-col divide-y divide-line overflow-hidden border border-line bg-surface">
          {entries.map((e) => (
            <li key={e.seq} className={clsx("flex flex-wrap items-baseline gap-x-4 gap-y-0.5 px-4 py-2.5 text-sm", FAILED_KIND.test(e.kind) && "bg-now-bg")}>
              <span className="min-w-0 flex-1 basis-48 font-medium">{e.kind.startsWith("remediation_")
                ? <Link to="/remediation" hash={`job-${e.subject}`} className="text-ink underline decoration-line-strong hover:decoration-ink">{humaniseKind(e.kind)}</Link>
                : humaniseKind(e.kind)}</span>
              <span className="min-w-0 break-all text-sm text-muted" title={e.subject}><span className="sr-only">About </span>{[jobHost.get(e.subject), ledgerSubject(e)].filter(Boolean).join(" · ")}</span>
              <code className="font-mono text-xs text-muted" title={e.hash}><span className="sr-only">Hash </span>{e.hash.slice(0, 10)}</code>
              <time className="text-right text-muted" dateTime={parseUtc(e.ts).toISOString()} title={relativeTime(e.ts)}>{parseUtc(e.ts).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })}</time>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}
