import { Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { ArrowRight, CheckCircle2, TriangleAlert } from "lucide-react";
import { filtersToSearch, parseFilters, plural, PRIORITIES, PRIORITY_LABEL, priorityOf, summaryQ, useTitle, type Action } from "./lib";
import { Onboarding } from "./onboarding";
import { PlanFixButton, StatusPill } from "./remediation";
import { ErrorState, KevBadge, PriorityPill, Skeleton } from "./ui";
import clsx from "clsx";

const TILE: Record<string, string> = { "fix-now": "text-now-fg", next: "text-next-fg", planned: "text-planned-fg", low: "text-low-fg" };

export function Home() {
  const q = useQuery(summaryQ);
  useTitle(q.data?.assets === 0 ? "Add a machine" : "Fix first");

  if (q.isPending) return <HomeSkeleton />;
  if (q.error) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  const s = q.data;
  if (s.assets === 0) return <Onboarding />;

  const total = PRIORITIES.reduce((n, p) => n + (s.open_by_priority[p] ?? 0), 0);
  return (
    <div className="flex flex-col gap-8">
      <header>
        <h1 className="text-3xl font-semibold">Fix first</h1>
        <p className="mt-1 text-muted">
          {total === 0
            ? `No open findings across ${plural(s.assets, "machine")}.`
            : `${plural(total, "open finding")} across ${plural(s.assets, "machine")}. These upgrades clear the most risk.`}
        </p>
      </header>

      {s.attention.length > 0 && (
        <section aria-labelledby="attention" className="rounded-lg border border-line-strong bg-sunken p-4">
          <h2 id="attention" className="flex items-center gap-2 font-semibold"><TriangleAlert className="size-4" aria-hidden />{plural(s.attention.length, "fix", "fixes")} need{s.attention.length === 1 ? "s" : ""} a look</h2>
          <ul className="mt-2 flex flex-col gap-1.5 text-sm">
            {s.attention.slice(0, 5).map((j) => (
              <li key={j.id} className="flex flex-wrap items-center gap-x-2 gap-y-1"><StatusPill status={j.status} /><span>{j.summary} on {j.hostname}</span></li>
            ))}
          </ul>
          <Link to="/remediation" className="mt-3 inline-flex items-center gap-1.5 text-sm font-medium text-accent underline">Review in Remediation <ArrowRight className="size-4" aria-hidden /></Link>
        </section>
      )}

      <ul className="grid grid-cols-2 gap-2 sm:grid-cols-4" aria-label="Open findings by priority">
        {PRIORITIES.map((p) => (
          <li key={p}>
            <Link
              to="/findings"
              search={filtersToSearch({ ...parseFilters({}), priority: [p], fixable: false })}
              className="flex flex-col rounded-lg border border-line bg-surface px-3.5 py-2.5 hover:border-line-strong"
            >
              <span className={clsx("num text-2xl font-semibold", TILE[p])}>{s.open_by_priority[p] ?? 0}</span>
              <span className="text-sm text-muted">{PRIORITY_LABEL[p]}</span>
            </Link>
          </li>
        ))}
      </ul>

      <section aria-labelledby="actions">
        <h2 id="actions" className="mb-3 text-lg font-semibold">Recommended upgrades</h2>
        {s.top_actions.length === 0 ? (
          <div className="flex items-start gap-3 rounded-lg border border-dashed border-line-strong p-5">
            <CheckCircle2 className="mt-0.5 size-5 shrink-0 text-accent" aria-hidden />
            <p className="text-sm text-muted">
              {total === 0 ? "Everything reported so far is clean. New findings will show up here." : "Nothing here can be fixed by an upgrade yet. Review the findings with no fix to mitigate or accept them."}
            </p>
          </div>
        ) : (
          <ol className="flex flex-col gap-2">
            {s.top_actions.map((a) => <ActionCard key={a.ecosystem + a.package} a={a} />)}
          </ol>
        )}
      </section>
    </div>
  );
}

function ActionCard({ a }: { a: Action }) {
  return (
    <li className="flex flex-col gap-3 rounded-lg border border-line bg-surface p-4 sm:flex-row sm:items-center sm:justify-between">
      <div className="min-w-0">
        <p className="text-base">
          Upgrade <strong className="font-semibold">{a.package}</strong> to{" "}
          <code className="break-all bg-sunken px-1.5 py-0.5 font-mono text-[13px]">{a.fixed_version}</code>
        </p>
        <p className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1.5 text-sm text-muted">
          <PriorityPill priority={priorityOf(a.max_score, a.kev)} />
          {a.kev && <KevBadge />}
          <span>
            Fixes {plural(a.vulns.length, "vulnerability", "vulnerabilities")} on {plural(a.hosts.length, "host")}
            <span className="hidden md:inline">: {a.hosts.slice(0, 3).join(", ")}{a.hosts.length > 3 && ` +${a.hosts.length - 3}`}</span>
          </span>
        </p>
      </div>
      <div className="flex shrink-0 flex-wrap items-start gap-x-4 gap-y-2">
        <PlanFixButton ecosystem={a.ecosystem} pkg={a.package} hosts={a.hosts} />
        <Link
          to="/findings"
          search={filtersToSearch({ ...parseFilters({}), q: a.package })}
          className="inline-flex min-h-9 items-center gap-1.5 text-sm font-medium text-accent underline"
        >
          View findings <ArrowRight className="size-4" aria-hidden />
        </Link>
      </div>
    </li>
  );
}

function HomeSkeleton() {
  return (
    <div className="flex flex-col gap-8" aria-busy="true" aria-label="Loading">
      <Skeleton className="h-16 w-72" />
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">{[0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-16" />)}</div>
      <div className="flex flex-col gap-2">{[0, 1, 2].map((i) => <Skeleton key={i} className="h-20" />)}</div>
    </div>
  );
}
