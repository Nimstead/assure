import { Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { ArrowRight, CheckCircle2, TriangleAlert } from "lucide-react";
import { dependenciesNeeded, filtersToSearch, jobAnchor, JOB_STATUS_LABEL, parseFilters, plural, PRIORITIES, PRIORITY_LABEL, priorityOf, summaryQ, useTitle, type Action } from "./lib";
import { PlanFixButton } from "./remediation";
import { ErrorState, KevBadge, Loading, PriorityPill, StatusPill } from "./ui";
import clsx from "clsx";
import { lazy, Suspense } from "react";

const Onboarding = lazy(() => import("./onboarding").then((m) => ({ default: m.Onboarding })));

// Only a non-zero "fix now" carries colour; the rest are ink so a count never reads as disabled.
const tile = (p: string, n: number) => (p === "fix-now" && n > 0 ? "text-now-fg" : "text-ink");

export function Home() {
  const q = useQuery(summaryQ);
  useTitle(q.data?.assets === 0 ? "Add a machine" : "Fix first");

  if (q.isPending) return <HomeSkeleton />;
  if (q.error) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  const s = q.data;
  if (s.assets === 0) return <Suspense fallback={<Loading className="h-64" />}><Onboarding /></Suspense>;

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
        <section aria-labelledby="attention" className="border border-line-strong bg-surface p-4">
          <h2 id="attention" className="flex items-center gap-2 font-semibold"><TriangleAlert className="size-4" aria-hidden />{plural(s.attention.length, "fix", "fixes")} need{s.attention.length === 1 ? "s" : ""} a look</h2>
          <ul className="mt-2 flex flex-col gap-1.5 text-sm">
            {s.attention.slice(0, 5).map((j) => (
              <li key={j.id} className="flex flex-wrap items-center gap-x-2 gap-y-1"><StatusPill status={j.status} />
                <Link to="/remediation" hash={jobAnchor(j.id)} className="min-w-0 break-words text-ink underline decoration-line-strong hover:decoration-ink">{j.summary}</Link></li>
            ))}
          </ul>
          <Link to="/remediation" className="mt-1 inline-flex min-h-[44px] items-center gap-1.5 text-sm font-medium text-accent underline md:min-h-0">Review in Remediation <ArrowRight className="size-4" aria-hidden /></Link>
        </section>
      )}

      {(s.hosts_not_reporting > 0 || s.agents_need_attention > 0) && (
        <section aria-labelledby="fleet" className="border border-line-strong bg-surface p-4">
          <h2 id="fleet" className="flex items-center gap-2 font-semibold"><TriangleAlert className="size-4" aria-hidden />Machines need a look</h2>
          <ul className="mt-2 flex flex-col gap-1 text-sm">
            {s.hosts_not_reporting > 0 && <li>{plural(s.hosts_not_reporting, "machine")} stopped reporting, so {s.hosts_not_reporting === 1 ? "its" : "their"} findings may be out of date.</li>}
            {s.agents_need_attention > 0 && <li>{plural(s.agents_need_attention, "agent")} can't update {s.agents_need_attention === 1 ? "itself" : "themselves"}; Assets says why and what to do.</li>}
          </ul>
          <Link to="/assets" className="mt-1 inline-flex min-h-[44px] items-center gap-1.5 text-sm font-medium text-accent underline md:min-h-0">Review in Assets <ArrowRight className="size-4" aria-hidden /></Link>
        </section>
      )}

      <ul className="grid grid-cols-2 gap-2 sm:grid-cols-4" aria-label="Open findings by priority">
        {PRIORITIES.map((p) => (
          <li key={p}>
            <Link
              to="/findings"
              search={filtersToSearch({ ...parseFilters({}), priority: [p], fixable: false })}
              className="flex flex-col border border-line bg-surface px-3.5 py-2.5 no-underline hover:border-line-strong"
            >
              <span className={clsx("num text-2xl font-semibold", tile(p, s.open_by_priority[p] ?? 0))}>{s.open_by_priority[p] ?? 0}</span>
              <span className="text-sm text-muted">{PRIORITY_LABEL[p]}</span>
            </Link>
          </li>
        ))}
      </ul>

      <section aria-labelledby="actions">
        <h2 id="actions" className="mb-3 text-lg font-semibold">Recommended upgrades</h2>
        {s.top_actions.length === 0 ? (
          <div className="flex items-start gap-3 border border-dashed border-line-strong p-5">
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

export function ActionCard({ a }: { a: Action }) {
  const free = a.asset_ids.filter((id) => !a.busy_asset_ids.includes(id));
  const failed = a.last_attempt && !a.job ? a.last_attempt : null;
  // A failure that named extra packages is re-planned from its job card ("Plan again including …"), never blind from here.
  const needsMore = failed ? dependenciesNeeded(failed.error).length > 0 : false;
  return (
    <li className="flex flex-col gap-3 border border-line bg-surface p-4 sm:flex-row sm:items-center sm:justify-between">
      <div className="min-w-0">
        <p className="text-base">
          Upgrade <strong className="break-all font-semibold">{a.package}</strong> to{" "}
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
      <div className="flex shrink-0 flex-col items-start gap-2 sm:items-end">
        {(a.job || failed) && (
          <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <StatusPill status={(a.job ?? failed)!.status} />
            <Link to="/remediation" hash={jobAnchor((a.job ?? failed)!.id)} className="inline-flex min-h-[44px] items-center gap-1.5 text-sm font-medium text-accent underline md:min-h-9">
              {a.job ? "View fix" : `Last attempt ${JOB_STATUS_LABEL[failed!.status].toLowerCase()}: review`}<span className="sr-only"> for {a.package}</span> <ArrowRight className="size-4" aria-hidden />
            </Link>
          </span>
        )}
        <span className="flex flex-wrap items-start gap-x-4 gap-y-2">
        {free.length > 0 && !needsMore && (
          <PlanFixButton ecosystem={a.ecosystem} pkg={a.package} assetIds={free}
            label={a.job ? `Plan fix for ${plural(free.length, "more host")}` : failed ? "Plan fix again" : "Plan fix"} />
        )}
        <Link
          to="/findings"
          search={filtersToSearch({ ...parseFilters({}), q: a.package })}
          className="inline-flex min-h-[44px] items-center gap-1.5 text-sm font-medium text-accent underline md:min-h-9"
        >
          View findings <ArrowRight className="size-4" aria-hidden />
        </Link>
        </span>
      </div>
    </li>
  );
}

function HomeSkeleton() {
  return (
    <div className="flex flex-col gap-8">
      <Loading className="h-20" rows={4} label="Loading Fix first…" />
    </div>
  );
}
