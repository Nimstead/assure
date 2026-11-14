import { Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { ArrowRight, CheckCircle2, TriangleAlert } from "lucide-react";
import { assetsQ, dependenciesNeeded, coverageQ, settingsQ, filtersToSearch, jobAnchor, JOB_STATUS_LABEL, parseFilters, plural, PRIORITIES, PRIORITY_LABEL, priorityOf, summaryQ, useTitle, type Action } from "./lib";
import { PlanFixButton } from "./planfix";
import { ErrorState, KevBadge, Loading, PriorityPill, StatusPill } from "./ui";
import clsx from "clsx";
import { Fragment, lazy, Suspense, useState } from "react";

const Onboarding = lazy(() => import("./onboarding").then((m) => ({ default: m.Onboarding })));

// Only a non-zero "fix now" carries colour; the rest are ink so a count never reads as disabled.
const tile = (p: string, n: number) => (p === "fix-now" && n > 0 ? "text-now-fg" : "text-ink");

/** Render fleet priorities and recommended actions, with onboarding when no assets exist. */
export function Home() {
  const q = useQuery(summaryQ);
  const coverage = useQuery(coverageQ);
  const settings = useQuery(settingsQ);
  const assets = useQuery(assetsQ);
  useTitle(q.data?.assets === 0 ? "Add a machine" : "Fix first");

  if (q.isPending) return <HomeSkeleton />;
  if (q.error) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  const s = q.data;
  if (s.assets === 0) return <Suspense fallback={<Loading className="h-64" />}><Onboarding /></Suspense>;

  const total = PRIORITIES.reduce((n, p) => n + (s.open_by_priority[p] ?? 0), 0);
  const unchecked = coverage.data?.inventory_only ?? 0;
  const prodLocked = settings.data?.production_remediation_allowed === false;
  // what can be planned from here comes first; the rest keeps its risk order below
  const tests = new Set((assets.data ?? []).filter((x) => x.sandbox).map((x) => x.id));
  const plannable = (a: Action) => a.plannable && (!prodLocked || a.asset_ids.some((id) => tests.has(id)));
  const now = s.top_actions.filter(plannable), later = s.top_actions.filter((a) => !plannable(a));
  const devices = s.devices_with_issues ?? 0;
  const fleet = s.hosts_not_reporting > 0 || s.agents_need_attention > 0 || devices > 0;
  // a queue: what broke comes first, as direct links; fleet health is named in one line and sits after the fixes
  const look = [s.hosts_not_reporting > 0 && `${plural(s.hosts_not_reporting, "machine")} stopped reporting`,
    s.agents_need_attention > 0 && `${plural(s.agents_need_attention, "agent")} can't update`,
    devices > 0 && `${plural(devices, "device")} with no agent ${devices === 1 ? "has" : "have"} issues`].filter((x): x is string => !!x);
  return (
    <div className="flex flex-col gap-8">
      <header>
        <h1 className="text-3xl font-semibold">Fix first</h1>
        <p className="mt-1 text-muted">
          {total === 0
            ? `No open findings across ${plural(s.assets, "asset")}.${unchecked ? ` Installed apps not checked: ${unchecked}, listed on Assets.` : ""}`
            : `${plural(total, "open finding")} across ${plural(s.assets, "asset")}. These fixes clear the most risk.`}
        </p>
        {look.length > 0 && <p className="mt-2 text-sm text-muted">{look.join(" · ")}. <a href="#needs-a-look" className="font-medium text-ink underline">Review below</a></p>}
      </header>

      {s.attention.length > 0 && (
        <section aria-labelledby="attention" className="border border-line-strong bg-surface p-4">
          <h2 id="attention" className="flex items-center gap-2 font-semibold"><TriangleAlert className="size-4" aria-hidden />{plural(s.attention.length, "fix", "fixes")} didn't work</h2>
          <ul className="mt-2 flex flex-col gap-1.5 text-sm">
            {s.attention.slice(0, 5).map((j) => (
              <li key={j.id} className="flex flex-wrap items-center gap-x-2 gap-y-1"><StatusPill status={j.status} />
                <Link to="/remediation" hash={jobAnchor(j.id)} className="inline-flex tap min-w-0 items-center break-words text-ink underline decoration-line-strong hover:decoration-ink">{j.summary}</Link></li>
            ))}
          </ul>
          {s.attention.length > 5 && <Link to="/remediation" className="mt-1 inline-flex tap items-center gap-1.5 text-sm font-medium text-accent underline">All {s.attention.length} in Remediation <ArrowRight className="size-4" aria-hidden /></Link>}
        </section>
      )}

      <ul className="grid grid-cols-2 gap-2 sm:grid-cols-4" aria-label="Open findings by priority">
        {PRIORITIES.map((p) => (
          <li key={p}>
            <Link
              to="/findings"
              search={filtersToSearch({ ...parseFilters({}), priority: [p], fixable: false })}
              className="group relative flex flex-col border border-line bg-surface px-3.5 py-2.5 no-underline hover:border-ink"
            >
              <ArrowRight aria-hidden className="absolute right-3 top-3 size-4 text-muted group-hover:text-ink" />
              <span className={clsx("num text-2xl font-semibold", tile(p, s.open_by_priority[p] ?? 0))}>{(s.open_by_priority[p] ?? 0).toLocaleString()}</span>
              <span className="text-sm text-muted">{PRIORITY_LABEL[p]}</span>
            </Link>
          </li>
        ))}
      </ul>

      <section aria-labelledby="actions">
        <h2 id="actions" className="mb-3 text-lg font-semibold">Recommended fixes</h2>
        {prodLocked && <p className="-mt-1 mb-3 max-w-prose text-sm text-muted">Production remediation is off on this server, so these can only be planned for test machines. <Link to="/settings" hash="remediation" className="font-medium text-ink underline">How to turn it on</Link></p>}
        {s.top_actions.length === 0 ? (
          <div className="flex items-start gap-3 border border-dashed border-line-strong p-5">
            <CheckCircle2 className="mt-0.5 size-5 shrink-0 text-accent" aria-hidden />
            <p className="text-sm text-muted">
              {total === 0 ? "Everything reported so far is clean. New findings will show up here." : "Nothing here can be fixed by an upgrade or a setting change yet. Review the findings with no fix to mitigate or accept them."}
            </p>
          </div>
        ) : (
          <>
            {now.length > 0 && <ol className="flex flex-col gap-2">
              {now.map((a) => <ActionCard key={a.ecosystem + a.package} a={a} />)}
            </ol>}
            {/* only what can be planned here (the owner's call); the rest is one line away, in Findings */}
            {/* these are the top fixes by risk, not all of them: say so, and where the rest are */}
            <p className="mt-3 max-w-prose text-sm text-muted">
              These are the top fixes by risk, not every one.{later.length > 0 && <>
                {" "}{later.length === 1 ? "One more of the top fixes" : `${later.length} more of the top fixes`} can't be planned from here (their own updater, a policy, or production machines while production remediation is off):{" "}
                {/* named, each a link: a Fix now or KEV fix that can't be planned here is still the work to do */}
                {later.map((a, i) => <Fragment key={a.ecosystem + a.package}>
                  <span className="inline-flex items-center gap-1.5 whitespace-nowrap align-middle"><PriorityPill priority={priorityOf(a.max_score, a.kev)} />{a.kev && <KevBadge />}
                  <Link to="/findings" search={filtersToSearch({ ...parseFilters({}), q: a.package, ecosystem: a.ecosystem })} className="font-medium text-ink underline">{a.package.split(":").at(-1)}</Link></span>{i < later.length - 1 ? ", " : "."}{" "}
                </Fragment>)}
              </>}{" "}
              <Link to="/findings" search={filtersToSearch({ ...parseFilters({}), fixable: true, group: "package" })} className="font-medium text-ink underline">Every fix, by package</Link></p>
          </>
        )}
      </section>

      {fleet && (
        <section id="needs-a-look" aria-labelledby="fleet" className="scroll-mt-6 border border-line-strong bg-surface p-4">
          <h2 id="fleet" className="font-semibold">Machines and devices that need a look</h2>
          <ul className="mt-2 flex flex-col gap-1 text-sm">
            {s.hosts_not_reporting > 0 && <li><Link to="/assets" search={{ show: "quiet" }} className="underline decoration-line-strong hover:decoration-ink">{plural(s.hosts_not_reporting, "machine")} stopped reporting</Link>, so {s.hosts_not_reporting === 1 ? "its" : "their"} findings may be out of date.</li>}
            {s.agents_need_attention > 0 && <li><Link to="/assets" search={{ show: "agent" }} className="underline decoration-line-strong hover:decoration-ink">{plural(s.agents_need_attention, "agent")} can't update {s.agents_need_attention === 1 ? "itself" : "themselves"}</Link>; Assets says why and what to do.</li>}
            {devices > 0 && <li><Link to="/assets" search={{ view: "devices" }} className="underline decoration-line-strong hover:decoration-ink">{plural(devices, "device")} with no agent</Link> {devices === 1 ? "has" : "have"} exposed services found by network checks.</li>}
          </ul>
        </section>
      )}
    </div>
  );
}

/** Render upgrade recommendation a with its scope and fix-planning action. */
export function ActionCard({ a }: { a: Action }) {
  const prodOk = useQuery(settingsQ).data?.production_remediation_allowed ?? true;  // unknown: let the API say no
  const assets = useQuery(assetsQ).data ?? [];
  const sandbox = new Set(assets.filter((x) => x.sandbox).map((x) => x.id));
  const [allHosts, setAllHosts] = useState(false);
  const idle = a.asset_ids.filter((id) => !a.busy_asset_ids.includes(id));
  const free = prodOk ? idle : idle.filter((id) => sandbox.has(id));
  const held = idle.length - free.length;
  const tests = a.asset_ids.filter((id) => sandbox.has(id)).length;  // busy or not: what this server may ever change here  // production machines this server won't change yet
  const failed = a.last_attempt && !a.job ? a.last_attempt : null;
  // A failure that named extra packages is re-planned from its job card ("Plan again including …"), never blind from here.
  const needsMore = failed ? dependenciesNeeded(failed.error).length > 0 : false;
  const nameOf = new Map(assets.map((x) => [x.id, x.hostname]));
  const freeNames = free.map((id) => nameOf.get(id)).filter((n): n is string => !!n);
  return (
    <li className="flex flex-col gap-3 border border-line bg-surface p-4 sm:flex-row sm:items-center sm:justify-between">
      <div className="min-w-0">
        <p className="text-base">
          {a.fixed_version ? <>
            Upgrade <strong className="break-all font-semibold">{a.package}</strong> to{" "}
            <code className="text-mono whitespace-nowrap bg-sunken px-1.5 py-0.5 font-mono">{a.fixed_version}</code>
          </> : <>Change setting <strong className="break-all font-semibold">{a.package}</strong></>}
          {" "}<span className="text-sm text-muted">{a.ecosystem}</span>
        </p>
        {a.summary && <p className="mt-1 max-w-prose break-words text-sm text-muted">{a.summary}</p>}
        <p className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1.5 text-sm text-muted">
          <PriorityPill priority={priorityOf(a.max_score, a.kev)} />
          {a.kev && <KevBadge />}
          {(a.job || failed) && <StatusPill status={(a.job ?? failed)!.status} />}
          <span>
            Fixes {a.fixed_version ? plural(a.vulns.length, "vulnerability", "vulnerabilities") : plural(a.vulns.length, "finding")} on {plural(a.hosts.length, "host")}
            <span className="hidden md:inline">: {(allHosts ? a.hosts : a.hosts.slice(0, 3)).join(", ")}{a.hosts.length > 3 && !allHosts && <>{" "}
              <button className="cursor-pointer text-ink underline decoration-line-strong hover:decoration-ink" onClick={() => setAllHosts(true)}>and {a.hosts.length - 3} more<span className="sr-only"> hosts for {a.package}</span></button></>}</span>
          </span>
        </p>
        {a.plannable
          ? (a.person_only || a.forward_only) && <p className="mt-1 text-sm text-muted">{a.person_only && "A person approves this one, never the trust ladder."}{a.forward_only && " It can't be undone."}</p>
          : <p className="mt-1 text-sm text-muted">Nimstead can't plan this one: update it with its own updater or by policy.</p>}
        {a.plannable && !prodOk && tests < a.asset_ids.length && <p className="mt-1 text-sm text-muted">
          {/* the reason is said once, above the list: each card only says how many */}
          {tests ? `${tests} of ${a.asset_ids.length} can be fixed from here (test ${tests === 1 ? "machine" : "machines"})` : `None of the ${a.asset_ids.length} can be fixed from here`}</p>}
      </div>
      <div className="flex shrink-0 flex-col items-start gap-2 sm:items-end">
        <span className="flex flex-wrap items-center gap-x-4 gap-y-2 sm:justify-end">
        {(a.job || failed) && (
            <Link to="/remediation" hash={jobAnchor((a.job ?? failed)!.id)} className="inline-flex min-h-[44px] items-center gap-1.5 text-sm font-medium text-accent underline md:min-h-9">
              <span>{a.job ? "View fix" : `Last attempt ${JOB_STATUS_LABEL[failed!.status].toLowerCase()}: review`}<span className="sr-only"> for {a.package}</span></span> <ArrowRight className="size-4" aria-hidden />
            </Link>
        )}
        {a.plannable && free.length > 0 && !needsMore && (
          <PlanFixButton ecosystem={a.ecosystem} pkg={a.package} assetIds={free} names={freeNames} kind={prodOk ? "machine" : "test machine"}
            label={a.job ? `Plan fix for ${plural(free.length, "more host")}` : failed ? "Plan fix again" : held ? (freeNames.length === 1 ? `Plan fix on ${freeNames[0]}` : `Plan fix on ${plural(free.length, "test machine")}`) : "Plan fix"} />
        )}
        <Link
          to="/findings"
          search={filtersToSearch({ ...parseFilters({}), q: a.package, ecosystem: a.ecosystem })}
          className="inline-flex min-h-[44px] items-center gap-1.5 text-sm font-medium text-accent underline md:min-h-9"
        >
          <span>View findings<span className="sr-only"> for {a.package}</span></span> <ArrowRight className="size-4" aria-hidden />
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
