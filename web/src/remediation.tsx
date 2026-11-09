import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, TriangleAlert, Wrench, X } from "lucide-react";
import { adminGate, api, APPROVE_COPY, dependenciesNeeded, filtersToSearch, groupJobs, isActiveJob, jobAnchor, jobsQ, kbFleetQ, kbHostsQ, parseFilters, parseUtc, plural, refresh, relativeTime, useHashScroll, useIsAdmin, useTitle, meQ, assetsQ, type Asset, type Job, type KbRow } from "./lib";
import { Alert, btnPrimary, btnQuiet, ConfirmDialog, EmptyState, ErrorState, Loading, StatusPill, Tag } from "./ui";

const CANCELLABLE: Job["status"][] = ["planned", "approved"];
const AGAIN: Job["status"][] = ["failed", "rolled_back", "rollback_failed", "not_fixed"];

/** Return array entries in j.packages that are objects with a string name, otherwise [].
 * Only name is validated. Optional from/to/kb values pass through without validation.
 * Return a new array with shared package objects. Do not mutate j or perform I/O.
 */
export function jobPackages(j: { packages?: unknown }): { name: string; from?: string; to?: string; kb?: string }[] {
  return Array.isArray(j.packages) ? j.packages.filter((p): p is { name: string } => !!p && typeof p === "object" && typeof (p as { name?: unknown }).name === "string") : [];
}

// shortcut: agents (<= 0.6.6) report a step that fell back and then succeeded as ok, recognised by its wording; send a `warn` flag from the agent if more appear.
const RECOVERED = /not available|rebuilding|rebuilt from|retry \d/i;
/** Classify step s for display: false ok wins, then fallback wording, then passed.
 * Inspect step/output with the RECOVERED regex. Wording alone is not execution evidence.
 * Invalid runtime string types can throw. No mutation or I/O occurs.
 */
export const stepState = (s: { step: string; ok: boolean; output?: string }) => (!s.ok ? "failed" : RECOVERED.test(s.step) || RECOVERED.test(s.output ?? "") ? "recovered" : "passed");

function PackageList({ job }: { job: { packages?: unknown; summary?: string } }) {
  const pkgs = jobPackages(job);
  // shortcut: the plan's target lives only in its summary ("(fixed in X)"); store it on the job if more views need it
  const target = /\(fixed in ([^)]+)\)$/.exec(job.summary ?? "")?.[1];
  if (!pkgs.length) return null;
  return (
    <ul className="mt-2 flex flex-col gap-0.5 text-sm" aria-label="Packages this fix changes">
      {pkgs.map((p) => (
        <li key={p.name} className="break-words"><span className="font-medium">{p.name}</span>{" "}
          <span className="font-mono text-muted">{p.kb ? p.kb : <>{p.from ?? "?"} → {p.to ?? (target ? `${target} or the repository's newer` : "the repository candidate")}</>}</span></li>
      ))}
    </ul>
  );
}

/** Render remediation under router and QueryClient providers, without props.
 * Query jobs, current user and assets. Poll jobs every three seconds while an
 * approved/dispatched/verifying row exists. Planned-only jobs do not trigger polling.
 * Approval/cancellation POST through controlled dialogs; refresh job-derived queries on success.
 * Render query/mutation errors locally. Server authorization and execution gates remain authoritative.
 */
export function RemediationPage() {
  useTitle("Remediation");
  const qc = useQueryClient();
  // Poll while anything is approved/dispatched/verifying.
  const q = useQuery({ ...jobsQ, refetchInterval: (query) => (query.state.data?.some(isActiveJob) ? 3000 : false) });
  const [target, setTarget] = useState<Job | null>(null);
  const me = useQuery(meQ).data?.email;
  const assets = useQuery(assetsQ);
  const [cancelling, setCancelling] = useState<Job | null>(null);
  const approve = useMutation({
    mutationFn: (j: Pick<Job, "id" | "forward_only">) => api<Job>(`/api/remediation/jobs/${j.id}/approve`, { method: "POST", body: { forward_only: !!j.forward_only } }),
    onSuccess: () => { setTarget(null); void refresh(qc, "jobs"); },
  });
  const cancel = useMutation({
    mutationFn: (id: string) => api<Job>(`/api/remediation/jobs/${id}/cancel`, { method: "POST" }),
    onSuccess: () => { setCancelling(null); void refresh(qc, "jobs"); },
  });
  useHashScroll(!!q.data);  // #job-<id> from Home, the finding drawer or Plan fix
  const groups = q.data ? groupJobs(q.data).filter((g) => g.jobs.length) : [];

  return (
    <div className="flex flex-col gap-8">
      <header>
        <h1 className="text-3xl font-semibold">Remediation</h1>
        <p className="mt-1 max-w-prose text-muted">Fixes need a plan and human or eligible policy approval. Review inventory and remaining findings after execution. A Windows stepping job can succeed before the final fix.</p>
      </header>
      {q.isPending ? <Loading className="h-24" rows={3} label="Loading fixes…" />
        : q.error ? <ErrorState error={q.error} retry={() => q.refetch()} />
        : groups.length === 0 ? <EmptyState title="No fixes planned yet">Use “Plan fix” on a recommended fix or a finding. Eligible fixes can receive policy approval in Auto mode.</EmptyState>
        : groups.map((g) => (
          <section key={g.key} aria-labelledby={`g-${g.key}`}>
            <h2 id={`g-${g.key}`} className="mb-3 flex items-center gap-2 text-lg font-semibold">{g.title}<span className="sr-only">: </span><span className="num border border-line px-2 text-sm font-medium text-muted">{g.jobs.length}</span></h2>
            <ul className="flex flex-col gap-2">
              {g.jobs.map((j) => <JobCard key={j.id} job={j} onApprove={() => { approve.reset(); setTarget(j); }} onCancel={() => { cancel.reset(); setCancelling(j); }} />)}
            </ul>
          </section>
        ))}
      <KbFleet />
      <ApproveDialog job={target} context={machineContext(assets.data?.find((a) => a.id === target?.asset_id))} onOpenChange={(o) => !o && setTarget(null)} pending={approve.isPending} ownPlan={!!target && target.created_by === me}
        error={approve.error?.message} onConfirm={() => target && approve.mutate(target)} />
      <ConfirmDialog open={!!cancelling} onOpenChange={(o) => !o && setCancelling(null)} title="Cancel this fix?"
        description={<><strong className="font-semibold">{cancelling?.summary}</strong>. Cancellation succeeds only before dispatch. A job already sent to {cancelling?.hostname} cannot be cancelled here. You can plan a cancelled fix again later.</>}
        confirmLabel="Cancel fix" cancelLabel="Keep it" pendingLabel="Cancelling…" pending={cancel.isPending} error={cancel.error} onConfirm={() => cancelling && cancel.mutate(cancelling.id)} />
    </div>
  );
}

/** Query cumulative-update groups and render counts with expandable host details.
 * No props. Require router/QueryClient context. Empty or pending data renders nothing;
 * errors render a retry action. Opening a row enables its KB/product detail query.
 * Counts and rollout suggestions come from stored server state, not a new scan.
 */
export function KbFleet() {
  const q = useQuery(kbFleetQ);
  if (q.error) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  if (!q.data?.length) return null;
  return (
    <section aria-labelledby="kb-fleet">
      <h2 id="kb-fleet" className="text-lg font-semibold">Windows updates across the fleet</h2>
      <p className="mb-3 mt-1 max-w-prose text-sm text-muted">Judged by the build each machine last reported. A newer cumulative update includes the older ones.</p>
      <ul className="flex flex-col gap-2">{q.data.map((r) => <KbFleetRow key={r.product + r.kb} row={r} />)}</ul>
    </section>
  );
}

function KbFleetRow({ row: r }: { row: KbRow }) {
  const [open, setOpen] = useState(false);
  const q = useQuery({ ...kbHostsQ(r), enabled: open });
  const left = r.hosts - r.fixed;
  return (
    <li className="border border-line bg-surface p-4">
      <p className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <span className="min-w-0 break-words font-medium">{r.title}</span>
        <span className="num text-sm">{r.fixed} of {plural(r.hosts, "host")}</span>
      </p>
      <p className="mt-1 break-words text-sm text-muted">{r.product}, build {r.build}</p>
      {left > 0 && (
        <details className="group mt-2" onToggle={(e) => setOpen(e.currentTarget.open)}>
          <summary className="flex min-h-[44px] w-fit cursor-pointer items-center text-sm font-medium text-accent underline md:min-h-9">
            <span className="group-open:hidden">Show {plural(left, "machine")} without it</span><span className="hidden group-open:inline">Hide machines</span>
          </summary>
          {q.isPending ? <Loading className="h-16" label="Loading machines…" />
            : q.error ? <ErrorState error={q.error} retry={() => q.refetch()} />
            : (
              <div className="mt-2 flex flex-col gap-3">
                {q.data.plan_asset_ids.length > 0 && (
                  <PlanFixButton ecosystem="Windows" pkg={r.product} assetIds={q.data.plan_asset_ids}
                    label={q.data.plan_asset_ids.length === left ? `Plan the rest (${left})` : `Plan ${plural(q.data.plan_asset_ids.length, "machine")} now`} />
                )}
                {q.data.plan_note && <p className="text-sm text-muted">{q.data.plan_note}</p>}
                <ul className="flex flex-col gap-2">
                  {q.data.missing.map((h) => (
                    <li key={h.asset_id} className="border-t border-line pt-2 text-sm">
                      <p className="break-words"><span className="font-medium">{h.hostname}</span>{h.ring === 0 && " (canary)"} <span className="text-muted">on build {h.build}</span></p>
                      <p className="mt-0.5 break-words">{h.job
                        ? <Link to="/remediation" hash={jobAnchor(h.job.id)} className="text-ink underline decoration-line-strong hover:decoration-ink">{h.why}</Link>
                        : h.why}</p>
                      {h.notes.map((n) => <p key={n} className="mt-0.5 break-words text-muted">{n}</p>)}
                    </li>
                  ))}
                </ul>
              </div>
            )}
        </details>
      )}
    </li>
  );
}

/** Render job with status, package scope, step log and errors under app providers.
 * onApprove/onCancel are optional parent actions, exposed only for eligible states
 * with a client admin gate. Dependency refusals can POST a replacement plan directly.
 * Replan errors render locally; success refreshes job-derived queries. job is not mutated.
 * Optional package fields are not fully validated. Invalid dates/shapes can throw during render.
 */
export function JobCard({ job: j, onApprove, onCancel }: { job: Job; onApprove?: () => void; onCancel?: () => void }) {
  const admin = useIsAdmin();
  const steps = j.steps ?? [];
  const qc = useQueryClient();
  const deps = j.status === "aborted" ? dependenciesNeeded(j.error) : [];
  const [ecosystem, pkg] = j.action_key.split("|");
  const replan = useMutation({
    mutationFn: () => api<Job>("/api/remediation/jobs", { method: "POST", body: { asset_id: j.asset_id, ecosystem, package: pkg, include: deps } }),
    onSuccess: () => void refresh(qc, "jobs"),
  });
  return (
    // the job's address: Home, the drawer and Plan fix link here (#job-<id>)
    <li id={jobAnchor(j.id)} tabIndex={-1} className="scroll-mt-24 border border-line bg-surface p-4 target:border-ink target:shadow-[inset_0_0_0_1px_var(--ink)]">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <p className="font-medium">
            <Link to="/findings" search={filtersToSearch({ ...parseFilters({}), asset: j.asset_id, q: pkg ?? "", fixable: false })} className="text-ink underline decoration-line-strong hover:decoration-ink">{j.summary}</Link>
          </p>
          {/* no dot separators: on a phone they'd start wrapped lines; spacing alone separates the facts */}
          <ul className="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1.5 text-sm text-muted">
            <li><StatusPill status={j.status} /></li>
            <li className="min-w-0 break-all">on <Link to="/findings" search={filtersToSearch({ ...parseFilters({}), asset: j.asset_id, fixable: false })} className="inline-flex tap items-center font-semibold text-ink underline decoration-line-strong hover:decoration-ink">{j.hostname}</Link></li>
            <li className="break-all">planned by {j.created_by}</li>
            {j.approved_by && <li className="break-all">approved by {j.approved_by}</li>}
            {j.forward_only && <li className="text-now-fg">forward-only: no automatic rollback</li>}
            {j.waits_for_window && <li>waits for the maintenance window ({parseUtc(j.waits_for_window).toLocaleString()})</li>}
            {/* shown, not blocked: auditors look for this under SOC 2 CC8.1 */}
            {j.approved_by && j.approved_by === j.created_by && <li><Tag tone="warn" why="Nobody else checked this change. A second approver is the usual control (SOC 2 CC8.1).">Self-approved</Tag></li>}
            <li><time dateTime={parseUtc(j.updated).toISOString()} title={parseUtc(j.updated).toLocaleString()}>{relativeTime(j.updated)}</time></li>
          </ul>
        </div>
        <div className="flex shrink-0 flex-wrap gap-2">
          {CANCELLABLE.includes(j.status) && onCancel && (
            <button className={btnQuiet} onClick={onCancel} {...adminGate(admin)}>Cancel fix<span className="sr-only"> on {j.hostname}</span></button>
          )}
          {j.status === "planned" && onApprove && (
            <button className={btnPrimary} onClick={onApprove} {...adminGate(admin)}><Check className="size-4" aria-hidden />Review and approve<span className="sr-only"> fix on {j.hostname}</span></button>
          )}
        </div>
      </div>
      {j.status === "planned" && <PackageList job={j} />}
      {j.error && <RefusalNote error={j.error} />}
      {j.status === "rolled_back" && <p className="mt-2 max-w-prose text-sm">Before planning it again: try it on a test or canary machine first, and check that the service named above works with the new version (its log usually says why it wouldn't start).</p>}
      {AGAIN.includes(j.status) && deps.length === 0 && pkg && <PlanFixButton ecosystem={ecosystem!} pkg={pkg} assetIds={[j.asset_id]} label="Plan fix again" className="mt-3" />}
      {deps.length > 0 && (
        <div className="mt-2 flex flex-wrap items-center gap-3">
          <button className={btnQuiet} onClick={() => replan.mutate()} disabled={replan.isPending || replan.isSuccess} {...adminGate(admin)}>
            <Wrench className="size-4" aria-hidden />{replan.isSuccess ? "Planned" : `Plan again including ${deps.join(", ")}`}
          </button>
          <span className="text-sm text-muted">Review the new plan's dependency scope and recovery limits.</span>
          <Alert error={replan.error} />
        </div>
      )}
      {steps.length > 0 && (
        <details className="group mt-3">
          <summary className="flex min-h-[44px] w-fit cursor-pointer items-center text-sm font-medium text-accent underline md:min-h-9">
            <span className="group-open:hidden">Show step log ({steps.length})</span><span className="hidden group-open:inline">Hide step log</span>
          </summary>
          {steps.some((s) => !s.ok) && <a href={`#${jobAnchor(j.id)}-fail`} onClick={(e) => { const el = document.getElementById(`${jobAnchor(j.id)}-fail`); if (el) { e.preventDefault(); el.scrollIntoView({ block: "center" }); el.focus(); } }} className="mt-2 inline-flex tap items-center text-sm font-medium text-now-fg underline">Jump to the failed step<span className="sr-only"> on {j.hostname}</span></a>}
          <ol className="mt-2 flex flex-col gap-2">
            {steps.map((s, i) => (
              <li key={i} id={i === steps.findIndex((x) => !x.ok) ? `${jobAnchor(j.id)}-fail` : undefined} tabIndex={i === steps.findIndex((x) => !x.ok) ? -1 : undefined} className="scroll-mt-24 text-sm focus:shadow-[inset_3px_0_0_var(--now-fg)] focus:pl-2">
                <p className="flex items-start gap-2">
                  {{ passed: <Check className="mt-0.5 size-4 shrink-0 text-accent" aria-hidden />, recovered: <TriangleAlert className="mt-0.5 size-4 shrink-0 text-muted" aria-hidden />,
                    failed: <X className="mt-0.5 size-4 shrink-0 text-now-fg" aria-hidden /> }[stepState(s)]}
                  <span><span className="sr-only">{{ passed: "Passed: ", recovered: "Recovered: ", failed: "Failed: " }[stepState(s)]}</span>{s.step}</span>
                </p>
                {s.output && (stepState(s) === "passed"
                  ? <details className="ml-6"><summary className="flex tap min-w-[44px] w-fit cursor-pointer items-center text-xs text-muted">Output</summary><pre tabIndex={0} aria-label={`Output of ${s.step}`} className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap break-all bg-sunken p-2.5 font-mono text-xs">{s.output}</pre></details>
                  : <pre tabIndex={0} aria-label={`Output of ${s.step}`} className="ml-6 mt-1 max-h-48 overflow-auto whitespace-pre-wrap break-all bg-sunken p-2.5 font-mono text-xs">{s.output}</pre>)}
              </li>
            ))}
          </ol>
        </details>
      )}
    </li>
  );
}

/** Return a host-context string from a, or undefined when a is absent.
 * Include hostname, criticality, ring, sandbox and health-unit text without validation.
 * Do not fetch or mutate a. Malformed health_units can throw.
 */
export const machineContext = (a?: Asset) => a && [a.hostname, `${a.criticality} criticality`, a.ring === 0 ? "canary ring" : "broad ring",
  a.sandbox ? "test machine" : "production", a.health_units.length ? `health checks: ${a.health_units.join(", ")}` : "no health checks set"].join(" · ");

/** Render a controlled approval dialog; job=null closes it.
 * job supplies summary/hostname and optional package/manager/forward-only metadata.
 * onOpenChange requests parent open state; onConfirm invokes the parent's approval action.
 * pending disables confirmation and error displays parent failure text. ownPlan/context
 * add review information. This component makes no request or server-policy decision.
 * Requires the app's dialog/browser environment. Invalid package shapes can throw during render.
 */
export function ApproveDialog({ job, onOpenChange, onConfirm, pending, error, ownPlan, context }: {
  job: (Pick<Job, "summary" | "hostname"> & { forward_only?: boolean; packages?: unknown; manager?: string }) | null; onOpenChange: (o: boolean) => void; onConfirm: () => void; pending?: boolean; error?: string; ownPlan?: boolean; context?: string;
}) {
  const fwd = !!job?.forward_only;
  return (
    <ConfirmDialog open={!!job} onOpenChange={onOpenChange} title={fwd ? "Approve a fix that can't be undone?" : "Approve this fix?"} description={<><strong className="font-semibold">{job?.summary}</strong>.</>}
      confirmLabel={fwd ? "Approve: it can't be undone" : "Approve fix"} pendingLabel="Approving…" destructive={fwd} pending={pending} error={error} onConfirm={onConfirm}>
      {context && <p className="mt-2 text-sm text-muted">{context}</p>}
      {job && <PackageList job={job} />}
      {ownPlan && <p className="mt-3 border border-now-fg p-3 text-sm">You planned this fix. Approving it yourself is recorded as self-approved: no second person checked the change (SOC 2 CC8.1).</p>}
      {fwd ? <p className="mt-3 border border-now-fg p-3 text-sm">This is a forward-only change with no automatic rollback. Configured health checks still apply. A failed change can require manual recovery. Approving records your acceptance of that limit.</p>
        : <p className="mt-3 border border-line p-3 text-sm">{APPROVE_COPY}</p>}
    </ConfirmDialog>
  );
}

/** Return a dependency-refusal explanation for matching error text, otherwise null.
 * Parse case-sensitive "would also change:" text through dependenciesNeeded.
 * This is a display heuristic, not proof that a host made no changes. No I/O occurs.
 */
export function plainRefusal(error: string): string | null {
  const deps = dependenciesNeeded(error);
  if (deps.length) return `The report says the upgrade would also change ${deps.join(", ")}, outside the approved plan. Review the machine's report below.`;
  return null;
}

/** A job error, with a way to Settings when the refusal is about production remediation being off. */
function RefusalNote({ error }: { error: string }) {
  const plain = plainRefusal(error);
  return (
    <div className="mt-3 bg-now-bg px-3 py-2 text-sm text-now-fg">
      {plain ? <><p>{plain}</p><details className="mt-1"><summary className="flex tap w-fit cursor-pointer items-center">What the machine reported</summary><p className="text-mono-sm mt-1 break-words font-mono">{error}</p></details></>
        : error}
      {/sandbox/i.test(error) && <> Only test machines can be fixed until production remediation is turned on for this server. <Link to="/settings" hash="remediation" className="font-medium text-now-fg underline">How to turn it on</Link></>}
    </div>
  );
}

import { PlanFixButton } from "./planfix";
export { PlanFixButton };
