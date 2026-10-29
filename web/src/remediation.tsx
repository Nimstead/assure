import { useState } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Wrench, X } from "lucide-react";
import clsx from "clsx";
import { adminGate, api, APPROVE_COPY, dependenciesNeeded, filtersToSearch, groupJobs, isActiveJob, jobAnchor, jobsQ, parseFilters, parseUtc, refresh, relativeTime, useHashScroll, useIsAdmin, useTitle, type Job } from "./lib";
import { Alert, btnPrimary, btnQuiet, ConfirmDialog, EmptyState, ErrorState, Loading, StatusPill } from "./ui";

const CANCELLABLE: Job["status"][] = ["planned", "approved"];

export function RemediationPage() {
  useTitle("Remediation");
  const qc = useQueryClient();
  // Poll while anything is approved/dispatched/verifying.
  const q = useQuery({ ...jobsQ, refetchInterval: (query) => (query.state.data?.some(isActiveJob) ? 3000 : false) });
  const [target, setTarget] = useState<Job | null>(null);
  const [cancelling, setCancelling] = useState<Job | null>(null);
  const approve = useMutation({
    mutationFn: (id: string) => api<Job>(`/api/remediation/jobs/${id}/approve`, { method: "POST" }),
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
        <p className="mt-1 max-w-prose text-muted">Every fix is planned first, approved by a person (unless you enable auto), and only counted as done once the next inventory proves the vulnerability is gone.</p>
      </header>
      {q.isPending ? <Loading className="h-24" rows={3} label="Loading fixes…" />
        : q.error ? <ErrorState error={q.error} retry={() => q.refetch()} />
        : groups.length === 0 ? <EmptyState title="No fixes planned yet">Use “Plan fix” on a recommended upgrade or a finding. Nothing changes on a machine until you approve it.</EmptyState>
        : groups.map((g) => (
          <section key={g.key} aria-labelledby={`g-${g.key}`}>
            <h2 id={`g-${g.key}`} className="mb-3 flex items-center gap-2 text-lg font-semibold">{g.title}<span className="num border border-line px-2 text-sm font-medium text-muted">{g.jobs.length}</span></h2>
            <ul className="flex flex-col gap-2">
              {g.jobs.map((j) => <JobCard key={j.id} job={j} onApprove={() => { approve.reset(); setTarget(j); }} onCancel={() => { cancel.reset(); setCancelling(j); }} />)}
            </ul>
          </section>
        ))}
      <ApproveDialog job={target} onOpenChange={(o) => !o && setTarget(null)} pending={approve.isPending}
        error={approve.error?.message} onConfirm={() => target && approve.mutate(target.id)} />
      <ConfirmDialog open={!!cancelling} onOpenChange={(o) => !o && setCancelling(null)} title="Cancel this fix?"
        description={<><strong className="font-semibold">{cancelling?.summary}</strong>. No machine has picked it up yet, so nothing has changed on {cancelling?.hostname}. You can plan it again later.</>}
        confirmLabel="Cancel fix" cancelLabel="Keep it" pendingLabel="Cancelling…" pending={cancel.isPending} error={cancel.error} onConfirm={() => cancelling && cancel.mutate(cancelling.id)} />
    </div>
  );
}

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
            <li className="min-w-0 break-all">on <Link to="/findings" search={filtersToSearch({ ...parseFilters({}), asset: j.asset_id, fixable: false })} className="font-semibold text-ink underline decoration-line-strong hover:decoration-ink">{j.hostname}</Link></li>
            <li className="break-all">planned by {j.created_by}</li>
            {j.approved_by && <li className="break-all">approved by {j.approved_by}</li>}
            {/* shown, not blocked: auditors look for this under SOC 2 CC8.1 */}
            {j.approved_by && j.approved_by === j.created_by && <li className="text-ink">planned and approved by the same person</li>}
            <li><time dateTime={parseUtc(j.updated).toISOString()} title={parseUtc(j.updated).toLocaleString()}>{relativeTime(j.updated)}</time></li>
          </ul>
        </div>
        <div className="flex shrink-0 flex-wrap gap-2">
          {CANCELLABLE.includes(j.status) && onCancel && (
            <button className={btnQuiet} onClick={onCancel} {...adminGate(admin)}>Cancel<span className="sr-only"> fix on {j.hostname}</span></button>
          )}
          {j.status === "planned" && onApprove && (
            <button className={btnPrimary} onClick={onApprove} {...adminGate(admin)}><Check className="size-4" aria-hidden />Approve<span className="sr-only"> fix on {j.hostname}</span></button>
          )}
        </div>
      </div>
      {j.error && <RefusalNote error={j.error} />}
      {deps.length > 0 && (
        <div className="mt-2 flex flex-wrap items-center gap-3">
          <button className={btnQuiet} onClick={() => replan.mutate()} disabled={replan.isPending || replan.isSuccess} {...adminGate(admin)}>
            <Wrench className="size-4" aria-hidden />{replan.isSuccess ? "Planned" : `Plan again including ${deps.join(", ")}`}
          </button>
          <span className="text-sm text-muted">They'll be saved and rolled back together with {pkg}.</span>
          <Alert error={replan.error} />
        </div>
      )}
      {steps.length > 0 && (
        <details className="group mt-3">
          <summary className="flex min-h-[44px] w-fit cursor-pointer items-center text-sm font-medium text-accent underline md:min-h-9">
            <span className="group-open:hidden">Show step log ({steps.length})</span><span className="hidden group-open:inline">Hide step log</span>
          </summary>
          <ol className="mt-2 flex flex-col gap-2">
            {steps.map((s, i) => (
              <li key={i} className="text-sm">
                <p className="flex items-start gap-2">
                  {s.ok ? <Check className="mt-0.5 size-4 shrink-0 text-accent" aria-hidden /> : <X className="mt-0.5 size-4 shrink-0 text-now-fg" aria-hidden />}
                  <span><span className="sr-only">{s.ok ? "Passed: " : "Failed: "}</span>{s.step}</span>
                </p>
                {s.output && <pre tabIndex={0} className="ml-6 mt-1 max-h-48 overflow-auto whitespace-pre-wrap break-all bg-sunken p-2 font-mono text-xs">{s.output}</pre>}
              </li>
            ))}
          </ol>
        </details>
      )}
    </li>
  );
}

/** Pure view (no network) so the copy can be tested. */
export function ApproveDialog({ job, onOpenChange, onConfirm, pending, error }: {
  job: Pick<Job, "summary" | "hostname"> | null; onOpenChange: (o: boolean) => void; onConfirm: () => void; pending?: boolean; error?: string;
}) {
  return (
    <ConfirmDialog open={!!job} onOpenChange={onOpenChange} title="Approve this fix?" description={<><strong className="font-semibold">{job?.summary}</strong>.</>}
      confirmLabel="Approve and run" pendingLabel="Approving…" pending={pending} error={error} onConfirm={onConfirm}>
      <p className="mt-3 border border-line p-3 text-sm">{APPROVE_COPY}</p>
    </ConfirmDialog>
  );
}

/** A job error, with a way to Settings when the refusal is about production remediation being off. */
function RefusalNote({ error }: { error: string }) {
  return (
    <p className="mt-3 bg-now-bg px-3 py-2 text-sm text-now-fg">
      {error}
      {/sandbox/i.test(error) && <> Only test machines can be fixed until production remediation is turned on for this server. <Link to="/settings" hash="remediation" className="font-medium text-now-fg underline">How to turn it on</Link></>}
    </p>
  );
}

/** Plans a fix for one package on the given machines (one job each). */
export function PlanFixButton({ ecosystem, pkg, assetIds, hosts = assetIds.length, label = "Plan fix", className }: { ecosystem: string; pkg: string; assetIds: string[]; hosts?: number; label?: string; className?: string }) {
  const admin = useIsAdmin();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const plan = useMutation({
    mutationFn: async (_from: string) => {
      const errors: string[] = [], made: Job[] = [];
      for (const asset_id of assetIds) {
        try { made.push(await api<Job>("/api/remediation/jobs", { method: "POST", body: { asset_id, ecosystem, package: pkg } })); }
        catch (e) { errors.push((e as Error).message); }
      }
      if (errors.length) throw new Error([...new Set(errors)].join(" "));
      return made;
    },
    onSettled: () => refresh(qc, "jobs"), // partial failures still created some jobs
    // Land on the new fix, but only if the user is still where they pressed the button.
    onSuccess: (made, from) => {
      if (location.pathname === from) void navigate({ to: "/remediation", hash: made[0] ? jobAnchor(made[0].id) : undefined });
    },
  });
  return (
    <div className={clsx("flex flex-col items-start gap-1.5", className)}>
      <button className={btnQuiet} disabled={plan.isPending} onClick={() => plan.mutate(location.pathname)} {...adminGate(admin)}>
        <Wrench className="size-4" aria-hidden />{plan.isPending ? "Planning…" : label}
        <span className="sr-only"> for {pkg}{hosts > 1 ? ` on ${hosts} hosts` : ""}</span>
      </button>
      <Alert error={plan.error} className="max-w-sm" />
    </div>
  );
}
