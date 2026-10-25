import { useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Dialog } from "radix-ui";
import { Check, Wrench, X } from "lucide-react";
import clsx from "clsx";
import { api, APPROVE_COPY, dependenciesNeeded, groupJobs, isActiveJob, JOB_STATUS_LABEL, relativeTime, useTitle, type Finding, type Job, type JobStatus } from "./lib";
import { btnPrimary, btnQuiet, EmptyState, ErrorState, Skeleton } from "./ui";

const STATUS_CLASS: Record<JobStatus, string> = {
  planned: "bg-next-bg text-next-fg", approved: "bg-planned-bg text-planned-fg", dispatched: "bg-planned-bg text-planned-fg", verifying: "bg-planned-bg text-planned-fg",
  succeeded: "bg-accent-soft text-ink", failed: "bg-now-bg text-now-fg", rolled_back: "bg-now-bg text-now-fg", rollback_failed: "bg-now-bg text-now-fg",
  not_fixed: "bg-now-bg text-now-fg", aborted: "bg-now-bg text-now-fg", cancelled: "bg-sunken text-ink",
};
export const StatusPill = ({ status }: { status: JobStatus }) => (
  <span className={clsx("inline-flex items-center gap-1.5 whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-medium", STATUS_CLASS[status])}>
    <span aria-hidden className="size-1.5 rounded-full bg-current" />{JOB_STATUS_LABEL[status]}
  </span>
);

export function RemediationPage() {
  useTitle("Remediation");
  const qc = useQueryClient();
  // Poll while anything is approved/dispatched/verifying.
  const q = useQuery({
    queryKey: ["jobs"], queryFn: () => api<Job[]>("/api/remediation/jobs"),
    refetchInterval: (query) => (query.state.data?.some(isActiveJob) ? 3000 : false),
  });
  const [target, setTarget] = useState<Job | null>(null);
  const approve = useMutation({
    mutationFn: (id: string) => api<Job>(`/api/remediation/jobs/${id}/approve`, { method: "POST" }),
    onSuccess: () => { setTarget(null); void Promise.all(["jobs", "summary"].map((k) => qc.invalidateQueries({ queryKey: [k] }))); },
  });
  const groups = q.data ? groupJobs(q.data).filter((g) => g.jobs.length) : [];

  return (
    <div className="flex flex-col gap-8">
      <header>
        <h1 className="text-3xl font-semibold">Remediation</h1>
        <p className="mt-1 max-w-prose text-muted">Every fix is planned first, approved by a person (unless you enable auto), and only counted as done once the next inventory proves the vulnerability is gone.</p>
      </header>
      {q.isPending ? <div className="flex flex-col gap-2">{[0, 1, 2].map((i) => <Skeleton key={i} className="h-24" />)}</div>
        : q.error ? <ErrorState error={q.error} retry={() => q.refetch()} />
        : groups.length === 0 ? <EmptyState title="No fixes planned yet">Use “Plan fix” on a recommended upgrade or a finding. Nothing changes on a machine until you approve it.</EmptyState>
        : groups.map((g) => (
          <section key={g.key} aria-labelledby={`g-${g.key}`}>
            <h2 id={`g-${g.key}`} className="mb-3 flex items-center gap-2 text-lg font-semibold">{g.title}<span className="num rounded-full bg-sunken px-2 text-sm font-medium text-muted">{g.jobs.length}</span></h2>
            <ul className="flex flex-col gap-2">
              {g.jobs.map((j) => <JobCard key={j.id} job={j} onApprove={() => { approve.reset(); setTarget(j); }} />)}
            </ul>
          </section>
        ))}
      <ApproveDialog job={target} onOpenChange={(o) => !o && setTarget(null)} pending={approve.isPending}
        error={approve.error?.message} onConfirm={() => target && approve.mutate(target.id)} />
    </div>
  );
}

export function JobCard({ job: j, onApprove }: { job: Job; onApprove?: () => void }) {
  const steps = j.steps ?? [];
  const qc = useQueryClient();
  const deps = j.status === "aborted" ? dependenciesNeeded(j.error) : [];
  const [ecosystem, pkg] = j.action_key.split("|");
  const replan = useMutation({
    mutationFn: () => api<Job>("/api/remediation/jobs", { method: "POST", body: { asset_id: j.asset_id, ecosystem, package: pkg, include: deps } }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["jobs"] }),
  });
  return (
    <li className="rounded-lg border border-line bg-surface p-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <p className="font-medium">{j.summary}</p>
          <p className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1.5 text-sm text-muted">
            <StatusPill status={j.status} />
            <span>on <strong className="font-semibold text-ink">{j.hostname}</strong></span>
            <span>· planned by {j.created_by}</span>
            {j.approved_by && <span>· approved by {j.approved_by}</span>}
            <span>· <time dateTime={j.updated}>{relativeTime(j.updated)}</time></span>
          </p>
        </div>
        {j.status === "planned" && onApprove && (
          <button className={clsx(btnPrimary, "shrink-0")} onClick={onApprove}><Check className="size-4" aria-hidden />Approve<span className="sr-only"> fix on {j.hostname}</span></button>
        )}
      </div>
      {j.error && <p className="mt-3 rounded-md bg-now-bg px-3 py-2 text-sm text-now-fg">{j.error}</p>}
      {deps.length > 0 && (
        <div className="mt-2 flex flex-wrap items-center gap-3">
          <button className={btnQuiet} onClick={() => replan.mutate()} disabled={replan.isPending || replan.isSuccess}>
            <Wrench className="size-4" aria-hidden />{replan.isSuccess ? "Planned" : `Plan again including ${deps.join(", ")}`}
          </button>
          <span className="text-sm text-muted">They'll be saved and rolled back together with {pkg}.</span>
          {replan.error && <span role="alert" className="text-sm text-now-fg">{replan.error.message}</span>}
        </div>
      )}
      {steps.length > 0 && (
        <details className="group mt-3">
          <summary className="min-h-9 w-fit cursor-pointer text-sm font-medium text-accent underline">
            <span className="group-open:hidden">Show step log ({steps.length})</span><span className="hidden group-open:inline">Hide step log</span>
          </summary>
          <ol className="mt-2 flex flex-col gap-2">
            {steps.map((s, i) => (
              <li key={i} className="text-sm">
                <p className="flex items-start gap-2">
                  {s.ok ? <Check className="mt-0.5 size-4 shrink-0 text-accent" aria-hidden /> : <X className="mt-0.5 size-4 shrink-0 text-now-fg" aria-hidden />}
                  <span><span className="sr-only">{s.ok ? "Passed: " : "Failed: "}</span>{s.step}</span>
                </p>
                {s.output && <pre tabIndex={0} className="ml-6 mt-1 max-h-48 overflow-auto whitespace-pre-wrap break-all rounded-md bg-sunken p-2 font-mono text-xs">{s.output}</pre>}
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
    <Dialog.Root open={!!job} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="overlay" />
        <Dialog.Content className="fixed left-1/2 top-[15vh] z-[51] w-[min(30rem,calc(100%-2rem))] -translate-x-1/2 rounded-xl border border-line bg-surface p-5 shadow-2xl">
          <Dialog.Title className="text-lg font-semibold">Approve this fix?</Dialog.Title>
          <Dialog.Description className="mt-2 text-sm">
            <strong className="font-semibold">{job?.summary}</strong> on <strong className="font-semibold">{job?.hostname}</strong>.
          </Dialog.Description>
          <p className="mt-3 rounded-md bg-sunken p-3 text-sm">{APPROVE_COPY}</p>
          {error && <p role="alert" className="mt-3 rounded-md bg-now-bg px-3 py-2 text-sm text-now-fg">{error}</p>}
          <div className="mt-5 flex justify-end gap-2">
            <Dialog.Close className={btnQuiet}>Cancel</Dialog.Close>
            <button className={btnPrimary} onClick={onConfirm} disabled={pending}>{pending ? "Approving…" : "Approve and run"}</button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

/** Plans a fix for one package on one or more hosts. Host names are mapped to asset ids via /api/findings. */
export function PlanFixButton({ ecosystem, pkg, hosts, className }: { ecosystem: string; pkg: string; hosts: string[]; className?: string }) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const plan = useMutation({
    mutationFn: async () => {
      const found = await api<Finding[]>(`/api/findings?${new URLSearchParams({ q: pkg, fixable: "true", limit: "5000" })}`);
      const ids = [...new Set(found.filter((f) => f.package === pkg && f.ecosystem === ecosystem && hosts.includes(f.hostname)).map((f) => f.asset_id))];
      if (!ids.length) throw new Error("Couldn't find these machines. Refresh and try again.");
      const errors: string[] = [];
      for (const asset_id of ids) {
        try { await api("/api/remediation/jobs", { method: "POST", body: { asset_id, ecosystem, package: pkg } }); }
        catch (e) { errors.push((e as Error).message); }
      }
      if (errors.length) throw new Error([...new Set(errors)].join(" "));
    },
    onSettled: () => qc.invalidateQueries({ queryKey: ["jobs"] }), // partial failures still created some jobs
    onSuccess: () => navigate({ to: "/remediation" }),
  });
  return (
    <div className={clsx("flex flex-col items-start gap-1.5", className)}>
      <button className={btnQuiet} disabled={plan.isPending} onClick={() => plan.mutate()}>
        <Wrench className="size-4" aria-hidden />{plan.isPending ? "Planning…" : "Plan fix"}
        <span className="sr-only"> for {pkg}{hosts.length > 1 ? ` on ${hosts.length} hosts` : ""}</span>
      </button>
      {plan.error && <p role="alert" className="max-w-sm text-sm text-now-fg">{plan.error.message}</p>}
    </div>
  );
}
