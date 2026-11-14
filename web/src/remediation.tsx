import { Fragment, useState } from "react";
import clsx from "clsx";
import { Link } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, ChevronRight, TriangleAlert, Wrench, X } from "lucide-react";
import { adminGate, api, APPROVE_COPY, dependenciesNeeded, filtersToSearch, groupJobs, isActiveJob, jobAnchor, jobsQ, kbFleetQ, kbHostsQ, parseFilters, parseUtc, plural, refresh, relativeTime, useHashScroll, useIsAdmin, useTitle, meQ, assetsQ, settingsQ, type Asset, type Job, type KbRow } from "./lib";
import { Alert, btnPrimary, btnQuiet, ConfirmDialog, EmptyState, ErrorState, Loading, StatusPill } from "./ui";

const CANCELLABLE: Job["status"][] = ["planned", "approved"];
const AGAIN: Job["status"][] = ["failed", "rolled_back", "rollback_failed", "not_fixed"];

/** The packages a job changes, as the plan recorded them ({name, from, to?}). */
export function jobPackages(j: { packages?: unknown }): { name: string; from?: string; to?: string; kb?: string }[] {
  return Array.isArray(j.packages) ? j.packages.filter((p): p is { name: string } => !!p && typeof p === "object" && typeof (p as { name?: unknown }).name === "string") : [];
}

// shortcut: agents (<= 0.6.6) report a step that fell back and then succeeded as ok, recognised by its wording; send a `warn` flag from the agent if more appear.
const RECOVERED = /not available|rebuilding|rebuilt from|retry \d/i;
/** Return failed for a false result, recovered for recognised fallback text, or passed otherwise. */
export const stepState = (s: { step: string; ok: boolean; output?: string }) => (!s.ok ? "failed" : RECOVERED.test(s.step) || RECOVERED.test(s.output ?? "") ? "recovered" : "passed");

function PackageList({ job }: { job: { packages?: unknown; summary?: string } }) {
  const pkgs = jobPackages(job);
  // shortcut: the plan's target lives only in its title ("… to X on host", or an older job's "(fixed in X)"); store it on the job if more views need it
  const target = (/ to (\S+) on \S+$/.exec(job.summary ?? "") ?? /\(fixed in ([^)]+)\)$/.exec(job.summary ?? ""))?.[1];
  if (!pkgs.length) return null;
  return (
    <ul className="mt-2 flex flex-col gap-0.5 text-sm" aria-label="Packages this fix changes">
      {pkgs.map((p) => (
        <li key={p.name} className="break-words"><span className="font-medium">{p.name}</span>{" "}
          <span className="font-mono text-muted">{p.kb ? p.kb : <>{p.from ?? "?"} → {p.to ?? (target ? `${target} or the repository's newer` : "the newest fixed version")}</>}</span></li>
      ))}
    </ul>
  );
}

/** Render grouped remediation jobs and poll while execution or verification remains active. */
export function RemediationPage() {
  useTitle("Remediation");
  const qc = useQueryClient();
  // Poll while anything is approved/dispatched/verifying.
  const q = useQuery({ ...jobsQ, refetchInterval: (query) => (query.state.data?.some(isActiveJob) ? 3000 : false) });
  const [target, setTarget] = useState<Job | null>(null);
  const me = useQuery(meQ).data?.email;
  const assets = useQuery(assetsQ);
  const targetAsset = assets.data?.find((a) => a.id === target?.asset_id);
  const settings = useQuery(settingsQ);
  const admin = useIsAdmin();
  const byId = new Map((assets.data ?? []).map((a) => [a.id, a]));
  const prodOff = settings.data?.production_remediation_allowed === false;
  // what one approval may cover: not a production machine while that's off, not a fix that can't be undone (that one gets its own dialog)
  const approvable = (j: Job) => !j.forward_only && !(prodOff && byId.get(j.asset_id)?.sandbox === false);
  const [several, setManyJobs] = useState<Job[] | null>(null);
  const [chosen, setChosen] = useState<Set<string>>(new Set());  // which of them to approve: all to start, untick to approve fewer
  const setMany = (js: Job[] | null) => { setManyJobs(js); setChosen(new Set(js?.map((j) => j.id))); };
  const picked = several?.filter((j) => chosen.has(j.id)) ?? [];
  // one approval request per machine: each is its own ledger entry and its own self-approval check, as approving them one by one
  const many = useMutation({
    mutationFn: async (js: Job[]) => {
      const refused: string[] = [];
      for (const j of js) {
        try { await api<Job>(`/api/remediation/jobs/${j.id}/approve`, { method: "POST", body: { forward_only: false } }); }
        catch (e) { refused.push(`${j.hostname}: ${(e as Error).message}`); }
      }
      if (refused.length) throw new Error(`${plural(js.length - refused.length, "machine")} approved. Not approved: ${refused.join("; ")}`);
    },
    onSuccess: () => setMany(null),
    onSettled: () => void refresh(qc, "jobs"),
  });
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
        <p className="mt-1 max-w-prose text-muted">Every fix is planned first, approved by a person (unless you enable auto), and only counted as done once the next inventory proves the vulnerability is gone.</p>
      </header>
      {q.data && <Rollouts jobs={q.data} assets={assets.data ?? []} canApprove={approvable} onApprove={admin ? (js) => { many.reset(); setMany(js); } : undefined} />}
      {q.isPending ? <Loading className="h-24" rows={3} label="Loading fixes…" />
        : q.error ? <ErrorState error={q.error} retry={() => q.refetch()} />
        : groups.length === 0 ? <EmptyState title="No fixes planned yet">Use “Plan fix” on a recommended fix or a finding. Nothing changes on a machine until you approve it.</EmptyState>
        : groups.map((g) => (
          <section key={g.key} aria-labelledby={`g-${g.key}`}>
            <h2 id={`g-${g.key}`} className="mb-3 flex items-center gap-2 text-lg font-semibold">{g.title}<span className="sr-only">: </span><span className="num border border-line px-2 text-sm font-medium text-muted">{g.jobs.length}</span></h2>
            {(() => { const own = g.jobs.filter((j) => j.approved_by && j.approved_by === j.created_by).length; return own > 0 &&
              <p className="-mt-2 mb-3 text-sm text-warn-fg">{own === g.jobs.length ? (own === 1 ? "Self-approved" : own === 2 ? "Both self-approved" : `All ${own} self-approved`) : `${own} of ${g.jobs.length} self-approved`}: approved by the person who planned {own === 1 ? "it" : "them"}, with no second approver (SOC 2 CC8.1).</p>; })()}
            <ul className="flex flex-col gap-2">
              {byPackage(g.jobs).map((js) => {
                const card = (j: Job) => <JobCard key={j.id} job={j} onApprove={() => { approve.reset(); setTarget(j); }} onCancel={() => { cancel.reset(); setCancelling(j); }} />;
                if (js.length < 3) return js.map(card);
                // three or more machines for one package fold into one block: the Rollouts table above has their totals
                const linked = js.some((j) => location.hash === `#${jobAnchor(j.id)}`);
                return (
                  <li key={js[0]!.action_key + g.key}>
                    <details open={linked} className="border border-line bg-surface">
                      <summary className="group/sum flex tap cursor-pointer flex-wrap items-center gap-x-3 gap-y-1 px-4 py-3">
                        <ChevronRight aria-hidden className="size-4 shrink-0 transition-transform [details[open]_&]:rotate-90" />
                        <span className="font-semibold">{js[0]!.action_key.split("|")[1]}</span><span className="text-sm text-muted">{js[0]!.action_key.split("|")[0]}</span>
                        <span className="text-sm">on {plural(js.length, "machine")}</span>
                        <span className="min-w-0 truncate text-sm text-muted">{js.slice(0, 3).map((j) => j.hostname).join(", ")}{js.length > 3 && ` and ${js.length - 3} more`}</span>
                      </summary>
                      <ul className="flex flex-col gap-2 border-t border-line bg-sunken p-2">{js.map(card)}</ul>
                    </details>
                  </li>
                );
              })}
            </ul>
          </section>
        ))}
      <KbFleet />
      <ApproveDialog job={target} context={machineContext(targetAsset)} unchecked={targetAsset?.kind === "host" && !targetAsset.health_units.length ? { assetId: targetAsset.id } : undefined}
        production={settings.data?.production_remediation_allowed === false && targetAsset?.sandbox === false}
        ahead={!!target && targetAsset?.ring !== 0 && !(q.data ?? []).some((j) => j.action_key === target.action_key && j.status === "succeeded" && byId.get(j.asset_id)?.ring === 0)} onOpenChange={(o) => !o && setTarget(null)} pending={approve.isPending} ownPlan={!!target && target.created_by === me}
        error={approve.error?.message} onConfirm={() => target && approve.mutate(target)} />
      <ConfirmDialog open={!!several} onOpenChange={(o) => !o && setMany(null)} title={`Approve this fix on the ${byId.get(several?.[0]?.asset_id ?? "")?.ring === 0 ? "canary" : "broad"} ring?`}
        description={<><strong className="font-semibold">Upgrade {several?.[0]?.action_key.split("|")[1]}</strong>. Each machine is approved and recorded on its own, as if you approved them one by one.</>}
        confirmLabel={`Approve ${picked.length} and run`} pendingLabel="Approving…" pending={many.isPending} error={many.error} blocked={!picked.length} onConfirm={() => many.mutate(picked)}>
        {several && <>
          <fieldset className="mt-3 text-sm">
            <legend className="text-muted">Machines to approve now</legend>
            <ul className="mt-1 flex flex-wrap gap-x-4">
              {several.map((j) => (
                <li key={j.id}><label className="flex tap cursor-pointer items-center gap-2 whitespace-nowrap">
                  <input type="checkbox" className="size-4 accent-[var(--ink)]" checked={chosen.has(j.id)}
                    onChange={(e) => setChosen((c) => { const n = new Set(c); if (e.target.checked) n.add(j.id); else n.delete(j.id); return n; })} />
                  {j.hostname}{byId.get(j.asset_id)?.sandbox && <span className="text-muted">(test)</span>}
                </label></li>
              ))}
            </ul>
          </fieldset>
          {several[0] && <PackageList job={several[0]} />}
          {(() => { const bare = picked.filter((j) => byId.get(j.asset_id)?.kind === "host" && !byId.get(j.asset_id)?.health_units.length); return bare.length > 0 &&
            <p className="mt-3 border border-now-fg p-3 text-sm">No health checks are set on {bare.map((j) => <Fragment key={j.id}><span className="whitespace-nowrap">{j.hostname},</span>{" "}</Fragment>)}so a service this upgrade breaks there isn't noticed and isn't rolled back; only a failed upgrade is.</p>; })()}
          {picked.some((j) => j.created_by === me) && <p className="mt-3 border border-line p-3 text-sm">You planned {picked.every((j) => j.created_by === me) ? "these fixes" : "some of these fixes"}. Approving them yourself is recorded as self-approved for each machine: no second person checked the change (SOC 2 CC8.1).</p>}
          <p className="mt-3 border border-line p-3 text-sm">{APPROVE_COPY}</p>
        </>}
      </ConfirmDialog>
      <ConfirmDialog open={!!cancelling} onOpenChange={(o) => !o && setCancelling(null)} title="Cancel this fix?"
        description={<><strong className="font-semibold">{cancelling?.summary}</strong>. No machine has picked it up yet, so nothing has changed on {cancelling?.hostname}. You can plan it again later.</>}
        confirmLabel="Cancel fix" cancelLabel="Keep it" pendingLabel="Cancelling…" pending={cancel.isPending} error={cancel.error} onConfirm={() => cancelling && cancel.mutate(cancelling.id)} />
    </div>
  );
}

/** "October 2026 cumulative KB…: 41 of 50 hosts", opening to the rest and why each hasn't got it. Nothing to show on a fleet with no Windows. */
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

/** Render job state, packages, steps, and optional approval/cancellation actions. */
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
            {/* the count lives here, not in the title (DESIGN.md: one title format) */}
            {j.finding_ids.length > 0 && <li>fixes {plural(j.finding_ids.length, "vulnerability", "vulnerabilities")}</li>}
            {/* a name opens that thing's detail (DESIGN.md): the machine's drawer */}
            <li className="min-w-0 break-all">on <Link to="/assets" search={{ machine: j.asset_id }} className="inline-flex tap items-center font-semibold text-ink underline decoration-line-strong hover:decoration-ink">{j.hostname}</Link></li>
            <li className="break-all">planned by {j.created_by}</li>
            {j.approved_by && <li className="break-all">approved by {j.approved_by}</li>}
            {j.forward_only && <li className="text-now-fg">forward-only: no automatic rollback</li>}
            {j.waits_for_window && <li>waits for the maintenance window ({parseUtc(j.waits_for_window).toLocaleString()})</li>}
            {/* shown, not blocked: auditors look for this under SOC 2 CC8.1 */}
            {/* self-approval is said once per section (the owner's call); the card still shows who planned and who approved */}
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
      {/* a cancel is deliberate: said plainly, never in the error box */}
      {j.error && (j.status === "cancelled" ? <p className="mt-2 text-sm text-muted">{j.error}.</p> : <RefusalNote error={j.error} />)}
      {j.status === "rolled_back" && <p className="mt-2 max-w-prose text-sm">Before planning it again: try it on a test or canary machine first, and check that the service named above works with the new version (its log usually says why it wouldn't start).</p>}
      {AGAIN.includes(j.status) && deps.length === 0 && pkg && <PlanFixButton ecosystem={ecosystem!} pkg={pkg} assetIds={[j.asset_id]} label="Plan fix again" className="mt-3" />}
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

/** Jobs for the same package together, in the order the first of each arrived. */
export function byPackage(jobs: Job[]): Job[][] {
  const m = new Map<string, Job[]>();
  for (const j of jobs) m.set(j.action_key, [...(m.get(j.action_key) ?? []), j]);
  return [...m.values()];
}

const FIXED: Job["status"][] = ["succeeded"], MOVING: Job["status"][] = ["approved", "dispatched", "verifying"];
const STUCK: Job["status"][] = ["failed", "rolled_back", "rollback_failed", "not_fixed", "aborted"];

/** One package's fix across several machines, canary ring first: what's fixed, moving, waiting and stuck in each ring.
 * The job cards below stay the place to approve each machine; this is where the rollout as a whole shows. */
export function Rollouts({ jobs, assets, canApprove, onApprove }: { jobs: Job[]; assets: Asset[]; canApprove?: (j: Job) => boolean; onApprove?: (js: Job[]) => void }) {
  const ring = new Map(assets.map((a) => [a.id, a.ring]));
  const by = new Map<string, Job[]>();
  for (const j of jobs) if (j.status !== "cancelled") by.set(j.action_key, [...(by.get(j.action_key) ?? []), j]);
  const rows = [...by].filter(([, js]) => new Set(js.map((j) => j.asset_id)).size > 1);
  if (!rows.length) return null;
  const tally = (js: Job[]) => {
    const n = (st: Job["status"][]) => js.filter((j) => st.includes(j.status)).length;
    return { total: js.length, fixed: n(FIXED), moving: n(MOVING), waiting: n(["planned"]), stuck: n(STUCK) };
  };
  // one review per ring, canary first: the broad ring's approval waits until every canary machine is fixed, so the
  // test-then-production order holds. Each machine's own card still approves it alone.
  const approveRing = (js: Job[], isCanary: boolean, pkg: string, held: boolean) => {
    const ready = js.filter((j) => (ring.get(j.asset_id) === 0) === isCanary && j.status === "planned" && (canApprove?.(j) ?? true));
    if (!onApprove || !ready.length) return null;
    return (
      <div className="mt-2"><button className={btnQuiet} disabled={held} title={held ? "Approve the broad ring once the canary machines are fixed" : undefined} onClick={() => onApprove(ready)}>
        <Check className="size-4" aria-hidden />Approve {isCanary ? "canary" : "broad"} ({ready.length})<span className="sr-only">, {pkg}</span>
      </button></div>
    );
  };
  const cell = (t: ReturnType<typeof tally>) => !t.total ? <span className="text-muted">none</span> : (
    <span className="num"><strong className="font-semibold">{t.fixed} of {t.total}</strong> fixed
      {t.moving > 0 && <span className="text-muted"> · {t.moving} running</span>}
      {t.waiting > 0 && <span className="text-muted"> · {t.waiting} awaiting approval</span>}
      {t.stuck > 0 && <span className="text-now-fg"> · {t.stuck} didn't work</span>}</span>);
  return (
    <section aria-labelledby="rollouts">
      <h2 id="rollouts" className="mb-1 text-lg font-semibold">Rollouts</h2>
      <p className="mb-3 max-w-prose text-sm text-muted">A fix on several machines goes to canary machines first; broad machines follow once a canary has stayed healthy.</p>
      {/* a table from md up; on phones each rollout stacks into a card, every cell labelled */}
      <div className="border border-line bg-surface">
        <table className="block w-full border-collapse text-sm md:table">
          <thead className="hidden text-left text-xs text-muted md:table-header-group"><tr className="border-b border-line">
            <th scope="col" className="px-3 py-2 font-normal">Package</th><th scope="col" className="px-3 py-2 font-normal">Canary</th>
            <th scope="col" className="px-3 py-2 font-normal">Broad</th><th scope="col" className="px-3 py-2 font-normal">Where it stands</th>
          </tr></thead>
          <tbody className="block divide-y divide-line md:table-row-group">
            {rows.map(([key, js]) => {
              const [eco, pkg] = key.split("|");
              const canary = tally(js.filter((j) => ring.get(j.asset_id) === 0)), broad = tally(js.filter((j) => ring.get(j.asset_id) !== 0));
              const stands = canary.stuck ? "A canary didn't work: review it before the rest go"
                : canary.total && canary.fixed < canary.total ? "Waiting on the canary machines"
                : broad.fixed + broad.stuck === broad.total ? (broad.stuck ? "Done, with machines to review" : "Done")
                : broad.waiting ? `${canary.total ? "Canary fixed: " : ""}approve the broad machines (${broad.waiting} waiting)`
                : broad.moving ? `${canary.total ? "Canary fixed: " : ""}broad machines running`
                : canary.total ? "Canary fixed: plan the broad machines" : "No canary machine in this fix";
              return (
                <tr key={key} className="block py-1 align-top md:table-row md:py-0">
                  <td className="block px-3 py-1.5 md:table-cell md:py-2"><span className="font-semibold">{pkg}</span> <span className="text-muted">{eco}</span></td>
                  <td className="block px-3 py-1.5 md:table-cell md:py-2"><span className="text-xs text-muted md:hidden">Canary: </span>{cell(canary)}{approveRing(js, true, pkg ?? key, false)}</td>
                  <td className="block px-3 py-1.5 md:table-cell md:py-2"><span className="text-xs text-muted md:hidden">Broad: </span>{cell(broad)}{approveRing(js, false, pkg ?? key, canary.total > 0 && canary.fixed < canary.total)}</td>
                  <td className={clsx("block px-3 py-1.5 md:table-cell md:py-2", canary.stuck ? "text-now-fg" : "text-ink")}>{stands}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}

/** Pure view (no network) so the copy can be tested. */
/** "build-runner-01 · critical · canary · test machine · health checks: nginx": what the approver should know about the target. */
export const machineContext = (a?: Asset) => a && [a.hostname, `${a.criticality} criticality`, a.ring === 0 ? "canary (fixed first)" : "broad ring",
  a.sandbox ? "test machine" : "production", a.health_units.length ? `health checks: ${a.health_units.join(", ")}` : "no health checks set"].join(" · ");

/** Render a controlled approval dialog with package scope, host context, and forward-only acknowledgement. */
export function ApproveDialog({ job, onOpenChange, onConfirm, pending, error, ownPlan, context, unchecked, production, ahead }: {
  job: (Pick<Job, "summary" | "hostname"> & { forward_only?: boolean; packages?: unknown; manager?: string }) | null; onOpenChange: (o: boolean) => void; onConfirm: () => void; pending?: boolean; error?: string; ownPlan?: boolean; context?: string;
  /** the target host has no health checks: say what that means before it runs */
  unchecked?: { assetId: string };
  /** a production machine while this server changes test machines only: approving can't run, so it isn't offered */
  production?: boolean;
  /** a broad-ring machine whose fix hasn't succeeded on a canary yet: allowed (a person's call), but said */
  ahead?: boolean;
}) {
  const fwd = !!job?.forward_only;
  return (
    <ConfirmDialog open={!!job} onOpenChange={onOpenChange} title={fwd ? "Approve a fix that can't be undone?" : "Approve this fix?"} description={<><strong className="font-semibold">{job?.summary}</strong>.</>}
      confirmLabel={fwd ? "Approve: it can't be undone" : "Approve and run"} pendingLabel="Approving…" destructive={fwd} pending={pending} error={error} onConfirm={onConfirm} blocked={production}>
      {ahead && !production && <p className="mt-3 border border-next-fg p-3 text-sm">This fix hasn't succeeded on a canary machine yet. Approving runs it on {job?.hostname} now, ahead of the canary; automatic rollout would wait.</p>}
      {production && <p className="mt-3 border border-now-fg p-3 text-sm">{job?.hostname} is a production machine, and this server changes test machines only, so this fix can't run yet. <Link to="/settings" hash="remediation" className="font-medium underline">How to turn production remediation on</Link></p>}
      {context && <p className="mt-2 text-sm text-muted">{context}</p>}
      {job && <PackageList job={job} />}
      {unchecked && <p className="mt-3 border border-now-fg p-3 text-sm">No health checks are set on {job?.hostname}, so a service this upgrade breaks isn't noticed and isn't rolled back; only a failed upgrade is. <Link to="/assets" search={{ machine: unchecked.assetId }} className="font-medium underline">Set its health checks</Link></p>}
      {ownPlan && <p className="mt-3 border border-line p-3 text-sm">You planned this fix. Approving it yourself is recorded as self-approved: no second person checked the change (SOC 2 CC8.1).</p>}
      {fwd ? <p className="mt-3 border border-now-fg p-3 text-sm">This app's installer can't go back to the version it replaces, so if the new version breaks something there is no automatic rollback. The machine's health checks still run and a failure is reported. Approving records that you accepted this.</p>
        : <p className="mt-3 border border-line p-3 text-sm">{APPROVE_COPY}</p>}
    </ConfirmDialog>
  );
}

/** The agent's refusal as a sentence a person reads; the raw text stays one click away for support. */
export function plainRefusal(error: string): string | null {
  const deps = dependenciesNeeded(error);
  if (deps.length) return `Nothing was changed. The upgrade would also have changed ${deps.join(", ")}, which wasn't in the plan, so the machine refused it.`;
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
