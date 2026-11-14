import { Fragment, useState, type ReactNode } from "react";
import clsx from "clsx";
import { Link } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, TriangleAlert, Wrench, X } from "lucide-react";
import { adminGate, api, APPROVE_COPY, dependenciesNeeded, filtersToSearch, groupJobs, isActiveJob, jobAnchor, jobsQ, kbFleetQ, kbHostsQ, parseFilters, parseUtc, plural, refresh, relativeTime, useHashScroll, useIsAdmin, useTitle, meQ, assetsQ, settingsQ, type Asset, type Job, type KbRow } from "./lib";
import { Alert, btnQuiet, ConfirmDialog, EmptyState, ErrorState, Loading, StatusPill } from "./ui";

const CANCELLABLE: Job["status"][] = ["planned", "approved"];
const LAST_EVENT: Record<Job["status"], string> = { planned: "planned", approved: "approved", dispatched: "started", verifying: "applied", succeeded: "verified",
  failed: "failed", rolled_back: "rolled back", rollback_failed: "rollback failed", not_fixed: "checked", aborted: "aborted", cancelled: "cancelled" };
const AGAIN: Job["status"][] = ["failed", "rolled_back", "rollback_failed", "not_fixed"];

/** The packages a job changes, as the plan recorded them ({name, from, to?}). */
export function jobPackages(j: { packages?: unknown }): { name: string; from?: string; to?: string; kb?: string }[] {
  return Array.isArray(j.packages) ? j.packages.filter((p): p is { name: string } => !!p && typeof p === "object" && typeof (p as { name?: unknown }).name === "string") : [];
}

// shortcut: agents (<= 0.6.6) report a step that fell back and then succeeded as ok, recognised by its wording; send a `warn` flag from the agent if more appear.
const RECOVERED = /not available|rebuilding|rebuilt from|retry \d/i;
/** Return failed for a false result, recovered for recognised fallback text, or passed otherwise. */
export const stepState = (s: { step: string; ok: boolean; output?: string }) => (!s.ok ? "failed" : RECOVERED.test(s.step) || RECOVERED.test(s.output ?? "") ? "recovered" : "passed");

/** The packages a fix changes, with versions; for several machines, every package any of them changes and on how many. */
export function PackageList({ job, jobs }: { job: { packages?: unknown; summary?: string }; jobs?: { packages?: unknown; summary?: string; hostname?: string }[] }) {
  // several machines: every package any of them changes, and on how many when not all (DESIGN.md: dialogs list what will change)
  const all = jobs ?? [job];
  const seen = new Map<string, { p: ReturnType<typeof jobPackages>[number]; target?: string; n: number; froms: Set<string> }>();
  for (const j of all) {
    // shortcut: the plan's target lives only in its title ("… to X on host", or an older job's "(fixed in X)"); store it on the job if more views need it
    const target = (/ to (\S+) on \S+$/.exec(j.summary ?? "") ?? /\(fixed in ([^)]+)\)$/.exec(j.summary ?? ""))?.[1];
    for (const p of jobPackages(j)) { const e = seen.get(p.name); seen.set(p.name, { p: e?.p ?? p, target: e?.target ?? target, n: (e?.n ?? 0) + 1, froms: (e?.froms ?? new Set()).add(p.from ?? "?") }); }
  }
  if (!seen.size) return null;
  return (
    <ul className="mt-2 flex flex-col gap-0.5 text-sm" aria-label="Packages this fix changes">
      {[...seen.values()].map(({ p, target, n, froms }) => (
        <li key={p.name} className="break-words"><span className="font-medium">{p.name}</span>{" "}
          {/* a version never wraps mid-token: the arrow is where the line may break */}
          {/* mono only on the versions compared; the words around them are prose */}
          <span className="text-muted">{p.kb ? <span className="font-mono">{p.kb}</span> : <>{froms.size > 1 ? "several versions" : <span className="whitespace-nowrap font-mono">{p.from ?? "?"}</span>} → {p.to || target ? <span className="whitespace-nowrap font-mono">{p.to ?? target}</span> : "the newest fixed version"}{!p.to && target && " or the repository's newer"}</>}</span>
          {n < all.length && <span className="text-muted"> on {n} of {plural(all.length, "machine")}{(() => { const not = all.filter((j) => !jobPackages(j).some((q) => q.name === p.name)).map((j) => (j as { hostname?: string }).hostname).filter(Boolean); return not.length > 0 && not.length <= 3 ? ` (not ${not.join(", ")})` : ""; })()}</span>}</li>
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
  const prodBlocked = (j: Job) => prodOff && byId.get(j.asset_id)?.sandbox === false;
  const hold = (j: Job) => prodBlocked(j) ? "production remediation is off" : j.forward_only ? "can't be undone, so each is approved on its own" : null;
  const [several, setManyJobs] = useState<Job[] | null>(null);
  const [chosen, setChosen] = useState<Set<string>>(new Set());  // which of them to approve: all to start, untick to approve fewer
  const setMany = (js: Job[] | null) => { setManyJobs(js); setChosen(new Set(js?.map((j) => j.id))); };
  const picked = several?.filter((j) => chosen.has(j.id)) ?? [];
  // one approval request per machine: each is its own ledger entry and its own self-approval check, as approving them one by one
  const many = useMutation({
    mutationFn: async (js: Job[]) => {
      const refused: string[] = [];
      for (const j of js) {
        // untick each machine once approved, so a retry after a partial failure sends only what's still waiting
        try { await api<Job>(`/api/remediation/jobs/${j.id}/approve`, { method: "POST", body: { forward_only: false } }); setChosen((c) => { const n = new Set(c); n.delete(j.id); return n; }); }
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
  const card = (j: Job, inRollout?: boolean) => <JobCard key={j.id} job={j} inRollout={inRollout} blocked={prodBlocked(j) ? "production remediation is off" : undefined}
    onApprove={() => { approve.reset(); setTarget(j); }} onCancel={() => { cancel.reset(); setCancelling(j); }} />;
  useHashScroll(!!q.data);  // #job-<id> from Home, the finding drawer or Plan fix
  const groups = q.data ? sections(q.data) : [];

  return (
    <div className="flex flex-col gap-8">
      <header>
        <h1 className="text-3xl font-semibold">Remediation</h1>
        <p className="mt-1 max-w-prose text-muted">A fix is done once the next inventory proves the vulnerability gone.</p>
      </header>
      {q.isPending ? <Loading className="h-24" rows={3} label="Loading fixes…" />
        : q.error ? <ErrorState error={q.error} retry={() => q.refetch()} />
        : groups.length === 0 ? <EmptyState title="No fixes planned yet">Use “Plan fix” on a recommended fix or a finding. Nothing changes on a machine until you approve it.</EmptyState>
        : groups.map((g) => (
          <section key={g.key} aria-labelledby={`g-${g.key}`}>
            <h2 id={`g-${g.key}`} className="mb-3 flex items-center gap-2 text-lg font-semibold">{g.title}<span className="sr-only">: </span><span className="num border border-line px-2 text-sm font-medium text-muted">{plural(g.rollouts.length + g.singles.length, "fix", "fixes")}</span></h2>
            {(() => { const own = g.jobs.filter((j) => j.approved_by && j.approved_by === j.created_by).length; return own > 0 &&
              <p className="-mt-2 mb-3 text-sm text-warn-fg">{own === g.jobs.length ? (own === 1 ? "Self-approved" : own === 2 ? "Both self-approved" : `All ${own} self-approved`) : `${own} of ${g.jobs.length} self-approved`}: approved by the person who planned {own === 1 ? "it" : "them"}, with no second approver (SOC 2 CC8.1).</p>; })()}
            <ul className="flex flex-col gap-2">
              {g.rollouts.map((js) => <RolloutCard key={js[0]!.action_key} jobs={js} assets={assets.data ?? []} hold={hold} card={(j) => card(j, true)}
                onApprove={admin ? (sel) => { many.reset(); setMany(sel); } : undefined} />)}
              {g.singles.map((j) => card(j))}
            </ul>
          </section>
        ))}
      <KbFleet />
      <ApproveDialog job={target} context={machineContext(targetAsset)} unchecked={targetAsset?.kind === "host" && !targetAsset.health_units.length ? { assetId: targetAsset.id } : undefined}
        production={settings.data?.production_remediation_allowed === false && targetAsset?.sandbox === false}
        ahead={!!target && targetAsset?.ring !== 0 && !(q.data ?? []).some((j) => j.action_key === target.action_key && j.status === "succeeded" && byId.get(j.asset_id)?.ring === 0)} onOpenChange={(o) => !o && setTarget(null)} pending={approve.isPending} ownPlan={!!target && target.created_by === me}
        ringFailed={target ? ringFailures(q.data ?? [], target, byId) : []} onGo={() => setTarget(null)}
        error={approve.error?.message} onConfirm={() => target && approve.mutate(target)} />
      <ConfirmDialog open={!!several} onOpenChange={(o) => !o && setMany(null)} title={`Approve this fix on the ${byId.get(several?.[0]?.asset_id ?? "")?.ring === 0 ? "canary" : "broad"} ring?`}
        description={<><strong className="font-semibold">Upgrade {several?.[0]?.action_key.split("|")[1]}</strong>. Each machine is approved and recorded on its own, as if you approved them one by one.</>}
        confirmLabel={`Approve ${picked.length} and run`} pendingLabel="Approving…" pending={many.isPending} error={many.error} blocked={!picked.length} onConfirm={() => many.mutate(picked)}>
        {several && <>
          <RingFailure failed={ringFailures(q.data ?? [], several[0]!, byId)} onGo={() => setMany(null)} />
          <fieldset className="mt-3 text-sm">
            <legend className="text-muted">Machines to approve now</legend>
            <ul className="mt-1 flex flex-col sm:flex-row sm:flex-wrap sm:gap-x-4">
              {several.map((j) => (
                <li key={j.id}><label className="flex tap cursor-pointer items-center gap-2 whitespace-nowrap">
                  <input type="checkbox" className="size-4 accent-[var(--ink)]" checked={chosen.has(j.id)}
                    onChange={(e) => setChosen((c) => { const n = new Set(c); if (e.target.checked) n.add(j.id); else n.delete(j.id); return n; })} />
                  {j.hostname}{byId.get(j.asset_id)?.sandbox && <span className="text-muted">(test)</span>}
                </label></li>
              ))}
            </ul>
          </fieldset>
          {picked[0] && <PackageList job={picked[0]} jobs={picked} />}
          {/* the same sentence and place as the single-machine dialog: after what changes */}
          {(() => { const bare = picked.filter((j) => byId.get(j.asset_id)?.kind === "host" && !byId.get(j.asset_id)?.health_units.length); return bare.length > 0 &&
            <p className="mt-3 border border-now-fg p-3 text-sm">No health checks on {bare.map((j, i) => <Fragment key={j.id}>{i > 0 && (i === bare.length - 1 ? " and " : ", ")}<span className="whitespace-nowrap">{j.hostname}</span></Fragment>)}: a service this breaks won't be noticed or rolled back.</p>; })()}
          {picked.some((j) => j.created_by === me) && <p className="mt-3 border border-line p-3 text-sm">You planned {picked.every((j) => j.created_by === me) ? "these fixes" : "some of these fixes"}. Approving them yourself is recorded as self-approved for each machine: no second person checked the change (SOC 2 CC8.1).</p>}
          <details className="mt-3 text-sm text-muted"><summary className="flex tap w-fit cursor-pointer items-center">How a fix runs</summary><p className="mt-1">{APPROVE_COPY}</p></details>
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
        <span className="num text-sm">{r.fixed} of {plural(r.hosts, "machine")}</span>
      </p>
      <p className="mt-1 break-words text-sm text-muted">{r.product}, build {r.build}</p>
      {left > 0 && (
        <details className="group mt-2" onToggle={(e) => setOpen(e.currentTarget.open)}>
          <summary className="flex min-h-[44px] w-fit cursor-pointer items-center text-sm font-medium text-accent md:min-h-9">
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
export function JobCard({ job: j, onApprove, onCancel, blocked, inRollout }: { job: Job; onApprove?: () => void; onCancel?: () => void; blocked?: string; inRollout?: boolean }) {
  const admin = useIsAdmin();
  const steps = j.steps ?? [];
  const qc = useQueryClient();
  const deps = j.status === "aborted" ? dependenciesNeeded(j.error) : [];
  const [ecosystem, pkg] = j.action_key.split("|");
  // a waiting job planned for an older version than Fix first now recommends says so (DESIGN.md: numbers that agree)
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
            {/* inside a rollout the card above says the fix: each machine's card is titled by its machine */}
            {inRollout ? <Link to="/assets" search={{ machine: j.asset_id }} className="text-ink underline decoration-line-strong hover:decoration-ink">{j.hostname}</Link>
              : <Link to="/findings" search={filtersToSearch({ ...parseFilters({}), asset: j.asset_id, q: pkg ?? "", fixable: false })} className="text-ink underline decoration-line-strong hover:decoration-ink">{j.summary}</Link>}
          </p>
          {/* no dot separators: on a phone they'd start wrapped lines; spacing alone separates the facts */}
          <ul className="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1.5 text-sm text-muted">
            <li><StatusPill status={j.status} /></li>
            {/* the count lives here, not in the title (DESIGN.md: one title format) */}
            {j.finding_ids.length > 0 && !inRollout && !/to fix \d/.test(j.summary) && <li>fixes {plural(j.finding_ids.length, "finding")}</li>}
            {/* a name opens that thing's detail (DESIGN.md): the machine's drawer */}
            {!inRollout && <li className="min-w-0 break-all">on <Link to="/assets" search={{ machine: j.asset_id }} className="inline-flex tap items-center font-semibold text-ink underline decoration-line-strong hover:decoration-ink">{j.hostname}</Link></li>}
            {/* who planned and who approved, as one fact (DESIGN.md: one muted line per card) */}
            {(!inRollout || j.approved_by) && <li className="break-all">{j.approved_by === j.created_by ? `planned and approved by ${j.created_by}`
              : [!inRollout && `planned by ${j.created_by}`, j.approved_by && `approved by ${j.approved_by}`].filter(Boolean).join(", ")}</li>}
            {j.forward_only && <li className="text-now-fg">forward-only: no automatic rollback</li>}
            {j.waits_for_window && <li>waits for the maintenance window ({parseUtc(j.waits_for_window).toLocaleString()})</li>}
            {/* shown, not blocked: auditors look for this under SOC 2 CC8.1 */}
            {/* self-approval is said once per section (the owner's call); the card still shows who planned and who approved */}
            {/* the time of the latest event, named, so it never reads as the approval time */}
            <li>{LAST_EVENT[j.status]} <time dateTime={parseUtc(j.updated).toISOString()} title={parseUtc(j.updated).toLocaleString()}>{relativeTime(j.updated)}</time></li>
          </ul>
        </div>
        <div className="flex shrink-0 flex-wrap items-center gap-2">
          {j.status === "planned" && blocked && <p className="text-sm text-muted">Can't run: {blocked}</p>}
          {j.status === "planned" && onApprove && !blocked && (
            <button className={btnQuiet} onClick={onApprove} {...adminGate(admin)}><Check className="size-4" aria-hidden />Review and approve<span className="sr-only"> fix on {j.hostname}</span></button>
          )}
          {/* the main action first; cancelling is the trailing link (DESIGN.md: action row) */}
          {CANCELLABLE.includes(j.status) && onCancel && (
            <button className="tap inline-flex cursor-pointer items-center px-1 text-sm underline decoration-line-strong hover:decoration-ink disabled:cursor-not-allowed disabled:opacity-50" onClick={onCancel} {...adminGate(admin)}>Cancel fix<span className="sr-only"> on {j.hostname}</span></button>
          )}
        </div>
      </div>
      {j.status === "planned" && <PackageList job={j} />}
      {/* a cancel is deliberate: said plainly, never in the error box */}
      {j.error && (j.status === "cancelled" ? <p className="mt-2 text-sm text-muted">{j.error}.</p> : <RefusalNote error={j.error} />)}
      {j.status === "rolled_back" && <p className="mt-2 max-w-prose text-sm">Before planning it again, try it on a test machine; the service's log usually says why it wouldn't start.</p>}
      {AGAIN.includes(j.status) && deps.length === 0 && pkg && (blocked ? <p className="mt-3 text-sm text-muted">Can't plan it again here: {blocked}.</p>
        : <PlanFixButton ecosystem={ecosystem!} pkg={pkg} assetIds={[j.asset_id]} label={`Plan fix again on ${j.hostname}`} className="mt-3" />)}
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
          <summary className="flex min-h-[44px] w-fit cursor-pointer items-center text-sm font-medium text-accent md:min-h-9">
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
/** Machines in this job's ring where the same fix didn't work, judged by each machine's newest job (a later success lifts it, as on the server). */
export function ringFailures(jobs: Job[], job: Pick<Job, "action_key" | "asset_id">, byId: Map<string, Asset>): Job[] {
  const canaryRing = byId.get(job.asset_id)?.ring === 0, seen = new Set<string>();
  return jobs.filter((j) => j.action_key === job.action_key && j.status !== "cancelled" && !seen.has(j.asset_id) && !!seen.add(j.asset_id))
    .filter((j) => j.asset_id !== job.asset_id && STUCK.includes(j.status) && (byId.get(j.asset_id)?.ring === 0) === canaryRing);
}

/** The crimson first line of an approval when its ring has a failure; each machine opens its job (closing the dialog). */
function RingFailure({ failed, onGo }: { failed: Job[]; onGo?: () => void }) {
  if (!failed.length) return null;
  return (
    <p className="mt-3 border border-now-fg p-3 text-sm text-now-fg">This fix didn't work on {failed.map((j, i) => <Fragment key={j.id}>
      <Link to="/remediation" hash={jobAnchor(j.id)} onClick={onGo} className="whitespace-nowrap font-medium text-now-fg underline">{j.hostname}</Link>{i < failed.length - 1 ? ", " : ""}</Fragment>)}{" "}
      in this ring. Review {failed.length === 1 ? "it" : "them"} before approving more.</p>
  );
}

/** what broke first, then what waits on you, then what's running, then what's done (DESIGN.md page order) */
const urgency = (j: Job) => (STUCK.includes(j.status) ? 0 : j.status === "planned" ? 1 : MOVING.includes(j.status) ? 2 : 3);

/** One package's fix across several machines, as one card: canary and broad tallies, where it stands, a review per
 * ring, and every machine's own card inside. It sits once, in the section of its most urgent machine. */
export function RolloutCard({ jobs, assets, hold, onApprove, card }: {
  jobs: Job[]; assets: Asset[]; hold?: (j: Job) => string | null; onApprove?: (js: Job[]) => void; card?: (j: Job) => ReactNode;
}) {
  const ring = new Map(assets.map((a) => [a.id, a.ring]));
  // one job per machine, its newest (the list is newest first): a canary that failed and was then fixed counts as fixed, as the server judges it
  const seen = new Set<string>();
  const live = jobs.filter((j) => j.status !== "cancelled" && !seen.has(j.asset_id) && !!seen.add(j.asset_id));
  const tally = (js: Job[]) => {
    const n = (st: Job["status"][]) => js.filter((j) => st.includes(j.status)).length;
    return { total: js.length, fixed: n(FIXED), moving: n(MOVING), waiting: n(["planned"]), stuck: n(STUCK) };
  };
  const canary = tally(live.filter((j) => ring.get(j.asset_id) === 0)), broad = tally(live.filter((j) => ring.get(j.asset_id) !== 0));
  const [eco, pkg] = jobs[0]!.action_key.split("|");
  const stands = canary.stuck ? "A canary didn't work: review it before the rest go"
    : canary.total && canary.fixed < canary.total ? "Waiting on the canary machines"
    : broad.fixed + broad.stuck === broad.total ? (broad.stuck ? "Done, with machines to review" : "Done")
    : broad.waiting ? `${canary.total ? "Canary fixed: " : ""}approve the broad machines`
    : broad.moving ? `${canary.total ? "Canary fixed: " : ""}broad machines in progress`
    : canary.total ? "Canary fixed: plan the broad machines" : "No canary machine in this fix";
  const cell = (label: string, t: ReturnType<typeof tally>) => t.total > 0 && (
    <span className="num">{label} <strong className="font-semibold">{t.fixed} of {t.total}</strong> fixed
      {t.moving > 0 && <span className="text-muted"> · {t.moving} approved or running</span>}
      {t.waiting > 0 && <span className="text-muted"> · {t.waiting} awaiting approval</span>}
      {t.stuck > 0 && <span className="text-now-fg"> · {t.stuck} didn't work</span>}</span>);
  const waiting = live.filter((j) => j.status === "planned");
  const held = waiting.filter((j) => hold?.(j));
  // one review per ring, canary first: the broad ring waits until every canary machine is fixed (test, then production)
  const ringButton = (isCanary: boolean) => {
    const ready = waiting.filter((j) => (ring.get(j.asset_id) === 0) === isCanary && !hold?.(j));
    if (!onApprove || !ready.length) return null;
    const wait = !isCanary && canary.total > 0 && canary.fixed < canary.total;
    return (
      <button className={btnQuiet} disabled={wait} title={wait ? "Approve the broad ring once the canary machines are fixed" : undefined} onClick={() => onApprove(ready)}>
        <Check className="size-4" aria-hidden />Approve {isCanary ? "canary" : "broad"} ({ready.length})<span className="sr-only">, {pkg}</span>
      </button>
    );
  };
  const reasons = [...new Set(held.map((j) => hold!(j)!))];
  const linked = typeof location !== "undefined" && jobs.some((j) => location.hash === `#${jobAnchor(j.id)}`);
  return (
    <li className="border border-line bg-surface" aria-label={`${pkg} rollout`}>
      <div className="flex flex-col gap-3 p-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <p className="font-medium"><span className="font-semibold">Upgrade {pkg}{(() => { const t = (/ to (\S+) on \S+$/.exec(jobs[0]!.summary ?? ""))?.[1]; return t && <> to <span className="font-mono text-sm">{t}</span></>; })()}</span> <span className="text-sm text-muted">{eco}</span> <span className="text-sm">on {plural(new Set(live.map((j) => j.asset_id)).size, "machine")}</span></p>
          <p className="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-sm">{cell("Canary", canary)}{cell("Broad", broad)}</p>
          {/* "approve the broad machines" is what the button beside it says: said once (DESIGN.md: copy budget) */}
          {!(onApprove && waiting.some((j) => !hold?.(j)) && stands.endsWith("approve the broad machines")) && <p className={clsx("mt-1 text-sm", canary.stuck ? "text-now-fg" : "text-ink")}>{stands}</p>}
          {/* what broke is on the card, each machine a link to its job, not only a count inside the folded list */}
          {live.some((j) => STUCK.includes(j.status)) && <p className="mt-1 text-sm text-now-fg">Didn't work on {live.filter((j) => STUCK.includes(j.status)).map((j, i, all) => <Fragment key={j.id}>
            <Link to="/remediation" hash={jobAnchor(j.id)} className="whitespace-nowrap font-medium text-now-fg underline">{j.hostname}</Link>{i < all.length - 1 ? ", " : ""}</Fragment>)}: review before approving more.</p>}
          {reasons.map((r) => <p key={r} className="mt-1 text-sm text-muted">{plural(held.filter((j) => hold!(j) === r).length, "waiting machine")} left out: {r}</p>)}
        </div>
        <div className="flex shrink-0 flex-wrap gap-2">{ringButton(true)}{ringButton(false)}</div>
      </div>
      {card && (
        <details open={linked} className="border-t border-line">
          <summary className="flex tap w-fit cursor-pointer items-center gap-2 px-4 py-2 text-sm font-medium">
            Machines ({live.length}{jobs.length > live.length && `, plus ${jobs.length - live.length} cancelled`})
          </summary>
          {/* under their ring, so the tallies above read straight against the list */}
          <div className="flex flex-col gap-2 bg-sunken p-2">
            {([["Canary", jobs.filter((j) => ring.get(j.asset_id) === 0)], ["Broad", jobs.filter((j) => ring.get(j.asset_id) !== 0)]] as [string, Job[]][])
              // the ring with what broke comes first (DESIGN.md: lead with what broke)
              .sort((x, y) => Math.min(9, ...x[1].map(urgency)) - Math.min(9, ...y[1].map(urgency))).map(([label, js]) => js.length > 0 && (
              <section key={label} aria-label={`${label} machines`}>
                <h4 className="px-1 pb-1 text-xs font-medium text-muted">{label}</h4>
                <ul className="flex flex-col gap-2">{[...js].sort((x, y) => urgency(x) - urgency(y)).map(card)}</ul>
              </section>
            ))}
          </div>
        </details>
      )}
    </li>
  );
}

/** The page's sections, what broke first: a rollout (one package on two or more machines) sits once, in the section
 * of its most urgent machine; every other job sits in its own status's section. */
export function sections(jobs: Job[]) {
  const machines = new Map<string, Set<string>>();
  for (const j of jobs) if (j.status !== "cancelled") machines.set(j.action_key, (machines.get(j.action_key) ?? new Set()).add(j.asset_id));
  const isRollout = (j: Job) => (machines.get(j.action_key)?.size ?? 0) > 1;
  const placed = new Set<string>();
  return groupJobs(jobs).map((g) => {
    const rollouts = byPackage(g.jobs.filter((j) => j.status !== "cancelled" && isRollout(j) && !placed.has(j.action_key)))
      .map((js) => { placed.add(js[0]!.action_key); return jobs.filter((j) => j.action_key === js[0]!.action_key); });
    const singles = g.jobs.filter((j) => !isRollout(j));
    // the count and the self-approval line are about jobs in this section's own statuses, not a rollout's others
    const shown = [...rollouts.flat(), ...singles];
    return { ...g, rollouts, singles, jobs: shown.filter((j) => (g.statuses as readonly string[]).includes(j.status)) };
  }).filter((g) => g.rollouts.length || g.singles.length);
}

/** Pure view (no network) so the copy can be tested. */
/** "build-runner-01 · critical · canary · test machine · health checks: nginx": what the approver should know about the target. */
export const machineContext = (a?: Asset) => a && [a.hostname, `${a.criticality} criticality`, a.ring === 0 ? "canary (fixed first)" : "broad ring",
  a.sandbox ? "test machine" : "production", a.health_units.length ? `health checks: ${a.health_units.join(", ")}` : "no health checks set"].join(" · ");

/** Render a controlled approval dialog with package scope, host context, and forward-only acknowledgement. */
export function ApproveDialog({ job, onOpenChange, onConfirm, pending, error, ownPlan, context, unchecked, production, ahead, ringFailed = [], onGo }: {
  /** machines in this job's ring where the same fix didn't work (their newest job): said first */
  ringFailed?: Job[]; onGo?: () => void;
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
      <RingFailure failed={ringFailed} onGo={onGo} />
      {ahead && !production && <p className="mt-3 border border-next-fg p-3 text-sm">This fix hasn't succeeded on a canary machine yet. Approving runs it on {job?.hostname} now, ahead of the canary; automatic rollout would wait.</p>}
      {production && <p className="mt-3 border border-now-fg p-3 text-sm">{job?.hostname} is a production machine, and this server changes test machines only, so this fix can't run yet. <Link to="/settings" hash="remediation" className="font-medium underline">How to turn production remediation on</Link></p>}
      {context && <p className="mt-2 text-sm text-muted">{context}</p>}
      {job && <PackageList job={job} />}
      {unchecked && <p className="mt-3 border border-now-fg p-3 text-sm">No health checks on {job?.hostname}: a service this breaks won't be noticed or rolled back. <Link to="/assets" search={{ machine: unchecked.assetId }} className="font-medium underline">Set its health checks</Link></p>}
      {ownPlan && <p className="mt-3 border border-line p-3 text-sm">You planned this fix. Approving it yourself is recorded as self-approved: no second person checked the change (SOC 2 CC8.1).</p>}
      {fwd ? <p className="mt-3 border border-now-fg p-3 text-sm">This app's installer can't go back to the version it replaces, so if the new version breaks something there is no automatic rollback. The machine's health checks still run and a failure is reported. Approving records that you accepted this.</p>
        : <details className="mt-3 text-sm text-muted"><summary className="flex tap w-fit cursor-pointer items-center">How a fix runs</summary><p className="mt-1">{APPROVE_COPY}</p></details>}
    </ConfirmDialog>
  );
}

/** The agent's refusal as a sentence a person reads; the raw text stays one click away for support. */
export function plainRefusal(error: string): string | null {
  const deps = dependenciesNeeded(error);
  if (deps.length) return `Nothing was changed. The upgrade would also have changed ${deps.join(", ")}, which wasn't in the plan, so the machine refused it.`;
  // a health check that failed after the change: the agent's wording names the unit and how often it restarted
  const unit = /([\w@.-]+?)(?:\.service)? active after change failed/.exec(error);
  if (unit) {
    const n = /restarted (\d+) times/.exec(error)?.[1];
    return `${unit[1]} didn't start properly after the upgrade${n ? ` (restarted ${n} times)` : ""}, so the change was rolled back.`;
  }
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
