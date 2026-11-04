import { useEffect, useRef, useState } from "react";
import { Link } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Dialog, Switch } from "radix-ui";
import { AppWindow, ArrowRight, Plus, Trash2, Upload } from "lucide-react";
import { adminGate, AGENT_UPDATE, api, refresh, assetsQ, coverageQ, filtersToSearch, parseFilters, parseUtc, plural, PRIORITIES, relativeTime, sbomSummary, updateSource, useIsAdmin, useTitle, type Asset, type Criticality, type SbomResult } from "./lib";
import { Alert, btnPrimary, btnQuiet, ConfirmDialog, CopyBlock, dialogBox, Done, EmptyState, ErrorState, Field, input, Loading, PriorityPill, switchRoot, switchThumb, Tag } from "./ui";
import clsx from "clsx";
import { ExternalTargets } from "./targets";

type AssetPatch = Partial<Pick<Asset, "criticality" | "internet_facing" | "directory_source" | "ring" | "health_units">>;
const LEVELS: Criticality[] = ["low", "medium", "high", "critical"];

export function AssetsPage() {
  useTitle("Assets");
  const qc = useQueryClient();
  const q = useQuery(assetsQ);

  const patch = useMutation({
    mutationFn: ({ id, ...body }: { id: string } & AssetPatch) =>
      api(`/api/assets/${id}`, { method: "PATCH", body }),
    onMutate: async ({ id, ...body }) => {
      await qc.cancelQueries({ queryKey: assetsQ.queryKey });
      const prev = qc.getQueryData<Asset[]>(assetsQ.queryKey)?.find((x) => x.id === id);
      qc.setQueryData<Asset[]>(assetsQ.queryKey, (a) => a?.map((x) => (x.id === id ? { ...x, ...body } : x)));
      return { prev };
    },
    // Roll back only the asset that failed, so a concurrent edit to another row isn't undone with it.
    onError: (e, { id }, ctx) => {
      if (ctx?.prev) qc.setQueryData<Asset[]>(assetsQ.queryKey, (a) => a?.map((x) => (x.id === id ? ctx.prev! : x)));
      setFailed({ id, message: e.message });
    },
    onSuccess: (_d, { id }) => setSaved(id),
    // Context changes re-score findings, so everything derived from them is stale.
    onSettled: () => refresh(qc, "assets"),
  });

  const [target, setTarget] = useState<Asset | null>(null);
  const [saved, setSaved] = useState("");  // the asset whose last change saved: it says so, and that findings were re-ranked
  const [failed, setFailed] = useState<{ id: string; message: string } | null>(null);  // shown on that row, not the page top
  const admin = useIsAdmin();
  const del = useMutation({
    mutationFn: (id: string) => api(`/api/assets/${id}`, { method: "DELETE" }),
    onSuccess: () => { setTarget(null); void refresh(qc, "assets"); },
  });

  return (
    <div className="flex flex-col gap-6">
      <header className="flex flex-wrap items-center justify-between gap-x-4 gap-y-3">
        <h1 className="w-full text-3xl font-semibold sm:w-auto">Assets</h1>
        <div className="flex flex-wrap items-center gap-2">
          <AddApplication />
          <Link to="/add" className={clsx(btnPrimary, "no-underline")}><Plus className="size-4" aria-hidden />Add machine</Link>
        </div>
      </header>

      <Unmanaged />
      <AttackPaths />
      <Baselines />
      <NotAssessed />

      {q.isPending ? <Loading className="h-20" rows={3} label="Loading assets…" />
        : q.error ? <ErrorState error={q.error} retry={() => q.refetch()} />
        : q.data.every((a) => a.kind === "external") ? (
          <EmptyState title="No machines yet" action={<Link to="/add" className={clsx(btnPrimary, "no-underline")}>Add your first machine</Link>}>
            Machines show up here once they report in.
          </EmptyState>
        ) : (
          <section aria-labelledby="machines-h" className="flex flex-col gap-3">
            <h2 id="machines-h" className="text-lg font-semibold">Machines and applications</h2>
            {admin && (
              <p className="max-w-prose text-sm text-muted">
                <strong className="font-medium text-ink">Ring:</strong> canary machines get a fix first; broad machines wait until a canary has stayed healthy.{" "}
                <strong className="font-medium text-ink">Health units:</strong> systemd units checked before and after a fix, saved when you leave the field.
              </p>
            )}
            <AgentUpdateSummary assets={q.data.filter((a) => a.kind === "host")} />
            <ul className="flex flex-col divide-y divide-line overflow-hidden border border-line bg-surface">
              {q.data.filter((a) => a.kind !== "external").map((a) => <AssetRow key={a.id} a={a} saved={saved === a.id && !patch.isPending}
                error={failed?.id === a.id ? failed.message : undefined}
                onPatch={(p) => { setSaved(""); setFailed(null); patch.mutate({ id: a.id, ...p }); }} onDelete={() => { del.reset(); setTarget(a); }} />)}
            </ul>
          </section>
        )}
      {q.data && <ExternalTargets targets={q.data.filter((a) => a.kind === "external")} onDelete={(a) => { del.reset(); setTarget(a); }} />}
      <ConfirmDialog open={!!target} onOpenChange={(o) => !o && setTarget(null)} title={`Delete ${target?.hostname}?`}
        description="Its findings and installed-software list are removed. The evidence ledger keeps the history of what was detected and fixed, so audit records stay intact. This can't be undone."
        confirmLabel="Delete asset" pendingLabel="Deleting…" destructive pending={del.isPending} error={del.error} onConfirm={() => target && del.mutate(target.id)} />
    </div>
  );
}

/** Agents that can't update themselves, said once for the list, grouped by reason, instead of on every row. */
interface UnmanagedComputer { domain: string; name: string; os: string; os_version: string; last_logon: string; end_of_support: string | null }

/** Windows computers in Active Directory that have no agent (plan T43); nothing shows until an agent reports a domain. */
function Unmanaged() {
  const q = useQuery({ queryKey: ["directory-unmanaged"], queryFn: () => api<UnmanagedComputer[]>("/api/directory/unmanaged") });
  const rows = q.data ?? [];
  if (!rows.length) return null;
  const domains = [...new Set(rows.map((r) => r.domain))].join(", ");
  const eos = rows.filter((r) => r.end_of_support).length;
  return (
    <section aria-labelledby="unmanaged" className="flex flex-col gap-2 border border-line bg-sunken p-4">
      <h2 id="unmanaged" className="text-base font-semibold">{rows.length} Windows computer{rows.length === 1 ? "" : "s"} in {domains} {rows.length === 1 ? "has" : "have"} no agent</h2>
      <p className="text-sm text-muted">Enabled in Active Directory and signed in within 30 days, but not reporting here, so nothing about them is checked.{eos ? ` ${eos} run Windows that no longer gets security updates.` : ""}</p>
      <details className="text-sm">
        <summary className="min-h-[44px] cursor-pointer py-2 md:min-h-0">Show them</summary>
        <ul className="mt-2 flex flex-col gap-1">
          {rows.slice(0, 200).map((r) => <li key={r.domain + r.name} className="break-all"><span className="font-medium">{r.name}</span> · {r.os || "unknown OS"}{r.end_of_support && <span className="text-now-fg"> · {r.end_of_support}: out of support</span>}</li>)}
        </ul>
      </details>
      <a href="/api/directory/unmanaged?format=csv" className="text-sm">Download as CSV</a>
    </section>
  );
}

interface BaselineCounts { name: string; version: string; automated: number; manual: number; pass: number; fail: number; not_assessed: number; not_applicable: number }
interface BaselineHost extends BaselineCounts { asset_id: string; hostname: string }
interface BaselineRule { id: string; severity: string; status: string; setting: string; expected: string; found: string; note: string }

/** "12 of 31 automated checks pass": rules that don't apply to this host aren't counted, and nothing here claims conformance. */
export function baselineSummary(c: BaselineCounts) {
  return `${c.pass} of ${c.automated - c.not_applicable} checks we can automate pass, ${c.fail} fail, ${c.not_assessed} not assessed`;
}

const RULE_ORDER = ["fail", "not assessed", "pass", "not applicable"];

function BaselineHostRow({ h }: { h: BaselineHost }) {
  const [open, setOpen] = useState(false);
  const q = useQuery({ queryKey: ["baseline", h.asset_id], enabled: open, queryFn: () => api<{ rules: BaselineRule[] }>(`/api/baselines/${h.asset_id}`) });
  const rules = [...(q.data?.rules ?? [])].sort((a, b) => RULE_ORDER.indexOf(a.status) - RULE_ORDER.indexOf(b.status));
  return (
    <li>
      <details className="text-sm" onToggle={(e) => setOpen(e.currentTarget.open)}>
        <summary className="min-h-[44px] cursor-pointer break-words py-2 md:min-h-0"><span className="font-medium">{h.hostname}</span>: {baselineSummary(h)}</summary>
        {q.isLoading && <Loading />}
        <Alert error={q.error} />
        <ul className="mt-2 flex flex-col gap-2">
          {rules.map((r) => (
            <li key={r.id} className="break-words border-t border-line pt-2">
              <span className={clsx("font-medium", r.status === "fail" && "text-now-fg")}>{r.status}</span> · {r.id} · {r.severity}
              <div className="text-muted">{r.setting}: expected {r.expected}, read {r.found}{r.note && `. ${r.note}`}</div>
            </li>
          ))}
        </ul>
      </details>
    </li>
  );
}

/** Settings compared with published baselines (DECISIONS 75): a reference. Manual checks are never assessed, and it says so. */
export function Baselines() {
  const q = useQuery({ queryKey: ["baselines"], queryFn: () => api<{ baselines: (BaselineCounts & { baseline_id: string; hosts: number })[]; hosts: BaselineHost[]; no_baseline: number }>("/api/baselines") });
  const d = q.data;
  if (!d?.hosts.length) return null;
  return (
    <section aria-labelledby="baselines" className="flex flex-col gap-2 border border-line bg-sunken p-4">
      <h2 id="baselines" className="text-base font-semibold">Windows settings compared with published baselines</h2>
      <p className="max-w-prose text-sm text-muted">A reference, not a conformance result: a pass means the setting read as the baseline expects. Only the checks we can automate are counted, and manual checks are not assessed.{d.no_baseline ? ` ${plural(d.no_baseline, "Windows host")} on other versions ${d.no_baseline === 1 ? "has" : "have"} no baseline here.` : ""}</p>
      {d.baselines.map((b) => (
        <div key={b.baseline_id} className="flex flex-col gap-1">
          <h3 className="text-sm font-semibold">{b.name} {b.version}</h3>
          <p className="text-sm">{plural(b.hosts, "host")}, {b.automated} checks we can automate and {b.manual} manual checks not assessed. Across these hosts: {b.pass} pass, {b.fail} fail, {b.not_assessed} not assessed.</p>
          <ul className="flex flex-col">
            {d.hosts.filter((h) => h.name === b.name && h.version === b.version).map((h) => <BaselineHostRow key={h.asset_id} h={h} />)}
          </ul>
        </div>
      ))}
      <a href="/api/baselines.csv" className="flex min-h-[44px] items-center text-sm md:min-h-0">Download as CSV</a>
    </section>
  );
}

interface PathSummary { kind: "network" | "foothold"; start: string; grade: string; steps: string[]; break_at: { label: string; fixes: number; refs: string[] } }
interface FleetHost { hostname: string; judged: boolean; paths: PathSummary[] }
interface Reach { host: string; hops: string[]; grade: string; fix_on_host: string[] }
interface AttackPathsData { hosts: Record<string, FleetHost>; truncated?: boolean; chains: { start: string; why_start: string; reach: Reach[] }[] }

/** How weaknesses chain on each host and from one host to the next (DECISIONS 97, 98): every step is evidence, and the grade is the weakest one's. */
export function AttackPaths() {
  const q = useQuery({ queryKey: ["attack-paths"], queryFn: () => api<AttackPathsData>("/api/attack-paths") });
  const d = q.data;
  const withPaths = Object.entries(d?.hosts ?? {}).filter(([, h]) => h.paths.length);
  if (!d || (!withPaths.length && !d.chains.length)) return null;
  const name = (id: string) => d.hosts[id]?.hostname ?? id;
  const unjudged = Object.values(d.hosts).filter((h) => !h.judged).length;
  return (
    <section aria-labelledby="attack-paths" className="flex flex-col gap-2 border border-line bg-sunken p-4">
      <h2 id="attack-paths" className="text-base font-semibold">How these weaknesses combine</h2>
      <p className="max-w-prose text-sm text-muted">Each step is a vulnerability or a setting read on the host. A path is only as sure as its weakest step, and whether one host can route to another isn't seen, so nothing across hosts is better than reasonable. Each host's part rests on what its own agent reported, so a compromised host could make its own links look worse or better.{unjudged ? ` ${plural(unjudged, "host")} ${unjudged === 1 ? "hasn't" : "haven't"} been judged yet.` : ""}{d.truncated ? " So many hosts link to each other that only the first links are shown: fix the settings named below first." : ""}</p>
      {d.chains.map((c) => (
        <div key={c.start} className="flex flex-col gap-1">
          <h3 className="text-sm font-semibold">From {name(c.start)} ({c.why_start}), an attacker can reach {plural(c.reach.length, "other host")}</h3>
          <ul className="flex flex-col gap-1 text-sm">
            {c.reach.map((r) => (
              <li key={r.host} className="break-words">
                <span className="font-medium">{name(r.host)}</span> via {[c.start, ...r.hops].map(name).join(" → ")} · how sure: {r.grade} · cut it on {name(r.host)}: {r.fix_on_host.join(", ")}
              </li>
            ))}
          </ul>
        </div>
      ))}
      <details className="text-sm">
        <summary className="min-h-[44px] cursor-pointer py-2 md:min-h-0">Paths on each host ({withPaths.length})</summary>
        <ul className="mt-2 flex flex-col gap-2">
          {withPaths.map(([id, h]) => h.paths.map((p) => (
            <li key={id + p.kind} className="break-words border-t border-line pt-2">
              <span className="font-medium">{h.hostname}</span>, {p.start} · how sure: {p.grade}
              <div className="text-muted">{p.steps.join(" → ")}. Break it: fix {plural(p.break_at.fixes, "way")} of {p.break_at.label.toLowerCase()} ({p.break_at.refs.join(", ")})</div>
            </li>
          )))}
        </ul>
      </details>
    </section>
  );
}

/** Software the curated rules don't cover (DECISIONS 24): listed, never matched, so saying so is part of every clean result. */
export function NotAssessed() {
  const q = useQuery(coverageQ);
  if (!q.data?.inventory_only) return null;
  const { assessed, inventory_only: only, not_assessed: rows } = q.data;
  return (
    <section aria-labelledby="not-assessed" className="flex flex-col gap-2 border border-line bg-sunken p-4">
      <h2 id="not-assessed" className="text-base font-semibold">{plural(only, "installed app")} {only === 1 ? "isn't" : "aren't"} checked for vulnerabilities</h2>
      <p className="max-w-prose text-sm text-muted">{plural(assessed, "install")} of known apps {assessed === 1 ? "is" : "are"} checked. The rest are listed but never matched, because a wrong guess is worse than saying so. Many are runtimes and drivers, but no finding for them doesn't mean they're safe.</p>
      <details className="text-sm">
        <summary className="min-h-[44px] cursor-pointer py-2 md:min-h-0">Show them, most common first</summary>
        <ul className="mt-2 flex flex-col gap-1">
          {rows.map((r) => <li key={`${r.name}|${r.publisher}`} className="break-words"><span className="font-medium">{r.name}</span>{r.publisher && ` · ${r.publisher}`} · {plural(r.hosts, "machine")}</li>)}
        </ul>
      </details>
    </section>
  );
}

export function AgentUpdateSummary({ assets }: { assets: Asset[] }) {
  const groups = new Map<string, { failed: boolean; hosts: string[] }>();
  for (const a of assets) {
    if (!a.agent_update || ["current", "updating"].includes(a.agent_update)) continue;
    const why = AGENT_UPDATE[a.agent_update as Exclude<typeof a.agent_update, "current">].why(a);
    const g = groups.get(why) ?? { failed: a.agent_update === "failed", hosts: [] };
    g.hosts.push(a.hostname);
    groups.set(why, g);
  }
  if (!groups.size) return null;
  return (
    <ul className="flex flex-col gap-1.5 border border-line-strong bg-surface px-3 py-2 text-sm">
      {[...groups].map(([why, g]) => (
        <li key={why} className={clsx("break-words", g.failed && "text-now-fg")}>
          <strong className="font-semibold">{g.hosts.join(", ")}:</strong> {why}
        </li>
      ))}
    </ul>
  );
}

export function AssetRow({ a, onPatch, onDelete, saved, error }: { a: Asset; onPatch: (p: AssetPatch) => void; onDelete: () => void; saved?: boolean; error?: string }) {
  const admin = useIsAdmin();
  const open = PRIORITIES.filter((p) => a.open_by_priority[p]);
  const host = a.kind === "host";
  return (
    <li className="flex flex-col gap-3 p-4">
      <div className="flex flex-wrap items-start justify-between gap-x-6 gap-y-2">
      <div className="min-w-0 flex-1 basis-60">
        <h3 className="flex flex-wrap items-center gap-2 text-base font-semibold"><span className="min-w-0 break-all" title={a.hostname}>{a.hostname}</span>
          {a.sandbox && <Tag why="Test machine: the only kind automated fixes may change until production remediation is turned on">Test machine</Tag>}
          {a.not_reporting && <Tag tone="now" why="No report for over 14 hours, so findings may be out of date. Check the host is running and the agent's timer or scheduled task.">Not reporting</Tag>}
          {a.agent_update && a.agent_update !== "current" && <Tag tone={a.agent_update === "failed" ? "now" : "muted"}>{AGENT_UPDATE[a.agent_update].label}</Tag>}</h3>
        <p className="truncate text-sm text-muted">
          {a.kind === "application" ? "Application (SBOM)" : a.os_name || "Unknown OS"}{a.agent_version && ` · agent ${a.agent_version}`} · seen <time dateTime={parseUtc(a.last_seen).toISOString()} title={parseUtc(a.last_seen).toLocaleString()}>{relativeTime(a.last_seen)}</time>
        </p>
        {a.not_reporting && <p className="mt-1 text-xs text-now-fg">No report for over 14 hours, so findings may be out of date.</p>}
        {a.apps && a.apps.inventory_only > 0 && <p className="mt-1 text-xs text-muted">{a.apps.assessed === 0 ? `None of its ${plural(a.apps.inventory_only, "installed app")} could be checked.` : `${a.apps.assessed} of ${a.apps.assessed + a.apps.inventory_only} installed apps checked; the rest are listed only.`}</p>}
        {a.facts?.os_unmatched && <p className="mt-1 text-xs text-muted">OS not matched to Microsoft's fixes: {a.facts.os_unmatched}. Apps and end of support are still checked.</p>}
        {a.facts?.pending_reboot && <p className="mt-1 text-xs text-next-fg">Updates are installed and waiting for a restart: findings close after it.</p>}
        {updateSource(a.facts) && <p className="mt-1 text-xs text-muted">{updateSource(a.facts)}</p>}
      </div>
      <div className="flex flex-wrap items-center gap-1.5">
        {open.length === 0 ? <span className="text-sm text-muted">No open findings</span> : open.map((p) => (
          <Link key={p} to="/findings" search={filtersToSearch({ ...parseFilters({}), asset: a.id, priority: [p], fixable: false })} className="inline-flex min-h-[44px] items-center no-underline md:min-h-0">
            <PriorityPill priority={p} count={a.open_by_priority[p]} />
          </Link>
        ))}
        {open.length > 0 && (
          <Link to="/findings" search={filtersToSearch({ ...parseFilters({}), asset: a.id })} aria-label={`View findings for ${a.hostname}`} className="inline-flex size-[44px] items-center justify-center text-muted hover:bg-sunken hover:text-ink md:size-9"><ArrowRight className="size-4" aria-hidden /></Link>
        )}
      </div>
      </div>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        {/* The API only lets admins change these; everyone else reads them (as in Settings). */}
        {!admin ? (
          <p className="text-sm text-muted">
            Criticality: <span className="capitalize text-ink">{a.criticality}</span> · {a.internet_facing ? "Internet-facing" : "Not internet-facing"}
            {host && <> · Ring: <span className="text-ink">{a.ring === 0 ? "Canary" : "Broad"}</span> · Health units: <span className="text-ink">{a.health_units.join(", ") || "none"}</span></>}
          </p>
        ) : <>
        <label className="flex items-center gap-2 text-sm">
          <span className="whitespace-nowrap text-muted">Criticality</span>
          <select className={clsx(input, "w-auto capitalize md:min-h-9")} value={a.criticality} onChange={(e) => onPatch({ criticality: e.target.value as Criticality })}>
            {LEVELS.map((l) => <option key={l} value={l}>{l}</option>)}
          </select>
        </label>
        <label className="flex min-h-[44px] cursor-pointer items-center gap-2 whitespace-nowrap text-sm md:min-h-0">
          <Switch.Root checked={a.internet_facing} onCheckedChange={(internet_facing) => onPatch({ internet_facing })} className={switchRoot}>
            <Switch.Thumb className={switchThumb} />
          </Switch.Root>
          Internet-facing
        </label>
        {a.kind === "host" && (a.directory_source || (typeof a.facts?.domain_role === "number" && a.facts.domain_role >= 1)) && (
          <label className="flex min-h-[44px] cursor-pointer items-center gap-2 whitespace-nowrap text-sm md:min-h-0"
            title="Only this machine's agent may send the domain's computer list (with --ad-discovery); any other host is refused">
            <Switch.Root checked={!!a.directory_source} onCheckedChange={(directory_source) => onPatch({ directory_source })} className={switchRoot}>
              <Switch.Thumb className={switchThumb} />
            </Switch.Root>
            Directory source
          </label>
        )}
        {a.kind === "host" && <><label className="flex items-center gap-2 text-sm">
          <span className="whitespace-nowrap text-muted">Ring</span>
          <select className={clsx(input, "w-auto md:min-h-9")} value={a.ring} onChange={(e) => onPatch({ ring: Number(e.target.value) as 0 | 1 })}>
            <option value={0}>Canary</option><option value={1}>Broad</option>
          </select>
        </label>
        <HealthUnits a={a} onPatch={onPatch} /></>}
        </>}
        <SbomUpload a={a} />
        {saved && <Done className="text-muted">Saved. Findings re-ranked.</Done>}
        <button className={clsx(btnQuiet, "ml-auto px-3 md:px-2.5")} onClick={onDelete} title={`Delete ${a.hostname}`} {...adminGate(admin)}>
          <Trash2 className="size-4" aria-hidden /><span className="md:sr-only">Delete</span><span className="sr-only"> {a.hostname}</span>
        </button>
      </div>
      <Alert error={error} prefix="Couldn't save that change: " />
    </li>
  );
}

/** Comma-separated systemd units checked before and after a fix; saved on blur / Enter. */
function HealthUnits({ a, onPatch }: { a: Asset; onPatch: (p: AssetPatch) => void }) {
  const saved = a.health_units.join(", ");
  const [text, setText] = useState(saved);
  useEffect(() => setText(saved), [saved]);  // re-sync after a save or a rollback
  const commit = () => {
    const units = text.split(",").map((u) => u.trim()).filter(Boolean);
    if (units.join(", ") !== saved) onPatch({ health_units: units });
  };
  return (
    <label className="flex items-center gap-2 text-sm">
      <span className="whitespace-nowrap text-muted">Health units</span>
      <input className={clsx(input, "w-40 md:min-h-9")} value={text} placeholder="nginx, sshd" onChange={(e) => setText(e.target.value)} onBlur={commit}
        onKeyDown={(e) => e.key === "Enter" && commit()} aria-describedby="health-units-hint" />
      <span id="health-units-hint" className="sr-only">systemd units checked before and after a fix; saved when you leave the field</span>
    </label>
  );
}

/** Creates an agent-less application asset; the one-time upload token lets CI post SBOMs without a login. */
function AddApplication() {
  const admin = useIsAdmin();
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [made, setMade] = useState<{ id: string; name: string; token: string } | null>(null);
  const create = useMutation({
    mutationFn: (n: string) => api<Asset & { upload_token: string }>("/api/assets", { method: "POST", body: { name: n } }),
    onSuccess: (a) => { setMade({ id: a.id, name: a.hostname, token: a.upload_token }); setName(""); void qc.invalidateQueries({ queryKey: ["assets"] }); },
  });
  const close = (o: boolean) => { setOpen(o); if (!o) { setMade(null); create.reset(); } };
  return (
    <Dialog.Root open={open} onOpenChange={close}>
      <Dialog.Trigger className={btnQuiet} {...adminGate(admin)}><AppWindow className="size-4" aria-hidden />Add application</Dialog.Trigger>
      <Dialog.Portal>
        <Dialog.Overlay className="overlay" />
        <Dialog.Content className={dialogBox}>
          <Dialog.Title className="text-lg font-semibold">Add an application</Dialog.Title>
          {made ? (
            <>
              <Dialog.Description className="mt-2 text-sm">
                <strong>{made.name}</strong> was added. Upload its CycloneDX SBOM from the Assets page, or from CI with this token (shown once):
              </Dialog.Description>
              <div className="mt-3">
                <CopyBlock label="Upload command for CI" text={`curl -X POST -H "Authorization: Bearer ${made.token}" \\
  --data-binary @bom.json ${location.origin}/api/assets/${made.id}/sbom`} />
              </div>
              <div className="mt-5 flex justify-end"><Dialog.Close className={btnPrimary}>Done</Dialog.Close></div>
            </>
          ) : (
            <form className="mt-3 flex flex-col gap-3" onSubmit={(e) => { e.preventDefault(); if (name.trim()) create.mutate(name.trim()); }}>
              <Dialog.Description className="text-sm text-muted">Software without an agent: findings come from the CycloneDX SBOM you upload.</Dialog.Description>
              <Field label="Name" error={create.error?.message}>
                <input className={input} value={name} onChange={(e) => setName(e.target.value)} maxLength={255} required autoComplete="off" placeholder="billing-service" />
              </Field>
              <div className="flex justify-end gap-2">
                <Dialog.Close className={btnQuiet}>Cancel</Dialog.Close>
                <button className={btnPrimary} disabled={create.isPending || !name.trim()}>{create.isPending ? "Adding…" : "Add application"}</button>
              </div>
            </form>
          )}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

/** Button -> file picker -> POST of the raw CycloneDX JSON. The result is announced in a live region. */
export function SbomUpload({ a }: { a: Asset }) {
  const qc = useQueryClient();
  const admin = useIsAdmin();
  const file = useRef<HTMLInputElement>(null);
  const up = useMutation({
    mutationFn: async (f: File) => api<SbomResult>(`/api/assets/${a.id}/sbom`, { method: "POST", body: await f.text() }),
    onSuccess: () => refresh(qc, "assets"),
  });
  return (
    <div className="flex flex-col gap-1">
      <button className={btnQuiet} disabled={up.isPending} aria-label={`Upload SBOM for ${a.hostname}`} onClick={() => file.current?.click()} {...adminGate(admin)}>
        <Upload className="size-4" aria-hidden />{up.isPending ? "Uploading…" : "Upload SBOM"}
      </button>
      <input ref={file} type="file" accept=".json,application/json" hidden tabIndex={-1} data-testid={`sbom-file-${a.id}`}
        onChange={(e) => { const f = e.target.files?.[0]; e.target.value = ""; if (f) up.mutate(f); }} />
      <div aria-live="polite" className="max-w-sm text-xs text-muted">
        {up.data && <span role="status">{sbomSummary(up.data)}</span>}
      </div>
      <Alert error={up.error} prefix="SBOM rejected: " />
    </div>
  );
}
