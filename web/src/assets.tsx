import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Switch } from "radix-ui";
import { ArrowRight, Plus } from "lucide-react";
import { api, assetsQ, filtersToSearch, parseFilters, PRIORITIES, relativeTime, useTitle, type Asset, type Criticality } from "./lib";
import { btnPrimary, EmptyState, ErrorState, input, PriorityPill, Skeleton } from "./ui";
import clsx from "clsx";

type AssetPatch = Partial<Pick<Asset, "criticality" | "internet_facing" | "ring" | "health_units">>;
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
      const prev = qc.getQueryData<Asset[]>(assetsQ.queryKey);
      qc.setQueryData<Asset[]>(assetsQ.queryKey, (a) => a?.map((x) => (x.id === id ? { ...x, ...body } : x)));
      return { prev };
    },
    onError: (_e, _v, ctx) => qc.setQueryData(assetsQ.queryKey, ctx?.prev),
    // Context changes re-score findings, so everything derived from them is stale.
    onSettled: () => Promise.all(["assets", "findings", "summary", "finding"].map((k) => qc.invalidateQueries({ queryKey: [k] }))),
  });

  return (
    <div className="flex flex-col gap-6">
      <header className="flex items-center justify-between gap-4">
        <h1 className="text-3xl font-semibold">Assets</h1>
        <Link to="/add" className={clsx(btnPrimary, "no-underline")}><Plus className="size-4" aria-hidden />Add machine</Link>
      </header>
      {patch.error && <p role="alert" className="rounded-md bg-now-bg px-3 py-2 text-sm text-now-fg">Couldn't save that change: {patch.error.message}</p>}

      {q.isPending ? <div className="flex flex-col gap-2">{[0, 1, 2].map((i) => <Skeleton key={i} className="h-20" />)}</div>
        : q.error ? <ErrorState error={q.error} retry={() => q.refetch()} />
        : q.data.length === 0 ? (
          <EmptyState title="No machines yet" action={<Link to="/add" className={clsx(btnPrimary, "no-underline")}>Add your first machine</Link>}>
            Machines show up here once they report in.
          </EmptyState>
        ) : (
          <ul className="flex flex-col divide-y divide-line overflow-hidden rounded-lg border border-line bg-surface">
            {q.data.map((a) => <AssetRow key={a.id} a={a} onPatch={(p) => patch.mutate({ id: a.id, ...p })} />)}
          </ul>
        )}
    </div>
  );
}

function AssetRow({ a, onPatch }: { a: Asset; onPatch: (p: AssetPatch) => void }) {
  const open = PRIORITIES.filter((p) => a.open_by_priority[p]);
  return (
    <li className="grid gap-x-6 gap-y-3 p-4 lg:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)_auto] lg:items-center">
      <div className="min-w-0">
        <h2 className="flex items-center gap-2 text-base font-semibold"><span className="truncate">{a.hostname}</span>
          {a.sandbox && <span title="Disposable test machine: the only kind remediation may change until production remediation is enabled" className="shrink-0 rounded border border-line-strong px-1.5 py-px text-[11px] font-semibold tracking-wide text-muted">Sandbox</span>}</h2>
        <p className="truncate text-sm text-muted">
          {a.os_name || "Unknown OS"} · seen <time dateTime={a.last_seen + "Z"} title={new Date(a.last_seen + "Z").toLocaleString()}>{relativeTime(a.last_seen)}</time>
        </p>
      </div>
      <div className="flex flex-wrap items-center gap-1.5">
        {open.length === 0 ? <span className="text-sm text-muted">No open findings</span> : open.map((p) => (
          <Link key={p} to="/findings" search={filtersToSearch({ ...parseFilters({}), asset: a.id, priority: [p], fixable: false })} className="no-underline">
            <PriorityPill priority={p} count={a.open_by_priority[p]} />
          </Link>
        ))}
        {open.length > 0 && (
          <Link to="/findings" search={filtersToSearch({ ...parseFilters({}), asset: a.id })} aria-label={`View findings for ${a.hostname}`} className="ml-1 text-muted hover:text-ink"><ArrowRight className="size-4" aria-hidden /></Link>
        )}
      </div>
      <div className="flex flex-wrap items-center gap-x-5 gap-y-2">
        <label className="flex items-center gap-2 text-sm">
          <span className="text-muted">Criticality</span>
          <select className={clsx(input, "min-h-9 w-auto capitalize")} value={a.criticality} onChange={(e) => onPatch({ criticality: e.target.value as Criticality })}>
            {LEVELS.map((l) => <option key={l} value={l}>{l}</option>)}
          </select>
        </label>
        <label className="flex cursor-pointer items-center gap-2 text-sm">
          <Switch.Root checked={a.internet_facing} onCheckedChange={(internet_facing) => onPatch({ internet_facing })}
            className="relative h-5 w-9 shrink-0 cursor-pointer rounded-full bg-line-strong data-[state=checked]:bg-accent">
            <Switch.Thumb className="block size-4 translate-x-0.5 rounded-full bg-surface transition-transform data-[state=checked]:translate-x-[18px]" />
          </Switch.Root>
          Internet-facing
        </label>
        <label className="flex items-center gap-2 text-sm">
          <span className="text-muted">Ring</span>
          <select className={clsx(input, "min-h-9 w-auto")} value={a.ring} onChange={(e) => onPatch({ ring: Number(e.target.value) as 0 | 1 })}>
            <option value={0}>Canary</option><option value={1}>Broad</option>
          </select>
        </label>
        <HealthUnits a={a} onPatch={onPatch} />
      </div>
    </li>
  );
}

/** Comma-separated systemd units checked before and after a fix; saved on blur / Enter. */
function HealthUnits({ a, onPatch }: { a: Asset; onPatch: (p: AssetPatch) => void }) {
  const saved = a.health_units.join(", ");
  const [text, setText] = useState(saved);
  const commit = () => {
    const units = text.split(",").map((u) => u.trim()).filter(Boolean);
    if (units.join(", ") !== saved) onPatch({ health_units: units });
  };
  return (
    <label className="flex items-center gap-2 text-sm">
      <span className="text-muted">Health units</span>
      <input className={clsx(input, "min-h-9 w-48")} value={text} placeholder="nginx, sshd" onChange={(e) => setText(e.target.value)} onBlur={commit}
        onKeyDown={(e) => e.key === "Enter" && commit()} title="systemd units that must be active before and after a fix" />
    </label>
  );
}
