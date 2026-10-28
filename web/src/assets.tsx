import { useRef, useState } from "react";
import { Link } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Dialog, Switch } from "radix-ui";
import { AppWindow, ArrowRight, Plus, Trash2, Upload } from "lucide-react";
import { adminGate, AGENT_UPDATE, api, assetsQ, filtersToSearch, parseFilters, parseUtc, PRIORITIES, relativeTime, sbomSummary, useIsAdmin, useTitle, type Asset, type Criticality, type SbomResult } from "./lib";
import { Alert, btnPrimary, btnQuiet, ConfirmDialog, CopyBlock, dialogBox, Done, EmptyState, ErrorState, input, Loading, PriorityPill, switchRoot, switchThumb, Tag } from "./ui";
import clsx from "clsx";
import { ExternalTargets } from "./targets";

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
    onSuccess: (_d, { id }) => setSaved(id),
    // Context changes re-score findings, so everything derived from them is stale.
    onSettled: () => Promise.all(["assets", "findings", "summary", "finding"].map((k) => qc.invalidateQueries({ queryKey: [k] }))),
  });

  const [target, setTarget] = useState<Asset | null>(null);
  const [saved, setSaved] = useState("");  // the asset whose last change saved: it says so, and that findings were re-ranked
  const del = useMutation({
    mutationFn: (id: string) => api(`/api/assets/${id}`, { method: "DELETE" }),
    onSuccess: () => { setTarget(null); void Promise.all(["assets", "findings", "summary", "finding", "ledger", "jobs"].map((k) => qc.invalidateQueries({ queryKey: [k] }))); },
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
      <Alert error={patch.error} prefix="Couldn't save that change: " />

      {q.isPending ? <Loading className="h-20" rows={3} label="Loading assets…" />
        : q.error ? <ErrorState error={q.error} retry={() => q.refetch()} />
        : q.data.every((a) => a.kind === "external") ? (
          <EmptyState title="No machines yet" action={<Link to="/add" className={clsx(btnPrimary, "no-underline")}>Add your first machine</Link>}>
            Machines show up here once they report in.
          </EmptyState>
        ) : (
          <section aria-labelledby="machines-h" className="flex flex-col gap-3">
            <h2 id="machines-h" className="text-lg font-semibold">Machines and applications</h2>
            <ul className="flex flex-col divide-y divide-line overflow-hidden border border-line bg-surface">
              {q.data.filter((a) => a.kind !== "external").map((a) => <AssetRow key={a.id} a={a} saved={saved === a.id && !patch.isPending}
                onPatch={(p) => { setSaved(""); patch.mutate({ id: a.id, ...p }); }} onDelete={() => { del.reset(); setTarget(a); }} />)}
            </ul>
          </section>
        )}
      {q.data && <ExternalTargets targets={q.data.filter((a) => a.kind === "external")} onDelete={(a) => { del.reset(); setTarget(a); }} />}
      <ConfirmDialog open={!!target} onOpenChange={(o) => !o && setTarget(null)} title={`Delete ${target?.hostname}?`}
        description="Its findings and installed-software list are removed. The evidence ledger keeps the history of what was detected and fixed, so audit records stay intact. This can't be undone."
        confirmLabel="Delete asset" pendingLabel="Deleting…" pending={del.isPending} error={del.error} onConfirm={() => target && del.mutate(target.id)} />
    </div>
  );
}

export function AssetRow({ a, onPatch, onDelete, saved }: { a: Asset; onPatch: (p: AssetPatch) => void; onDelete: () => void; saved?: boolean }) {
  const admin = useIsAdmin();
  const open = PRIORITIES.filter((p) => a.open_by_priority[p]);
  return (
    <li className="flex flex-col gap-3 p-4">
      <div className="flex flex-wrap items-start justify-between gap-x-6 gap-y-2">
      <div className="min-w-0 flex-1 basis-60">
        <h3 className="flex flex-wrap items-center gap-2 text-base font-semibold"><span className="truncate">{a.hostname}</span>
          {a.sandbox && <Tag why="Test machine: the only kind automated fixes may change until production remediation is turned on">Test machine</Tag>}
          {a.not_reporting && <Tag tone="now" why="No report for over 14 hours, so findings may be out of date. Check the host is running and the agent's timer or scheduled task.">Not reporting</Tag>}
          {a.agent_update && a.agent_update !== "current" && <Tag tone={a.agent_update === "failed" ? "now" : "muted"}>{AGENT_UPDATE[a.agent_update].label}</Tag>}</h3>
        <p className="truncate text-sm text-muted">
          {a.kind === "application" ? "Application (SBOM)" : a.os_name || "Unknown OS"}{a.agent_version && ` · agent ${a.agent_version}`} · seen <time dateTime={parseUtc(a.last_seen).toISOString()} title={parseUtc(a.last_seen).toLocaleString()}>{relativeTime(a.last_seen)}</time>
        </p>
        {a.not_reporting && <p className="mt-1 text-xs text-now-fg">No report for over 14 hours, so findings may be out of date.</p>}
        {a.agent_update && !["current", "updating"].includes(a.agent_update) && (
          <p className={clsx("mt-1 text-xs", a.agent_update === "failed" ? "text-now-fg" : "text-muted")}>{AGENT_UPDATE[a.agent_update as Exclude<typeof a.agent_update, "current">].why(a)}</p>
        )}
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
        {a.kind === "host" && <><label className="flex items-center gap-2 text-sm">
          <span className="whitespace-nowrap text-muted">Ring</span>
          <select className={clsx(input, "w-auto md:min-h-9")} value={a.ring} onChange={(e) => onPatch({ ring: Number(e.target.value) as 0 | 1 })}>
            <option value={0}>Canary</option><option value={1}>Broad</option>
          </select>
        </label>
        <HealthUnits a={a} onPatch={onPatch} /></>}
        <SbomUpload a={a} />
        {saved && <Done className="text-muted">Saved. Findings re-ranked.</Done>}
        <button className={clsx(btnQuiet, "ml-auto px-2.5")} onClick={onDelete} title={`Delete ${a.hostname}`} {...adminGate(admin)}><Trash2 className="size-4" aria-hidden /><span className="sr-only">Delete {a.hostname}</span></button>
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
      <span className="whitespace-nowrap text-muted">Health units</span>
      <input className={clsx(input, "w-40 md:min-h-9")} value={text} placeholder="nginx, sshd" onChange={(e) => setText(e.target.value)} onBlur={commit}
        onKeyDown={(e) => e.key === "Enter" && commit()} title="systemd units that must be active before and after a fix" />
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
              <label className="flex flex-col gap-1 text-sm font-medium">Name
                <input className={input} value={name} onChange={(e) => setName(e.target.value)} maxLength={255} required autoComplete="off" placeholder="billing-service" />
              </label>
              <Alert error={create.error} />
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
    onSuccess: () => Promise.all(["assets", "findings", "summary", "finding", "ledger"].map((k) => qc.invalidateQueries({ queryKey: [k] }))),
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
        {up.error && <span role="alert" className="text-now-fg">SBOM rejected: {up.error.message}</span>}
      </div>
    </div>
  );
}
