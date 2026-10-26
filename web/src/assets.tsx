import { useRef, useState } from "react";
import { Link } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertDialog, Dialog, Switch } from "radix-ui";
import { AppWindow, ArrowRight, Plus, Trash2, Upload } from "lucide-react";
import { adminGate, api, assetsQ, filtersToSearch, parseFilters, PRIORITIES, relativeTime, sbomSummary, useIsAdmin, useTitle, type Asset, type Criticality, type SbomResult } from "./lib";
import { btnPrimary, btnQuiet, EmptyState, ErrorState, input, PriorityPill, Skeleton } from "./ui";
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
    // Context changes re-score findings, so everything derived from them is stale.
    onSettled: () => Promise.all(["assets", "findings", "summary", "finding"].map((k) => qc.invalidateQueries({ queryKey: [k] }))),
  });

  const [target, setTarget] = useState<Asset | null>(null);
  const del = useMutation({
    mutationFn: (id: string) => api(`/api/assets/${id}`, { method: "DELETE" }),
    onSuccess: () => { setTarget(null); void Promise.all(["assets", "findings", "summary", "finding", "ledger", "jobs"].map((k) => qc.invalidateQueries({ queryKey: [k] }))); },
  });

  return (
    <div className="flex flex-col gap-6">
      <header className="flex items-center justify-between gap-4">
        <h1 className="text-3xl font-semibold">Assets</h1>
        <div className="flex flex-wrap items-center gap-2">
          <AddApplication />
          <Link to="/add" className={clsx(btnPrimary, "no-underline")}><Plus className="size-4" aria-hidden />Add machine</Link>
        </div>
      </header>
      {patch.error && <p role="alert" className="rounded-md bg-now-bg px-3 py-2 text-sm text-now-fg">Couldn't save that change: {patch.error.message}</p>}

      {q.isPending ? <div className="flex flex-col gap-2">{[0, 1, 2].map((i) => <Skeleton key={i} className="h-20" />)}</div>
        : q.error ? <ErrorState error={q.error} retry={() => q.refetch()} />
        : q.data.every((a) => a.kind === "external") ? (
          <EmptyState title="No machines yet" action={<Link to="/add" className={clsx(btnPrimary, "no-underline")}>Add your first machine</Link>}>
            Machines show up here once they report in.
          </EmptyState>
        ) : (
          <ul className="flex flex-col divide-y divide-line overflow-hidden rounded-lg border border-line bg-surface">
            {q.data.filter((a) => a.kind !== "external").map((a) => <AssetRow key={a.id} a={a} onPatch={(p) => patch.mutate({ id: a.id, ...p })} onDelete={() => { del.reset(); setTarget(a); }} />)}
          </ul>
        )}
      {q.data && <ExternalTargets targets={q.data.filter((a) => a.kind === "external")} onDelete={(a) => { del.reset(); setTarget(a); }} />}
      <AlertDialog.Root open={!!target} onOpenChange={(o) => !o && setTarget(null)}>
        <AlertDialog.Portal>
          <AlertDialog.Overlay className="overlay" />
          <AlertDialog.Content className="fixed left-1/2 top-[15vh] z-[51] w-[min(30rem,calc(100%-2rem))] -translate-x-1/2 rounded-xl border border-line bg-surface p-5 shadow-2xl">
            <AlertDialog.Title className="text-lg font-semibold">Delete {target?.hostname}?</AlertDialog.Title>
            <AlertDialog.Description className="mt-2 text-sm">
              Its findings and installed-software list are removed. The evidence ledger keeps the history of what was detected and fixed, so audit records stay intact. This can't be undone.
            </AlertDialog.Description>
            {del.error && <p role="alert" className="mt-3 text-sm text-now-fg">{del.error.message}</p>}
            <div className="mt-5 flex justify-end gap-2">
              <AlertDialog.Cancel className={btnQuiet}>Cancel</AlertDialog.Cancel>
              <button className={btnPrimary} disabled={del.isPending} onClick={() => target && del.mutate(target.id)}>{del.isPending ? "Deleting…" : "Delete asset"}</button>
            </div>
          </AlertDialog.Content>
        </AlertDialog.Portal>
      </AlertDialog.Root>
    </div>
  );
}

function AssetRow({ a, onPatch, onDelete }: { a: Asset; onPatch: (p: AssetPatch) => void; onDelete: () => void }) {
  const admin = useIsAdmin();
  const open = PRIORITIES.filter((p) => a.open_by_priority[p]);
  return (
    <li className="flex flex-col gap-3 p-4">
      <div className="flex flex-wrap items-start justify-between gap-x-6 gap-y-2">
      <div className="min-w-0 flex-1 basis-60">
        <h2 className="flex items-center gap-2 text-base font-semibold"><span className="truncate">{a.hostname}</span>
          {a.sandbox && <span title="Disposable test machine: the only kind remediation may change until production remediation is enabled" className="shrink-0 border border-line-strong px-1.5 py-px text-[11px] font-semibold tracking-wide text-muted">Sandbox</span>}</h2>
        <p className="truncate text-sm text-muted">
          {a.kind === "application" ? "Application (SBOM)" : a.os_name || "Unknown OS"} · seen <time dateTime={a.last_seen + "Z"} title={new Date(a.last_seen + "Z").toLocaleString()}>{relativeTime(a.last_seen)}</time>
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
      </div>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <label className="flex items-center gap-2 text-sm">
          <span className="whitespace-nowrap text-muted">Criticality</span>
          <select className={clsx(input, "min-h-9 w-auto capitalize")} value={a.criticality} onChange={(e) => onPatch({ criticality: e.target.value as Criticality })}>
            {LEVELS.map((l) => <option key={l} value={l}>{l}</option>)}
          </select>
        </label>
        <label className="flex cursor-pointer items-center gap-2 whitespace-nowrap text-sm">
          <Switch.Root checked={a.internet_facing} onCheckedChange={(internet_facing) => onPatch({ internet_facing })}
            className="relative h-5 w-9 shrink-0 cursor-pointer rounded-full bg-line-strong data-[state=checked]:bg-accent">
            <Switch.Thumb className="block size-4 translate-x-0.5 rounded-full bg-surface transition-transform data-[state=checked]:translate-x-[18px]" />
          </Switch.Root>
          Internet-facing
        </label>
        {a.kind === "host" && <><label className="flex items-center gap-2 text-sm">
          <span className="whitespace-nowrap text-muted">Ring</span>
          <select className={clsx(input, "min-h-9 w-auto")} value={a.ring} onChange={(e) => onPatch({ ring: Number(e.target.value) as 0 | 1 })}>
            <option value={0}>Canary</option><option value={1}>Broad</option>
          </select>
        </label>
        <HealthUnits a={a} onPatch={onPatch} /></>}
        <SbomUpload a={a} />
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
      <input className={clsx(input, "min-h-9 w-40")} value={text} placeholder="nginx, sshd" onChange={(e) => setText(e.target.value)} onBlur={commit}
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
        <Dialog.Content className="fixed left-1/2 top-[15vh] z-[51] w-[min(30rem,calc(100%-2rem))] -translate-x-1/2 rounded-xl border border-line bg-surface p-5 shadow-2xl">
          <Dialog.Title className="text-lg font-semibold">Add an application</Dialog.Title>
          {made ? (
            <>
              <Dialog.Description className="mt-2 text-sm">
                <strong>{made.name}</strong> was added. Upload its CycloneDX SBOM from the Assets page, or from CI with this token (shown once):
              </Dialog.Description>
              <pre className="mt-3 overflow-x-auto rounded-md bg-bg p-3 text-xs" tabIndex={0} aria-label="Upload token and example command">{`curl -X POST -H "Authorization: Bearer ${made.token}" \\
  --data-binary @bom.json ${location.origin}/api/assets/${made.id}/sbom`}</pre>
              <div className="mt-5 flex justify-end"><Dialog.Close className={btnPrimary}>Done</Dialog.Close></div>
            </>
          ) : (
            <form className="mt-3 flex flex-col gap-3" onSubmit={(e) => { e.preventDefault(); if (name.trim()) create.mutate(name.trim()); }}>
              <Dialog.Description className="text-sm text-muted">Software without an agent: findings come from the CycloneDX SBOM you upload.</Dialog.Description>
              <label className="flex flex-col gap-1 text-sm font-medium">Name
                <input className={input} value={name} onChange={(e) => setName(e.target.value)} maxLength={255} required autoComplete="off" placeholder="billing-service" />
              </label>
              {create.error && <p role="alert" className="text-sm text-now-fg">{create.error.message}</p>}
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
  const file = useRef<HTMLInputElement>(null);
  const up = useMutation({
    mutationFn: async (f: File) => api<SbomResult>(`/api/assets/${a.id}/sbom`, { method: "POST", body: await f.text() }),
    onSuccess: () => Promise.all(["assets", "findings", "summary", "finding", "ledger"].map((k) => qc.invalidateQueries({ queryKey: [k] }))),
  });
  return (
    <div className="flex flex-col gap-1">
      <button className={btnQuiet} disabled={up.isPending} aria-label={`Upload SBOM for ${a.hostname}`} onClick={() => file.current?.click()}>
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
