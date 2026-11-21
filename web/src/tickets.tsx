import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ExternalLink, Plus, TriangleAlert, X } from "lucide-react";
import { api, parseUtc, plural, PRIORITY_LABEL, relativeTime, type TicketLink, type TicketPreview, type TicketSettings } from "./lib";
import { Alert, btnPrimary, btnQuiet, ConfirmDialog, Done, ErrorState, Field, HowJudged, input, Loading } from "./ui";

/** A ticket's key and state, linking to it in the tracker (a new tab). */
export function TicketChip({ t }: { t: TicketLink }) {
  return (
    <a href={t.url} target="_blank" rel="noopener noreferrer" className="inline-flex tap items-center gap-1.5 border border-line-strong px-2 py-0.5 text-xs hover:bg-sunken">
      <span className="font-mono">{t.key}</span><span className="text-muted">{t.state}</span>
      <ExternalLink className="size-3" aria-label="(opens in a new tab)" />
    </a>
  );
}

/** "Tracked in PAY-12, OPS-4" for a fix that reached the tracker; nothing otherwise. */
export function TicketLinks({ tickets, className }: { tickets?: TicketLink[] | null; className?: string }) {
  if (!tickets?.length) return null;
  return (
    <p className={className ?? "mt-1.5 flex flex-wrap items-center gap-2 text-sm text-muted"}>
      Tracked in {tickets.map((t) => <TicketChip key={t.url} t={t} />)}
    </p>
  );
}

const THRESHOLDS = [
  { value: "fix-now", label: "Fix now only" }, { value: "next", label: "Next and above" },
  { value: "planned", label: "Routine and above" }, { value: "low", label: "Every open finding" },
] as const;

type Form = { kind: "jira" | "gitlab"; site: string; user: string; token: string; default_project: string; routes: { owner: string; project: string }[]; min_priority: string; enabled: boolean };
const fromSaved = (s: TicketSettings): Form => ({ kind: s.kind, site: s.site, user: s.user, token: "", default_project: s.default_project,
  routes: s.routes, min_priority: s.min_priority, enabled: s.enabled });

/** Render Settings → Ticketing: the tracker, team routes, which findings become tickets, and what the last sync did. */
export function TicketsSection() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["tickets"], queryFn: () => api<TicketSettings>("/api/settings/tickets"), retry: false });
  const [form, setForm] = useState<Form | null>(null);
  const [confirm, setConfirm] = useState(false);
  const save = useMutation({
    mutationFn: (body: object) => api<TicketSettings>("/api/settings/tickets", { method: "PUT", body }),
    onSuccess: (data) => { qc.setQueryData(["tickets"], data); setForm(null); setConfirm(false); preview.reset(); void qc.invalidateQueries({ queryKey: ["ledger"] }); },
  });
  const test = useMutation({ mutationFn: () => api<{ ok: boolean; message: string }>("/api/settings/tickets/test", { method: "POST" }) });
  const preview = useMutation({ mutationFn: () => api<TicketPreview>("/api/settings/tickets/preview") });
  const sync = useMutation({
    mutationFn: () => api("/api/settings/tickets/sync", { method: "POST" }),
    // the sync runs after the response; its result lands in "Last sync"
    onSuccess: () => { for (const ms of [2000, 6000, 15000]) setTimeout(() => void qc.invalidateQueries({ queryKey: ["tickets"] }), ms); },
  });
  if (q.isPending) return <Loading className="h-40" />;
  if (q.error) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  const s = q.data;
  const f = form ?? fromSaved(s);
  const dirty = form !== null;
  const set = (patch: Partial<Form>) => { save.reset(); setForm({ ...f, ...patch }); };
  const jira = f.kind === "jira";
  const open = Object.values(s.open_by_project).reduce((a, b) => a + b, 0);
  const moved = !!s.site && (f.kind !== s.kind || f.site.trim().replace(/\/+$/, "") !== s.site);
  const body = () => ({ ...f, token: f.token || undefined, routes: f.routes.filter((r) => r.owner.trim() && r.project.trim()) });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (moved && open + s.closed > 0) setConfirm(true);
    else save.mutate(body());
  };
  const last = s.last_sync;
  const errors = s.failing.length ? s.failing : (last?.errors ?? []).map((x) => ({ key: x.ticket, project: x.project ?? "", title: x.title ?? "", error: x.error }));
  return (
    <section aria-labelledby="tickets-h3" className="flex flex-col gap-3">
      <h3 id="tickets-h3" className="text-lg font-semibold">Jira or GitLab</h3>
      <HowJudged label="How tickets work" lead={<>One ticket per fix per team, in the team's own project. Nimstead closes a ticket only when the machines' own inventory shows the fix, and reopens it if one is exposed again or it's closed while findings are still open.</>}>
        Each ticket lists the machines (hostname and installed version), the vulnerabilities, the priority and the due date, and keeps them current as machines are fixed. Its closing comment says, machine by machine, why each left: fixed, risk accepted, moved to another team, or removed. To stop tracking a finding, accept the risk in Nimstead: that's recorded and has an end date. Nothing is sent until you switch tickets on, and every ticket opened, closed and reopened is in the evidence ledger.
      </HowJudged>

      {last && (last.error
        ? <p className="flex items-start gap-2 bg-now-bg px-3 py-2 text-sm text-now-fg"><TriangleAlert className="mt-0.5 size-4 shrink-0" aria-hidden />
            <span><strong className="font-semibold">Last sync failed</strong> (<time dateTime={parseUtc(last.at).toISOString()}>{relativeTime(last.at)}</time>): {last.error}</span></p>
        : <p className="text-sm text-muted">
            Last sync <time dateTime={parseUtc(last.at).toISOString()}>{relativeTime(last.at)}</time>: {last.opened ?? 0} opened, {last.updated ?? 0} updated, {last.closed ?? 0} closed, {last.reopened ?? 0} reopened
            {!!last.failed && <>, <strong className="font-semibold text-now-fg">{last.failed} failed</strong></>}.
            {!!last.waiting && <> {plural(last.waiting, "change")} wait for the next run (at most 100 a run, most urgent first).</>}
          </p>)}
      {open > 0 && <p className="text-sm">Open tickets: {Object.entries(s.open_by_project).map(([p, n], i) => <span key={p}>{i > 0 && " · "}<span className="font-mono">{p}</span> {n}</span>)}</p>}
      {errors.length > 0 && (
        <div className="border border-line p-3 text-sm">
          <p className="font-medium">Last errors, in the tracker's words</p>
          <ul className="mt-1 flex flex-col gap-1">{errors.map((x, i) => (
            <li key={i} className="break-words text-muted">{x.project && <span className="font-mono">{x.project} </span>}{x.key ? <span className="font-mono text-ink">{x.key}</span> : x.title ? <span className="text-ink">{x.title}</span> : null}{(x.key || x.title) && ": "}{x.error}</li>))}</ul>
        </div>
      )}

      <form onSubmit={submit} className="grid max-w-xl gap-4">
        <Field label="Tracker">
          <select className={input} value={f.kind} onChange={(e) => set({ kind: e.target.value as Form["kind"], user: e.target.value === "gitlab" ? "" : f.user })}>
            <option value="jira">Jira (Cloud or Data Center)</option>
            <option value="gitlab">GitLab (gitlab.com or self-managed)</option>
          </select>
        </Field>
        <Field label="Site URL" hint={jira ? "The address you open Jira at, like https://acme.atlassian.net." : "Like https://gitlab.com or https://gitlab.example.com."}>
          <input className={input} type="url" autoComplete="off" value={f.site} onChange={(e) => set({ site: e.target.value })} placeholder={jira ? "https://acme.atlassian.net" : "https://gitlab.example.com"} />
        </Field>
        {jira && (
          <Field label="Account email" hint="Jira Cloud: the account the API token belongs to. Jira Data Center: leave it empty and use a personal access token.">
            <input className={input} type="email" autoComplete="off" value={f.user} onChange={(e) => set({ user: e.target.value })} />
          </Field>
        )}
        <Field label={jira ? "API token" : "Access token"} hint={(s.token_set && !moved ? "Saved. Enter a new one to replace it. " : moved && s.site ? "A new site or tracker needs its own token. " : "")
          + (jira ? "It needs to create, edit, comment on and transition issues in the projects below." : "A personal, group or project access token with the api scope, and Reporter access or more to the projects.")}>
          <input className={input} type="password" autoComplete="new-password" value={f.token} onChange={(e) => set({ token: e.target.value })} placeholder={s.token_set && !moved ? "Unchanged" : ""} />
        </Field>

        <fieldset className="flex flex-col gap-2">
          <legend className="text-sm font-medium">Team routes</legend>
          <p className="text-xs text-muted">Each team's findings go to its own project; every other finding goes to the default project.</p>
          <datalist id="ticket-owners">{s.owners.map((o) => <option key={o} value={o} />)}</datalist>
          {f.routes.map((r, i) => (
            <div key={i} className="flex flex-wrap items-end gap-2">
              <Field label="Owner" className="min-w-40 flex-1"><input className={input} list="ticket-owners" value={r.owner} autoComplete="off"
                onChange={(e) => set({ routes: f.routes.map((x, j) => j === i ? { ...x, owner: e.target.value } : x) })} /></Field>
              <Field label="Project" className="min-w-32 flex-1"><input className={input} value={r.project} autoComplete="off" placeholder={jira ? "PAY" : "group/project"}
                onChange={(e) => set({ routes: f.routes.map((x, j) => j === i ? { ...x, project: e.target.value } : x) })} /></Field>
              <button type="button" className={btnQuiet} onClick={() => set({ routes: f.routes.filter((_, j) => j !== i) })}>
                <X className="size-4" aria-hidden /><span className="sr-only">Remove the route for {r.owner || "this owner"}</span></button>
            </div>
          ))}
          <div><button type="button" className={btnQuiet} onClick={() => set({ routes: [...f.routes, { owner: "", project: "" }] })}><Plus className="size-4" aria-hidden />Add a route</button></div>
        </fieldset>
        <Field label="Default project" hint="Findings on machines with no owner, or an owner with no route, go here. Leave it empty to send only routed teams' findings.">
          <input className={input} value={f.default_project} autoComplete="off" placeholder={jira ? "OPS" : "group/project"} onChange={(e) => set({ default_project: e.target.value })} />
        </Field>
        <Field label="Which findings become tickets" hint="Every open finding at or above this priority is in exactly one ticket.">
          <select className={input} value={f.min_priority} onChange={(e) => set({ min_priority: e.target.value })}>
            {THRESHOLDS.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
          </select>
        </Field>
        <label className="tap flex cursor-pointer items-start gap-2 text-sm">
          <input type="checkbox" checked={f.enabled} onChange={(e) => set({ enabled: e.target.checked })} className="mt-0.5 size-4 shrink-0 accent-[var(--ink)]" />
          <span><span className="font-medium">Send tickets</span>
            <span className="block text-muted">The hourly feed run opens, updates, closes and reopens tickets. Tickets name machines (hostname and installed version): the team needs them to act.</span></span>
        </label>
        {!s.public_url && <p className="text-xs text-muted">NIMSTEAD_PUBLIC_URL isn't set on this server, so tickets can't link back to their findings here.</p>}
        <div className="flex flex-wrap items-center gap-2">
          <button className={btnPrimary} disabled={save.isPending || !dirty}>{save.isPending ? "Saving…" : "Save ticket settings"}</button>
          {save.isSuccess && <Done>Saved</Done>}
          <button type="button" className={btnQuiet} disabled={!s.site || dirty || test.isPending} onClick={() => test.mutate()}>{test.isPending ? "Testing…" : "Test connection"}</button>
          <button type="button" className={btnQuiet} disabled={!s.site || dirty || preview.isPending} onClick={() => preview.mutate()}>{preview.isPending ? "Working it out…" : "Preview"}</button>
          {s.enabled && <button type="button" className={btnQuiet} disabled={dirty || sync.isPending} onClick={() => sync.mutate()}>{sync.isPending ? "Starting…" : "Sync now"}</button>}
        </div>
        {dirty && s.site && <p className="text-xs text-muted">Save first: Test connection, Preview and Sync now use the saved settings.</p>}
        <Alert error={save.error} prefix="Couldn't save: " />
        <Alert error={test.error} prefix="Couldn't test: " />
        <Alert error={sync.error} prefix="Couldn't sync: " />
        {test.data && (test.data.ok ? <Done>{test.data.message}</Done> : <Alert error={test.data.message} prefix="Connection failed: " />)}
        {sync.isSuccess && <Done>Sync started. Its result appears under Last sync in a moment.</Done>}
      </form>
      <Alert error={preview.error} prefix="Couldn't preview: " />
      {preview.data && <PreviewResult p={preview.data} />}
      <ConfirmDialog open={confirm} onOpenChange={setConfirm} title="Change tracker?" confirmLabel="Save and start afresh" pendingLabel="Saving…"
        pending={save.isPending} error={save.error} onConfirm={() => save.mutate(body())}
        description={<>Nimstead will stop updating the {plural(open + s.closed, "ticket")} it opened in {s.site}. They stay there as they are; new tickets go to the new tracker.</>} />
    </section>
  );
}

function PreviewResult({ p }: { p: TicketPreview }) {
  const byProject = new Map<string, TicketPreview["open"]>();
  for (const t of p.open) byProject.set(t.project, [...(byProject.get(t.project) ?? []), t]);
  const shown = 20;
  return (
    <div aria-live="polite" className="flex max-w-xl flex-col gap-2 border border-line p-4 text-sm">
      <p className="font-medium">
        {p.open.length ? `A sync now would open ${plural(p.open.length, "ticket")}` : "A sync now would open no ticket"}
        {(p.update || p.close || p.reopen) ? `, update ${p.update}, close ${p.close} and reopen ${p.reopen}` : ""}.
        {" "}<span className="font-normal text-muted">{plural(p.findings, "finding")} in {plural(p.tickets, "ticket")} in all.</span>
      </p>
      {[...byProject].map(([project, ts]) => (
        <div key={project}>
          <p className="font-mono text-xs text-muted">{project} ({ts.length})</p>
          <ul className="mt-1 flex flex-col gap-0.5">{ts.slice(0, shown).map((t, i) => <li key={i} className="break-words"><span className="text-muted">{PRIORITY_LABEL[t.priority]}:</span> {t.title}</li>)}
            {ts.length > shown && <li className="text-muted">and {ts.length - shown} more</li>}</ul>
        </div>
      ))}
      {p.skipped.length > 0 && <p className="text-muted">Not sent, for want of a route or a default project: {p.skipped.map((x) => `${x.owner ?? "no owner"} (${plural(x.findings, "finding")})`).join(", ")}.</p>}
    </div>
  );
}
