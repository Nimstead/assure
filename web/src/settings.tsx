import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { RadioGroup, Switch } from "radix-ui";
import { Info } from "lucide-react";
import clsx from "clsx";
import { adminGate, api, assetsQ, meQ, refresh, parseUtc, PRIORITIES, PRIORITY_LABEL, relativeTime, settingsQ, useHashScroll, useIsAdmin, useTitle, type EnrollToken, type Priority, type Settings } from "./lib";
import { NotificationsSection, SsoSection } from "./integrations";
import { AccountSection, ApiTokensSection, UsersSection } from "./people";
import { Alert, btnPrimary, btnQuiet, ConfirmDialog, Done, ErrorState, Field, input, Loading, switchRoot, switchThumb, Tag } from "./ui";

const MODES: { value: Settings["remediation_mode"]; title: string; body: string }[] = [
  { value: "suggest", title: "Suggest", body: "Nimstead recommends upgrades. It never changes a machine; you apply fixes yourself." },
  { value: "approve", title: "Approve", body: "You plan a fix and a person approves each one before anything runs. Every approval is recorded." },
  { value: "auto", title: "Auto", body: "Fixes are applied without asking, canary machines first. Broad machines wait until a canary has stayed healthy for the soak period; any failure halts the rollout." },
];

type SettingsPatch = Partial<Pick<Settings, "remediation_mode" | "canary_soak_hours" | "agent_updates_paused" | "sla_days">>;

const GROUPS = [
  { id: "remediation", title: "Remediation" },
  { id: "access", title: "Access" },
  { id: "alerts", title: "Alerts" },
  { id: "account", title: "Your account" },
  { id: "server", title: "This server" },
] as const;

function Group({ id, title, children }: { id: string; title: string; children: React.ReactNode }) {
  return (
    // scroll-mt clears the sticky header and section bar, so an anchored heading lands below them
    <section id={id} aria-labelledby={`${id}-h`} tabIndex={-1} className="flex scroll-mt-32 flex-col gap-8 border-t border-line-strong pt-6 outline-none first-of-type:border-t-0 first-of-type:pt-0 md:scroll-mt-20">
      <h2 id={`${id}-h`} className="text-xl font-semibold">{title}</h2>
      {children}
    </section>
  );
}

/** The section bar: scrolls sideways on phones (with a fade showing there's more) and marks the section in view. */
function SectionBar() {
  const [current, setCurrent] = useState<string>(GROUPS[0].id);
  useEffect(() => {
    if (typeof IntersectionObserver === "undefined") return;  // old browsers and jsdom: the bar still works, unmarked
    const seen = new Map<string, boolean>();
    const io = new IntersectionObserver((entries) => {
      for (const e of entries) seen.set(e.target.id, e.isIntersecting);
      const first = GROUPS.find((g) => seen.get(g.id));
      if (first) setCurrent(first.id);
    }, { rootMargin: "-120px 0px -55% 0px" });
    for (const g of GROUPS) { const el = document.getElementById(g.id); if (el) io.observe(el); }
    return () => io.disconnect();
  }, []);
  return (
    <nav aria-label="Settings sections" className="sticky top-[53px] z-[5] -mx-4 border-y border-line bg-bg md:top-0 md:mx-0">
      <div className="flex gap-1 overflow-x-auto px-4 py-1.5 [scrollbar-width:none] md:px-0 [&::-webkit-scrollbar]:hidden">
        {GROUPS.map((g) => (
          <a key={g.id} href={`#${g.id}`} aria-current={current === g.id ? "location" : undefined}
            className="inline-flex min-h-[44px] shrink-0 items-center px-3 text-sm text-muted no-underline hover:bg-sunken hover:text-ink aria-[current]:font-medium aria-[current]:text-ink aria-[current]:shadow-[inset_0_-2px_0_var(--ink)] md:min-h-9">
            {g.title}
          </a>
        ))}
      </div>
      <span aria-hidden className="pointer-events-none absolute inset-y-0 right-0 w-8 bg-gradient-to-l from-bg md:hidden" />
    </nav>
  );
}

const PRODUCTION_HOW = <>To let fixes run on other machines, set <code className="bg-sunken px-1">NIMSTEAD_ALLOW_PRODUCTION_REMEDIATION=1</code> in <code className="bg-sunken px-1">.env</code> on the server and restart it, once you've watched fixes and rollbacks work on test machines.</>;

export function SettingsPage() {
  useTitle("Settings");
  const qc = useQueryClient();
  const q = useQuery(settingsQ);
  const me = useQuery(meQ);
  const admin = useIsAdmin();
  const [hours, setHours] = useState("");
  const [sla, setSla] = useState<Record<string, string>>({});
  const [mode, setMode] = useState<Settings["remediation_mode"] | null>(null);
  const [confirmAuto, setConfirmAuto] = useState(false);
  // Seed the forms once. Later data (a save elsewhere on the page) must not overwrite what someone is typing.
  const seeded = useRef(false);
  useEffect(() => {
    if (!q.data || seeded.current) return;
    seeded.current = true;
    setHours(String(q.data.canary_soak_hours));
    setSla(Object.fromEntries(PRIORITIES.map((p) => [p, String(q.data.sla_days[p])])));
    setMode(q.data.remediation_mode);
  }, [q.data]);
  const save = useMutation({
    mutationFn: (body: SettingsPatch) => api<Settings>("/api/settings", { method: "PATCH", body }),
    onSuccess: (data, body) => {
      setConfirmAuto(false);
      qc.setQueryData(settingsQ.queryKey, data);
      // reset only what was saved, from the server's answer
      if ("canary_soak_hours" in body) setHours(String(data.canary_soak_hours));
      if ("sla_days" in body) setSla(Object.fromEntries(PRIORITIES.map((p) => [p, String(data.sla_days[p])])));
      if ("remediation_mode" in body) setMode(data.remediation_mode);
      void qc.invalidateQueries({ queryKey: ["ledger"] });
    },
  });
  useHashScroll(!!q.data);
  // The machine count makes the Auto confirmation concrete; only admins see the ladder controls.
  const hosts = useQuery({ ...assetsQ, enabled: admin }).data?.filter((a) => a.kind === "host") ?? [];
  const mine = (key: keyof SettingsPatch) => !!save.variables && key in save.variables;
  const savedHere = (key: keyof SettingsPatch) => save.isSuccess && mine(key) ? <Done>Saved</Done> : null;
  // a failed save is shown beside the control that failed, not at the top of the page
  const errorHere = (key: keyof SettingsPatch) => save.isError && mine(key) ? <Alert error={save.error} prefix="Couldn't save: " className="w-full" /> : null;

  const s = q.data;
  const n = Number(hours);
  const hoursOk = Number.isInteger(n) && n >= 1 && n <= 720;
  const slaDays = Object.fromEntries(PRIORITIES.map((p) => [p, Number(sla[p])])) as Settings["sla_days"];
  const slaBad = (p: Priority) => !(Number.isInteger(slaDays[p]) && slaDays[p] >= 1 && slaDays[p] <= 365);
  const slaOk = !PRIORITIES.some(slaBad);
  const slaDirty = !!s && PRIORITIES.some((p) => slaDays[p] !== s.sla_days[p]);
  const saveMode = () => { if (mode === "auto") setConfirmAuto(true); else if (mode) save.mutate({ remediation_mode: mode }); };
  const canary = hosts.filter((h) => h.ring === 0).length;

  return (
    <div className="flex max-w-3xl flex-col gap-8">
      <header>
        <h1 className="text-3xl font-semibold">Settings</h1>
        <p className="mt-1 text-muted">How much Nimstead is trusted to do on its own, who can do what, and where alerts go. Changes are recorded in the evidence ledger.</p>
      </header>
      <SectionBar />

      {/* Sections that don't need /api/settings load alongside it rather than after it. */}
      <Group id="remediation" title="Remediation">
        {q.isPending ? <Loading className="h-64" label="Loading settings…" /> : q.error ? <ErrorState error={q.error} retry={() => q.refetch()} /> : s && <>
        {!s.production_remediation_allowed && (
          <p className="flex items-start gap-2 border border-line-strong bg-surface p-3 text-sm">
            <Info className="mt-0.5 size-4 shrink-0" aria-hidden />
            <span className="min-w-0 [overflow-wrap:anywhere]">Production remediation is switched off on this server. Fixes can only run on machines enrolled as <strong className="font-semibold">test machines</strong> (sandbox); other machines are refused with an explanation. {PRODUCTION_HOW}</span>
          </p>
        )}

        <section aria-labelledby="ladder" className="flex flex-col items-start gap-3">
          <h3 id="ladder" className="text-lg font-semibold">Trust ladder</h3>
          {!admin ? <p className="text-sm"><strong className="font-semibold">{MODES.find((m) => m.value === s.remediation_mode)?.title}.</strong> {MODES.find((m) => m.value === s.remediation_mode)?.body} <span className="text-muted">Only organisation admins can change this.</span></p> : <>
            {/* Choosing only selects; nothing is saved until Save, so arrowing through the radios can't switch on Auto. */}
            <RadioGroup.Root aria-labelledby="ladder" value={mode ?? s.remediation_mode} onValueChange={(v) => { save.reset(); setMode(v as Settings["remediation_mode"]); }} className="grid w-full gap-2 md:grid-cols-3">
              {MODES.map((m) => (
                <RadioGroup.Item key={m.value} value={m.value} className="group flex cursor-pointer flex-col items-start gap-1.5 border border-line-strong bg-surface p-4 text-left hover:border-ink data-[state=checked]:border-ink data-[state=checked]:bg-accent-soft data-[state=checked]:shadow-[inset_0_0_0_1px_var(--ink)]">
                  <span className="flex w-full items-center justify-between gap-2 font-semibold">
                    <span className="flex items-center gap-2">
                      <span aria-hidden className="grid size-4 shrink-0 place-items-center border border-ink"><span className="size-2 bg-ink group-data-[state=unchecked]:hidden" /></span>
                      {m.title}
                    </span>
                    {m.value === s.remediation_mode && <Tag tone="ink">Current</Tag>}
                  </span>
                  <span className="text-sm text-muted group-data-[state=checked]:text-ink">{m.body}</span>
                </RadioGroup.Item>
              ))}
            </RadioGroup.Root>
            <div className="flex flex-wrap items-center gap-3">
              <button className={btnPrimary} disabled={save.isPending || !mode || mode === s.remediation_mode} onClick={saveMode}>{save.isPending && mine("remediation_mode") ? "Saving…" : "Save"}</button>
              {savedHere("remediation_mode")}
              {!confirmAuto && errorHere("remediation_mode")}
            </div>
          </>}
          <ConfirmDialog open={confirmAuto} onOpenChange={setConfirmAuto} title="Let Nimstead fix machines without asking?"
            description={<>Fixes will be applied to your {hosts.length} machine{hosts.length === 1 ? "" : "s"} without a person approving each one: {canary} canary machine{canary === 1 ? "" : "s"} first, then everything else once a canary has stayed healthy for {s.canary_soak_hours} hours. Any failure halts the rollout.</>}
            confirmLabel="Switch to Auto" pendingLabel="Saving…" cancelLabel="Keep current mode" pending={save.isPending} error={save.error} onConfirm={() => save.mutate({ remediation_mode: "auto" })}>
            {!s.production_remediation_allowed && <p className="mt-3 text-sm text-muted">Production remediation is off on this server, so only test machines can be changed.</p>}
          </ConfirmDialog>
        </section>

        <section aria-labelledby="canary" className="flex flex-col items-start gap-3">
          <h3 id="canary" className="text-lg font-semibold">Canary soak</h3>
          <p className="max-w-prose text-sm text-muted">
            Each machine is in a ring. <strong className="font-semibold text-ink">Canary</strong> (ring 0) machines get a change first. <strong className="font-semibold text-ink">Broad</strong> (ring 1) machines only get it after a canary has succeeded and stayed healthy for the soak period below. Set rings and health checks per machine on the Assets page.
          </p>
          {!admin ? <p className="text-sm">Soak time: <strong className="font-semibold">{s.canary_soak_hours} hours.</strong> <span className="text-muted">Only organisation admins can change this.</span></p> : <form className="flex flex-wrap items-start gap-3" onSubmit={(e) => { e.preventDefault(); if (hoursOk) save.mutate({ canary_soak_hours: n }); }}>
            <Field label="Soak time (hours)" hint="Whole hours, 1 to 720." error={hoursOk ? null : "Enter whole hours from 1 to 720."} className="w-40">
              <input className={input} type="number" inputMode="numeric" min={1} max={720} value={hours} onChange={(e) => { save.reset(); setHours(e.target.value); }} />
            </Field>
            <button className={clsx(btnPrimary, "mt-[26px]")} disabled={!hoursOk || save.isPending || n === s.canary_soak_hours}>{save.isPending && mine("canary_soak_hours") ? "Saving…" : "Save"}</button>
            {savedHere("canary_soak_hours")}
            {errorHere("canary_soak_hours")}
          </form>}
        </section>

        <section aria-labelledby="sla" className="flex flex-col items-start gap-3">
          <h3 id="sla" className="text-lg font-semibold">Remediation deadlines</h3>
          <p className="max-w-prose text-sm text-muted">Days from first detection to fix, by priority (1 to 365). Evidence packs measure your SLA against these and show them to auditors; Cyber Essentials' 14 days is checked separately.</p>
          <form className="flex flex-wrap items-start gap-3" onSubmit={(e) => { e.preventDefault(); if (slaOk) save.mutate({ sla_days: slaDays }); }}>
            {PRIORITIES.map((p) => (
              <Field key={p} label={PRIORITY_LABEL[p]} error={slaBad(p) ? "1 to 365 days" : null} className="w-28">
                <input className={input} type="number" inputMode="numeric" min={1} max={365} required value={sla[p] ?? ""} disabled={!admin}
                  onChange={(e) => { save.reset(); setSla((x) => ({ ...x, [p]: e.target.value })); }} />
              </Field>
            ))}
            {admin && <button className={clsx(btnPrimary, "mt-[26px]")} disabled={save.isPending || !slaDirty || !slaOk}>{save.isPending && mine("sla_days") ? "Saving…" : "Save"}</button>}
            {savedHere("sla_days")}
            {errorHere("sla_days")}
          </form>
        </section>

        <section aria-labelledby="agent-updates" className="flex flex-col items-start gap-3">
          <h3 id="agent-updates" className="text-lg font-semibold">Agent updates</h3>
          <p className="max-w-prose text-sm text-muted">
            Agents replace themselves with newer releases at their next run. A release is accepted only if it's signed by the Nimstead release key built into the agent, so this server can hold an update back but can't change one. Each agent tests the new version on its host before switching and keeps the old one if the test fails.
          </p>
          {!s.signed_agent_release && (
            <p className="flex items-start gap-2 border border-line-strong bg-surface p-3 text-sm">
              <Info className="mt-0.5 size-4 shrink-0" aria-hidden />
              <span>This server has no signed release for the agent it serves (a development build, or the release files haven't been fetched yet), so agents stay on their current version.</span>
            </p>
          )}
          {!admin ? <p className="text-sm">Agent updates are <strong className="font-semibold">{s.agent_updates_paused ? "paused" : "on"}</strong>. <span className="text-muted">Only organisation admins can change this.</span></p> : (
            <div className="flex flex-wrap items-center gap-3">
              <label className="flex min-h-[44px] cursor-pointer items-center gap-2 text-sm md:min-h-0">
                <Switch.Root checked={s.agent_updates_paused} disabled={save.isPending} onCheckedChange={(agent_updates_paused) => save.mutate({ agent_updates_paused })} className={switchRoot}>
                  <Switch.Thumb className={switchThumb} />
                </Switch.Root>
                Pause agent updates for this organisation
              </label>
              {savedHere("agent_updates_paused")}
              {errorHere("agent_updates_paused")}
            </div>
          )}
        </section>
        </>}
      </Group>

      <Group id="access" title="Access">
        {me.data?.admin && <UsersSection />}
        <TokensSection />
        {me.data?.admin && <ApiTokensSection />}
        {me.data?.admin && <SsoSection />}
      </Group>

      <Group id="alerts" title="Alerts">
        {me.data?.admin ? <NotificationsSection /> : <p className="text-sm text-muted">Only organisation admins can change where alerts go.</p>}
      </Group>

      <Group id="account" title="Your account">
        <AccountSection />
      </Group>

      <Group id="server" title="This server">
        {s ? <PlatformSection p={s.platform} /> : <Loading className="h-16" label="" />}
      </Group>
    </div>
  );
}

const UPDATE_OUTCOME = { updated: "Updated", rolled_back: "Update failed and was rolled back", rollback_failed: "Update failed and the rollback failed too", refused: "Update refused" } as const;

export function PlatformSection({ p }: { p: Settings["platform"] }) {
  const last = p.last_update;
  return (
    <section aria-labelledby="platform" className="flex flex-col items-start gap-2">
      <h3 id="platform" className="text-lg font-semibold">Version and updates</h3>
      <p className="text-sm">Nimstead Assure <strong className="font-semibold">{p.version || "development build"}</strong>
        {p.running_channel && <span className="text-muted"> ({p.running_channel})</span>}
        {p.update_available ? <> · <a href={p.latest_url ?? undefined} className="font-medium text-accent underline">{p.latest} ({p.latest_channel}) is available</a></> : p.checked ? <span className="text-muted"> · up to date</span> : null}
      </p>
      <p className="max-w-prose text-sm text-muted">
        Follows the <strong className="font-semibold text-ink">{p.channel}</strong> channel{p.channel === "stable" ? "" : p.channel === "beta" ? " (beta and stable releases)" : " (every release, earliest first)"}. Set <code className="bg-sunken px-1">NIMSTEAD_UPDATE_CHANNEL</code> to preview, beta or stable in <code className="bg-sunken px-1">.env</code> on the server.
      </p>
      {p.update_available && <p className="max-w-prose text-sm text-muted">Install it on the Docker host with <code className="bg-sunken px-1">deploy/update.sh</code>. It checks the release signature, backs up the database, and rolls back automatically if the new version doesn't come up healthy.</p>}
      {last && (
        // Past news, not a live event: plain text, so it isn't announced on every visit.
        <p className={clsx("text-sm", last.outcome === "updated" ? "text-muted" : "bg-now-bg px-3 py-2 text-now-fg")}>
          {UPDATE_OUTCOME[last.outcome] ?? last.outcome}{last.to && ` (${last.from ? `${last.from} → ` : ""}${last.to})`}{last.at && `, ${relativeTime(last.at)}`}{last.error && `: ${last.error}`}
        </p>
      )}
    </section>
  );
}

function TokensSection() {
  const admin = useIsAdmin();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["enroll-tokens"], queryFn: () => api<EnrollToken[]>("/api/enroll-tokens") });
  const [target, setTarget] = useState<EnrollToken | null>(null);
  const revoke = useMutation({
    mutationFn: (id: string) => api(`/api/enroll-tokens/${id}`, { method: "DELETE" }),
    onSuccess: () => { setTarget(null); void refresh(qc, "people"); },
  });
  const now = Date.now();
  return (
    <section aria-labelledby="tokens" className="flex flex-col gap-3">
      <h3 id="tokens" className="text-lg font-semibold">Enrolment tokens</h3>
      <p className="max-w-prose text-sm text-muted">Tokens let a machine join. Revoke any you no longer need; machines already enrolled keep working.</p>
      {q.isPending ? <Loading className="h-20" /> : q.error ? <ErrorState error={q.error} retry={() => q.refetch()} />
        : q.data.length === 0 ? <p className="text-sm text-muted">No tokens yet.</p> : (
          <ul className="flex flex-col divide-y divide-line overflow-hidden border border-line bg-surface">
            {q.data.map((t) => {
              const expired = parseUtc(t.expires).getTime() < now;
              return (
                <li key={t.id} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-2.5 text-sm">
                  <code className="font-mono text-xs">{t.id}</code>
                  {t.sandbox && <Tag>Test machines</Tag>}
                  <span className="min-w-0 flex-1 text-muted">
                    {t.revoked ? "Revoked" : expired ? "Expired " : "Expires "}
                    {!t.revoked && <time dateTime={parseUtc(t.expires).toISOString()} title={parseUtc(t.expires).toLocaleString()}>{relativeTime(t.expires)}</time>}
                  </span>
                  {!t.revoked && !expired && <button className={btnQuiet} onClick={() => { revoke.reset(); setTarget(t); }} {...adminGate(admin)}>Revoke<span className="sr-only"> token {t.id}</span></button>}
                </li>
              );
            })}
          </ul>
        )}
      <ConfirmDialog open={!!target} onOpenChange={(o) => !o && setTarget(null)} title="Revoke this token?"
        description={<>Token <code className="font-mono">{target?.id}</code> will stop working for new machines. This can't be undone.</>}
        confirmLabel="Revoke token" pendingLabel="Revoking…" destructive pending={revoke.isPending} error={revoke.error} onConfirm={() => target && revoke.mutate(target.id)} />
    </section>
  );
}
