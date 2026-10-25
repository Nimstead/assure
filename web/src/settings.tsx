import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertDialog, RadioGroup } from "radix-ui";
import { Info } from "lucide-react";
import clsx from "clsx";
import { api, parseUtc, relativeTime, settingsQ, useTitle, type EnrollToken, type Settings } from "./lib";
import { btnPrimary, btnQuiet, ErrorState, input, Skeleton } from "./ui";

const MODES: { value: Settings["remediation_mode"]; title: string; body: string }[] = [
  { value: "suggest", title: "Suggest", body: "Nimstead recommends upgrades. It never changes a machine; you apply fixes yourself." },
  { value: "approve", title: "Approve", body: "You plan a fix and a person approves each one before anything runs. Every approval is recorded." },
  { value: "auto", title: "Auto", body: "Fixes are applied without asking, canary machines first. Broad machines wait until a canary has stayed healthy for the soak period; any failure halts the rollout." },
];

export function SettingsPage() {
  useTitle("Settings");
  const qc = useQueryClient();
  const q = useQuery(settingsQ);
  const [hours, setHours] = useState("");
  useEffect(() => { if (q.data) setHours(String(q.data.canary_soak_hours)); }, [q.data]);
  const save = useMutation({
    mutationFn: (body: Partial<Pick<Settings, "remediation_mode" | "canary_soak_hours">>) => api<Settings>("/api/settings", { method: "PATCH", body }),
    onSuccess: (data) => { qc.setQueryData(settingsQ.queryKey, data); void qc.invalidateQueries({ queryKey: ["ledger"] }); },
  });

  if (q.isPending) return <Skeleton className="h-64" />;
  if (q.error) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  const s = q.data;
  const n = Number(hours);
  const hoursOk = Number.isInteger(n) && n >= 1 && n <= 720;

  return (
    <div className="flex max-w-3xl flex-col gap-8">
      <header>
        <h1 className="text-3xl font-semibold">Settings</h1>
        <p className="mt-1 text-muted">How much Nimstead is trusted to do on its own. Changes are recorded in the evidence ledger.</p>
      </header>
      {save.error && <p role="alert" className="rounded-md bg-now-bg px-3 py-2 text-sm text-now-fg">Couldn't save: {save.error.message}</p>}

      {!s.production_remediation_allowed && (
        <p className="flex items-start gap-2 rounded-lg border border-line-strong bg-sunken p-3 text-sm">
          <Info className="mt-0.5 size-4 shrink-0" aria-hidden />
          <span>Production remediation is switched off on this server. Fixes can only run on machines enrolled as <strong className="font-semibold">sandbox</strong> (disposable test machines). Other machines will be refused with an explanation.</span>
        </p>
      )}

      <section aria-labelledby="ladder">
        <h2 id="ladder" className="text-lg font-semibold">Trust ladder</h2>
        <RadioGroup.Root aria-labelledby="ladder" value={s.remediation_mode} onValueChange={(v) => save.mutate({ remediation_mode: v as Settings["remediation_mode"] })} className="mt-3 grid gap-2 md:grid-cols-3">
          {MODES.map((m) => (
            <RadioGroup.Item key={m.value} value={m.value} className="group flex cursor-pointer flex-col items-start gap-1.5 rounded-lg border border-line bg-surface p-4 text-left hover:border-line-strong data-[state=checked]:border-accent data-[state=checked]:bg-accent-soft">
              <span className="flex w-full items-center justify-between font-semibold">
                {m.title}
                <span className="rounded-full bg-accent px-2 py-px text-xs font-medium text-accent-ink group-data-[state=unchecked]:hidden">Selected</span>
              </span>
              <span className="text-sm text-muted group-data-[state=checked]:text-ink">{m.body}</span>
            </RadioGroup.Item>
          ))}
        </RadioGroup.Root>
      </section>

      <section aria-labelledby="canary" className="flex flex-col items-start gap-3">
        <h2 id="canary" className="text-lg font-semibold">Canary soak</h2>
        <p className="max-w-prose text-sm text-muted">
          Each machine is in a ring. <strong className="font-semibold text-ink">Canary</strong> (ring 0) machines get a change first. <strong className="font-semibold text-ink">Broad</strong> (ring 1) machines only get it after a canary has succeeded and stayed healthy for the soak period below. Set rings and health checks per machine on the Assets page.
        </p>
        <form className="flex flex-wrap items-end gap-3" onSubmit={(e) => { e.preventDefault(); if (hoursOk) save.mutate({ canary_soak_hours: n }); }}>
          <label className="flex flex-col gap-1 text-sm">
            <span className="font-medium">Soak time (hours)</span>
            <input className={clsx(input, "w-32")} type="number" inputMode="numeric" min={1} max={720} value={hours} onChange={(e) => setHours(e.target.value)} aria-invalid={!hoursOk} aria-describedby="soak-hint" />
          </label>
          <button className={btnPrimary} disabled={!hoursOk || save.isPending || n === s.canary_soak_hours}>{save.isPending ? "Saving…" : "Save"}</button>
        </form>
        <p id="soak-hint" className={clsx("text-xs", hoursOk ? "text-muted" : "text-now-fg")}>Whole hours, 1 to 720.</p>
      </section>
      <TokensSection />
    </div>
  );
}

function TokensSection() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["enroll-tokens"], queryFn: () => api<EnrollToken[]>("/api/enroll-tokens") });
  const [target, setTarget] = useState<EnrollToken | null>(null);
  const revoke = useMutation({
    mutationFn: (id: string) => api(`/api/enroll-tokens/${id}`, { method: "DELETE" }),
    onSuccess: () => { setTarget(null); void Promise.all(["enroll-tokens", "ledger"].map((k) => qc.invalidateQueries({ queryKey: [k] }))); },
  });
  const now = Date.now();
  return (
    <section aria-labelledby="tokens" className="flex flex-col gap-3">
      <h2 id="tokens" className="text-lg font-semibold">Enrolment tokens</h2>
      <p className="max-w-prose text-sm text-muted">Tokens let a machine join. Revoke any you no longer need; machines already enrolled keep working.</p>
      {q.isPending ? <Skeleton className="h-20" /> : q.error ? <ErrorState error={q.error} retry={() => q.refetch()} />
        : q.data.length === 0 ? <p className="text-sm text-muted">No tokens yet.</p> : (
          <ul className="flex flex-col divide-y divide-line overflow-hidden rounded-lg border border-line bg-surface">
            {q.data.map((t) => {
              const expired = parseUtc(t.expires).getTime() < now;
              return (
                <li key={t.id} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-2.5 text-sm">
                  <code className="font-mono text-xs">{t.id}</code>
                  {t.sandbox && <span className="rounded border border-line-strong px-1.5 py-px text-[11px] font-semibold tracking-wide text-muted">Sandbox</span>}
                  <span className="min-w-0 flex-1 text-muted">
                    {t.revoked ? "Revoked" : expired ? "Expired " : "Expires "}
                    {!t.revoked && <time dateTime={parseUtc(t.expires).toISOString()} title={parseUtc(t.expires).toLocaleString()}>{relativeTime(t.expires)}</time>}
                  </span>
                  {!t.revoked && !expired && <button className={btnQuiet} onClick={() => { revoke.reset(); setTarget(t); }}>Revoke<span className="sr-only"> token {t.id}</span></button>}
                </li>
              );
            })}
          </ul>
        )}
      <AlertDialog.Root open={!!target} onOpenChange={(o) => !o && setTarget(null)}>
        <AlertDialog.Portal>
          <AlertDialog.Overlay className="overlay" />
          <AlertDialog.Content className="fixed left-1/2 top-[15vh] z-[51] w-[min(30rem,calc(100%-2rem))] -translate-x-1/2 rounded-xl border border-line bg-surface p-5 shadow-2xl">
            <AlertDialog.Title className="text-lg font-semibold">Revoke this token?</AlertDialog.Title>
            <AlertDialog.Description className="mt-2 text-sm">Token <code className="font-mono">{target?.id}</code> will stop working for new machines. This can't be undone.</AlertDialog.Description>
            {revoke.error && <p role="alert" className="mt-3 text-sm text-now-fg">{revoke.error.message}</p>}
            <div className="mt-5 flex justify-end gap-2">
              <AlertDialog.Cancel className={btnQuiet}>Cancel</AlertDialog.Cancel>
              <button className={btnPrimary} disabled={revoke.isPending} onClick={() => target && revoke.mutate(target.id)}>{revoke.isPending ? "Revoking…" : "Revoke token"}</button>
            </div>
          </AlertDialog.Content>
        </AlertDialog.Portal>
      </AlertDialog.Root>
    </section>
  );
}
