import { useState, type FormEvent, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { TriangleAlert } from "lucide-react";
import { api, relativeTime, type NotifySettings, type SsoSettings } from "./lib";
import { btnPrimary, btnQuiet, ErrorState, input, Skeleton } from "./ui";

const Field = ({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) => (
  <label className="flex flex-col gap-1.5 text-sm font-medium">
    {label}
    {children}
    {hint && <span className="text-xs font-normal text-muted">{hint}</span>}
  </label>
);

const list = (s: string) => s.split(/[\s,]+/).filter(Boolean);

export function SsoSection() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["sso"], queryFn: () => api<SsoSettings>("/api/settings/sso"), retry: false });
  const save = useMutation({
    mutationFn: (body: object) => api<SsoSettings>("/api/settings/sso", { method: "PUT", body }),
    onSuccess: (data) => { qc.setQueryData(["sso"], data); void qc.invalidateQueries({ queryKey: ["ledger"] }); },
  });
  if (q.isPending) return <Skeleton className="h-40" />;
  if (q.error) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  const s = q.data;
  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = e.currentTarget, f = new FormData(form);
    save.mutate({
      issuer: f.get("issuer"), client_id: f.get("client_id"), client_secret: f.get("client_secret") || undefined,
      domains: list(String(f.get("domains"))), required: f.get("required") === "on",
    }, { onSuccess: () => form.reset() });  // clears the write-only secret field
  };
  return (
    <section aria-labelledby="sso" className="flex flex-col gap-3">
      <h2 id="sso" className="text-lg font-semibold">Single sign-on (OIDC)</h2>
      <p className="max-w-prose text-sm text-muted">
        Let people sign in with your identity provider. Register this redirect URI there: <code className="font-mono text-xs text-ink">{s.redirect_uri}</code>. People whose email is on an allowed domain get an account here the first time they sign in. Leave the issuer empty to switch SSO off.
      </p>
      {save.error && <p role="alert" className="rounded-md bg-now-bg px-3 py-2 text-sm text-now-fg">Couldn't save: {save.error.message}</p>}
      <form key={JSON.stringify(s)} onSubmit={submit} className="grid max-w-xl gap-4">
        <Field label="Issuer URL"><input className={input} name="issuer" type="url" defaultValue={s.issuer} placeholder="https://login.example.com" autoComplete="off" /></Field>
        <Field label="Client ID"><input className={input} name="client_id" defaultValue={s.client_id} autoComplete="off" /></Field>
        <Field label="Client secret" hint={s.client_secret_set ? "A secret is saved and never shown again. Leave blank to keep it." : "Stored on the server; it can't be read back."}>
          <input className={input} name="client_secret" type="password" autoComplete="new-password" placeholder={s.client_secret_set ? "Unchanged" : ""} />
        </Field>
        <Field label="Allowed email domains" hint="Comma or space separated, for example example.com">
          <input className={input} name="domains" defaultValue={s.domains.join(", ")} autoComplete="off" />
        </Field>
        <label className="flex items-start gap-2 text-sm">
          <input type="checkbox" name="required" defaultChecked={s.required} className="mt-1 size-4" />
          <span><span className="font-medium">Require SSO</span><br /><span className="text-muted">Password sign-in is switched off for everyone in this organisation. Check SSO works first: nobody can sign in with a password to fix a mistake.</span></span>
        </label>
        <div><button className={btnPrimary} disabled={save.isPending}>{save.isPending ? "Saving…" : "Save SSO settings"}</button></div>
      </form>
    </section>
  );
}

export function NotificationsSection() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["notifications"], queryFn: () => api<NotifySettings>("/api/settings/notifications"), retry: false });
  const refresh = (data: NotifySettings) => qc.setQueryData(["notifications"], data);
  const save = useMutation({
    mutationFn: (body: object) => api<NotifySettings>("/api/settings/notifications", { method: "PUT", body }),
    onSuccess: (data) => { refresh(data); void qc.invalidateQueries({ queryKey: ["ledger"] }); },
  });
  const test = useMutation({
    mutationFn: () => api("/api/settings/notifications/test", { method: "POST" }),
    onSuccess: () => setTimeout(() => void qc.invalidateQueries({ queryKey: ["notifications"] }), 1500),
  });
  const [removing, setRemoving] = useState(false);
  if (q.isPending) return <Skeleton className="h-40" />;
  if (q.error) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  const s = q.data;
  const last = s.recent[0];
  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = e.currentTarget, f = new FormData(form);
    save.mutate({
      webhook_url: removing ? "" : String(f.get("webhook_url") || "") || undefined, webhook_format: f.get("webhook_format"),
      emails: list(String(f.get("emails"))),
    }, { onSuccess: () => { form.reset(); setRemoving(false); } });
  };
  return (
    <section aria-labelledby="alerts" className="flex flex-col gap-3">
      <h2 id="alerts" className="text-lg font-semibold">Failure alerts</h2>
      <p className="max-w-prose text-sm text-muted">
        Get told when a fix is rolled back, fails or doesn't take, and when a new fix-now vulnerability (known exploited) appears. One message per machine, not one per CVE.
      </p>
      <div role="status" aria-live="polite">
        {last && !last.ok && (
          <p className="flex items-start gap-2 rounded-md bg-now-bg px-3 py-2 text-sm text-now-fg">
            <TriangleAlert className="mt-0.5 size-4 shrink-0" aria-hidden />
            <span><strong className="font-semibold">Last delivery failed</strong> ({last.channel}, <time>{relativeTime(last.ts)}</time>): {last.error}</span>
          </p>
        )}
        {last?.ok && <p className="text-sm text-muted">Last delivery succeeded {relativeTime(last.ts)} ({last.channel}).</p>}
      </div>
      {save.error && <p role="alert" className="rounded-md bg-now-bg px-3 py-2 text-sm text-now-fg">Couldn't save: {save.error.message}</p>}
      <form key={JSON.stringify([s.webhook_set, s.webhook_format, s.emails])} onSubmit={submit} className="grid max-w-xl gap-4">
        <Field label="Webhook URL" hint={s.webhook_set ? `Saved for ${s.webhook_host}. Enter a new URL to replace it.` : "https only. Slack incoming webhooks work as they are."}>
          <input className={input} name="webhook_url" type="url" autoComplete="off" placeholder={s.webhook_set ? "Unchanged" : "https://hooks.slack.com/services/…"} disabled={removing} />
        </Field>
        <Field label="Webhook format">
          <select className={input} name="webhook_format" defaultValue={s.webhook_format}>
            <option value="slack">Slack-compatible ({"{"}"text": …{"}"})</option>
            <option value="json">Generic JSON (kind, urgent, text)</option>
          </select>
        </Field>
        <Field label="Email recipients" hint={s.email_available ? "Comma or space separated." : "Email isn't set up on this server (NIMSTEAD_SMTP_URL and NIMSTEAD_SMTP_FROM), so these won't be sent."}>
          <input className={input} name="emails" type="text" defaultValue={s.emails.join(", ")} autoComplete="off" />
        </Field>
        <div className="flex flex-wrap items-center gap-2">
          <button className={btnPrimary} disabled={save.isPending}>{save.isPending ? "Saving…" : "Save alert settings"}</button>
          <button type="button" className={btnQuiet} disabled={test.isPending || (!s.webhook_set && !(s.emails.length && s.email_available))} onClick={() => test.mutate()}>
            {test.isPending ? "Sending…" : "Send test alert"}
          </button>
          {s.webhook_set && (
            <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={removing} onChange={(e) => setRemoving(e.target.checked)} className="size-4" />Remove webhook on save</label>
          )}
        </div>
      </form>
    </section>
  );
}
