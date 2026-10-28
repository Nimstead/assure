import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import clsx from "clsx";
import { api, meQ, relativeTime, type ApiTokenRow, type MfaSetup, type OrgUser } from "./lib";
import { btnPrimary, btnQuiet, CopyBlock, ErrorState, input, Skeleton } from "./ui";

const fd = (e: FormEvent<HTMLFormElement>) => { e.preventDefault(); return new FormData(e.currentTarget); };
const Alert = ({ error }: { error: Error | null }) => error && <p role="alert" className="rounded-md bg-now-bg px-3 py-2 text-sm text-now-fg">{error.message}</p>;
const Done = ({ children }: { children: string }) => <p role="status" className="rounded-md bg-surface px-3 py-2 text-sm">{children}</p>;

/** Shows the key to add to an authenticator app and asks for its first code. */
export function MfaEnrol({ setup, onCode, pending, extra }: { setup: MfaSetup; onCode: (code: string, current?: string) => void; pending: boolean; extra?: boolean }) {
  return (
    <form className="flex flex-col gap-3" onSubmit={(e) => { const f = fd(e); onCode(String(f.get("code")), extra ? String(f.get("current")) : undefined); }}>
      <p className="text-sm">Add this key to an authenticator app (1Password, Google Authenticator, Authy…), then enter the 6-digit code it shows.</p>
      <CopyBlock label="Setup key" text={setup.secret} />
      <p className="text-xs text-muted break-all">Or open: <a className="underline" href={setup.uri}>{setup.uri}</a></p>
      {extra && (
        <label className="flex flex-col gap-1.5 text-sm font-medium">Code from your current authenticator (or a recovery code)
          <input className={input} name="current" required autoComplete="one-time-code" />
        </label>
      )}
      <label className="flex flex-col gap-1.5 text-sm font-medium">Code from the app
        <input className={input} name="code" required inputMode="numeric" pattern="[0-9 ]{6,7}" autoComplete="one-time-code" />
      </label>
      <button className={clsx(btnPrimary, "self-start")} disabled={pending}>{pending ? "Checking…" : "Turn on"}</button>
    </form>
  );
}

export function RecoveryCodes({ codes }: { codes: string[] }) {
  return (
    <div role="status" className="flex flex-col gap-2 rounded-lg border border-line-strong p-4">
      <p className="text-sm font-semibold">Save these recovery codes now. Each works once if you lose your authenticator; they won't be shown again.</p>
      <CopyBlock label="Recovery codes" text={codes.join("\n")} />
    </div>
  );
}

export function AccountSection() {
  const me = useQuery(meQ).data;
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [setup, setSetup] = useState<MfaSetup | null>(null);
  const [codes, setCodes] = useState<string[]>([]);
  const start = useMutation({ mutationFn: () => api<MfaSetup>("/api/me/mfa/setup", { method: "POST" }), onSuccess: setSetup });
  const confirm = useMutation({
    mutationFn: (b: { code: string; current_code?: string }) => api<{ recovery_codes: string[] }>("/api/me/mfa", { method: "POST", body: { setup: setup?.setup, ...b } }),
    onSuccess: (r) => { setSetup(null); setCodes(r.recovery_codes); void qc.invalidateQueries({ queryKey: meQ.queryKey }); },
  });
  const pw = useMutation({ mutationFn: (f: FormData) => api("/api/me/password", { method: "POST", body: { current: f.get("current"), new: f.get("new"), code: f.get("code") || null } }) });
  const everywhere = useMutation({ mutationFn: () => api("/api/me/sessions/revoke", { method: "POST" }), onSuccess: () => { qc.clear(); void navigate({ to: "/signin" }); } });
  if (!me) return null;
  const password = me.origin === "password";
  return (
    <section aria-labelledby="account" className="flex flex-col items-start gap-4">
      <h2 id="account" className="text-lg font-semibold">Your account</h2>
      <p className="text-sm text-muted">{me.email} · {password ? "password sign-in" : "single sign-on"}</p>
      {password && (
        <div className="flex w-full max-w-md flex-col gap-3">
          <h3 className="text-sm font-semibold">Two-step sign-in</h3>
          <p className="text-sm text-muted">
            {me.mfa ? `On. ${me.recovery_codes_left} recovery code${me.recovery_codes_left === 1 ? "" : "s"} left.` : "Off. Admins must use it; everyone else can."}
          </p>
          {codes.length > 0 && <RecoveryCodes codes={codes} />}
          {setup ? <MfaEnrol setup={setup} extra={me.mfa} pending={confirm.isPending} onCode={(code, current_code) => confirm.mutate({ code, current_code })} />
            : <button className={clsx(btnQuiet, "self-start")} disabled={start.isPending} onClick={() => start.mutate()}>{me.mfa ? "Move to a new authenticator" : "Turn on two-step sign-in"}</button>}
          <Alert error={start.error ?? confirm.error} />
        </div>
      )}
      {password && (
        <form className="flex w-full max-w-md flex-col gap-3" onSubmit={(e) => { const f = fd(e); pw.mutate(f, { onSuccess: () => (e.target as HTMLFormElement).reset() }); }}>
          <h3 className="text-sm font-semibold">Change password</h3>
          <label className="flex flex-col gap-1.5 text-sm font-medium">Current password<input className={input} name="current" type="password" required autoComplete="current-password" /></label>
          <label className="flex flex-col gap-1.5 text-sm font-medium">New password<input className={input} name="new" type="password" required minLength={12} autoComplete="new-password" /></label>
          {me.mfa && <label className="flex flex-col gap-1.5 text-sm font-medium">Authenticator code<input className={input} name="code" required autoComplete="one-time-code" /></label>}
          <Alert error={pw.error} />
          {pw.isSuccess && <Done>Password changed. Other devices were signed out.</Done>}
          <button className={clsx(btnPrimary, "self-start")} disabled={pw.isPending}>{pw.isPending ? "Saving…" : "Change password"}</button>
        </form>
      )}
      <button className={btnQuiet} disabled={everywhere.isPending} onClick={() => everywhere.mutate()}>Sign out everywhere</button>
      <Alert error={everywhere.error} />
    </section>
  );
}

export function UsersSection() {
  const qc = useQueryClient();
  const me = useQuery(meQ).data;
  const q = useQuery({ queryKey: ["users"], queryFn: () => api<OrgUser[]>("/api/users") });
  const done = () => Promise.all(["users", "ledger"].map((k) => qc.invalidateQueries({ queryKey: [k] })));
  const invite = useMutation({ mutationFn: (email: string) => api("/api/users/invite", { method: "POST", body: { email } }), onSuccess: done });
  const role = useMutation({ mutationFn: (u: OrgUser) => api(`/api/users/${u.id}`, { method: "PATCH", body: { admin: !u.admin } }), onSuccess: done });
  const remove = useMutation({ mutationFn: (u: OrgUser) => api(`/api/users/${u.id}`, { method: "DELETE" }), onSuccess: done });
  return (
    <section aria-labelledby="people" className="flex flex-col gap-3">
      <h2 id="people" className="text-lg font-semibold">People</h2>
      <p className="max-w-prose text-sm text-muted">Admins can change policy, approve fixes and manage people; everyone else can look. Removing someone signs them out at once and ends their API tokens. With single sign-on, people join by signing in.</p>
      {q.isPending ? <Skeleton className="h-20" /> : q.error ? <ErrorState error={q.error} retry={() => q.refetch()} /> : (
        <ul className="flex flex-col divide-y divide-line overflow-hidden rounded-lg border border-line bg-surface">
          {q.data.map((u) => (
            <li key={u.id} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-2.5 text-sm">
              <span className="min-w-0 flex-1 truncate">{u.email}{u.email === me?.email && <span className="text-muted"> (you)</span>}</span>
              <span className="text-muted">{u.admin ? "Admin" : "Member"} · {u.origin === "sso" ? "SSO" : u.mfa ? "password + code" : "password"}</span>
              <button className={btnQuiet} disabled={role.isPending} onClick={() => role.mutate(u)}>{u.admin ? "Make member" : "Make admin"}<span className="sr-only"> {u.email}</span></button>
              <button className={btnQuiet} disabled={remove.isPending} onClick={() => confirm(`Remove ${u.email}? They're signed out at once.`) && remove.mutate(u)}>Remove<span className="sr-only"> {u.email}</span></button>
            </li>
          ))}
        </ul>
      )}
      <Alert error={role.error ?? remove.error} />
      <form className="flex flex-wrap items-end gap-3" onSubmit={(e) => { const f = fd(e); invite.mutate(String(f.get("email")), { onSuccess: () => (e.target as HTMLFormElement).reset() }); }}>
        <label className="flex flex-col gap-1.5 text-sm font-medium">Invite by email<input className={clsx(input, "w-72")} name="email" type="email" required autoComplete="off" placeholder="colleague@company.com" /></label>
        <button className={btnPrimary} disabled={invite.isPending}>{invite.isPending ? "Sending…" : "Send invitation"}</button>
      </form>
      <Alert error={invite.error} />
      {invite.isSuccess && <Done>Invitation sent. They choose their own password from the link (valid 24 hours).</Done>}
    </section>
  );
}

export function ApiTokensSection() {
  const qc = useQueryClient();
  const me = useQuery(meQ).data;
  const q = useQuery({ queryKey: ["api-tokens"], queryFn: () => api<ApiTokenRow[]>("/api/tokens") });
  const [made, setMade] = useState("");
  const done = () => Promise.all(["api-tokens", "ledger"].map((k) => qc.invalidateQueries({ queryKey: [k] })));
  const create = useMutation({
    mutationFn: (f: FormData) => api<{ token: string }>("/api/tokens", { method: "POST", body: { name: f.get("name"), days: Number(f.get("days")), code: f.get("code") || null } }),
    onSuccess: (r) => { setMade(r.token); void done(); },
  });
  const revoke = useMutation({ mutationFn: (id: string) => api(`/api/tokens/${id}`, { method: "DELETE" }), onSuccess: done });
  return (
    <section aria-labelledby="api-tokens" className="flex flex-col gap-3">
      <h2 id="api-tokens" className="text-lg font-semibold">API tokens</h2>
      <p className="max-w-prose text-sm text-muted">Read-only access for scripts and other tools: findings (also as CSV), assets, the summary and evidence. Send it as <code className="rounded bg-sunken px-1">Authorization: Bearer …</code>. A token stops working if its creator stops being an admin.</p>
      {q.isPending ? <Skeleton className="h-16" /> : q.error ? <ErrorState error={q.error} retry={() => q.refetch()} /> : q.data.length > 0 && (
        <ul className="flex flex-col divide-y divide-line overflow-hidden rounded-lg border border-line bg-surface">
          {q.data.map((t) => (
            <li key={t.id} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-2.5 text-sm">
              <span className="font-medium">{t.name}</span>
              <span className="min-w-0 flex-1 text-muted">by {t.created_by} · expires {relativeTime(t.expires ?? "")} · {t.last_used ? `used ${relativeTime(t.last_used)}` : "never used"}</span>
              <button className={btnQuiet} disabled={revoke.isPending} onClick={() => revoke.mutate(t.id)}>Revoke<span className="sr-only"> {t.name}</span></button>
            </li>
          ))}
        </ul>
      )}
      {made && <CopyBlock label="New token (shown once)" text={made} />}
      <form className="flex flex-wrap items-end gap-3" onSubmit={(e) => { const f = fd(e); setMade(""); create.mutate(f, { onSuccess: () => (e.target as HTMLFormElement).reset() }); }}>
        <label className="flex flex-col gap-1.5 text-sm font-medium">Name<input className={clsx(input, "w-56")} name="name" required maxLength={100} placeholder="Jira sync" /></label>
        <label className="flex flex-col gap-1.5 text-sm font-medium">Expires
          <select className={clsx(input, "w-36")} name="days" defaultValue="90">
            <option value="30">in 30 days</option><option value="90">in 90 days</option><option value="365">in a year</option>
          </select>
        </label>
        {me?.mfa && <label className="flex flex-col gap-1.5 text-sm font-medium">Authenticator code<input className={clsx(input, "w-36")} name="code" required autoComplete="one-time-code" /></label>}
        <button className={btnPrimary} disabled={create.isPending}>{create.isPending ? "Creating…" : "Create token"}</button>
      </form>
      <Alert error={create.error ?? revoke.error} />
    </section>
  );
}
