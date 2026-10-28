import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api, useTitle } from "./lib";
import { btnPrimary, btnQuiet, input } from "./ui";
import { MfaEnrol, RecoveryCodes } from "./people";
import type { MfaSetup } from "./lib";
import { Logo } from "./shell";

const SSO_ERRORS: Record<string, string> = {
  not_configured: "Single sign-on isn't set up for that email domain.",
  state: "That sign-in attempt expired or didn't start here. Try again.",
  account_elsewhere: "That email already belongs to an account in another organisation.",
  domain_not_allowed: "Your email domain isn't allowed to sign in to this organisation.",
  email_unverified: "Your identity provider hasn't verified your email address.",
};
const ssoError = (code: string | null) => code && (SSO_ERRORS[code] ?? "Single sign-on failed. Try again or ask your administrator.");

export function AuthPage({ mode }: { mode: "signin" | "signup" }) {
  const signup = mode === "signup";
  useTitle(signup ? "Create account" : "Sign in");
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [org, setOrg] = useState("");
  const [sentTo, setSentTo] = useState("");
  const [creds, setCreds] = useState({ email: "", password: "" });
  const [mfa, setMfa] = useState<null | { mfa: "required" } | ({ mfa: "setup" } & MfaSetup)>(null);
  const [codes, setCodes] = useState<string[]>([]);
  const [forgot, setForgot] = useState(false);
  const params = new URLSearchParams(window.location.search);
  const ssoMsg = ssoError(params.get("sso_error"));
  const enter = async () => { qc.clear(); await navigate({ to: "/" }); };
  type Answer = { status?: string; email?: string; mfa?: "required" | "setup"; recovery_codes?: string[] } & Partial<MfaSetup>;
  const go = useMutation({
    mutationFn: (b: { email: string; password: string; code?: string; setup?: string }) =>
      signup
        ? api<Answer>("/api/auth/signup", { method: "POST", body: { ...b, org_name: org } })
        : api<Answer>("/api/auth/login", { method: "POST", body: b }),
    onSuccess: async (r) => {
      if (r.status === "check_email") return setSentTo(r.email ?? ""); // the account is created from the emailed link
      if (r.mfa === "required") return setMfa({ mfa: "required" });
      if (r.mfa === "setup") return setMfa(r as { mfa: "setup" } & MfaSetup);
      if (r.recovery_codes) return setCodes(r.recovery_codes); // shown once, then Continue
      await enter();
    },
  });
  const reset = useMutation({ mutationFn: (email: string) => api<{ email: string }>("/api/auth/password/reset", { method: "POST", body: { email } }) });
  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const c = { email: String(f.get("email")), password: String(f.get("password")) };
    setCreds(c);
    go.mutate(c);
  };
  if (codes.length) return (
    <main className="mx-auto flex min-h-dvh w-full max-w-sm flex-col justify-center gap-6 px-4 py-10">
      <Logo />
      <RecoveryCodes codes={codes} />
      <button className={btnPrimary} onClick={enter}>I've saved them, continue</button>
    </main>
  );
  if (mfa) return (
    <main className="mx-auto flex min-h-dvh w-full max-w-sm flex-col justify-center gap-6 px-4 py-10">
      <Logo />
      <h1 className="text-2xl font-semibold">{mfa.mfa === "setup" ? "Set up two-step sign-in" : "Enter your code"}</h1>
      {mfa.mfa === "setup" ? <>
        <p className="text-sm text-muted">Admins can change what runs on your machines, so a password alone isn't enough.</p>
        <MfaEnrol setup={mfa} pending={go.isPending} onCode={(code) => go.mutate({ ...creds, code, setup: mfa.setup })} />
      </> : (
        <form className="flex flex-col gap-4" onSubmit={(e) => { e.preventDefault(); go.mutate({ ...creds, code: String(new FormData(e.currentTarget).get("code")) }); }}>
          <label className="flex flex-col gap-1.5 text-sm font-medium">Code from your authenticator app, or a recovery code
            <input className={input} name="code" required autoFocus autoComplete="one-time-code" />
          </label>
          <button className={btnPrimary} disabled={go.isPending}>{go.isPending ? "Checking…" : "Sign in"}</button>
        </form>
      )}
      {go.error && <p role="alert" className="rounded-md bg-now-bg px-3 py-2 text-sm text-now-fg">{go.error.message}</p>}
      <button className={btnQuiet} onClick={() => { setMfa(null); go.reset(); }}>Back</button>
    </main>
  );

  return (
    <main className="mx-auto flex min-h-dvh w-full max-w-sm flex-col justify-center gap-8 px-4 py-10">
      <Logo />
      <div>
        <h1 className="text-2xl font-semibold">{signup ? "Create your account" : "Welcome back"}</h1>
        <p className="mt-1 text-sm text-muted">
          {signup ? "Find out what to fix first on your machines, in a few minutes." : "Sign in to see what needs fixing."}
        </p>
      </div>
      <form onSubmit={submit} className="flex flex-col gap-4">
        {signup && (
          <label className="flex flex-col gap-1.5 text-sm font-medium">
            Organisation
            <input className={input} value={org} onChange={(e) => setOrg(e.target.value)} required maxLength={200} autoComplete="organization" placeholder="Acme Ltd" />
          </label>
        )}
        <label className="flex flex-col gap-1.5 text-sm font-medium">
          Email
          <input className={input} name="email" type="email" required autoComplete="email" placeholder="you@company.com" />
        </label>
        <label className="flex flex-col gap-1.5 text-sm font-medium">
          Password
          <input className={input} name="password" type="password" required minLength={signup ? 12 : undefined} autoComplete={signup ? "new-password" : "current-password"} aria-describedby="pw-hint" />
          {signup && <span id="pw-hint" className="text-xs font-normal text-muted">At least 12 characters. A few random words works well.</span>}
        </label>
        {go.error && <p role="alert" className="rounded-md bg-now-bg px-3 py-2 text-sm text-now-fg">{go.error.message}</p>}
        {sentTo && <p role="status" className="rounded-md bg-surface px-3 py-2 text-sm">Check {sentTo} for a link to finish creating your account and choose your password.</p>}
        {!signup && params.get("reset") && <p role="status" className="rounded-md bg-surface px-3 py-2 text-sm">Password changed. Sign in with your new password.</p>}
        <button className={btnPrimary} disabled={go.isPending}>{go.isPending ? "One moment…" : signup ? "Create account" : "Sign in"}</button>
      </form>
      {!signup && (forgot ? (
        <form className="flex flex-col gap-3" onSubmit={(e) => { e.preventDefault(); reset.mutate(String(new FormData(e.currentTarget).get("email"))); }}>
          <label className="flex flex-col gap-1.5 text-sm font-medium">Email for the reset link
            <input className={input} name="email" type="email" required autoComplete="email" />
          </label>
          <button className={btnQuiet} disabled={reset.isPending}>Send reset link</button>
          {reset.error && <p role="alert" className="rounded-md bg-now-bg px-3 py-2 text-sm text-now-fg">{reset.error.message}</p>}
          {reset.data && <p role="status" className="rounded-md bg-surface px-3 py-2 text-sm">If {reset.data.email} has a password account, a link to reset it is on its way (valid 1 hour).</p>}
        </form>
      ) : <button className="self-start text-sm text-accent underline" onClick={() => setForgot(true)}>Forgot password?</button>)}
      {!signup && (
        <form method="post" action="/api/auth/sso/start" className="flex flex-col gap-3 border-t border-line pt-6" aria-labelledby="sso-h">
          <h2 id="sso-h" className="text-sm font-semibold">Single sign-on</h2>
          {ssoMsg && <p role="alert" className="rounded-md bg-now-bg px-3 py-2 text-sm text-now-fg">{ssoMsg}</p>}
          <label className="flex flex-col gap-1.5 text-sm font-medium">
            Work email
            <input className={input} name="email" type="email" required autoComplete="email" placeholder="you@company.com" />
          </label>
          <button className={btnQuiet}>Continue with SSO</button>
        </form>
      )}
      <p className="text-sm text-muted">
        {signup ? "Already have an account? " : "New to Nimstead? "}
        <Link to={signup ? "/signin" : "/signup"} className="font-medium text-accent underline">{signup ? "Sign in" : "Create an account"}</Link>
      </p>
    </main>
  );
}
