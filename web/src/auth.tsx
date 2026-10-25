import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api, useTitle } from "./lib";
import { btnPrimary, input } from "./ui";
import { Logo } from "./shell";

export function AuthPage({ mode }: { mode: "signin" | "signup" }) {
  const signup = mode === "signup";
  useTitle(signup ? "Create account" : "Sign in");
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [org, setOrg] = useState("");
  const go = useMutation({
    mutationFn: (f: FormData) =>
      signup
        ? api("/api/auth/signup", { method: "POST", body: { email: f.get("email"), password: f.get("password"), org_name: org } })
        : api("/api/auth/login", { method: "POST", body: { email: f.get("email"), password: f.get("password") } }),
    onSuccess: async () => {
      qc.clear();
      await navigate({ to: "/" });
    },
  });
  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    go.mutate(new FormData(e.currentTarget));
  };

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
        <button className={btnPrimary} disabled={go.isPending}>{go.isPending ? "One moment…" : signup ? "Create account" : "Sign in"}</button>
      </form>
      <p className="text-sm text-muted">
        {signup ? "Already have an account? " : "New to Nimstead? "}
        <Link to={signup ? "/signin" : "/signup"} className="font-medium text-accent underline">{signup ? "Sign in" : "Create an account"}</Link>
      </p>
    </main>
  );
}
