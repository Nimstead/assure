import { useEffect, useRef, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, assetsQ, installCommands, useTitle } from "./lib";
import { btnPrimary, CopyBlock } from "./ui";

/** Pure view so the rendered commands can be tested without a network. */
export function InstallCommands({ origin, token }: { origin: string; token: string }) {
  const c = installCommands(origin, token);
  return (
    <div className="flex flex-col gap-5">
      <CopyBlock label="Linux, one line" text={c.curl} />
      <CopyBlock label="Windows, in an Administrator PowerShell (needs Python 3)" text={c.windows} />
      <CopyBlock label="Or with Python directly" text={c.python} />
    </div>
  );
}

export function Onboarding() {
  useTitle("Add a machine");
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [sandbox, setSandbox] = useState(false);
  const token = useMutation({ mutationFn: () => api<{ token: string }>("/api/enroll-tokens", { method: "POST", body: { sandbox } }) });
  const [celebrate, setCelebrate] = useState(false);
  const baseline = useRef<number | null>(null);

  const assets = useQuery({ ...assetsQ, refetchInterval: 3000 });
  const count = assets.data?.length;
  useEffect(() => {
    if (count === undefined) return;
    baseline.current ??= count;
    if (count > baseline.current) setCelebrate(true);
  }, [count]);
  useEffect(() => {
    if (!celebrate) return;
    const t = setTimeout(async () => {
      await qc.invalidateQueries();
      await navigate({ to: "/" });
    }, 2200);
    return () => clearTimeout(t);
  }, [celebrate, qc, navigate]);

  if (celebrate) {
    return (
      <div role="status" className="mx-auto flex max-w-md flex-col items-center gap-4 py-24 text-center">
        <svg viewBox="0 0 24 24" className="size-14 text-accent" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
          <circle cx="12" cy="12" r="10" strokeOpacity=".25" />
          <path className="draw" d="M7.5 12.5l3 3 6-6.5" />
        </svg>
        <h1 className="text-2xl font-semibold">{assets.data?.at(-1)?.hostname ?? "Your machine"} is connected</h1>
        <p className="text-muted">Checking it now. Taking you to what to fix first.</p>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-2xl py-6 md:py-12">
      <h1 className="text-3xl font-semibold">Add your first machine</h1>
      <p className="mt-2 max-w-prose text-muted">
        Nimstead reads the list of installed software on a machine, then matches it against known vulnerabilities. It never scans your network or guesses from banners. It takes about a minute.
      </p>
      <div className="mt-8 rounded-lg border border-line bg-surface p-5 md:p-6">
        {token.data ? (
          <div className="flex flex-col gap-6">
            <InstallCommands origin={window.location.origin} token={token.data.token} />
            <p className="text-sm text-muted">This token is shown once. Run the command on the machine you want to check.</p>
            <p className="flex items-center gap-2 text-sm" role="status">
              <span aria-hidden className="size-2 animate-pulse rounded-full bg-accent" />
              Waiting for the first report…
            </p>
          </div>
        ) : (
          <div className="flex flex-col items-start gap-4">
            <ol className="flex flex-col gap-2 text-sm">
              <li className="flex items-center gap-2"><span className="size-4 text-center text-xs" aria-hidden>1</span>Create a one-time enrolment token</li>
              <li className="flex items-center gap-2 text-muted"><span className="size-4 text-center text-xs" aria-hidden>2</span>Run one command on the machine</li>
              <li className="flex items-center gap-2 text-muted"><span className="size-4 text-center text-xs" aria-hidden>3</span>See what to fix first</li>
            </ol>
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" className="size-4 accent-[var(--accent)]" checked={sandbox} onChange={(e) => setSandbox(e.target.checked)} />
              This is a disposable test machine
            </label>
            {sandbox && <p className="max-w-prose text-sm text-muted">Sandbox machines are the only ones automated fixes may change until production remediation is enabled.</p>}
            <button className={btnPrimary} onClick={() => token.mutate()} disabled={token.isPending}>
              {token.isPending ? "Creating…" : "Add a machine"}
            </button>
            {token.error && <p role="alert" className="text-sm text-now-fg">{token.error.message}</p>}
          </div>
        )}
      </div>
    </div>
  );
}
