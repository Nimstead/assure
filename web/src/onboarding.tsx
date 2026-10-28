import { useEffect, useRef, useState } from "react";
import { Link } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { RadioGroup } from "radix-ui";
import { ArrowRight } from "lucide-react";
import clsx from "clsx";
import { adminGate, api, assetsQ, installCommands, useIsAdmin, useTitle } from "./lib";
import { Alert, btnPrimary, CopyBlock } from "./ui";

/** Pure view so the rendered commands can be tested without a network. */
export function InstallCommands({ origin, token }: { origin: string; token: string }) {
  const c = installCommands(origin, token);
  return (
    <div className="flex flex-col gap-5">
      <CopyBlock label="Linux, one line" text={c.curl} />
      <div className="flex flex-col gap-1.5">
        <CopyBlock label="Windows, in an Administrator PowerShell" text={c.windows} />
        <p className="text-xs text-muted">Needs Python 3 installed for all users first: <code className="font-mono">winget install Python.Python.3.13 --scope machine</code></p>
      </div>
      <CopyBlock label="Or with Python directly" text={c.python} />
    </div>
  );
}

const KINDS = [
  { value: "test", title: "Test machines", body: "Automated fixes may change these machines. Use for disposable or staging hosts." },
  { value: "production", title: "Production machines", body: "Nimstead finds vulnerabilities here. Fixes stay off until production remediation is turned on for this server." },
] as const;
type Kind = (typeof KINDS)[number]["value"];

/** Shown after this long without a first report: most first-run problems are one of these. */
export const TROUBLESHOOT_AFTER_MS = 120_000;

export function Onboarding() {
  useTitle("Add a machine");
  const qc = useQueryClient();
  const admin = useIsAdmin();
  // No default: sandbox is fixed per machine at enrolment, so the choice must be deliberate (DECISIONS 46).
  const [kind, setKind] = useState<Kind | null>(null);
  const token = useMutation({ mutationFn: () => api<{ token: string }>("/api/enroll-tokens", { method: "POST", body: { sandbox: kind === "test" } }) });
  const [connected, setConnected] = useState(false);
  const [slow, setSlow] = useState(false);
  const baseline = useRef<number | null>(null);

  const assets = useQuery({ ...assetsQ, refetchInterval: connected ? false : 3000 });
  const count = assets.data?.length;
  useEffect(() => {
    if (count === undefined) return;
    baseline.current ??= count;
    if (count > baseline.current) setConnected(true);
  }, [count]);
  useEffect(() => {
    if (!token.data || connected) return;
    const t = setTimeout(() => setSlow(true), TROUBLESHOOT_AFTER_MS);
    return () => clearTimeout(t);
  }, [token.data, connected]);

  if (connected) {
    return (
      <div role="status" className="mx-auto flex max-w-md flex-col items-center gap-4 py-24 text-center">
        <svg viewBox="0 0 24 24" className="size-14 text-accent" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
          <circle cx="12" cy="12" r="10" strokeOpacity=".25" />
          <path className="draw" d="M7.5 12.5l3 3 6-6.5" />
        </svg>
        <h1 className="text-2xl font-semibold">{assets.data?.at(-1)?.hostname ?? "Your machine"} is connected</h1>
        <p className="text-muted">Its software is being checked now.</p>
        <Link to="/" onClick={() => void qc.invalidateQueries()} className={clsx(btnPrimary, "no-underline")}>Go to Fix first <ArrowRight className="size-4" aria-hidden /></Link>
      </div>
    );
  }

  const first = baseline.current === 0;
  return (
    <div className="mx-auto max-w-2xl py-6 md:py-12">
      <h1 className="text-3xl font-semibold">{first ? "Add your first machine" : "Add a machine"}</h1>
      <p className="mt-2 max-w-prose text-muted">
        Nimstead reads the list of installed software on a machine, then matches it against known vulnerabilities. It never scans your network or guesses from banners. It takes about a minute.
      </p>
      <div className="mt-8 border border-line bg-surface p-5 md:p-6">
        {token.data ? (
          <div className="flex flex-col gap-6">
            <InstallCommands origin={window.location.origin} token={token.data.token} />
            <p className="text-sm text-muted">This command is shown once. Run it on each {kind === "test" ? "test" : "production"} machine you want to check; it works for 30 days.</p>
            <p className="flex items-center gap-2 text-sm" role="status">
              <span aria-hidden className="size-2 animate-pulse bg-accent" />
              Waiting for the first report…
            </p>
            {slow && (
              <div role="status" className="border border-line-strong p-4 text-sm">
                <p className="font-semibold">Nothing yet? Check these:</p>
                <ul className="mt-2 list-disc space-y-1 pl-5">
                  <li>The command finished without an error on the machine. If it printed one, that's the place to start.</li>
                  <li>The machine can reach <code className="font-mono">{window.location.origin}</code> (firewall, proxy, or a name it can't resolve).</li>
                  <li>On Windows, Python 3 is installed for all users and the PowerShell window was opened as Administrator.</li>
                  <li>The <a className="underline" href="https://github.com/Nimstead/assure/blob/main/docs/install.md" target="_blank" rel="noopener noreferrer">install guide</a> covers proxies and HTTPS.</li>
                </ul>
              </div>
            )}
          </div>
        ) : (
          <div className="flex flex-col items-start gap-5">
            <ol className="flex flex-col gap-2 text-sm">
              <li className="flex items-center gap-2"><span className="size-4 text-center text-xs" aria-hidden>1</span>Say what kind of machines these are, then create the install command</li>
              <li className="flex items-center gap-2 text-muted"><span className="size-4 text-center text-xs" aria-hidden>2</span>Run that command on the machine</li>
              <li className="flex items-center gap-2 text-muted"><span className="size-4 text-center text-xs" aria-hidden>3</span>See what to fix first</li>
            </ol>
            <fieldset className="flex w-full flex-col gap-2">
              <legend id="kind-h" className="mb-2 text-sm font-semibold">What kind of machines are these?</legend>
              <RadioGroup.Root aria-labelledby="kind-h" aria-describedby="kind-note" value={kind ?? ""} onValueChange={(v) => setKind(v as Kind)} className="grid gap-2 sm:grid-cols-2">
                {KINDS.map((k) => (
                  <RadioGroup.Item key={k.value} value={k.value} className="group flex cursor-pointer flex-col items-start gap-1 border border-line-strong bg-surface p-4 text-left hover:border-ink data-[state=checked]:border-ink data-[state=checked]:bg-accent-soft data-[state=checked]:shadow-[inset_0_0_0_1px_var(--ink)]">
                    <span className="flex items-center gap-2 font-semibold">
                      <span aria-hidden className="grid size-4 place-items-center border border-ink"><span className="size-2 bg-ink group-data-[state=unchecked]:hidden" /></span>
                      {k.title}
                    </span>
                    <span className="text-sm text-muted group-data-[state=checked]:text-ink">{k.body}</span>
                  </RadioGroup.Item>
                ))}
              </RadioGroup.Root>
              <p id="kind-note" className="text-xs text-muted">This is fixed for every machine enrolled with this command.</p>
            </fieldset>
            <button className={btnPrimary} onClick={() => token.mutate()} disabled={token.isPending || !kind} {...adminGate(admin)}>
              {token.isPending ? "Creating…" : "Create install command"}
            </button>
            <Alert error={token.error} />
          </div>
        )}
      </div>
    </div>
  );
}
