import { Link } from "@tanstack/react-router";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ArrowRight, Wrench } from "lucide-react";
import clsx from "clsx";
import { Fragment, useState } from "react";
import { adminGate, api, jobAnchor, plural, refresh, useIsAdmin, type Job } from "./lib";
import { Alert, btnQuiet, ConfirmDialog, Done } from "./ui";

/** "web-1", "web-1 and web-2", "web-1, web-2 and 3 more". */
export const hostList = (names: string[]) =>
  names.length <= 2 ? names.join(" and ") : `${names.slice(0, 2).join(", ")} and ${names.length - 2} more`;

/** Plans a fix for one package on the given machines (one job each). It stays where it is and says what it planned, with a
 * link to review it: planning several fixes in a row never means coming back each time. Approval is still the gate. */
export function PlanFixButton({ ecosystem, pkg, assetIds, names, hosts = assetIds.length, label = "Plan fix", kind = "machine", className }: {
  ecosystem: string; pkg: string; assetIds: string[]; names?: string[]; hosts?: number; label?: string; kind?: string; className?: string;
}) {
  const admin = useIsAdmin();
  const qc = useQueryClient();
  const [confirming, setConfirming] = useState(false);
  const plan = useMutation({
    mutationFn: async () => {
      // one request for every machine: each is planned on its own, so a refusal on one keeps the others
      const r = await api<{ jobs: Job[]; errors: { asset_id: string; error: string }[] }>("/api/remediation/jobs/batch",
        { method: "POST", body: { asset_ids: assetIds, ecosystem, package: pkg } });
      if (r.errors.length) throw new Error([...new Set(r.errors.map((e) => e.error))].join(" "));
      return r.jobs;
    },
    onSettled: () => refresh(qc, "jobs"), // partial failures still created some jobs
  });
  const made = plan.data;
  if (made?.length) {
    const where = names?.length ? ` on ${hostList(names)}` : made.length > 1 ? ` on ${plural(made.length, "machine")}` : "";
    return (
      <div className={clsx("flex flex-col items-start gap-1", className)}>
        <Done>{`Planned${where}: awaiting approval.`}</Done>
        <Link to="/remediation" hash={jobAnchor(made[0]!.id)} className="inline-flex min-h-[44px] items-center gap-1.5 text-sm font-medium text-accent underline md:min-h-9">
          <span>Review and approve<span className="sr-only"> the fix for {pkg}</span></span> <ArrowRight className="size-4" aria-hidden />
        </Link>
      </div>
    );
  }
  return (
    <div className={clsx("flex flex-col items-start gap-1.5", className)}>
      {/* more than two machines: list them all before planning; one or two are named on the button already */}
      <button className={btnQuiet} disabled={plan.isPending} onClick={() => (names && names.length > 2 ? setConfirming(true) : plan.mutate())} {...adminGate(admin)}>
        <Wrench className="size-4" aria-hidden />{plan.isPending ? "Planning…" : label}
        <span className="sr-only"> for {pkg}{names?.length ? ` on ${hostList(names)}` : hosts > 1 ? ` on ${hosts} machines` : ""}</span>
      </button>
      {/* what one click will plan, said before the click */}
      {/* aria-hidden: the button's own name already says these hosts to a screen reader */}
      {names && names.length > 1 && !plan.isPending && <p aria-hidden className="max-w-xs text-xs text-muted">On {hostList(names)}</p>}
      <Alert error={plan.error} className="max-w-sm" />
      <ConfirmDialog open={confirming} onOpenChange={setConfirming} title={`Plan the ${pkg} fix on ${plural(names?.length ?? 0, kind)}?`}
        description="Planning changes nothing: each machine's fix waits for approval." confirmLabel={`Plan on ${plural(names?.length ?? 0, kind)}`}
        onConfirm={() => { setConfirming(false); plan.mutate(); }}>
        <p className="mt-3 text-sm">{names?.map((n, i) => <Fragment key={n}><span className="whitespace-nowrap">{n}{i < (names?.length ?? 0) - 1 && ","}</span>{" "}</Fragment>)}</p>
      </ConfirmDialog>
    </div>
  );
}
