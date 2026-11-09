import { useNavigate } from "@tanstack/react-router";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Wrench } from "lucide-react";
import clsx from "clsx";
import { adminGate, api, jobAnchor, refresh, useIsAdmin, type Job } from "./lib";
import { Alert, btnQuiet } from "./ui";

/** Render an admin-gated batch-plan action under router and QueryClient providers.
 * ecosystem/pkg identify the action and assetIds is sent unchanged to the server.
 * hosts defaults to assetIds.length and affects accessible text only. label/className
 * customize presentation. On click, POST batch plans and refresh job-derived queries
 * after success or failure. Any returned per-asset errors show one deduplicated error;
 * partial jobs remain created. Full success navigates to Remediation with an optional first-job anchor only while
 * the current pathname still equals its click-time value. This does not approve jobs.
 */
export function PlanFixButton({ ecosystem, pkg, assetIds, hosts = assetIds.length, label = "Plan fix", className }: { ecosystem: string; pkg: string; assetIds: string[]; hosts?: number; label?: string; className?: string }) {
  const admin = useIsAdmin();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const plan = useMutation({
    mutationFn: async (_from: string) => {
      // one request for every machine: each is planned on its own, so a refusal on one keeps the others
      const r = await api<{ jobs: Job[]; errors: { asset_id: string; error: string }[] }>("/api/remediation/jobs/batch",
        { method: "POST", body: { asset_ids: assetIds, ecosystem, package: pkg } });
      if (r.errors.length) throw new Error([...new Set(r.errors.map((e) => e.error))].join(" "));
      return r.jobs;
    },
    onSettled: () => refresh(qc, "jobs"), // partial failures still created some jobs
    // Land on the new fix, but only if the user is still where they pressed the button.
    onSuccess: (made, from) => {
      if (location.pathname === from) void navigate({ to: "/remediation", hash: made[0] ? jobAnchor(made[0].id) : undefined });
    },
  });
  return (
    <div className={clsx("flex flex-col items-start gap-1.5", className)}>
      <button className={btnQuiet} disabled={plan.isPending} onClick={() => plan.mutate(location.pathname)} {...adminGate(admin)}>
        <Wrench className="size-4" aria-hidden />{plan.isPending ? "Planning…" : label}
        <span className="sr-only"> for {pkg}{hosts > 1 ? ` on ${hosts} hosts` : ""}</span>
      </button>
      <Alert error={plan.error} className="max-w-sm" />
    </div>
  );
}
