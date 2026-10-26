import { useEffect } from "react";
import { queryOptions, useQuery } from "@tanstack/react-query";

// ---- types (mirror api/src/nimstead/app.py) ---------------------------------
export const PRIORITIES = ["fix-now", "next", "planned", "low"] as const;
export type Priority = (typeof PRIORITIES)[number];
export type Status = "open" | "resolved" | "accepted";
export type Criticality = "low" | "medium" | "high" | "critical";

export interface Asset {
  id: string; hostname: string; os_name: string; ecosystem: string; kind: "host" | "application";
  criticality: Criticality; internet_facing: boolean; sandbox: boolean; ring: 0 | 1; health_units: string[];
  first_seen: string; last_seen: string; open_by_priority: Partial<Record<Priority, number>>;
}
export interface SbomResult { components: number; mapped: number; unique_packages: number; skipped: Record<string, number>; open: number; resolved: number }
export const sbomSummary = (r: SbomResult) =>
  `${r.mapped} of ${r.components} components recognised (${r.unique_packages} unique packages), ${r.components - r.mapped} skipped. ${r.open} open finding${r.open === 1 ? "" : "s"}, ${r.resolved} resolved.`;
export interface Finding {
  id: string; asset_id: string; hostname: string; ecosystem: string; package: string;
  installed_version: string; fixed_version: string | null; vuln_id: string; advisory_ids: string[];
  summary: string | null; cvss: number | null; epss: number | null; kev: boolean; score: number;
  priority: Priority; reasons: string[]; status: Status; first_seen: string; last_seen: string;
  resolved_at: string | null;
}
export interface Action {
  ecosystem: string; package: string; fixed_version: string; hosts: string[]; vulns: string[];
  kev: boolean; max_score: number;
}
export interface Summary { assets: number; open_by_priority: Partial<Record<Priority, number>>; top_actions: Action[]; attention: Job[] }

// ---- remediation -----------------------------------------------------------------
export type JobStatus = "planned" | "approved" | "dispatched" | "verifying" | "succeeded" | "failed" | "rolled_back" | "rollback_failed" | "not_fixed" | "aborted" | "cancelled";
export interface JobStep { step: string; ok: boolean; output?: string }
export interface Job {
  id: string; asset_id: string; hostname: string; status: JobStatus; manager: string; action_key: string;
  packages: unknown; finding_ids: string[]; summary: string; created_by: string; approved_by: string | null;
  created: string; updated: string; steps: JobStep[] | null; error: string | null;
}
export const JOB_GROUPS = [
  { key: "approval", title: "Needs approval", statuses: ["planned"] },
  { key: "progress", title: "In progress", statuses: ["approved", "dispatched", "verifying"] },
  { key: "attention", title: "Needs attention", statuses: ["failed", "rolled_back", "rollback_failed", "not_fixed", "aborted"] },
  { key: "done", title: "Done", statuses: ["succeeded", "cancelled"] },
] as const;
export const JOB_STATUS_LABEL: Record<JobStatus, string> = {
  planned: "Awaiting approval", approved: "Approved, waiting for host", dispatched: "Running on host", verifying: "Verifying",
  succeeded: "Fixed and verified", failed: "Failed", rolled_back: "Rolled back", rollback_failed: "Rollback failed",
  not_fixed: "Applied, still vulnerable", aborted: "Aborted", cancelled: "Cancelled",
};
export const groupJobs = (jobs: Job[]) =>
  JOB_GROUPS.map((g) => ({ ...g, jobs: jobs.filter((j) => (g.statuses as readonly string[]).includes(j.status)) }));
export const isActiveJob = (j: Pick<Job, "status">) => ["approved", "dispatched", "verifying"].includes(j.status);

export const APPROVE_COPY = "Saves a rollback copy of each package, upgrades, checks health, rolls back automatically on failure. Success is confirmed by the next inventory.";

/** "remediation_not_fixed" -> "Remediation not fixed". */
export const humaniseKind = (k: string) => { const t = k.replace(/_/g, " ").trim(); return t.charAt(0).toUpperCase() + t.slice(1); };

export interface LedgerEntry { seq: number; ts: string; kind: string; subject: string; hash: string; prev_hash: string; data: Record<string, unknown> }
export interface Control { framework: string; control: string; requirement: string; status: "met" | "not_met"; evidence: string }
export interface EvidenceReport {
  controls: Control[]; period: { from: string; to: string };
  metrics: { resolved: number; resolved_within_sla: number; overdue_open: number; mttr_days: number | null };
  ledger: { head_hash: string; entries: number };
}
export interface EnrollToken { id: string; created: string; expires: string; revoked: boolean; sandbox: boolean }
export interface Settings { remediation_mode: "suggest" | "approve" | "auto"; canary_soak_hours: number; production_remediation_allowed: boolean }
export interface SsoSettings {
  issuer: string; client_id: string; client_secret_set: boolean; domains: string[]; required: boolean; redirect_uri: string;
  domain_checks: { domain: string; verified: boolean; txt_name: string; txt_value: string }[];
}
export interface NotifySettings {
  webhook_set: boolean; webhook_host: string | null; webhook_format: "slack" | "json"; emails: string[]; email_available: boolean;
  last_delivery_failed: boolean; recent: { ts: string; kind: string; channel: string; urgent: boolean; ok: boolean; error: string | null }[];
}
export const settingsQ = queryOptions({ queryKey: ["settings"], queryFn: () => api<Settings>("/api/settings") });

// ---- api ---------------------------------------------------------------------
export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

/** A string body is sent as-is (already-serialised JSON, e.g. an uploaded SBOM); anything else is JSON-encoded. */
export async function api<T>(path: string, init?: { method?: string; body?: unknown }): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, {
      method: init?.method,
      headers: init?.body ? { "Content-Type": "application/json" } : undefined,
      body: init?.body ? (typeof init.body === "string" ? init.body : JSON.stringify(init.body)) : undefined,
    });
  } catch {
    throw new ApiError(0, "Can't reach the server. Check your connection and try again.");
  }
  if (!res.ok) throw new ApiError(res.status, await errorMessage(res));
  return res.status === 204 ? (undefined as T) : res.json();
}

/** FastAPI `detail` is a string, or a list of validation errors. */
async function errorMessage(res: Response): Promise<string> {
  try {
    const { detail } = await res.json();
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail) && detail[0]?.msg) {
      const field = detail[0].loc?.at(-1);
      return `${field ? `${field}: ` : ""}${detail[0].msg}`;
    }
  } catch { /* not JSON */ }
  return `Something went wrong (${res.status}).`;
}

// ---- priority ----------------------------------------------------------------
export const PRIORITY_LABEL: Record<Priority, string> = { "fix-now": "Fix now", next: "Next", planned: "Planned", low: "Low" };
export const PRIORITY_CLASS: Record<Priority, string> = {
  "fix-now": "bg-now-bg text-now-fg", next: "bg-next-bg text-next-fg",
  planned: "bg-planned-bg text-planned-fg", low: "bg-low-bg text-low-fg",
};

/** Same thresholds as api/src/nimstead/risk.py. */
export function priorityOf(score: number, kev: boolean): Priority {
  return kev || score >= 75 ? "fix-now" : score >= 50 ? "next" : score >= 25 ? "planned" : "low";
}

// ---- formatting ----------------------------------------------------------------
/** API timestamps are naive UTC (no zone suffix); treat them as UTC. */
export function parseUtc(s: string): Date {
  return new Date(/(Z|[+-]\d\d:?\d\d)$/i.test(s) ? s : s + "Z");
}

const rtf = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
export function relativeTime(s: string, now = Date.now()): string {
  const sec = Math.round((parseUtc(s).getTime() - now) / 1000);
  if (Math.abs(sec) < 45) return "just now";
  for (const [unit, size, limit] of [["minute", 60, 3600], ["hour", 3600, 86400], ["day", 86400, 2592000], ["month", 2592000, 31536000]] as const) {
    if (Math.abs(sec) < limit) return rtf.format(Math.round(sec / size), unit);
  }
  return rtf.format(Math.round(sec / 31536000), "year");
}

export const plural = (n: number, one: string, many = one + "s") => `${n.toLocaleString("en")} ${n === 1 ? one : many}`;
export const pct = (x: number) => (x < 0.01 ? "<1%" : `${Math.round(x * 100)}%`);

/** "Installed A < fixed B per DSA-1" sentence parts. */
export function whyMatched(f: Pick<Finding, "installed_version" | "fixed_version" | "advisory_ids" | "vuln_id">): string {
  if (!f.fixed_version) return `Installed ${f.installed_version}. No fixed version has been published yet.`;
  const src = f.advisory_ids.length ? f.advisory_ids.slice(0, 3).join(", ") : f.vuln_id;
  return `Installed ${f.installed_version} < fixed ${f.fixed_version} per ${src}`;
}

export function installCommands(origin: string, token: string) {
  return {
    curl: `curl -fsSL ${origin}/install.sh | sudo sh -s -- --token ${token}`,
    python: `python3 nimstead_agent.py enroll --server ${origin} --token ${token} && python3 nimstead_agent.py report`,
    windows: `$env:NIMSTEAD_TOKEN = "${token}"; irm ${origin}/install.ps1 | iex`,
  };
}

// ---- findings filters <-> URL ----------------------------------------------------
export interface FindingsFilters {
  q: string; priority: Priority[]; fixable: boolean; kev: boolean; status: Status; asset: string; open: string;
}
export type RawSearch = Record<string, string | undefined>;

/** Defaults: open findings, fixable only (noise reduction). Unknown values fall back to defaults. */
export function parseFilters(raw: RawSearch): FindingsFilters {
  const status = (["open", "resolved", "accepted"] as const).find((s) => s === raw.status) ?? "open";
  const priority = (raw.priority ?? "").split(",").filter((p): p is Priority => (PRIORITIES as readonly string[]).includes(p));
  return { q: raw.q ?? "", priority, fixable: raw.fixable !== "0", kev: raw.kev === "1", status, asset: raw.asset ?? "", open: raw.f ?? "" };
}

/** Inverse of parseFilters: only non-default values reach the URL. */
export function filtersToSearch(f: FindingsFilters): RawSearch {
  return {
    q: f.q || undefined,
    priority: f.priority.length ? PRIORITIES.filter((p) => f.priority.includes(p)).join(",") : undefined,
    fixable: f.fixable ? undefined : "0",
    kev: f.kev ? "1" : undefined,
    status: f.status === "open" ? undefined : f.status,
    asset: f.asset || undefined,
    f: f.open || undefined,
  };
}

/** Query string sent to /api/findings. */
export function filtersToApi(f: FindingsFilters): string {
  const p = new URLSearchParams({ status: f.status, limit: "5000" });
  if (f.q) p.set("q", f.q);
  if (f.priority.length) p.set("priority", f.priority.join(","));
  if (f.asset) p.set("asset_id", f.asset);
  if (f.fixable) p.set("fixable", "true");
  if (f.kev) p.set("kev", "true");
  return p.toString();
}

// ---- AI (optional) -------------------------------------------------------------
export interface AiFilter { q?: string | null; priority?: string[] | null; status?: string | null; fixable?: boolean | null; kev?: boolean | null }
export const aiStatusQ = queryOptions({ queryKey: ["ai-status"], queryFn: () => api<{ enabled: boolean }>("/api/ai/status"), staleTime: 5 * 60_000, retry: false });

/** Looks like a question rather than a package/CVE search. */
export const looksLikeQuestion = (t: string) => t.trim().endsWith("?") || t.trim().split(/\s+/).length >= 4;

/** Turn an AI filter into the patch applied to the URL filters. Unknown values are ignored. */
export function aiFilterToPatch(a: AiFilter): Partial<FindingsFilters> {
  const priority = (a.priority ?? []).filter((p): p is Priority => (PRIORITIES as readonly string[]).includes(p));
  const status = (["open", "resolved", "accepted"] as const).find((s) => s === a.status);
  return { q: a.q ?? "", priority, kev: !!a.kev, fixable: !!a.fixable, ...(status ? { status } : {}) };
}

// ---- misc ----------------------------------------------------------------------
export function useTitle(title: string) {
  useEffect(() => { document.title = `${title} · Nimstead`; }, [title]);
}

export function setTheme(t: "light" | "dark") {
  document.documentElement.dataset.theme = t;
  try { localStorage.setItem("theme", t); } catch { /* storage blocked */ }
}
export const isDark = () =>
  (document.documentElement.dataset.theme ?? (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")) === "dark";

// ---- shared queries ----------------------------------------------------------------
export const meQ = queryOptions({ queryKey: ["me"], queryFn: () => api<{ email: string; org: string; admin: boolean }>("/api/me"), retry: false, staleTime: 5 * 60_000 });
/** Admin-only actions are disabled until /api/me says otherwise (loading counts as non-admin). */
export const useIsAdmin = () => useQuery(meQ).data?.admin === true;
export const ADMIN_ONLY = "Only organisation admins can do this";
/** Spread onto a button after its own `disabled`: no-op for admins, disables with an explanation for everyone else. */
export const adminGate = (admin: boolean) => (admin ? {} : { disabled: true, title: ADMIN_ONLY });
export const summaryQ = queryOptions({ queryKey: ["summary"], queryFn: () => api<Summary>("/api/summary") });
export const assetsQ = queryOptions({ queryKey: ["assets"], queryFn: () => api<Asset[]>("/api/assets") });

/** Packages a refused dry run said the fix also needs ("would also change: musl, libcrypto3"). */
export function dependenciesNeeded(error: string | null | undefined): string[] {
  const m = /would also change: ([^\n;]+)/.exec(error ?? "");
  return m?.[1] ? m[1].split(",").map((s) => s.trim()).filter(Boolean) : [];
}
