import { useEffect } from "react";
import { queryOptions, useQuery, type QueryClient } from "@tanstack/react-query";

// ---- types (mirror api/src/nimstead/app.py) ---------------------------------
export const PRIORITIES = ["fix-now", "next", "planned", "low"] as const;
export type Priority = (typeof PRIORITIES)[number];
export type Status = "open" | "resolved" | "accepted";
export type Criticality = "low" | "medium" | "high" | "critical";

export interface HostFacts {
  edition_id?: string; esu?: boolean | null; os_unmatched?: string;
  wsus?: string | null; wufb_quality_deferral_days?: number | null; pending_reboot?: boolean; last_update_success?: string | null;
  [k: string]: unknown;
}

/** Where a Windows host gets its updates from, in one line, or "" when the agent hasn't said (plan T12). */
export function updateSource(f?: HostFacts): string {
  if (!f || (f.wsus === undefined && !f.last_update_success)) return "";
  const from = f.wsus ? `Updates from WSUS (${f.wsus})` : "Updates from Windows Update";
  const defer = f.wufb_quality_deferral_days ? `, deferred ${f.wufb_quality_deferral_days} days by policy` : "";
  // Windows reports 1601-01-01 (its zero date) when nothing has ever been installed: seen on real VMs as "426 years ago"
  const never = f.last_update_success?.startsWith("1601-");
  const last = f.last_update_success ? (never ? " · nothing installed through it yet" : ` · last installed ${relativeTime(f.last_update_success)}`) : "";
  return from + defer + last;
}

export interface Asset {
  id: string; hostname: string; os_name: string; ecosystem: string; kind: "host" | "application" | "external" | "device";
  criticality: Criticality; internet_facing: boolean; directory_source?: boolean; sandbox: boolean; ring: 0 | 1; health_units: string[];
  first_seen: string; last_seen: string; open_by_priority: Partial<Record<Priority, number>>;
  apps?: { assessed: number; inventory_only: number }; // Windows hosts: installed apps checked against those only listed
  agent_version?: string; agent_outdated?: boolean; agent_update?: AgentUpdate; agent_update_error?: string | null; not_reporting?: boolean; // hosts only
  facts?: HostFacts; // hosts only: what the agent reports about the host itself
  verified?: boolean; verified_at?: string | null; txt_name?: string; txt_value?: string; proof_path?: string; // external targets only
}
// What happens to a host's agent next (app.py agent_update_status)
export type AgentUpdate = "current" | "updating" | "failed" | "paused" | "off" | "reinstall";
export const AGENT_UPDATE: Record<Exclude<AgentUpdate, "current">, { label: string; why: (a: Asset) => string }> = {
  updating: { label: "Agent updating", why: (a) => `Agent ${a.agent_version} will replace itself with this server's signed release at its next run.` },
  failed: { label: "Agent update failed", why: (a) => `${a.agent_update_error ?? "The last self-update failed."} The agent kept running ${a.agent_version} and will try again at its next run.` },
  paused: { label: "Agent update paused", why: () => "Agent updates are paused for your organisation (Settings)." },
  off: { label: "Agent outdated", why: () => "Automatic updates are switched off on this host. Rerun the install command to update it; the enrolment is kept." },
  reinstall: { label: "Agent outdated", why: (a) => `${a.agent_version ? `Agent ${a.agent_version}` : "This agent"} can't update itself. Rerun the install command on this host once; the enrolment is kept, and later versions update automatically.` },
};
export interface Coverage { assessed: number; inventory_only: number; not_assessed: { name: string; publisher: string | null; hosts: number }[] }
export const coverageQ = { queryKey: ["coverage"], queryFn: () => api<Coverage>("/api/coverage") };
export interface SbomResult { components: number; mapped: number; unique_packages: number; skipped: Record<string, number>; open: number; resolved: number }
/** Return a display summary of mapped, unique, skipped, open, and resolved counts in r. */
export const sbomSummary = (r: SbomResult) =>
  `${r.mapped} of ${r.components} components recognised (${r.unique_packages} unique packages), ${r.components - r.mapped} skipped. ${r.open} open finding${r.open === 1 ? "" : "s"}, ${r.resolved} resolved.`;
export interface Finding {
  id: string; asset_id: string; hostname: string; ecosystem: string; package: string;
  installed_version: string; fixed_version: string | null; setting_fix: boolean; plannable?: boolean;
  /** Drawer only: the upgrade that clears every open finding for this package on this host. */
  package_fix?: { version: string; open: number } | null; vuln_id: string; advisory_ids: string[];
  rule_evidence?: "proven" | "real name" | "pattern" | null;
  summary: string | null; cvss: number | null; epss: number | null; kev: boolean; score: number;
  priority: Priority; reasons: string[]; status: Status; first_seen: string; last_seen: string;
  resolved_at: string | null;
  /** Deadline from the SLA in force when it was first detected (ISO date); null once resolved or accepted. */
  due: string | null;
}
export interface Action {
  /** fixed_version is null for a setting, which `summary` then describes. */
  ecosystem: string; package: string; fixed_version: string | null; hosts: string[]; asset_ids: string[]; vulns: string[];
  kev: boolean; max_score: number; summary: string | null;
  /** How it gets fixed: the same rules plan and approve apply. person_only is never approved by the trust ladder. */
  fix: string | null; plannable: boolean; person_only: boolean; forward_only: boolean;
  /** A fix already in flight for this package, if any: link to it rather than planning another. */
  job: { id: string; status: JobStatus } | null;
  /** Machines with that fix in flight; the rest can still be planned. */
  busy_asset_ids: string[];
  /** The newest failed attempt for this package, so Home doesn't offer the same plan blind. */
  last_attempt: { id: string; status: JobStatus; error: string | null } | null;
}
export interface Summary {
  assets: number; open_by_priority: Partial<Record<Priority, number>>; top_actions: Action[]; attention: Job[];
  hosts_not_reporting: number; agents_need_attention: number;
}

// ---- remediation -----------------------------------------------------------------
export type JobStatus = "planned" | "approved" | "dispatched" | "verifying" | "succeeded" | "failed" | "rolled_back" | "rollback_failed" | "not_fixed" | "aborted" | "cancelled";
export interface JobStep { step: string; ok: boolean; output?: string }
export interface Job {
  id: string; asset_id: string; hostname: string; status: JobStatus; manager: string; action_key: string;
  packages: unknown; finding_ids: string[]; summary: string; created_by: string; approved_by: string | null;
  created: string; updated: string; steps: JobStep[] | null; error: string | null;
  forward_only?: boolean; waits_for_window?: string | null; // plan T22, T40
}
const JOB_GROUPS = [
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
/** Return the configured job groups with matching jobs, preserving each group's input order. */
export const groupJobs = (jobs: Job[]) =>
  JOB_GROUPS.map((g) => ({ ...g, jobs: jobs.filter((j) => (g.statuses as readonly string[]).includes(j.status)) }));
/** A job no one has finished with yet (remediate.py ACTIVE): one per package per machine. */
export const ACTIVE_JOB_STATUSES: readonly JobStatus[] = ["planned", "approved", "dispatched", "verifying"];
/** Running somewhere, so worth polling. */
export const isActiveJob = (j: Pick<Job, "status">) => j.status !== "planned" && ACTIVE_JOB_STATUSES.includes(j.status);
/** One cumulative update across the fleet (remediate.kb_fleet). The hosts and the plan come from kbHostsQ. */
export interface KbRow { kb: string; product: string; title: string; released: string | null; build: string; hosts: number; fixed: number; plan_note: string | null }
export interface KbHost { asset_id: string; hostname: string; build: string; ring: number; why: string; notes: string[]; job: { id: string; status: JobStatus } | null }
export const kbFleetQ = queryOptions({ queryKey: ["kb-fleet"], queryFn: () => api<KbRow[]>("/api/windows-updates") });
/** Build query options for host details keyed by the KB and product in r; API failures reject the query. */
export const kbHostsQ = (r: Pick<KbRow, "kb" | "product">) => queryOptions({
  queryKey: ["kb-fleet", r.kb, r.product],
  queryFn: () => api<KbRow & { missing: KbHost[]; plan_asset_ids: string[] }>(`/api/windows-updates/${r.kb}?product=${encodeURIComponent(r.product)}`),
});
export const jobsQ = queryOptions({ queryKey: ["jobs"], queryFn: () => api<Job[]>("/api/remediation/jobs") });
/** Address of a job card on the Remediation page. */
export const jobAnchor = (id: string) => `job-${id}`;

export const APPROVE_COPY = "Saves a rollback copy of each package, upgrades, checks health, rolls back automatically on failure. Success is confirmed by the next inventory.";

/** "remediation_not_fixed" -> "Remediation not fixed". */
export const humaniseKind = (k: string) => { const t = k.replace(/_/g, " ").trim(); return t.charAt(0).toUpperCase() + t.slice(1); };

export interface LedgerEntry { seq: number; ts: string; kind: string; subject: string; hash: string; prev_hash: string; data: Record<string, unknown> }
export interface Control { framework: string; control: string; requirement: string; status: ControlStatus; evidence: string; exceptions?: number }
/** "no_activity": a timeliness control with nothing fixed or changed in the period and nothing overdue (DECISIONS 45). */
export type ControlStatus = "met" | "not_met" | "no_activity";
export interface EvidenceReport {
  controls: Control[]; period: { from: string; to: string };
  metrics: { resolved: number; resolved_within_sla: number; overdue_open: number; mttr_days: number | null };
  ledger: { head_hash: string; entries: number };
}
export interface EnrollToken { id: string; created: string; expires: string; revoked: boolean; sandbox: boolean }
export interface Settings {
  remediation_mode: "suggest" | "approve" | "auto"; canary_soak_hours: number; production_remediation_allowed: boolean;
  agent_updates_paused: boolean; signed_agent_release: boolean; platform: Platform; sla_days: Record<Priority, number>;
  maintenance_window: MaintenanceWindow | null; reboot_deadline_hours: number;
}
/** When fixes may run (plan T40): days 0-6 = Monday-Sunday, start "HH:MM" local to tz, length in hours. */
export interface MaintenanceWindow { days: number[]; start: string; hours: number; tz: string }
// updates.status(): last_update is what deploy/update.sh last did on the Docker host
export interface Platform {
  version: string; latest: string | null; latest_url: string | null; update_available: boolean; checked: string | null;
  channel: "preview" | "beta" | "stable"; running_channel: "preview" | "beta" | "stable" | null; latest_channel: string | null;
  last_update: { outcome: "updated" | "rolled_back" | "rollback_failed" | "refused"; from?: string; to?: string; error?: string; at?: string } | null;
}
export interface SsoSettings {
  issuer: string; client_id: string; client_secret_set: boolean; domains: string[]; required: boolean; redirect_uri: string;
  domain_checks: { domain: string; verified: boolean; txt_name: string; txt_value: string }[];
}
export interface NotifySettings {
  webhook_set: boolean; webhook_host: string | null; webhook_format: "slack" | "json"; emails: string[]; emails_confirmed: string[]; email_available: boolean;
  last_delivery_failed: boolean; recent: { ts: string; kind: string; channel: string; urgent: boolean; ok: boolean; error: string | null }[];
}
export const settingsQ = queryOptions({ queryKey: ["settings"], queryFn: () => api<Settings>("/api/settings") });

// ---- api ---------------------------------------------------------------------
/** API failure with HTTP status and display message. Status 0 represents a network failure. */
export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

/** Send a same-origin JSON request using the browser's session cookie.
 * @param path API URL path.
 * @param init Optional method and body; strings are sent verbatim, other truthy bodies are JSON-encoded.
 * @returns Parsed JSON typed as T, or undefined for HTTP 204. The generic does not validate the response.
 * @throws ApiError for network failure (status 0) or a non-success HTTP response; JSON parse errors propagate.
 */
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
// "planned" stays the stored value; it reads as "Routine" so it can't be mistaken for a planned fix (DECISIONS 50).
export const PRIORITY_LABEL: Record<Priority, string> = { "fix-now": "Fix now", next: "Next", planned: "Routine", low: "Low" };
export const PRIORITY_CLASS: Record<Priority, string> = {
  "fix-now": "bg-now-bg text-now-fg", next: "bg-next-bg text-next-fg",
  planned: "bg-planned-bg text-planned-fg", low: "bg-low-bg text-low-fg",  // one fill ramp, Fix now darkest to Low none
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
/** Format UTC timestamp s relative to now (Unix milliseconds), using English calendar units. Invalid dates can raise RangeError. */
export function relativeTime(s: string, now = Date.now()): string {
  const sec = Math.round((parseUtc(s).getTime() - now) / 1000);
  if (Math.abs(sec) < 45) return "just now";
  for (const [unit, size, limit] of [["minute", 60, 3600], ["hour", 3600, 86400], ["day", 86400, 2592000], ["month", 2592000, 31536000]] as const) {
    if (Math.abs(sec) < limit) return rtf.format(Math.round(sec / size), unit);
  }
  return rtf.format(Math.round(sec / 31536000), "year");
}

/** Format count n and choose one only for 1; many defaults to the singular text plus s. */
export const plural = (n: number, one: string, many = one + "s") => `${n.toLocaleString("en")} ${n === 1 ? one : many}`;
/** Format ratio x as a rounded percentage, using <1% below 0.01. The input is not range-checked. */
export const pct = (x: number) => (x < 0.01 ? "<1%" : `${Math.round(x * 100)}%`);

/** What to move to. Settings, end of support and exposures never have a fixed version, and "no fix yet" would be untrue. */
export function fixLabel(f: Pick<Finding, "fixed_version" | "ecosystem">): string {
  return f.fixed_version ?? ({ WinConfig: "change the setting", Lifecycle: "move to a supported version", External: "close or restrict it", Network: "close or restrict it", WinDriver: "update or remove the driver" } as Record<string, string>)[f.ecosystem] ?? "no fix yet";
}

/** "Installed A < fixed B per DSA-1" sentence parts. */
export function whyMatched(f: Pick<Finding, "installed_version" | "fixed_version" | "advisory_ids" | "vuln_id"> & { ecosystem?: string }): string {
  if (f.ecosystem === "WinConfig") return `Found ${f.installed_version} on this host.`;
  if (f.ecosystem === "Lifecycle") return `Installed ${f.installed_version}, which is past its end of support.`;
  if (f.ecosystem === "External") return "Seen from outside by an external scan.";
  if (f.ecosystem === "Network") return "Seen on your network by one of your machines' network checks.";
  if (f.ecosystem === "WinDriver") return `This exact file (SHA-256 ${f.installed_version}) is listed by LOLDrivers.`;
  if (!f.fixed_version) return `Installed ${f.installed_version}. No fixed version has been published yet.`;
  const src = f.advisory_ids.length ? f.advisory_ids.slice(0, 3).join(", ") : f.vuln_id;
  return `Installed ${f.installed_version} < fixed ${f.fixed_version} per ${src}`;
}

/** Return Linux, direct-Python, and PowerShell enrolment commands for origin and token.
 * Inputs must be the trusted server origin and generated token; this helper does not escape arbitrary shell input. */
export function installCommands(origin: string, token: string) {
  return {
    // the token goes in the environment (export is a shell builtin), never argv: ps and sudo logs show every argument
    curl: `export NIMSTEAD_TOKEN=${token}; curl -fsSL ${origin.startsWith("https://") ? "--proto '=https' " : ""}${origin}/install.sh | sudo --preserve-env=NIMSTEAD_TOKEN sh; unset NIMSTEAD_TOKEN`,
    python: `export NIMSTEAD_TOKEN=${token}; python3 nimstead_agent.py enroll --server ${origin} && python3 nimstead_agent.py report; unset NIMSTEAD_TOKEN`,
    windows: `$env:NIMSTEAD_TOKEN = "${token}"; irm ${origin}/install.ps1 | iex`,
  };
}

// ---- findings filters <-> URL ----------------------------------------------------
export interface FindingsFilters {
  q: string; priority: Priority[]; fixable: boolean; kev: boolean; status: Status; asset: string; open: string;
  /** Open and past its deadline (as evidence packs count it). */
  overdue: boolean;
  sort: FindingSort; group: FindingGroup;
}
export type FindingSort = "score" | "package" | "host" | "vuln" | "newest";
export type FindingGroup = "" | "vuln" | "package";
/** One vulnerability or package across the fleet (GET /api/findings/groups). */
export interface FindingGroupRow { key: string; findings: number; hosts: number; score: number; kev: boolean; priority: Priority; fixed_version: string | null; packages: number; package: string; vuln_id: string; vulns: number; ecosystem: string | null }
export type RawSearch = Record<string, string | undefined>;

/** Defaults: open findings, fixable only (noise reduction). Unknown values fall back to defaults. */
export function parseFilters(raw: RawSearch): FindingsFilters {
  const status = (["open", "resolved", "accepted"] as const).find((s) => s === raw.status) ?? "open";
  const priority = (raw.priority ?? "").split(",").filter((p): p is Priority => (PRIORITIES as readonly string[]).includes(p));
  const sort = (["score", "package", "host", "vuln", "newest"] as const).find((s) => s === raw.sort) ?? "score";
  const group = (["vuln", "package"] as const).find((g) => g === raw.group) ?? "";
  return { q: raw.q ?? "", priority, fixable: raw.fixable !== "0", kev: raw.kev === "1", status, asset: raw.asset ?? "", open: raw.f ?? "", overdue: raw.overdue === "1", sort, group };
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
    overdue: f.overdue ? "1" : undefined,
    sort: f.sort === "score" ? undefined : f.sort,
    group: f.group || undefined,
  };
}

/** Query string sent to /api/findings. */
/** Rows per page of the findings list; more load as it scrolls. */
export const FINDINGS_CAP = 500;
/** The filters only (no paging, sort or view): what /api/findings/count and /groups take too. */
export function filtersToApi(f: FindingsFilters, list = true): string {
  const p = new URLSearchParams({ status: f.status });
  if (list) { p.set("limit", String(FINDINGS_CAP)); p.set("view", "list"); if (f.sort !== "score") p.set("sort", f.sort); }
  if (f.q) p.set("q", f.q);
  if (f.priority.length) p.set("priority", f.priority.join(","));
  if (f.asset) p.set("asset_id", f.asset);
  if (f.fixable) p.set("fixable", "true");
  if (f.kev) p.set("kev", "true");
  if (f.overdue) p.set("overdue", "true");
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
/** Everything derived from these changes together; one place decides what a change makes stale. */
const STALE = {
  jobs: ["jobs", "summary", "ledger", "kb-fleet"],
  findings: ["findings", "finding", "summary", "ledger"],
  assets: ["assets", "findings", "finding", "summary", "ledger", "jobs", "kb-fleet"],
  people: ["users", "api-tokens", "enroll-tokens", "ledger"],
} as const;
/** Invalidate query groups affected by what and return a Promise for all invalidations on qc. */
export const refresh = (qc: QueryClient, what: keyof typeof STALE) =>
  Promise.all(STALE[what].map((k) => qc.invalidateQueries({ queryKey: [k] })));

/** Says something through the shell's live regions (DECISIONS 49). Cleared first so the same words are read again. */
export function announce(text: string, assertive = false) {
  const el = typeof document === "undefined" ? null : document.getElementById(assertive ? "live-alert" : "live");
  if (!el) return;
  el.textContent = "";
  setTimeout(() => { el.textContent = text; }, 30);
}

/** Set the browser document title to the page title plus the product name whenever title changes. */
export function useTitle(title: string) {
  useEffect(() => { document.title = `${title} · Nimstead Assure`; }, [title]);
}

/** Lazy pages render their anchors only after their data loads, so the browser's own #hash jump finds nothing: do it then. */
export function useHashScroll(ready: boolean) {
  useEffect(() => {
    if (!ready || !location.hash) return;
    const el = document.getElementById(decodeURIComponent(location.hash.slice(1)));
    if (!el) return;
    el.scrollIntoView({ block: "start" });
    el.focus({ preventScroll: true });  // targets carry tabIndex=-1, so keyboard and screen-reader users land there too
  }, [ready]);
}

export type ThemeChoice = "system" | "light" | "dark";
/** "system" follows prefers-color-scheme; index.html's inline script applies a stored choice before first paint. */
export const themeChoice = (): ThemeChoice => {
  const t = document.documentElement.dataset.theme;
  return t === "light" || t === "dark" ? t : "system";
};
/** Apply theme t to the document and persist it when storage is available; system removes the override. */
export function setTheme(t: ThemeChoice) {
  if (t === "system") delete document.documentElement.dataset.theme; else document.documentElement.dataset.theme = t;
  try { if (t === "system") localStorage.removeItem("theme"); else localStorage.setItem("theme", t); } catch { /* storage blocked */ }
}
export const NEXT_THEME: Record<ThemeChoice, ThemeChoice> = { system: "light", light: "dark", dark: "system" };
export const THEME_LABEL: Record<ThemeChoice, string> = { system: "System", light: "Light", dark: "Dark" };

// ---- shared queries ----------------------------------------------------------------
export interface Me { email: string; org: string; admin: boolean; origin: "password" | "sso"; mfa: boolean; recovery_codes_left: number }
export const meQ = queryOptions({ queryKey: ["me"], queryFn: () => api<Me>("/api/me"), retry: false, staleTime: 5 * 60_000 });
export interface OrgUser { id: string; email: string; admin: boolean; origin: "password" | "sso"; mfa: boolean; created: string }
export interface ApiTokenRow { id: string; name: string; created_by: string; created: string; expires: string | null; last_used: string | null }
export interface MfaSetup { setup: string; secret: string; uri: string }
/** Admin-only actions are disabled until /api/me says otherwise (loading counts as non-admin). */
export const useIsAdmin = () => useQuery(meQ).data?.admin === true;
export const ADMIN_ONLY = "Only organisation admins can do this";
export const ADMIN_ONLY_ID = "admin-only-note";
/** Spread onto a button after its own props: no-op for admins. For everyone else the button stays focusable (so the reason
 *  can be reached by keyboard and screen reader) but does nothing; the shell renders the visible note it points to. */
export const adminGate = (admin: boolean) => (admin ? {} : {
  "aria-disabled": true, "aria-describedby": ADMIN_ONLY_ID, title: ADMIN_ONLY,
  onClick: (e: { preventDefault: () => void; stopPropagation: () => void }) => { e.preventDefault(); e.stopPropagation(); },
});
export const summaryQ = queryOptions({ queryKey: ["summary"], queryFn: () => api<Summary>("/api/summary") });
export const assetsQ = queryOptions({ queryKey: ["assets"], queryFn: () => api<Asset[]>("/api/assets") });

/** Packages a refused dry run said the fix also needs ("would also change: musl, libcrypto3"). */
export function dependenciesNeeded(error: string | null | undefined): string[] {
  const m = /would also change: ([^\n;]+)/.exec(error ?? "");
  return m?.[1] ? m[1].split(",").map((s) => s.trim()).filter(Boolean) : [];
}

// ---- saved views ------------------------------------------------------------------
// shortcut: saved in this browser only (localStorage); store them per user on the server if teams need to share them
export interface SavedView { name: string; search: RawSearch }
const VIEWS_KEY = "nimstead:findings-views";
/** Read named findings views from localStorage; return [] when storage or JSON is unavailable. Only names are validated. */
export function savedViews(): SavedView[] {
  try { const v = JSON.parse(localStorage.getItem(VIEWS_KEY) ?? "[]"); return Array.isArray(v) ? v.filter((x) => x && typeof x.name === "string") : []; } catch { return []; }
}
/** Persist views and dispatch nimstead-views so listeners refresh; storage failures are ignored. */
export function saveViews(views: SavedView[]) {
  try { localStorage.setItem(VIEWS_KEY, JSON.stringify(views)); window.dispatchEvent(new Event("nimstead-views")); } catch { /* private mode: views just don't persist */ }
}
