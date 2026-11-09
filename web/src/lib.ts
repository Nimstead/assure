import { useEffect } from "react";
import { queryOptions, useQuery, type QueryClient } from "@tanstack/react-query";

// ---- UI-selected API shapes; these declarations do not validate JSON or enumerate every server field ----
export const PRIORITIES = ["fix-now", "next", "planned", "low"] as const;
export type Priority = (typeof PRIORITIES)[number];
export type Status = "open" | "resolved" | "accepted";
export type Criticality = "low" | "medium" | "high" | "critical";

export interface HostFacts {
  edition_id?: string; esu?: boolean | null; os_unmatched?: string;
  wsus?: string | null; wufb_quality_deferral_days?: number | null; pending_reboot?: boolean; last_update_success?: string | null;
  [k: string]: unknown;
}

/** Format reported update facts f without probing the host; absent source evidence returns "".
 * Explicit wsus=null selects Windows Update. Deferral-only facts produce no text.
 * A 1601-prefixed success date means no prior install. Other dates use relativeTime.
 * Invalid nested values/dates can throw. Do not mutate f.
 */
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
  id: string; hostname: string; os_name: string; ecosystem: string; kind: "host" | "application" | "external";
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
  updating: { label: "Agent release differs", why: (a) => `The server offers a different signed release from agent ${a.agent_version}. The host checks version and channel eligibility at its next run.` },
  failed: { label: "Agent update failed", why: (a) => `${a.agent_update_error ?? "The last self-update failed."} The last reported agent version is ${a.agent_version}. A failed self-test can delay retry for 24 hours.` },
  paused: { label: "Agent update paused", why: () => "Agent updates are paused for your organisation (Settings)." },
  off: { label: "Agent outdated", why: () => "Automatic updates are switched off on this host. Use the installation instructions to update it, and check its local update setting afterward." },
  reinstall: { label: "Agent outdated", why: (a) => `${a.agent_version ? `Agent ${a.agent_version}` : "This agent"} cannot use automatic updates from this server. Check its signed release and local update settings, or use the installation instructions.` },
};
export interface Coverage { assessed: number; inventory_only: number; not_assessed: { name: string; publisher: string | null; hosts: number }[] }
export const coverageQ = { queryKey: ["coverage"], queryFn: () => api<Coverage>("/api/coverage") };
export interface SbomResult { components: number; mapped: number; unique_packages: number; skipped: Record<string, number>; open: number; resolved: number }
/** Format r's mapping/finding counts; skipped equals components minus mapped.
 * Do not sum r.skipped or validate count consistency/ranges. No I/O or mutation occurs.
 */
export const sbomSummary = (r: SbomResult) =>
  `${r.mapped} of ${r.components} components recognised (${r.unique_packages} unique packages), ${r.components - r.mapped} skipped. ${r.open} open finding${r.open === 1 ? "" : "s"}, ${r.resolved} resolved.`;
export interface Finding {
  id: string; asset_id: string; hostname: string; ecosystem: string; package: string;
  installed_version: string; fixed_version: string | null; setting_fix: boolean; plannable?: boolean;
  /** Drawer only: highest recorded fixed version across eligible open package findings, not a fresh repair proof. */
  package_fix?: { version: string; open: number } | null; vuln_id: string; advisory_ids: string[];
  rule_evidence?: "proven" | "real name" | "pattern" | null;
  summary: string | null; cvss: number | null; epss: number | null; kev: boolean; score: number;
  priority: Priority; reasons: string[]; status: Status; first_seen: string; last_seen: string;
  resolved_at: string | null;
  /** UTC deadline using historical SLA days and current priority; null for nonopen findings or omitted deadline calculation. */
  due: string | null;
}
export interface Action {
  /** fixed_version is null for a setting, which `summary` then describes. */
  ecosystem: string; package: string; fixed_version: string | null; hosts: string[]; asset_ids: string[]; vulns: string[];
  kev: boolean; max_score: number; summary: string | null;
  /** Server path classification. person_only excludes the action from normal automatic planning. */
  fix: string | null; plannable: boolean; person_only: boolean; forward_only: boolean;
  /** One active job in the server-selected rows, or null. This is not a complete active-job list. */
  job: { id: string; status: JobStatus } | null;
  /** Asset IDs represented by active jobs in selected rows. Other IDs still face normal planning guards. */
  busy_asset_ids: string[];
  /** Newest nonactive selected attempt only when classified as a failure, otherwise null. */
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
  planned: "Awaiting approval", approved: "Approved, waiting for host", dispatched: "Sent to host", verifying: "Verifying",
  succeeded: "Job succeeded", failed: "Failed", rolled_back: "Rolled back", rollback_failed: "Rollback failed",
  not_fixed: "Applied, still vulnerable", aborted: "Aborted", cancelled: "Cancelled",
};
/** Return all configured groups with new job arrays, preserving input order and shared job objects.
 * Unknown status values appear in no group. Do not mutate jobs or query the server.
 */
export const groupJobs = (jobs: Job[]) =>
  JOB_GROUPS.map((g) => ({ ...g, jobs: jobs.filter((j) => (g.statuses as readonly string[]).includes(j.status)) }));
/** A job no one has finished with yet (remediate.py ACTIVE): one per package per machine. */
export const ACTIVE_JOB_STATUSES: readonly JobStatus[] = ["planned", "approved", "dispatched", "verifying"];
/** Return whether j.status is approved/dispatched/verifying; planned is not polled. */
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
/** Return job- plus id for a card anchor, without encoding or validation. */
export const jobAnchor = (id: string) => `job-${id}`;

export const APPROVE_COPY = "Approval lets the host receive this plan when dispatch gates allow. The agent checks its prerequisites and uses the plan's recovery path where available. Review the next inventory and any remaining findings after execution.";

/** Replace underscores in string k, trim outer whitespace and capitalize its first character.
 * Empty text returns "". Interior repeated spaces remain. No I/O occurs.
 */
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
/** Dispatch window: days 0-6 = Monday-Sunday, local start HH:MM and elapsed-hour length. */
export interface MaintenanceWindow { days: number[]; start: string; hours: number; tz: string }
// updates.status(): last_update is what deploy/update.sh last did on the Docker host
export interface Platform {
  version: string; latest: string | null; latest_url: string | null; update_available: boolean; checked: string | null;
  channel: "preview" | "beta" | "stable"; running_channel: "preview" | "beta" | "stable" | null; latest_channel: string | null;
  last_update: { outcome: "updated" | "rolled_back" | "rollback_failed" | "refused"; from?: string; to?: string; error?: string | null; at?: string } | null;
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
/** Error subclass with public status and supplied message; name remains Error.
 * Constructor does not validate either value. api also uses status 0 for request-preparation failures.
 */
export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

/** Request and parse JSON through browser fetch, without runtime response validation.
 * @param path Expected same-origin API path; absolute/cross-origin URLs are not refused here.
 * @param init Optional method and body; strings are sent verbatim, other truthy bodies are JSON-encoded.
 * @returns Parsed JSON typed as T, or undefined for HTTP 204. The generic does not validate the response.
 * @throws ApiError for fetch or request-serialization failure (status 0), or non-success HTTP status.
 * Successful response JSON errors propagate separately. Fetch defaults govern credentials.
 * No explicit timeout, abort signal, retry, or origin validation is supplied.
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
    throw new ApiError(0, "Couldn't complete the request. Check the input and connection, then try again.");
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

/** Classify score using 75/50/25 thresholds, with kev overriding to fix-now.
 * Do not validate score ranges; NaN falls to low. No I/O or mutation occurs.
 */
export function priorityOf(score: number, kev: boolean): Priority {
  return kev || score >= 75 ? "fix-now" : score >= 50 ? "next" : score >= 25 ? "planned" : "low";
}

// ---- formatting ----------------------------------------------------------------
/** Parse string s as Date, appending Z unless it ends in Z or a numeric UTC offset.
 * Invalid timestamp text returns Invalid Date. This helper does not validate or throw for ordinary bad date text.
 */
export function parseUtc(s: string): Date {
  return new Date(/(Z|[+-]\d\d:?\d\d)$/i.test(s) ? s : s + "Z");
}

const rtf = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
/** Format timestamp s relative to now (Unix milliseconds), using English rounded elapsed units.
 * Months are 30 days and years 365 days, not calendar arithmetic. Under 45 rounded
 * seconds is "just now". Invalid dates/nonfinite now can raise RangeError.
 */
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

/** Return f.fixed_version when nonnull, otherwise an ecosystem action or "no fix recorded".
 * An empty fixed-version string is retained. No advisory lookup, comparison or mutation occurs.
 */
export function fixLabel(f: Pick<Finding, "fixed_version" | "ecosystem">): string {
  return f.fixed_version ?? ({ WinConfig: "change the setting", Lifecycle: "move to a supported version", External: "close or restrict it", WinDriver: "update or remove the driver" } as Record<string, string>)[f.ecosystem] ?? "no fix recorded";
}

/** Format finding f's recorded match explanation without re-evaluating versions or evidence.
 * Special ecosystems use fixed wording. Ordinary rows name at most three advisory IDs,
 * otherwise vuln_id. Missing fixed_version describes missing recorded fix data.
 * Invalid array/string inputs can throw. No I/O or mutation occurs.
 */
export function whyMatched(f: Pick<Finding, "installed_version" | "fixed_version" | "advisory_ids" | "vuln_id"> & { ecosystem?: string }): string {
  if (f.ecosystem === "WinConfig") return `Found ${f.installed_version} on this host.`;
  if (f.ecosystem === "Lifecycle") return `Installed ${f.installed_version}, which is past its end of support.`;
  if (f.ecosystem === "External") return "Seen from outside by an external scan.";
  if (f.ecosystem === "WinDriver") return `This exact file (SHA-256 ${f.installed_version}) is listed by LOLDrivers.`;
  if (!f.fixed_version) return `Installed ${f.installed_version}. No fixed version is recorded for this finding.`;
  const src = f.advisory_ids.length ? f.advisory_ids.slice(0, 3).join(", ") : f.vuln_id;
  return `Installed ${f.installed_version} < fixed ${f.fixed_version} per ${src}`;
}

/** Return curl/python/windows command strings for trusted origin and generated token.
 * Interpolate inputs without shell escaping or URL normalization. Do not execute commands.
 * Inputs must be trusted. The direct-Python command assumes the agent file is present.
 * The strings use environment variables; the helper does not control caller process/log handling.
 */
export function installCommands(origin: string, token: string) {
  return {
    // Use environment assignments in the displayed commands; execution/logging belongs to the caller.
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

/** Parse raw string search values with open/fixable/score/ungrouped defaults.
 * Only fixable=0 disables that flag; kev/overdue require exact 1. Priority names
 * are case-sensitive, untrimmed, and can repeat. Copy q/asset/f text unchanged.
 * Unknown enum values fall back. Ignore other keys. Invalid runtime value types can throw.
 */
export function parseFilters(raw: RawSearch): FindingsFilters {
  const status = (["open", "resolved", "accepted"] as const).find((s) => s === raw.status) ?? "open";
  const priority = (raw.priority ?? "").split(",").filter((p): p is Priority => (PRIORITIES as readonly string[]).includes(p));
  const sort = (["score", "package", "host", "vuln", "newest"] as const).find((s) => s === raw.sort) ?? "score";
  const group = (["vuln", "package"] as const).find((g) => g === raw.group) ?? "";
  return { q: raw.q ?? "", priority, fixable: raw.fixable !== "0", kev: raw.kev === "1", status, asset: raw.asset ?? "", open: raw.f ?? "", overdue: raw.overdue === "1", sort, group };
}

/** Return a RawSearch object with undefined default fields for typed filters f.
 * Canonicalize priorities to unique PRIORITIES order, dropping unknown entries.
 * This is normalization, not an exact inverse for every raw URL. No encoding,
 * input mutation or I/O occurs. Malformed priority values can throw.
 */
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

/** Rows per page of the findings list; more load as it scrolls. */
export const FINDINGS_CAP = 500;
/** Return URL-encoded server filters from f, with list controls when list=true.
 * Always include status. The default adds limit=500/view=list and nondefault sort.
 * list=false omits those controls. Map asset to asset_id; omit false booleans and
 * UI open/group state. Preserve priority order. No validation, mutation or I/O occurs.
 */
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

/** Return whether trimmed t ends in ? or has at least four whitespace-separated tokens.
 * This is a text heuristic, not natural-language validation. No I/O occurs.
 */
export const looksLikeQuestion = (t: string) => t.trim().endsWith("?") || t.trim().split(/\s+/).length >= 4;

/** Return a URL-filter patch from a, without validating the full runtime shape.
 * Always set q/priority/kev/fixable. Missing text/priority becomes empty; flags use
 * truthiness. Include status only when recognized, so an invalid status is omitted.
 * Keep duplicate recognized priorities. Invalid runtime arrays can throw. No I/O occurs.
 */
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

/** Clear the selected live region, then set text after 30 ms.
 * assertive selects live-alert instead of live. Missing document/region is a no-op.
 * Timers are independent. An earlier message can appear during a later call's delay.
 */
export function announce(text: string, assertive = false) {
  const el = typeof document === "undefined" ? null : document.getElementById(assertive ? "live-alert" : "live");
  if (!el) return;
  el.textContent = "";
  setTimeout(() => { el.textContent = text; }, 30);
}

/** Set the document title from title plus product name in a React effect.
 * Require a browser DOM. Re-run when title changes, without restoring an old title on cleanup.
 */
export function useTitle(title: string) {
  useEffect(() => { document.title = `${title} · Nimstead Assure`; }, [title]);
}

/** On mount/ready changes, scroll to and request focus on the decoded hash target.
 * Require browser location/document. Missing targets are ignored without retry.
 * Hash changes alone do not rerun this effect. Invalid percent escapes throw URIError.
 * The caller must make targets focusable. No tabindex or history changes are made.
 */
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
/** Read light/dark from the document dataset, otherwise return system.
 * Require a browser DOM. Do not read storage or the system preference here.
 */
export const themeChoice = (): ThemeChoice => {
  const t = document.documentElement.dataset.theme;
  return t === "light" || t === "dark" ? t : "system";
};
/** Apply typed theme t to the document dataset and persist it under theme.
 * system removes both overrides. Suppress storage errors after the DOM change.
 * Require a browser DOM. Do not validate unexpected runtime strings or emit an event.
 */
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

/** Parse case-sensitive dependency text in error, treating null/undefined as empty.
 * Read the first would-also-change clause until newline/semicolon. Split/trim commas,
 * retain duplicate nonempty names and perform no package validation. No I/O occurs.
 */
export function dependenciesNeeded(error: string | null | undefined): string[] {
  const m = /would also change: ([^\n;]+)/.exec(error ?? "");
  return m?.[1] ? m[1].split(",").map((s) => s.trim()).filter(Boolean) : [];
}

// ---- saved views ------------------------------------------------------------------
// shortcut: saved in this browser only (localStorage); store them per user on the server if teams need to share them
export interface SavedView { name: string; search: RawSearch }
const VIEWS_KEY = "nimstead:findings-views";
/** Return named JSON entries from localStorage's nimstead:findings-views, otherwise [].
 * Validate only each name's string type; search shapes can be absent or malformed.
 * Storage/parse failures are suppressed. Views belong to this browser, not an account.
 */
export function savedViews(): SavedView[] {
  try { const v = JSON.parse(localStorage.getItem(VIEWS_KEY) ?? "[]"); return Array.isArray(v) ? v.filter((x) => x && typeof x.name === "string") : []; } catch { return []; }
}
/** JSON-store views and then dispatch nimstead-views on window.
 * Suppress serialization/storage/event errors and return undefined. A storage write
 * can succeed before an event failure. No schema validation or server request occurs.
 */
export function saveViews(views: SavedView[]) {
  try { localStorage.setItem(VIEWS_KEY, JSON.stringify(views)); window.dispatchEvent(new Event("nimstead-views")); } catch { /* private mode: views just don't persist */ }
}
