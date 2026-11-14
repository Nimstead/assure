import { Fragment, memo, startTransition, useCallback, useDeferredValue, useEffect, useId, useMemo, useRef, useState, type ReactNode } from "react";
import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Dialog, Switch } from "radix-ui";
import { AppWindow, ArrowRight, Plus, Search, SlidersHorizontal, Trash2, Upload, X } from "lucide-react";
import { adminGate, AGENT_UPDATE, api, refresh, assetsQ, coverageQ, filtersToApi, filtersToSearch, parseFilters, parseUtc, plural, PRIORITIES, PRIORITY_LABEL, relativeTime, sbomSummary, updateSource, useIsAdmin, useTitle, type AgentUpdate, type Asset, type Criticality, type Finding, type Priority, type SbomResult } from "./lib";
import { Alert, btnPrimary, btnQuiet, chip, ConfirmDialog, CopyBlock, dialogBox, Done, EmptyState, ErrorState, Field, input, Loading, PriorityPill, switchRoot, switchThumb, Tag, useReturnFocus, HowJudged } from "./ui";
import clsx from "clsx";
import { ExternalTargets } from "./targets";

type AssetPatch = Partial<Pick<Asset, "criticality" | "internet_facing" | "directory_source" | "ring" | "health_units">>;
const LEVELS: Criticality[] = ["low", "medium", "high", "critical"];
const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

/** Render the asset inventory with URL filters, bulk edits, and host details. */
export function AssetsPage() {
  useTitle("Assets");
  const qc = useQueryClient();
  const q = useQuery(assetsQ);

  const patch = useMutation({
    mutationFn: ({ id, ...body }: { id: string } & AssetPatch) =>
      api(`/api/assets/${id}`, { method: "PATCH", body }),
    onMutate: async ({ id, ...body }) => {
      await qc.cancelQueries({ queryKey: assetsQ.queryKey });
      const prev = qc.getQueryData<Asset[]>(assetsQ.queryKey)?.find((x) => x.id === id);
      qc.setQueryData<Asset[]>(assetsQ.queryKey, (a) => a?.map((x) => (x.id === id ? { ...x, ...body } : x)));
      return { prev };
    },
    // Roll back only the asset that failed, so a concurrent edit to another row isn't undone with it.
    onError: (e, { id }, ctx) => {
      if (ctx?.prev) qc.setQueryData<Asset[]>(assetsQ.queryKey, (a) => a?.map((x) => (x.id === id ? ctx.prev! : x)));
      setFailed({ id, message: e.message });
    },
    onSuccess: (_d, { id }, ctx) => { setSaved(id); setLast(ctx?.prev ? { id, prev: ctx.prev } : null); },
    // Context changes re-score findings, so everything derived from them is stale.
    onSettled: () => refresh(qc, "assets"),
  });

  // machines, devices with no agent, internet targets: one view at a time (?view=), a device link opens its view
  const sp = useSearch({ strict: false }) as { view?: string; device?: string };
  const view: AssetView = sp.device ? "devices" : sp.view === "devices" || sp.view === "internet" ? sp.view : "machines";
  const devices = useQuery(devicesQ);
  const flagged = (devices.data ?? []).filter((r) => r.checked?.open.length).length;
  const [target, setTarget] = useState<Asset | null>(null);
  const [saved, setSaved] = useState("");
  const [last, setLast] = useState<{ id: string; prev: Asset } | null>(null);  // the last single change, for Undo
  const [failed, setFailed] = useState<{ id: string; message: string } | null>(null);  // shown on that row, not the page top
  const del = useMutation({
    mutationFn: (id: string) => api(`/api/assets/${id}`, { method: "DELETE" }),
    onSuccess: () => { setTarget(null); void refresh(qc, "assets"); },
  });

  return (
    <div className="flex flex-col gap-6">
      <header className="flex flex-wrap items-center justify-between gap-x-4 gap-y-3">
        <h1 className="w-full text-3xl font-semibold sm:w-auto">Assets</h1>
        <div className="flex flex-wrap items-center gap-2">
          <AddApplication />
          <Link to="/add" className={clsx(btnPrimary, "no-underline")}><Plus className="size-4" aria-hidden />Add machine</Link>
        </div>
      </header>

      <AssetViews view={view} devices={devices.data?.length ?? 0} flagged={flagged} external={(q.data ?? []).filter((a) => a.kind === "external").length} />

      {view === "machines" && <>
      <Unmanaged />
      <AttackPaths />
      <Baselines />
      <NotAssessed />

      {q.isPending ? <Loading className="h-20" rows={3} label="Loading assets…" />
        : q.error ? <ErrorState error={q.error} retry={() => q.refetch()} />
        : q.data.every((a) => a.kind === "external" || a.kind === "device") ? (
          <EmptyState title="No machines yet" action={<Link to="/add" className={clsx(btnPrimary, "no-underline")}>Add your first machine</Link>}>
            Machines show up here once they report in.
          </EmptyState>
        ) : (
          <MachineList assets={q.data.filter((a) => a.kind !== "external" && a.kind !== "device")} saved={patch.isPending ? "" : saved} failed={failed}
            undo={last ? () => { const { id, prev } = last; setLast(null); patch.mutate({ id, criticality: prev.criticality, internet_facing: prev.internet_facing, ring: prev.ring, health_units: prev.health_units }); } : undefined}
            onPatch={(id, p) => { setSaved(""); setFailed(null); patch.mutate({ id, ...p }); }} onDelete={(a) => { del.reset(); setTarget(a); }} />
        )}
      </>}
      {view === "internet" && q.data && <ExternalTargets targets={q.data.filter((a) => a.kind === "external")} onDelete={(a) => { del.reset(); setTarget(a); }} />}
      {view === "devices" && <UnmanagedDevices />}
      <ConfirmDialog open={!!target} onOpenChange={(o) => !o && setTarget(null)} title={`Delete ${target?.hostname}?`}
        description="Its findings and installed-software list are removed. The evidence ledger keeps the history of what was detected and fixed, so audit records stay intact. This can't be undone."
        confirmLabel="Delete asset" pendingLabel="Deleting…" destructive pending={del.isPending} error={del.error} onConfirm={() => target && del.mutate(target.id)} />
    </div>
  );
}

/** Agents that can't update themselves, said once for the list, grouped by reason, instead of on every row. */
interface UnmanagedComputer { domain: string; name: string; os: string; os_version: string; last_logon: string; end_of_support: string | null }

/** Windows computers in Active Directory that have no agent (plan T43); nothing shows until an agent reports a domain. */
function Unmanaged() {
  const q = useQuery({ queryKey: ["directory-unmanaged"], queryFn: () => api<UnmanagedComputer[]>("/api/directory/unmanaged") });
  const rows = q.data ?? [];
  if (!rows.length) return null;
  const domains = [...new Set(rows.map((r) => r.domain))].join(", ");
  const eos = rows.filter((r) => r.end_of_support).length;
  return (
    <section aria-labelledby="unmanaged" className="flex flex-col gap-2 border border-line bg-sunken p-4">
      <h2 id="unmanaged" className="text-base font-semibold">{rows.length} Windows computer{rows.length === 1 ? "" : "s"} in {domains} {rows.length === 1 ? "has" : "have"} no agent</h2>
      <p className="text-sm text-muted">Enabled in Active Directory and signed in within 30 days, but not reporting here, so nothing about them is checked.{eos ? ` ${eos} run Windows that no longer gets security updates.` : ""}</p>
      <details className="text-sm">
        <summary className="tap cursor-pointer py-2">Show them</summary>
        <ul className="mt-2 flex flex-col gap-1">
          {rows.slice(0, 200).map((r) => <li key={r.domain + r.name} className="break-all"><span className="font-medium">{r.name}</span> · {r.os || "unknown OS"}{r.end_of_support && <span className="text-now-fg"> · {r.end_of_support}: out of support</span>}</li>)}
        </ul>
      </details>
      <a href="/api/directory/unmanaged?format=csv" className="text-sm">Download as CSV</a>
    </section>
  );
}

export interface UnmanagedDevice {
  mac: string; vendor: string; addresses: string[]; seen_by: string[]; first_seen: string; last_seen: string;
  checked: { asset_id: string; at: string; from: string; open: string[]; priority?: Priority | null } | null;  // a machine opted in to network checks looked at it (DECISIONS 129)
}

// the list is rate-limited per person: five minutes fresh keeps ordinary browsing well inside it
const devicesQ = { queryKey: ["network-unmanaged"], queryFn: () => api<UnmanagedDevice[]>("/api/network/unmanaged"), staleTime: 300_000 };
const DEVICE_PAGE = 25;
const deviceName = (r: UnmanagedDevice) => r.addresses[0] ?? r.mac;
const rank = (r: UnmanagedDevice) => (r.checked?.priority ? PRIORITIES.indexOf(r.checked.priority) : PRIORITIES.length);
/** Devices by their most urgent issue, then most issues, then checked ones, then the most recently seen. */
export const sortDevices = (rows: UnmanagedDevice[]) => [...rows].sort((a, b) =>
  rank(a) - rank(b) || (b.checked?.open.length ?? -1) - (a.checked?.open.length ?? -1) || b.last_seen.localeCompare(a.last_seen));
const deviceFindings = (r: UnmanagedDevice) => filtersToSearch({ ...parseFilters({}), asset: r.checked!.asset_id, fixable: false });
const when = (t: string) => <time dateTime={parseUtc(t).toISOString()} title={parseUtc(t).toLocaleString()}>{relativeTime(t)}</time>;

type AssetView = "machines" | "devices" | "internet";

/** The three kinds of asset as views, with counts; devices with issues say so on the tab. */
function AssetViews({ view, devices, flagged, external }: { view: AssetView; devices: number; flagged: number; external: number }) {
  const tabs: [AssetView, string, ReactNode][] = [
    ["machines", "Machines", null],
    ["devices", "Devices with no agent", devices ? <span className="num text-muted">{devices}{flagged > 0 && <span className="text-now-fg"> · {plural(flagged, "with issues", "with issues")}</span>}</span> : null],
    ["internet", "Internet targets", external ? <span className="num text-muted">{external}</span> : null],
  ];
  return (
    <nav aria-label="Asset views" className="-mb-2 flex flex-wrap gap-x-1 border-b border-line">
      {tabs.map(([v, label, count]) => (
        <Link key={v} to="/assets" search={v === "machines" ? {} : { view: v }} aria-current={view === v ? "page" : undefined}
          className={clsx("-mb-px inline-flex min-h-[44px] items-center gap-2 border-b-2 px-3 text-sm no-underline md:min-h-10",
            view === v ? "border-ink font-semibold text-ink" : "border-transparent text-muted hover:text-ink")}>
          {label}{count}
        </Link>
      ))}
    </nav>
  );
}

/** Devices on the fleet's networks that no agent accounts for, from each agent's own neighbour table (DECISIONS 128). Passive:
 * nothing is sent to them. Hidden while there are none, like the Active Directory list. */
export function UnmanagedDevices() {
  const q = useQuery(devicesQ);
  const [text, setText] = useState("");
  const [issuesOnly, setIssuesOnly] = useState(false);
  const [shown, setShown] = useState(DEVICE_PAGE);
  // ?device=<mac> opens one device's drawer: Ctrl K links to it
  const sp = useSearch({ strict: false }) as { device?: string };
  const navigate = useNavigate();
  const [picked, setPicked] = useState<UnmanagedDevice | null | undefined>();  // a click shows at once; the URL keeps it linkable
  useEffect(() => setPicked(undefined), [sp.device]);  // a link (Ctrl K, Back) to another device wins over the last click
  const open = picked !== undefined ? picked : (q.data ?? []).find((r) => r.mac === sp.device) ?? null;
  const setOpen = (r: UnmanagedDevice | null) => {
    setPicked(r);
    void navigate({ to: "/assets", search: (x: Record<string, unknown>) => ({ ...x, view: "devices", device: r?.mac }), resetScroll: false });
  };
  const typed = useDeferredValue(text.trim().toLowerCase());
  const all = useMemo(() => sortDevices(q.data ?? []), [q.data]);
  const rows = useMemo(() => all.filter((r) => (!issuesOnly || r.checked?.open.length)
    && (!typed || [r.mac, r.vendor, ...r.addresses, ...r.seen_by].some((v) => v.toLowerCase().includes(typed)))), [all, issuesOnly, typed]);
  if (q.isError) return <Alert error={q.error} prefix="Couldn't load the devices with no agent: " />;
  if (!all.length) return null;
  const named = all.filter((r) => r.vendor && r.vendor !== "randomised MAC").length;
  const checkedCount = all.filter((r) => r.checked).length;
  const flagged = all.filter((r) => r.checked?.open.length).length;
  return (
    <section aria-labelledby="unmanaged-devices" className="flex flex-col gap-3">
      <div className="flex flex-col gap-1">
        <h2 id="unmanaged-devices" className="scroll-mt-6 text-xl font-semibold">{all.length} device{all.length === 1 ? "" : "s"} on your networks {all.length === 1 ? "has" : "have"} no agent</h2>
        <HowJudged className="max-w-[65ch]" lead={<>Seen in your machines' own network tables in the last 30 days{checkedCount ? `; ${checkedCount} checked for exposed services` : ""}.</>}>
          <p>Nothing is sent to a device to find it: each agent reports its own machine's neighbour table.{checkedCount ? " Exposed services are checked only by a machine enrolled with --allow-network-checks, on its own subnet." : " None is checked unless a machine on that network is enrolled with --allow-network-checks."}</p>
          {named > 0 && <p>{named === 1 ? "1 is" : `${named} are`} named by their network card's maker, from the IEEE registry.</p>}
        </HowJudged>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <label className="relative min-w-0 flex-1 basis-64">
          <span className="sr-only">Search devices</span>
          <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted" aria-hidden />
          <input type="search" className={clsx(input, "pl-9")} placeholder="Search by address, maker, MAC or machine" value={text} onChange={(e) => { setText(e.target.value); setShown(DEVICE_PAGE); }} />
        </label>
        {flagged > 0 && <button className={chip(issuesOnly)} aria-pressed={issuesOnly} onClick={() => { setIssuesOnly((x) => !x); setShown(DEVICE_PAGE); }}>With issues<span className="num text-muted">{flagged}</span></button>}
        <a href="/api/network/unmanaged?format=csv" className="tap inline-flex items-center px-1 text-sm">Download as CSV</a>
      </div>
      <p className="num text-sm text-muted" role="status">{rows.length === all.length ? `${plural(all.length, "device")}, those with issues first` : `${rows.length.toLocaleString()} of ${plural(all.length, "device")}`}</p>
      {rows.length === 0 ? (
        <EmptyState title="No devices match" action={<button className={btnQuiet} onClick={() => { setText(""); setIssuesOnly(false); }}>Clear search and filter</button>}>
          Nothing matches {text ? `“${text}”` : "this filter"}.
        </EmptyState>
      ) : (
        <div className="border border-line bg-surface">
          <table className="w-full border-collapse text-sm">
            <thead className="text-left text-xs text-muted">
              <tr className="border-b border-line">
                <th scope="col" className="px-3 py-2 font-normal">Device</th>
                <th scope="col" className="hidden px-3 py-2 font-normal md:table-cell">MAC</th>
                <th scope="col" className="hidden px-3 py-2 font-normal lg:table-cell">Seen by</th>
                <th scope="col" className="hidden px-3 py-2 font-normal sm:table-cell">Last seen</th>
                <th scope="col" className="px-3 py-2 font-normal">Network check</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {rows.slice(0, shown).map((r) => (
                <tr key={r.mac} className="align-top">
                  <td className="px-3 py-2">
                    <button className="tap cursor-pointer text-left font-semibold underline decoration-line-strong underline-offset-4 hover:decoration-ink" onClick={() => setOpen(r)}>
                      <span className="num">{deviceName(r)}</span><span className="sr-only">: device details</span>
                    </button>
                    <p className="text-muted">{r.vendor || "Unknown maker"}{r.addresses.length > 1 && ` · ${plural(r.addresses.length - 1, "other address", "other addresses")}`}</p>
                  </td>
                  <td className="num hidden whitespace-nowrap px-3 py-2 text-muted md:table-cell">{r.mac}</td>
                  <td className="hidden px-3 py-2 lg:table-cell"><SeenBy names={r.seen_by} /></td>
                  <td className="hidden whitespace-nowrap px-3 py-2 text-muted sm:table-cell">{when(r.last_seen)}</td>
                  <td className="px-3 py-2">
                    {!r.checked ? <span className="text-muted">Not checked</span>
                      : r.checked.open.length ? <Link to="/findings" search={deviceFindings(r)} className="tap inline-flex items-center gap-2 no-underline">
                          {r.checked.priority && <PriorityPill priority={r.checked.priority} />}<span className="font-medium text-ink underline decoration-line-strong underline-offset-4">{plural(r.checked.open.length, "issue")}<span className="sr-only"> on {deviceName(r)}</span></span></Link>
                      : <span className="text-muted">Nothing found</span>}
                    {r.checked && <p className="text-xs text-muted">by <span className="whitespace-nowrap">{r.checked.from}</span></p>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {rows.length > shown && <button className={clsx(btnQuiet, "self-start")} onClick={() => setShown((n) => n + DEVICE_PAGE * 4)}>{rows.length - shown <= DEVICE_PAGE * 4 ? `Show the other ${rows.length - shown}` : `Show ${DEVICE_PAGE * 4} more (${rows.length - shown} left)`}</button>}
      <DeviceDrawer d={open} onClose={() => setOpen(null)} />
    </section>
  );
}

/** "web-1, db-1 and 8 more": names wrap whole, never mid-name. */
function SeenBy({ names }: { names: string[] }) {
  const head = names.slice(0, 2);
  return <span>{head.map((h, i) => <Fragment key={h}><span className="whitespace-nowrap">{h}{i < head.length - 1 && ","}</span>{" "}</Fragment>)}{names.length > 2 && <span className="text-muted">and {names.length - 2} more</span>}</span>;
}

/** One device with no agent: who it is, where it was seen, and what a network check found on it. */
function DeviceDrawer({ d, onClose }: { d: UnmanagedDevice | null; onClose: () => void }) {
  const issues = useQuery({ queryKey: ["findings", "device", d?.checked?.asset_id], enabled: !!d?.checked?.open.length,
    queryFn: () => api<Finding[]>(`/api/findings?${filtersToApi({ ...parseFilters({}), asset: d!.checked!.asset_id, fixable: false }, false)}`) });  // full rows: the drawer shows each summary
  const title = useRef<HTMLHeadingElement>(null);
  const focus = useReturnFocus(title);
  const row = (label: string, value: ReactNode) => <div className="grid grid-cols-[8rem_1fr] gap-3 py-2"><dt className="text-muted">{label}</dt><dd className="min-w-0">{value}</dd></div>;
  return (
    <Dialog.Root open={!!d} onOpenChange={(o) => !o && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay className="overlay" />
        <Dialog.Content className="drawer flex flex-col gap-5 p-5 md:p-6" aria-describedby={undefined} {...focus}>
          {d && <>
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <Dialog.Title ref={title} tabIndex={-1} className="num break-all text-lg font-semibold">{deviceName(d)}</Dialog.Title>
                <p className="text-sm text-muted">{d.vendor || "Unknown maker"} · no agent</p>
              </div>
              <Dialog.Close className={clsx(btnQuiet, "size-[44px] shrink-0 !px-0 md:size-9")} aria-label="Close"><X className="size-4" aria-hidden /></Dialog.Close>
            </div>
            <section aria-labelledby="device-check" className="flex flex-col gap-2">
              <h3 id="device-check" className="text-base font-semibold">Network check</h3>
              {!d.checked ? <p className="max-w-[60ch] text-sm text-muted">Not checked. A machine on this network enrolled with <code className="num">--allow-network-checks</code> checks it for exposed services each report.</p>
                : <>
                  <p className="text-sm text-muted">Checked by <span className="text-ink">{d.checked.from}</span> {when(d.checked.at)}.</p>
                  {d.checked.open.length ? <>
                    <ul className="flex flex-col divide-y divide-line border border-line">
                      {d.checked.open.map((id) => { const f = issues.data?.find((x) => x.vuln_id === id); return (
                        <li key={id}>
                          <Link to="/findings" search={{ ...deviceFindings(d), f: f?.id }} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-sm no-underline hover:bg-sunken">
                            {f && <PriorityPill priority={f.priority} />}
                            <span className="min-w-0 flex-1">
                              <span className="block font-medium text-ink underline decoration-line-strong underline-offset-4">{f ? f.package : id}</span>
                              {f?.summary && <span className="block text-muted">{f.summary}</span>}
                            </span>
                          </Link>
                        </li>); })}
                    </ul>
                    <Link to="/findings" search={deviceFindings(d)} className={clsx(btnPrimary, "self-start no-underline")}>Review {plural(d.checked.open.length, "issue")}<ArrowRight className="size-4" aria-hidden /></Link>
                  </> : <p className="text-sm">Nothing exposed was found.</p>}
                </>}
            </section>
            <section aria-labelledby="device-identity">
              <h3 id="device-identity" className="text-base font-semibold">Identity</h3>
              <dl className="divide-y divide-line text-sm">
                {row("Maker", d.vendor === "randomised MAC" ? "Unknown: the MAC is randomised, as phones and laptops do per network" : d.vendor || "Unknown")}
                {row("MAC", <span className="num">{d.mac}</span>)}
                {row(d.addresses.length === 1 ? "Address" : "Addresses", <span className="num">{d.addresses.join(", ")}</span>)}
                {row("First seen", when(d.first_seen))}
                {row("Last seen", when(d.last_seen))}
                {row("Seen by", <span>{d.seen_by.map((h, i) => <Fragment key={h}><span className="whitespace-nowrap">{h}{i < d.seen_by.length - 1 && ","}</span>{" "}</Fragment>)}</span>)}
              </dl>
            </section>
            <p className="max-w-[60ch] text-sm text-muted">Found in your machines' own network tables; nothing is sent to it to find it. It leaves this list 30 days after it was last seen.</p>
          </>}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

interface BaselineCounts { name: string; version: string; automated: number; manual: number; pass: number; fail: number; not_assessed: number; not_applicable: number }
interface BaselineHost extends BaselineCounts { asset_id: string; hostname: string }
interface BaselineRule { id: string; severity: string; status: string; setting: string; expected: string; found: string; note: string }

/** "12 of 31 automated checks pass": rules that don't apply to this host aren't counted, and nothing here claims conformance. */
export function baselineSummary(c: BaselineCounts) {
  return `${c.pass} of ${c.automated - c.not_applicable} checks we can automate pass, ${c.fail} fail, ${c.not_assessed} not assessed`;
}

const RULE_ORDER = ["fail", "not assessed", "pass", "not applicable"];

function BaselineHostRow({ h }: { h: BaselineHost }) {
  const [open, setOpen] = useState(false);
  const q = useQuery({ queryKey: ["baseline", h.asset_id], enabled: open, queryFn: () => api<{ rules: BaselineRule[] }>(`/api/baselines/${h.asset_id}`) });
  const rules = [...(q.data?.rules ?? [])].sort((a, b) => RULE_ORDER.indexOf(a.status) - RULE_ORDER.indexOf(b.status));
  return (
    <li>
      <details className="text-sm" onToggle={(e) => setOpen(e.currentTarget.open)}>
        <summary className="tap cursor-pointer break-words py-2"><span className="font-medium">{h.hostname}</span>: {baselineSummary(h)}</summary>
        {q.isLoading && <Loading />}
        <Alert error={q.error} />
        <ul className="mt-2 flex flex-col gap-2">
          {rules.map((r) => (
            <li key={r.id} className="break-words border-t border-line pt-2">
              <span className={clsx("font-medium", r.status === "fail" && "text-now-fg")}>{r.status}</span> · {r.id} · {r.severity}
              <div className="text-muted">{r.setting}: expected {r.expected}, read {r.found}{r.note && `. ${r.note}`}</div>
            </li>
          ))}
        </ul>
      </details>
    </li>
  );
}

/** Settings compared with published baselines (DECISIONS 75): a reference. Manual checks are never assessed, and it says so. */
export function Baselines() {
  const q = useQuery({ queryKey: ["baselines"], queryFn: () => api<{ baselines: (BaselineCounts & { baseline_id: string; hosts: number })[]; hosts: BaselineHost[]; no_baseline: number }>("/api/baselines") });
  const d = q.data;
  if (!d?.hosts.length) return null;
  return (
    <section aria-labelledby="baselines" className="flex flex-col gap-2 border border-line bg-sunken p-4">
      <h2 id="baselines" className="text-base font-semibold">Windows settings compared with published baselines</h2>
      <HowJudged lead="A reference, not a conformance result: a pass means the setting read as the baseline expects.">
        <p>Only the checks we can automate are counted, and manual checks are not assessed.{d.no_baseline ? ` ${plural(d.no_baseline, "Windows host")} on other versions ${d.no_baseline === 1 ? "has" : "have"} no baseline here.` : ""}</p>
      </HowJudged>
      {d.baselines.map((b) => (
        <div key={b.baseline_id} className="flex flex-col gap-1">
          <h3 className="text-sm font-semibold">{b.name} {b.version}</h3>
          <p className="text-sm">{plural(b.hosts, "host")}, {b.automated} checks we can automate and {b.manual} manual checks not assessed. Across these hosts: {b.pass} pass, {b.fail} fail, {b.not_assessed} not assessed.</p>
          <ul className="flex flex-col">
            {d.hosts.filter((h) => h.name === b.name && h.version === b.version).map((h) => <BaselineHostRow key={h.asset_id} h={h} />)}
          </ul>
        </div>
      ))}
      <a href="/api/baselines.csv" className="flex tap items-center text-sm">Download as CSV</a>
    </section>
  );
}

interface PathSummary { kind: "network" | "foothold"; start: string; grade: string; steps: string[]; break_at: { label: string; fixes: number; refs: string[] } }
interface FleetHost { hostname: string; judged: boolean; paths: PathSummary[] }
interface Reach { host: string; hops: string[]; grade: string; fix_on_host: string[] }
interface AttackPathsData { hosts: Record<string, FleetHost>; truncated?: boolean; chains: { start: string; why_start: string; reach: Reach[] }[] }

/** How weaknesses chain on each host and from one host to the next (DECISIONS 97, 98): every step is evidence, and the grade is the weakest one's. */
export function AttackPaths() {
  const q = useQuery({ queryKey: ["attack-paths"], queryFn: () => api<AttackPathsData>("/api/attack-paths") });
  const d = q.data;
  const withPaths = Object.entries(d?.hosts ?? {}).filter(([, h]) => h.paths.length);
  if (!d || (!withPaths.length && !d.chains.length)) return null;
  const name = (id: string) => d.hosts[id]?.hostname ?? id;
  const unjudged = Object.values(d.hosts).filter((h) => !h.judged).length;
  return (
    <section aria-labelledby="attack-paths" className="flex flex-col gap-2 border border-line bg-sunken p-4">
      <h2 id="attack-paths" className="text-base font-semibold">How these weaknesses combine</h2>
      <HowJudged lead={<>Each step is a vulnerability or a setting read on the host.{d.truncated ? " Only the first links are shown: fix the settings named below first." : ""}</>}>
        <p>A path is only as sure as its weakest step, and whether one host can route to another isn't seen, so nothing across hosts is better than reasonable.</p>
        <p>Each host's part rests on what its own agent reported, so a compromised host could make its own links look worse or better.{unjudged ? ` ${plural(unjudged, "host")} ${unjudged === 1 ? "hasn't" : "haven't"} been judged yet.` : ""}</p>
      </HowJudged>
      {d.chains.map((c) => (
        <div key={c.start} className="flex flex-col gap-1">
          <h3 className="text-sm font-semibold">From {name(c.start)} ({c.why_start}), an attacker can reach {plural(c.reach.length, "other host")}</h3>
          <ul className="flex flex-col gap-1 text-sm">
            {c.reach.map((r) => (
              <li key={r.host} className="break-words">
                <span className="font-medium">{name(r.host)}</span> via {[c.start, ...r.hops].map(name).join(" → ")} · how sure: {r.grade} · cut it on {name(r.host)}: {r.fix_on_host.join(", ")}
              </li>
            ))}
          </ul>
        </div>
      ))}
      <details className="text-sm">
        <summary className="tap cursor-pointer py-2">Paths on each host ({withPaths.length})</summary>
        <ul className="mt-2 flex flex-col gap-2">
          {withPaths.map(([id, h]) => h.paths.map((p) => (
            <li key={id + p.kind} className="break-words border-t border-line pt-2">
              <span className="font-medium">{h.hostname}</span>, {p.start} · how sure: {p.grade}
              <div className="text-muted">{p.steps.join(" → ")}. Break it: fix {plural(p.break_at.fixes, "way")} of {p.break_at.label.toLowerCase()} ({p.break_at.refs.join(", ")})</div>
            </li>
          )))}
        </ul>
      </details>
    </section>
  );
}

/** Software the curated rules don't cover (DECISIONS 24): listed, never matched, so saying so is part of every clean result. */
export function NotAssessed() {
  const q = useQuery(coverageQ);
  if (!q.data?.inventory_only) return null;
  const { assessed, inventory_only: only, not_assessed: rows } = q.data;
  return (
    <section aria-labelledby="not-assessed" className="flex flex-col gap-2 border border-line bg-sunken p-4">
      <h2 id="not-assessed" className="text-base font-semibold">{plural(only, "installed app")} {only === 1 ? "isn't" : "aren't"} checked for vulnerabilities</h2>
      <p className="max-w-prose text-sm text-muted">{plural(assessed, "install")} of known apps {assessed === 1 ? "is" : "are"} checked. The rest are listed but never matched, because a wrong guess is worse than saying so. Many are runtimes and drivers, but no finding for them doesn't mean they're safe.</p>
      <details className="text-sm">
        <summary className="tap cursor-pointer py-2">Show them, most common first</summary>
        <ul className="mt-2 flex flex-col gap-1">
          {rows.map((r) => <li key={`${r.name}|${r.publisher}`} className="break-words"><span className="font-medium">{r.name}</span>{r.publisher && ` · ${r.publisher}`} · {plural(r.hosts, "machine")}</li>)}
        </ul>
      </details>
    </section>
  );
}

type Sort = "urgent" | "name" | "seen";
const FILTERS = { quiet: "Not reporting", agent: "Agent outdated", canary: "Canary", facing: "Internet-facing", test: "Test machine" } as const;
type Filter = keyof typeof FILTERS;
const FILTER_HELP: Record<Filter, string> = {
  quiet: "No report for over 14 hours: findings may be out of date", agent: "The agent can't update itself; rerun its install command once",
  canary: "Canary machines get a fix first; the rest wait until a canary has stayed healthy", facing: "Reachable from the internet: its findings rank higher",
  test: "Test machines are the only ones fixes may change until production remediation is on",
};
const MATCH: Record<Filter, (a: Asset) => boolean> = {
  quiet: (a) => !!a.not_reporting, agent: (a) => !!a.agent_update && !["current", "updating"].includes(a.agent_update),
  canary: (a) => a.kind === "host" && a.ring === 0, facing: (a) => a.internet_facing, test: (a) => a.sandbox,
};
const WEIGHT: Record<string, number> = { "fix-now": 1e9, next: 1e6, planned: 1e3, low: 1 };
const urgency = (a: Asset) => Object.entries(a.open_by_priority).reduce((n, [p, c]) => n + (WEIGHT[p] ?? 0) * (c ?? 0), 0);
const PAGE = 40;

/** Search, filter and sort the fleet (pure, so it can be tested). */
export function filterAssets(assets: Asset[], text: string, on: Filter[], crit: Criticality | "", sort: Sort) {
  const t = text.trim().toLowerCase();
  const rows = assets.filter((a) => (!t || `${a.hostname} ${a.os_name} ${a.agent_version ?? ""}`.toLowerCase().includes(t))
    && on.every((f) => MATCH[f](a)) && (!crit || a.criticality === crit));
  return rows.sort(sort === "name" ? (x, y) => x.hostname.localeCompare(y.hostname)
    : sort === "seen" ? (x, y) => x.last_seen.localeCompare(y.last_seen) : (x, y) => urgency(y) - urgency(x) || x.hostname.localeCompare(y.hostname));
}

/** The fleet as one line per machine; editing happens in a drawer, or for several at once through the bulk bar. */
function MachineList({ assets, saved, failed, onPatch, onDelete, undo }: {
  assets: Asset[]; saved: string; failed: { id: string; message: string } | null; onPatch: (id: string, p: AssetPatch) => void; onDelete: (a: Asset) => void; undo?: () => void;
}) {
  const admin = useIsAdmin();
  // ?show=quiet,agent and ?machine=<id> make a filtered list or one machine's drawer linkable (the palette uses them)
  const sp = useSearch({ strict: false }) as { show?: string; machine?: string; q?: string; crit?: string; sort?: string };
  const navigate = useNavigate();
  const [text, setText] = useState(sp.q ?? "");
  const [on, setOn] = useState<Filter[]>(() => (sp.show ?? "").split(",").filter((f): f is Filter => f in FILTERS));
  useEffect(() => { if (sp.show) setOn(sp.show.split(",").filter((f): f is Filter => f in FILTERS)); }, [sp.show]);
  const [crit, setCrit] = useState<Criticality | "">(() => (LEVELS as string[]).includes(sp.crit ?? "") ? sp.crit as Criticality : "");
  const [sort, setSort] = useState<Sort>(() => (["urgent", "name", "seen"].includes(sp.sort ?? "") ? sp.sort as Sort : "urgent"));
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [shown, setShown] = useState(PAGE);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const editing = sp.machine ?? null;
  const setEditing = (id: string | null) => void navigate({ to: "/assets", search: (s: Record<string, unknown>) => ({ ...s, machine: id ?? undefined }), resetScroll: false });
  const open = useCallback((id: string) => void navigate({ to: "/assets", search: (s: Record<string, unknown>) => ({ ...s, machine: id }), resetScroll: false }), [navigate]);
  const typed = useDeferredValue(text);  // the list catches up after the keystroke, never blocking it
  // the list's state lives in the URL too, so Back, refresh and a shared link keep it
  useEffect(() => {
    void navigate({ to: "/assets", replace: true, resetScroll: false,
      search: (s: Record<string, unknown>) => ({ ...s, q: typed || undefined, show: on.join(",") || undefined, crit: crit || undefined, sort: sort === "urgent" ? undefined : sort }) });
  }, [typed, on, crit, sort, navigate]);
  const fleetwideAgent = assets.filter(MATCH.agent).length > assets.length / 2;  // said once in the banner, not on every row
  const rows = useMemo(() => filterAssets(assets, typed, on, crit, sort), [assets, typed, on, crit, sort]);
  const pick = useCallback((id: string, v: boolean) => setPicked((s) => { const n = new Set(s); if (v) n.add(id); else n.delete(id); return n; }), []);
  const counts = useMemo(() => Object.fromEntries((Object.keys(FILTERS) as Filter[]).map((f) => [f, assets.filter(MATCH[f]).length])) as Record<Filter, number>, [assets]);
  const visible = rows.slice(0, shown);
  const pickedRows = assets.filter((a) => picked.has(a.id));
  const apps = pickedRows.filter((a) => a.kind !== "host").length;
  const allPicked = rows.length > 0 && rows.every((a) => picked.has(a.id));
  const [staged, setStaged] = useState<AssetPatch>({});
  const [applied, setApplied] = useState<{ text: string; undo: { id: string; p: AssetPatch }[] } | null>(null);
  const describe = (p: AssetPatch) => [p.criticality && `criticality ${p.criticality}`, p.ring !== undefined && `ring ${p.ring === 0 ? "canary" : "broad"}`,
    p.internet_facing !== undefined && (p.internet_facing ? "internet-facing" : "not internet-facing")].filter(Boolean).join(", ");
  const apply = () => {
    // what each machine had before, so the whole change can be undone
    const undo = pickedRows.map((a) => ({ id: a.id, p: Object.fromEntries(Object.keys(staged).map((k) => [k, a[k as keyof AssetPatch]])) as AssetPatch }));
    // ring and health units mean nothing for an application (no agent runs fixes there)
    const forRow = (a: Asset) => (a.kind === "host" ? staged : { ...staged, ring: undefined });
    pickedRows.forEach((a) => { const p = forRow(a); if (describe(p)) onPatch(a.id, p); });
    setApplied({ text: `Set ${describe(staged)} on ${plural(pickedRows.length, "machine")}.`, undo });
    setStaged({});
  };
  const current = assets.find((a) => a.id === editing) ?? null;
  const bar = useRef<HTMLDivElement>(null);
  const barOpen = admin && picked.size > 0;
  useEffect(() => {
    const root = document.documentElement;
    if (barOpen && bar.current) root.style.setProperty("--bulk-bar", `${bar.current.offsetHeight + 8}px`);
    return () => { root.style.removeProperty("--bulk-bar"); };
  }, [barOpen]);
  const clear = () => { setText(""); setOn([]); setCrit(""); setShown(PAGE); };
  return (
    <section aria-labelledby="machines-h" className="flex flex-col gap-3">
      <h2 id="machines-h" className="sr-only">Machines and applications</h2>
      <AgentUpdateSummary assets={assets.filter((a) => a.kind === "host")} onShow={() => { setOn(["agent"]); setShown(PAGE); }} />
      <div className="flex flex-col gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <button className={clsx(chip(on.length > 0 || !!crit), "md:hidden")} aria-expanded={filtersOpen} aria-controls="asset-filters" onClick={() => setFiltersOpen((x) => !x)}>
            <SlidersHorizontal className="size-4" aria-hidden />Filters ({on.length + Number(!!crit)})
          </button>
          <label className="relative min-w-0 flex-1 basis-64">
            <span className="sr-only">Search assets</span>
            <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted" aria-hidden />
            <input type="search" className={clsx(input, "pl-9")} placeholder="Search by name, OS or agent version" value={text} onChange={(e) => { setText(e.target.value); setShown(PAGE); }} />
          </label>
          <div id="asset-filters" className={clsx("w-full flex-wrap items-center gap-2 md:flex md:w-auto", filtersOpen ? "flex" : "hidden")}>
          {/* the quick filters as one control (DESIGN.md: six controls before the first row); a link may still set several */}
          <label className="flex items-center gap-2 text-sm">
            <span className="text-muted">Show</span>
            <select className={clsx(input, "w-auto md:min-h-9")} value={on.length === 1 ? on[0] : on.length ? "several" : ""}
              onChange={(e) => startTransition(() => { setOn(e.target.value ? [e.target.value as Filter] : []); setShown(PAGE); })}>
              <option value="">All machines</option>
              {on.length > 1 && <option value="several" disabled>{on.map((f) => FILTERS[f]).join(" + ")}</option>}
              {(Object.keys(FILTERS) as Filter[]).filter((f) => counts[f] > 0 || on.includes(f)).map((f) => (
                <option key={f} value={f} title={FILTER_HELP[f]}>{FILTERS[f]} ({counts[f].toLocaleString()})</option>
              ))}
            </select>
          </label>
          <label className="flex items-center gap-2 text-sm">
            <span className="text-muted">Criticality</span>
            <select className={clsx(input, "w-auto capitalize md:min-h-9")} value={crit} onChange={(e) => setCrit(e.target.value as Criticality | "")}>
              <option value="">Any</option>{LEVELS.map((l) => <option key={l} value={l}>{cap(l)}</option>)}
            </select>
          </label>
          <label className="flex items-center gap-2 text-sm">
            <span className="text-muted">Sort</span>
            <select className={clsx(input, "w-auto md:min-h-9")} value={sort} onChange={(e) => setSort(e.target.value as Sort)}>
              <option value="urgent">Most urgent first</option><option value="name">Name</option><option value="seen">Longest since last report</option>
            </select>
          </label>
          </div>
        </div>
      </div>
      <div className="flex min-h-[44px] flex-wrap items-center gap-x-4 gap-y-2 md:min-h-9">
        <p className="num text-sm text-muted" role="status">{rows.length === assets.length ? plural(assets.length, "asset") : `${rows.length.toLocaleString()} of ${plural(assets.length, "asset")}`}</p>
        {admin && rows.length > 0 && (
          <label className="flex tap cursor-pointer items-center gap-2 text-sm">
            <input type="checkbox" className="size-4 accent-[var(--ink)]" checked={allPicked} onChange={() => startTransition(() => setPicked(allPicked ? new Set() : new Set(rows.map((a) => a.id))))} />
            Select all {rows.length.toLocaleString()}{rows.length === assets.length ? "" : " matching"}{rows.length > shown ? `, including ${(rows.length - shown).toLocaleString()} not shown yet` : ""}
          </label>
        )}
      </div>
      {admin && picked.size > 0 && (
        <div role="region" aria-label="Change selected machines" ref={bar} className="fixed inset-x-2 bottom-[calc(var(--tabbar-h,3.5rem)+0.5rem)] z-10 flex max-h-[40dvh] flex-wrap items-center gap-x-4 gap-y-2 overflow-y-auto border border-ink bg-surface px-3 py-2 text-sm shadow-[0_6px_16px_var(--shadow)] md:bottom-4 md:left-[calc(var(--sidebar-w)+1.5rem)] md:right-6">
          <SlidersHorizontal className="size-4" aria-hidden /><strong className="num font-semibold">{picked.size} selected</strong>
          <label className="flex w-full items-center gap-2 sm:w-auto"><span className="text-muted">Criticality</span>
            <select className={clsx(input, "min-w-0 flex-1 capitalize sm:w-auto sm:flex-none md:min-h-9")} value={staged.criticality ?? ""} onChange={(e) => setStaged((s) => ({ ...s, criticality: (e.target.value || undefined) as Criticality | undefined }))}>
              <option value="">Unchanged</option>{LEVELS.map((l) => <option key={l} value={l}>{cap(l)}</option>)}
            </select></label>
          {apps > 0 && <span className="w-full text-muted">{plural(apps, "application")} selected: ring doesn't apply to {apps === 1 ? "it" : "them"}.</span>}
          <label className="flex w-full items-center gap-2 sm:w-auto"><span className="text-muted">Ring</span>
            <select className={clsx(input, "min-w-0 flex-1 sm:w-auto sm:flex-none md:min-h-9")} value={staged.ring ?? ""} onChange={(e) => setStaged((s) => ({ ...s, ring: e.target.value === "" ? undefined : Number(e.target.value) as 0 | 1 }))}>
              <option value="">Unchanged</option><option value="0">Canary</option><option value="1">Broad</option>
            </select></label>
          <label className="flex w-full items-center gap-2 sm:w-auto"><span className="text-muted">Internet-facing</span>
            <select className={clsx(input, "min-w-0 flex-1 sm:w-auto sm:flex-none md:min-h-9")} value={staged.internet_facing === undefined ? "" : staged.internet_facing ? "yes" : "no"} onChange={(e) => setStaged((s) => ({ ...s, internet_facing: e.target.value === "" ? undefined : e.target.value === "yes" }))}>
              <option value="">Unchanged</option><option value="yes">Yes</option><option value="no">No</option>
            </select></label>
          <div className="ml-auto flex gap-2">
            <button className={btnQuiet} onClick={() => { setPicked(new Set()); setStaged({}); }}>Clear selection</button>
            <button className={btnPrimary} disabled={!describe(staged)} onClick={apply}>Apply to {plural(picked.size, apps ? "asset" : "machine")}</button>
          </div>
        </div>
      )}
      {applied && (
        <div className="flex flex-wrap items-center gap-3">
          <Done className="text-muted">{applied.text}</Done>
          <button className={btnQuiet} onClick={() => { applied.undo.forEach((u) => onPatch(u.id, u.p)); setApplied(null); }}>Undo</button>
        </div>
      )}
      {rows.length === 0 ? (
        <EmptyState title="No machines match" action={<button className={btnQuiet} onClick={clear}>Clear search and filters</button>}>
          Nothing matches {text ? `“${text}”` : "these filters"}.
        </EmptyState>
      ) : (
        <div className="flex flex-col">
        {/* the count columns say what they count once, at the top */}
        <div aria-hidden className="hidden items-end justify-end gap-x-4 px-3 pb-1 text-xs text-muted lg:flex">
          <span className="grid grid-cols-[repeat(4,minmax(0,6.5rem))_2.25rem] gap-1 text-center">{PRIORITIES.map((p) => <span key={p}>{PRIORITY_LABEL[p]}</span>)}<span /></span>
        </div>
        <ul className="flex flex-col divide-y divide-line border border-line bg-surface">
          {visible.map((a) => <MachineLine key={a.id} a={a} picked={picked.has(a.id)} saved={saved === a.id} onPick={pick} onOpen={open} quietAgent={fleetwideAgent} />)}
        </ul>
        </div>
      )}
      {barOpen && <div aria-hidden style={{ height: "var(--bulk-bar, 6rem)" }} />}
      {rows.length > shown && <button className={clsx(btnQuiet, "self-start")} onClick={() => setShown((n) => n + PAGE * 5)}>{rows.length - shown <= PAGE * 5 ? `Show the other ${rows.length - shown}` : `Show ${PAGE * 5} more (${rows.length - shown} left)`}</button>}
      <MachineDrawer a={current} onClose={() => setEditing(null)}>
        {current && <AssetRow a={current} saved={saved === current.id} inDrawer undo={saved === current.id ? undo : undefined} error={failed?.id === current.id ? failed.message : undefined}
          onPatch={(p) => onPatch(current.id, p)} onDelete={() => { setEditing(null); onDelete(current); }} />}
      </MachineDrawer>
    </section>
  );
}

/** One line per machine: name, state, where it stands. Its settings live in the drawer. */
const MachineLine = memo(function MachineLine({ a, picked, saved, onPick, onOpen, quietAgent }: { a: Asset; picked: boolean; saved: boolean; onPick: (id: string, v: boolean) => void; onOpen: (id: string) => void; quietAgent?: boolean }) {
  const admin = useIsAdmin();
  return (
    <li className={clsx("flex flex-wrap items-center gap-x-4 gap-y-1 px-3 py-2", picked && "bg-accent-soft")}>
      {/* the label is the 44px target on phones */}
      {admin && <label className="-my-2 -ml-3 flex tap min-w-[44px] shrink-0 cursor-pointer items-center justify-center md:min-w-0 md:ml-0 md:my-0">
        <input type="checkbox" className="size-4 accent-[var(--ink)]" checked={picked} onChange={(e) => onPick(a.id, e.target.checked)} aria-label={`Select ${a.hostname}`} />
      </label>}
      <div className="min-w-[min(12rem,100%)] flex-1 basis-56">
        <div className="flex flex-wrap items-center gap-x-2">
          <button className="tap cursor-pointer text-left font-semibold underline decoration-line-strong underline-offset-4 hover:decoration-ink" onClick={() => onOpen(a.id)}>
            <span className="break-all">{a.hostname}</span><span className="sr-only">: details and settings</span>
          </button>
          {a.not_reporting && <Tag tone="now">Not reporting</Tag>}
          {a.agent_update && !["current", "updating"].includes(a.agent_update) && (!quietAgent || a.agent_update === "failed") && <Tag tone={a.agent_update === "failed" ? "now" : "muted"}>{AGENT_UPDATE[a.agent_update as Exclude<AgentUpdate, "current">].label}</Tag>}
          {a.sandbox && <Tag>Test machine</Tag>}
          {saved && <Done className="text-muted">Saved</Done>}
        </div>
        <p className="truncate text-sm text-muted">
          {a.kind === "application" ? "Application (SBOM)" : a.os_name || "Unknown OS"} · <span className="capitalize">{a.criticality}</span>
          {a.kind === "host" && a.ring === 0 && " · canary"}{a.internet_facing && " · internet-facing"} · seen <time dateTime={parseUtc(a.last_seen).toISOString()} title={parseUtc(a.last_seen).toLocaleString()}>{relativeTime(a.last_seen)}</time>
        </p>
      </div>
      <PriorityLinks a={a} columns />
    </li>
  );
});

/** A machine's open findings by priority, each a link to them; `columns` lines them up across rows of a list. */
function PriorityLinks({ a, columns }: { a: Asset; columns?: boolean }) {
  const open = PRIORITIES.filter((p) => a.open_by_priority[p]);
  return (
    <div className={clsx("flex flex-wrap items-center gap-1.5", columns && "md:justify-end lg:grid lg:grid-cols-[repeat(4,minmax(0,6.5rem))_2.25rem] lg:gap-1")}>
      {open.length === 0 ? <span className={clsx("text-sm text-muted", columns && "lg:col-span-4")}>No open findings</span> : PRIORITIES.map((p) => a.open_by_priority[p] ? (
        <Link key={p} to="/findings" search={filtersToSearch({ ...parseFilters({}), asset: a.id, priority: [p], fixable: false })} className="inline-flex tap items-center no-underline">
          <PriorityPill priority={p} count={a.open_by_priority[p]} />
        </Link>
      ) : columns ? <span key={p} aria-hidden className="hidden text-center text-muted lg:block">–</span> : null)}
      {open.length > 0 && (
        <Link to="/findings" search={filtersToSearch({ ...parseFilters({}), asset: a.id, fixable: false })} aria-label={`View findings for ${a.hostname}`} className="inline-flex size-[44px] items-center justify-center text-muted hover:bg-sunken hover:text-ink md:size-9"><ArrowRight className="size-4" aria-hidden /></Link>
      )}
    </div>
  );
}

function MachineDrawer({ a, onClose, children }: { a: Asset | null; onClose: () => void; children: ReactNode }) {
  const title = useRef<HTMLHeadingElement>(null);
  const focus = useReturnFocus(title);
  return (
    <Dialog.Root open={!!a} onOpenChange={(o) => !o && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay className="overlay" />
        <Dialog.Content className="drawer p-5 md:p-6" aria-describedby={undefined} {...focus}>
          <div className="flex items-start justify-between gap-3">
            <Dialog.Title ref={title} tabIndex={-1} className="break-all text-lg font-semibold">{a?.hostname}</Dialog.Title>
            <Dialog.Close className={clsx(btnQuiet, "size-[44px] shrink-0 !px-0 md:size-9")} aria-label="Close"><X className="size-4" aria-hidden /></Dialog.Close>
          </div>
          {/* one machine's settings save as you make them (Undo takes back the last); Settings' org-wide forms have a Save each */}
          <p className="mt-1 text-sm text-muted">Changes here save as you make them and re-rank this machine's findings. Undo takes back the last one.</p>
          <ul className="-mx-4">{children}</ul>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

/** Summarise agents needing attention from assets; onShow optionally opens the relevant view. */
export function AgentUpdateSummary({ assets, onShow }: { assets: Asset[]; onShow?: () => void }) {
  const groups = new Map<string, { failed: boolean; hosts: string[] }>();
  for (const a of assets) {
    if (!a.agent_update || ["current", "updating"].includes(a.agent_update)) continue;
    const why = AGENT_UPDATE[a.agent_update as Exclude<typeof a.agent_update, "current">].why(a);
    const g = groups.get(why) ?? { failed: a.agent_update === "failed", hosts: [] };
    g.hosts.push(a.hostname);
    groups.set(why, g);
  }
  if (!groups.size) return null;
  // one reason for most hosts (an old agent that predates self-update) is said once, with the versions
  const reinstall = [...groups].filter(([why]) => /can't update itself/.test(why));
  if (reinstall.length > 1) {
    const hosts = reinstall.flatMap(([, g]) => g.hosts);
    // an agent that reported no version ("" or null) is "unknown", never an empty label
    const versions = assets.filter((a) => hosts.includes(a.hostname)).reduce<Record<string, number>>((n, a) => ({ ...n, [a.agent_version || "unknown"]: (n[a.agent_version || "unknown"] ?? 0) + 1 }), {});
    const named = Object.entries(versions).map(([v, n]) => `${v} (${plural(n, "machine")})`);
    for (const [why] of reinstall) groups.delete(why);
    groups.set(`Agent version${named.length > 1 ? "s" : ""} ${named.length > 1 ? `${named.slice(0, -1).join(", ")} and ${named.at(-1)}` : named[0]} predate${named.length > 1 ? "" : "s"} self-update. Rerun the install command on each once; the enrolment is kept, and later versions update automatically.`, { failed: false, hosts });
  }
  return (
    <ul className="flex flex-col gap-1.5 border border-line-strong bg-surface px-3 py-2 text-sm [&>li]:max-w-[60ch]">
      {[...groups].map(([why, g]) => (
        <li key={why} className={clsx(g.failed && "text-now-fg")}>
          <strong className="font-semibold">{plural(g.hosts.length, "machine")}:</strong> {why}
          {/* one link per notice (DESIGN.md): where the list can filter to them, that; otherwise the names in place */}
          {onShow ? <> <Link to="/assets" search={{ show: "agent" }} onClick={onShow} className="font-medium underline">List them</Link></> : <details className="mt-1">
            <summary className="tap w-fit cursor-pointer py-2 text-muted md:py-0">Show which</summary>
            {/* names never break mid-word: each wraps as a whole */}
            <p className="mt-1">{g.hosts.map((h, i) => <Fragment key={h}><span className="whitespace-nowrap">{h}{i < g.hosts.length - 1 && ","}</span>{" "}</Fragment>)}</p>
          </details>}
        </li>
      ))}
    </ul>
  );
}

/** Render asset a and editable details; invoke onPatch/onDelete for mutations and display saved/error/undo state. */
export function AssetRow({ a, onPatch, onDelete, saved, error, inDrawer, undo }: { a: Asset; onPatch: (p: AssetPatch) => void; onDelete: () => void; saved?: boolean; error?: string; inDrawer?: boolean; undo?: () => void }) {
  const admin = useIsAdmin();
  const open = PRIORITIES.filter((p) => a.open_by_priority[p]);
  const host = a.kind === "host";
  return (
    <li className="flex flex-col gap-3 p-4">
      <div className="flex flex-wrap items-start justify-between gap-x-6 gap-y-2">
      <div className="min-w-0 flex-1 basis-60">
        <div className="flex flex-wrap items-center gap-2"><h3 className={inDrawer ? "sr-only" : "min-w-0 break-all text-base font-semibold"} title={a.hostname}>{a.hostname}</h3>
          {a.sandbox && <Tag why="Test machine: the only kind automated fixes may change until production remediation is turned on">Test machine</Tag>}
          {a.not_reporting && <Tag tone="now" why={`Last report ${relativeTime(a.last_seen)}, so findings may be out of date. Check the host is running and the agent's timer or scheduled task.`}>Not reporting</Tag>}
          {a.agent_update && a.agent_update !== "current" && <Tag tone={a.agent_update === "failed" ? "now" : "muted"}>{AGENT_UPDATE[a.agent_update].label}</Tag>}</div>
        <p className="truncate text-sm text-muted">
          {a.kind === "application" ? "Application (SBOM)" : a.os_name || "Unknown OS"}{a.agent_version && ` · agent ${a.agent_version}`} · seen <time dateTime={parseUtc(a.last_seen).toISOString()} title={parseUtc(a.last_seen).toLocaleString()}>{relativeTime(a.last_seen)}</time>
        </p>
        {a.not_reporting && <p className="mt-1 text-xs text-now-fg">Last report {relativeTime(a.last_seen)}, so findings may be out of date.</p>}
        {a.apps && a.apps.inventory_only > 0 && <p className="mt-1 text-xs text-muted">{a.apps.assessed === 0 ? `None of its ${plural(a.apps.inventory_only, "installed app")} could be checked.` : `${a.apps.assessed} of ${a.apps.assessed + a.apps.inventory_only} installed apps checked; the rest are listed only.`}</p>}
        {a.facts?.os_unmatched && <p className="mt-1 text-xs text-muted">OS not matched to Microsoft's fixes: {a.facts.os_unmatched}. Apps and end of support are still checked.</p>}
        {a.facts?.pending_reboot && <p className="mt-1 text-xs text-next-fg">Updates are installed and waiting for a restart: findings close after it.</p>}
        {updateSource(a.facts) && <p className="mt-1 text-xs text-muted">{updateSource(a.facts)}</p>}
        {inDrawer && a.agent_update && a.agent_update !== "current" && <p className="mt-2 text-sm">{AGENT_UPDATE[a.agent_update].why(a)} <Link to="/add" className="font-medium underline">Install command</Link></p>}
        {inDrawer && open.length > 0 && <p className="mt-2 text-sm"><Link to="/findings" search={filtersToSearch({ ...parseFilters({}), asset: a.id, group: "package" })} className="inline-flex tap items-center font-medium underline">Fixes for this machine, by package</Link></p>}
      </div>
      <PriorityLinks a={a} />
      </div>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        {/* The API only lets admins change these; everyone else reads them (as in Settings). */}
        {!admin ? (
          <p className="text-sm text-muted">
            Criticality: <span className="capitalize text-ink">{a.criticality}</span> · {a.internet_facing ? "Internet-facing" : "Not internet-facing"}
            {host && <> · Ring: <span className="text-ink">{a.ring === 0 ? "Canary" : "Broad"}</span> · Health units: <span className="text-ink">{a.health_units.join(", ") || "none"}</span></>}
          </p>
        ) : <>
        <label className="flex items-center gap-2 text-sm">
          <span className="whitespace-nowrap text-muted">Criticality</span>
          <select className={clsx(input, "w-auto capitalize md:min-h-9")} value={a.criticality} onChange={(e) => onPatch({ criticality: e.target.value as Criticality })}>
            {LEVELS.map((l) => <option key={l} value={l}>{cap(l)}</option>)}
          </select>
        </label>
        <label className="flex tap cursor-pointer items-center gap-2 whitespace-nowrap text-sm">
          <Switch.Root checked={a.internet_facing} onCheckedChange={(internet_facing) => onPatch({ internet_facing })} className={switchRoot}>
            <Switch.Thumb className={switchThumb} />
          </Switch.Root>
          Internet-facing
        </label>
        {a.kind === "host" && (a.directory_source || (typeof a.facts?.domain_role === "number" && a.facts.domain_role >= 1)) && (
          <label className="flex tap cursor-pointer items-center gap-2 whitespace-nowrap text-sm"
            title="Only this machine's agent may send the domain's computer list (with --ad-discovery); any other host is refused">
            <Switch.Root checked={!!a.directory_source} onCheckedChange={(directory_source) => onPatch({ directory_source })} className={switchRoot}>
              <Switch.Thumb className={switchThumb} />
            </Switch.Root>
            Directory source
          </label>
        )}
        {a.kind === "host" && <><label className="flex items-center gap-2 text-sm">
          <span className="whitespace-nowrap text-muted">Ring</span>
          <select className={clsx(input, "w-auto md:min-h-9")} value={a.ring} onChange={(e) => onPatch({ ring: Number(e.target.value) as 0 | 1 })}>
            <option value={0}>Canary</option><option value={1}>Broad</option>
          </select>
        </label>
        <HealthUnits a={a} onPatch={onPatch} /></>}
        </>}
        <SbomUpload a={a} />
        {saved && <Done className="text-muted">Saved. Findings re-ranked.</Done>}
        {saved && undo && <button className={btnQuiet} onClick={undo}>Undo</button>}
        {!inDrawer && <button className={clsx(btnQuiet, "ml-auto px-3 md:px-2.5")} onClick={onDelete} title={`Delete ${a.hostname}`} {...adminGate(admin)}>
          <Trash2 className="size-4" aria-hidden /><span className="md:sr-only">Delete</span><span className="sr-only"> {a.hostname}</span>
        </button>}
      </div>
      <Alert error={error} prefix="Couldn't save that change: " />
      {inDrawer && host && <p className="max-w-[60ch] text-sm text-muted">
        <strong className="font-medium text-ink">Ring:</strong> canary machines get a fix first; broad machines wait until a canary has stayed healthy.{" "}
        <strong className="font-medium text-ink">Health units:</strong> systemd units checked before and after a fix, saved when you leave the field or press Enter.
      </p>}
      {/* in the drawer, deleting sits apart from the settings, never next to an ordinary action */}
      {inDrawer && <div className="mt-2 flex flex-wrap items-center justify-between gap-3 border-t border-line pt-4">
        <p className="text-sm text-muted">Removes its findings and installed-software list; the ledger keeps the history.</p>
        <button className={clsx(btnQuiet, "border-now-fg text-now-fg hover:bg-now-bg")} onClick={onDelete} {...adminGate(admin)}>
          <Trash2 className="size-4" aria-hidden />Delete {a.kind === "application" ? "application" : "machine"}<span className="sr-only"> {a.hostname}</span>
        </button>
      </div>}
    </li>
  );
}

/** Comma-separated systemd units checked before and after a fix; saved on blur / Enter. */
function HealthUnits({ a, onPatch }: { a: Asset; onPatch: (p: AssetPatch) => void }) {
  const hint = useId();
  const saved = a.health_units.join(", ");
  const [text, setText] = useState(saved);
  useEffect(() => setText(saved), [saved]);  // re-sync after a save or a rollback
  const commit = () => {
    const units = text.split(",").map((u) => u.trim()).filter(Boolean);
    if (units.join(", ") !== saved) onPatch({ health_units: units });
  };
  return (
    <label className="flex items-center gap-2 text-sm">
      <span className="whitespace-nowrap text-muted">Health units</span>
      <input className={clsx(input, "w-40 md:min-h-9")} value={text} placeholder="nginx, sshd" onChange={(e) => setText(e.target.value)} onBlur={commit}
        onKeyDown={(e) => e.key === "Enter" && commit()} aria-describedby={hint} />
      <span id={hint} className="sr-only">systemd units checked before and after a fix; saved when you leave the field</span>
    </label>
  );
}

/** Creates an agent-less application asset; the one-time upload token lets CI post SBOMs without a login. */
function AddApplication() {
  const admin = useIsAdmin();
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [made, setMade] = useState<{ id: string; name: string; token: string } | null>(null);
  const create = useMutation({
    mutationFn: (n: string) => api<Asset & { upload_token: string }>("/api/assets", { method: "POST", body: { name: n } }),
    onSuccess: (a) => { setMade({ id: a.id, name: a.hostname, token: a.upload_token }); setName(""); void qc.invalidateQueries({ queryKey: ["assets"] }); },
  });
  const close = (o: boolean) => { setOpen(o); if (!o) { setMade(null); create.reset(); } };
  return (
    <Dialog.Root open={open} onOpenChange={close}>
      <Dialog.Trigger className={btnQuiet} {...adminGate(admin)}><AppWindow className="size-4" aria-hidden />Add application</Dialog.Trigger>
      <Dialog.Portal>
        <Dialog.Overlay className="overlay" />
        <Dialog.Content className={dialogBox}>
          <Dialog.Title className="text-lg font-semibold">Add an application</Dialog.Title>
          {made ? (
            <>
              <Dialog.Description className="mt-2 text-sm">
                <strong>{made.name}</strong> was added. Upload its CycloneDX SBOM from the Assets page, or from CI with this token (shown once):
              </Dialog.Description>
              <div className="mt-3">
                <CopyBlock label="Upload command for CI" text={`curl -X POST -H "Authorization: Bearer ${made.token}" \\
  --data-binary @bom.json ${location.origin}/api/assets/${made.id}/sbom`} />
              </div>
              <div className="mt-5 flex justify-end"><Dialog.Close className={btnPrimary}>Done</Dialog.Close></div>
            </>
          ) : (
            <form className="mt-3 flex flex-col gap-3" onSubmit={(e) => { e.preventDefault(); if (name.trim()) create.mutate(name.trim()); }}>
              <Dialog.Description className="text-sm text-muted">Software without an agent: findings come from the CycloneDX SBOM you upload.</Dialog.Description>
              <Field label="Name" error={create.error?.message}>
                <input className={input} value={name} onChange={(e) => setName(e.target.value)} maxLength={255} required autoComplete="off" placeholder="billing-service" />
              </Field>
              <div className="flex justify-end gap-2">
                <Dialog.Close className={btnQuiet}>Cancel</Dialog.Close>
                <button className={btnPrimary} disabled={create.isPending || !name.trim()}>{create.isPending ? "Adding…" : "Add application"}</button>
              </div>
            </form>
          )}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

/** Button -> file picker -> POST of the raw CycloneDX JSON. The result is announced in a live region. */
export function SbomUpload({ a }: { a: Asset }) {
  const qc = useQueryClient();
  const admin = useIsAdmin();
  const file = useRef<HTMLInputElement>(null);
  const up = useMutation({
    mutationFn: async (f: File) => api<SbomResult>(`/api/assets/${a.id}/sbom`, { method: "POST", body: await f.text() }),
    onSuccess: () => refresh(qc, "assets"),
  });
  return (
    <div className="flex flex-col gap-1">
      <button className={btnQuiet} disabled={up.isPending} aria-label={`Upload SBOM for ${a.hostname}`} onClick={() => file.current?.click()} {...adminGate(admin)}>
        <Upload className="size-4" aria-hidden />{up.isPending ? "Uploading…" : "Upload SBOM"}
      </button>
      <input ref={file} type="file" accept=".json,application/json" hidden tabIndex={-1} data-testid={`sbom-file-${a.id}`}
        onChange={(e) => { const f = e.target.files?.[0]; e.target.value = ""; if (f) up.mutate(f); }} />
      <div aria-live="polite" className="max-w-sm text-xs text-muted">
        {up.data && <span role="status">{sbomSummary(up.data)}</span>}
      </div>
      <Alert error={up.error} prefix="SBOM rejected: " />
    </div>
  );
}
