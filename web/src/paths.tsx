import { useEffect, useId, useState, type ReactNode } from "react";
import { Link, useNavigate, useRouter, useSearch } from "@tanstack/react-router";
import { queryOptions, useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { api, assetsQ, filtersToSearch, parseFilters, pct, plural, useTitle } from "./lib";
import { btnQuiet, chip, EmptyState, ErrorState, HowJudged, input, Loading } from "./ui";

export interface PathSummary {
  kind: "network" | "foothold"; start: string; grade: string; steps: string[]; break_at: { label: string; fixes: number; refs: string[] };
  reaches?: { root: boolean; users: string[] };
}
export interface FleetHost { hostname: string; judged: boolean; entry?: boolean; internet_facing?: boolean; paths: PathSummary[]; unlikely?: { epss: number | null } }
interface EdgeWay { via: string; how: string; because: string; grade: string; gives?: string; account?: string }
interface Edge { from: string; to: string; grade: string; kind?: "ssh"; ways: EdgeWay[] }
export interface ChokePoint {
  kind: "way-in" | "retire-key" | "untrust-key" | "setting"; action: string; cuts: number; hosts: string[]; ways_removed: number; lower_bound: boolean; ref: string; grade?: string;
  on?: string; account?: string; held_on?: string[]; trusted_by?: number; accounts?: string[];
}

/** A choke point named for a person: a key by the account it signs in as, with its fingerprint apart, and who holds or trusts it. */
export function pointText(p: ChokePoint, name: (id: string) => string): { what: string; id?: string; detail: string } {
  const fp = `${p.ref.slice(0, 19)}…`;
  const few = (ids: string[]) => (ids.length > 3 ? `${ids.slice(0, 3).map(name).join(", ")} and ${ids.length - 3} more` : ids.map(name).join(", "));
  if (p.kind === "retire-key" && p.held_on) {
    return { what: `Retire the key for ${p.accounts?.join(", ") || "its account"}`, id: fp,
             detail: `Held on ${few(p.held_on)} · trusted by ${plural(p.trusted_by ?? 0, "machine")}` };
  }
  if (p.kind === "untrust-key" && p.on) return { what: `Remove the key for ${p.account} from ${name(p.on)}`, id: fp, detail: `From ${p.account}'s authorized_keys there; it stays trusted elsewhere` };
  const [what, detail] = splitAction(p.action);
  return { what, detail };
}
/** One machine in the flow (DECISIONS 173): the link onto it, its route from a way in, what is held there, and the changes that cut it off. */
export interface FlowMachine { as: "root" | string[]; grade: string; route?: string[]; via?: string; account?: string; cut_by?: number[] }
type FlowStart = { reaches: number; through: Record<string, number> } | { covered_by: string };
export interface AttackPathsData {
  hosts: Record<string, FleetHost>; truncated?: boolean; partial?: boolean; edges?: Edge[]; choke_points?: ChokePoint[];
  chains: { start: string; why_start: string; reach: unknown[]; reach_count?: number }[];
  flow?: { machines: Record<string, FlowMachine>; starts: Record<string, FlowStart> };
}

// a whole-fleet read the server limits per hour: the page, the Assets line and every machine drawer share one copy
export const pathsQ = queryOptions({ queryKey: ["attack-paths"], queryFn: () => api<AttackPathsData>("/api/attack-paths"), staleTime: 5 * 60_000 });

const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

/** A link's way across in words: an SSH key by its fingerprint's start, a setting by its check. */
export function viaLabel(via: string) {
  if (via.startsWith("SSH:")) return `the key ${via.slice(4, 23)}…`;
  return via.startsWith("SHA256:") ? `the key ${via.slice(0, 19)}…` : via;
}

/** A link's name in the flow: which account a key signs in as, and the start of its fingerprint; a setting by its check. */
export function linkName(via: string, account?: string): { name: string; id?: string } {
  if (via.startsWith("SSH:")) return { name: account ? `Key for ${account}` : "SSH key", id: `${via.slice(4, 23)}…` };
  return { name: via.startsWith("CFG:") ? `Setting ${via.slice(4)}` : via };
}

/** A choke point's action split into what to do and where: the server writes "Do this: details". */
export function splitAction(a: string): [string, string] {
  const i = a.indexOf(": ");
  return i < 0 ? [a, ""] : [a.slice(0, i), a.slice(i + 2)];
}

/** How sure, as a chip that reads without its colour: confirmed is filled, unverified dashed. */
export function Grade({ g }: { g: string }) {
  return (
    <span className={clsx("inline-flex h-6 items-center whitespace-nowrap border px-2 text-xs",
      g === "confirmed" ? "border-ink bg-ink text-accent-ink" : g === "unverified" ? "border-dashed border-line-strong text-muted" : "border-line-strong text-ink")}>{cap(g)}</span>
  );
}

const MORE = "\u0000more";  // a flow row standing for everything past the first SHOWN
const SHOWN = 7;  // rows a flow column draws before "and N more": eight rows read the same at any fleet size
const BARS = 220;  // px the tallest column's bars take, whatever the fleet's size: the flow fits the first screen with Cut these first
const X = { startsEnd: 240, viaStart: 380, viaEnd: 620, groupStart: 760 };  // flow columns, in thousandths of the width
const STEP = 76;  // px between ways in: two lines of text each
/** Criticality reads in its own order, most critical first; owners read largest first. */
export const CRITICALITY = ["Critical", "High", "Medium", "Low", "Not set"];

interface Node { key: string; n: number; cut: number; y: number; h: number; slot: number }

/** Stack rows top-down, tallest first (or in `order`), past SHOWN folded into one "more" row; each row's bar is its share of the machines. */
function stack(counts: Map<string, { n: number; cut: number }>, scale: number, min: number, order?: string[]): Node[] {
  const at = (k: string) => (order!.includes(k) ? order!.indexOf(k) : order!.length);
  const rows = [...counts].sort(order ? (a, b) => at(a[0]) - at(b[0]) || a[0].localeCompare(b[0]) : (a, b) => b[1].n - a[1].n || a[0].localeCompare(b[0]));
  const shown = rows.length > SHOWN + 1 ? rows.slice(0, SHOWN) : rows;
  const rest = rows.slice(shown.length);
  const all = rest.length ? [...shown, [MORE, rest.reduce((s, [, v]) => ({ n: s.n + v.n, cut: s.cut + v.cut }), { n: 0, cut: 0 })] as const] : shown;
  let y = 0;
  return all.map(([key, v]) => {
    const h = Math.max(v.n * scale, v.n ? 2 : 0), slot = Math.max(min, h);
    const node = { key, n: v.n, cut: v.cut, y, h, slot };
    y += slot + 10;
    return node;
  });
}

const bump = (m: Map<string, { n: number; cut: number }>, k: string, cut: boolean) => {
  const v = m.get(k) ?? { n: 0, cut: 0 };
  m.set(k, { n: v.n + 1, cut: v.cut + (cut ? 1 : 0) });
};

/** The flow's numbers and geometry from the API's per-machine rows (pure, so it can be tested). */
export function layoutFlow(d: AttackPathsData, groupOf: (id: string) => string, cut: number | null, order?: string[]) {
  const flow = d.flow!;
  const reached = Object.entries(flow.machines).filter(([, m]) => m.route);
  const scale = BARS / Math.max(1, reached.length);
  const isCut = (m: FlowMachine) => cut !== null && !!m.cut_by?.includes(cut);
  const viaN = new Map<string, { n: number; cut: number }>(), groupN = new Map<string, { n: number; cut: number }>();
  const account = new Map<string, string>();
  for (const [id, m] of reached) {
    bump(viaN, m.via ?? "", isCut(m));
    bump(groupN, groupOf(id), isCut(m));
    if (m.via && m.account) account.set(m.via, m.account);
  }
  const vias = stack(viaN, scale, 56), groups = stack(groupN, scale, 56, order);
  const vKey = (v: string) => (vias.some((x) => x.key === v) ? v : MORE), gKey = (g: string) => (groups.some((x) => x.key === g) ? g : MORE);
  // links to groups, conserved: each machine is counted once, on the link that let an attacker onto it
  const pairs = new Map<string, { n: number; cut: number }>();
  for (const [id, m] of reached) bump(pairs, `${vKey(m.via ?? "")}\u0001${gKey(groupOf(id))}`, isCut(m));
  const outAt = new Map(vias.map((v) => [v.key, v.y])), inAt = new Map(groups.map((g) => [g.key, g.y]));
  const bands = [...pairs].sort(([a], [b]) => {
    const [va = "", ga = ""] = a.split("\u0001"), [vb = "", gb = ""] = b.split("\u0001");
    return vias.findIndex((v) => v.key === va) - vias.findIndex((v) => v.key === vb) || groups.findIndex((g) => g.key === ga) - groups.findIndex((g) => g.key === gb);
  }).map(([k, v]) => {
    const [via = "", group = ""] = k.split("\u0001");
    const h = v.n * scale, y0 = outAt.get(via)!, y1 = inAt.get(group)!;
    outAt.set(via, y0 + h); inAt.set(group, y1 + h);
    return { via, group, n: v.n, cut: v.cut, y0, y1, h };
  });
  // ways in: each walked start's own reach, in full; one that another reaches is said to be covered by it
  const startRows = Object.entries(flow.starts).sort(([a, x], [b, y]) => ("reaches" in y ? y.reaches : -1) - ("reaches" in x ? x.reaches : -1)
    || (d.hosts[a]?.hostname ?? a).localeCompare(d.hosts[b]?.hostname ?? b));
  const shownStarts = startRows.length > SHOWN + 1 ? startRows.slice(0, SHOWN) : startRows;
  const moreStarts = startRows.length - shownStarts.length;
  const starts = shownStarts.map(([id, s], i) => ({ id, s, y: i * STEP }));
  const lines: { start: string; via: string; n: number; y0: number; y1: number }[] = [];
  const into = new Map<string, number>();
  for (const { s } of starts) if ("through" in s) for (const v of Object.keys(s.through)) into.set(vKey(v), (into.get(vKey(v)) ?? 0) + 1);
  const seen = new Map<string, number>();
  for (const { id, s, y } of starts) {
    if (!("through" in s)) continue;
    const per = new Map<string, number>();
    for (const [v, n] of Object.entries(s.through)) per.set(vKey(v), (per.get(vKey(v)) ?? 0) + n);
    for (const [v, n] of per) {
      const node = vias.find((x) => x.key === v);
      if (!node) continue;
      const k = seen.get(v) ?? 0;
      seen.set(v, k + 1);
      lines.push({ start: id, via: v, n, y0: y + 22, y1: node.y + (node.h || 2) * ((k + 0.5) / (into.get(v) ?? 1)) });
    }
  }
  const height = Math.max(...[vias, groups].map((c) => (c.length ? c.at(-1)!.y + c.at(-1)!.slot : 0)), starts.length * STEP + (moreStarts ? 30 : 0), 60);
  return { reached, vias, groups, bands, starts, moreStarts, lines, height, account, scale };
}

/** The Attack paths page (DECISIONS 173): what to cut first, the fleet's exposure as one flow, and every machine it reaches. */
export function AttackPathsPage() {
  useTitle("Attack paths");
  const q = useQuery(pathsQ);
  const assets = useQuery(assetsQ);
  const sp = useSearch({ strict: false }) as { cut?: string; by?: string; group?: string; q?: string; show?: string };
  const navigate = useNavigate();
  const router = useRouter();
  const [cut, setCut] = useState<number | null>(() => (sp.cut === "none" ? null : Number.isInteger(Number(sp.cut)) && Number(sp.cut) > 0 ? Number(sp.cut) - 1 : 0));
  const owned = (assets.data ?? []).some((a) => a.owner);
  const [by, setBy] = useState<"owner" | "criticality" | null>(() => (sp.by === "owner" || sp.by === "criticality" ? sp.by : null));
  const [group, setGroup] = useState<string | null>(sp.group ?? null);
  const [show, setShow] = useState<"all" | "cut" | "left">("all");
  const grouping = by ?? (owned ? "owner" : "criticality");
  useEffect(() => {
    // the selection lives in the URL too, so Back, refresh and a shared link keep it
    if (router.latestLocation.pathname !== "/attack-paths") return;
    void navigate({ to: "/attack-paths", replace: true, resetScroll: false,
      search: (s: Record<string, unknown>) => ({ ...s, cut: cut === null ? "none" : cut === 0 ? undefined : String(cut + 1), by: by ?? undefined, group: group ?? undefined }) });
  }, [cut, by, group, navigate, router]);

  if (q.isPending) return <Page><Loading className="h-40" rows={5} label="Loading attack paths…" /></Page>;
  if (q.error) return <Page><ErrorState error={q.error} retry={() => q.refetch()} /></Page>;
  const d = q.data;
  const unjudged = Object.values(d.hosts).filter((h) => !h.judged).length;
  const withPaths = Object.values(d.hosts).filter((h) => h.paths.length).length;
  if (!withPaths && !d.chains.length) {
    return <Page><EmptyState title="No attack paths">
      No machine's last report shows a way in or a way up.{unjudged ? ` ${plural(unjudged, "machine")} ${unjudged === 1 ? "hasn't" : "haven't"} been judged yet.` : ""} Linux machines are read for who can get in from agent 0.11.0.
    </EmptyState></Page>;
  }
  const byId = new Map((assets.data ?? []).map((a) => [a.id, a]));
  const groupOf = (id: string) => (grouping === "owner" ? byId.get(id)?.owner || "No owner" : cap(byId.get(id)?.criticality ?? "not set"));
  const points = d.choke_points ?? [];
  const sel = cut !== null && cut < points.length ? cut : null;
  const reached = d.flow ? Object.values(d.flow.machines).filter((m) => m.route).length : null;
  const ways = d.flow ? Object.keys(d.flow.starts).length : d.chains.length;
  const unlikely = Object.values(d.hosts).filter((h) => h.unlikely).length;
  // machines in the table each change cuts off: a change that only closes a way in cuts its start, which the table doesn't list
  const listed = points.map((_, i) => (d.flow ? Object.values(d.flow.machines).filter((m) => m.route && m.cut_by?.includes(i)).length : 0));
  const showCut = (i: number) => {
    setCut(i); setShow("cut"); setGroup(null);
    document.getElementById("reached-h")?.scrollIntoView({ block: "start" });
  };
  return (
    <Page>
      <header className="flex flex-wrap items-baseline justify-between gap-x-8 gap-y-2">
        <h1 className="text-3xl font-semibold">Attack paths</h1>
        <dl className="flex flex-wrap gap-x-6 gap-y-1 text-sm">
          <Fact n={ways} label={ways === 1 ? "way in" : "ways in"} />
          {reached !== null && <Fact n={reached} label={`${reached === 1 ? "machine" : "machines"} reachable from them`} />}
          {unlikely > 0 && <Fact n={unlikely} label="left out as unlikely" muted />}
        </dl>
      </header>
      <HowJudged className="-mt-3" lead={<>The changes that cut the most machines off from every likely way in, and how far each reaches.{d.partial ? " Past the limits not every link was followed, so some may be missing." : ""}</>}>
        <p>A way in is likely when it's a setting, or a flaw that is known to be exploited, has an EPSS (the chance of exploitation in 30 days) of 10% or more, or has no EPSS yet. {unlikely ? `${plural(unlikely, "machine")} ${unlikely === 1 ? "has" : "have"} a way in only through flaws with no sign of exploitation; ${unlikely === 1 ? "it starts" : "they start"} nothing here, and ${unlikely === 1 ? "its path is" : "their paths are"} under Paths on each machine.` : ""}</p>
        <p>Each count says what it counts. A key can be trusted on more machines than are reached through it (some are reached by a shorter route first), and a change cuts off fewer than it touches when a machine has another route.</p>
        <p>A path is only as sure as its weakest step. An SSH key link is confirmed only when the key matches exactly, needs no passphrase, the other machine's sshd lets that account in, and a connection between them was seen. Windows links across hosts are no better than reasonable unless the sign-in and a connection were both seen.</p>
        <p>Each machine's part rests on what its own agent reported, so a compromised machine could make its own links look worse or better. Keys are compared by fingerprint: no key leaves a machine, and nothing here signs in anywhere.{unjudged ? ` ${plural(unjudged, "machine")} ${unjudged === 1 ? "hasn't" : "haven't"} been judged yet.` : ""}</p>
      </HowJudged>
      <CutFirst points={points} sel={sel} onSelect={(i) => setCut(i === sel ? null : i)} name={(id) => d.hosts[id]?.hostname ?? id} listed={listed} onShow={showCut} />
      {d.flow && reached !== null && (ways > 0 || reached > 0) && (
        <Flow d={d} groupOf={groupOf} sel={sel} point={sel === null ? undefined : points[sel]} grouping={grouping} canOwner={owned}
          onGrouping={(g) => { setBy(g); setGroup(null); }} group={group} onGroup={(g) => setGroup(g === group ? null : g)} />
      )}
      {d.flow && reached ? <Reached d={d} groupOf={groupOf} group={group} clearGroup={() => setGroup(null)} sel={sel} initialQ={sp.q ?? ""} show={show} setShow={setShow} /> : null}
      <Depth d={d} />
    </Page>
  );
}

const Page = ({ children }: { children: ReactNode }) => <div className="flex flex-col gap-6">{children}</div>;

function Fact({ n, label, muted }: { n: number; label: string; muted?: boolean }) {
  return (
    <div className="flex items-baseline gap-1.5"><dt className={clsx("order-2", muted ? "text-muted" : "text-ink")}>{label}</dt>
      <dd className="num order-1 text-xl font-semibold text-ink">{n.toLocaleString("en")}</dd></div>
  );
}

/** Cut these first: the single changes that cut the most machines off, largest first (DECISIONS 169); choosing one re-weights the flow. */
function CutFirst({ points, sel, onSelect, name, listed, onShow }: {
  points: ChokePoint[]; sel: number | null; onSelect: (i: number) => void; name: (id: string) => string; listed: number[]; onShow: (i: number) => void;
}) {
  const [all, setAll] = useState(false);
  const top = Math.max(1, ...points.map((p) => p.cuts));
  return (
    <section aria-labelledby="cut-first" className="flex flex-col gap-2">
      <h2 id="cut-first" className="text-base font-semibold">Cut these first</h2>
      {!points.length ? <p className="text-sm text-muted">No single change cuts a machine off: every machine reachable has more than one route.</p> : (
        <ol className="border border-line bg-surface">
          {(all ? points : points.slice(0, 5)).map((p, i) => {
            const { what, id, detail } = pointText(p, name);
            return (
              <li key={`${p.kind}|${p.ref}|${p.action}`} className={clsx("grid grid-cols-[1.5rem_1fr] items-start gap-x-3 gap-y-2 border-t border-line p-3 first:border-t-0 md:grid-cols-[1.5rem_1fr_14rem_7rem] md:items-center",
                i === sel && "bg-sunken outline-2 -outline-offset-2 outline-ink")}>
                <span className="num pt-0.5 text-sm font-semibold text-muted md:pt-0">{i + 1}</span>
                <div className="min-w-0">
                  <button type="button" aria-pressed={i === sel} onClick={() => onSelect(i)} className="block w-full cursor-pointer text-left">
                    <span className="block break-words"><span className="font-semibold">{what}</span>{id && <span className="ml-2 font-mono text-xs">{id}</span>}</span>
                    {detail && <span className="mt-0.5 line-clamp-2 block break-words text-sm text-muted">{detail}</span>}
                  </button>
                  {/* the links keep their 44px phone targets: the spare height below overlaps the row's gap, never the text above */}
                  <span className="-mb-3 flex flex-wrap items-center gap-x-4 md:mb-0">
                    {(listed[i] ?? 0) > 0 && <button type="button" className="tap inline-flex cursor-pointer items-center text-sm underline" onClick={() => onShow(i)}>Show the {plural(listed[i]!, "machine")}</button>}
                    {p.kind === "way-in" && <Link to="/findings" search={filtersToSearch({ ...parseFilters({}), asset: p.ref, fixable: false })} className="tap inline-flex items-center text-sm underline">Findings on {name(p.ref)}</Link>}
                  </span>
                </div>
                <span className="col-start-2 flex items-center gap-2 text-sm md:col-start-auto">
                  <span aria-hidden className="h-2 shrink-0 bg-ink" style={{ width: `${Math.max(0.25, (p.cuts / top) * 5)}rem` }} />
                  <span className="whitespace-nowrap"><span className="num font-semibold">{p.lower_bound ? "at least " : ""}{p.cuts.toLocaleString("en")}</span> {p.cuts === 1 ? "machine" : "machines"} cut off</span>
                </span>
                <span className="col-start-2 md:col-start-auto">{p.grade && <Grade g={p.grade} />}</span>
              </li>
            );
          })}
        </ol>
      )}
      {points.length > 5 && <button type="button" className="tap w-fit cursor-pointer text-sm underline" onClick={() => setAll(!all)}>{all ? "Show the first 5" : `Show all ${points.length}`}</button>}
    </section>
  );
}

/** The fleet's exposure as one flow: ways in, the links machines are reached through, and the machines by group (DECISIONS 173). */
function Flow({ d, groupOf, sel, point, grouping, canOwner, onGrouping, group, onGroup }: {
  d: AttackPathsData; groupOf: (id: string) => string; sel: number | null; point?: ChokePoint; grouping: "owner" | "criticality"; canOwner: boolean;
  onGrouping: (g: "owner" | "criticality") => void; group: string | null; onGroup: (g: string) => void;
}) {
  const hatch = useId();
  const L = layoutFlow(d, groupOf, sel, grouping === "criticality" ? CRITICALITY : undefined);
  const most = Math.max(1, ...L.groups.map((g) => g.n));
  const name = (id: string) => d.hosts[id]?.hostname ?? id;
  const viaHit = (v: string) => !!point && (point.kind === "setting" ? v === point.ref : (point.kind === "retire-key" || point.kind === "untrust-key") && v === `SSH:${point.ref}`);
  const startHit = (id: string) => point?.kind === "way-in" && point.ref === id;
  const viaText = (v: string) => (v === MORE ? { name: `${L.vias.find((x) => x.key === MORE)!.n.toLocaleString("en")} through other links` } : v ? linkName(v, L.account.get(v)) : { name: "Another link" });
  const top = (n: { y: number }) => ({ top: `${n.y}px` });
  return (
    <section aria-labelledby="flow-h" className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 id="flow-h" className="text-base font-semibold">{point ? `What change ${sel! + 1} cuts off` : "How far the ways in reach"}</h2>
        <div className="flex flex-wrap items-center gap-x-5 gap-y-2 text-sm">
          {sel !== null && <span className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted">
            <span className="flex items-center gap-1.5"><span aria-hidden className="inline-block h-2.5 w-4 bg-ink" />Cut off by change {sel + 1}</span>
            <span className="flex items-center gap-1.5"><span aria-hidden className="inline-block h-2.5 w-4 border border-line-strong bg-[repeating-linear-gradient(135deg,var(--line-strong)_0_2px,var(--surface)_2px_5px)]" />Still reachable</span>
          </span>}
          {canOwner ? <div role="group" aria-label="Group machines by" className="flex items-center gap-2">
            <span className="text-muted">Group by</span>
            <button type="button" className={chip(grouping === "owner")} aria-pressed={grouping === "owner"} onClick={() => onGrouping("owner")}>Owner</button>
            <button type="button" className={chip(grouping === "criticality")} aria-pressed={grouping === "criticality"} onClick={() => onGrouping("criticality")}>Criticality</button>
          </div> : <span className="text-muted">Grouped by criticality: no machine has an owner yet</span>}
        </div>
      </div>
      <div className="border border-line bg-surface p-4">
        <div className="mb-2 hidden text-xs font-medium uppercase tracking-wide text-muted sm:grid sm:grid-cols-[24%_14%_24%_14%_24%]">
          <span>Ways in</span><span /><span>Through</span><span /><span>Machines reached, by {grouping}</span>
        </div>
        <div className="relative flex flex-col gap-6 sm:block">
          <div className="hidden sm:block" style={{ height: L.height }} />
          <svg aria-hidden className="absolute inset-x-0 top-0 hidden sm:block" width="100%" height={L.height} viewBox={`0 0 1000 ${L.height}`} preserveAspectRatio="none">
            <defs><pattern id={hatch} width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
              <rect width="6" height="6" fill="var(--surface)" /><rect width="2" height="6" fill="var(--line-strong)" /></pattern></defs>
            {L.lines.map((l) => (
              <path key={`${l.start}>${l.via}`} className="flow-band" fill="none" stroke={startHit(l.start) || viaHit(l.via) ? "var(--ink)" : "var(--line-strong)"}
                strokeWidth={Math.min(10, Math.max(1.5, l.n * L.scale * 0.5))} d={`M${X.startsEnd},${l.y0} C${(X.startsEnd + X.viaStart) / 2},${l.y0} ${(X.startsEnd + X.viaStart) / 2},${l.y1} ${X.viaStart},${l.y1}`} />
            ))}
            {L.bands.map((b) => {
              const m = (X.viaEnd + X.groupStart) / 2, c = b.cut * L.scale;
              const area = (a0: number, a1: number, b0: number, b1: number) => `M${X.viaEnd},${a0} C${m},${a0} ${m},${b0} ${X.groupStart},${b0} L${X.groupStart},${b1} C${m},${b1} ${m},${a1} ${X.viaEnd},${a1} Z`;
              return (
                // both parts always drawn, at no height when empty, so every band moves together when the change does
                <g key={`${b.via}>${b.group}`} opacity={group && b.group !== group ? 0.35 : 1}>
                  <path className="flow-band" fill="var(--ink)" fillOpacity={0.88} stroke="var(--surface)" strokeWidth={c > 0 ? 1 : 0} vectorEffect="non-scaling-stroke" d={area(b.y0, b.y0 + c, b.y1, b.y1 + c)} />
                  {/* a pattern fill can't fade, so the plain and hatched still-reachable parts cross-fade by opacity.
                      shortcut: Safari doesn't transition `d`, so there the bands jump to their new widths; upgrade with a JS tween if it matters */}
                  <path className="flow-band" fill="var(--line-strong)" opacity={sel === null ? 1 : 0} stroke="var(--surface)" strokeWidth={b.h - c > 0 ? 1 : 0} vectorEffect="non-scaling-stroke" d={area(b.y0 + c, b.y0 + b.h, b.y1 + c, b.y1 + b.h)} />
                  <path className="flow-band" fill={`url(#${hatch})`} opacity={sel === null ? 0 : 1} stroke="var(--surface)" strokeWidth={b.h - c > 0 ? 1 : 0} vectorEffect="non-scaling-stroke" d={area(b.y0 + c, b.y0 + b.h, b.y1 + c, b.y1 + b.h)} />
                </g>
              );
            })}
            {/* a link is its two bars, in and out, as tall as the machines reached through it; its name sits at the top */}
            {L.vias.map((v) => <g key={v.key}><rect x={X.viaStart} y={v.y} width="4" height={v.h} fill="var(--line-strong)" />
              <rect x={X.viaEnd - 5} y={v.y} width="5" height={v.h} fill={viaHit(v.key) ? "var(--ink)" : "var(--line-strong)"} /></g>)}
            {L.groups.map((g) => <g key={g.key}><rect x={X.groupStart} y={g.y} width="5" height={g.cut * L.scale} fill="var(--ink)" />
              <rect x={X.groupStart} y={g.y + g.cut * L.scale} width="5" height={g.h - g.cut * L.scale} fill={sel === null ? "var(--ink)" : "var(--line-strong)"} /></g>)}
          </svg>
          <ul aria-label="Ways in" className="flex flex-col gap-2 sm:absolute sm:inset-y-0 sm:left-0 sm:w-[24%] sm:gap-0">
            <li className="text-xs font-medium uppercase tracking-wide text-muted sm:hidden">Ways in</li>
            {L.starts.map(({ id, s, y }) => (
              <li key={id} style={top({ y })} className={clsx("border bg-surface px-2.5 py-1.5 text-sm sm:absolute sm:inset-x-0 sm:mr-1", startHit(id) ? "border-2 border-ink" : "border-line-strong")}>
                <span className="block truncate font-semibold" title={name(id)}>{name(id)}</span>
                <span className="line-clamp-2 block text-muted">{d.hosts[id]?.entry ? "From the network" : d.hosts[id]?.internet_facing ? "Internet-facing, with a way up" : "A way in"} · {"reaches" in s ? (s.reaches ? `reaches ${plural(s.reaches, "machine")}` : "reaches no other") : `reaches what ${name(s.covered_by)} does`}</span>
              </li>
            ))}
            {L.moreStarts > 0 && <li style={top({ y: L.starts.length * STEP })} className="text-sm text-muted sm:absolute">and {plural(L.moreStarts, "more way in", "more ways in")}</li>}
          </ul>
          <ul aria-label="Through" className="flex flex-col gap-2 sm:absolute sm:inset-y-0 sm:left-[38%] sm:w-[24%] sm:gap-0">
            <li className="text-xs font-medium uppercase tracking-wide text-muted sm:hidden">Through</li>
            {L.vias.map((v) => {
              const t = viaText(v.key);
              return (
                <li key={v.key} style={top(v)} className={clsx("border bg-surface py-1.5 pl-2.5 pr-3 text-sm sm:absolute sm:inset-x-[0.6rem]", viaHit(v.key) ? "border-2 border-ink" : "border-line-strong")}>
                  <span className="block truncate"><span className="font-semibold">{t.name}</span>{t.id && <span className="ml-1.5 font-mono text-xs">{t.id}</span>}</span>
                  <span className="line-clamp-2 block text-muted">{plural(v.n, "machine")} reached through it{sel !== null && v.cut ? ` · ${v.cut.toLocaleString("en")} cut off` : ""}</span>
                </li>
              );
            })}
          </ul>
          <ul aria-label={`Machines reached, by ${grouping}`} className="flex flex-col gap-2 sm:absolute sm:inset-y-0 sm:left-[76%] sm:w-[24%] sm:gap-0">
            <li className="text-xs font-medium uppercase tracking-wide text-muted sm:hidden">Machines reached, by {grouping}</li>
            {L.groups.map((g) => (
              <li key={g.key} style={top(g)} className="sm:absolute sm:inset-x-0">
                {g.key === MORE ? <span className="block pl-3 text-sm text-muted">{plural(g.n, "machine")} in other groups{sel !== null && g.cut ? ` · ${g.cut.toLocaleString("en")} cut off` : ""}</span> : (
                  <button type="button" aria-pressed={group === g.key} onClick={() => onGroup(g.key)}
                    className={clsx("tap flex w-full cursor-pointer flex-col items-start pl-3 text-left text-sm hover:underline", group === g.key && "font-semibold underline")}>
                    <span className="flex w-full items-baseline justify-between gap-2"><span className="truncate">{g.key}</span><span className="num">{g.n.toLocaleString("en")}</span></span>
                    {/* the group's share cut off at a glance: solid what the change cuts, hatched what stays reachable */}
                    <span aria-hidden className="mt-1 flex h-1.5" style={{ width: `${(g.n / most) * 100}%` }}>
                      <span className="bg-ink" style={{ width: `${sel === null ? 100 : (g.cut / g.n) * 100}%` }} />
                      {sel !== null && <span className="flex-1 bg-[repeating-linear-gradient(135deg,var(--line-strong)_0_2px,var(--surface)_2px_5px)]" />}
                    </span>
                    {sel !== null && <span className="mt-0.5 text-muted">{g.cut ? `${g.cut.toLocaleString("en")} cut off` : "none cut off"}</span>}
                  </button>
                )}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  );
}

const PAGE = 25;

/** Every machine reached, one row each: the route there, the link onto it, what is held, how sure, and the changes that cut it off. */
function Reached({ d, groupOf, group, clearGroup, sel, initialQ, show, setShow }: {
  d: AttackPathsData; groupOf: (id: string) => string; group: string | null; clearGroup: () => void; sel: number | null; initialQ: string;
  show: "all" | "cut" | "left"; setShow: (s: "all" | "cut" | "left") => void;
}) {
  const [text, setText] = useState(initialQ);
  const [shown, setShown] = useState(PAGE);
  const name = (id: string) => d.hosts[id]?.hostname ?? id;
  const all = Object.entries(d.flow!.machines).filter(([, m]) => m.route)
    .sort(([a, x], [b, y]) => x.route!.length - y.route!.length || name(a).localeCompare(name(b)));
  const t = text.trim().toLowerCase();
  const rows = all.filter(([id, m]) => (!group || groupOf(id) === group) && (!t || name(id).toLowerCase().includes(t))
    && (show === "all" || sel === null || (show === "cut") === !!m.cut_by?.includes(sel)));
  const cutN = sel === null ? 0 : all.filter(([id, m]) => (!group || groupOf(id) === group) && m.cut_by?.includes(sel)).length;
  return (
    <section aria-labelledby="reached-h" className="flex flex-col gap-3">
      <h2 id="reached-h" className="text-base font-semibold">Machines reached{group ? ` in ${group}` : ""} <span className="num font-normal text-muted">{rows.length.toLocaleString("en")}</span></h2>
      <div className="flex flex-wrap items-center gap-2">
        <input className={clsx(input, "md:w-72")} placeholder="Search machines" aria-label="Search machines" value={text} onChange={(e) => { setText(e.target.value); setShown(PAGE); }} />
        {group && <button type="button" className={btnQuiet} onClick={clearGroup}>All groups</button>}
        {sel !== null && <div role="group" aria-label="Show" className="flex flex-wrap gap-2">
          <button type="button" className={chip(show === "all")} aria-pressed={show === "all"} onClick={() => setShow("all")}>All</button>
          <button type="button" className={chip(show === "cut")} aria-pressed={show === "cut"} onClick={() => setShow("cut")}>Cut off by change {sel + 1} <span className="num text-muted">{cutN}</span></button>
          <button type="button" className={chip(show === "left")} aria-pressed={show === "left"} onClick={() => setShow("left")}>Still reachable</button>
        </div>}
      </div>
      {!rows.length ? <p className="text-sm text-muted">No machine matches.</p> : (
        // on phones each row is a card, labelled, so the grade and what cuts it off stay on screen (DESIGN.md: tables stack)
        <div className="border border-line bg-surface md:overflow-x-auto">
          <table className="w-full text-sm max-md:block md:min-w-[46rem]">
            <thead className="max-md:sr-only"><tr className="border-b border-line text-left text-xs text-muted">
              <th className="px-3 py-2 font-medium">Machine</th><th className="px-3 py-2 font-medium">Route from a way in</th><th className="px-3 py-2 font-medium">Onto it through</th>
              <th className="px-3 py-2 font-medium">Holds</th><th className="px-3 py-2 font-medium">How sure</th><th className="px-3 py-2 font-medium">Cut off by</th>
            </tr></thead>
            <tbody className="max-md:block">
              {rows.slice(0, shown).map(([id, m]) => {
                const l = m.via ? linkName(m.via, m.account) : null;
                return (
                  <tr key={id} className="border-t border-line first:border-t-0 max-md:block max-md:py-2">
                    <td className="px-3 py-2 max-md:block max-md:py-0.5"><Link to="/assets" search={{ machine: id }} className="inline-flex tap items-center break-all font-medium underline">{name(id)}</Link><div className="text-xs text-muted">{groupOf(id)}</div></td>
                    <td className="px-3 py-2 max-md:block max-md:py-0.5 max-md:break-words"><Cell>Route</Cell>{m.route!.map(name).join(" → ")}</td>
                    <td className="px-3 py-2 max-md:block max-md:py-0.5"><Cell>Onto it through</Cell>{l ? <>{l.name}{l.id && <span className="ml-1.5 font-mono text-xs">{l.id}</span>}</> : "—"}</td>
                    <td className="px-3 py-2 max-md:block max-md:py-0.5"><Cell>Holds</Cell>{m.as === "root" ? "root" : m.as.join(", ")}</td>
                    <td className="px-3 py-2 max-md:inline-block max-md:py-1"><Grade g={m.grade} /></td>
                    <td className="num px-3 py-2 max-md:inline-block max-md:py-1">{m.cut_by?.length ? m.cut_by.map((i) => `change ${i + 1}`).join(", ") : <span className="text-muted">no single change</span>}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {rows.length > shown && <button type="button" className={clsx(btnQuiet, "w-fit")} onClick={() => setShown(shown + PAGE)}>Show {Math.min(PAGE, rows.length - shown)} more of {rows.length.toLocaleString("en")}</button>}
    </section>
  );
}

/** A cell's column name, shown on phones where the table has no header row. */
const Cell = ({ children }: { children: string }) => <span className="mr-1.5 text-xs text-muted md:hidden">{children}</span>;

/** For analysts: every SSH key link and each machine's own path, as the agent's report reads them. */
function Depth({ d }: { d: AttackPathsData }) {
  const name = (id: string) => d.hosts[id]?.hostname ?? id;
  const keys = (d.edges ?? []).filter((e) => e.kind === "ssh");
  const others = (d.edges ?? []).filter((e) => e.kind !== "ssh");
  const withPaths = Object.entries(d.hosts).filter(([, h]) => h.paths.length);
  return (
    <section aria-labelledby="depth-h" className="flex flex-col gap-1 border-t border-line pt-4">
      <h2 id="depth-h" className="text-base font-semibold">The evidence behind each link</h2>
      {d.truncated && <p className="max-w-prose text-sm text-muted">Only the first links are listed; everything above uses all of them.</p>}
      {keys.length > 0 && <EdgeList title="SSH key links" edges={keys} name={name} />}
      {others.length > 0 && <EdgeList title="Windows sign-in links" edges={others} name={name} />}
      <details className="text-sm">
        <summary className="tap cursor-pointer py-2">Paths on each machine ({withPaths.length.toLocaleString("en")})</summary>
        <ul className="mt-2 flex flex-col gap-2">
          {withPaths.map(([id, h]) => <HostPaths key={id} h={h} />)}
        </ul>
      </details>
    </section>
  );
}

function EdgeList({ title, edges, name }: { title: string; edges: Edge[]; name: (id: string) => string }) {
  const [shown, setShown] = useState(100);
  return (
    <details className="text-sm">
      <summary className="tap cursor-pointer py-2">{title} ({edges.length.toLocaleString("en")})</summary>
      <ul className="mt-2 flex flex-col gap-2">
        {edges.slice(0, shown).map((e) => (
          <li key={`${e.from}>${e.to}`} className="break-words border-t border-line pt-2">
            <span className="font-medium">{name(e.from)} → {name(e.to)}</span> · how sure: {e.grade}
            {e.ways.slice(0, 3).map((w, i) => (
              <div key={`${i}:${w.via}:${w.account ?? ""}`} className="text-muted">{w.how.replace(" on A ", ` on ${name(e.from)} `).replace(/ on B$/, ` on ${name(e.to)}`)}{w.gives ? `, which gives ${w.gives}` : ""}: {w.because} ({w.grade})</div>
            ))}
          </li>
        ))}
      </ul>
      {edges.length > shown && <button type="button" className={clsx(btnQuiet, "mt-2")} onClick={() => setShown(shown + 100)}>Show 100 more of {edges.length.toLocaleString("en")}</button>}
    </details>
  );
}

/** One machine's own paths, from its last report: where it starts, the steps, how sure, and the fewest fixes that break it. */
function HostPaths({ h }: { h: FleetHost }) {
  return <>{h.paths.map((p) => (
    <li key={p.kind} className="break-words border-t border-line pt-2">
      <span className="font-medium">{h.hostname}</span>, {p.start} · how sure: {p.grade}{p.reaches ? ` · reaches ${p.reaches.root ? "root" : p.reaches.users.join(", ")}` : ""}{p.kind === "network" && h.unlikely ? ` · unlikely: EPSS ${pct(h.unlikely.epss ?? 0)}, not known to be exploited` : ""}
      <div className="text-muted">{p.steps.join(" → ")}. Break it: fix {plural(p.break_at.fixes, "way")} of {p.break_at.label.toLowerCase()} ({p.break_at.refs.map(viaLabel).join(", ")})</div>
    </li>
  ))}</>;
}

/** Assets' one line about attack paths: how far the ways in reach and the top change, linking to the page. */
export function AttackPathsSummary() {
  const q = useQuery(pathsQ);
  const d = q.data;
  if (!d?.flow || (!d.chains.length && !Object.values(d.hosts).some((h) => h.paths.length))) return null;
  const ways = Object.keys(d.flow.starts).length, reached = Object.values(d.flow.machines).filter((m) => m.route).length;
  const top = d.choke_points?.[0];
  return (
    <p className="text-sm">
      <Link to="/attack-paths" className="tap font-medium underline">{ways ? `${plural(ways, "way in", "ways in")} reach ${plural(reached, "machine")}` : "Attack paths on each machine"}</Link>
      {top && <span className="text-muted"> · {splitAction(top.action)[0]} cuts {plural(top.cuts, "machine")} off</span>}
    </p>
  );
}

/** A machine's own attack paths in its drawer, and how it's reached, linking to it on the Attack paths page. */
export function MachinePaths({ id }: { id: string }) {
  const q = useQuery(pathsQ);
  const d = q.data;
  const h = d?.hosts[id];
  const m = d?.flow?.machines[id];
  if (!d || !h || (!h.paths.length && !m)) return null;
  const name = (x: string) => d.hosts[x]?.hostname ?? x;
  const l = m?.via ? linkName(m.via, m.account) : null;
  return (
    <div className="mt-3 text-sm">
      <p className="font-medium">Attack paths</p>
      {m && <p className="mt-1">{m.route ? <>Reachable as {m.as === "root" ? "root" : m.as.join(", ")}: {m.route.map(name).join(" → ")}{l ? `, through ${l.name.charAt(0).toLowerCase() + l.name.slice(1)}${l.id ? ` ${l.id}` : ""}` : ""}</> : "A way in: chains start here"} · how sure: {m.grade}
        {m.cut_by?.length ? ` · cut off by change ${m.cut_by.map((i) => i + 1).join(" or ")}` : ""}</p>}
      {h.paths.length > 0 && <ul className="mt-1 flex flex-col gap-1">{h.paths.map((p) => (
        <li key={p.kind} className="break-words text-muted">{cap(p.start)}: {p.steps.join(" → ")} · how sure: {p.grade}{p.kind === "network" && h.unlikely ? ` · unlikely (EPSS ${pct(h.unlikely.epss ?? 0)})` : ""}</li>
      ))}</ul>}
      <Link to="/attack-paths" search={{ q: h.hostname }} className="tap mt-1 inline-flex underline">See it on Attack paths</Link>
    </div>
  );
}

