import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Radar, ShieldCheck, Trash2 } from "lucide-react";
import { adminGate, api, parseUtc, plural, refresh, relativeTime, useIsAdmin, type Asset } from "./lib";
import { Alert, btnPrimary, btnQuiet, CopyBlock, Field, HowJudged, input, Loading, Tag } from "./ui";

interface ScanResult { address: string; open: number; resolved: number; still_open: number; skipped: string[] }

/** The engine's network report for a target (api engine/network.build_report); only the fields shown here. */
export interface TargetReport {
  headline: { status: string; text: string };
  vulnerable: { product: string; grade: string; action: string; raise_confidence: string | null; vulnerabilities: { id: string }[] }[];
  undetermined: { reason: string; why: string; what_to_do: string; count: number; examples: string[] }[];
  coverage: { sources: { label: string; state: string; error: string | null }[]; statements: string[] };
}

const STATE = { open: "answered", closed: "refused (nothing listening)", filtered: "no answer: not checked" } as Record<string, string>;

/** What the last scan of a target found, couldn't determine, and saw on each port; nothing here reads as clean that wasn't checked. */
export function TargetReportView({ r }: { r: TargetReport }) {
  return (
    <div className="flex flex-col gap-3">
      <p className="font-medium">{r.headline.text}</p>
      {r.vulnerable.length > 0 && (
        <ul className="flex flex-col gap-2">
          {r.vulnerable.map((g) => (
            <li key={g.product + g.vulnerabilities[0]?.id} className="break-words border-t border-line pt-2">
              <span className="font-medium">{g.product}</span> · {g.vulnerabilities.map((v) => v.id).join(", ")} <Tag tone={g.grade === "unverified" ? "warn" : "muted"} why={g.raise_confidence ?? undefined}>{g.grade}</Tag>
              <div className="text-muted">{g.action}</div>
            </li>
          ))}
        </ul>
      )}
      {r.undetermined.map((u) => (
        <p key={u.reason} className="break-words"><span className="font-medium">Couldn't determine ({u.count}):</span> {u.why}. {u.what_to_do}.</p>
      ))}
      <ul className="flex flex-col text-muted">{r.coverage.statements.map((s) => <li key={s}>{s}</li>)}</ul>
      <table className="w-full text-left">
        <caption className="sr-only">Each port the scan tried</caption>
        <thead><tr><th scope="col" className="font-medium">Port</th><th scope="col" className="font-medium">What it did</th></tr></thead>
        <tbody>{r.coverage.sources.map((src) => <tr key={src.label} className="border-t border-line"><td className="py-1 pr-4">{src.label}</td><td>{src.error && src.state !== "filtered" ? src.error : STATE[src.state] ?? src.state}</td></tr>)}</tbody>
      </table>
    </div>
  );
}

function TargetReportPanel({ id }: { id: string }) {
  const [open, setOpen] = useState(false);
  const q = useQuery({ queryKey: ["target-report", id], enabled: open, queryFn: () => api<TargetReport>(`/api/assets/${id}/scan-report`) });
  return (
    <details className="text-sm" onToggle={(e) => setOpen(e.currentTarget.open)}>
      <summary className="tap cursor-pointer py-2">What the last scan checked</summary>
      {q.isLoading && <Loading />}
      <Alert error={q.error} />
      {q.data && <TargetReportView r={q.data} />}
    </details>
  );
}

/** Internet hosts scanned from outside; only ever after a DNS TXT proof of ownership. */
export function ExternalTargets({ targets, onDelete }: { targets: Asset[]; onDelete: (a: Asset) => void }) {
  const admin = useIsAdmin();
  const qc = useQueryClient();
  const [hostname, setHostname] = useState("");
  const add = useMutation({
    mutationFn: (h: string) => api("/api/targets", { method: "POST", body: { hostname: h } }),
    onSuccess: () => { setHostname(""); void qc.invalidateQueries({ queryKey: ["assets"] }); },
  });
  return (
    <section aria-labelledby="ext-h" className="flex flex-col gap-3">
      <h2 id="ext-h" className="text-lg font-semibold">Internet targets</h2>
      <HowJudged label="More about this" lead="Checks hosts you prove you own for risky open services, weak TLS and files served by mistake.">
        <p>Risky services: RDP, SMB, Telnet, databases, the Docker API and others. TLS: expired, expiring or untrusted certificates, and TLS 1.0/1.1. Files: /.git/config and /.env.</p>
        <p>Only TCP connects, TLS handshakes and read-only requests; nothing is logged into or exploited.</p>
      </HowJudged>
      <form className="flex flex-wrap items-start gap-2" onSubmit={(e) => { e.preventDefault(); if (hostname.trim()) add.mutate(hostname.trim()); }}>
        <Field label="Hostname to scan" error={add.error?.message} className="w-full sm:w-72">
          <input className={input} value={hostname} onChange={(e) => { add.reset(); setHostname(e.target.value); }} placeholder="www.example.com" autoComplete="off" maxLength={255} required />
        </Field>
        <button className={`${btnPrimary} sm:mt-[26px]`} disabled={add.isPending || !hostname.trim()} {...adminGate(admin)}><Plus className="size-4" aria-hidden />{add.isPending ? "Adding…" : "Add target"}</button>
      </form>
      {targets.length === 0 ? <p className="text-sm text-muted">No internet targets yet. Add a hostname you own above; it's scanned once a DNS record proves it's yours.</p> : (
        <ul className="flex flex-col divide-y divide-line overflow-hidden border border-line bg-surface">
          {targets.map((t) => <TargetRow key={t.id} t={t} onDelete={() => onDelete(t)} />)}
        </ul>
      )}
    </section>
  );
}

/** Render external target t with ownership proof, verification, scan, and deletion controls. */
export function TargetRow({ t, onDelete }: { t: Asset; onDelete: () => void }) {
  const admin = useIsAdmin();
  const qc = useQueryClient();
  const open = Object.values(t.open_by_priority).reduce((n, c) => n + (c ?? 0), 0);
  const verify = useMutation({
    mutationFn: () => api(`/api/targets/${t.id}/verify`, { method: "POST" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["assets"] }),
  });
  const scan = useMutation({
    mutationFn: () => api<ScanResult>(`/api/targets/${t.id}/scan`, { method: "POST" }),
    onSuccess: () => { void refresh(qc, "assets"); void qc.invalidateQueries({ queryKey: ["target-report", t.id] }); },
  });
  return (
    <li className="flex flex-col gap-3 p-4">
      <div className="flex flex-wrap items-center justify-between gap-x-6 gap-y-2">
        <div className="min-w-0">
          <h3 className="flex flex-wrap items-center gap-2 text-base font-semibold"><span className="min-w-0 break-all">{t.hostname}</span>
            <Tag tone={t.verified ? "ink" : "muted"}>{t.verified && <ShieldCheck className="size-3" aria-hidden />}{t.verified ? "Verified" : "Unverified"}</Tag></h3>
          <p className="text-sm text-muted">
            {plural(open, "open finding")} · {t.verified && t.last_seen !== t.first_seen ? <>last scanned <time dateTime={parseUtc(t.last_seen).toISOString()}>{relativeTime(t.last_seen)}</time></> : "not scanned"}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {t.verified
            ? <button className={btnPrimary} disabled={scan.isPending} {...adminGate(admin)} onClick={() => scan.mutate()}><Radar className="size-4" aria-hidden />{scan.isPending ? "Scanning…" : "Scan now"}<span className="sr-only"> {t.hostname}</span></button>
            : <button className={btnPrimary} disabled={verify.isPending} {...adminGate(admin)} onClick={() => verify.mutate()}>{verify.isPending ? "Verifying…" : "Verify"}<span className="sr-only"> {t.hostname}</span></button>}
          <button className={btnQuiet} onClick={onDelete} {...adminGate(admin)}><Trash2 className="size-4" aria-hidden />Delete<span className="sr-only"> {t.hostname}</span></button>
        </div>
      </div>
      {!t.verified && (
        <div className="flex flex-col gap-2">
          <p className="text-sm">Add this DNS TXT record to prove you own {t.hostname}, and serve the same value from the server it points at (HTTPS or HTTP), then press Verify. Owning the name alone doesn't prove the server is yours.</p>
          <CopyBlock label="TXT record name" text={t.txt_name ?? ""} />
          <CopyBlock label="TXT record value" text={t.txt_value ?? ""} />
          <CopyBlock label="Serve the value at" text={`${t.hostname}${t.proof_path ?? "/.well-known/nimstead-verify.txt"}`} />
          <Alert error={verify.error} />
        </div>
      )}
      {t.verified && t.last_seen !== t.first_seen && <TargetReportPanel id={t.id} />}
      <div aria-live="polite" className="text-sm">
        {scan.data && <p role="status">{scan.data.open} open, {scan.data.resolved} resolved{scan.data.still_open > 0 && <>, {scan.data.still_open} not seen but not proven fixed</>}{scan.data.skipped.length > 0 && <> · Not checked: {scan.data.skipped.join(", ")}</>}</p>}
        <Alert error={scan.error} />
      </div>
    </li>
  );
}
