import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Radar, ShieldCheck, Trash2 } from "lucide-react";
import clsx from "clsx";
import { adminGate, api, plural, relativeTime, useIsAdmin, type Asset } from "./lib";
import { btnPrimary, btnQuiet, CopyBlock, input } from "./ui";

interface ScanResult { address: string; open: number; resolved: number; skipped: string[] }

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
      <h2 id="ext-h" className="text-xl font-semibold">External targets</h2>
      <p className="text-sm text-muted">
        Checks exposed risky services (RDP, SMB, Telnet, databases, Docker API…) and TLS (expired, expiring or untrusted certificates, TLS 1.0/1.1).
        TCP connects and TLS handshakes only; nothing is logged into or exploited. We only scan hosts you prove you own.
      </p>
      <form className="flex flex-wrap items-end gap-2" onSubmit={(e) => { e.preventDefault(); if (hostname.trim()) add.mutate(hostname.trim()); }}>
        <label className="flex flex-col gap-1 text-sm font-medium">Hostname to scan
          <input className={clsx(input, "w-72")} value={hostname} onChange={(e) => setHostname(e.target.value)} placeholder="www.example.com" autoComplete="off" maxLength={255} required />
        </label>
        <button className={btnPrimary} disabled={add.isPending || !hostname.trim()} {...adminGate(admin)}><Plus className="size-4" aria-hidden />{add.isPending ? "Adding…" : "Add target"}</button>
      </form>
      {add.error && <p role="alert" className="text-sm text-now-fg">{add.error.message}</p>}
      {targets.length === 0 ? <p className="text-sm text-muted">No external targets yet.</p> : (
        <ul className="flex flex-col divide-y divide-line overflow-hidden rounded-lg border border-line bg-surface">
          {targets.map((t) => <TargetRow key={t.id} t={t} onDelete={() => onDelete(t)} />)}
        </ul>
      )}
    </section>
  );
}

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
    onSuccess: () => Promise.all(["assets", "findings", "summary"].map((k) => qc.invalidateQueries({ queryKey: [k] }))),
  });
  return (
    <li className="flex flex-col gap-3 p-4">
      <div className="flex flex-wrap items-center justify-between gap-x-6 gap-y-2">
        <div className="min-w-0">
          <h3 className="flex items-center gap-2 text-base font-semibold"><span className="truncate">{t.hostname}</span>
            <span className="inline-flex shrink-0 items-center gap-1 rounded border border-line-strong px-1.5 py-px text-[11px] font-semibold tracking-wide text-muted">
              {t.verified && <ShieldCheck className="size-3" aria-hidden />}{t.verified ? "Verified" : "Unverified"}</span></h3>
          <p className="text-sm text-muted">
            {plural(open, "open finding")} · {t.verified && t.last_seen !== t.first_seen ? <>last scanned <time dateTime={t.last_seen + "Z"}>{relativeTime(t.last_seen)}</time></> : "not scanned"}
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
          <p className="text-sm">Add this DNS TXT record to prove you own {t.hostname}, then press Verify.</p>
          <CopyBlock label="TXT record name" text={t.txt_name ?? ""} />
          <CopyBlock label="TXT record value" text={t.txt_value ?? ""} />
          {verify.error && <p role="alert" className="text-sm text-now-fg">{verify.error.message}</p>}
        </div>
      )}
      <div aria-live="polite" className="text-sm">
        {scan.data && <p role="status">{scan.data.open} open, {scan.data.resolved} resolved{scan.data.skipped.length > 0 && <> · Not checked: {scan.data.skipped.join(", ")}</>}</p>}
        {scan.error && <p role="alert" className="text-now-fg">{scan.error.message}</p>}
      </div>
    </li>
  );
}
