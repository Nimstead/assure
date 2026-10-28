import { useState, type ReactNode } from "react";
import { AlertDialog } from "radix-ui";
import { Check, Copy, TriangleAlert } from "lucide-react";
import clsx from "clsx";
import { JOB_STATUS_LABEL, PRIORITY_CLASS, PRIORITY_LABEL, type JobStatus, type Priority } from "./lib";

// 44px tall on phones (touch), 36px from md up.
export const btn = "inline-flex min-h-[44px] md:min-h-9 items-center justify-center gap-2 rounded-md px-3.5 text-sm font-medium transition-colors disabled:opacity-50 aria-disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed aria-disabled:cursor-not-allowed";
export const btnPrimary = clsx(btn, "bg-accent text-accent-ink hover:brightness-110");
export const btnQuiet = clsx(btn, "border border-line-strong bg-surface text-ink hover:bg-sunken");
export const input = "min-h-[44px] md:min-h-10 w-full rounded-md border border-line-strong bg-surface px-3 text-sm text-ink placeholder:text-muted";
/** Filter chips: square, 44px on phones; the selected one gets a full ink border, not only a tint. */
export const chip = (on: boolean) => clsx("inline-flex min-h-[44px] md:min-h-8 cursor-pointer items-center gap-1.5 border px-3 text-sm", on ? "border-ink bg-accent-soft font-medium" : "border-line-strong text-muted hover:text-ink");
export const switchRoot = "relative h-5 w-9 shrink-0 cursor-pointer rounded-full bg-line-strong data-[state=checked]:bg-accent disabled:opacity-50";
export const switchThumb = "block size-4 translate-x-0.5 rounded-full bg-surface transition-transform data-[state=checked]:translate-x-[18px]";
export const dialogBox = "fixed left-1/2 top-[15vh] z-[51] w-[min(30rem,calc(100%-2rem))] -translate-x-1/2 border border-line bg-surface p-5 shadow-2xl";

/** Colour is never the only signal: dot + text label. */
export function PriorityPill({ priority, count }: { priority: Priority; count?: number }) {
  return (
    <span className={clsx("inline-flex items-center gap-1.5 whitespace-nowrap px-2 py-0.5 text-xs font-medium", PRIORITY_CLASS[priority])}>
      <span aria-hidden className="size-1.5 bg-current" />
      {PRIORITY_LABEL[priority]}
      {count !== undefined && <span className="num font-semibold">{count}</span>}
    </span>
  );
}

const STATUS_CLASS: Record<JobStatus, string> = {
  planned: "bg-next-bg text-next-fg", approved: "bg-planned-bg text-planned-fg", dispatched: "bg-planned-bg text-planned-fg", verifying: "bg-planned-bg text-planned-fg",
  succeeded: "bg-accent-soft text-ink", failed: "bg-now-bg text-now-fg", rolled_back: "bg-now-bg text-now-fg", rollback_failed: "bg-now-bg text-now-fg",
  not_fixed: "bg-now-bg text-now-fg", aborted: "bg-now-bg text-now-fg", cancelled: "bg-sunken text-ink",
};
export const StatusPill = ({ status }: { status: JobStatus }) => (
  <span className={clsx("inline-flex items-center gap-1.5 whitespace-nowrap border border-line px-2 py-0.5 text-xs font-medium", STATUS_CLASS[status])}>
    <span aria-hidden className="size-1.5 bg-current" />{JOB_STATUS_LABEL[status]}
  </span>
);

/** Small bordered label. `why` is read to screen readers and shown on hover; say anything that matters visibly too. */
export function Tag({ children, tone = "muted", why, className }: { children: ReactNode; tone?: "muted" | "now" | "ink"; why?: string; className?: string }) {
  return (
    <span title={why} className={clsx("inline-flex shrink-0 items-center gap-1 border px-1.5 py-px text-[11px] font-semibold tracking-wide",
      tone === "now" ? "border-now-fg text-now-fg" : tone === "ink" ? "border-ink text-ink" : "border-line-strong text-muted", className)}>
      {children}{why && <span className="sr-only">: {why}</span>}
    </span>
  );
}

export const KevBadge = () => <Tag tone="now" why="Listed in CISA's Known Exploited Vulnerabilities catalog">KEV</Tag>;

export const Skeleton = ({ className }: { className?: string }) => <div aria-hidden className={clsx("skeleton", className)} />;

/** Skeleton placeholder that tells assistive tech something is loading. */
export function Loading({ className, rows = 1, label = "Loading…" }: { className?: string; rows?: number; label?: string }) {
  return (
    <div aria-busy="true" role="status" className="flex flex-col gap-2">
      <span className="sr-only">{label}</span>
      {Array.from({ length: rows }, (_, i) => <Skeleton key={i} className={className} />)}
    </div>
  );
}

/** Inline error line. Accepts an Error, a message or nothing (renders nothing). */
export function Alert({ error, prefix, className }: { error: Error | string | null | undefined; prefix?: string; className?: string }) {
  if (!error) return null;
  return <p role="alert" className={clsx("bg-now-bg px-3 py-2 text-sm text-now-fg", className)}>{prefix}{typeof error === "string" ? error : error.message}</p>;
}

/** Success confirmation, announced politely. */
export const Done = ({ children, className }: { children: ReactNode; className?: string }) => (
  <p role="status" className={clsx("inline-flex items-center gap-1.5 text-sm text-ink", className)}><Check className="size-4" aria-hidden />{children}</p>
);

export const Field = ({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) => (
  <label className="flex flex-col gap-1.5 text-sm font-medium">
    {label}
    {children}
    {hint && <span className="text-xs font-normal text-muted">{hint}</span>}
  </label>
);

/** The one confirmation pattern for destructive or high-stakes actions. */
export function ConfirmDialog({ open, onOpenChange, title, description, children, confirmLabel, pendingLabel, pending, error, onConfirm }: {
  open: boolean; onOpenChange: (o: boolean) => void; title: string; description: ReactNode; children?: ReactNode;
  confirmLabel: string; pendingLabel?: string; pending?: boolean; error?: Error | string | null; onConfirm: () => void;
}) {
  return (
    <AlertDialog.Root open={open} onOpenChange={onOpenChange}>
      <AlertDialog.Portal>
        <AlertDialog.Overlay className="overlay" />
        <AlertDialog.Content className={dialogBox}>
          <AlertDialog.Title className="text-lg font-semibold">{title}</AlertDialog.Title>
          <AlertDialog.Description className="mt-2 text-sm">{description}</AlertDialog.Description>
          {children}
          <Alert error={error} className="mt-3" />
          <div className="mt-5 flex justify-end gap-2">
            <AlertDialog.Cancel className={btnQuiet}>Cancel</AlertDialog.Cancel>
            <button className={btnPrimary} disabled={pending} onClick={onConfirm}>{pending ? pendingLabel ?? "Working…" : confirmLabel}</button>
          </div>
        </AlertDialog.Content>
      </AlertDialog.Portal>
    </AlertDialog.Root>
  );
}

export function ErrorState({ error, retry }: { error: Error; retry: () => void }) {
  return (
    <div role="alert" className="flex flex-col items-start gap-3 border border-line bg-surface p-5">
      <p className="flex items-center gap-2 font-medium"><TriangleAlert className="size-4 text-now-fg" aria-hidden />Couldn't load this. Check your connection and try again.</p>
      <p className="text-sm text-muted">Details: {error.message}</p>
      <button className={btnQuiet} onClick={retry}>Try again</button>
    </div>
  );
}

export function EmptyState({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-start gap-3 border border-dashed border-line-strong px-5 py-8">
      <h2 className="text-base font-semibold">{title}</h2>
      {children && <p className="max-w-prose text-sm text-muted">{children}</p>}
      {action}
    </div>
  );
}

export function CopyBlock({ label, text }: { label: string; text: string }) {
  const [done, setDone] = useState(false);
  const copy = async () => {
    try { await navigator.clipboard.writeText(text); setDone(true); setTimeout(() => setDone(false), 2000); } catch { /* user can select the text */ }
  };
  return (
    <div>
      <div className="mb-1.5 flex items-center justify-between gap-3">
        <span className="text-sm font-medium">{label}</span>
        <button className={clsx(btnQuiet, "md:min-h-8 !px-2.5")} onClick={copy}>
          {done ? <Check className="size-4" aria-hidden /> : <Copy className="size-4" aria-hidden />}
          {done ? "Copied" : "Copy"}
        </button>
      </div>
      <pre tabIndex={0} className="overflow-x-auto bg-sunken p-3 font-mono text-[13px] leading-relaxed whitespace-pre-wrap break-all select-all"><code>{text}</code></pre>
      <span role="status" className="sr-only">{done ? "Copied to clipboard" : ""}</span>
    </div>
  );
}
