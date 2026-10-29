import { cloneElement, isValidElement, useEffect, useId, useRef, useState, type ReactElement, type ReactNode, type RefObject } from "react";
import { AlertDialog } from "radix-ui";
import { Check, Copy, TriangleAlert } from "lucide-react";
import clsx from "clsx";
import { announce, ApiError, JOB_STATUS_LABEL, PRIORITY_CLASS, PRIORITY_LABEL, type JobStatus, type Priority } from "./lib";

// 44px tall on phones (touch), 36px from md up.
export const btn = "inline-flex min-h-[44px] md:min-h-9 items-center justify-center gap-2 px-3.5 text-sm font-medium transition-colors disabled:opacity-50 aria-disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed aria-disabled:cursor-not-allowed";
export const btnPrimary = clsx(btn, "bg-accent text-accent-ink hover:brightness-110");
export const btnQuiet = clsx(btn, "border border-line-strong bg-surface text-ink hover:bg-sunken");
/** For confirming something that can't be undone: the "fix now" colour, never used for an ordinary primary action. */
export const btnDanger = clsx(btn, "bg-now-fg text-surface hover:brightness-110");
export const input = "min-h-[44px] md:min-h-10 w-full border border-line-strong bg-surface px-3 text-sm text-ink placeholder:text-muted";
/** Filter chips: square, 44px on phones; the selected one gets a full ink border, not only a tint. */
export const chip = (on: boolean) => clsx("inline-flex min-h-[44px] md:min-h-8 cursor-pointer items-center gap-1.5 border px-3 text-sm", on ? "border-ink bg-accent-soft font-medium" : "border-line-strong text-muted hover:text-ink");
export const switchRoot = "relative h-5 w-9 shrink-0 cursor-pointer rounded-full bg-line-strong data-[state=checked]:bg-accent disabled:opacity-50";
export const switchThumb = "block size-4 translate-x-0.5 rounded-full bg-surface transition-transform data-[state=checked]:translate-x-[18px]";
export const dialogBox = "fixed left-1/2 top-[15vh] z-[51] w-[min(30rem,calc(100%-2rem))] -translate-x-1/2 border border-line bg-surface p-5 shadow-2xl";

/**
 * Radix returns focus only to a Dialog.Trigger; ours open from state, so this hands focus back to whatever opened the
 * dialog (DECISIONS 48). Pass `initial` to start focus somewhere other than the first focusable element.
 */
export function useReturnFocus(initial?: RefObject<HTMLElement | null>) {
  const opener = useRef<HTMLElement | null>(null);
  return {
    onOpenAutoFocus: (e: Event) => {
      opener.current = document.activeElement instanceof HTMLElement && document.activeElement !== document.body ? document.activeElement : null;
      if (initial?.current) { e.preventDefault(); initial.current.focus(); }
    },
    onCloseAutoFocus: (e: Event) => {
      if (opener.current?.isConnected) { e.preventDefault(); opener.current.focus(); }
    },
  };
}

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
  // outlined only, so a deliberate cancel never looks like a success
  not_fixed: "bg-now-bg text-now-fg", aborted: "bg-now-bg text-now-fg", cancelled: "border-dashed !border-line-strong bg-transparent text-muted",
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

const Skeleton = ({ className }: { className?: string }) => <div aria-hidden className={clsx("skeleton", className)} />;

/** Skeleton placeholder with a label for assistive tech. */
export function Loading({ className, rows = 1, label = "Loading…" }: { className?: string; rows?: number; label?: string }) {
  return (
    <div role="status" className="flex flex-col gap-2">
      {label && <span className="sr-only">{label}</span>}
      {Array.from({ length: rows }, (_, i) => <Skeleton key={i} className={className} />)}
    </div>
  );
}

/** Inline error line. Accepts an Error, a message or nothing (renders nothing). role="alert" is announced as it appears. */
export function Alert({ error, prefix, className, id }: { error: Error | string | null | undefined; prefix?: string; className?: string; id?: string }) {
  if (!error) return null;
  return <p id={id} role="alert" className={clsx("bg-now-bg px-3 py-2 text-sm text-now-fg", className)}>{prefix}{typeof error === "string" ? error : error.message}</p>;
}

/** Success confirmation. A node that appears already holding text is often not read, so it's announced through the shell's live region (DECISIONS 49). */
export function Done({ children, className }: { children: string; className?: string }) {
  useEffect(() => announce(children), [children]);
  return <p className={clsx("inline-flex items-center gap-1.5 text-sm text-ink", className)}><Check className="size-4" aria-hidden />{children}</p>;
}

/** A bordered note that appears after something happened ("Check your email…"), announced like Done. */
export function Notice({ children, className }: { children: string; className?: string }) {
  useEffect(() => announce(children), [children]);
  return <p className={clsx("border border-line-strong bg-surface px-3 py-2 text-sm", className)}>{children}</p>;
}

/** The two live regions Done, Notice and page changes speak through; the shell has them, signed-out pages render their own. */
export const LiveRegions = () => (
  <>
    <div id="live" role="status" aria-live="polite" className="sr-only" />
    <div id="live-alert" role="alert" aria-live="assertive" className="sr-only" />
  </>
);

/** Label + control + hint + error. The control (a single element child) is given aria-invalid and aria-describedby. */
export function Field({ label, hint, error, children, className }: { label: string; hint?: string; error?: string | null; children: ReactNode; className?: string }) {
  const id = useId();
  const described = [hint && `${id}-hint`, error && `${id}-error`].filter(Boolean).join(" ") || undefined;
  const control = isValidElement(children)
    ? cloneElement(children as ReactElement<Record<string, unknown>>, { "aria-invalid": error ? true : undefined, "aria-describedby": described })
    : children;
  return (
    <div className={clsx("flex flex-col gap-1.5", className)}>
      <label className="flex flex-col gap-1.5 text-sm font-medium">
        {label}
        {control}
      </label>
      {hint && <span id={`${id}-hint`} className="text-xs text-muted">{hint}</span>}
      {error && <span id={`${id}-error`} role="alert" className="text-sm text-now-fg">{error}</span>}
    </div>
  );
}

/** The one confirmation pattern for destructive or high-stakes actions. Focus returns to whatever opened it. */
export function ConfirmDialog({ open, onOpenChange, title, description, children, confirmLabel, pendingLabel, cancelLabel = "Cancel", destructive, pending, error, onConfirm }: {
  open: boolean; onOpenChange: (o: boolean) => void; title: string; description: ReactNode; children?: ReactNode;
  confirmLabel: string; pendingLabel?: string; cancelLabel?: string; destructive?: boolean; pending?: boolean; error?: Error | string | null; onConfirm: () => void;
}) {
  const focus = useReturnFocus();
  return (
    <AlertDialog.Root open={open} onOpenChange={onOpenChange}>
      <AlertDialog.Portal>
        <AlertDialog.Overlay className="overlay" />
        <AlertDialog.Content className={dialogBox} {...focus}>
          <AlertDialog.Title className="break-words text-lg font-semibold">{title}</AlertDialog.Title>
          <AlertDialog.Description className="mt-2 break-words text-sm">{description}</AlertDialog.Description>
          {children}
          <Alert error={error} className="mt-3" />
          <div className="mt-5 flex flex-wrap justify-end gap-2">
            <AlertDialog.Cancel className={btnQuiet}>{cancelLabel}</AlertDialog.Cancel>
            <button className={destructive ? btnDanger : btnPrimary} disabled={pending} onClick={onConfirm}>{pending ? pendingLabel ?? "Working…" : confirmLabel}</button>
          </div>
        </AlertDialog.Content>
      </AlertDialog.Portal>
    </AlertDialog.Root>
  );
}

/** What went wrong, in words that fit the cause, then the raw detail. */
export function errorLead(error: Error): string {
  if (!(error instanceof ApiError)) return "Couldn't load this.";
  if (error.status === 0) return "Can't reach the server. Check your connection and try again.";
  if (error.status === 401 || error.status === 403) return "You don't have access to this.";
  if (error.status >= 500) return "The server had a problem. Try again in a moment.";
  return "Couldn't load this.";
}

export function ErrorState({ error, retry }: { error: Error; retry: () => void }) {
  return (
    <div role="alert" className="flex flex-col items-start gap-3 border border-line bg-surface p-5">
      <p className="flex items-center gap-2 font-medium"><TriangleAlert className="size-4 text-now-fg" aria-hidden />{errorLead(error)}</p>
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
