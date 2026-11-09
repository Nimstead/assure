import { cloneElement, isValidElement, useEffect, useId, useRef, useState, type ReactElement, type ReactNode, type RefObject } from "react";
import { AlertDialog } from "radix-ui";
import { Check, Copy, TriangleAlert } from "lucide-react";
import clsx from "clsx";
import { announce, ApiError, JOB_STATUS_LABEL, PRIORITY_CLASS, PRIORITY_LABEL, type JobStatus, type Priority } from "./lib";

// 44px tall on phones (touch), 36px from md up.
export const btn = "inline-flex min-h-[44px] md:min-h-9 items-center justify-center gap-2 px-3.5 text-sm font-medium transition-colors disabled:opacity-50 aria-disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed aria-disabled:cursor-not-allowed";
export const btnPrimary = clsx(btn, "bg-accent text-accent-ink hover:bg-accent/80 disabled:border disabled:border-line-strong disabled:bg-transparent disabled:text-muted disabled:opacity-100");
export const btnQuiet = clsx(btn, "border border-line-strong bg-surface text-ink hover:bg-sunken");
/** For confirming something that can't be undone: the "fix now" colour, never used for an ordinary primary action. */
export const btnDanger = clsx(btn, "bg-now-fg text-surface hover:bg-now-fg/85");
export const input = "min-h-[44px] md:min-h-10 w-full border border-line-strong bg-surface px-3 text-base md:text-sm text-ink placeholder:text-muted";
/** Return selected/unselected filter classes from on; do not add ARIA state or event behavior. */
export const chip = (on: boolean) => clsx("inline-flex min-h-[44px] md:min-h-8 cursor-pointer items-center gap-1.5 border px-3 text-sm", on ? "border-ink bg-ink font-medium text-accent-ink [&_.text-muted]:text-accent-ink" : "border-line-strong text-muted hover:text-ink");
export const switchRoot = "relative h-5 w-9 shrink-0 cursor-pointer rounded-full bg-line-strong data-[state=checked]:bg-accent disabled:opacity-50";
export const switchThumb = "block size-4 translate-x-0.5 rounded-full bg-surface transition-transform data-[state=checked]:translate-x-[18px]";
export const dialogBox = "fixed left-1/2 top-[15vh] z-[51] w-[min(30rem,calc(100%-2rem))] -translate-x-1/2 border border-line bg-surface p-5 shadow-[0_24px_48px_-12px_var(--shadow)]";

/** Return Radix autofocus handlers that remember the opener at open time.
 * initial optionally supplies a requested first-focus element. A connected opener
 * receives a close-time focus request. Otherwise allow Radix's default behavior.
 * Require a browser DOM. Do not guarantee focus on hidden/disabled/unfocusable nodes.
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

/** Render typed priority's label/style and optional raw count, including zero.
 * No scoring, formatting or unknown-priority fallback occurs. No I/O occurs.
 */
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
  succeeded: "!border-ink bg-surface text-ink", failed: "bg-now-bg text-now-fg", rolled_back: "bg-now-bg text-now-fg", rollback_failed: "bg-now-bg text-now-fg",
  // outlined only, so a deliberate cancel never looks like a success
  not_fixed: "bg-now-bg text-now-fg", aborted: "bg-now-bg text-now-fg", cancelled: "border-dashed !border-line-strong bg-transparent text-muted",
};
/** Render status using the shared label/style map, without fetching job state.
 * Unknown runtime statuses have no label fallback. Success refers to a job, not all findings.
 */
export const StatusPill = ({ status }: { status: JobStatus }) => (
  <span className={clsx("inline-flex items-center gap-1.5 whitespace-nowrap border border-line px-2 py-0.5 text-xs font-medium", STATUS_CLASS[status])}>
    {status === "succeeded" ? <Check aria-hidden className="size-3" /> : <span aria-hidden className="size-1.5 bg-current" />}{JOB_STATUS_LABEL[status]}
  </span>
);

/** Render children with tone classes (default muted) and optional className.
 * why becomes title text and a screen-reader-only suffix. It is not visible body
 * help on touch devices. The caller supplies essential visible explanations.
 */
export function Tag({ children, tone = "muted", why, className }: { children: ReactNode; tone?: "muted" | "now" | "ink" | "warn"; why?: string; className?: string }) {
  return (
    <span title={why} className={clsx("inline-flex shrink-0 items-center gap-1 px-1.5 py-px text-xs font-semibold tracking-wide",
      tone === "now" ? "bg-now-bg text-now-fg" : tone === "warn" ? "bg-warn-bg text-warn-fg" : tone === "ink" ? "bg-accent-soft text-ink" : "bg-sunken text-muted", className)}>
      {children}{why && <span className="sr-only">: {why}</span>}
    </span>
  );
}

/** Render the static KEV label/explanation without checking a feed or accepting props. */
export const KevBadge = () => <Tag tone="now" why="Listed in CISA's Known Exploited Vulnerabilities catalog">KEV</Tag>;

const Skeleton = ({ className }: { className?: string }) => <div aria-hidden className={clsx("skeleton", className)} />;

/** Render rows placeholders (default one) with a status label (default Loading…).
 * className applies to each skeleton. Empty label removes hidden text. rows is not
 * range-validated; extreme values can fail allocation. No loading request occurs here.
 */
export function Loading({ className, rows = 1, label = "Loading…" }: { className?: string; rows?: number; label?: string }) {
  return (
    <div role="status" className="flex flex-col gap-2">
      {label && <span className="sr-only">{label}</span>}
      {Array.from({ length: rows }, (_, i) => <Skeleton key={i} className={className} />)}
    </div>
  );
}

/** Render truthy error text/message as an alert, with optional prefix/className/id.
 * Falsey error renders null. Do not interpret status, sanitize meaning or perform I/O.
 */
export function Alert({ error, prefix, className, id }: { error: Error | string | null | undefined; prefix?: string; className?: string; id?: string }) {
  if (!error) return null;
  return <p id={id} role="alert" className={clsx("bg-now-bg px-3 py-2 text-sm text-now-fg", className)}>{prefix}{typeof error === "string" ? error : error.message}</p>;
}

/** Render string children with a check icon and optional className.
 * On mount/children changes, call announce. A live region must exist for that output.
 * This presentation does not verify success. Announcement timers are not cancelled here.
 */
export function Done({ children, className }: { children: string; className?: string }) {
  useEffect(() => announce(children), [children]);
  return <p className={clsx("inline-flex items-center gap-1.5 text-sm text-ink", className)}><Check className="size-4" aria-hidden />{children}</p>;
}

/** Render string children as a bordered note with optional className.
 * Announce on mount/children changes when a live region exists. No request occurs.
 */
export function Notice({ children, className }: { children: string; className?: string }) {
  useEffect(() => announce(children), [children]);
  return <p className={clsx("border border-line-strong bg-surface px-3 py-2 text-sm", className)}>{children}</p>;
}

/** Render empty polite live and assertive live-alert regions, without props or requests.
 * Mount one pair per page so announce can locate unique IDs.
 */
export const LiveRegions = () => (
  <>
    <div id="live" role="status" aria-live="polite" className="sr-only" />
    <div id="live-alert" role="alert" aria-live="assertive" className="sr-only" />
  </>
);

/** Render label/children, optional hint/error and wrapper className.
 * A valid React element child is cloned with aria-invalid/aria-describedby, replacing
 * existing values. Arrays/text pass unchanged. Custom controls must forward these
 * props to their input. The caller supplies suitable labelable content.
 * Error text uses an alert role. This component does not validate or manage input state.
 */
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

/** Render a controlled Radix alert dialog from open/onOpenChange.
 * title/description name the decision; children adds content. confirmLabel and optional
 * pendingLabel/cancelLabel customize buttons. destructive changes confirmation styling.
 * pending disables confirmation only; cancellation remains available. error renders
 * an alert. onConfirm is called without awaiting or automatically closing the dialog.
 * The parent owns request state, result handling and open state. Focus restoration
 * uses useReturnFocus. Require a browser DOM; no network request occurs here.
 */
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

/** Return a display lead from Error type/status, without reading its message.
 * Only ApiError instances receive status-specific copy: 0, 401/403, or >=500.
 * Other cases use generic load-failure text. No I/O or mutation occurs.
 */
export function errorLead(error: Error): string {
  if (!(error instanceof ApiError)) return "Couldn't load this.";
  if (error.status === 0) return "Couldn't complete the request. Check the input and connection, then try again.";
  if (error.status === 401 || error.status === 403) return "You don't have access to this.";
  if (error.status >= 500) return "The server had a problem. Try again in a moment.";
  return "Couldn't load this.";
}

/** Render errorLead(error), raw error.message and a Try again button calling retry.
 * The parent owns retry/pending behavior. No request or promise handling occurs here.
 */
export function ErrorState({ error, retry }: { error: Error; retry: () => void }) {
  return (
    <div role="alert" className="flex flex-col items-start gap-3 border border-line bg-surface p-5">
      <p className="flex items-center gap-2 font-medium"><TriangleAlert className="size-4 text-now-fg" aria-hidden />{errorLead(error)}</p>
      <p className="text-sm text-muted">Details: {error.message}</p>
      <button className={btnQuiet} onClick={retry}>Try again</button>
    </div>
  );
}

/** Render title, optional paragraph children, and optional action without requests.
 * The caller supplies paragraph-compatible children and any action behavior.
 */
export function EmptyState({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-start gap-3 border border-dashed border-line-strong px-5 py-8">
      <h2 className="text-base font-semibold">{title}</h2>
      {children && <p className="max-w-prose text-sm text-muted">{children}</p>}
      {action}
    </div>
  );
}

/** Render label/text and a button calling navigator.clipboard.writeText(text).
 * Success shows Copied and status text for two seconds. Clipboard failures are
 * suppressed without error feedback; text remains selectable. Repeated copy timers
 * are independent and not cleared on unmount. Require a browser DOM/clipboard for copying.
 */
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
      <pre tabIndex={0} className="text-mono overflow-x-auto bg-sunken p-3 font-mono leading-relaxed whitespace-pre-wrap break-all select-all"><code>{text}</code></pre>
      <span role="status" className="sr-only">{done ? "Copied to clipboard" : ""}</span>
    </div>
  );
}
