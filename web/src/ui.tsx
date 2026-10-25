import { useState, type ReactNode } from "react";
import { Check, Copy, TriangleAlert } from "lucide-react";
import clsx from "clsx";
import { PRIORITY_CLASS, PRIORITY_LABEL, type Priority } from "./lib";

export const btn = "inline-flex min-h-9 items-center justify-center gap-2 rounded-md px-3.5 text-sm font-medium transition-colors disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed";
export const btnPrimary = clsx(btn, "bg-accent text-accent-ink hover:brightness-110");
export const btnQuiet = clsx(btn, "border border-line-strong bg-surface text-ink hover:bg-sunken");
export const input = "min-h-10 w-full rounded-md border border-line-strong bg-surface px-3 text-sm text-ink placeholder:text-muted";

/** Colour is never the only signal: dot + text label. */
export function PriorityPill({ priority, count }: { priority: Priority; count?: number }) {
  return (
    <span className={clsx("inline-flex items-center gap-1.5 whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-medium", PRIORITY_CLASS[priority])}>
      <span aria-hidden className="size-1.5 rounded-full bg-current" />
      {PRIORITY_LABEL[priority]}
      {count !== undefined && <span className="num font-semibold">{count}</span>}
    </span>
  );
}

export const KevBadge = () => (
  <span title="Listed in CISA's Known Exploited Vulnerabilities catalog" className="rounded border border-now-fg px-1.5 py-px text-[11px] font-semibold tracking-wide text-now-fg">KEV</span>
);

export const Skeleton = ({ className }: { className?: string }) => <div aria-hidden className={clsx("skeleton", className)} />;

export function ErrorState({ error, retry }: { error: Error; retry: () => void }) {
  return (
    <div role="alert" className="flex flex-col items-start gap-3 rounded-lg border border-line bg-surface p-5">
      <p className="flex items-center gap-2 font-medium"><TriangleAlert className="size-4 text-now-fg" aria-hidden />Couldn't load this</p>
      <p className="text-sm text-muted">{error.message}</p>
      <button className={btnQuiet} onClick={retry}>Try again</button>
    </div>
  );
}

export function EmptyState({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-start gap-3 rounded-lg border border-dashed border-line-strong px-5 py-8">
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
      <div className="mb-1.5 flex items-center justify-between">
        <span className="text-sm font-medium">{label}</span>
        <button className={clsx(btnQuiet, "min-h-8 !px-2.5")} onClick={copy}>
          {done ? <Check className="size-4" aria-hidden /> : <Copy className="size-4" aria-hidden />}
          {done ? "Copied" : "Copy"}
        </button>
      </div>
      <pre tabIndex={0} className="overflow-x-auto rounded-md bg-sunken p-3 font-mono text-[13px] leading-relaxed whitespace-pre-wrap break-all select-all"><code>{text}</code></pre>
      <span role="status" className="sr-only">{done ? "Copied to clipboard" : ""}</span>
    </div>
  );
}
