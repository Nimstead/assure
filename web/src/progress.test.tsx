// Programme view (tasks/plan-programme.md T6): one answer to "better or worse?", every chart readable as a table,
// owners ordered by who is behind and linked to their findings.
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, within } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, vi } from "vitest";
import { meQ, type Progress, type ProgressDay } from "./lib";
import { dayLabel, niceCeil, ProgressPage, progressSentences } from "./progress";

vi.mock("@tanstack/react-router", () => ({
  Link: ({ children, to, search, className }: { children: ReactNode; to: string; search?: Record<string, string | undefined>; className?: string }) => {
    const qs = new URLSearchParams(Object.entries(search ?? {}).filter((e): e is [string, string] => e[1] !== undefined)).toString();
    return <a href={`${to}${qs ? `?${qs}` : ""}`} className={className}>{children}</a>;
  },
  useNavigate: () => vi.fn(),
  useSearch: () => ({}),
}));

function serve(body: unknown) {
  vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(body), { status: 200 })));
}
function wrap(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  qc.setQueryData(meQ.queryKey, { email: "a@example.com", org: "Acme", admin: false, origin: "password", mfa: true, recovery_codes_left: 10 });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}
afterEach(() => vi.unstubAllGlobals());

/** `count` days ending 2026-11-20, fix now going from `fixFrom` to `fixTo` in a straight line. */
function series(count: number, fixFrom: number, fixTo: number, rest = 100, overdue = 0): ProgressDay[] {
  return Array.from({ length: count }, (_, i) => {
    const d = new Date(Date.UTC(2026, 10, 20 - (count - 1 - i)));
    const fix = Math.round(fixFrom + ((fixTo - fixFrom) * i) / Math.max(1, count - 1));
    return { date: d.toISOString().slice(0, 10), open: { "fix-now": fix, next: 0, planned: 0, low: rest }, overdue, accepted: 0 };
  });
}

it("answers better or worse in one sentence, with the pace on fix now", () => {
  const falling = progressSentences({ days: series(90, 60, 20, 100, 3) });
  expect(falling[0]).toBe("Open findings fell from 160 to 120 in the last 90 days; 3 are overdue.");
  // 28 days at 40/89 a day is about 12.6 fewer in four weeks, 3.1 a week: 20 left clear in 7 weeks
  expect(falling[1]).toBe("At the last four weeks' pace, the 20 fix-now findings would clear in about 7 weeks.");
  const rising = progressSentences({ days: series(30, 5, 9) });
  expect(rising).toEqual(["Open findings rose from 105 to 109 in the last 30 days; none are overdue.", "Fix-now findings grew by 4 in the last four weeks."]);
  const flat = progressSentences({ days: series(30, 7, 7, 100, 1) });
  expect(flat).toEqual(["Open findings held at 107 over the last 30 days; 1 is overdue.", "Fix-now findings haven't fallen in the last four weeks (7 open)."]);
  expect(progressSentences({ days: series(30, 4, 0) })[1]).toBe("Every fix-now finding is closed.");
  expect(progressSentences({ days: series(365, 1100, 999) })[1]).toBe("At the last four weeks' pace, the 999 fix-now findings would take more than a year to clear.");
});

it("rounds the axis to 1, 2 or 5 and labels UTC days", () => {
  expect([1, 3, 7, 12, 99, 101, 4999].map(niceCeil)).toEqual([1, 5, 10, 20, 100, 200, 5000]);
  expect(dayLabel("2026-08-23", 2026)).toBe("23 Aug");
  expect(dayLabel("2025-12-31", 2026)).toBe("31 Dec 2025");
});

const PROGRESS: Progress = {
  start: "2026-08-23T00:00:00", end: "2026-11-20T13:30:00", days: series(90, 12, 4, 50, 2),
  weeks: [{ start: "2026-11-09", opened: 8, resolved: 15, partial: false }, { start: "2026-11-16", opened: 3, resolved: 1, partial: true }],
  owners: [
    { owner: "Payments", open: 20, fix_now: 3, overdue: 2, accepted: 0, open_at_start: 30, resolved: 10, resolved_on_time: 9, mean_days_to_resolve: 4.2 },
    { owner: null, open: 34, fix_now: 1, overdue: 0, accepted: 1, open_at_start: 32, resolved: 0, resolved_on_time: 0, mean_days_to_resolve: null },
  ],
  totals: { open: 54, fix_now: 4, overdue: 2, accepted: 1, open_at_start: 62, resolved: 10, resolved_on_time: 9, mean_days_to_resolve: 4.2 },
  basis: { entries: 1234, head_seq: 5678, head_hash: "abcdef0123456789", findings: 70, no_ledger_record: 0, mismatched: 1, problems: [] },
};

it("shows the answer, every series with its change, a table view, and owners linked to their findings", async () => {
  serve(PROGRESS);
  wrap(<ProgressPage />);
  expect(await screen.findByText("Open findings fell from 62 to 54 in the last 90 days; 2 are overdue.")).toBeInTheDocument();
  const panels = screen.getByRole("group", { name: /Open findings by day/ });
  const names = within(panels).getAllByRole("link").map((a) => a.textContent);
  expect(names).toEqual(["Overdue", "Fix now", "Next", "Routine", "Low", "Accepted risk"]);  // what broke first
  expect(within(panels).getByRole("link", { name: "Overdue" })).toHaveAttribute("href", "/findings?overdue=1");
  expect(within(panels).getByText("down 8 since 23 Aug")).toBeInTheDocument();  // fix now 12 -> 4
  // stepping back a day with the keyboard reads that day everywhere
  fireEvent.keyDown(panels, { key: "ArrowLeft" });
  expect(screen.getAllByText("19 Nov").length).toBeGreaterThan(1);
  // every number is reachable without the chart
  const table = screen.getAllByRole("table", { name: /Open findings by day/ })[0]!;
  expect(within(table).getAllByRole("row")).toHaveLength(91);
  expect(screen.getByRole("link", { name: "Payments" })).toHaveAttribute("href", "/findings?owner=Payments");
  expect(screen.getByRole("link", { name: "No owner" })).toHaveAttribute("href", "/findings?noowner=1");
  expect(screen.getByText("−10")).toBeInTheDocument();  // Payments: 30 open at the start, 20 now
  expect(screen.getAllByText("9 of 10")).toHaveLength(2);  // Payments, and everyone
  expect(screen.getByText(/1 finding isn't charted/)).toBeInTheDocument();
  expect(screen.getByText("abcdef0123")).toHaveAttribute("title", "abcdef0123456789");
});

it("says plainly when the ledger behind the numbers fails its check", async () => {
  serve({ ...PROGRESS, basis: { ...PROGRESS.basis, problems: ["seq 3: hash mismatch"] } });
  wrap(<ProgressPage />);
  expect(await screen.findByText("The evidence ledger failed its integrity check")).toBeInTheDocument();
  expect(screen.queryByText(/the record your evidence packs are signed from/)).toBeNull();  // no provenance claim next to it
});

it("says there is nothing to chart rather than drawing empty lines", async () => {
  serve({ ...PROGRESS, basis: { ...PROGRESS.basis, findings: 0 } });
  wrap(<ProgressPage />);
  expect(await screen.findByText("Nothing to chart yet")).toBeInTheDocument();
  expect(screen.queryByRole("group", { name: /Open findings by day/ })).toBeNull();
});
