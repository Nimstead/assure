import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, vi } from "vitest";
import { aiFilterToPatch, api, ApiError, filtersToSearch, parseFilters, parseUtc, relativeTime, savedViews, saveViews } from "./lib";
import { ConfirmDialog, Field } from "./ui";

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); localStorage.clear(); });

it("request preparation failures share status zero without calling fetch", async () => {
  const fetch = vi.fn();
  vi.stubGlobal("fetch", fetch);
  const cyclic: Record<string, unknown> = {};
  cyclic.self = cyclic;
  await expect(api("/api/example", { method: "POST", body: cyclic })).rejects.toMatchObject({ status: 0 });
  expect(fetch).not.toHaveBeenCalled();
  const error = new ApiError(0, "preparation failed");
  expect(error).toBeInstanceOf(Error);
  expect(error.name).toBe("Error");
});

it("transport omits falsey bodies and accepts URLs without an origin guard", async () => {
  const fetch = vi.fn(async (_url: RequestInfo | URL, _init?: RequestInit) => new Response(null, { status: 204 }));
  vi.stubGlobal("fetch", fetch);
  for (const body of [false, 0, "", null]) await expect(api("https://example.invalid/api", { method: "POST", body })).resolves.toBeUndefined();
  expect(fetch).toHaveBeenCalledTimes(4);
  for (const [url, init] of fetch.mock.calls) {
    expect(url).toBe("https://example.invalid/api");
    expect(init).toMatchObject({ body: undefined, headers: undefined });
  }
});

it("successful invalid JSON rejects separately from HTTP errors", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => new Response("{", { status: 200 })));
  await expect(api("/api/example")).rejects.toBeInstanceOf(SyntaxError);
});

it("filter URLs normalize priorities and use exact boolean sentinels", () => {
  const parsed = parseFilters({ priority: "low,next,next, low", fixable: "false", kev: "true", overdue: "1" });
  expect(parsed.priority).toEqual(["low", "next", "next"]);
  expect(parsed).toMatchObject({ fixable: true, kev: false, overdue: true });
  expect(filtersToSearch(parsed).priority).toBe("next,low");
  expect(aiFilterToPatch({ status: "unknown" })).toEqual({ q: "", priority: [], kev: false, fixable: false });
});

it("date parsing returns an invalid Date while relative formatting rejects it", () => {
  expect(Number.isNaN(parseUtc("not a timestamp").getTime())).toBe(true);
  expect(() => relativeTime("not a timestamp")).toThrow(RangeError);
});

it("saved views validate names only and suppress serialization failures", () => {
  localStorage.setItem("nimstead:findings-views", JSON.stringify([{ name: "incomplete" }, { name: 7 }]));
  expect(savedViews()).toEqual([{ name: "incomplete" }]);
  const dispatch = vi.spyOn(window, "dispatchEvent");
  const cyclic = { name: "cycle", search: {} };
  Object.assign(cyclic.search, { self: cyclic });
  expect(() => saveViews([cyclic])).not.toThrow();
  expect(dispatch).not.toHaveBeenCalled();
  expect(savedViews()).toEqual([{ name: "incomplete" }]);
});

it("Field replaces a child's ARIA description rather than merging it", () => {
  render(<><span id="original">Original help</span><Field label="Name" hint="Current help" error="Current error"><input aria-describedby="original" /></Field></>);
  const input = screen.getByRole("textbox", { name: "Name" });
  expect(input).toHaveAccessibleDescription("Current help Current error");
  expect(input.getAttribute("aria-describedby")).not.toContain("original");
  expect(input).toHaveAttribute("aria-invalid", "true");
});

it("confirmation invokes the parent and pending still permits a cancellation request", () => {
  const confirm = vi.fn(), change = vi.fn();
  const view = (pending: boolean) => <ConfirmDialog open onOpenChange={change} title="Review" description="Fixture decision" confirmLabel="Confirm" pending={pending} onConfirm={confirm} />;
  const rendered = render(view(false));
  fireEvent.click(screen.getByRole("button", { name: "Confirm" }));
  expect(confirm).toHaveBeenCalledOnce();
  expect(screen.getByRole("alertdialog")).toBeInTheDocument();
  rendered.rerender(view(true));
  expect(screen.getByRole("button", { name: "Working…" })).toBeDisabled();
  fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
  expect(change).toHaveBeenCalledWith(false);
});
