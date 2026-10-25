import { render, screen } from "@testing-library/react";
import { InstallCommands } from "./onboarding";
import { PriorityPill } from "./ui";

it("priority pill carries a text label, not just colour", () => {
  render(<PriorityPill priority="fix-now" count={3} />);
  expect(screen.getByText("Fix now")).toBeInTheDocument();
  expect(screen.getByText("3")).toBeInTheDocument();
});

it("onboarding shows both copyable commands", () => {
  render(<InstallCommands origin="http://localhost:5173" token="nme_t0k" />);
  expect(screen.getByText(/curl -fsSL http:\/\/localhost:5173\/install\.sh \| sudo sh -s -- --token nme_t0k/)).toBeInTheDocument();
  expect(screen.getByText(/enroll --server http:\/\/localhost:5173 --token nme_t0k/)).toBeInTheDocument();
  expect(screen.getAllByRole("button", { name: "Copy" })).toHaveLength(2);
});
