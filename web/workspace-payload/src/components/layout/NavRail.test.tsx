import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@solidjs/testing-library";
import { NavRail } from "./NavRail";

describe("NavRail", () => {
  afterEach(() => cleanup());

  it("moves focus across group boundaries in DOM order", () => {
    const onSelect = vi.fn();
    render(() => <NavRail active="overview" onSelect={onSelect} capabilityOf={() => true} />);

    // Trade is the first item of the second group. ArrowDown must land on the
    // next DOM item (Limits), not jump back into the first group.
    const trade = screen.getByRole("button", { name: /^Trade/ });
    trade.focus();
    fireEvent.keyDown(trade, { key: "ArrowDown" });
    expect(onSelect).toHaveBeenLastCalledWith("limits", { focusMain: false });

    // ArrowUp from the second group must land on the previous DOM item (Trade),
    // not wrap into the first group.
    onSelect.mockClear();
    const limits = screen.getByRole("button", { name: /^Limits/ });
    limits.focus();
    fireEvent.keyDown(limits, { key: "ArrowUp" });
    expect(onSelect).toHaveBeenLastCalledWith("trade", { focusMain: false });
  });

  it("supports Home and End", () => {
    const onSelect = vi.fn();
    render(() => <NavRail active="overview" onSelect={onSelect} capabilityOf={() => true} />);
    const security = screen.getByRole("button", { name: /^Security/ });
    security.focus();
    fireEvent.keyDown(security, { key: "Home" });
    expect(onSelect).toHaveBeenLastCalledWith("overview", { focusMain: false });
    onSelect.mockClear();
    fireEvent.keyDown(screen.getByRole("button", { name: /^Overview/ }), { key: "End" });
    expect(onSelect).toHaveBeenLastCalledWith("security", { focusMain: false });
  });

  it("marks the active view with aria-current", () => {
    render(() => <NavRail active="portfolio" onSelect={() => {}} capabilityOf={() => true} />);
    expect(screen.getByRole("button", { name: /^Portfolio/ }).getAttribute("aria-current")).toBe("page");
  });
});
