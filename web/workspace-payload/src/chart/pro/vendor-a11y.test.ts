import { describe, expect, it } from "vitest";
import { normalizePositiveTabindex } from "./vendor-a11y";

describe("normalizePositiveTabindex", () => {
  it("rewrites a positive tabindex to 0", () => {
    const root = document.createElement("div");
    root.innerHTML = `<div class="klinecharts-pro-widget"><div tabindex="1"></div></div>`;
    normalizePositiveTabindex(root);
    const target = root.querySelector<HTMLElement>(".klinecharts-pro-widget > div")!;
    expect(target.getAttribute("tabindex")).toBe("0");
  });

  it("leaves 0 and -1 tabindex values untouched", () => {
    const root = document.createElement("div");
    root.innerHTML = `<button tabindex="0"></button><button tabindex="-1"></button>`;
    normalizePositiveTabindex(root);
    expect(root.querySelectorAll("button")[0]!.getAttribute("tabindex")).toBe("0");
    expect(root.querySelectorAll("button")[1]!.getAttribute("tabindex")).toBe("-1");
  });

  it("ignores non-numeric or empty tabindex values", () => {
    const root = document.createElement("div");
    root.innerHTML = `<div tabindex="auto"></div><div tabindex=""></div>`;
    normalizePositiveTabindex(root);
    const divs = root.querySelectorAll("div");
    expect(divs[0]!.getAttribute("tabindex")).toBe("auto");
    expect(divs[1]!.getAttribute("tabindex")).toBe("");
  });

  it("patches deep descendants, not just direct children", () => {
    const root = document.createElement("div");
    root.innerHTML = `<section><span><i tabindex="2"></i></span></section>`;
    normalizePositiveTabindex(root);
    expect(root.querySelector("i")!.getAttribute("tabindex")).toBe("0");
  });

  it("does not add a tabindex attribute where none existed", () => {
    const root = document.createElement("div");
    root.innerHTML = `<div></div>`;
    normalizePositiveTabindex(root);
    expect(root.querySelector("div")!.hasAttribute("tabindex")).toBe(false);
  });

  it("is idempotent", () => {
    const root = document.createElement("div");
    root.innerHTML = `<div tabindex="3"></div>`;
    normalizePositiveTabindex(root);
    normalizePositiveTabindex(root);
    expect(root.querySelector("div")!.getAttribute("tabindex")).toBe("0");
  });
});
