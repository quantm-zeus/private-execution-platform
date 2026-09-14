import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@solidjs/testing-library";
import { KeyValue, Metric } from "../components/ui/primitives";

/**
 * XSS regression: every value in the UI is rendered as a text node by Solid's
 * templating. A hostile token symbol/name must never become markup.
 */
describe("text escaping", () => {
  afterEach(() => cleanup());

  const payload = '<img src=x onerror="globalThis.__pwned=1">';

  it("renders hostile text as text, not markup", () => {
    render(() => <Metric label="Symbol" value={payload} />);
    expect(document.querySelector("img")).toBeNull();
    expect(document.body.textContent).toContain(payload);
    expect((globalThis as Record<string, unknown>).__pwned).toBeUndefined();
  });

  it("escapes key/value evidence rows", () => {
    render(() => <KeyValue rows={[{ key: "k", label: "Label", value: payload }]} />);
    expect(document.querySelector("img")).toBeNull();
    expect(screen.getByText(payload)).toBeTruthy();
  });

  it("does not evaluate injected script content", () => {
    render(() => <Metric label="Script" value={"<script>globalThis.__pwned=1</script>"} />);
    expect(document.querySelector("script")).toBeNull();
    expect((globalThis as Record<string, unknown>).__pwned).toBeUndefined();
  });
});
