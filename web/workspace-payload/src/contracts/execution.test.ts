import { describe, expect, it } from "vitest";
import {
  parseRouterSource,
  routerSourceLabel,
  type RouterPreference,
  type RouterSourceView,
} from "./execution";

/**
 * W15 contract-conformance tests: the routing discriminant is reconciled with the
 * landed `agent-backend` P84B/P84C contract on canonical `origin/main`.
 *
 * `crates/agent-commands/src/command.rs` serialises `RouterSource` with
 * `#[serde(rename_all = "snake_case")]` as the bare strings `"okx"` / `"local"`,
 * and `crates/agent-backend/tests/hybrid_router.rs` asserts the response JSON:
 *   preview["router_source"]  == Value::String("okx")
 *   value["quote"]["router_source"] == Value::String("local")
 * The private web contract accepts that canonical string form as well as the
 * object `{ id, detail }` form it originally requested (BR-10), and normalises
 * both to {@link RouterSourceView}.
 */
describe("parseRouterSource (W15 canonical + object wire forms)", () => {
  it.each([
    ["okx", "okx"],
    ["local", "local"],
  ] as const)("accepts the canonical string %s", (wire, id) => {
    expect(parseRouterSource(wire)).toEqual({ id, detail: null } satisfies RouterSourceView);
  });

  it("accepts the object form and preserves a neutral detail string", () => {
    expect(parseRouterSource({ id: "local", detail: "pep-local" })).toEqual({
      id: "local",
      detail: "pep-local",
    } satisfies RouterSourceView);
    expect(parseRouterSource({ id: "okx" })).toEqual({ id: "okx", detail: null });
    expect(parseRouterSource({ id: "okx", detail: null })).toEqual({ id: "okx", detail: null });
  });

  it("does not coerce a non-string detail into a rendered value", () => {
    // A hostile relay could try to smuggle an object/array into `detail`; only a
    // string survives, everything else normalises to null.
    expect(parseRouterSource({ id: "okx", detail: { html: "<img>" } })).toEqual({
      id: "okx",
      detail: null,
    });
    expect(parseRouterSource({ id: "okx", detail: 42 })).toEqual({ id: "okx", detail: null });
  });

  it("rejects non-canonical labels (case, whitespace, unknown, sentinels)", () => {
    const rejected = ["OKX", "Local", " okx", "okx ", "", "solana", "none"];
    for (const wire of rejected) {
      expect(parseRouterSource(wire), wire).toBeNull();
    }
  });

  it.each([
    [null, "null"],
    [undefined, "undefined"],
    [42, "number"],
    [true, "boolean"],
    [["okx"], "array"],
    [{}, "missing id"],
    [{ id: "OKX" }, "non-canonical id"],
    [{ id: 1 }, "non-string id"],
    [{ detail: "okx" }, "detail without id"],
  ] as const)("rejects malformed input %# (%s)", (value, _label) => {
    expect(parseRouterSource(value)).toBeNull();
  });

  it("reconstructs the view instead of spreading unknown fields", () => {
    expect(parseRouterSource({ id: "okx", detail: "x", extra: true })).toEqual({
      id: "okx",
      detail: "x",
    });
  });

  it("parses the exact landed P84B/P84C response JSON discriminants", () => {
    // Verbatim shapes from crates/agent-backend/tests/hybrid_router.rs.
    const previewOkx = { preview: { router_source: "okx", truncated: false } };
    const previewLocal = { preview: { router_source: "local", truncated: false } };
    const getQuoteOkx = { quote: { router_source: "okx" } };
    const getQuoteLocal = { quote: { router_source: "local" } };

    expect(parseRouterSource(previewOkx.preview.router_source)?.id).toBe<RouterPreference>("okx");
    expect(parseRouterSource(previewLocal.preview.router_source)?.id).toBe<RouterPreference>("local");
    expect(parseRouterSource(getQuoteOkx.quote.router_source)?.id).toBe<RouterPreference>("okx");
    expect(parseRouterSource(getQuoteLocal.quote.router_source)?.id).toBe<RouterPreference>("local");
  });

  it("labels the canonical ids for display without leaking provider internals", () => {
    expect(routerSourceLabel("okx")).toBe("OKX");
    expect(routerSourceLabel("local")).toBe("Local Router");
  });
});
