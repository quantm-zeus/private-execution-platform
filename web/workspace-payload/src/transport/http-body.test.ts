import { describe, expect, it } from "vitest";
import { readBoundedJson, readBoundedText } from "./http-body";

const MAX = 2 * 1024 * 1024;

function responseWithText(text: string): Response {
  return {
    headers: { get: () => null },
    text: async () => text,
  } as unknown as Response;
}

describe("bounded private response body", () => {
  it("parses a small JSON body", async () => {
    await expect(readBoundedJson(responseWithText('{"a":1}'))).resolves.toEqual({ a: 1 });
  });

  it("rejects a body over the byte ceiling", async () => {
    const huge = "x".repeat(MAX + 1);
    await expect(readBoundedText(responseWithText(huge))).rejects.toMatchObject({
      code: "protocol",
    });
    await expect(readBoundedJson(responseWithText(huge))).rejects.toMatchObject({
      code: "protocol",
    });
  });

  it("rejects a declared content-length over the ceiling before reading", async () => {
    const response = {
      headers: {
        get: (name: string) => (name === "content-length" ? String(3 * 1024 * 1024) : null),
      },
      text: async () => "{}",
    } as unknown as Response;
    await expect(readBoundedJson(response)).rejects.toMatchObject({ code: "protocol" });
  });

  it("rejects invalid JSON", async () => {
    await expect(readBoundedJson(responseWithText("not json"))).rejects.toMatchObject({
      code: "protocol",
    });
  });
});
