import { describe, expect, it } from "@jest/globals";
import { getRuntimeAdapter, supportedRuntimeAdapters } from "../../src/adapters/index.js";

describe("runtime adapter registry", () => {
  it("resolves the supported Claude Code adapter", () => {
    expect(getRuntimeAdapter("claude-code")?.runtime).toBe("claude-code");
    expect(supportedRuntimeAdapters()).toEqual(["claude-code"]);
  });

  it("returns null for unsupported runtime adapters", () => {
    expect(getRuntimeAdapter("unknown-runtime")).toBeNull();
  });
});
