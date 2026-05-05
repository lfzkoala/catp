import { describe, it, expect } from "vitest";
import { encodeActionData } from "../../src/layer2/AuthorizerClient.js";
import { ActionType } from "../../src/layer2/types.js";

const ZERO32 = `0x${"00".repeat(32)}` as `0x${string}`;

describe("encodeActionData()", () => {
  it("produces a 0x-prefixed hex string of 128 bytes (258 chars total)", () => {
    const hex = encodeActionData({
      actionType: ActionType.Swap,
      protocol: ZERO32,
      token: ZERO32,
      value: 0n,
    });
    expect(hex).toMatch(/^0x[0-9a-f]{256}$/);
  });

  it("encodes actionType as big-endian uint32 at bytes 28-31", () => {
    const hex = encodeActionData({
      actionType: ActionType.Transfer,
      protocol: ZERO32,
      token: ZERO32,
      value: 0n,
    });
    // bytes 28-31 → chars 56-63 after stripping "0x"
    expect(hex.slice(2).slice(56, 64)).toBe("00000001");
  });

  it("encodes Deposit (2) correctly in bytes 28-31", () => {
    const hex = encodeActionData({
      actionType: ActionType.Deposit,
      protocol: ZERO32,
      token: ZERO32,
      value: 0n,
    });
    expect(hex.slice(2).slice(56, 64)).toBe("00000002");
  });

  it("encodes value as big-endian uint64 in the last 8 bytes", () => {
    const hex = encodeActionData({
      actionType: ActionType.Swap,
      protocol: ZERO32,
      token: ZERO32,
      value: 1n,
    });
    // bytes 96-103 → chars 192-207
    expect(hex.slice(2).slice(192, 208)).toBe("0000000000000001");
  });

  it("produces different encodings for different action types", () => {
    const swap = encodeActionData({ actionType: ActionType.Swap, protocol: ZERO32, token: ZERO32, value: 0n });
    const transfer = encodeActionData({ actionType: ActionType.Transfer, protocol: ZERO32, token: ZERO32, value: 0n });
    expect(swap).not.toBe(transfer);
  });
});
