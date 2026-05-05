import { describe, it, expect } from "vitest";
import { computePolicyCommitment, encodeActionData } from "../../src/layer2/AuthorizerClient.js";
import { ActionType } from "../../src/layer2/types.js";

const ZERO32 = `0x${"00".repeat(32)}` as `0x${string}`;

describe("encodeActionData()", () => {
  it("produces a 0x-prefixed hex string of 128 bytes (258 chars total)", () => {
    const hex = encodeActionData({
      actionType: ActionType.Swap,
      protocol: ZERO32,
      token: ZERO32,
      value: 1n,
    });
    expect(hex).toMatch(/^0x[0-9a-f]{256}$/);
  });

  it("encodes actionType as big-endian uint32 at bytes 28-31", () => {
    const hex = encodeActionData({
      actionType: ActionType.Transfer,
      protocol: ZERO32,
      token: ZERO32,
      value: 1n,
    });
    // bytes 28-31 → chars 56-63 after stripping "0x"
    expect(hex.slice(2).slice(56, 64)).toBe("00000001");
  });

  it("encodes Deposit (2) correctly in bytes 28-31", () => {
    const hex = encodeActionData({
      actionType: ActionType.Deposit,
      protocol: ZERO32,
      token: ZERO32,
      value: 1n,
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

  it("rejects zero and values outside u64 range", () => {
    expect(() =>
      encodeActionData({
        actionType: ActionType.Swap,
        protocol: ZERO32,
        token: ZERO32,
        value: 0n,
      }),
    ).toThrow("action.value must be between 1 and u64::MAX");

    expect(() =>
      encodeActionData({
        actionType: ActionType.Swap,
        protocol: ZERO32,
        token: ZERO32,
        value: 1n << 64n,
      }),
    ).toThrow("action.value must be between 1 and u64::MAX");

    expect(() =>
      encodeActionData({
        actionType: ActionType.Swap,
        protocol: ZERO32,
        token: ZERO32,
        value: -1n,
      }),
    ).toThrow("action.value must be between 1 and u64::MAX");
  });

  it("rejects protocol or token values that are not bytes32", () => {
    expect(() =>
      encodeActionData({
        actionType: ActionType.Swap,
        protocol: "0x1234",
        token: ZERO32,
        value: 1n,
      }),
    ).toThrow("action bytes32 field must be a 32-byte hex string");

    expect(() =>
      encodeActionData({
        actionType: ActionType.Swap,
        protocol: ZERO32,
        token: `0x${"11".repeat(33)}`,
        value: 1n,
      }),
    ).toThrow("action bytes32 field must be a 32-byte hex string");
  });

  it("produces different encodings for different action types", () => {
    const swap = encodeActionData({ actionType: ActionType.Swap, protocol: ZERO32, token: ZERO32, value: 1n });
    const transfer = encodeActionData({ actionType: ActionType.Transfer, protocol: ZERO32, token: ZERO32, value: 1n });
    expect(swap).not.toBe(transfer);
  });
});

describe("computePolicyCommitment()", () => {
  const wasm = {
    compute_policy_commitment: () => new Uint8Array(32),
  };

  const policy = {
    allowedAction: ActionType.Swap,
    allowedProtocol: ZERO32,
    allowedToken: ZERO32,
    maxValuePerTx: 100n,
    maxValueTotal: 1000n,
    validFrom: 0n,
    validUntil: 9999999999n,
  };

  it("rejects numeric fields outside u64 range before calling WASM", () => {
    expect(() => computePolicyCommitment({ ...policy, maxValuePerTx: 1n << 64n }, wasm)).toThrow(
      "maxValuePerTx must fit in u64",
    );
    expect(() => computePolicyCommitment({ ...policy, maxValueTotal: -1n }, wasm)).toThrow(
      "maxValueTotal must fit in u64",
    );
    expect(() => computePolicyCommitment({ ...policy, validFrom: 1n << 64n }, wasm)).toThrow(
      "validFrom must fit in u64",
    );
    expect(() => computePolicyCommitment({ ...policy, validUntil: -1n }, wasm)).toThrow(
      "validUntil must fit in u64",
    );
  });
});
