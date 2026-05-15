import { describe, it, expect } from "vitest";
import { PolicyBuilder } from "../../src/authorization/PolicyBuilder.js";
import { ActionType } from "../../src/authorization/types.js";

const ZERO32 = `0x${"00".repeat(32)}` as `0x${string}`;

const fullPolicy = () =>
  new PolicyBuilder()
    .allowAction(ActionType.Swap)
    .allowProtocol(ZERO32)
    .allowToken(ZERO32)
    .maxValuePerTx(100n)
    .maxValueTotal(1000n)
    .validFrom(0n)
    .validUntil(9999999999n)
    .build();

describe("PolicyBuilder", () => {
  describe("build()", () => {
    it("returns a complete policy when all fields are set", () => {
      const p = fullPolicy();
      expect(p.allowedAction).toBe(ActionType.Swap);
      expect(p.maxValuePerTx).toBe(100n);
      expect(p.maxValueTotal).toBe(1000n);
      expect(p.validFrom).toBe(0n);
      expect(p.validUntil).toBe(9999999999n);
    });

    it("throws when no fields are set", () => {
      expect(() => new PolicyBuilder().build()).toThrow("all fields are required");
    });

    it("throws when only some fields are set", () => {
      expect(() =>
        new PolicyBuilder().allowAction(ActionType.Transfer).build(),
      ).toThrow("all fields are required");
    });

    it("stores the last value when a setter is called twice", () => {
      const p = new PolicyBuilder()
        .allowAction(ActionType.Swap)
        .allowAction(ActionType.Transfer)
        .allowProtocol(ZERO32)
        .allowToken(ZERO32)
        .maxValuePerTx(0n)
        .maxValueTotal(0n)
        .validFrom(0n)
        .validUntil(0n)
        .build();
      expect(p.allowedAction).toBe(ActionType.Transfer);
    });
  });

  describe("method chaining", () => {
    it("each setter returns the same builder instance", () => {
      const b = new PolicyBuilder();
      expect(b.allowAction(ActionType.Swap)).toBe(b);
      expect(b.allowProtocol(ZERO32)).toBe(b);
      expect(b.allowToken(ZERO32)).toBe(b);
      expect(b.maxValuePerTx(0n)).toBe(b);
      expect(b.maxValueTotal(0n)).toBe(b);
      expect(b.validFrom(0n)).toBe(b);
      expect(b.validUntil(0n)).toBe(b);
    });
  });

  describe("encode()", () => {
    it("produces a 97-byte Uint8Array", () => {
      expect(PolicyBuilder.encode(fullPolicy())).toHaveLength(97);
    });

    it("encodes ActionType in the first byte", () => {
      const base = {
        allowedProtocol: ZERO32,
        allowedToken: ZERO32,
        maxValuePerTx: 0n,
        maxValueTotal: 0n,
        validFrom: 0n,
        validUntil: 0n,
      };
      expect(PolicyBuilder.encode({ ...base, allowedAction: ActionType.Swap })[0]).toBe(0);
      expect(PolicyBuilder.encode({ ...base, allowedAction: ActionType.Transfer })[0]).toBe(1);
      expect(PolicyBuilder.encode({ ...base, allowedAction: ActionType.Deposit })[0]).toBe(2);
      expect(PolicyBuilder.encode({ ...base, allowedAction: ActionType.Withdraw })[0]).toBe(3);
    });

    it("encodes maxValuePerTx as big-endian uint64 at offset 65", () => {
      const encoded = PolicyBuilder.encode({
        allowedAction: ActionType.Swap,
        allowedProtocol: ZERO32,
        allowedToken: ZERO32,
        maxValuePerTx: 256n,
        maxValueTotal: 0n,
        validFrom: 0n,
        validUntil: 0n,
      });
      // 256 = 0x0000000000000100: byte[71]=1, byte[72]=0
      expect(encoded[71]).toBe(1);
      expect(encoded[72]).toBe(0);
    });

    it("rejects numeric fields outside u64 range", () => {
      const base = fullPolicy();
      expect(() => PolicyBuilder.encode({ ...base, maxValuePerTx: 1n << 64n })).toThrow(
        "maxValuePerTx must fit in u64",
      );
      expect(() => PolicyBuilder.encode({ ...base, maxValueTotal: -1n })).toThrow(
        "maxValueTotal must fit in u64",
      );
      expect(() => PolicyBuilder.encode({ ...base, validFrom: 1n << 64n })).toThrow(
        "validFrom must fit in u64",
      );
      expect(() => PolicyBuilder.encode({ ...base, validUntil: -1n })).toThrow(
        "validUntil must fit in u64",
      );
    });

    it("rejects protocol or token values that are not bytes32", () => {
      const base = fullPolicy();
      expect(() => PolicyBuilder.encode({ ...base, allowedProtocol: "0x1234" })).toThrow(
        "policy bytes32 field must be a 32-byte hex string",
      );
      expect(() =>
        PolicyBuilder.encode({ ...base, allowedToken: `0x${"11".repeat(33)}` }),
      ).toThrow("policy bytes32 field must be a 32-byte hex string");
    });

    it("produces different encodings for different policies", () => {
      const base = fullPolicy();
      const altered = { ...base, maxValuePerTx: 999n };
      const a = Buffer.from(PolicyBuilder.encode(base)).toString("hex");
      const b = Buffer.from(PolicyBuilder.encode(altered)).toString("hex");
      expect(a).not.toBe(b);
    });
  });
});
