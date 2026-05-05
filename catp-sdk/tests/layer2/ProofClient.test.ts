import { describe, it, expect, vi, beforeEach } from "vitest";
import { ProofClient, type WasmProver } from "../../src/layer2/ProofClient.js";
import { ActionType } from "../../src/layer2/types.js";

const ZERO32 = `0x${"00".repeat(32)}` as `0x${string}`;
const FAKE_BYTES = new Uint8Array([1, 2, 3, 4, 5]);
// compute_policy_commitment returns 32 zero bytes → policyCommitment = ZERO32
const FAKE_COMMITMENT = new Uint8Array(32);

const mockWasm: WasmProver = {
  compute_policy_commitment: vi.fn(() => FAKE_COMMITMENT),
  prove_authorization: vi.fn(() => FAKE_BYTES),
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

const action = {
  actionType: ActionType.Swap,
  protocol: ZERO32,
  token: ZERO32,
  value: 50n,
};

const publicInputs = {
  policyCommitment: ZERO32,
  actionType: 0n,
  actionProtocol: [0n, 0n, 0n, 0n],
  actionToken: [0n, 0n, 0n, 0n],
  actionValue: 50n,
  currentTimestamp: 123n,
  cumulativeSpend: 0n,
};

describe("ProofClient", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.unstubAllGlobals();
  });

  describe("prove()", () => {
    it("calls wasm.prove_authorization once", async () => {
      const client = new ProofClient(mockWasm);
      await client.prove(policy, action, 0n);
      expect(mockWasm.prove_authorization).toHaveBeenCalledOnce();
    });

    it("calls wasm.compute_policy_commitment once", async () => {
      const client = new ProofClient(mockWasm);
      await client.prove(policy, action, 0n);
      expect(mockWasm.compute_policy_commitment).toHaveBeenCalledOnce();
    });

    it("passes correct action_type string to WASM", async () => {
      const client = new ProofClient(mockWasm);
      await client.prove(policy, action, 0n);
      const [, actionJson] = (mockWasm.prove_authorization as ReturnType<typeof vi.fn>).mock.calls[0] as [string, string];
      expect(JSON.parse(actionJson).action_type).toBe("Swap");
    });

    it("passes correct value to WASM action JSON", async () => {
      const client = new ProofClient(mockWasm);
      await client.prove(policy, action, 0n);
      const [, actionJson] = (mockWasm.prove_authorization as ReturnType<typeof vi.fn>).mock.calls[0] as [string, string];
      expect(JSON.parse(actionJson).value).toBe("50");
    });

    it("passes correct policy fields to WASM", async () => {
      const client = new ProofClient(mockWasm);
      await client.prove(policy, action, 0n);
      const [policyJson] = (mockWasm.prove_authorization as ReturnType<typeof vi.fn>).mock.calls[0] as [string];
      const p = JSON.parse(policyJson);
      expect(p.allowed_action).toBe("Swap");
      expect(p.max_value_per_tx).toBe("100");
      expect(p.max_value_total).toBe("1000");
    });

    it("passes cumulative_spend as bigint to WASM", async () => {
      const client = new ProofClient(mockWasm);
      await client.prove(policy, action, 7n);
      const [, , , , spend] = (mockWasm.prove_authorization as ReturnType<typeof vi.fn>).mock.calls[0] as [string, string, Uint8Array, bigint, bigint];
      expect(spend).toBe(7n);
    });

    it("returns proof bytes as hex string", async () => {
      const client = new ProofClient(mockWasm);
      const result = await client.prove(policy, action, 0n);
      expect(result.proof).toBe("0x0102030405");
    });

    it("returns publicInputs with policyCommitment from WASM and cumulativeSpend", async () => {
      const client = new ProofClient(mockWasm);
      const result = await client.prove(policy, action, 42n);
      expect(result.publicInputs.policyCommitment).toBe(ZERO32);
      expect(result.publicInputs.actionType).toBe(0n);
      expect(result.publicInputs.actionValue).toBe(50n);
      expect(result.publicInputs.cumulativeSpend).toBe(42n);
    });

    it("rejects malformed policy bytes32 fields before calling WASM", async () => {
      const client = new ProofClient(mockWasm);
      await expect(
        client.prove({ ...policy, allowedProtocol: "0x1234" as `0x${string}` }, action, 0n),
      ).rejects.toThrow("policy bytes32 field must be a 32-byte hex string");
      expect(mockWasm.prove_authorization).not.toHaveBeenCalled();
    });

    it("rejects malformed action bytes32 fields before calling WASM", async () => {
      const client = new ProofClient(mockWasm);
      await expect(
        client.prove(policy, { ...action, token: `0x${"00".repeat(31)}zz` as `0x${string}` }, 0n),
      ).rejects.toThrow("action bytes32 field must be a 32-byte hex string");
      expect(mockWasm.prove_authorization).not.toHaveBeenCalled();
    });

    it("rejects unprefixed bytes32 fields before calling WASM", async () => {
      const client = new ProofClient(mockWasm);
      await expect(
        client.prove(policy, { ...action, protocol: "00".repeat(32) as `0x${string}` }, 0n),
      ).rejects.toThrow("action bytes32 field must be 0x-prefixed hex");
      expect(mockWasm.prove_authorization).not.toHaveBeenCalled();
    });

    it("rejects values outside the circuit u64 range before calling WASM", async () => {
      const client = new ProofClient(mockWasm);
      const tooLarge = 1n << 64n;
      await expect(client.prove({ ...policy, maxValueTotal: tooLarge }, action, 0n)).rejects.toThrow(
        "maxValueTotal must fit in u64",
      );
      await expect(client.prove(policy, { ...action, value: -1n }, 0n)).rejects.toThrow(
        "action.value must be between 1 and u64::MAX",
      );
      await expect(client.prove(policy, { ...action, value: 0n }, 0n)).rejects.toThrow(
        "action.value must be between 1 and u64::MAX",
      );
      await expect(client.prove(policy, action, tooLarge)).rejects.toThrow("cumulativeSpend must fit in u64");
      expect(mockWasm.prove_authorization).not.toHaveBeenCalled();
    });
  });

  describe("verify()", () => {
    it("POSTs to /verify with base64-encoded proof and returns true", async () => {
      const fetchMock = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ valid: true }),
      });
      vi.stubGlobal("fetch", fetchMock);

      const client = new ProofClient(mockWasm, "http://localhost:3030");
      const result = await client.verify("0x0102030405", publicInputs);

      expect(result).toBe(true);
      expect(fetchMock).toHaveBeenCalledWith(
        "http://localhost:3030/verify",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({
            proof: "AQIDBAU=",
            publicInputs: {
              policyCommitment: ZERO32,
              actionType: "0",
              actionProtocol: ["0", "0", "0", "0"],
              actionToken: ["0", "0", "0", "0"],
              actionValue: "50",
              currentTimestamp: "123",
              cumulativeSpend: "0",
            },
          }),
        }),
      );
    });

    it("returns false when server reports invalid proof", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue({
          ok: true,
          json: () => Promise.resolve({ valid: false }),
        }),
      );
      const client = new ProofClient(mockWasm);
      expect(await client.verify("0x0102030405", publicInputs)).toBe(false);
    });

    it("throws when server returns a non-OK status", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 500 }));
      const client = new ProofClient(mockWasm);
      await expect(client.verify("0x0102030405", publicInputs)).rejects.toThrow("catp-verify returned 500");
    });

    it("rejects malformed proof hex before POSTing", async () => {
      const fetchMock = vi.fn();
      vi.stubGlobal("fetch", fetchMock);
      const client = new ProofClient(mockWasm);
      await expect(client.verify("0x123" as `0x${string}`, publicInputs)).rejects.toThrow(
        "proof must be an even-length hex string",
      );
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it("rejects unprefixed proof hex before POSTing", async () => {
      const fetchMock = vi.fn();
      vi.stubGlobal("fetch", fetchMock);
      const client = new ProofClient(mockWasm);
      await expect(client.verify("0102" as `0x${string}`, publicInputs)).rejects.toThrow(
        "proof must be 0x-prefixed hex",
      );
      expect(fetchMock).not.toHaveBeenCalled();
    });
  });
});
