import { describe, it, expect, vi, beforeEach } from "vitest";
import { ProofClient, type WasmProver } from "../../src/layer2/ProofClient.js";
import { ActionType } from "../../src/layer2/types.js";

const ZERO32 = `0x${"00".repeat(32)}` as `0x${string}`;
const FAKE_BYTES = new Uint8Array([1, 2, 3, 4, 5]);

const mockWasm: WasmProver = {
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

describe("ProofClient", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.unstubAllGlobals();
  });

  describe("prove()", () => {
    it("calls wasm.prove_authorization once", async () => {
      const client = new ProofClient(mockWasm);
      await client.prove(policy, action, ZERO32, 0n);
      expect(mockWasm.prove_authorization).toHaveBeenCalledOnce();
    });

    it("passes correct action_type string to WASM", async () => {
      const client = new ProofClient(mockWasm);
      await client.prove(policy, action, ZERO32, 0n);
      const [, actionJson] = (mockWasm.prove_authorization as ReturnType<typeof vi.fn>).mock.calls[0] as string[];
      expect(JSON.parse(actionJson).action_type).toBe("Swap");
    });

    it("passes correct value to WASM action JSON", async () => {
      const client = new ProofClient(mockWasm);
      await client.prove(policy, action, ZERO32, 0n);
      const [, actionJson] = (mockWasm.prove_authorization as ReturnType<typeof vi.fn>).mock.calls[0] as string[];
      expect(JSON.parse(actionJson).value).toBe(50);
    });

    it("passes correct policy fields to WASM", async () => {
      const client = new ProofClient(mockWasm);
      await client.prove(policy, action, ZERO32, 0n);
      const [policyJson] = (mockWasm.prove_authorization as ReturnType<typeof vi.fn>).mock.calls[0] as string[];
      const p = JSON.parse(policyJson);
      expect(p.allowed_action).toBe("Swap");
      expect(p.max_value_per_tx).toBe(100);
      expect(p.max_value_total).toBe(1000);
    });

    it("passes cumulative_spend to WASM public inputs", async () => {
      const client = new ProofClient(mockWasm);
      await client.prove(policy, action, ZERO32, 7n);
      const [, , pubJson] = (mockWasm.prove_authorization as ReturnType<typeof vi.fn>).mock.calls[0] as string[];
      expect(JSON.parse(pubJson).cumulative_spend).toBe(7);
    });

    it("returns proof bytes as hex string", async () => {
      const client = new ProofClient(mockWasm);
      const result = await client.prove(policy, action, ZERO32, 0n);
      expect(result.proof).toBe("0x0102030405");
    });

    it("returns publicInputs with policyCommitment and cumulativeSpend", async () => {
      const client = new ProofClient(mockWasm);
      const result = await client.prove(policy, action, ZERO32, 42n);
      expect(result.publicInputs.policyCommitment).toBe(ZERO32);
      expect(result.publicInputs.cumulativeSpend).toBe(42n);
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
      const result = await client.verify("0x0102030405");

      expect(result).toBe(true);
      expect(fetchMock).toHaveBeenCalledWith(
        "http://localhost:3030/verify",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({ proof: "AQIDBAU=" }),
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
      expect(await client.verify("0x0102030405")).toBe(false);
    });

    it("throws when server returns a non-OK status", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 500 }));
      const client = new ProofClient(mockWasm);
      await expect(client.verify("0x0102030405")).rejects.toThrow("catp-verify returned 500");
    });
  });
});
