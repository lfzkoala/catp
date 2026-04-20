import type { AuthorizationPolicy, Action, AuthorizationPublicInputs } from "./types.js";

export interface ProofResult {
  proof: `0x${string}`;
  publicInputs: AuthorizationPublicInputs;
}

/**
 * STUB: Returns a placeholder proof. Replace with wasm-pack Halo2 prover in Phase 2
 * once the real on-chain verifier is generated from the circuit.
 */
export class ProofClient {
  async prove(
    _policy: AuthorizationPolicy,
    _action: Action,
    policyCommitment: `0x${string}`,
    cumulativeSpend: bigint,
  ): Promise<ProofResult> {
    return {
      proof: "0xdeadbeef",
      publicInputs: {
        policyCommitment,
        currentTimestamp: BigInt(Math.floor(Date.now() / 1000)),
        cumulativeSpend,
      },
    };
  }
}
