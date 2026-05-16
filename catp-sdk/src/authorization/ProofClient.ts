import type { Action, AuthorizationPolicy, AuthorizationPublicInputs } from "./types.js";
import { ActionType } from "./types.js";

export interface ProofResult {
  proof: `0x${string}`;
  publicInputs: AuthorizationPublicInputs;
}

/**
 * Subset of the local catp-circuits/wasm exports used by the Halo2/off-chain
 * authorization_v1 path.
 *
 * This is not the active Groth16/EVM proof path and is not currently published
 * as a separate catp-wasm npm package.
 */
export interface WasmProver {
  compute_policy_commitment(policy_json: string): Uint8Array;
  prove_authorization(
    policy_json: string,
    action_json: string,
    policy_commitment_be: Uint8Array,
    current_timestamp: bigint,
    cumulative_spend: bigint,
  ): Uint8Array;
}

// Rust serde serializes unit enum variants as strings.
const ACTION_TYPE_NAME: Record<ActionType, string> = {
  [ActionType.Swap]: "Swap",
  [ActionType.Transfer]: "Transfer",
  [ActionType.Deposit]: "Deposit",
  [ActionType.Withdraw]: "Withdraw",
};

const MAX_U64 = (1n << 64n) - 1n;

function hexToBytes(hex: `0x${string}`, field: string): Uint8Array {
  assertHex(hex, field);
  const h = hex.slice(2);
  const bytes = new Uint8Array(h.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytes32ToBytes(hex: `0x${string}`, field: string): Uint8Array {
  assertBytes32Hex(hex, field);
  return hexToBytes(hex, field);
}

function assertHex(hex: `0x${string}`, field: string): void {
  if (!hex.startsWith("0x")) {
    throw new Error(`${field} must be 0x-prefixed hex`);
  }
  const h = hex.slice(2);
  if (h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) {
    throw new Error(`${field} must be an even-length hex string`);
  }
}

function assertBytes32Hex(hex: `0x${string}`, field: string): void {
  if (!hex.startsWith("0x")) {
    throw new Error(`${field} must be 0x-prefixed hex`);
  }
  const h = hex.slice(2);
  if (!/^[0-9a-fA-F]{64}$/.test(h)) {
    throw new Error(`${field} must be a 32-byte hex string`);
  }
}

function assertU64(value: bigint, field: string): void {
  if (value < 0n || value > MAX_U64) {
    throw new Error(`${field} must fit in u64`);
  }
}

function assertPositiveU64(value: bigint, field: string): void {
  if (value <= 0n || value > MAX_U64) {
    throw new Error(`${field} must be between 1 and u64::MAX`);
  }
}

function u64LimbsLE(hex: `0x${string}`): [bigint, bigint, bigint, bigint] {
  const bytes = bytes32ToBytes(hex, "action bytes32 field");
  const limbs: bigint[] = [];
  for (let limb = 0; limb < 4; limb++) {
    let value = 0n;
    for (let i = 0; i < 8; i++) {
      value |= BigInt(bytes[limb * 8 + i]) << BigInt(i * 8);
    }
    limbs.push(value);
  }
  return limbs as [bigint, bigint, bigint, bigint];
}

function bytesToHex(bytes: Uint8Array): `0x${string}` {
  return `0x${Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")}`;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

export class ProofClient {
  /**
   * @param wasm - local catp-circuits/wasm module built with `npm run wasm:build`
   * @param verifyUrl - base URL of a running catp-verify server
   */
  constructor(
    private readonly wasm: WasmProver,
    private readonly verifyUrl = "http://localhost:3030",
  ) {}

  async prove(
    policy: AuthorizationPolicy,
    action: Action,
    cumulativeSpend: bigint,
  ): Promise<ProofResult> {
    assertU64(policy.maxValuePerTx, "maxValuePerTx");
    assertU64(policy.maxValueTotal, "maxValueTotal");
    assertU64(policy.validFrom, "validFrom");
    assertU64(policy.validUntil, "validUntil");
    assertPositiveU64(action.value, "action.value");
    assertU64(cumulativeSpend, "cumulativeSpend");

    const currentTimestamp = BigInt(Math.floor(Date.now() / 1000));

    const policyJson = JSON.stringify({
      allowed_action: ACTION_TYPE_NAME[policy.allowedAction],
      allowed_protocol: Array.from(bytes32ToBytes(policy.allowedProtocol, "policy bytes32 field")),
      allowed_token: Array.from(bytes32ToBytes(policy.allowedToken, "policy bytes32 field")),
      max_value_per_tx: policy.maxValuePerTx.toString(),
      max_value_total: policy.maxValueTotal.toString(),
      valid_from: policy.validFrom.toString(),
      valid_until: policy.validUntil.toString(),
    });

    const actionJson = JSON.stringify({
      action_type: ACTION_TYPE_NAME[action.actionType],
      protocol: Array.from(bytes32ToBytes(action.protocol, "action bytes32 field")),
      token: Array.from(bytes32ToBytes(action.token, "action bytes32 field")),
      value: action.value.toString(),
    });

    const commitmentBe = this.wasm.compute_policy_commitment(policyJson);
    const policyCommitment = bytesToHex(commitmentBe);

    const proofBytes = this.wasm.prove_authorization(
      policyJson,
      actionJson,
      commitmentBe,
      currentTimestamp,
      cumulativeSpend,
    );

    return {
      proof: bytesToHex(proofBytes),
      publicInputs: {
        policyCommitment,
        actionType: BigInt(action.actionType),
        actionProtocol: u64LimbsLE(action.protocol),
        actionToken: u64LimbsLE(action.token),
        actionValue: action.value,
        currentTimestamp,
        cumulativeSpend,
      },
    };
  }

  /** Verify a proof via the catp-verify REST endpoint. */
  async verify(
    proof: `0x${string}`,
    publicInputs: AuthorizationPublicInputs,
  ): Promise<boolean> {
    const base64 = bytesToBase64(hexToBytes(proof, "proof"));
    const res = await fetch(`${this.verifyUrl}/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        proof: base64,
        publicInputs: {
          policyCommitment: publicInputs.policyCommitment,
          actionType: publicInputs.actionType.toString(),
          actionProtocol: publicInputs.actionProtocol.map((v) => v.toString()),
          actionToken: publicInputs.actionToken.map((v) => v.toString()),
          actionValue: publicInputs.actionValue.toString(),
          currentTimestamp: publicInputs.currentTimestamp.toString(),
          cumulativeSpend: publicInputs.cumulativeSpend.toString(),
        },
      }),
    });
    if (!res.ok) throw new Error(`catp-verify returned ${res.status}`);
    const data = (await res.json()) as { valid: boolean; error?: string };
    return data.valid;
  }
}
