import { Action, ActionType } from "./types.js";
import type { AuthorizationPolicy, Groth16AuthorizationCall } from "./types.js";

export interface AuthorizerClientConfig {
  contractAddress: `0x${string}`;
  rpcUrl: string;
}

export interface PolicyStatus {
  isActive: boolean;
  cumulativeSpend: bigint;
}

export type ExecuteAuthorizedArgs = readonly [
  policyCommitment: `0x${string}`,
  actionData: `0x${string}`,
  currentTimestamp: bigint,
  proof: `0x${string}`,
];

export const AGENT_AUTHORIZER_ABI = [
  {
    name: "registerPolicy",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "policyCommitment", type: "bytes32" }],
    outputs: [],
  },
  {
    name: "revokePolicy",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "policyCommitment", type: "bytes32" }],
    outputs: [],
  },
  {
    name: "executeAuthorized",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "policyCommitment", type: "bytes32" },
      { name: "actionData", type: "bytes" },
      { name: "currentTimestamp", type: "uint256" },
      { name: "proof", type: "bytes" },
    ],
    outputs: [],
  },
  {
    name: "isPolicyActive",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "policyCommitment", type: "bytes32" }],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    name: "getCumulativeSpend",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "policyCommitment", type: "bytes32" }],
    outputs: [{ name: "", type: "uint256" }],
  },
] as const;

const MAX_U64 = (1n << 64n) - 1n;

export function encodeActionData(action: Action): `0x${string}` {
  assertPositiveU64(action.value, "action.value");
  const buf = new ArrayBuffer(128);
  const view = new DataView(buf);

  view.setUint32(28, action.actionType, false);

  const encodeHex = (hex: string, offset: number) => {
    assertBytes32Hex(hex, "action bytes32 field");
    const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
    for (let i = 0; i < 32; i++) {
      view.setUint8(offset + i, parseInt(clean.slice(i * 2, i * 2 + 2), 16));
    }
  };

  encodeHex(action.protocol, 32);
  encodeHex(action.token, 64);

  for (let i = 7; i >= 0; i--) {
    view.setUint8(96 + (7 - i), Number((action.value >> BigInt(i * 8)) & 0xffn));
  }

  return bufferToHex(new Uint8Array(buf));
}

export function executeAuthorizedArgsFromGroth16Call(
  call: Groth16AuthorizationCall,
): ExecuteAuthorizedArgs {
  if (call.proofVersion !== "authorization_groth16_v1") {
    throw new Error("Groth16 call proofVersion must be authorization_groth16_v1");
  }
  assertBytes32Hex(call.policyCommitment, "policyCommitment");
  assertHex(call.actionData, "actionData");
  assertU64(call.currentTimestamp, "currentTimestamp");
  assertHex(call.proof, "proof");
  if (hexByteLength(call.proof) !== 256) {
    throw new Error("proof must be 256 bytes");
  }
  if (call.publicInputs.policyCommitment.toLowerCase() !== call.policyCommitment.toLowerCase()) {
    throw new Error("publicInputs.policyCommitment must equal policyCommitment");
  }
  if (call.publicInputs.currentTimestamp !== call.currentTimestamp) {
    throw new Error("publicInputs.currentTimestamp must equal currentTimestamp");
  }
  return [call.policyCommitment, call.actionData, call.currentTimestamp, call.proof] as const;
}

function assertPositiveU64(value: bigint, field: string): void {
  if (value <= 0n || value > MAX_U64) {
    throw new Error(`${field} must be between 1 and u64::MAX`);
  }
}

function assertU64(value: bigint, field: string): void {
  if (value < 0n || value > MAX_U64) {
    throw new Error(`${field} must fit in u64`);
  }
}

function assertBytes32Hex(hex: string, field: string): void {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (!/^[0-9a-fA-F]{64}$/.test(clean)) {
    throw new Error(`${field} must be a 32-byte hex string`);
  }
}

function assertHex(hex: string, field: string): void {
  if (!hex.startsWith("0x")) {
    throw new Error(`${field} must be 0x-prefixed hex`);
  }
  const clean = hex.slice(2);
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
    throw new Error(`${field} must be an even-length hex string`);
  }
}

function hexByteLength(hex: string): number {
  return (hex.length - 2) / 2;
}

/** Compute the Poseidon-BN254 policy commitment via the catp-wasm module.
 *  Returns a `bytes32` hex string suitable for `registerPolicy` and `publicInputs[0]`.
 */
export function computePolicyCommitment(
  policy: AuthorizationPolicy,
  wasm: { compute_policy_commitment: (policy_json: string) => Uint8Array },
): `0x${string}` {
  assertU64(policy.maxValuePerTx, "maxValuePerTx");
  assertU64(policy.maxValueTotal, "maxValueTotal");
  assertU64(policy.validFrom, "validFrom");
  assertU64(policy.validUntil, "validUntil");

  const ACTION_NAME = ["Swap", "Transfer", "Deposit", "Withdraw"] as const;
  const policyJson = JSON.stringify({
    allowed_action: ACTION_NAME[policy.allowedAction],
    allowed_protocol: Array.from(hexToBytes(policy.allowedProtocol as `0x${string}`)),
    allowed_token: Array.from(hexToBytes(policy.allowedToken as `0x${string}`)),
    max_value_per_tx: policy.maxValuePerTx.toString(),
    max_value_total: policy.maxValueTotal.toString(),
    valid_from: policy.validFrom.toString(),
    valid_until: policy.validUntil.toString(),
  });
  return bufferToHex(wasm.compute_policy_commitment(policyJson));
}

function hexToBytes(hex: `0x${string}`): Uint8Array {
  assertBytes32Hex(hex, "policy bytes32 field");
  const h = hex.slice(2);
  const bytes = new Uint8Array(h.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bufferToHex(buf: Uint8Array): `0x${string}` {
  return ("0x" +
    Array.from(buf)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")) as `0x${string}`;
}

export { ActionType };
