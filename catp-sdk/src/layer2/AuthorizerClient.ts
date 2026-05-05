import { Action, ActionType } from "./types.js";
import type { AuthorizationPolicy } from "./types.js";

export interface AuthorizerClientConfig {
  contractAddress: `0x${string}`;
  rpcUrl: string;
}

export interface PolicyStatus {
  isActive: boolean;
  cumulativeSpend: bigint;
}

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

export function encodeActionData(action: Action): `0x${string}` {
  const buf = new ArrayBuffer(128);
  const view = new DataView(buf);

  view.setUint32(28, action.actionType, false);

  const encodeHex = (hex: string, offset: number) => {
    const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
    const padded = clean.padStart(64, "0");
    for (let i = 0; i < 32; i++) {
      view.setUint8(offset + i, parseInt(padded.slice(i * 2, i * 2 + 2), 16));
    }
  };

  encodeHex(action.protocol, 32);
  encodeHex(action.token, 64);

  for (let i = 7; i >= 0; i--) {
    view.setUint8(96 + (7 - i), Number((action.value >> BigInt(i * 8)) & 0xffn));
  }

  return bufferToHex(new Uint8Array(buf));
}

/** Compute the Poseidon-BN254 policy commitment via the catp-wasm module.
 *  Returns a `bytes32` hex string suitable for `registerPolicy` and `publicInputs[0]`.
 */
export function computePolicyCommitment(
  policy: AuthorizationPolicy,
  wasm: { compute_policy_commitment: (policy_json: string) => Uint8Array },
): `0x${string}` {
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
  const h = hex.slice(2).padStart(64, "0");
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
