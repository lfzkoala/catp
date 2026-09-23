import type { ToolAction } from "../runtime/types.js";
import type { CatpPolicy } from "../policy/types.js";
import { stableStringify, sha256Hex } from "./canonical.js";

/**
 * The exact, normalized action evidence CATP binds a decision to.
 *
 * This is the adapter-normalized `ToolAction` projected onto security-relevant
 * fields. The runtime-specific `raw` payload is deliberately excluded: it may
 * carry noise and secrets and is never part of a commitment.
 */
export interface CanonicalToolActionV1 {
  schema: "catp_tool_action_v1";
  runtime: ToolAction["runtime"];
  phase: ToolAction["phase"];
  /** Present only when the runtime supplied a session id; absent otherwise. */
  session_id?: string;
  tool_name: string;
  tool_input: Record<string, unknown>;
}

/**
 * Domain separators. Every commitment is SHA-256 over a fixed ASCII domain
 * string followed by the canonical JSON bytes, so identical content under
 * different roles can never collide across domains.
 */
const ACTION_DOMAIN = "catp:action:v1\n";
const POLICY_DOMAIN = "catp:policy:v1\n";

/**
 * Project a runtime `ToolAction` onto its canonical evidence form.
 *
 * The optional `session_id` is omitted entirely when absent so it does not
 * participate in the commitment as an explicit `undefined`/`null`.
 */
export function canonicalizeToolAction(action: ToolAction): CanonicalToolActionV1 {
  const canonical: CanonicalToolActionV1 = {
    schema: "catp_tool_action_v1",
    runtime: action.runtime,
    phase: action.phase,
    tool_name: action.toolName,
    tool_input: action.toolInput,
  };
  if (typeof action.sessionId === "string") {
    canonical.session_id = action.sessionId;
  }
  return canonical;
}

/**
 * action_commitment = SHA256("catp:action:v1\n" || stable_json(canonical_action))
 *
 * Accepts the canonical evidence form (the object persisted as the action
 * sidecar) so enforcement, export, and receipt verification all hash the exact
 * same bytes.
 */
export function computeActionCommitment(canonical: CanonicalToolActionV1): string {
  return sha256Hex(ACTION_DOMAIN + stableStringify(canonical));
}

/**
 * policy_commitment = SHA256("catp:policy:v1\n" || stable_json(normalized_policy))
 *
 * The normalized policy is the `CatpPolicy` returned by the loader at the same
 * enforcement invocation that produced the decision.
 *
 * Determinism caveat: `stableStringify` sorts object keys but PRESERVES array
 * order. The caller MUST pass a policy whose array fields (notably `rules`) are
 * in a deterministic order, otherwise the same TOML can yield different
 * commitments across invocations.
 */
export function computePolicyCommitment(policy: CatpPolicy): string {
  return sha256Hex(POLICY_DOMAIN + stableStringify(policy));
}
