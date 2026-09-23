import { createHash } from "node:crypto";

/**
 * Deterministic ("stable") JSON serialization shared by every CATP security
 * commitment and by audit export hashing.
 *
 * Behavior:
 * - Object keys are sorted recursively using the default `Array.prototype.sort`
 *   order (UTF-16 code units), matching the historical audit-export serializer.
 * - Array element order is preserved.
 * - Output is UTF-8 with no insignificant whitespace unless `spaces` > 0.
 * - Non-JSON numeric values (NaN, +Infinity, -Infinity) are REJECTED rather than
 *   silently coerced to `null` by `JSON.stringify`. A commitment must never
 *   quietly hash different evidence than the value the caller intended.
 *
 * Byte-compatibility: for every valid JSON input the output is identical to the
 * historical `stableStringify` previously defined in `commands/log.ts`, so
 * existing `catp_audit_export_v1` bundles and `catp_authorization_receipt_v1`
 * signatures continue to verify unchanged.
 */
export function stableStringify(value: unknown, spaces = 0): string {
  return JSON.stringify(sortAndValidate(value), null, spaces);
}

/** SHA-256 hex digest over the UTF-8 bytes of `input`. */
export function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

function sortAndValidate(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortAndValidate);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error(`cannot canonicalize non-JSON numeric value: ${String(value)}`);
    }
    return value;
  }
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return Object.fromEntries(
      Object.keys(record)
        .sort()
        .map((key) => [key, sortAndValidate(record[key])]),
    );
  }
  return value;
}
