import { createHash } from "node:crypto";
import { stableStringify, sha256Hex } from "../../src/evidence/canonical.js";

describe("canonical stableStringify", () => {
  it("sorts object keys recursively", () => {
    const value = { b: 1, a: { d: 2, c: 3 } };
    expect(stableStringify(value)).toBe('{"a":{"c":3,"d":2},"b":1}');
  });

  it("preserves array ordering while sorting keys inside array elements", () => {
    const value = [{ b: 1, a: 2 }, { a: 3 }];
    // Array order is preserved; object keys within each element are sorted.
    expect(stableStringify(value)).toBe('[{"a":2,"b":1},{"a":3}]');
  });

  it("encodes Unicode strings deterministically", () => {
    const value = { s: "héllo — 世界 🔒" };
    const json = stableStringify(value);
    // JSON.stringify keeps non-ASCII characters literally (UTF-8), not escaped.
    expect(json).toBe('{"s":"héllo — 世界 🔒"}');
    expect(Buffer.byteLength(json, "utf8")).toBeGreaterThan(json.length);
  });

  it("serializes booleans, nulls, and numeric values", () => {
    const value = { t: true, f: false, n: null, zero: 0, neg: -1, frac: 1.5, exp: 1e21 };
    expect(stableStringify(value)).toBe(
      '{"exp":1e+21,"f":false,"frac":1.5,"n":null,"neg":-1,"t":true,"zero":0}',
    );
  });

  it("produces identical bytes for objects with different insertion order", () => {
    const first = { a: 1, b: 2, c: { x: 10, y: 20 } };
    const second = { c: { y: 20, x: 10 }, b: 2, a: 1 };
    expect(stableStringify(first)).toBe(stableStringify(second));
  });

  it("produces identical SHA-256 for objects with different insertion order", () => {
    const first = { a: 1, b: [1, 2, 3], c: { x: "y" } };
    const second = { c: { x: "y" }, b: [1, 2, 3], a: 1 };
    expect(sha256Hex(stableStringify(first))).toBe(sha256Hex(stableStringify(second)));
  });

  it("emits no insignificant whitespace by default and honors the spaces argument", () => {
    const value = { a: 1 };
    expect(stableStringify(value)).toBe('{"a":1}');
    expect(stableStringify(value, 2)).toBe('{\n  "a": 1\n}');
  });

  it("matches node:crypto SHA-256 over UTF-8 bytes", () => {
    const input = '{"a":1}';
    expect(sha256Hex(input)).toBe(createHash("sha256").update(input, "utf8").digest("hex"));
    expect(sha256Hex(input)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("rejects non-JSON numeric values instead of coercing them to null", () => {
    expect(() => stableStringify({ n: Number.NaN })).toThrow(/non-JSON numeric/);
    expect(() => stableStringify({ n: Number.POSITIVE_INFINITY })).toThrow(/non-JSON numeric/);
    expect(() => stableStringify({ n: Number.NEGATIVE_INFINITY })).toThrow(/non-JSON numeric/);
    expect(() => stableStringify([{ ok: 1 }, { bad: Number.NaN }])).toThrow(/non-JSON numeric/);
  });

  it("preserves byte-compatibility with the historical JSON.stringify(sort()) output", () => {
    // The shared canonicalizer must not change the bytes of existing v1 audit
    // exports / receipts. For valid JSON it equals JSON.stringify of a
    // recursively key-sorted copy. These samples are load-bearing: a single
    // divergence would invalidate every previously signed receipt.
    const samples: unknown[] = [
      { z: 1, a: [{ b: 2, a: 1 }], m: null },
      { "10": 1, "9": 2, "1": 3 }, // integer-like keys
      { "世界": 1, "é": 2, a: 3 }, // unicode keys
      { d: new Date("2026-01-01T00:00:00.000Z") }, // Date via toJSON
      { t: { toJSON: () => ({ b: 1, a: 2 }) } }, // custom toJSON
      [[null, false, 0, -0, 1e21, 1.5], { x: [true, "s"] }], // nested falsy/edge numbers
      {},
      [],
      "scalar",
      42,
      null,
      true,
    ];
    for (const value of samples) {
      expect(stableStringify(value)).toBe(JSON.stringify(sortLegacy(value)));
    }
  });
});

function sortLegacy(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortLegacy);
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return Object.fromEntries(Object.keys(record).sort().map((k) => [k, sortLegacy(record[k])]));
  }
  return value;
}
