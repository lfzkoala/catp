import { afterAll, beforeEach, describe, expect, it } from "@jest/globals";
import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { cmdInit, policyTemplate } from "../../src/commands/init.js";

const tmpBase = join(tmpdir(), `catp-init-test-${Date.now()}`);
const originalCwd = process.cwd();

beforeEach(() => {
  rmSync(tmpBase, { recursive: true, force: true });
  mkdirSync(tmpBase, { recursive: true });
  process.chdir(tmpBase);
});

afterAll(() => {
  process.chdir(originalCwd);
  rmSync(tmpBase, { recursive: true, force: true });
});

describe("policyTemplate", () => {
  it("omits authorization fields by default", () => {
    expect(policyTemplate()).not.toContain("[authorization]");
  });

  it("includes starter authorization fields when requested", () => {
    const template = policyTemplate({ authorization: true });

    expect(template).toContain("[authorization]");
    expect(template).toContain('allowed_action = "Swap"');
    expect(template).toContain("max_value_per_tx");
    expect(template).toContain("valid_until");
  });
});

describe("cmdInit", () => {
  it("creates the default policy template", () => {
    const originalWrite = process.stdout.write.bind(process.stdout);
    let output = "";
    process.stdout.write = ((chunk: string | Uint8Array) => {
      output += chunk.toString();
      return true;
    }) as typeof process.stdout.write;
    try {
      cmdInit();
    } finally {
      process.stdout.write = originalWrite;
    }

    const policyPath = join(tmpBase, "catp-policy.toml");
    expect(existsSync(policyPath)).toBe(true);
    expect(readFileSync(policyPath, "utf8")).not.toContain("[authorization]");
    expect(output).toContain("Created catp-policy.toml");
    expect(output).toContain("2. Run: catp validate");
    expect(output).not.toContain("catp witness");
  });

  it("creates an authorization-ready starter policy", () => {
    const originalWrite = process.stdout.write.bind(process.stdout);
    let output = "";
    process.stdout.write = ((chunk: string | Uint8Array) => {
      output += chunk.toString();
      return true;
    }) as typeof process.stdout.write;
    try {
      cmdInit({ authorization: true });
    } finally {
      process.stdout.write = originalWrite;
    }

    const content = readFileSync(join(tmpBase, "catp-policy.toml"), "utf8");
    expect(content).toContain("[authorization]");
    expect(content).toContain('allowed_action = "Swap"');
    expect(output).toContain("3. Run: catp witness --action <action.json> --out <witness.json>");
  });
});
