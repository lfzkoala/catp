import { describe, it, expect, afterEach } from '@jest/globals';
import { existsSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import {
  computeCommitment,
  summarizeInput,
  buildEntry,
  appendAuditEntry,
  getLastCommitment,
  auditDir,
} from '../../src/audit/logger.js';
import type { HookInput } from '../../src/policy/types.js';

const TEST_AGENT = `__test__${Date.now()}`;

afterEach(() => {
  const base = join(homedir(), '.catp', 'audit', TEST_AGENT);
  if (existsSync(base)) {
    rmSync(base, { recursive: true, force: true });
  }
});

const makeInput = (tool: string, toolInput: Record<string, unknown> = {}): HookInput => ({
  tool_name: tool,
  tool_input: toolInput,
});

describe('computeCommitment', () => {
  it('is deterministic for the same inputs', () => {
    const a = computeCommitment('Bash', 'allow', '2026-01-01T00:00:00.000Z', '0');
    const b = computeCommitment('Bash', 'allow', '2026-01-01T00:00:00.000Z', '0');
    expect(a).toBe(b);
  });

  it('returns a 64-character hex string (SHA-256)', () => {
    const h = computeCommitment('Bash', 'allow', '2026-01-01T00:00:00.000Z', '0');
    expect(h).toMatch(/^[0-9a-f]{64}$/);
  });

  it('changes when tool changes', () => {
    const a = computeCommitment('Bash', 'allow', '2026-01-01T00:00:00.000Z', '0');
    const b = computeCommitment('Write', 'allow', '2026-01-01T00:00:00.000Z', '0');
    expect(a).not.toBe(b);
  });

  it('changes when decision changes', () => {
    const a = computeCommitment('Bash', 'allow', '2026-01-01T00:00:00.000Z', '0');
    const b = computeCommitment('Bash', 'deny', '2026-01-01T00:00:00.000Z', '0');
    expect(a).not.toBe(b);
  });

  it('changes when timestamp changes', () => {
    const a = computeCommitment('Bash', 'allow', '2026-01-01T00:00:00.000Z', '0');
    const b = computeCommitment('Bash', 'allow', '2026-01-02T00:00:00.000Z', '0');
    expect(a).not.toBe(b);
  });

  it('chains on the previous commitment', () => {
    const first = computeCommitment('Bash', 'allow', '2026-01-01T00:00:00.000Z', '0');
    const withChain = computeCommitment('Write', 'deny', '2026-01-01T00:00:01.000Z', first);
    const withoutChain = computeCommitment('Write', 'deny', '2026-01-01T00:00:01.000Z', '0');
    expect(withChain).not.toBe(withoutChain);
  });

  it('defaults prev to "0"', () => {
    const a = computeCommitment('Bash', 'allow', '2026-01-01T00:00:00.000Z');
    const b = computeCommitment('Bash', 'allow', '2026-01-01T00:00:00.000Z', '0');
    expect(a).toBe(b);
  });
});

describe('summarizeInput', () => {
  it('returns the JSON string unchanged when it is short', () => {
    const result = summarizeInput(makeInput('Bash', { command: 'ls' }));
    expect(result).toBe(JSON.stringify({ command: 'ls' }));
  });

  it('truncates and appends ellipsis when longer than 200 chars', () => {
    const result = summarizeInput(makeInput('Write', { data: 'x'.repeat(300) }));
    expect(result.endsWith('…')).toBe(true);
    expect(result.length).toBe(201); // 200 chars + '…'
  });
});

describe('auditDir', () => {
  it('returns path under ~/.catp/audit/<agentId>/<today>', () => {
    const dir = auditDir('my-agent');
    const today = new Date().toISOString().slice(0, 10);
    expect(dir).toContain(join('.catp', 'audit', 'my-agent', today));
    expect(dir).toContain(homedir());
  });
});

describe('getLastCommitment', () => {
  it('returns "0" when the log file does not exist', () => {
    expect(getLastCommitment(TEST_AGENT)).toBe('0');
  });
});

describe('appendAuditEntry + getLastCommitment', () => {
  it('round-trips: appended commitment is readable via getLastCommitment', () => {
    const commitment = computeCommitment('Bash', 'allow', '2026-01-01T00:00:00.000Z', '0');
    appendAuditEntry(TEST_AGENT, {
      ts: '2026-01-01T00:00:00.000Z',
      tool: 'Bash',
      decision: 'allow',
      rule_matched: null,
      commitment,
      input_summary: 'test',
    });
    expect(getLastCommitment(TEST_AGENT)).toBe(commitment);
  });

  it('returns the last entry commitment after multiple appends', () => {
    const c1 = computeCommitment('Bash', 'allow', '2026-01-01T00:00:00.000Z', '0');
    const c2 = computeCommitment('Write', 'deny', '2026-01-01T00:00:01.000Z', c1);

    appendAuditEntry(TEST_AGENT, {
      ts: '2026-01-01T00:00:00.000Z', tool: 'Bash', decision: 'allow',
      rule_matched: null, commitment: c1, input_summary: 'first',
    });
    appendAuditEntry(TEST_AGENT, {
      ts: '2026-01-01T00:00:01.000Z', tool: 'Write', decision: 'deny',
      rule_matched: 'no-writes', commitment: c2, input_summary: 'second',
    });

    expect(getLastCommitment(TEST_AGENT)).toBe(c2);
  });
});

describe('buildEntry', () => {
  it('returns a valid AuditEntry with correct fields', () => {
    const entry = buildEntry(makeInput('Bash', { command: 'ls' }), 'allow', 'my-rule');
    expect(entry.tool).toBe('Bash');
    expect(entry.decision).toBe('allow');
    expect(entry.rule_matched).toBe('my-rule');
    expect(entry.commitment).toMatch(/^[0-9a-f]{64}$/);
    expect(entry.input_summary).toContain('ls');
    expect(new Date(entry.ts).getTime()).not.toBeNaN();
  });

  it('accepts null for rule_matched', () => {
    const entry = buildEntry(makeInput('Read', {}), 'allow', null);
    expect(entry.rule_matched).toBeNull();
  });

  it('chains on the provided prev commitment', () => {
    const prev = 'a'.repeat(64);
    const entry = buildEntry(makeInput('Bash', {}), 'allow', null, prev);
    const expected = computeCommitment('Bash', 'allow', entry.ts, prev);
    expect(entry.commitment).toBe(expected);
  });

  it('defaults prev to "0" when not provided', () => {
    const entry = buildEntry(makeInput('Bash', {}), 'deny', null);
    const expected = computeCommitment('Bash', 'deny', entry.ts, '0');
    expect(entry.commitment).toBe(expected);
  });
});
