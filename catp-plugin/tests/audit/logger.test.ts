import { describe, it, expect, afterEach } from '@jest/globals';
import { existsSync, mkdirSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  computeCommitment,
  computeCommitmentV4,
  summarizeInput,
  buildEntry,
  extractAuthorizationAction,
  appendAuditEntry,
  appendChainedAuditEntry,
  getLastCommitment,
  auditDir,
} from '../../src/audit/logger.js';
import {
  canonicalizeToolAction,
  computeActionCommitment,
  computePolicyCommitment,
} from '../../src/evidence/commitments.js';
import { auditRoot } from '../../src/audit/paths.js';
import type { CatpPolicy } from '../../src/policy/types.js';
import type { ToolAction } from '../../src/runtime/types.js';

const TEST_AGENT = `__test__${Date.now()}`;
const TEST_HOME = join(tmpdir(), `catp-plugin-test-${Date.now()}`);

process.env.CATP_HOME = TEST_HOME;

afterEach(() => {
  const base = join(TEST_HOME, 'audit', TEST_AGENT);
  if (existsSync(base)) {
    rmSync(base, { recursive: true, force: true });
  }
});

const makeInput = (tool: string, toolInput: Record<string, unknown> = {}): ToolAction => ({
  runtime: 'test-runtime',
  phase: 'pre',
  toolName: tool,
  toolInput,
});

const TEST_POLICY: CatpPolicy = { agent: { id: 'test', version: '1' }, rules: [] };

// Build the enforcement-time bindings buildEntry now requires. The action
// commitment is the real digest over the canonical action so v4 entries are
// internally consistent.
const bindingsFor = (input: ToolAction, reason = 'test-reason') => ({
  reason,
  policyCommitment: computePolicyCommitment(TEST_POLICY),
  actionCommitment: computeActionCommitment(canonicalizeToolAction(input)),
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
  it('returns path under CATP_HOME/audit/<agentId>/<today>', () => {
    const dir = auditDir('my-agent');
    const today = new Date().toISOString().slice(0, 10);
    expect(dir).toBe(join(TEST_HOME, 'audit', 'my-agent', today));
  });

  it.each(['../outside', 'agent/child', 'agent\\child', '.', '..'])(
    'rejects unsafe agent id %s',
    (agentId) => {
      expect(() => auditRoot(agentId)).toThrow('agent id');
    },
  );

  it.each(['agent-1', 'agent.v1', '__test__'])(
    'accepts safe agent id %s',
    (agentId) => {
      expect(auditRoot(agentId)).toBe(join(TEST_HOME, 'audit', agentId));
    },
  );
});

describe('getLastCommitment', () => {
  it('returns "0" when the log file does not exist', () => {
    expect(getLastCommitment(TEST_AGENT)).toBe('0');
  });

  it('throws when the existing log tail is malformed', () => {
    const dir = auditDir(TEST_AGENT);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'actions.jsonl'), 'not-json\n', 'utf8');

    expect(() => getLastCommitment(TEST_AGENT)).toThrow();
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

  it('recovers the tail from large daily files without scanning them', () => {
    const dir = auditDir(TEST_AGENT);
    mkdirSync(dir, { recursive: true });
    const inputSummary = 'x'.repeat(200);
    const ts = '2026-01-01T00:00:00.000Z';
    const lines: string[] = [];
    let prev = '0';
    // ~3000 bounded entries push the daily file far past the 64 KiB tail window.
    for (let i = 0; i < 3000; i++) {
      prev = computeCommitment('Bash', 'allow', ts, prev, null, inputSummary, undefined, 3, 'pre');
      lines.push(JSON.stringify({
        commitment_version: 3,
        phase: 'pre',
        ts,
        tool: 'Bash',
        decision: 'allow',
        rule_matched: null,
        commitment: prev,
        input_summary: inputSummary,
      }));
    }
    writeFileSync(join(dir, 'actions.jsonl'), lines.join('\n') + '\n', 'utf8');

    expect(getLastCommitment(TEST_AGENT)).toBe(prev);
  });

  it('throws when the file is a single line larger than the tail window', () => {
    const dir = auditDir(TEST_AGENT);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'actions.jsonl'), 'x'.repeat(70_000), 'utf8');

    expect(() => getLastCommitment(TEST_AGENT)).toThrow('invalid audit log tail');
  });
});

describe('appendChainedAuditEntry', () => {
  it('builds each entry from the latest commitment while holding the audit lock', () => {
    const first = appendChainedAuditEntry(TEST_AGENT, (prev) =>
      ({ auditEntry: buildEntry(makeInput('Bash'), 'allow', null, prev, bindingsFor(makeInput('Bash'))) }),
    );
    const second = appendChainedAuditEntry(TEST_AGENT, (prev) =>
      ({ auditEntry: buildEntry(makeInput('Write'), 'allow', null, prev, bindingsFor(makeInput('Write'))) }),
    );

    const bindings = bindingsFor(makeInput('Write'));
    expect(second.auditEntry.commitment).toBe(
      computeCommitmentV4({
        phase: 'pre',
        tool: 'Write',
        decision: 'allow',
        ts: second.auditEntry.ts,
        ruleMatched: null,
        reason: bindings.reason,
        inputSummary: '{}',
        policyCommitment: bindings.policyCommitment,
        actionCommitment: bindings.actionCommitment,
        authorization: undefined,
        prev: first.auditEntry.commitment,
      }),
    );
  });

  it('releases the audit lock when entry construction fails', () => {
    expect(() => appendChainedAuditEntry(TEST_AGENT, () => {
      throw new Error('build failed');
    })).toThrow('build failed');

    expect(() => appendChainedAuditEntry(TEST_AGENT, (prev) =>
      ({ auditEntry: buildEntry(makeInput('Bash'), 'allow', null, prev, bindingsFor(makeInput('Bash'))) }),
    )).not.toThrow();
  });

  it('recovers an abandoned audit lock', () => {
    const dir = auditDir(TEST_AGENT);
    const lockDir = join(dir, '.actions.lock');
    mkdirSync(lockDir, { recursive: true });
    utimesSync(lockDir, new Date(0), new Date(0));

    expect(() => appendChainedAuditEntry(TEST_AGENT, (prev) =>
      ({ auditEntry: buildEntry(makeInput('Bash'), 'allow', null, prev, bindingsFor(makeInput('Bash'))) }),
    )).not.toThrow();
  });
});

describe('buildEntry', () => {
  it('returns a valid v4 AuditEntry with correct fields', () => {
    const input = makeInput('Bash', { command: 'ls' });
    const entry = buildEntry(input, 'allow', 'my-rule', '0', bindingsFor(input, 'my-reason'));
    expect(entry.commitment_version).toBe(4);
    expect(entry.tool).toBe('Bash');
    expect(entry.decision).toBe('allow');
    expect(entry.rule_matched).toBe('my-rule');
    expect(entry.reason).toBe('my-reason');
    expect(entry.commitment).toMatch(/^[0-9a-f]{64}$/);
    expect(entry.policy_commitment).toMatch(/^[0-9a-f]{64}$/);
    expect(entry.action_commitment).toMatch(/^[0-9a-f]{64}$/);
    expect(entry.input_summary).toContain('ls');
    expect(new Date(entry.ts).getTime()).not.toBeNaN();
  });

  it('always contains both enforcement-time bindings', () => {
    const input = makeInput('Bash', { command: 'ls' });
    const entry = buildEntry(input, 'allow', null, '0', bindingsFor(input));
    expect(entry.policy_commitment).toBe(computePolicyCommitment(TEST_POLICY));
    expect(entry.action_commitment).toBe(computeActionCommitment(canonicalizeToolAction(input)));
  });

  it('accepts null for rule_matched', () => {
    const input = makeInput('Read', {});
    const entry = buildEntry(input, 'allow', null, '0', bindingsFor(input));
    expect(entry.rule_matched).toBeNull();
  });

  it('chains on the provided prev commitment', () => {
    const prev = 'a'.repeat(64);
    const input = makeInput('Bash', {});
    const bindings = bindingsFor(input);
    const entry = buildEntry(input, 'allow', null, prev, bindings);
    const expected = computeCommitmentV4({
      phase: 'pre',
      tool: 'Bash',
      decision: 'allow',
      ts: entry.ts,
      ruleMatched: null,
      reason: bindings.reason,
      inputSummary: '{}',
      policyCommitment: bindings.policyCommitment,
      actionCommitment: bindings.actionCommitment,
      authorization: undefined,
      prev,
    });
    expect(entry.commitment).toBe(expected);
    expect(entry.commitment_version).toBe(4);
  });

  it('attaches structured authorization action data when present', () => {
    const authorization = {
      actionType: 'Swap',
      protocol: `0x${'aa'.repeat(32)}`,
      token: `0x${'bb'.repeat(32)}`,
      value: '500',
      currentTimestamp: '150',
      cumulativeSpend: '0',
    };
    const input = makeInput('Bash', { catp_authorization: authorization });
    const entry = buildEntry(input, 'allow', null, '0', bindingsFor(input));
    expect(entry.authorization).toEqual(authorization);
  });

  it('does not let a display-summary change substitute for action evidence', () => {
    // Two actions whose capped display summaries are identical (the difference
    // is beyond the 200-char cap) must still have distinct action commitments.
    // input_summary is display-only and non-authoritative.
    const prefix = 'x'.repeat(250);
    const a = makeInput('Write', { data: `${prefix}SAFE` });
    const b = makeInput('Write', { data: `${prefix}DESTRUCTIVE` });
    expect(summarizeInput(a)).toBe(summarizeInput(b));

    const entryA = buildEntry(a, 'allow', null, '0', bindingsFor(a));
    const entryB = buildEntry(b, 'allow', null, '0', bindingsFor(b));
    expect(entryA.input_summary).toBe(entryB.input_summary);
    expect(entryA.action_commitment).not.toBe(entryB.action_commitment);
  });
});

describe('extractAuthorizationAction', () => {
  it('returns undefined when authorization action data is incomplete', () => {
    expect(extractAuthorizationAction(makeInput('Bash', { catp_authorization: { actionType: 'Swap' } }))).toBeUndefined();
  });
});
