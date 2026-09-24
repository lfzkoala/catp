import { describe, it, expect, afterEach } from '@jest/globals';
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
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
  repairAuditLogTail,
  auditDir,
} from '../../src/audit/logger.js';
import {
  canonicalizeToolAction,
  computeActionCommitment,
  computePolicyCommitment,
} from '../../src/evidence/commitments.js';
import { verifyEntryChain } from '../../src/audit/verifier.js';
import { actionSidecarPath, auditRoot } from '../../src/audit/paths.js';
import { nodeAuditStorage, type AuditStorage } from '../../src/audit/durable.js';
import type { AuditEntry, CatpPolicy } from '../../src/policy/types.js';
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

// A build callback result carrying both the v4 entry and the canonical action
// evidence that appendChainedAuditEntry persists as a content-addressed sidecar.
function chainedResult(
  input: ToolAction,
  decision: 'allow' | 'deny',
  prev: string,
  reason = 'test-reason',
) {
  return {
    auditEntry: buildEntry(input, decision, null, prev, bindingsFor(input, reason)),
    action: canonicalizeToolAction(input),
  };
}

// Locate the daily audit directory from the filesystem rather than re-deriving
// it from the current time, so these helpers cannot flake across a UTC midnight
// boundary between the logger's date and a test's own clock read.
function latestAuditDate(agentId: string): string {
  const dates = readdirSync(auditRoot(agentId)).sort();
  return dates[dates.length - 1];
}

// The sidecar path the logger wrote for a result.
function sidecarFor(entry: { action_commitment: string }): string {
  return actionSidecarPath(TEST_AGENT, latestAuditDate(TEST_AGENT), entry.action_commitment);
}

// nodeAuditStorage with exactly one method forced to throw, so a test can
// simulate a sidecar-fsync or log-fsync failure while everything else (including
// the durable empty-file creation the lock needs) still works.
function failingStorage(method: keyof AuditStorage, message: string): AuditStorage {
  return {
    ...nodeAuditStorage,
    [method]: () => {
      throw new Error(message);
    },
  } as AuditStorage;
}

describe('appendChainedAuditEntry', () => {
  it('builds each entry from the latest commitment while holding the audit lock', () => {
    const first = appendChainedAuditEntry(TEST_AGENT, (prev) =>
      chainedResult(makeInput('Bash'), 'allow', prev),
    );
    const second = appendChainedAuditEntry(TEST_AGENT, (prev) =>
      chainedResult(makeInput('Write'), 'allow', prev),
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

  it('persists the canonical action sidecar named by the entry action_commitment', () => {
    const input = makeInput('Bash', { command: 'ls -la' });
    const result = appendChainedAuditEntry(TEST_AGENT, (prev) =>
      chainedResult(input, 'allow', prev),
    );

    const sidecar = sidecarFor(result.auditEntry);
    expect(existsSync(sidecar)).toBe(true);
    const stored = JSON.parse(readFileSync(sidecar, 'utf8'));
    expect(stored).toEqual(canonicalizeToolAction(input));
    // The sidecar content re-hashes to the commitment the entry records.
    expect(computeActionCommitment(stored)).toBe(result.auditEntry.action_commitment);
  });

  it('gives two actions with an identical 200-char prefix distinct sidecars', () => {
    const prefix = 'x'.repeat(250);
    const a = makeInput('Write', { data: `${prefix}SAFE` });
    const b = makeInput('Write', { data: `${prefix}DESTRUCTIVE` });
    expect(summarizeInput(a)).toBe(summarizeInput(b));

    const ra = appendChainedAuditEntry(TEST_AGENT, (prev) => chainedResult(a, 'allow', prev));
    const rb = appendChainedAuditEntry(TEST_AGENT, (prev) => chainedResult(b, 'allow', prev));

    expect(ra.auditEntry.action_commitment).not.toBe(rb.auditEntry.action_commitment);
    const bodyA = JSON.parse(readFileSync(sidecarFor(ra.auditEntry), 'utf8'));
    const bodyB = JSON.parse(readFileSync(sidecarFor(rb.auditEntry), 'utf8'));
    expect(bodyA.tool_input.data).toBe(`${prefix}SAFE`);
    expect(bodyB.tool_input.data).toBe(`${prefix}DESTRUCTIVE`);
  });

  it('releases the audit lock when entry construction fails', () => {
    expect(() => appendChainedAuditEntry(TEST_AGENT, () => {
      throw new Error('build failed');
    })).toThrow('build failed');

    expect(() => appendChainedAuditEntry(TEST_AGENT, (prev) =>
      chainedResult(makeInput('Bash'), 'allow', prev),
    )).not.toThrow();
  });

  it('recovers an abandoned audit lock', () => {
    const dir = auditDir(TEST_AGENT);
    const lockDir = join(dir, '.actions.lock');
    mkdirSync(lockDir, { recursive: true });
    utimesSync(lockDir, new Date(0), new Date(0));

    expect(() => appendChainedAuditEntry(TEST_AGENT, (prev) =>
      chainedResult(makeInput('Bash'), 'allow', prev),
    )).not.toThrow();
  });

  it('fails closed and commits no entry when the sidecar write fails', () => {
    const storage = failingStorage('writeContentAddressed', 'sidecar fsync failed');
    expect(() =>
      appendChainedAuditEntry(TEST_AGENT, (prev) => chainedResult(makeInput('Bash'), 'allow', prev), storage),
    ).toThrow('sidecar fsync failed');
    // No entry was committed: the chain is still at genesis.
    expect(getLastCommitment(TEST_AGENT)).toBe('0');
  });

  it('fails closed when the audit append fails, leaving at most an unreferenced sidecar', () => {
    const storage = failingStorage('appendLine', 'log fsync failed');
    let commitment = '';
    expect(() =>
      appendChainedAuditEntry(TEST_AGENT, (prev) => {
        const r = chainedResult(makeInput('Bash'), 'allow', prev);
        commitment = r.auditEntry.action_commitment;
        return r;
      }, storage),
    ).toThrow('log fsync failed');
    // The entry was never committed.
    expect(getLastCommitment(TEST_AGENT)).toBe('0');
    // An unreferenced sidecar may remain, which the ordering explicitly allows.
    expect(existsSync(actionSidecarPath(TEST_AGENT, latestAuditDate(TEST_AGENT), commitment))).toBe(true);
  });

  it('refuses to persist when the action evidence does not match the entry binding', () => {
    const entryInput = makeInput('Bash', { command: 'ls' });
    const mismatched = makeInput('Write', { data: 'different' });
    expect(() =>
      appendChainedAuditEntry(TEST_AGENT, (prev) => ({
        auditEntry: buildEntry(entryInput, 'allow', null, prev, bindingsFor(entryInput)),
        action: canonicalizeToolAction(mismatched),
      })),
    ).toThrow('does not match audit entry binding');
    // The mismatched pair is never committed.
    expect(getLastCommitment(TEST_AGENT)).toBe('0');
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

// The daily log file the logger actually wrote (located from disk so it cannot
// flake across a UTC midnight boundary).
function auditFile(): string {
  return join(auditRoot(TEST_AGENT), latestAuditDate(TEST_AGENT), 'actions.jsonl');
}

function readEntries(file: string): AuditEntry[] {
  return readFileSync(file, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l) as AuditEntry);
}

describe('repairAuditLogTail', () => {
  it('reports clean and changes nothing for a well-formed log', () => {
    appendChainedAuditEntry(TEST_AGENT, (prev) => chainedResult(makeInput('Bash'), 'allow', prev));
    const file = auditFile();
    const before = readFileSync(file, 'utf8');

    const result = repairAuditLogTail(TEST_AGENT);

    expect(result.status).toBe('clean');
    expect(result.entries).toBe(1);
    expect(result.removedFragment).toBeNull();
    expect(readFileSync(file, 'utf8')).toBe(before);
  });

  it('truncates a torn non-JSON tail and the next append chains from the last complete entry', () => {
    appendChainedAuditEntry(TEST_AGENT, (prev) => chainedResult(makeInput('Bash', { command: 'one' }), 'allow', prev));
    const r2 = appendChainedAuditEntry(TEST_AGENT, (prev) => chainedResult(makeInput('Bash', { command: 'two' }), 'allow', prev));
    const file = auditFile();
    const good = readFileSync(file, 'utf8');
    expect(good.endsWith('\n')).toBe(true);

    // A crashed append left a partial fragment that is not valid JSON.
    const fragment = '{"commitment_version":4,"too';
    writeFileSync(file, good + fragment, 'utf8');

    const result = repairAuditLogTail(TEST_AGENT);
    expect(result.status).toBe('repaired');
    expect(result.entries).toBe(2);
    expect(result.removedFragment).toBe(fragment);
    expect(readFileSync(file, 'utf8')).toBe(good);

    // The next append connects to r2 (the last complete entry), not the fragment.
    appendChainedAuditEntry(TEST_AGENT, (prev) => {
      expect(prev).toBe(r2.auditEntry.commitment);
      return chainedResult(makeInput('Bash', { command: 'three' }), 'allow', prev);
    });
    expect(readEntries(file)).toHaveLength(3);
    expect(verifyEntryChain(readEntries(file)).ok).toBe(true);
  });

  it('refuses to auto-delete a complete entry whose commitment is wrong', () => {
    const r1 = appendChainedAuditEntry(TEST_AGENT, (prev) => chainedResult(makeInput('Bash'), 'allow', prev));
    const file = auditFile();
    const good = readFileSync(file, 'utf8');
    // A complete, newline-terminated entry with a tampered commitment.
    const tampered = JSON.stringify({ ...r1.auditEntry, commitment: 'f'.repeat(64) }) + '\n';
    writeFileSync(file, good + tampered, 'utf8');

    expect(() => repairAuditLogTail(TEST_AGENT)).toThrow(/refusing to repair/i);
    // Nothing was deleted: the complete-but-invalid entry is left for review.
    expect(readFileSync(file, 'utf8')).toBe(good + tampered);
  });

  it('refuses to truncate a trailing fragment that parses as a complete JSON object', () => {
    const r1 = appendChainedAuditEntry(TEST_AGENT, (prev) => chainedResult(makeInput('Bash'), 'allow', prev));
    const file = auditFile();
    const good = readFileSync(file, 'utf8');
    // A crash after a full entry object was written but before its newline.
    const dangling = JSON.stringify(r1.auditEntry);
    writeFileSync(file, good + dangling, 'utf8');

    expect(() => repairAuditLogTail(TEST_AGENT)).toThrow(/terminating newline|manual review/i);
    expect(readFileSync(file, 'utf8')).toBe(good + dangling);
  });
});
