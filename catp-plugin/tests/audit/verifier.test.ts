import { describe, it, expect, afterAll } from '@jest/globals';
import { writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { verifyChain } from '../../src/audit/verifier.js';
import { buildEntry, computeCommitment, computeCommitmentV4 } from '../../src/audit/logger.js';
import {
  canonicalizeToolAction,
  computeActionCommitment,
  computePolicyCommitment,
} from '../../src/evidence/commitments.js';
import type { AuditEntry, AuditEntryV4, CatpPolicy } from '../../src/policy/types.js';
import type { ToolAction } from '../../src/runtime/types.js';

const tmpBase = join(tmpdir(), `catp-verifier-test-${Date.now()}`);
mkdirSync(tmpBase, { recursive: true });

afterAll(() => {
  rmSync(tmpBase, { recursive: true, force: true });
});

const TEST_POLICY: CatpPolicy = { agent: { id: 'test', version: '1' }, rules: [] };

function makeEntry(
  tool: string,
  decision: 'allow' | 'deny',
  ts: string,
  prev = '0',
): AuditEntry {
  return {
    ts,
    tool,
    decision,
    rule_matched: null,
    commitment: computeCommitment(tool, decision, ts, prev, null, '{}'),
    input_summary: '{}',
  };
}

// A valid legacy entry at an explicit commitment version (2 or 3).
function makeLegacyEntry(
  version: 2 | 3,
  tool: string,
  decision: 'allow' | 'deny',
  ts: string,
  prev = '0',
): AuditEntry {
  const phase = version === 3 ? ('pre' as const) : undefined;
  const commitment = computeCommitment(tool, decision, ts, prev, null, '{}', undefined, version, phase);
  if (version === 3) {
    return {
      commitment_version: 3,
      phase: 'pre',
      ts,
      tool,
      decision,
      rule_matched: null,
      commitment,
      input_summary: '{}',
    };
  }
  return {
    commitment_version: 2,
    ts,
    tool,
    decision,
    rule_matched: null,
    commitment,
    input_summary: '{}',
  };
}

// A real v4 entry produced through buildEntry, so its policy/action commitments
// are genuine enforcement-time bindings.
function makeV4Entry(
  tool: string,
  decision: 'allow' | 'deny',
  prev = '0',
  toolInput: Record<string, unknown> = { command: tool },
): AuditEntryV4 {
  const input: ToolAction = { runtime: 'test-runtime', phase: 'pre', toolName: tool, toolInput };
  return buildEntry(input, decision, null, prev, {
    reason: 'test-reason',
    policyCommitment: computePolicyCommitment(TEST_POLICY),
    actionCommitment: computeActionCommitment(canonicalizeToolAction(input)),
  });
}

function writeLog(name: string, lines: AuditEntry[]): string {
  const path = join(tmpBase, name);
  writeFileSync(path, lines.map((l) => JSON.stringify(l)).join('\n') + '\n', 'utf8');
  return path;
}

describe('verifyChain', () => {
  it('returns ok=true for an empty file', async () => {
    const path = join(tmpBase, 'empty.jsonl');
    writeFileSync(path, '', 'utf8');
    const result = await verifyChain(path);
    expect(result.ok).toBe(true);
    expect(result.checked).toBe(0);
    expect(result.message).toBe('empty log');
  });

  it('returns ok=true for a single valid entry', async () => {
    const e1 = makeEntry('Bash', 'allow', '2026-01-01T00:00:00.000Z');
    const path = writeLog('single.jsonl', [e1]);
    const result = await verifyChain(path);
    expect(result.ok).toBe(true);
    expect(result.checked).toBe(1);
    expect(result.broken_at).toBeNull();
  });

  it('returns ok=true for multiple chained entries', async () => {
    const e1 = makeEntry('Bash', 'allow', '2026-01-01T00:00:00.000Z');
    const e2 = makeEntry('Write', 'deny', '2026-01-01T00:00:01.000Z', e1.commitment);
    const e3 = makeEntry('Read', 'allow', '2026-01-01T00:00:02.000Z', e2.commitment);
    const path = writeLog('chain.jsonl', [e1, e2, e3]);
    const result = await verifyChain(path);
    expect(result.ok).toBe(true);
    expect(result.checked).toBe(3);
    expect(result.message).toBe('chain intact');
  });

  it('detects a tampered commitment (index 1)', async () => {
    const e1 = makeEntry('Bash', 'allow', '2026-01-01T00:00:00.000Z');
    const e2Tampered: AuditEntry = {
      ...makeEntry('Write', 'deny', '2026-01-01T00:00:01.000Z', e1.commitment),
      commitment: 'deadbeef'.repeat(8),
    };
    const e3 = makeEntry('Read', 'allow', '2026-01-01T00:00:02.000Z', e2Tampered.commitment);
    const path = writeLog('tampered.jsonl', [e1, e2Tampered, e3]);
    const result = await verifyChain(path);
    expect(result.ok).toBe(false);
    expect(result.broken_at).toBe(1);
    expect(result.message).toContain('commitment mismatch');
  });

  it('detects a broken chain when prev commitment is wrong', async () => {
    const e1 = makeEntry('Bash', 'allow', '2026-01-01T00:00:00.000Z');
    const e2 = makeEntry('Write', 'deny', '2026-01-01T00:00:01.000Z', 'wrong-prev');
    const path = writeLog('broken.jsonl', [e1, e2]);
    const result = await verifyChain(path);
    expect(result.ok).toBe(false);
    expect(result.broken_at).toBe(1);
  });

  it('verifies a valid v2 chain', async () => {
    const e1 = makeLegacyEntry(2, 'Bash', 'allow', '2026-01-01T00:00:00.000Z');
    const e2 = makeLegacyEntry(2, 'Write', 'deny', '2026-01-01T00:00:01.000Z', e1.commitment);
    const path = writeLog('v2-chain.jsonl', [e1, e2]);
    const result = await verifyChain(path);
    expect(result.ok).toBe(true);
    expect(result.checked).toBe(2);
  });

  it('verifies a valid v3 chain', async () => {
    const e1 = makeLegacyEntry(3, 'Bash', 'allow', '2026-01-01T00:00:00.000Z');
    const e2 = makeLegacyEntry(3, 'Write', 'deny', '2026-01-01T00:00:01.000Z', e1.commitment);
    const path = writeLog('v3-chain.jsonl', [e1, e2]);
    const result = await verifyChain(path);
    expect(result.ok).toBe(true);
    expect(result.checked).toBe(2);
  });

  it('reports invalid JSON with broken_at pointing to the bad line', async () => {
    const e1 = makeEntry('Bash', 'allow', '2026-01-01T00:00:00.000Z');
    const path = join(tmpBase, 'badjson.jsonl');
    writeFileSync(path, JSON.stringify(e1) + '\nnot valid json\n', 'utf8');
    const result = await verifyChain(path);
    expect(result.ok).toBe(false);
    expect(result.broken_at).toBe(1);
    expect(result.message).toContain('invalid JSON');
  });
});

describe('verifyChain v4 bindings', () => {
  it('verifies a valid v4 chain', async () => {
    const e1 = makeV4Entry('Bash', 'allow');
    const e2 = makeV4Entry('Write', 'allow', e1.commitment, { file_path: 'src/app.ts' });
    const path = writeLog('v4-chain.jsonl', [e1, e2]);
    const result = await verifyChain(path);
    expect(result.ok).toBe(true);
    expect(result.checked).toBe(2);
  });

  it('detects tampering with structured authorization data', async () => {
    const entry = makeV4Entry('Bash', 'allow', '0', {
      padding: 'x'.repeat(250),
      authorization: {
        actionType: 'Swap',
        protocol: `0x${'aa'.repeat(32)}`,
        token: `0x${'bb'.repeat(32)}`,
        value: '1',
      },
    });
    const tampered = { ...entry, authorization: { ...entry.authorization!, value: '999' } };
    const path = writeLog('tampered-authorization.jsonl', [tampered]);
    const result = await verifyChain(path);
    expect(result.ok).toBe(false);
    expect(result.message).toContain('commitment mismatch');
  });

  it('detects tampering with the runtime phase', async () => {
    const entry = makeV4Entry('Bash', 'allow');
    const path = writeLog('tampered-phase.jsonl', [{ ...entry, phase: 'post' }]);
    const result = await verifyChain(path);
    expect(result.ok).toBe(false);
    expect(result.message).toContain('commitment mismatch');
  });

  it('detects tampering with the v4 policy_commitment', async () => {
    const entry = makeV4Entry('Bash', 'allow');
    const path = writeLog('tampered-v4-policy.jsonl', [{ ...entry, policy_commitment: 'c'.repeat(64) }]);
    const result = await verifyChain(path);
    expect(result.ok).toBe(false);
    expect(result.message).toContain('commitment mismatch');
  });

  it('detects tampering with the v4 action_commitment', async () => {
    const entry = makeV4Entry('Bash', 'allow');
    const path = writeLog('tampered-v4-action.jsonl', [{ ...entry, action_commitment: 'c'.repeat(64) }]);
    const result = await verifyChain(path);
    expect(result.ok).toBe(false);
    expect(result.message).toContain('commitment mismatch');
  });

  it('detects tampering with the v4 decision', async () => {
    const entry = makeV4Entry('Bash', 'allow');
    const path = writeLog('tampered-v4-decision.jsonl', [{ ...entry, decision: 'deny' }]);
    const result = await verifyChain(path);
    expect(result.ok).toBe(false);
    expect(result.message).toContain('commitment mismatch');
  });

  it('detects a v4 entry whose prev_commitment does not match its predecessor', async () => {
    const e1 = makeV4Entry('Bash', 'allow');
    // e2 is built over a different prev than e1's actual commitment.
    const e2 = makeV4Entry('Write', 'allow', 'f'.repeat(64), { file_path: 'src/app.ts' });
    const path = writeLog('tampered-v4-prev.jsonl', [e1, e2]);
    const result = await verifyChain(path);
    expect(result.ok).toBe(false);
    expect(result.broken_at).toBe(1);
    expect(result.message).toContain('commitment mismatch');
  });

  it('rejects a v4 entry with a missing policy_commitment', async () => {
    const entry = makeV4Entry('Bash', 'allow');
    const bad = { ...entry, policy_commitment: undefined } as unknown as AuditEntry;
    const path = writeLog('v4-missing-policy.jsonl', [bad]);
    const result = await verifyChain(path);
    expect(result.ok).toBe(false);
    expect(result.message).toContain('policy_commitment');
  });

  it('rejects a v4 entry with a non-lowercase-hex action_commitment', async () => {
    const entry = makeV4Entry('Bash', 'allow');
    const path = writeLog('v4-upperhex-action.jsonl', [{ ...entry, action_commitment: 'B'.repeat(64) }]);
    const result = await verifyChain(path);
    expect(result.ok).toBe(false);
    expect(result.message).toContain('action_commitment');
  });

  it('rejects an unsupported commitment version', async () => {
    const entry = { ...makeV4Entry('Bash', 'allow'), commitment_version: 9 } as unknown as AuditEntry;
    const path = writeLog('v4-unsupported.jsonl', [entry]);
    const result = await verifyChain(path);
    expect(result.ok).toBe(false);
    expect(result.message).toContain('unsupported commitment version');
  });
});

describe('computeCommitmentV4', () => {
  it('is domain-separated from legacy computeCommitment', () => {
    const v4 = computeCommitmentV4({
      phase: 'pre',
      tool: 'Bash',
      decision: 'allow',
      ts: '2026-01-01T00:00:00.000Z',
      ruleMatched: null,
      reason: 'r',
      inputSummary: '{}',
      policyCommitment: 'a'.repeat(64),
      actionCommitment: 'b'.repeat(64),
      prev: '0',
    });
    expect(v4).toMatch(/^[0-9a-f]{64}$/);
  });
});
