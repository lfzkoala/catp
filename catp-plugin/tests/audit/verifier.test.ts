import { describe, it, expect, afterAll } from '@jest/globals';
import { writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { verifyChain } from '../../src/audit/verifier.js';
import { computeCommitment } from '../../src/audit/logger.js';
import type { AuditEntry } from '../../src/policy/types.js';

const tmpBase = join(tmpdir(), `catp-verifier-test-${Date.now()}`);
mkdirSync(tmpBase, { recursive: true });

afterAll(() => {
  rmSync(tmpBase, { recursive: true, force: true });
});

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
