import { describe, expect, it } from '@jest/globals';
import { evaluatePreAction, recordPostAction } from '../../src/enforcement/core.js';
import type { CatpPolicy } from '../../src/policy/types.js';
import type { ToolAction } from '../../src/runtime/types.js';

const policy = (rules: CatpPolicy['rules']): CatpPolicy => ({
  agent: { id: 'test', version: '1' },
  rules,
});

const action = (toolName: string, toolInput: Record<string, unknown> = {}): ToolAction => ({
  runtime: 'test-runtime',
  phase: 'pre',
  toolName,
  toolInput,
});

describe('evaluatePreAction', () => {
  it('returns an allow result and audit entry for allowed actions', () => {
    const result = evaluatePreAction(
      policy([{ tool: 'Bash', allow: true, reason: 'ok' }]),
      action('Bash', { command: 'ls' }),
      'a'.repeat(64)
    );

    expect(result.allow).toBe(true);
    expect(result.reason).toBe('ok');
    expect(result.auditEntry.tool).toBe('Bash');
    expect(result.auditEntry.decision).toBe('allow');
    expect(result.auditEntry.rule_matched).toBe('Bash:allow');
    expect(result.auditEntry.commitment).toMatch(/^[0-9a-f]{64}$/);
  });

  it('returns a deny result and audit entry for blocked actions', () => {
    const result = evaluatePreAction(
      policy([{ tool: 'Bash', allow: false, pattern: ['rm -rf'], reason: 'too sharp' }]),
      action('Bash', { command: 'rm -rf /tmp/demo' })
    );

    expect(result.allow).toBe(false);
    expect(result.reason).toBe('too sharp');
    expect(result.auditEntry.decision).toBe('deny');
    expect(result.auditEntry.rule_matched).toBe('Bash:deny');
  });
});

describe('recordPostAction', () => {
  it('records post actions as allowed audit entries without policy evaluation', () => {
    const result = recordPostAction(action('Write', { file_path: 'src/app.ts' }));

    expect(result.allow).toBe(true);
    expect(result.auditEntry.tool).toBe('Write');
    expect(result.auditEntry.decision).toBe('allow');
    expect(result.auditEntry.rule_matched).toBeNull();
  });
});
