import { describe, expect, it } from '@jest/globals';
import { evaluatePreAction, recordPostAction } from '../../src/enforcement/core.js';
import {
  canonicalizeToolAction,
  computeActionCommitment,
  computePolicyCommitment,
} from '../../src/evidence/commitments.js';
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

const HEX64 = /^[0-9a-f]{64}$/;

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
    expect(result.auditEntry).toMatchObject({ phase: 'pre' });
    expect(result.auditEntry.decision).toBe('allow');
    expect(result.auditEntry.rule_matched).toBe('Bash:allow');
    expect(result.auditEntry.commitment).toMatch(HEX64);
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

  it('emits a v4 entry bound to the enforcement-time policy and full action', () => {
    const pol = policy([{ tool: 'Bash', allow: true, reason: 'ok' }]);
    const act = action('Bash', { command: 'ls -la' });
    const result = evaluatePreAction(pol, act, '0');

    expect(result.auditEntry.commitment_version).toBe(4);
    expect(result.auditEntry.reason).toBe('ok');
    expect(result.auditEntry.policy_commitment).toMatch(HEX64);
    expect(result.auditEntry.action_commitment).toMatch(HEX64);

    // The entry bindings are exactly the enforcement-time policy and the
    // complete canonical action, not a recomputed-from-disk value.
    expect(result.auditEntry.policy_commitment).toBe(computePolicyCommitment(pol));
    expect(result.action).toEqual(canonicalizeToolAction({ ...act, phase: 'pre' }));
    expect(result.auditEntry.action_commitment).toBe(computeActionCommitment(result.action));
  });

  it('excludes the runtime raw payload from the bound action evidence', () => {
    const act: ToolAction = {
      runtime: 'test-runtime',
      phase: 'pre',
      toolName: 'Bash',
      toolInput: { command: 'ls' },
      raw: { secret: 'do-not-bind' },
    };
    const result = evaluatePreAction(policy([{ tool: 'Bash', allow: true }]), act, '0');
    expect(result.action).not.toHaveProperty('raw');
    expect(JSON.stringify(result.action)).not.toContain('do-not-bind');
  });
});

describe('recordPostAction', () => {
  it('records post actions as allowed v4 audit entries without policy evaluation', () => {
    const pol = policy([{ tool: 'Write', allow: true }]);
    const result = recordPostAction(pol, action('Write', { file_path: 'src/app.ts' }));

    expect(result.allow).toBe(true);
    expect(result.auditEntry.tool).toBe('Write');
    expect(result.auditEntry).toMatchObject({ phase: 'post' });
    expect(result.auditEntry.decision).toBe('allow');
    expect(result.auditEntry.rule_matched).toBeNull();
    expect(result.auditEntry.commitment_version).toBe(4);
    expect(result.auditEntry.policy_commitment).toBe(computePolicyCommitment(pol));
    expect(result.auditEntry.action_commitment).toBe(computeActionCommitment(result.action));
    expect(result.action.phase).toBe('post');
  });
});
