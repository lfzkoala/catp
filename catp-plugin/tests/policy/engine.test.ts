import { describe, it, expect } from '@jest/globals';
import { evaluate } from '../../src/policy/engine.js';
import type { CatpPolicy } from '../../src/policy/types.js';
import type { ToolAction } from '../../src/runtime/types.js';

const policy = (rules: CatpPolicy['rules']): CatpPolicy => ({
  agent: { id: 'test', version: '1' },
  rules,
});

const input = (tool: string, toolInput: Record<string, unknown> = {}): ToolAction => ({
  runtime: 'test-runtime',
  phase: 'pre',
  toolName: tool,
  toolInput,
});

describe('evaluate — default behavior', () => {
  it('allows by default when no rules exist', () => {
    const r = evaluate(policy([]), input('Bash'));
    expect(r.allow).toBe(true);
    expect(r.rule).toBeNull();
    expect(r.reason).toContain('default allow');
  });

  it('allows by default when no rule matches the tool', () => {
    const r = evaluate(policy([{ tool: 'Write', allow: false }]), input('Bash'));
    expect(r.allow).toBe(true);
    expect(r.rule).toBeNull();
  });
});

describe('evaluate — unconditional rules', () => {
  it('allows when an unconditional allow rule matches', () => {
    const r = evaluate(policy([{ tool: 'WebFetch', allow: true, reason: 'open reads' }]), input('WebFetch'));
    expect(r.allow).toBe(true);
    expect(r.rule).not.toBeNull();
    expect(r.reason).toBe('open reads');
  });

  it('denies when an unconditional deny rule matches', () => {
    const r = evaluate(policy([{ tool: 'Bash', allow: false, reason: 'no shell' }]), input('Bash'));
    expect(r.allow).toBe(false);
    expect(r.reason).toBe('no shell');
  });

  it('uses default reason text when reason is not provided', () => {
    const allow = evaluate(policy([{ tool: 'Read', allow: true }]), input('Read'));
    expect(allow.reason).toBe('allowed by policy');

    const deny = evaluate(policy([{ tool: 'Read', allow: false }]), input('Read'));
    expect(deny.reason).toBe('denied by policy');
  });

  it('matches wildcard tool "*"', () => {
    const r = evaluate(policy([{ tool: '*', allow: false, reason: 'deny all' }]), input('Bash'));
    expect(r.allow).toBe(false);
    expect(r.reason).toBe('deny all');
  });

  it('first matching rule wins — allow before deny', () => {
    const p = policy([
      { tool: 'Bash', allow: true, reason: 'first' },
      { tool: 'Bash', allow: false, reason: 'second' },
    ]);
    const r = evaluate(p, input('Bash'));
    expect(r.allow).toBe(true);
    expect(r.reason).toBe('first');
  });

  it('first matching rule wins — deny before allow', () => {
    const p = policy([
      { tool: 'Bash', allow: false, reason: 'block' },
      { tool: 'Bash', allow: true, reason: 'permit' },
    ]);
    const r = evaluate(p, input('Bash'));
    expect(r.allow).toBe(false);
    expect(r.reason).toBe('block');
  });
});

describe('evaluate — pattern rules', () => {
  it('denies when command is a substring of a pattern', () => {
    const p = policy([{ tool: 'Bash', allow: false, pattern: ['rm -rf'] }]);
    const r = evaluate(p, input('Bash', { command: 'rm -rf /' }));
    expect(r.allow).toBe(false);
  });

  it('denies when command matches a glob pattern', () => {
    const p = policy([{ tool: 'Bash', allow: false, pattern: ['sudo *'] }]);
    const r = evaluate(p, input('Bash', { command: 'sudo apt install vim' }));
    expect(r.allow).toBe(false);
  });

  it('falls through to default allow when command matches no pattern', () => {
    const p = policy([{ tool: 'Bash', allow: false, pattern: ['sudo *', 'rm -rf'] }]);
    const r = evaluate(p, input('Bash', { command: 'ls -la' }));
    expect(r.allow).toBe(true);
  });

  it('does not match when tool_input has no command field', () => {
    const p = policy([{ tool: 'Bash', allow: false, pattern: ['rm *'] }]);
    const r = evaluate(p, input('Bash', {}));
    expect(r.allow).toBe(true);
  });

  it('does not match when command field is not a string', () => {
    const p = policy([{ tool: 'Bash', allow: false, pattern: ['rm *'] }]);
    const r = evaluate(p, input('Bash', { command: 42 }));
    expect(r.allow).toBe(true);
  });
});

describe('evaluate — path_allowlist rules', () => {
  it('rule matches when file is outside allowlist → apply rule decision', () => {
    const p = policy([{ tool: 'Write', allow: false, path_allowlist: ['src/**'], reason: 'outside src' }]);
    const r = evaluate(p, input('Write', { file_path: 'scripts/hack.sh' }));
    expect(r.allow).toBe(false);
    expect(r.reason).toBe('outside src');
  });

  it('rule does not match when file is inside allowlist → default allow', () => {
    const p = policy([{ tool: 'Write', allow: false, path_allowlist: ['src/**'] }]);
    const r = evaluate(p, input('Write', { file_path: 'src/foo.ts' }));
    expect(r.allow).toBe(true);
    expect(r.rule).toBeNull();
  });

  it('does not match when tool_input has no path field', () => {
    const p = policy([{ tool: 'Write', allow: false, path_allowlist: ['src/**'] }]);
    const r = evaluate(p, input('Write', {}));
    expect(r.allow).toBe(true);
  });
});

describe('evaluate — path_denylist rules', () => {
  it('rule matches when file is in denylist', () => {
    const p = policy([{ tool: 'Write', allow: false, path_denylist: ['secrets/**'] }]);
    const r = evaluate(p, input('Write', { file_path: 'secrets/key.pem' }));
    expect(r.allow).toBe(false);
  });

  it('rule does not match when file is outside denylist', () => {
    const p = policy([{ tool: 'Write', allow: false, path_denylist: ['secrets/**'] }]);
    const r = evaluate(p, input('Write', { file_path: 'src/key.ts' }));
    expect(r.allow).toBe(true);
  });

  it('does not match when tool_input has no path field', () => {
    const p = policy([{ tool: 'Write', allow: false, path_denylist: ['secrets/**'] }]);
    const r = evaluate(p, input('Write', {}));
    expect(r.allow).toBe(true);
  });
});

describe('evaluate — path extraction fallback keys', () => {
  it('extracts path from "path" key', () => {
    const p = policy([{ tool: 'Write', allow: false, path_denylist: ['secret/**'] }]);
    const r = evaluate(p, input('Write', { path: 'secret/foo' }));
    expect(r.allow).toBe(false);
  });

  it('extracts path from "filePath" key', () => {
    const p = policy([{ tool: 'Write', allow: false, path_denylist: ['secret/**'] }]);
    const r = evaluate(p, input('Write', { filePath: 'secret/bar' }));
    expect(r.allow).toBe(false);
  });

  it('prefers "file_path" over "path" when both present', () => {
    const p = policy([{ tool: 'Write', allow: false, path_denylist: ['secret/**'] }]);
    // file_path points to safe location; path points to denylist — file_path wins
    const r = evaluate(p, input('Write', { file_path: 'src/safe.ts', path: 'secret/key' }));
    expect(r.allow).toBe(true);
  });
});
