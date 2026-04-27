import { describe, it, expect, afterAll } from '@jest/globals';
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { findPolicyFile, loadPolicy } from '../../src/policy/loader.js';

const tmpBase = join(tmpdir(), `catp-loader-test-${Date.now()}`);
mkdirSync(tmpBase, { recursive: true });

afterAll(() => {
  rmSync(tmpBase, { recursive: true, force: true });
});

const VALID_TOML = `
[agent]
id = "test-agent"
version = "1"

[[rules]]
tool = "Bash"
allow = false
reason = "no shell"

[[rules]]
tool = "Read"
allow = true
`;

describe('findPolicyFile', () => {
  it('returns null when no policy file exists in the directory tree', () => {
    const dir = join(tmpBase, 'no-policy');
    mkdirSync(dir, { recursive: true });
    expect(findPolicyFile(dir)).toBeNull();
  });

  it('finds the policy file in the given directory', () => {
    const dir = join(tmpBase, 'with-policy');
    mkdirSync(dir, { recursive: true });
    const policyPath = join(dir, 'catp-policy.toml');
    writeFileSync(policyPath, VALID_TOML, 'utf8');
    expect(findPolicyFile(dir)).toBe(policyPath);
  });

  it('finds the policy file in a parent directory', () => {
    const root = join(tmpBase, 'parent-policy');
    const sub = join(root, 'src', 'deep');
    mkdirSync(sub, { recursive: true });
    const policyPath = join(root, 'catp-policy.toml');
    writeFileSync(policyPath, VALID_TOML, 'utf8');
    expect(findPolicyFile(sub)).toBe(policyPath);
  });
});

describe('loadPolicy', () => {
  it('parses a valid policy and returns a CatpPolicy object', () => {
    const path = join(tmpBase, 'valid.toml');
    writeFileSync(path, VALID_TOML, 'utf8');
    const policy = loadPolicy(path);
    expect(policy.agent.id).toBe('test-agent');
    expect(policy.agent.version).toBe('1');
    expect(policy.rules).toHaveLength(2);
    expect(policy.rules[0].tool).toBe('Bash');
    expect(policy.rules[0].allow).toBe(false);
    expect(policy.rules[0].reason).toBe('no shell');
    expect(policy.rules[1].tool).toBe('Read');
    expect(policy.rules[1].allow).toBe(true);
  });

  it('parses optional rule fields (pattern, path_allowlist, path_denylist)', () => {
    const toml = `
[agent]
id = "a"
version = "1"

[[rules]]
tool = "Write"
allow = false
pattern = ["rm *"]
path_allowlist = ["src/**"]
path_denylist = ["secrets/**"]
reason = "custom"
`;
    const path = join(tmpBase, 'optional-fields.toml');
    writeFileSync(path, toml, 'utf8');
    const rule = loadPolicy(path).rules[0];
    expect(rule.pattern).toEqual(['rm *']);
    expect(rule.path_allowlist).toEqual(['src/**']);
    expect(rule.path_denylist).toEqual(['secrets/**']);
    expect(rule.reason).toBe('custom');
  });

  it('throws when [agent] section is missing', () => {
    const path = join(tmpBase, 'no-agent.toml');
    writeFileSync(path, '[[rules]]\ntool = "Bash"\nallow = true\n', 'utf8');
    expect(() => loadPolicy(path)).toThrow('missing [agent] section');
  });

  it('throws when agent.id is missing', () => {
    const path = join(tmpBase, 'no-id.toml');
    writeFileSync(path, '[agent]\nversion = "1"\n[[rules]]\ntool = "Bash"\nallow = true\n', 'utf8');
    expect(() => loadPolicy(path)).toThrow('agent.id');
  });

  it('throws when agent.version is missing', () => {
    const path = join(tmpBase, 'no-version.toml');
    writeFileSync(path, '[agent]\nid = "a"\n[[rules]]\ntool = "Bash"\nallow = true\n', 'utf8');
    expect(() => loadPolicy(path)).toThrow('agent.version');
  });

  it('throws when [[rules]] array is missing', () => {
    const path = join(tmpBase, 'no-rules.toml');
    writeFileSync(path, '[agent]\nid = "a"\nversion = "1"\n', 'utf8');
    expect(() => loadPolicy(path)).toThrow('[[rules]]');
  });

  it('throws when a rule is missing tool', () => {
    const path = join(tmpBase, 'no-tool.toml');
    writeFileSync(path, '[agent]\nid = "a"\nversion = "1"\n[[rules]]\nallow = true\n', 'utf8');
    expect(() => loadPolicy(path)).toThrow('rules[0].tool');
  });

  it('throws when a rule is missing allow', () => {
    const path = join(tmpBase, 'no-allow.toml');
    writeFileSync(path, '[agent]\nid = "a"\nversion = "1"\n[[rules]]\ntool = "Bash"\n', 'utf8');
    expect(() => loadPolicy(path)).toThrow('rules[0].allow');
  });
});
