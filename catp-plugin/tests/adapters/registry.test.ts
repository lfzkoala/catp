import { describe, expect, it } from '@jest/globals';
import {
  adaptRuntimePayload,
  getRuntimeAdapter,
  listRuntimeAdapters,
} from '../../src/adapters/registry.js';

describe('runtime adapter registry', () => {
  it('lists supported adapter names', () => {
    expect(listRuntimeAdapters()).toEqual(['claude-code']);
  });

  it('returns adapters by name', () => {
    expect(getRuntimeAdapter('claude-code')?.runtime).toBe('claude-code');
    expect(getRuntimeAdapter('unknown')).toBeNull();
  });

  it('normalizes payloads through registered adapters', () => {
    const action = adaptRuntimePayload('claude-code', 'pre', {
      tool_name: 'Bash',
      tool_input: { command: 'ls' },
    });

    expect(action?.runtime).toBe('claude-code');
    expect(action?.phase).toBe('pre');
    expect(action?.toolName).toBe('Bash');
  });

  it('returns null for unknown adapters', () => {
    expect(adaptRuntimePayload('unknown', 'pre', {})).toBeNull();
  });
});
