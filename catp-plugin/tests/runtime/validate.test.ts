import { describe, expect, it } from '@jest/globals';
import { validateToolAction } from '../../src/runtime/validate.js';

describe('validateToolAction', () => {
  it('accepts a minimal valid ToolAction', () => {
    const result = validateToolAction({
      runtime: 'test-runtime',
      phase: 'pre',
      toolName: 'Bash',
      toolInput: { command: 'ls' },
    });

    expect(result.ok).toBe(true);
    expect(result.action?.toolName).toBe('Bash');
  });

  it('accepts post phase and optional sessionId', () => {
    const result = validateToolAction({
      runtime: 'test-runtime',
      phase: 'post',
      sessionId: 'session-1',
      toolName: 'Write',
      toolInput: {},
    });

    expect(result.ok).toBe(true);
    expect(result.action?.sessionId).toBe('session-1');
  });

  it('rejects malformed events with field-specific errors', () => {
    const result = validateToolAction({
      runtime: '',
      phase: 'during',
      toolName: '',
      toolInput: [],
      sessionId: 123,
    });

    expect(result.ok).toBe(false);
    expect(result.errors).toContain('runtime must be a non-empty string');
    expect(result.errors).toContain('phase must be "pre" or "post"');
    expect(result.errors).toContain('toolName must be a non-empty string');
    expect(result.errors).toContain('toolInput must be an object');
    expect(result.errors).toContain('sessionId must be a string when present');
  });

  it('rejects non-object events', () => {
    const result = validateToolAction(null);

    expect(result.ok).toBe(false);
    expect(result.errors).toEqual(['event must be an object']);
  });
});
