import { describe, expect, it } from '@jest/globals';
import {
  cmdListAdapters,
  formatEventValidationSummary,
  validateEventPayload,
} from '../../src/commands/event.js';

describe('validateEventPayload', () => {
  it('validates canonical ToolAction payloads', () => {
    const result = validateEventPayload({
      runtime: 'test-runtime',
      phase: 'pre',
      toolName: 'Bash',
      toolInput: { command: 'ls' },
    });

    expect(result.ok).toBe(true);
    expect(result.action?.runtime).toBe('test-runtime');
    expect(result.action?.toolName).toBe('Bash');
  });

  it('normalizes Claude Code pre hook payloads before validation', () => {
    const result = validateEventPayload(
      {
        session_id: 'session-1',
        tool_name: 'Bash',
        tool_input: { command: 'ls' },
      },
      { adapter: 'claude-code', phase: 'pre' }
    );

    expect(result.ok).toBe(true);
    expect(result.action?.runtime).toBe('claude-code');
    expect(result.action?.phase).toBe('pre');
    expect(result.action?.sessionId).toBe('session-1');
  });

  it('normalizes Claude Code post hook payloads before validation', () => {
    const result = validateEventPayload(
      {
        tool_name: 'Write',
        tool_input: { file_path: 'src/app.ts' },
      },
      { adapter: 'claude-code', phase: 'post' }
    );

    expect(result.ok).toBe(true);
    expect(result.action?.phase).toBe('post');
    expect(result.action?.toolName).toBe('Write');
  });

  it('rejects unsupported adapters', () => {
    const result = validateEventPayload({}, { adapter: 'unknown', phase: 'pre' });

    expect(result.ok).toBe(false);
    expect(result.errors[0]).toContain('unsupported or invalid adapter payload');
  });
});

describe('formatEventValidationSummary', () => {
  it('formats valid event summaries', () => {
    const summary = formatEventValidationSummary({
      ok: true,
      errors: [],
      action: {
        runtime: 'claude-code',
        phase: 'pre',
        toolName: 'Bash',
        toolInput: { command: 'ls' },
      },
    });

    expect(summary).toContain('✓ event valid');
    expect(summary).toContain('runtime: claude-code');
    expect(summary).toContain('phase: pre');
    expect(summary).toContain('tool: Bash');
    expect(summary).toContain('inputKeys: 1');
  });

  it('formats invalid event summaries', () => {
    const summary = formatEventValidationSummary({
      ok: false,
      errors: ['toolName must be a non-empty string'],
    });

    expect(summary).toContain('✗ event invalid');
    expect(summary).toContain('toolName must be a non-empty string');
  });
});

describe('cmdListAdapters', () => {
  it('prints supported adapter names', () => {
    const originalWrite = process.stdout.write.bind(process.stdout);
    let output = '';
    process.stdout.write = ((chunk: string | Uint8Array) => {
      output += chunk.toString();
      return true;
    }) as typeof process.stdout.write;
    try {
      cmdListAdapters();
    } finally {
      process.stdout.write = originalWrite;
    }

    expect(output).toBe('claude-code\n');
  });
});
