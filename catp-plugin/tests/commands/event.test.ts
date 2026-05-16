import { describe, expect, it } from '@jest/globals';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  cmdListAdapters,
  cmdNormalizeEvent,
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

describe('cmdNormalizeEvent', () => {
  it('prints canonical ToolAction JSON for valid standard payloads', async () => {
    const output = await captureStdout(() =>
      cmdNormalizeEvent({
        file: writeJsonFixture({
          runtime: 'test-runtime',
          phase: 'pre',
          toolName: 'Bash',
          toolInput: { command: 'ls' },
        }),
      })
    );

    expect(JSON.parse(output)).toEqual({
      runtime: 'test-runtime',
      phase: 'pre',
      toolName: 'Bash',
      toolInput: { command: 'ls' },
    });
  });

  it('prints canonical ToolAction JSON for adapter payloads', async () => {
    const output = await captureStdout(() =>
      cmdNormalizeEvent({
        adapter: 'claude-code',
        file: writeJsonFixture({
          tool_name: 'Write',
          tool_input: { file_path: 'src/app.ts' },
        }),
        phase: 'post',
      })
    );

    expect(JSON.parse(output)).toMatchObject({
      runtime: 'claude-code',
      phase: 'post',
      toolName: 'Write',
      toolInput: { file_path: 'src/app.ts' },
    });
  });
});

async function captureStdout<T>(run: () => Promise<T> | T): Promise<string> {
  const originalWrite = process.stdout.write.bind(process.stdout);
  let output = '';

  process.stdout.write = ((chunk: string | Uint8Array) => {
    output += chunk.toString();
    return true;
  }) as typeof process.stdout.write;

  try {
    await run();
    return output;
  } finally {
    process.stdout.write = originalWrite;
  }
}

function writeJsonFixture(value: unknown): string {
  const dir = mkdtempSync(join(tmpdir(), 'catp-event-test-'));
  const file = join(dir, 'event.json');
  writeFileSync(file, JSON.stringify(value), 'utf8');
  process.on('exit', () => rmSync(dir, { recursive: true, force: true }));
  return file;
}
