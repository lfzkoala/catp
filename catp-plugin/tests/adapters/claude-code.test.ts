import { describe, expect, it } from '@jest/globals';
import { claudeCodeAdapter } from '../../src/adapters/claude-code.js';

describe('claudeCodeAdapter', () => {
  it('maps PreToolUse payloads into runtime-neutral tool actions', () => {
    const action = claudeCodeAdapter.fromPreToolUse({
      session_id: 'session-1',
      tool_name: 'Bash',
      tool_input: { command: 'ls' },
    });

    expect(action).toEqual({
      runtime: 'claude-code',
      phase: 'pre',
      sessionId: 'session-1',
      toolName: 'Bash',
      toolInput: { command: 'ls' },
      raw: {
        session_id: 'session-1',
        tool_name: 'Bash',
        tool_input: { command: 'ls' },
      },
    });
  });

  it('maps PostToolUse payloads with post phase', () => {
    const action = claudeCodeAdapter.fromPostToolUse({
      tool_name: 'Write',
      tool_input: { file_path: 'src/app.ts' },
    });

    expect(action?.runtime).toBe('claude-code');
    expect(action?.phase).toBe('post');
    expect(action?.toolName).toBe('Write');
    expect(action?.toolInput).toEqual({ file_path: 'src/app.ts' });
  });

  it('rejects malformed hook payloads', () => {
    expect(claudeCodeAdapter.fromPreToolUse({ tool_name: 'Bash' })).toBeNull();
    expect(claudeCodeAdapter.fromPreToolUse({ tool_name: '', tool_input: {} })).toBeNull();
    expect(claudeCodeAdapter.fromPreToolUse({ tool_name: 'Bash', tool_input: [] })).toBeNull();
  });
});
