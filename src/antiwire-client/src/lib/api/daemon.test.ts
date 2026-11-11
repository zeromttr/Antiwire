import { describe, expect, it } from 'bun:test';
import { requireMutationSuccess, raceWithTimeout } from './daemon';

describe('requireMutationSuccess', () => {
  it('allows successful daemon mutations', () => {
    expect(() => requireMutationSuccess(true, 'remove_rule')).not.toThrow();
  });

  it('rejects daemon mutations that resolve false', () => {
    expect(() => requireMutationSuccess(false, 'remove_rule')).toThrow(
      "Daemon rejected mutation 'remove_rule'",
    );
  });
});

describe('raceWithTimeout', () => {
  it('resolves when the pending promise wins', async () => {
    await expect(raceWithTimeout(Promise.resolve('ok'), 'cmd', 50)).resolves.toBe('ok');
  });

  it('rejects when the pending promise rejects', async () => {
    await expect(raceWithTimeout(Promise.reject(new Error('boom')), 'cmd', 50)).rejects.toThrow(
      'boom',
    );
  });

  it('times out without leaving a late rejection unhandled', async () => {
    let rejectPending!: (reason?: unknown) => void;
    const pending = new Promise<string>((_, reject) => {
      rejectPending = reject;
    });

    await expect(raceWithTimeout(pending, 'hang', 10)).rejects.toThrow(
      "IPC timeout: 'hang' failed to respond within 10ms",
    );

    rejectPending(new Error('late failure'));
    await new Promise((resolve) => setTimeout(resolve, 0));
  });

  it('passes through when timeoutMs is not positive', async () => {
    await expect(raceWithTimeout(Promise.resolve(7), 'cmd', 0)).resolves.toBe(7);
  });
});
