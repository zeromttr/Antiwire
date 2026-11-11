import { describe, expect, it } from 'bun:test';
import { fireUiAction, invokeUiCallback, runUiAction } from './ui-action';

describe('runUiAction', () => {
  it('returns the result of a successful sync action', async () => {
    await expect(runUiAction(() => 42)).resolves.toBe(42);
  });

  it('returns the result of a successful async action', async () => {
    await expect(runUiAction(async () => 'saved')).resolves.toBe('saved');
  });

  it('routes sync throws to onError and resolves undefined', async () => {
    const reports: Array<{ message: string; error: unknown }> = [];
    const failure = new Error('dialog unavailable');

    const result = await runUiAction(
      () => {
        throw failure;
      },
      {
        onError: (message, error) => {
          reports.push({ message, error });
        },
      },
    );

    expect(result).toBeUndefined();
    expect(reports).toHaveLength(1);
    expect(reports[0].message).toBe('dialog unavailable');
    expect(reports[0].error).toBe(failure);
  });

  it('routes async rejections to onError instead of escaping', async () => {
    const messages: string[] = [];

    const result = await runUiAction(() => Promise.reject(new Error('storage quota exceeded')), {
      onError: (message) => {
        messages.push(message);
      },
    });

    expect(result).toBeUndefined();
    expect(messages).toEqual(['storage quota exceeded']);
  });

  it('formats non-Error throw values for user feedback', async () => {
    const messages: string[] = [];

    await runUiAction(
      () => {
        throw 'locale file missing';
      },
      {
        onError: (message) => {
          messages.push(message);
        },
      },
    );

    expect(messages).toEqual(['locale file missing']);
  });

  it('falls back to a generic message for empty throws', async () => {
    const messages: string[] = [];

    await runUiAction(
      () => {
        throw null;
      },
      {
        onError: (message) => {
          messages.push(message);
        },
      },
    );

    expect(messages).toEqual(['An unexpected error occurred.']);
  });

  it('never throws when the reporter itself fails', async () => {
    await expect(
      runUiAction(
        () => {
          throw new Error('native dialog failed');
        },
        {
          onError: () => {
            throw new Error('toast store broken');
          },
        },
      ),
    ).resolves.toBeUndefined();
  });

  it('works without a reporter', async () => {
    await expect(
      runUiAction(() => Promise.reject(new Error('unobserved'))),
    ).resolves.toBeUndefined();
  });
});

describe('fireUiAction', () => {
  it('observes async failures from click-style handlers', async () => {
    const messages: string[] = [];
    fireUiAction(() => Promise.reject(new Error('save failed')), {
      onError: (message) => {
        messages.push(message);
      },
    });

    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(messages).toEqual(['save failed']);
  });
});

describe('invokeUiCallback', () => {
  it('invokes sync shared-control callbacks with the value', () => {
    const seen: unknown[] = [];
    invokeUiCallback((value: never) => {
      seen.push(value);
    }, 'dark' as never);
    expect(seen).toEqual(['dark']);
  });

  it('routes async callback rejections to onError', async () => {
    const messages: string[] = [];
    invokeUiCallback(
      (_value: never) => Promise.reject(new Error('locale switch failed')),
      'de' as never,
      {
        onError: (message) => {
          messages.push(message);
        },
      },
    );

    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(messages).toEqual(['locale switch failed']);
  });

  it('ignores missing callbacks', () => {
    expect(() => invokeUiCallback(undefined, true as never)).not.toThrow();
  });
});
