import { describe, expect, it } from 'bun:test';
import { catchAsyncError, daemonErrorMessage, formatErrorMessage, tryMessage } from './error';

describe('catchAsyncError', () => {
  it('reports rejected detached work and resolves cleanly', async () => {
    const errors: unknown[] = [];

    await expect(
      catchAsyncError(Promise.reject(new Error('activity failed')), (error) => {
        errors.push(error);
      }),
    ).resolves.toBeUndefined();

    expect(errors).toHaveLength(1);
    expect(errors[0]).toBeInstanceOf(Error);
  });
});

describe('formatErrorMessage', () => {
  it('uses Error.message when present', () => {
    expect(formatErrorMessage(new Error('chart exploded'))).toBe('chart exploded');
  });

  it('uses a non-empty string as-is', () => {
    expect(formatErrorMessage('  malformed GeoJSON  ')).toBe('malformed GeoJSON');
  });

  it('reads message from plain objects', () => {
    expect(formatErrorMessage({ message: 'null property' })).toBe('null property');
  });

  it('falls back for empty, null, and opaque values', () => {
    expect(formatErrorMessage(null)).toBe('An unexpected error occurred.');
    expect(formatErrorMessage(undefined)).toBe('An unexpected error occurred.');
    expect(formatErrorMessage(new Error('  '))).toBe('An unexpected error occurred.');
    expect(formatErrorMessage({})).toBe('An unexpected error occurred.');
    expect(formatErrorMessage('')).toBe('An unexpected error occurred.');
  });

  it('accepts a custom fallback', () => {
    expect(formatErrorMessage(null, 'view failed')).toBe('view failed');
  });

  it('does not throw when error properties and coercion are hostile', () => {
    const error = Object.defineProperties(
      {},
      {
        message: {
          get() {
            throw new Error('message getter failed');
          },
        },
        toString: {
          value() {
            throw new Error('string conversion failed');
          },
        },
      },
    );

    expect(formatErrorMessage(error, 'safe fallback')).toBe('safe fallback');
  });
});

describe('daemonErrorMessage', () => {
  it('pulls the message out of a forwarded gRPC status', () => {
    const text =
      'gRPC error: status: InvalidArgument, message: "domain must be a hostname", details: [], metadata: MetadataMap { headers: {"content-type": "application/grpc"} }';
    expect(daemonErrorMessage(text)).toBe('domain must be a hostname');
  });

  it('unescapes quotes and keeps other text unchanged', () => {
    expect(daemonErrorMessage('status: Internal, message: "bad \\"name\\"", details: []')).toBe(
      'bad "name"',
    );
    expect(daemonErrorMessage('Daemon not connected')).toBe('Daemon not connected');
  });
});

describe('tryMessage', () => {
  it('returns the reader result', () => {
    expect(tryMessage(() => 'Recover View', 'fallback')).toBe('Recover View');
  });

  it('returns fallback when the reader throws or is empty', () => {
    expect(
      tryMessage(() => {
        throw new Error('catalog missing');
      }, 'fallback'),
    ).toBe('fallback');
    expect(tryMessage(() => '   ', 'fallback')).toBe('fallback');
  });
});
