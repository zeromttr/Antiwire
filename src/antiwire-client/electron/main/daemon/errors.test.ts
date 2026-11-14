import { describe, expect, it } from 'bun:test';
import { Metadata, status } from '@grpc/grpc-js';
import { accessDeniedMessage, ipcClientGroup, toDaemonError } from './errors';
import { GrpcStatus } from './grpc-status';

describe('GrpcStatus', () => {
  it('matches the codes grpc-js uses', () => {
    for (const [name, code] of Object.entries(GrpcStatus)) {
      expect(status[name as keyof typeof status]).toBe(code);
    }
    const numeric = Object.values(status).filter((value) => typeof value === 'number');
    expect(Object.keys(GrpcStatus)).toHaveLength(numeric.length);
  });
});

/** The renderer's parser (`daemonErrorMessage` in `src/lib/utils/error.ts`). */
function humanPart(text: string): string {
  const match = /message: "((?:[^"\\]|\\.)*)"/.exec(text);
  return match ? match[1].replace(/\\(.)/g, '$1') : text;
}

describe('accessDeniedMessage', () => {
  for (const platform of ['win32', 'darwin', 'linux'] as const) {
    it(`names the group to join on ${platform}`, () => {
      const message = accessDeniedMessage(platform);
      expect(message).toContain(ipcClientGroup(platform));
      expect(message).toContain('sign out');
    });
  }

  it('uses the Windows group name there', () => {
    expect(ipcClientGroup('win32')).toBe('Antiwire Users');
    expect(ipcClientGroup('linux')).toBe('antiwire');
  });
});

describe('toDaemonError', () => {
  it('renders a status like tonic so the UI can pull out the message', () => {
    const error = Object.assign(new Error('3 INVALID_ARGUMENT: x'), {
      code: status.INVALID_ARGUMENT,
      details: 'domain must be a "hostname"',
      metadata: new Metadata(),
    });
    const converted = toDaemonError(error);
    expect(converted.message.startsWith('gRPC error: status: InvalidArgument, message: ')).toBe(
      true,
    );
    expect(humanPart(converted.message)).toBe('domain must be a "hostname"');
    expect(converted.code).toBe(status.INVALID_ARGUMENT);
  });

  it('keeps other errors as they are', () => {
    expect(toDaemonError(new Error('boom')).message).toBe('boom');
  });
});
