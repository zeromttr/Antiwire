import type { ServiceError } from '@grpc/grpc-js';
import { GrpcStatus } from './grpc-status';

/**
 * Errors from talking to the daemon. The message is what the renderer shows,
 * so each one matches the text the Rust client produced: the UI pulls the
 * human part out of `gRPC error: status: …, message: "…"` (see
 * `daemonErrorMessage` in `src/lib/utils/error.ts`).
 */
export class DaemonError extends Error {
  constructor(
    message: string,
    /** The gRPC status code when the daemon answered with one. */
    readonly code?: number,
  ) {
    super(message);
    this.name = 'DaemonError';
  }
}

/** Local group whose members may use the daemon's API (`antiwire_proto::IPC_CLIENT_GROUP`). */
export function ipcClientGroup(platform: NodeJS.Platform = process.platform): string {
  return platform === 'win32' ? 'Antiwire Users' : 'antiwire';
}

/** How to fix an unreadable token on this platform. */
export function accessDeniedMessage(platform: NodeJS.Platform = process.platform): string {
  const group = ipcClientGroup(platform);
  const how =
    platform === 'win32'
      ? `Add it to the local "${group}" group`
      : platform === 'darwin'
        ? `Run: sudo dseditgroup -o edit -a "$USER" -t user ${group}`
        : `Run: sudo usermod -aG ${group} "$USER"`;
  return `This account is not allowed to use the Antiwire daemon. ${how}, then sign out and back in.`;
}

export const notConnected = () => new DaemonError('not connected to daemon');
export const noCredentials = () => new DaemonError('credentials not found');
/** The daemon's token exists but this account may not read it: it is not in the client group. */
export const accessDenied = () => new DaemonError(accessDeniedMessage());
/** A rejection the daemon carried in a normal reply rather than a status. */
export const rejected = (message: string) => new DaemonError(`gRPC error: ${message}`);

/** tonic's names for each status code, as its `Display` prints them. */
const CODE_NAMES: Record<number, string> = {
  [GrpcStatus.OK]: 'Ok',
  [GrpcStatus.CANCELLED]: 'Cancelled',
  [GrpcStatus.UNKNOWN]: 'Unknown',
  [GrpcStatus.INVALID_ARGUMENT]: 'InvalidArgument',
  [GrpcStatus.DEADLINE_EXCEEDED]: 'DeadlineExceeded',
  [GrpcStatus.NOT_FOUND]: 'NotFound',
  [GrpcStatus.ALREADY_EXISTS]: 'AlreadyExists',
  [GrpcStatus.PERMISSION_DENIED]: 'PermissionDenied',
  [GrpcStatus.RESOURCE_EXHAUSTED]: 'ResourceExhausted',
  [GrpcStatus.FAILED_PRECONDITION]: 'FailedPrecondition',
  [GrpcStatus.ABORTED]: 'Aborted',
  [GrpcStatus.OUT_OF_RANGE]: 'OutOfRange',
  [GrpcStatus.UNIMPLEMENTED]: 'Unimplemented',
  [GrpcStatus.INTERNAL]: 'Internal',
  [GrpcStatus.UNAVAILABLE]: 'Unavailable',
  [GrpcStatus.DATA_LOSS]: 'DataLoss',
  [GrpcStatus.UNAUTHENTICATED]: 'Unauthenticated',
};

function isServiceError(error: unknown): error is ServiceError {
  return (
    error instanceof Error &&
    typeof (error as Partial<ServiceError>).code === 'number' &&
    'details' in error
  );
}

/**
 * Converts whatever a call threw into a `DaemonError`. Status errors keep
 * their code and render like tonic's (`gRPC error: status: Code, message: "…"`);
 * response metadata is deliberately left out.
 */
export function toDaemonError(error: unknown): DaemonError {
  if (error instanceof DaemonError) return error;
  if (isServiceError(error)) {
    const name = CODE_NAMES[error.code] ?? String(error.code);
    return new DaemonError(
      `gRPC error: status: ${name}, message: ${JSON.stringify(error.details ?? '')}`,
      error.code,
    );
  }
  return new DaemonError(error instanceof Error ? error.message : String(error));
}
