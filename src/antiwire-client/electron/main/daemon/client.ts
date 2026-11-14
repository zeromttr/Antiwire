// Types only: the library itself is loaded on first connect (see `runtime.ts`).
import type {
  ChannelCredentials,
  ChannelOptions,
  Client,
  ClientReadableStream,
  Metadata,
  ServiceDefinition,
  StatusObject,
} from '@grpc/grpc-js';
import { GrpcStatus } from './grpc-status';
import { loadGrpcRuntime, type GrpcRuntime } from './runtime';
import {
  IpcCredentialResolver,
  isAccessDenied,
  readCertAt,
  readTokenAt,
  type CredentialHost,
  defaultHost,
} from './credentials';
import { accessDenied, DaemonError, noCredentials, notConnected, toDaemonError } from './errors';
import type { StreamRpcs, UnaryRpcs } from './messages';
import type { AnyMethod } from './proto';

/** Metadata key the daemon reads the IPC token from (`antiwire_proto::TOKEN_HEADER`). */
export const TOKEN_HEADER = 'x-antiwire-token';

const RPC_TIMEOUT_MS = 10_000;
/**
 * For requests that wait on servers outside this machine (domain registries,
 * the DNS upstream, crt.sh and the AI backend), and for the daemon's own slow
 * work, such as putting a settings change into effect.
 */
const SLOW_RPC_TIMEOUT_MS = 120_000;

/**
 * How long a call may take. `stream` has no deadline: a grpc-js deadline
 * covers the whole call, and a live stream is meant to run until cancelled.
 * The Rust client's channel timeout only bounded the wait for response
 * headers, which `openStream` reproduces by settling on the headers.
 */
export type CallSpeed = 'normal' | 'slow' | 'stream';

export function deadlineFor(speed: CallSpeed, now = Date.now()): Date | undefined {
  if (speed === 'stream') return undefined;
  return new Date(now + (speed === 'slow' ? SLOW_RPC_TIMEOUT_MS : RPC_TIMEOUT_MS));
}

/** Large log exports and capture chunks exceed grpc-js's 4 MiB default. */
const MAX_MESSAGE_BYTES = 64 * 1024 * 1024;

export interface Transport {
  target: string;
  credentials: ChannelCredentials;
  options: ChannelOptions;
}

/**
 * Windows: TLS over loopback, trusting only the daemon's published
 * certificate. It is issued for `localhost` and `127.0.0.1`; naming
 * `localhost` keeps grpc-js from sending an IP address as the TLS server name.
 * Elsewhere: the daemon's Unix socket, which only root and the client group
 * may open.
 */
export function transportFor(
  { credentials }: GrpcRuntime['grpc'],
  host: CredentialHost,
  certPem: Buffer,
): Transport {
  const options: ChannelOptions = {
    'grpc.max_receive_message_length': MAX_MESSAGE_BYTES,
  };
  if (host.platform === 'win32') {
    return {
      target: '127.0.0.1:50051',
      credentials: credentials.createSsl(certPem),
      options: {
        ...options,
        'grpc.ssl_target_name_override': 'localhost',
        'grpc.default_authority': 'localhost',
      },
    };
  }
  const socket = host.env.ANTIWIRE_IPC_SOCKET ?? '/var/run/antiwire.sock';
  return { target: `unix:${socket}`, credentials: credentials.createInsecure(), options };
}

/** Request metadata carrying `token`. The token is never part of an error message. */
function tokenMetadata(grpc: GrpcRuntime['grpc'], token: string): Metadata {
  const metadata = new grpc.Metadata();
  try {
    metadata.set(TOKEN_HEADER, token);
  } catch {
    // grpc-js quotes the rejected value in its error; keep the token out of it.
    throw new DaemonError('invalid IPC token', GrpcStatus.UNAUTHENTICATED);
  }
  return metadata;
}

/**
 * The daemon connection. One channel serves every call; the deadline is
 * chosen per call (see `CallSpeed`), so slow lookups need no channel of
 * their own.
 */
export class GrpcClient {
  #client: Client | null = null;
  #service: ServiceDefinition | null = null;
  /** Set by the first `connect`; every call needs a connection, so it is set before any call. */
  #grpc: GrpcRuntime['grpc'] | null = null;
  readonly #resolver: IpcCredentialResolver;

  constructor(
    private readonly loadService: () => Promise<ServiceDefinition>,
    private readonly host: CredentialHost = defaultHost(),
  ) {
    this.#resolver = new IpcCredentialResolver(host);
  }

  isConnected(): boolean {
    return this.#client !== null;
  }

  /**
   * Loads grpc-js and the service definition. `connect` awaits it; calling it
   * early (at start-up) only moves the work off the first connection's path.
   */
  async prepare(): Promise<void> {
    this.#grpc ??= (await loadGrpcRuntime()).grpc;
    this.#service ??= await this.loadService();
  }

  #method(name: string): AnyMethod {
    if (!this.#service) throw notConnected();
    const method = this.#service[name] as AnyMethod | undefined;
    if (!method) throw new DaemonError(`the daemon API has no method ${name}`);
    return method;
  }

  async connect(): Promise<void> {
    const candidates = this.#resolver.candidateTokenPaths();
    if (candidates.length === 0) {
      this.disconnect();
      throw noCredentials();
    }
    try {
      await this.prepare();
    } catch (error) {
      this.disconnect();
      throw toDaemonError(error);
    }

    let lastError: DaemonError | null = null;
    let denied = false;
    for (const tokenPath of candidates) {
      const token = readTokenAt(tokenPath);
      if (!token) {
        denied ||= isAccessDenied(tokenPath);
        continue;
      }
      const cert =
        this.host.platform === 'win32'
          ? readCertAt(this.#resolver.certPathFor(tokenPath))
          : Buffer.alloc(0);
      try {
        const client = await this.#tryConnect(token, cert);
        this.#resolver.resolve(tokenPath, token);
        this.#replaceClient(client);
        return;
      } catch (error) {
        lastError = toDaemonError(error);
      }
    }

    // Drop any client from a previous connection so a failed reconnect cannot
    // leave a dead channel being handed out.
    this.disconnect();
    // A token this account cannot read explains any other failure: a stale
    // token elsewhere is rejected precisely because the live one is out of reach.
    throw denied ? accessDenied() : (lastError ?? noCredentials());
  }

  disconnect(): void {
    this.#replaceClient(null);
  }

  #replaceClient(next: Client | null): void {
    const previous = this.#client;
    this.#client = next;
    if (previous && previous !== next) previous.close();
  }

  /** Opens a channel and proves `token` is accepted. */
  async #tryConnect(token: string, cert: Buffer): Promise<Client> {
    const grpc = this.#requireGrpc();
    const transport = transportFor(grpc, this.host, cert);
    const client = new grpc.Client(transport.target, transport.credentials, transport.options);
    try {
      await this.#unaryOn(client, 'GetStats', {}, tokenMetadata(grpc, token), 'normal');
      return client;
    } catch (error) {
      client.close();
      throw error;
    }
  }

  #requireClient(): Client {
    if (!this.#client) throw notConnected();
    return this.#client;
  }

  #requireGrpc(): GrpcRuntime['grpc'] {
    if (!this.#grpc) throw notConnected();
    return this.#grpc;
  }

  /** Metadata for a call on the live connection, with the current token. */
  #metadata(): Metadata {
    return tokenMetadata(this.#requireGrpc(), this.#resolver.currentBestToken());
  }

  #unaryOn<M extends keyof UnaryRpcs>(
    client: Client,
    name: M,
    request: UnaryRpcs[M][0],
    metadata: Metadata,
    speed: CallSpeed,
  ): Promise<UnaryRpcs[M][1]> {
    const method = this.#method(name);
    return new Promise((resolve, reject) => {
      client.makeUnaryRequest(
        method.path,
        method.requestSerialize,
        method.responseDeserialize,
        request,
        metadata,
        { deadline: deadlineFor(speed) },
        (error, response) => {
          if (error) reject(toDaemonError(error));
          else resolve(response as UnaryRpcs[M][1]);
        },
      );
    });
  }

  /** Calls a unary RPC. `slow` is for requests that wait on servers outside this machine. */
  unary<M extends keyof UnaryRpcs>(
    name: M,
    request: UnaryRpcs[M][0],
    speed: Exclude<CallSpeed, 'stream'> = 'normal',
  ): Promise<UnaryRpcs[M][1]> {
    return this.#unaryOn(this.#requireClient(), name, request, this.#metadata(), speed);
  }

  /**
   * Starts a server stream and resolves once the daemon has accepted it (its
   * response headers arrived), so a refused stream fails the command that
   * started it. Aborting `signal` cancels the call. Read the result with
   * `for await`; errors after acceptance surface there.
   */
  openStream<M extends keyof StreamRpcs>(
    name: M,
    request: StreamRpcs[M][0],
    signal: AbortSignal,
    speed: CallSpeed = 'stream',
  ): Promise<ClientReadableStream<StreamRpcs[M][1]>> {
    const method = this.#method(name);
    const call = this.#requireClient().makeServerStreamRequest(
      method.path,
      method.requestSerialize,
      method.responseDeserialize,
      request,
      this.#metadata(),
      { deadline: deadlineFor(speed) },
    ) as ClientReadableStream<StreamRpcs[M][1]>;
    // Errors are read through the async iterator; this keeps one that arrives
    // before iteration starts from being an unhandled 'error' event.
    call.on('error', () => {});
    const cancel = () => call.cancel();
    if (signal.aborted) cancel();
    else signal.addEventListener('abort', cancel, { once: true });
    call.once('close', () => signal.removeEventListener('abort', cancel));

    return new Promise((resolve, reject) => {
      const settle = (error: unknown) => {
        call.off('metadata', onMetadata);
        call.off('status', onStatus);
        call.off('error', onError);
        if (error) reject(toDaemonError(error));
        else resolve(call);
      };
      const onMetadata = () => settle(null);
      const onStatus = (status: StatusObject) =>
        settle(
          status.code === GrpcStatus.OK
            ? null
            : Object.assign(new Error(status.details), {
                code: status.code,
                details: status.details,
              }),
        );
      const onError = (error: Error) => settle(error);
      call.on('metadata', onMetadata);
      call.on('status', onStatus);
      call.on('error', onError);
    });
  }
}
