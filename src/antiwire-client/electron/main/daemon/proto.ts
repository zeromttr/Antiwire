import type { MethodDefinition, ServiceDefinition } from '@grpc/grpc-js';
import type { Options } from '@grpc/proto-loader';
import { loadGrpcRuntime } from './runtime';

/**
 * Decoding chosen so messages map onto the client's DTOs with little work:
 * camelCase fields (serde's `rename_all = "camelCase"` produces the same
 * names), 64-bit integers as numbers (the renderer could never hold more
 * precision anyway), enums by name, and every scalar defaulted the way prost
 * defaults them. Proto3 `optional` fields are left out when unset, which is
 * how the client tells an older daemon from a confirmed `false`.
 */
export const PROTO_LOADER_OPTIONS: Options = {
  keepCase: false,
  longs: Number,
  enums: String,
  defaults: true,
  arrays: true,
  objects: true,
  oneofs: false,
};

const SERVICE_NAME = 'antiwire.AntiwireService';

export type AnyMethod = MethodDefinition<object, object>;

/** Loads `AntiwireService` from the daemon's proto file. */
export async function loadService(protoPath: string): Promise<ServiceDefinition> {
  const { protoLoader } = await loadGrpcRuntime();
  const definition = protoLoader.loadSync(protoPath, PROTO_LOADER_OPTIONS);
  const service = definition[SERVICE_NAME];
  if (!service || 'format' in service) {
    throw new Error(`${protoPath} does not define ${SERVICE_NAME}`);
  }
  return service as ServiceDefinition;
}
