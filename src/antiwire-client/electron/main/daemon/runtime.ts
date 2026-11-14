/**
 * The gRPC libraries, loaded on first use instead of at startup. Importing
 * grpc-js and proto-loader costs tens of milliseconds, and a static import
 * would spend it before the main window exists. `index.ts` starts the load
 * once the window is created, so it overlaps the renderer's own start-up.
 */
export interface GrpcRuntime {
  grpc: typeof import('@grpc/grpc-js');
  protoLoader: typeof import('@grpc/proto-loader');
}

let loading: Promise<GrpcRuntime> | null = null;

export function loadGrpcRuntime(): Promise<GrpcRuntime> {
  if (!loading) {
    loading = Promise.all([import('@grpc/grpc-js'), import('@grpc/proto-loader')]).then(
      ([grpc, protoLoader]) => ({ grpc, protoLoader }),
    );
    // A failed load must not stick: the next call retries.
    loading.catch(() => {
      loading = null;
    });
  }
  return loading;
}
