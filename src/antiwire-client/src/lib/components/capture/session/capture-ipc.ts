import { api, type CapturedPacketDto, type CaptureStatusDto } from '#lib/api/daemon.ts';
import { formatErrorMessage } from '#lib/utils/error.ts';
import { buildDefaultCaptureFilename } from './capture-policy';

export { buildDefaultCaptureFilename };

export interface CaptureStartOptions {
  deviceName: string;
  appPath: string;
  appName: string;
  captureFilter: string;
  snapLength: number;
  promiscuous: boolean;
  maxSeconds: number;
  maxBytes: number;
}

export interface CaptureIpc {
  listDevices: typeof api.listCaptureDevices;
  startCapture: (options: CaptureStartOptions) => Promise<string>;
  stopCapture: typeof api.stopCapture;
  getStatus: typeof api.getCaptureStatus;
  startPacketStream: typeof api.startCapturePacketStream;
  downloadCapture: typeof api.downloadCapture;
  openPacketInspector: typeof api.openPacketInspector;
  /** Native save dialog. Returns `null` when cancelled; throws an `Error` on failure. */
  pickSavePath: (defaultPath: string, filterName: string) => Promise<string | null>;
}

/**
 * IPC adapter for the capture route. Keeps all native dialog/IPC calls in one
 * place so the route component only deals with session state + rendering,
 * and so every native operation has a single, consistent error path.
 */
export function createCaptureIpc(overrides?: Partial<CaptureIpc>): CaptureIpc {
  return {
    listDevices: (...args) => api.listCaptureDevices(...args),
    startCapture: (options) => api.startCapture(options),
    stopCapture: (...args) => api.stopCapture(...args),
    getStatus: (...args) => api.getCaptureStatus(...args),
    startPacketStream: (...args) => api.startCapturePacketStream(...args),
    downloadCapture: (...args) => api.downloadCapture(...args),
    openPacketInspector: (...args) => api.openPacketInspector(...args),
    pickSavePath: async (defaultPath, filterName) => {
      try {
        return await api.pickSavePath(defaultPath, filterName, ['pcap']);
      } catch (error) {
        throw new Error(formatErrorMessage(error), { cause: error });
      }
    },
    ...overrides,
  };
}

export type { CapturedPacketDto, CaptureStatusDto };
