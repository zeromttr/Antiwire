import { z } from 'zod';
import { approvedSavePaths } from '../approved-paths';
import { AtomicFile } from '../atomic-file';
import { captureStreamTask, daemon } from '../daemon/connection';
import { DaemonError, toDaemonError } from '../daemon/errors';
import { pumpBatched } from '../daemon/stream-pump';
import { captureDevicesToDto, captureStatusToDto, packetToDto } from '../dto/capture';
import { emitToMain } from '../windows';
import { arg, command, noArgs, type CommandTable } from './define';

/** Captured packets held between ticks; beyond this the oldest are dropped. */
const MAX_PENDING_PACKETS = 250;

const captureId = { captureId: arg.text(128) };

export const captureCommands = {
  list_capture_devices: noArgs(async () =>
    captureDevicesToDto(await daemon.unary('ListCaptureDevices', {})),
  ),

  start_capture: command(
    {
      deviceName: arg.text(512),
      captureFilter: arg.text(4096),
      snapLength: arg.u32(),
      promiscuous: z.boolean(),
      maxSeconds: arg.u32(),
      maxBytes: arg.u64(),
      appPath: arg.text(4096),
      appName: arg.text(512),
    },
    async (a) => (await daemon.unary('StartCapture', { ...a, readTimeoutMs: 1000 })).captureId,
  ),

  stop_capture: command(captureId, async ({ captureId }) => {
    const response = await daemon.unary('StopCapture', { captureId });
    // Only tear down the stream once the daemon stopped this capture, and
    // only if the stream is this capture's.
    captureStreamTask.abortIf(captureId);
    return response.success;
  }),

  get_capture_status: command(captureId, async ({ captureId }) =>
    captureStatusToDto(await daemon.unary('GetCaptureStatus', { captureId })),
  ),

  start_capture_packet_stream: command(captureId, async ({ captureId }) => {
    const signal = captureStreamTask.replace(captureId);
    const stream = await daemon
      .openStream('StreamCapturedPackets', { captureId }, signal)
      .catch((error) => {
        captureStreamTask.finish(signal);
        throw error;
      });
    void pumpBatched({
      source: stream,
      signal,
      map: (packet) => packetToDto(captureId, packet),
      emit: (batch) => emitToMain('capture://packets', batch),
      maxPending: MAX_PENDING_PACKETS,
      // The capture finished: deliver the tail instead of waiting for a tick.
      onEnd: (flush) => flush(),
      onError: (error) =>
        emitToMain('capture://stream-error', {
          captureId,
          message: toDaemonError(error).message,
        }),
    }).finally(() => captureStreamTask.finish(signal));
  }),

  download_capture: command(
    { captureId: arg.text(128), path: arg.text(4096) },
    async ({ captureId, path }) => {
      if (!path.trim()) throw new DaemonError('capture destination path is empty');
      approvedSavePaths.require(path);
      const file = await AtomicFile.create(path);
      const controller = new AbortController();
      try {
        // A local download is quick; the slow deadline only stops a hung one.
        const stream = await daemon.openStream(
          'DownloadCapture',
          { captureId },
          controller.signal,
          'slow',
        );
        let complete = false;
        for await (const chunk of stream) {
          await file.write(chunk.data);
          if (chunk.last) {
            complete = true;
            break;
          }
        }
        if (!complete) {
          throw new DaemonError('capture download ended before the daemon sent the final chunk');
        }
        await file.commit();
        return true;
      } catch (error) {
        await file.discard();
        throw toDaemonError(error);
      } finally {
        controller.abort();
      }
    },
  ),
} satisfies Partial<CommandTable>;
