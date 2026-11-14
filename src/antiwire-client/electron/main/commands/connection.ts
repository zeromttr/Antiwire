import {
  daemon,
  desktopNotificationsAreEnabled,
  notificationTask,
  setDesktopNotificationsEnabled,
  trafficStreamTask,
} from '../daemon/connection';
import { pumpBatched } from '../daemon/stream-pump';
import { eventToDto } from '../dto/alerts';
import { trafficToDto } from '../dto/traffic';
import { showDesktopNotification } from '../notifications';
import { emitToMain } from '../windows';
import { noArgs, type CommandTable } from './define';

/** Live traffic events held between ticks; beyond this the oldest are dropped. */
const MAX_PENDING_TRAFFIC = 500;

/**
 * Reads the notification stream until it ends. The stream is the
 * connection's heartbeat: when it ends the daemon is gone, so report
 * disconnected and tell the UI.
 */
async function runNotificationStream(signal: AbortSignal): Promise<void> {
  const closed = () => {
    if (signal.aborted) return;
    notificationTask.finish(signal);
    daemon.disconnect();
    emitToMain('daemon://stream-closed', null);
  };
  try {
    const stream = await daemon.openStream('StreamNotifications', {}, signal);
    for await (const event of stream) {
      const dto = eventToDto(event);
      emitToMain('daemon-notification', dto);
      if (desktopNotificationsAreEnabled()) showDesktopNotification(dto.title, dto.body);
    }
  } catch {
    // Any failure ends the connection the same way as the stream ending.
  }
  closed();
}

export const connectionCommands = {
  get_connection_status: noArgs(() => ({ connected: daemon.isConnected() })),

  connect_daemon: noArgs(async () => {
    // Stopped first: closing the old channel ends its stream, which must not
    // be mistaken for the new connection dropping.
    notificationTask.abort();
    await daemon.connect();
    // Fail closed until the daemon confirms the persisted preference.
    setDesktopNotificationsEnabled(false);
    try {
      const settings = await daemon.unary('GetSettings', {});
      setDesktopNotificationsEnabled(settings.notifyEveryConnection === true);
    } catch {
      // Leave desktop notifications off.
    }
    void runNotificationStream(notificationTask.replace());
    return true;
  }),

  disconnect_daemon: noArgs(() => {
    notificationTask.abort();
    daemon.disconnect();
  }),

  /**
   * Forwards the daemon's live traffic stream as batched `traffic://event`
   * payloads (an array per 100ms tick). Events only flow while the daemon has
   * subscribers, so the UI can stop the stream when its real-time toggle is off.
   */
  start_realtime_traffic: noArgs(async () => {
    const signal = trafficStreamTask.replace();
    const stream = await daemon.openStream('StreamRealtimeTraffic', {}, signal).catch((error) => {
      trafficStreamTask.finish(signal);
      throw error;
    });
    void pumpBatched({
      source: stream,
      signal,
      map: trafficToDto,
      emit: (batch) => emitToMain('traffic://event', batch),
      maxPending: MAX_PENDING_TRAFFIC,
    }).finally(() => trafficStreamTask.finish(signal));
  }),

  stop_realtime_traffic: noArgs(() => trafficStreamTask.abort()),
} satisfies Partial<CommandTable>;
