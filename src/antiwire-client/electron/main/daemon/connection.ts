import { app } from 'electron';
import path from 'node:path';
import { GrpcClient } from './client';
import { loadService } from './proto';
import { TaskSlot } from './task-slot';

/**
 * The daemon's proto, loaded at runtime rather than copied into the sources:
 * from the repository in development, and in a packaged build from the copy
 * the main build emits next to its bundle (`bundleDaemonProto` in
 * electron.vite.config.ts). That copy is inside `app.asar`, so the asar
 * integrity fuse covers it like the code that reads it.
 */
export function protoPath(): string {
  return app.isPackaged
    ? path.join(app.getAppPath(), 'out', 'main', 'antiwire.proto')
    : path.resolve(app.getAppPath(), '../antiwire-rs/crates/antiwire-proto/proto/antiwire.proto');
}

/** The one daemon connection the app holds. */
export const daemon = new GrpcClient(() => loadService(protoPath()));

/** The notification stream, which doubles as the connection's heartbeat. */
export const notificationTask = new TaskSlot();
/** Keyed by the capture id the packet stream belongs to. */
export const captureStreamTask = new TaskSlot();
export const trafficStreamTask = new TaskSlot();

/**
 * Whether every daemon notification also raises a desktop notification
 * (the daemon's `notify_every_connection` setting). Off until the daemon
 * confirms the persisted preference, so it fails closed.
 */
let desktopNotificationsEnabled = false;

export function setDesktopNotificationsEnabled(enabled: boolean): void {
  desktopNotificationsEnabled = enabled;
}

export function desktopNotificationsAreEnabled(): boolean {
  return desktopNotificationsEnabled;
}

/** Stops every stream and drops the connection. Called when the app quits. */
export function shutdownDaemon(): void {
  notificationTask.abort();
  captureStreamTask.abort();
  trafficStreamTask.abort();
  daemon.disconnect();
}
