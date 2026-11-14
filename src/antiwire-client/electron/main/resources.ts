import { app, nativeImage, type NativeImage } from 'electron';
import path from 'node:path';

/** An icon from `resources/icons`, which is packed into the app archive. */
export function appIconPath(name: '32x32.png' | '128x128.png' | '128x128@2x.png'): string {
  return path.join(app.getAppPath(), 'resources', 'icons', name);
}

let notificationIcon: NativeImage | null = null;

/**
 * The icon desktop notifications show. Passed as an image, not a path:
 * Electron writes it to a real file for the OS, which cannot read inside the
 * app archive.
 */
export function notificationIconImage(): NativeImage {
  notificationIcon ??= nativeImage.createFromPath(appIconPath('128x128.png'));
  return notificationIcon;
}
