import { Notification } from 'electron';
import { notificationIconImage } from './resources';

/**
 * Shows a native desktop notification with the application icon. On Windows
 * the toast is attributed through the AppUserModelID set in `index.ts`, which
 * the installer's Start Menu shortcut registers.
 */
export function showDesktopNotification(title: string, body: string): void {
  if (!Notification.isSupported()) return;
  try {
    const icon = notificationIconImage();
    new Notification({ title, body, icon: icon.isEmpty() ? undefined : icon }).show();
  } catch (error) {
    console.warn('[antiwire] desktop notification failed', title, error);
  }
}
