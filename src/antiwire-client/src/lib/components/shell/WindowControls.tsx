import clsx from 'clsx';
import { memo, useState } from 'react';
import { api } from '#lib/api/daemon.ts';
import { isNative } from '#lib/bridge.ts';
import { m } from '#lib/i18n/messages.ts';
import { browserPreviewMode } from '#lib/preview/runtime.ts';
import type { WindowPlatform } from '#lib/utils/window-platform.ts';
import styles from './WindowControls.module.css';

type Action = 'close' | 'minimize' | 'maximize';

interface Props {
  platform: WindowPlatform;
  maximizable: boolean;
  maximized: boolean;
  onMaximize: () => Promise<void>;
  /** Receives a user-facing message, or `''` to clear it before each action. */
  onError: (message: string) => void;
}

export const WindowControls = memo(function WindowControls({
  platform,
  maximizable,
  maximized,
  onMaximize,
  onError,
}: Props) {
  const [busy, setBusy] = useState(false);
  const actions: readonly Action[] =
    platform === 'macos' ? ['close', 'minimize', 'maximize'] : ['minimize', 'maximize', 'close'];

  function name(action: Action) {
    if (action === 'close') return m.shell_close_aria();
    if (action === 'minimize') return m.shell_minimize_aria();
    return maximized ? m.shell_restore_aria() : m.shell_maximize_aria();
  }

  async function run(action: Action) {
    // Browser previews cannot operate on the containing browser window.
    if (busy) return;
    if (!isNative() && !(browserPreviewMode && !maximizable && action === 'close')) return;
    setBusy(true);
    onError('');
    try {
      if (action === 'close') await api.closeWindow();
      else if (action === 'minimize') await api.minimizeWindow();
      else await onMaximize();
    } catch (error) {
      console.error('[antiwire] window action failed', error);
      onError(m.shell_window_error());
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className={styles.controls} data-platform={platform}>
      {actions.map((action) =>
        action !== 'maximize' || maximizable ? (
          <button
            key={action}
            type="button"
            className={clsx(styles.ctrl, styles[action])}
            aria-label={name(action)}
            title={name(action)}
            disabled={busy}
            onClick={() => void run(action)}
          >
            <span className={styles.controlFace} aria-hidden="true">
              <svg
                width="12"
                height="12"
                viewBox="0 0 12 12"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.2"
              >
                {action === 'close' ? (
                  <path d="m2 2 8 8M10 2l-8 8" />
                ) : action === 'minimize' ? (
                  <path d="M1.5 6h9" />
                ) : maximized ? (
                  <>
                    <path d="M4 3V1.5h6.5V8H9" />
                    <rect x="1.5" y="4" width="6.5" height="6.5" rx=".5" />
                  </>
                ) : platform === 'macos' ? (
                  <path d="M6 2v8M2 6h8" />
                ) : (
                  <rect x="1.5" y="1.5" width="9" height="9" rx=".5" />
                )}
              </svg>
            </span>
          </button>
        ) : null,
      )}
    </div>
  );
});

export default WindowControls;
