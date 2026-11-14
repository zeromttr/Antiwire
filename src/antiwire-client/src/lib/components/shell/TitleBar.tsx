import clsx from 'clsx';
import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { api } from '#lib/api/daemon.ts';
import { isNative, listen } from '#lib/bridge.ts';
import { windowPlatform } from '#lib/utils/window-platform.ts';
import { WindowControls } from './WindowControls.tsx';
import applicationIcon from '../../../../resources/icons/128x128.png?inline';
import styles from './TitleBar.module.css';

interface Props {
  /** Centre slot, e.g. the tab bar (was the `nav` snippet). Without it `label` is shown. */
  nav?: ReactNode;
  label?: string;
  maximizable?: boolean;
}

const platform = windowPlatform();

/** The macOS app draws real traffic lights over the bar; the browser preview draws its own. */
const nativeTrafficLights = platform === 'macos' && isNative();

/**
 * Custom window chrome. The main process reports maximize and full-screen
 * changes through `window://maximized` and `window://fullscreen`; focus comes
 * from the renderer's own focus events. On macOS the native traffic lights sit
 * over the bar, so it only reserves their space.
 *
 * The window controls take one end of the bar and the logo the other: controls
 * on the right and the logo on the left on Windows and Linux, and the reverse
 * on macOS, where the traffic lights are on the left.
 */
export function TitleBar({ nav, label = '', maximizable = true }: Props) {
  const [maximized, setMaximized] = useState(false);
  const [fullscreen, setFullscreen] = useState(false);
  const [focused, setFocused] = useState(() =>
    typeof document === 'undefined' ? true : document.hasFocus(),
  );
  const [error, setError] = useState('');

  useEffect(() => {
    if (!isNative()) return;
    const onFocus = () => setFocused(true);
    const onBlur = () => setFocused(false);
    window.addEventListener('focus', onFocus);
    window.addEventListener('blur', onBlur);
    const stopMaximized = listen('window://maximized', (next) => setMaximized(Boolean(next)));
    const stopFullscreen = listen('window://fullscreen', (next) => setFullscreen(Boolean(next)));
    return () => {
      window.removeEventListener('focus', onFocus);
      window.removeEventListener('blur', onBlur);
      stopMaximized();
      stopFullscreen();
    };
  }, []);

  const toggleMaximize = useCallback(async () => {
    // The `window://maximized` event updates the glyph.
    await api.toggleMaximizeWindow();
  }, []);

  const controls = (
    <WindowControls
      platform={platform}
      maximizable={maximizable}
      maximized={maximized}
      onMaximize={toggleMaximize}
      onError={setError}
    />
  );

  const brand = (
    <div className={styles.brand}>
      <img
        className={styles.appIcon}
        src={applicationIcon}
        alt="Antiwire"
        width="26"
        height="26"
        draggable={false}
      />
    </div>
  );

  const hasNav = nav != null && nav !== false;

  return (
    <header
      // `titlebar` / `inactive` stay global too: WindowControls styles macOS
      // lights against `.titlebar.inactive`.
      className={clsx(styles.titlebar, 'titlebar', !focused && [styles.inactive, 'inactive'])}
      data-platform={platform}
    >
      <div className={styles.leading}>
        {nativeTrafficLights
          ? !fullscreen && <div className={styles.trafficLights} aria-hidden="true" />
          : platform === 'macos' && controls}
        {platform !== 'macos' && brand}
      </div>
      <div className={styles.center}>
        {hasNav ? (
          <div className={styles.navSlot}>{nav}</div>
        ) : (
          <span className={styles.windowLabel}>{label}</span>
        )}
      </div>
      <div className={styles.trailing}>{platform === 'macos' ? brand : controls}</div>
      {error && (
        <div className={styles.windowError} role="alert">
          {error}
        </div>
      )}
    </header>
  );
}

export default TitleBar;
