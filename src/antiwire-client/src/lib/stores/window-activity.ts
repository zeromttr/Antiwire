import { listen } from '#lib/bridge.ts';
import { Reactive } from '#lib/state/reactive.ts';

/**
 * Whether the user is looking at the app.
 *
 * A focused window renders at the display's full rate. An unfocused one (behind
 * another app, or on a second monitor) is "background": decorative motion
 * pauses (see `data-window` in app.css) and live data refreshes less often.
 * A hidden window is background too; the renderer then stops drawing anyway.
 */
class WindowActivity extends Reactive {
  #focused = true;

  /** The window has keyboard focus and is visible. */
  get focused(): boolean {
    return this.#focused;
  }

  get background() {
    return !this.#focused;
  }

  #started = false;
  #onForeground = new Set<() => void>();

  /** Calls `callback` each time the window comes back to the foreground. */
  onForeground(callback: () => void): () => void {
    this.#onForeground.add(callback);
    return () => this.#onForeground.delete(callback);
  }

  /** Installs the listeners once; returns a stop function. */
  start(): () => void {
    if (this.#started || typeof window === 'undefined') return () => {};
    this.#started = true;

    let windowFocused = document.hasFocus();
    // Electron reports a window hidden to the tray here; the document's own
    // visibility does not always change when the native window is hidden.
    let nativeVisible = true;
    const sync = () => {
      const focused = windowFocused && nativeVisible && document.visibilityState === 'visible';
      if (focused === this.#focused) return;
      this.#focused = focused;
      this.changed();
      document.documentElement.dataset.window = focused ? 'foreground' : 'background';
      if (focused) for (const callback of this.#onForeground) callback();
    };
    const onFocus = () => {
      windowFocused = true;
      sync();
    };
    const onBlur = () => {
      windowFocused = false;
      sync();
    };

    window.addEventListener('focus', onFocus);
    window.addEventListener('blur', onBlur);
    document.addEventListener('visibilitychange', sync);
    // A no-op in the browser preview.
    const unlistenVisibility = listen('window://visibility', (visible) => {
      nativeVisible = visible;
      sync();
    });
    document.documentElement.dataset.window = 'foreground';
    sync();

    return () => {
      this.#started = false;
      window.removeEventListener('focus', onFocus);
      window.removeEventListener('blur', onBlur);
      document.removeEventListener('visibilitychange', sync);
      unlistenVisibility();
      delete document.documentElement.dataset.window;
    };
  }
}

export const windowActivity = new WindowActivity();

/**
 * Pace for a live refresh: `foreground` while the user is looking, else
 * `background`. Timers read it on every tick so a focus change applies at once.
 */
export function livePace(foreground: number, background: number): number {
  return windowActivity.focused ? foreground : background;
}
