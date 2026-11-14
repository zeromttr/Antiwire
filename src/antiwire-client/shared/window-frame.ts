/**
 * How the app's windows are framed, for the main process that creates them and the renderer
 * that draws the title bar. Every platform gets an opaque window whose edge the operating
 * system draws; none is transparent with CSS-rounded corners.
 *
 * - Windows: an opaque frameless window keeps rounded corners, shadow, Snap,
 *   double-click to maximize and drag-to-restore. A transparent one loses all
 *   of that, because Electron then fakes maximize by resizing to the work area.
 * - macOS: a hidden title bar keeps the real traffic lights (hover glyphs, the
 *   green button's full-screen and tiling menu), native corners and shadow, and
 *   double-click on the bar following the user's "double-click a window's title
 *   bar to" setting.
 * - Linux: an opaque frameless window, which the window manager can maximize and tile. A
 *   transparent one draws black corners without a compositor and on some GPU drivers.
 */

/**
 * Whether closing the main window hides it to the tray. Linux desktops do not all have a
 * tray (GNOME has none by default), and a hidden window would then have no way back, so
 * there it minimizes instead.
 */
export function hidesToTray(platform: string): boolean {
  return platform !== 'linux';
}

/** Height of the custom title bar in CSS pixels; matches `.titlebar` in TitleBar.module.css. */
const TITLE_BAR_HEIGHT = 48;
const TRAFFIC_LIGHT_SIZE = 14;

/**
 * Top-left of the macOS traffic lights, centred vertically in the title bar.
 * TitleBar.module.css reserves their width (`--traffic-light-inset`).
 */
export const TRAFFIC_LIGHT_POSITION = {
  x: 18,
  y: Math.round((TITLE_BAR_HEIGHT - TRAFFIC_LIGHT_SIZE) / 2),
};
