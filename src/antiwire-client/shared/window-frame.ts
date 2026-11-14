/**
 * Whether windows on `platform` (a `process.platform` value) use the
 * operating system's own frame rather than a transparent, CSS-rounded one.
 *
 * - Windows: an opaque frameless window keeps rounded corners, shadow, Snap,
 *   double-click to maximize and drag-to-restore. A transparent one loses all
 *   of that, because Electron then fakes maximize by resizing to the work area.
 * - macOS: a hidden title bar keeps the real traffic lights (hover glyphs, the
 *   green button's full-screen and tiling menu), native corners and shadow, and
 *   double-click on the bar following the user's "double-click a window's title
 *   bar to" setting.
 * - Linux stays transparent so CSS can round the corners.
 */
export function usesNativeWindowFrame(platform: string): boolean {
  return platform === 'win32' || platform === 'darwin';
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
