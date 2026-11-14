export interface AccentPreset {
  id: string;
  label: string;
  color: string;
  /** Paired tone for upload / secondary highlights (not semantic warnings). */
  subColor: string;
}

export const DEFAULT_ACCENT_ID = 'mint';

/** Ordered around the color wheel so the picker reads as a spectrum. */
export const ACCENT_PRESETS: AccentPreset[] = [
  { id: 'mint', label: 'Mint', color: '#3ee6a0', subColor: '#5ce8ff' },
  { id: 'cyan', label: 'Cyan', color: '#4dd8e6', subColor: '#8ae4ff' },
  { id: 'sapphire', label: 'Sapphire', color: '#6b9eff', subColor: '#a89bff' },
  { id: 'lavender', label: 'Lavender', color: '#a89bff', subColor: '#ff9ec4' },
  { id: 'violet', label: 'Violet', color: '#b026ff', subColor: '#ff6fd6' },
  { id: 'magenta', label: 'Magenta', color: '#ff2bd6', subColor: '#ff8ae8' },
  { id: 'rose', label: 'Rose', color: '#ff3864', subColor: '#ff9a7a' },
  { id: 'copper', label: 'Copper', color: '#e8956a', subColor: '#ffd070' },
  { id: 'amber', label: 'Amber', color: '#ffb000', subColor: '#ff7a45' },
  { id: 'champagne', label: 'Champagne', color: '#e4c88a', subColor: '#f0a06a' },
  { id: 'lime', label: 'Lime', color: '#b6ff00', subColor: '#e8d44a' },
  { id: 'plasma', label: 'Plasma', color: '#55fbff', subColor: '#9d7cff' },
];

const HEX_COLOR = /^#[0-9a-f]{6}$/i;

/** A custom accent is stored as its `#rrggbb` hex in place of a preset id. */
export function isCustomAccentId(id: string | null | undefined): id is string {
  return typeof id === 'string' && HEX_COLOR.test(id);
}

function defaultPreset(): AccentPreset {
  return ACCENT_PRESETS.find((p) => p.id === DEFAULT_ACCENT_ID)!;
}

export function accentPresetById(id: string): AccentPreset {
  if (isCustomAccentId(id)) {
    const color = id.toLowerCase();
    // A custom colour identical to a preset is that preset.
    const preset = ACCENT_PRESETS.find((p) => p.color === color);
    if (preset) return preset;
    return { id: color, label: 'Custom', color, subColor: rotateHue(color, 36) };
  }
  return ACCENT_PRESETS.find((p) => p.id === id) ?? defaultPreset();
}

export function normalizeAccentId(id: string): string {
  return accentPresetById(id).id;
}

// --- OKLCH helpers -------------------------------------------------------
// Mirrors the relative-color rules in app.css so canvas and SVG charts, which
// take literal colors, match what CSS paints.

interface Oklch {
  l: number;
  c: number;
  h: number;
}

function toLinear(channel: number): number {
  const v = channel / 255;
  return v <= 0.04045 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
}

function fromLinear(v: number): number {
  const s = v <= 0.0031308 ? v * 12.92 : 1.055 * Math.pow(v, 1 / 2.4) - 0.055;
  return Math.round(Math.min(1, Math.max(0, s)) * 255);
}

function hexToOklch(hex: string): Oklch {
  const n = parseInt(hex.slice(1), 16);
  const r = toLinear((n >> 16) & 255);
  const g = toLinear((n >> 8) & 255);
  const b = toLinear(n & 255);
  const l = Math.cbrt(0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b);
  const m = Math.cbrt(0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b);
  const s = Math.cbrt(0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b);
  const L = 0.2104542553 * l + 0.793617785 * m - 0.0040720468 * s;
  const A = 1.9779984951 * l - 2.428592205 * m + 0.4505937099 * s;
  const B = 0.0259040371 * l + 0.7827717662 * m - 0.808675766 * s;
  return { l: L, c: Math.hypot(A, B), h: Math.atan2(B, A) };
}

function oklchToHex({ l: L, c, h }: Oklch): string {
  const A = c * Math.cos(h);
  const B = c * Math.sin(h);
  const l = (L + 0.3963377774 * A + 0.2158037573 * B) ** 3;
  const m = (L - 0.1055613458 * A - 0.0638541728 * B) ** 3;
  const s = (L - 0.0894841775 * A - 1.291485548 * B) ** 3;
  const r = 4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s;
  const g = -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s;
  const b = -0.0041960863 * l - 0.7034186147 * m + 1.707614701 * s;
  return '#' + [r, g, b].map((v) => fromLinear(v).toString(16).padStart(2, '0')).join('');
}

function rotateHue(hex: string, degrees: number): string {
  const color = hexToOklch(hex);
  return oklchToHex({ ...color, h: color.h + (degrees * Math.PI) / 180 });
}

/** Relative luminance (WCAG) of a `#rrggbb` color. */
export function relativeLuminance(hex: string): number {
  const n = parseInt(hex.slice(1), 16);
  return (
    0.2126 * toLinear((n >> 16) & 255) +
    0.7152 * toLinear((n >> 8) & 255) +
    0.0722 * toLinear(n & 255)
  );
}

/** Text color for content sitting on a solid accent fill. */
export function accentInkColor(hex: string): string {
  // Dark ink and white tie on contrast near a luminance of 0.18.
  return relativeLuminance(hex) > 0.18 ? '#0b0f0c' : '#ffffff';
}

/**
 * The accent as it should be drawn for text and lines on the given theme:
 * unchanged on dark surfaces, lightness capped on light ones so it stays
 * legible. Matches `oklch(from … min(l, 0.5) min(c, 0.2) h)` in app.css.
 */
export function accentForTheme(hex: string, theme: 'light' | 'dark'): string {
  if (theme === 'dark') return hex;
  const color = hexToOklch(hex);
  return oklchToHex({ l: Math.min(color.l, 0.5), c: Math.min(color.c, 0.2), h: color.h });
}
