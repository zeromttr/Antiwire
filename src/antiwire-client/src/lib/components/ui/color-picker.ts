/** Hue in degrees [0, 360), saturation and value in [0, 1]. */
export interface Hsv {
  h: number;
  s: number;
  v: number;
}

const HEX6 = /^#?([0-9a-f]{6})$/i;
const HEX3 = /^#?([0-9a-f]{3})$/i;

/** Accepts `#abc`, `abc`, `#aabbcc` or `aabbcc`; returns lowercase `#aabbcc` or null. */
export function normalizeHex(input: string): string | null {
  const value = input.trim();
  const six = value.match(HEX6);
  if (six) return `#${six[1]!.toLowerCase()}`;
  const three = value.match(HEX3);
  if (three) {
    const [r, g, b] = three[1]!.toLowerCase().split('');
    return `#${r}${r}${g}${g}${b}${b}`;
  }
  return null;
}

export function hexToHsv(hex: string): Hsv {
  const normalized = normalizeHex(hex) ?? '#000000';
  const n = parseInt(normalized.slice(1), 16);
  const r = ((n >> 16) & 255) / 255;
  const g = ((n >> 8) & 255) / 255;
  const b = (n & 255) / 255;
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  const d = max - min;
  let h = 0;
  if (d !== 0) {
    if (max === r) h = ((g - b) / d) % 6;
    else if (max === g) h = (b - r) / d + 2;
    else h = (r - g) / d + 4;
    h *= 60;
    if (h < 0) h += 360;
  }
  return { h, s: max === 0 ? 0 : d / max, v: max };
}

export function hsvToHex({ h, s, v }: Hsv): string {
  const hue = ((h % 360) + 360) % 360;
  const sat = clamp01(s);
  const val = clamp01(v);
  const c = val * sat;
  const x = c * (1 - Math.abs(((hue / 60) % 2) - 1));
  const m = val - c;
  const [r, g, b] =
    hue < 60
      ? [c, x, 0]
      : hue < 120
        ? [x, c, 0]
        : hue < 180
          ? [0, c, x]
          : hue < 240
            ? [0, x, c]
            : hue < 300
              ? [x, 0, c]
              : [c, 0, x];
  return (
    '#' +
    [r, g, b]
      .map((channel) =>
        Math.round((channel + m) * 255)
          .toString(16)
          .padStart(2, '0'),
      )
      .join('')
  );
}

export function clamp01(value: number): number {
  return Math.min(1, Math.max(0, value));
}

/** Keyboard step for the 2D area and hue strip: 1%, or 10% with Shift. */
export function stepFor(event: { shiftKey: boolean }): number {
  return event.shiftKey ? 0.1 : 0.01;
}
