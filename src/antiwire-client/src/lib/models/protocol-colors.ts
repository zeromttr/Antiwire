import { isWellKnownProtocolName, wellKnownProtocolNames } from './well-known-ports';

export const PROTOCOL_HUE_CONFLICT_DEGREES = 30;
export const PROTOCOL_THEME_SATURATION_MIN = 0.14;

/** Preferred hues for the protocols people see most. Others are hashed into the gaps. */
const SEMANTIC_HUES: Record<string, number> = {
  HTTPS: 200,
  HTTP: 214,
  DNS: 232,
  DOT: 220,
  MDNS: 248,
  LLMNR: 260,
  SSH: 36,
  SMB: 48,
  RDP: 0,
  DHCP: 98,
  NTP: 86,
  SPOTIFY: 72,
  STEAM: 206,
  OPENVPN: 318,
  IKE: 292,
  SIP: 308,
  MQTT: 164,
  MYSQL: 22,
  POSTGRES: 188,
  REDIS: 8,
};

const HUE_SHIFTS = [180, 90, 270, 45, 135, 225, 315, 60, 120, 150, 210, 240, 300, 330];

const PROTOCOL_HUES = buildProtocolHues();

type Rgb = { r: number; g: number; b: number };

export function hueDistance(a: number, b: number): number {
  const delta = Math.abs(a - b) % 360;
  return Math.min(delta, 360 - delta);
}

function normalizeHue(hue: number): number {
  return ((hue % 360) + 360) % 360;
}

function hashHue(name: string): number {
  let hash = 2166136261;
  for (let i = 0; i < name.length; i++) {
    hash ^= name.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0) % 360;
}

function claimHue(preferred: number, taken: number[]): number {
  let hue = normalizeHue(preferred);
  for (let step = 0; step < 51; step++) {
    if (!taken.some((existing) => hueDistance(existing, hue) < 4)) {
      taken.push(hue);
      return hue;
    }
    hue = normalizeHue(hue + 7);
  }
  taken.push(hue);
  return hue;
}

function buildProtocolHues(): Readonly<Record<string, number>> {
  const hues: Record<string, number> = {};
  const taken: number[] = [];
  const names = wellKnownProtocolNames();

  for (const name of names) {
    const semantic = SEMANTIC_HUES[name];
    if (semantic == null) continue;
    hues[name] = claimHue(semantic, taken);
  }

  for (const name of names) {
    if (hues[name] != null) continue;
    hues[name] = claimHue(hashHue(name), taken);
  }

  return hues;
}

/** Base hue for a named protocol, before theme/accent remapping. */
export function protocolBaseHue(name: string): number | undefined {
  return PROTOCOL_HUES[name.trim().toUpperCase()];
}

export function parseCssRgb(value: string): Rgb | null {
  const hex = value.trim().match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/i);
  if (hex) {
    let raw = hex[1]!;
    if (raw.length === 3) {
      raw = raw
        .split('')
        .map((ch) => ch + ch)
        .join('');
    }
    const n = Number.parseInt(raw, 16);
    return { r: (n >> 16) & 255, g: (n >> 8) & 255, b: n & 255 };
  }

  const rgb = value
    .trim()
    .match(/^rgba?\(\s*([\d.]+)\s*,\s*([\d.]+)\s*,\s*([\d.]+)(?:\s*,\s*[\d.]+)?\s*\)$/i);
  if (!rgb) return null;
  return {
    r: Math.round(Number(rgb[1])),
    g: Math.round(Number(rgb[2])),
    b: Math.round(Number(rgb[3])),
  };
}

export function rgbToHueSaturation(rgb: Rgb): { h: number; s: number } {
  const r = rgb.r / 255;
  const g = rgb.g / 255;
  const b = rgb.b / 255;
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  const delta = max - min;
  const l = (max + min) / 2;
  if (delta === 0) return { h: 0, s: 0 };

  const s = l > 0.5 ? delta / (2 - max - min) : delta / (max + min);
  let h: number;
  if (max === r) h = (g - b) / delta + (g < b ? 6 : 0);
  else if (max === g) h = (b - r) / delta + 2;
  else h = (r - g) / delta + 4;
  return { h: (h / 6) * 360, s };
}

/** Saturated theme/accent hues that protocol colors must stay away from. */
export function reservedHuesFromColors(colors: Iterable<string>): number[] {
  const hues: number[] = [];
  for (const color of colors) {
    const rgb = parseCssRgb(color);
    if (!rgb) continue;
    const { h, s } = rgbToHueSaturation(rgb);
    if (s < PROTOCOL_THEME_SATURATION_MIN) continue;
    hues.push(h);
  }
  return hues;
}

export function resolveProtocolHue(
  name: string,
  reservedHues: readonly number[],
): number | undefined {
  const base = protocolBaseHue(name);
  if (base == null) return undefined;
  if (
    !reservedHues.some((reserved) => hueDistance(base, reserved) < PROTOCOL_HUE_CONFLICT_DEGREES)
  ) {
    return base;
  }

  for (const shift of HUE_SHIFTS) {
    const candidate = normalizeHue(base + shift);
    if (
      reservedHues.every(
        (reserved) => hueDistance(candidate, reserved) >= PROTOCOL_HUE_CONFLICT_DEGREES,
      )
    ) {
      return candidate;
    }
  }

  return normalizeHue(base + 180);
}

export function protocolTextColor(
  name: string,
  appearance: 'light' | 'dark',
  reservedHues: readonly number[],
): string | undefined {
  const hue = resolveProtocolHue(name, reservedHues);
  if (hue == null) return undefined;
  const sat = appearance === 'dark' ? 66 : 74;
  const light = appearance === 'dark' ? 74 : 38;
  return `hsl(${hue.toFixed(1)} ${sat}% ${light}%)`;
}

export function protocolCssVarName(name: string): string {
  return `--proto-${name
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')}`;
}

/** CSS color for a named protocol cell, or undefined for TCP/UDP/unknown. */
export function recordProtocolColorVar(label: string): string | undefined {
  const name = label.trim().toUpperCase();
  if (!isWellKnownProtocolName(name)) return undefined;
  return `var(${protocolCssVarName(name)}, var(--t3))`;
}

export function applyProtocolColorProperties(
  style: CSSStyleDeclaration,
  appearance: 'light' | 'dark',
  reservedColors: Iterable<string>,
) {
  const reservedHues = reservedHuesFromColors(reservedColors);
  for (const name of wellKnownProtocolNames()) {
    const color = protocolTextColor(name, appearance, reservedHues);
    if (!color) continue;
    style.setProperty(protocolCssVarName(name), color);
  }
}

export function refreshDocumentProtocolColors(root: HTMLElement | null = null) {
  if (typeof document === 'undefined') return;
  const target = root ?? document.documentElement;
  const appearance = target.dataset.theme === 'light' ? 'light' : 'dark';
  const styles = getComputedStyle(target);
  applyProtocolColorProperties(target.style, appearance, [
    styles.getPropertyValue('--acc-base'),
    styles.getPropertyValue('--bg'),
    styles.getPropertyValue('--p1'),
  ]);
}
