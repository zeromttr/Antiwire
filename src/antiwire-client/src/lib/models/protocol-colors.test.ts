import { describe, expect, it } from 'bun:test';
import {
  hueDistance,
  parseCssRgb,
  protocolBaseHue,
  protocolCssVarName,
  protocolTextColor,
  recordProtocolColorVar,
  reservedHuesFromColors,
  resolveProtocolHue,
  rgbToHueSaturation,
} from './protocol-colors';
import { wellKnownProtocolNames } from './well-known-ports';

function hslHue(color: string): number {
  const match = color.match(/hsl\(\s*([\d.]+)/);
  if (!match) throw new Error(`not an hsl color: ${color}`);
  return Number(match[1]);
}

function hslLightness(color: string): number {
  const match = color.match(/hsl\(\s*[\d.]+\s+[\d.]+%\s+([\d.]+)%/);
  if (!match) throw new Error(`not an hsl color: ${color}`);
  return Number(match[1]);
}

describe('protocol hues', () => {
  it('gives every named protocol its own base hue', () => {
    const hues = wellKnownProtocolNames().map((name) => protocolBaseHue(name));
    expect(hues.every((hue) => hue != null)).toBe(true);
    const unique = new Set(hues.map((hue) => Math.round(hue!)));
    expect(unique.size).toBe(wellKnownProtocolNames().length);
  });

  it('keeps common protocols in distinct families', () => {
    expect(hueDistance(protocolBaseHue('HTTPS')!, protocolBaseHue('DNS')!)).toBeGreaterThan(20);
    expect(hueDistance(protocolBaseHue('HTTPS')!, protocolBaseHue('SSH')!)).toBeGreaterThan(40);
    expect(hueDistance(protocolBaseHue('SMB')!, protocolBaseHue('RDP')!)).toBeGreaterThan(30);
  });
});

describe('reservedHuesFromColors', () => {
  it('ignores gray theme surfaces and keeps saturated accents', () => {
    expect(reservedHuesFromColors(['#2c3038', '#383d46'])).toEqual([]);
    const mint = reservedHuesFromColors(['#2effa3']);
    expect(mint).toHaveLength(1);
    expect(hueDistance(mint[0]!, 150)).toBeLessThan(8);
  });
});

describe('resolveProtocolHue', () => {
  it('keeps the preferred hue when the theme is neutral', () => {
    expect(resolveProtocolHue('HTTPS', [])).toBe(protocolBaseHue('HTTPS'));
    expect(resolveProtocolHue('TCP', [])).toBeUndefined();
  });

  it('keeps HTTPS on the default mint accent', () => {
    const mint = reservedHuesFromColors(['#2effa3']);
    expect(resolveProtocolHue('HTTPS', mint)).toBe(protocolBaseHue('HTTPS'));
  });

  it('moves a protocol off a purple UI and a matching accent', () => {
    const dusk = reservedHuesFromColors(['#53307c']);
    const mint = reservedHuesFromColors(['#2effa3']);
    const purpleProtocol = wellKnownProtocolNames().find((name) => {
      const hue = protocolBaseHue(name);
      return hue != null && dusk.some((reserved) => hueDistance(hue, reserved) < 30);
    });
    expect(purpleProtocol).toBeDefined();
    const remapped = resolveProtocolHue(purpleProtocol!, dusk)!;
    expect(dusk.every((reserved) => hueDistance(remapped, reserved) >= 30)).toBe(true);

    const greenProtocol = wellKnownProtocolNames().find((name) => {
      const hue = protocolBaseHue(name);
      return hue != null && mint.some((reserved) => hueDistance(hue, reserved) < 30);
    });
    if (greenProtocol) {
      const moved = resolveProtocolHue(greenProtocol, mint)!;
      expect(mint.every((reserved) => hueDistance(moved, reserved) >= 30)).toBe(true);
    }
  });
});

describe('protocolTextColor', () => {
  it('is brighter in dark mode and darker in light mode', () => {
    const dark = protocolTextColor('HTTPS', 'dark', [])!;
    const light = protocolTextColor('HTTPS', 'light', [])!;
    expect(hslLightness(dark)).toBeGreaterThan(hslLightness(light));
    expect(hslHue(dark)).toBeCloseTo(hslHue(light), 0);
  });

  it('changes the color when the reserved hue collides', () => {
    const dusk = reservedHuesFromColors(['#53307c']);
    const name =
      wellKnownProtocolNames().find((protocol) => {
        const hue = protocolBaseHue(protocol);
        return hue != null && dusk.some((reserved) => hueDistance(hue, reserved) < 30);
      }) ?? 'OPENVPN';
    expect(protocolTextColor(name, 'dark', dusk)).not.toBe(protocolTextColor(name, 'dark', []));
  });

  it('leaves unknown transports uncolored', () => {
    expect(protocolTextColor('TCP', 'dark', [])).toBeUndefined();
    expect(protocolTextColor('UDP', 'light', [])).toBeUndefined();
  });
});

describe('recordProtocolColorVar', () => {
  it('returns a CSS variable only for named protocols', () => {
    expect(recordProtocolColorVar('HTTPS')).toBe('var(--proto-https, var(--t3))');
    expect(recordProtocolColorVar('NAT-T')).toBe('var(--proto-nat-t, var(--t3))');
    expect(recordProtocolColorVar('TCP')).toBeUndefined();
    expect(protocolCssVarName('NAT-T')).toBe('--proto-nat-t');
  });
});

describe('parseCssRgb', () => {
  it('reads hex and rgb colors', () => {
    expect(parseCssRgb('#2effa3')).toEqual({ r: 46, g: 255, b: 163 });
    expect(parseCssRgb('rgb(83, 48, 124)')).toEqual({ r: 83, g: 48, b: 124 });
    expect(rgbToHueSaturation({ r: 83, g: 48, b: 124 }).s).toBeGreaterThan(0.2);
  });
});
