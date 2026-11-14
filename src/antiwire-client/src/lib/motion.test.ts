import { describe, expect, test } from 'bun:test';
import { exitIn, expoOut, MOTION, navDirection, popOut } from './motion';

describe('motion', () => {
  test('easings start at 0 and land exactly on 1', () => {
    for (const ease of [expoOut, exitIn, popOut]) {
      expect(ease(0)).toBeCloseTo(0, 5);
      expect(ease(1)).toBeCloseTo(1, 5);
    }
  });

  test('expoOut front-loads movement; exitIn back-loads it', () => {
    expect(expoOut(0.25)).toBeGreaterThan(0.8);
    expect(exitIn(0.5)).toBeLessThan(0.2);
  });

  test('popOut overshoots slightly before settling', () => {
    const peak = Math.max(...Array.from({ length: 101 }, (_, i) => popOut(i / 100)));
    expect(peak).toBeGreaterThan(1);
    expect(peak).toBeLessThan(1.12);
  });

  test('exits are quicker than the entrances they undo', () => {
    expect(MOTION.exit).toBeLessThan(MOTION.base);
    expect(MOTION.fast).toBeLessThan(MOTION.base);
    expect(MOTION.base).toBeLessThan(MOTION.slow);
  });

  test('navDirection follows the tab order', () => {
    expect(navDirection('/', '/records')).toBe(1);
    expect(navDirection('/settings', '/firewall')).toBe(-1);
    expect(navDirection('/network', '/capture')).toBe(-1);
    expect(navDirection('/firewall', '/firewall')).toBe(0);
  });

  test('navDirection is neutral when either end is not a tab', () => {
    expect(navDirection('/inspector', '/records')).toBe(0);
    expect(navDirection(null, '/records')).toBe(0);
    expect(navDirection('/', '/nowhere')).toBe(0);
  });
});
