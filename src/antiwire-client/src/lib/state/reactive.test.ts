import { describe, expect, test } from 'bun:test';
import { Reactive, shallowEqual } from './reactive.ts';

class Counter extends Reactive {
  count = 0;
  bump() {
    this.count++;
    this.changed();
  }
}

describe('Reactive', () => {
  test('coalesces a burst of changes into one notification', async () => {
    const counter = new Counter();
    let calls = 0;
    counter.subscribe(() => calls++);
    counter.bump();
    counter.bump();
    counter.bump();
    expect(calls).toBe(0);
    await Promise.resolve();
    expect(calls).toBe(1);
    expect(counter.count).toBe(3);
  });

  test('version changes on every change and unsubscribe stops notifications', async () => {
    const counter = new Counter();
    let calls = 0;
    const off = counter.subscribe(() => calls++);
    const before = counter.version();
    counter.bump();
    expect(counter.version()).not.toBe(before);
    off();
    await Promise.resolve();
    expect(calls).toBe(0);
  });
});

describe('shallowEqual', () => {
  test('compares one level deep', () => {
    expect(shallowEqual({ a: 1, b: 'x' }, { a: 1, b: 'x' })).toBe(true);
    expect(shallowEqual({ a: 1 }, { a: 2 })).toBe(false);
    expect(shallowEqual([1, 2], [1, 2])).toBe(true);
    expect(shallowEqual({ a: {} }, { a: {} })).toBe(false);
    expect(shallowEqual([1], { 0: 1 })).toBe(false);
  });
});
